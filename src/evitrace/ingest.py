"""Normalized, taint-isolated ingestion for JSONL and CSV exports."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dateutil import parser as date_parser
from pydantic import BaseModel, Field

from evitrace.models import EventRecord, InjectionFlag, TimeBasis
from evitrace.security.sandbox import check_line_length, sha256_file
from evitrace.security.taint import scan_record
from evitrace.store import CaseStore


class IngestError(ValueError):
    """Raised when an event export cannot be normalized."""


class IngestStats(BaseModel):
    artifact_id: str
    events: int
    tainted: int
    injection_flags: int
    hosts: list[str] = Field(default_factory=list)


def parse_timestamp(
    value: Any, basis: TimeBasis, precision_seconds: float
) -> tuple[datetime, datetime, datetime]:
    """Return (recorded, earliest_utc, latest_utc).

    UTC and explicit-offset records use [t, t + precision]. Unknown local wall
    time is bounded by all valid IANA offsets: UTC-12 to UTC+14.
    """

    if isinstance(value, datetime):
        recorded = value
    elif isinstance(value, int | float):
        recorded = datetime.fromtimestamp(float(value), tz=UTC)
    else:
        text = str(value).strip()
        if not text:
            raise IngestError("missing timestamp")
        try:
            recorded = date_parser.isoparse(text)
        except ValueError:
            try:
                recorded = date_parser.parse(text)
            except (ValueError, OverflowError) as exc:
                raise IngestError(f"unparseable timestamp: {text!r}") from exc
    if recorded.tzinfo is None:
        if basis is TimeBasis.UNKNOWN_LOCAL:
            earliest = (recorded - timedelta(hours=14)).replace(tzinfo=UTC)
            latest = (
                recorded + timedelta(hours=12) + timedelta(seconds=precision_seconds)
            ).replace(tzinfo=UTC)
            return recorded, earliest, latest
        recorded = recorded.replace(tzinfo=UTC)
    recorded = recorded.astimezone(UTC)
    return recorded, recorded, recorded + timedelta(seconds=precision_seconds)


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _event_id(record: dict[str, Any], artifact_id: str, line: int) -> str:
    value = _first(record, ("event_id", "id", "uuid", "record_id"))
    if value is not None:
        return str(value)
    return f"{artifact_id}-{line:06d}"


def _host(record: dict[str, Any]) -> str:
    value = _first(
        record,
        ("host", "hostname", "host_name", "computer", "Computer", "source_host", "src_host"),
    )
    return str(value) if value is not None else "UNKNOWN-HOST"


def _event_type(record: dict[str, Any]) -> str:
    value = _first(record, ("event_type", "type", "event", "parser", "EventType", "action"))
    return str(value) if value is not None else "record"


def _fields(record: dict[str, Any]) -> dict[str, Any]:
    base: dict[str, Any] = {}
    if isinstance(record.get("fields"), dict):
        base = dict(record["fields"])
    elif isinstance(record.get("fields"), str):
        try:
            decoded = json.loads(record["fields"])
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            base = decoded
    event_data = record.get("EventData")
    if isinstance(event_data, dict):
        base.update(event_data)
    for key, value in record.items():
        if key in {
            "event_id",
            "id",
            "uuid",
            "record_id",
            "host",
            "hostname",
            "host_name",
            "computer",
            "Computer",
            "source_host",
            "src_host",
            "event_type",
            "type",
            "event",
            "parser",
            "EventType",
            "action",
            "timestamp",
            "timestamp_utc",
            "time",
            "Time",
            "datetime",
            "@timestamp",
            "precision_seconds",
            "precision",
            "time_basis",
            "basis",
            "fields",
            "EventData",
            "raw",
        }:
            continue
        base.setdefault(key, value)
    return base


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            check_line_length(line, source=f"{path.name}:{line_no}")
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise IngestError(f"{path.name}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise IngestError(f"{path.name}:{line_no}: each JSONL line must be an object")
            records.append(record)
    return records


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise IngestError(f"{path.name}: CSV has no header")
        return [dict(row) for row in reader]


def read_records(path: Path, fmt: str) -> list[dict[str, Any]]:
    if fmt in {"jsonl", "json", "evtx", "plaso"}:
        return _read_jsonl(path)
    if fmt in {"csv"}:
        return _read_csv(path)
    raise IngestError(f"unsupported format: {fmt}")


def normalize_records(
    records: list[dict[str, Any]],
    *,
    case_id: str,
    artifact_id: str,
) -> list[EventRecord]:
    events: list[EventRecord] = []
    seen: set[str] = set()
    for index, record in enumerate(records, start=1):
        event_id = _event_id(record, artifact_id, index)
        if event_id in seen:
            raise IngestError(f"duplicate event_id in artifact: {event_id}")
        seen.add(event_id)
        raw_timestamp = _first(
            record, ("timestamp", "timestamp_utc", "time", "Time", "datetime", "@timestamp")
        )
        if raw_timestamp is None:
            raise IngestError(f"event {event_id} has no timestamp")
        basis_text = str(_first(record, ("time_basis", "basis")) or "UTC").upper()
        try:
            basis = TimeBasis(basis_text)
        except ValueError as exc:
            raise IngestError(f"event {event_id} has an unknown time basis: {basis_text}") from exc
        precision = float(_first(record, ("precision_seconds", "precision")) or 1.0)
        recorded, earliest, latest = parse_timestamp(raw_timestamp, basis, precision)
        flags: list[InjectionFlag] = scan_record(event_id, record)
        events.append(
            EventRecord(
                event_id=event_id,
                case_id=case_id,
                host=_host(record),
                event_type=_event_type(record),
                timestamp=recorded,
                time_basis=basis,
                precision_seconds=precision,
                earliest_utc=earliest,
                latest_utc=latest,
                fields=_fields(record),
                source_artifact=artifact_id,
                source_line=index,
                raw=record,
                envelope_id=f"env-{event_id}",
                tainted=bool(flags),
                injection_flags=flags,
            )
        )
    return events


def ingest_artifact(
    store: CaseStore,
    path: str | Path,
    *,
    artifact_id: str,
    fmt: str = "jsonl",
    expected_sha256: str | None = None,
    roots: tuple[Path, ...] | None = None,
) -> IngestStats:
    record = store.register_artifact(
        path, artifact_id=artifact_id, fmt=fmt, roots=roots, expected_sha256=expected_sha256
    )
    source = Path(record.path)
    if expected_sha256 is None:
        # Re-hash after registration to make the provenance explicit in the audit log.
        if sha256_file(source) != record.sha256:
            raise IngestError("artifact changed between registration and ingestion")
    records = read_records(source, fmt)
    events = normalize_records(records, case_id=store.config.case_id, artifact_id=artifact_id)
    store.add_events(events)
    return IngestStats(
        artifact_id=artifact_id,
        events=len(events),
        tainted=sum(1 for event in events if event.tainted),
        injection_flags=sum(len(event.injection_flags) for event in events),
        hosts=sorted({event.host for event in events}),
    )
