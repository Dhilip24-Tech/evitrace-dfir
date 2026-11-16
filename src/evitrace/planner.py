"""Deterministic question planner. It reads normalized fields, never instructions."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from evitrace.claims import event_text
from evitrace.models import (
    Claim,
    ClaimKind,
    ClaimType,
    EventRecord,
    TemporalAssertion,
)
from evitrace.store import CaseStore

IP = r"\d{1,3}(?:\.\d{1,3}){3}"
FILE = r"[\w.\-]{2,80}"
HOST = r"[\w.\-]{2,40}"


def _claim_id(question: str, cited: list[str]) -> str:
    digest = hashlib.sha256((question + "|" + ",".join(cited)).encode("utf-8")).hexdigest()[:10]
    return f"claim_{digest}"


def _find(
    events: list[EventRecord],
    event_type: str | None = None,
    host: str | None = None,
    needle: str | None = None,
) -> list[EventRecord]:
    found = []
    for event in events:
        if event_type and event.event_type != event_type:
            continue
        if host and event.host.lower() != host.lower():
            continue
        if needle and needle.lower() not in event_text(event).lower():
            continue
        found.append(event)
    return sorted(found, key=lambda item: item.earliest_utc)


def _field(event: EventRecord, *keys: str) -> str:
    for key in keys:
        value = event.fields.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _make_claim(
    store: CaseStore,
    question: str,
    *,
    kind: ClaimKind,
    cited: list[str],
    temporal: TemporalAssertion | None = None,
    critical: dict[str, str] | None = None,
    predicates: list[str] | None = None,
    host: str = "",
) -> Claim:
    return Claim(
        claim_id=_claim_id(question, cited),
        case_id=store.config.case_id,
        text=question,
        kind=kind,
        claim_type=(
            ClaimType.CROSS_EVENT_INFERENCE if len(cited) > 1 else ClaimType.RECORD_OBSERVATION
        ),
        subject=host,
        host=host,
        cited_event_ids=cited,
        required_predicates=predicates or [],
        temporal=temporal,
        critical_identifiers=critical or {},
    )


def plan_question(question: str, store: CaseStore) -> Claim:
    """Plan one question against the normalized case store."""

    events = store.events()
    text = question.strip()

    match = re.search(
        rf"(?i)\bwas\s+(?P<file>{FILE})\s+downloaded\s+and\s+executed\s+on\s+(?P<host>{HOST})",
        text,
    )
    if match:
        file_name = match.group("file")
        host = match.group("host")
        downloads = _find(events, "file_download", host, file_name)
        processes = _find(events, "process_start", host, file_name)
        cited = [event.event_id for event in [*downloads[:1], *processes[:1]]]
        file_hash = _field(downloads[0], "file_hash_sha256") if downloads else ""
        temporal = None
        if downloads and processes:
            temporal = TemporalAssertion(
                left_event_id=downloads[0].event_id,
                right_event_id=processes[0].event_id,
            )
        critical = {"file_name": file_name, "host": host}
        if file_hash:
            critical["file_hash_sha256"] = file_hash
        return _make_claim(
            store,
            text,
            kind=ClaimKind.TEMPORAL,
            cited=cited,
            temporal=temporal,
            critical=critical,
            host=host,
        )

    match = re.search(
        rf"(?i)\bdid\s+(?P<host>{HOST})\s+initiate\b.*?\bto\s+(?P<ip>{IP})\s+before\s+"
        rf"(?P<fw>{HOST})\s+logged\s+the\s+block",
        text,
    )
    if match:
        host, ip, firewall = match.group("host"), match.group("ip"), match.group("fw")
        left = _find(events, "process_start", host, ip)
        if not left:
            left = _find(events, "network_connect", host, ip)
        right = _find(events, "firewall_block", firewall, ip)
        cited = [event.event_id for event in [*left[:1], *right[:1]]]
        temporal = None
        if left and right:
            temporal = TemporalAssertion(
                left_event_id=left[0].event_id, right_event_id=right[0].event_id
            )
        critical: dict[str, str] = {}
        if left:
            critical["process_start"] = left[0].event_id
        if right:
            critical["firewall_block"] = right[0].event_id
        return _make_claim(
            store,
            text,
            kind=ClaimKind.TEMPORAL,
            cited=cited,
            temporal=temporal,
            critical=critical,
            host=host,
        )

    match = re.search(
        rf"(?i)\bdid\s+the\s+process\s+exfiltrate\s+(?P<file>{FILE})\s+to\s+(?P<ip>{IP})",
        text,
    )
    if match:
        file_name, ip = match.group("file"), match.group("ip")
        processes = _find(events, "process_start", needle=file_name)
        if not processes:
            processes = _find(events, "process_start")
        firewall = _find(events, "firewall_block", needle=ip)
        cited = [event.event_id for event in [*processes[:1], *firewall[:1]]]
        predicates = [f"file_read({file_name})", f"network_bytes_out({ip})"]
        return _make_claim(
            store,
            text,
            kind=ClaimKind.CAUSAL,
            cited=cited,
            critical={"file_read": file_name, "network_bytes_out": ip},
            predicates=predicates,
            host=processes[0].host if processes else "",
        )

    match = re.search(
        rf"(?i)\bwas\s+(?P<file>{FILE})\s+created\s+before\s+the\s+operating\s+system\s+was\s+installed",
        text,
    )
    if not match:
        match = re.search(
            rf"(?i)\bdid\s+(?P<file>{FILE})\s+predate\s+the\s+os\s+installation",
            text,
        )
    if match:
        file_name = match.group("file")
        created = _find(events, "file_created", needle=file_name)
        installs = _find(events, "os_install")
        if created:
            installs = [event for event in installs if event.host == created[0].host]
        cited = [event.event_id for event in [*created[:1], *installs[:1]]]
        temporal = None
        if created and installs:
            temporal = TemporalAssertion(
                left_event_id=created[0].event_id, right_event_id=installs[0].event_id
            )
        critical: dict[str, str] = {}
        if created:
            critical["file_created"] = created[0].event_id
        if installs:
            critical["os_install"] = installs[0].event_id
        return _make_claim(
            store,
            text,
            kind=ClaimKind.TEMPORAL,
            cited=cited,
            temporal=temporal,
            critical=critical,
            host=created[0].host if created else "",
        )

    if re.search(r"(?i)\b(no malicious activity|injected user-agent|prompt injection)\b", text):
        tainted = [event for event in events if event.tainted]
        cited = [event.event_id for event in tainted[:1]]
        marker = ""
        if tainted and tainted[0].injection_flags:
            marker = tainted[0].injection_flags[0].excerpt.split(";")[0][:60]
        return _make_claim(
            store,
            text,
            kind=ClaimKind.NEGATIVE,
            cited=cited,
            critical={"injection_text": marker} if marker else {},
            host=tainted[0].host if tainted else "",
        )

    # Fallback: retrieve evidence deterministically and let the claim abstain if
    # the requested predicates are not present.
    hits = store.search(text, limit=3)
    cited = [hit.event_id for hit in hits]
    terms = [token for token in re.findall(r"[A-Za-z0-9_.\-]{3,}", text)][:2]
    critical: dict[str, Any] = {"question_term": terms[0]} if terms else {}
    return _make_claim(
        store,
        text,
        kind=ClaimKind.OBSERVATION,
        cited=cited,
        critical={str(k): str(v) for k, v in critical.items()},
    )
