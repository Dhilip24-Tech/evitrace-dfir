"""Isolated per-case SQLite evidence store with FTS5 and provenance."""

from __future__ import annotations

import json
import math
import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evitrace.models import (
    ArtifactRecord,
    CalibrationRecord,
    CaseConfig,
    Certificate,
    EventRecord,
    HostConfig,
    RunRecord,
    SearchHit,
)
from evitrace.security.sandbox import SandboxError, safe_resolve_path, sha256_file

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  registered_at TEXT NOT NULL,
  format TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  host TEXT NOT NULL,
  event_type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  time_basis TEXT NOT NULL,
  precision_seconds REAL NOT NULL,
  earliest_utc TEXT NOT NULL,
  latest_utc TEXT NOT NULL,
  fields_json TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  envelope_id TEXT NOT NULL,
  tainted INTEGER NOT NULL DEFAULT 0,
  injection_json TEXT NOT NULL DEFAULT '[]',
  search_text TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  event_id UNINDEXED,
  case_id UNINDEXED,
  search_text,
  tokenize='unicode61'
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  question_id TEXT NOT NULL,
  question TEXT NOT NULL,
  verdict TEXT NOT NULL,
  certificate_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  certificate_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS calibrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alpha REAL NOT NULL,
  qhat REAL NOT NULL,
  n INTEGER NOT NULL,
  rank INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""

TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@/\-]{1,}")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


class StoreError(RuntimeError):
    """Raised when a case or record violates isolation rules."""


class CaseStore:
    """One database per case. No method accepts a cross-case row silently."""

    def __init__(self, workspace: Path, config: CaseConfig) -> None:
        self.workspace = workspace.resolve()
        self.config = config
        self.case_dir = self.workspace / "cases" / config.case_id
        self.db_path = self.case_dir / "case.db"
        self.key_path = self.case_dir / "key.bin"
        self.config_path = self.case_dir / "case.json"

    @classmethod
    def create(cls, workspace: Path, config: CaseConfig) -> CaseStore:
        workspace = workspace.resolve()
        case_dir = workspace / "cases" / config.case_id
        if (case_dir / "case.db").exists():
            raise StoreError(f"case {config.case_id} already exists in {workspace}")
        case_dir.mkdir(parents=True, exist_ok=True)
        store = cls(workspace, config)
        store.config_path.write_text(config.model_dump_json(indent=2), encoding="utf-8")
        import secrets

        store.key_path.write_bytes(secrets.token_bytes(32))
        try:
            store.key_path.chmod(0o600)
        except OSError:
            pass
        with store._conn() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("case_id", config.case_id)
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("name", config.name)
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("hosts_json", json.dumps({k: v.model_dump() for k, v in config.hosts.items()})),
            )
        store.audit("case.create", f"created {config.case_id}")
        return store

    @classmethod
    def open(cls, workspace: Path, case_id: str) -> CaseStore:
        workspace = workspace.resolve()
        case_dir = workspace / "cases" / case_id
        config_path = case_dir / "case.json"
        if not config_path.exists():
            raise StoreError(f"unknown case: {case_id} in {workspace}")
        config = CaseConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        if config.case_id != case_id:
            raise StoreError("case metadata does not match the requested case_id")
        store = cls(workspace, config)
        if not store.db_path.exists():
            raise StoreError(f"case database missing: {store.db_path}")
        return store

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- artifacts ---------------------------------------------------------

    def register_artifact(
        self,
        path: str | Path,
        *,
        artifact_id: str,
        fmt: str = "jsonl",
        roots: tuple[Path, ...] | None = None,
        expected_sha256: str | None = None,
    ) -> ArtifactRecord:
        resolved = safe_resolve_path(path, roots or (self.workspace.parent, self.workspace))
        digest = sha256_file(resolved)
        if expected_sha256 and digest.lower() != expected_sha256.lower():
            raise SandboxError(
                f"artifact hash mismatch for {resolved.name}: "
                f"expected {expected_sha256}, got {digest}"
            )
        record = ArtifactRecord(
            artifact_id=artifact_id,
            path=str(resolved),
            sha256=digest,
            bytes=resolved.stat().st_size,
            registered_at=_now(),
            format=fmt,
        )
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT sha256 FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
            if existing and existing["sha256"] != digest:
                raise StoreError(f"artifact {artifact_id} already registered with another hash")
            conn.execute(
                "INSERT OR REPLACE INTO artifacts("
                "artifact_id, path, sha256, bytes, registered_at, format) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.artifact_id,
                    record.path,
                    record.sha256,
                    record.bytes,
                    _iso(record.registered_at),
                    record.format,
                ),
            )
        self.audit("artifact.register", f"{artifact_id} sha256={digest}")
        return record

    def artifact(self, artifact_id: str) -> ArtifactRecord | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if not row:
            return None
        return ArtifactRecord(
            artifact_id=row["artifact_id"],
            path=row["path"],
            sha256=row["sha256"],
            bytes=row["bytes"],
            registered_at=_parse(row["registered_at"]),
            format=row["format"],
        )

    def artifacts(self) -> list[ArtifactRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM artifacts ORDER BY artifact_id").fetchall()
        return [
            ArtifactRecord(
                artifact_id=row["artifact_id"],
                path=row["path"],
                sha256=row["sha256"],
                bytes=row["bytes"],
                registered_at=_parse(row["registered_at"]),
                format=row["format"],
            )
            for row in rows
        ]

    # -- events ------------------------------------------------------------

    def add_event(self, event: EventRecord) -> None:
        if event.case_id != self.config.case_id:
            raise StoreError(
                f"event {event.event_id} belongs to {event.case_id}, not {self.config.case_id}"
            )
        search_text = self._search_text(event)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO events(event_id, case_id, host, event_type, timestamp, "
                "time_basis, precision_seconds, earliest_utc, latest_utc, fields_json, raw_json, "
                "artifact_id, envelope_id, tainted, injection_json, search_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.case_id,
                    event.host,
                    event.event_type,
                    _iso(event.timestamp),
                    event.time_basis.value,
                    event.precision_seconds,
                    _iso(event.earliest_utc),
                    _iso(event.latest_utc),
                    json.dumps(event.fields, sort_keys=True, ensure_ascii=False),
                    json.dumps(event.raw, sort_keys=True, ensure_ascii=False),
                    event.source_artifact,
                    event.envelope_id,
                    1 if event.tainted else 0,
                    json.dumps([flag.model_dump(mode="json") for flag in event.injection_flags]),
                    search_text,
                ),
            )
            conn.execute("DELETE FROM events_fts WHERE event_id = ?", (event.event_id,))
            conn.execute(
                "INSERT INTO events_fts(event_id, case_id, search_text) VALUES (?, ?, ?)",
                (event.event_id, event.case_id, search_text),
            )

    def add_events(self, events: Iterable[EventRecord]) -> int:
        count = 0
        for event in events:
            self.add_event(event)
            count += 1
        self.audit("events.ingest", f"{count} events")
        return count

    def get_event(self, event_id: str) -> EventRecord | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if not row:
            return None
        if row["case_id"] != self.config.case_id:
            raise StoreError(f"event {event_id} belongs to another case")
        return self._row_to_event(row)

    def events(self) -> list[EventRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY timestamp, event_id").fetchall()
        return [self._row_to_event(row) for row in rows]

    def events_by_ids(
        self, event_ids: list[str]
    ) -> tuple[dict[str, EventRecord], list[str], list[str]]:
        found: dict[str, EventRecord] = {}
        missing: list[str] = []
        cross_case: list[str] = []
        with self._conn() as conn:
            for event_id in event_ids:
                row = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if not row:
                    missing.append(event_id)
                elif row["case_id"] != self.config.case_id:
                    cross_case.append(event_id)
                else:
                    found[event_id] = self._row_to_event(row)
        return found, missing, cross_case

    def event_count(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def _row_to_event(self, row: sqlite3.Row) -> EventRecord:
        from evitrace.models import InjectionFlag, TimeBasis

        return EventRecord(
            event_id=row["event_id"],
            case_id=row["case_id"],
            host=row["host"],
            event_type=row["event_type"],
            timestamp=_parse(row["timestamp"]),
            time_basis=TimeBasis(row["time_basis"]),
            precision_seconds=row["precision_seconds"],
            earliest_utc=_parse(row["earliest_utc"]),
            latest_utc=_parse(row["latest_utc"]),
            fields=json.loads(row["fields_json"]),
            source_artifact=row["artifact_id"],
            source_line=0,
            raw=json.loads(row["raw_json"]),
            envelope_id=row["envelope_id"],
            tainted=bool(row["tainted"]),
            injection_flags=[
                InjectionFlag.model_validate(f) for f in json.loads(row["injection_json"])
            ],
        )

    @staticmethod
    def _search_text(event: EventRecord) -> str:
        flat: list[str] = [event.event_id, event.host, event.event_type]

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
            elif value is not None:
                flat.append(str(value))

        walk(event.fields)
        walk(event.raw)
        return " ".join(flat)[:20_000]

    # -- retrieval ---------------------------------------------------------

    def search(self, query: str, limit: int = 10) -> list[SearchHit]:
        tokens = [token for token in TOKEN_RE.findall(query) if len(token) >= 2]
        if not tokens:
            return []
        match = " OR ".join(f'"{_escape_fts(token)}"' for token in tokens)
        hits: dict[str, dict[str, Any]] = {}
        with self._conn() as conn:
            try:
                rows = conn.execute(
                    "SELECT event_id, bm25(events_fts) AS rank FROM events_fts "
                    "WHERE events_fts MATCH ? AND case_id = ? ORDER BY rank LIMIT ?",
                    (match, self.config.case_id, max(limit * 4, 20)),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            for index, row in enumerate(rows):
                hits[row["event_id"]] = {
                    "lexical_rank": index,
                    "score": 0.0,
                    "exact": False,
                    "excerpt": "",
                }
            semantic = self._semantic_scores(query)
            for rank, (event_id, similarity) in enumerate(semantic[: max(limit * 4, 20)]):
                entry = hits.setdefault(
                    event_id, {"lexical_rank": None, "score": 0.0, "exact": False, "excerpt": ""}
                )
                entry["semantic_rank"] = rank
                entry["score"] = float(entry["score"]) + similarity * 0.25
            # Exact IOC/path/hash boost, scoped by case_id.
            lower_tokens = {token.lower() for token in tokens}
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT event_id, search_text FROM events WHERE case_id = ?",
                    (self.config.case_id,),
                ).fetchall()
            for row in rows:
                text_lower = row["search_text"].lower()
                exact_hits = sum(1 for token in lower_tokens if token in text_lower)
                if exact_hits:
                    entry = hits.setdefault(
                        row["event_id"],
                        {"lexical_rank": None, "score": 0.0, "exact": False, "excerpt": ""},
                    )
                    entry["exact"] = True
                    entry["score"] = float(entry["score"]) + 0.35 * exact_hits
                    entry["excerpt"] = row["search_text"][:160]
        for entry in hits.values():
            lexical_rank = entry.get("lexical_rank")
            if lexical_rank is not None:
                entry["score"] = float(entry["score"]) + 1.0 / (60.0 + lexical_rank)
        ordered = sorted(hits.items(), key=lambda item: float(item[1]["score"]), reverse=True)[
            :limit
        ]
        return [
            SearchHit(
                event_id=event_id,
                score=round(float(entry["score"]), 4),
                lexical_rank=entry.get("lexical_rank"),
                semantic_rank=entry.get("semantic_rank"),
                exact_match=bool(entry["exact"]),
                excerpt=str(entry["excerpt"]),
            )
            for event_id, entry in ordered
        ]

    def _semantic_scores(self, query: str) -> list[tuple[str, float]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT event_id, search_text FROM events WHERE case_id = ?", (self.config.case_id,)
            ).fetchall()
        if not rows:
            return []
        texts = [row["search_text"] for row in rows]
        try:
            from sklearn.feature_extraction.text import HashingVectorizer

            vectorizer = HashingVectorizer(
                n_features=256, alternate_sign=False, norm="l2", lowercase=True
            )
            matrix = vectorizer.transform([query, *texts])
            query_vec = matrix[0]
            scores = (matrix[1:] @ query_vec.T).toarray().ravel()
            return sorted(
                ((rows[i]["event_id"], float(scores[i])) for i in range(len(rows))),
                key=lambda item: item[1],
                reverse=True,
            )
        except ImportError:
            query_terms = {token.lower() for token in TOKEN_RE.findall(query)}
            scored: list[tuple[str, float]] = []
            for row in rows:
                terms = {token.lower() for token in TOKEN_RE.findall(row["search_text"])}
                union = query_terms | terms
                scored.append(
                    (row["event_id"], len(query_terms & terms) / len(union) if union else 0.0)
                )
            return sorted(scored, key=lambda item: item[1], reverse=True)

    # -- runs, calibration, audit -----------------------------------------

    def save_run(self, run: RunRecord, certificate: Certificate) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs(run_id, case_id, question_id, question, verdict, "
                "certificate_id, created_at, certificate_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.run_id,
                    run.case_id,
                    run.question_id,
                    run.question,
                    run.verdict.value,
                    run.certificate_id,
                    _iso(run.created_at),
                    certificate.model_dump_json(),
                ),
            )

    def runs(self) -> list[RunRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY rowid").fetchall()
        return [
            RunRecord(
                run_id=row["run_id"],
                case_id=row["case_id"],
                question_id=row["question_id"],
                question=row["question"],
                verdict=row["verdict"],
                certificate_id=row["certificate_id"],
                created_at=_parse(row["created_at"]),
            )
            for row in rows
        ]

    def certificate(self, run_id: str) -> Certificate | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT certificate_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return Certificate.model_validate_json(row[0]) if row else None

    def save_calibration(self, record: CalibrationRecord) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO calibrations(alpha, qhat, n, rank, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.alpha,
                    record.qhat,
                    record.n,
                    record.rank,
                    record.model_dump_json(),
                    _iso(record.created_at),
                ),
            )

    def latest_calibration(self, alpha: float) -> CalibrationRecord | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload_json FROM calibrations WHERE alpha = ? ORDER BY id DESC LIMIT 1",
                (alpha,),
            ).fetchone()
        return CalibrationRecord.model_validate_json(row[0]) if row else None

    def audit(self, action: str, detail: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit(action, detail, created_at) VALUES (?, ?, ?)",
                (action, detail, _iso(_now())),
            )

    def key_bytes(self) -> bytes:
        return self.key_path.read_bytes()

    # -- validation --------------------------------------------------------

    def validate_case(self) -> dict[str, Any]:
        issues: list[str] = []
        checks: list[str] = []
        with self._conn() as conn:
            event_count = int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            fts_count = int(conn.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0])
            case_ids = [row[0] for row in conn.execute("SELECT DISTINCT case_id FROM events")]
            tainted = int(
                conn.execute("SELECT COUNT(*) FROM events WHERE tainted = 1").fetchone()[0]
            )
        if event_count != fts_count:
            issues.append(f"FTS index has {fts_count} rows for {event_count} events")
        else:
            checks.append(f"FTS index covers all {event_count} events")
        if any(case_id != self.config.case_id for case_id in case_ids):
            issues.append("cross-case event rows found")
        else:
            checks.append(f"all events scoped to {self.config.case_id}")
        for artifact in self.artifacts():
            path = Path(artifact.path)
            if not path.exists():
                issues.append(f"artifact missing: {artifact.artifact_id}")
                continue
            actual = sha256_file(path)
            if actual != artifact.sha256:
                issues.append(f"artifact hash changed: {artifact.artifact_id}")
            else:
                checks.append(f"artifact {artifact.artifact_id} hash verified")
        if tainted:
            checks.append(f"{tainted} tainted event(s) preserved as evidence, authority stripped")
        return {
            "ok": not issues,
            "checks": checks,
            "issues": issues,
            "events": event_count,
            "tainted": tainted,
            "injection_flags": [
                flag.model_dump(mode="json")
                for event in self.events()
                for flag in event.injection_flags
            ],
        }

    def rebuild_index(self) -> int:
        events = self.events()
        with self._conn() as conn:
            conn.execute("DELETE FROM events_fts")
            for event in events:
                conn.execute(
                    "INSERT INTO events_fts(event_id, case_id, search_text) VALUES (?, ?, ?)",
                    (event.event_id, event.case_id, self._search_text(event)),
                )
        return len(events)


def _escape_fts(token: str) -> str:
    return token.replace('"', '""')


def load_calibration_file(path: Path) -> CalibrationRecord:
    return CalibrationRecord.model_validate_json(path.read_text(encoding="utf-8"))


def host_skew(config: CaseConfig, host: str) -> float:
    entry = config.hosts.get(host)
    return entry.skew_seconds if isinstance(entry, HostConfig) else config.default_skew_seconds


def quantile_scores(scores: list[float], alpha: float) -> tuple[float, int, int]:
    """Finite-sample corrected conformal quantile, including the 1.0 sentinel."""

    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")
    values = sorted(scores)
    n = len(values)
    rank = math.ceil((n + 1) * (1 - alpha))
    extended = values + [1.0]
    qhat = extended[min(rank, len(extended)) - 1]
    return qhat, n, rank
