from __future__ import annotations

from pathlib import Path

import pytest

from evitrace.models import CaseConfig, HostConfig
from evitrace.security.sandbox import SandboxError
from evitrace.store import CaseStore, StoreError


def test_artifact_hash_and_mismatch(tmp_path: Path, store: CaseStore) -> None:
    artifact = tmp_path / "evidence.jsonl"
    artifact.write_text('{"event_id": "E1"}\n', encoding="utf-8")
    record = store.register_artifact(artifact, artifact_id="ev", roots=(tmp_path,))
    assert record.sha256 == store.artifact("ev").sha256
    with pytest.raises(SandboxError):
        store.register_artifact(
            artifact, artifact_id="ev", roots=(tmp_path,), expected_sha256="0" * 64
        )


def test_path_escape_is_rejected(store: CaseStore, tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    inside_root = tmp_path / "workspace"
    with pytest.raises(SandboxError):
        store.register_artifact(outside, artifact_id="bad", roots=(inside_root,))


def test_cases_are_isolated(workspace: Path, config: CaseConfig, add_event) -> None:
    first = CaseStore.open(workspace, config.case_id)
    add_event("EV-1", "WKSTN-04", "process_start", "2026-10-12T10:00:00Z", {"file_name": "x.exe"})
    second = CaseStore.create(
        workspace,
        CaseConfig(
            case_id="CASE-TEST-002",
            name="Other",
            hosts={"WKSTN-04": HostConfig(host="WKSTN-04")},
        ),
    )
    assert second.get_event("EV-1") is None
    assert second.search("x.exe") == []
    assert first.get_event("EV-1") is not None


def test_cross_case_insert_is_rejected(store: CaseStore) -> None:
    from evitrace.ingest import parse_timestamp
    from evitrace.models import EventRecord, TimeBasis

    recorded, earliest, latest = parse_timestamp("2026-10-12T10:00:00Z", TimeBasis.UTC, 1.0)
    event = EventRecord(
        event_id="EV-X",
        case_id="OTHER-CASE",
        host="WKSTN-04",
        event_type="process_start",
        timestamp=recorded,
        earliest_utc=earliest,
        latest_utc=latest,
        source_artifact="a",
        envelope_id="env",
    )
    with pytest.raises(StoreError):
        store.add_event(event)


def test_validate_case_and_index(store: CaseStore, add_event) -> None:
    add_event("EV-1", "WKSTN-04", "process_start", "2026-10-12T10:00:00Z", {"file_name": "x.exe"})
    result = store.validate_case()
    assert result["ok"] is True
    assert result["events"] == 1
    assert store.rebuild_index() == 1
    assert store.search("x.exe")[0].event_id == "EV-1"


def test_search_is_scoped_by_case(workspace: Path, store: CaseStore, add_event) -> None:
    add_event(
        "EV-1", "WKSTN-04", "process_start", "2026-10-12T10:00:00Z", {"file_name": "alpha.exe"}
    )
    second = CaseStore.create(
        workspace,
        CaseConfig(
            case_id="CASE-TEST-002",
            name="Other",
            hosts={"WKSTN-04": HostConfig(host="WKSTN-04")},
        ),
    )
    event = store.get_event("EV-1")
    assert event is not None
    second.add_event(event.model_copy(update={"case_id": "CASE-TEST-002", "event_id": "EV-9"}))
    assert [hit.event_id for hit in store.search("alpha.exe")] == ["EV-1"]
    assert [hit.event_id for hit in second.search("alpha.exe")] == ["EV-9"]
