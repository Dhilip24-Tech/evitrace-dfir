from __future__ import annotations

from datetime import timedelta

import pytest

from evitrace.claims import prove_claim
from evitrace.ingest import parse_timestamp
from evitrace.models import TemporalOutcome, TimeBasis
from evitrace.planner import plan_question
from evitrace.temporal import verify_temporal


def test_unknown_local_time_uses_global_offset_bounds() -> None:
    recorded, earliest, latest = parse_timestamp(
        "2026-10-12T10:00:00", TimeBasis.UNKNOWN_LOCAL, 1.0
    )
    assert recorded.tzinfo is None
    assert earliest.hour == 20  # previous UTC day, 10:00 - 14h
    assert latest.hour == 22  # 10:00 + 12h + 1s
    assert latest - earliest == timedelta(hours=26, seconds=1)


def test_same_host_skew_cancels(demo_store) -> None:
    claim = plan_question("Was invoice_q4.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = verify_temporal(claim, demo_store.events(), demo_store.config)
    assert proof.outcome is TemporalOutcome.ENTAILED
    assert proof.sat_lt is True
    assert proof.sat_ge is False


def test_cross_host_skew_is_ambiguous(demo_store) -> None:
    claim = plan_question(
        "Did WKSTN-04 initiate the outbound connection to 198.51.100.42 before "
        "FW-EDGE-01 logged the block?",
        demo_store,
    )
    proof = verify_temporal(claim, demo_store.events(), demo_store.config)
    assert proof.outcome is TemporalOutcome.AMBIGUOUS_SKEW
    assert proof.sat_lt is True
    assert proof.sat_ge is True
    assert proof.overlap_seconds == 8.0


def test_backdated_mft_is_unsat_with_core(demo_store) -> None:
    claim = plan_question(
        "Was svc_update.ps1 created before the operating system was installed?", demo_store
    )
    proof = verify_temporal(claim, demo_store.events(), demo_store.config)
    assert proof.outcome is TemporalOutcome.UNSAT_CONFLICT
    assert proof.unsat_core
    assert any("precedence_os" in item for item in proof.unsat_core)


def test_backdated_event_does_not_poison_unrelated_claim(demo_store) -> None:
    claim = plan_question("Was invoice_q4.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.temporal.outcome is TemporalOutcome.ENTAILED
    assert proof.verdict.value == "ACCEPTED"


def test_missing_temporal_event_is_reported(demo_store) -> None:
    claim = plan_question("Was nonexistent.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = verify_temporal(claim, demo_store.events(), demo_store.config)
    assert proof.outcome is TemporalOutcome.NOT_APPLICABLE


@pytest.mark.parametrize("alpha", [0.05, 0.1, 0.2])
def test_missing_event_ids_do_not_crash(alpha: float, demo_store) -> None:
    claim = plan_question("Was absent.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=alpha)
    assert proof.verdict.value in {"ABSTAIN_INSUFFICIENT_EVIDENCE", "REJECTED"}
