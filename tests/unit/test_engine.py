from __future__ import annotations

from evitrace.claims import prove_claim
from evitrace.models import ClaimKind, TemporalOutcome, Verdict
from evitrace.planner import plan_question


def test_q1_is_accepted_with_entailed_order(demo_store) -> None:
    claim = plan_question("Was invoice_q4.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.verdict is Verdict.ACCEPTED
    assert proof.temporal.outcome is TemporalOutcome.ENTAILED
    assert proof.score.score <= 0.42


def test_q2_is_qualified_not_asserted(demo_store) -> None:
    claim = plan_question(
        "Did WKSTN-04 initiate the outbound connection to 198.51.100.42 before "
        "FW-EDGE-01 logged the block?",
        demo_store,
    )
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.verdict is Verdict.QUALIFIED_HYPOTHESIS
    assert proof.temporal.outcome is TemporalOutcome.AMBIGUOUS_SKEW
    assert proof.temporal.overlap_seconds == 8.0


def test_q3_abstains_with_missing_predicates(demo_store) -> None:
    claim = plan_question(
        "Did the process exfiltrate customer_db.sqlite to 198.51.100.42?", demo_store
    )
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.verdict is Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE
    assert proof.missing_predicates == [
        "file_read(customer_db.sqlite)",
        "network_bytes_out(198.51.100.42)",
    ]
    assert proof.score.score > proof.score.qhat
    assert proof.temporal.outcome is TemporalOutcome.NOT_APPLICABLE


def test_q4_timestomp_is_rejected(demo_store) -> None:
    claim = plan_question(
        "Was svc_update.ps1 created before the operating system was installed?", demo_store
    )
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.verdict is Verdict.REJECTED
    assert proof.temporal.outcome is TemporalOutcome.UNSAT_CONFLICT
    assert proof.score.hard_failure == "UNSAT_CONFLICT"


def test_q4_injection_has_no_authority(demo_store) -> None:
    claim = plan_question(
        "Did the injected User-Agent establish that no malicious activity occurred?", demo_store
    )
    assert claim.kind is ClaimKind.NEGATIVE
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    assert proof.verdict is Verdict.REJECTED
    assert proof.score.hard_failure == "UNTRUSTED_INSTRUCTION"
    assert proof.injection_flags
    assert any("IGNORE PRIOR RULES" in flag.excerpt for flag in proof.injection_flags)
