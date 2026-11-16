from __future__ import annotations

from evitrace.claims import prove_claim
from evitrace.cpc import issue_certificate, verify_certificate
from evitrace.planner import plan_question
from evitrace.report import render_report


def test_cpc_signature_round_trip(demo_store) -> None:
    claim = plan_question("Was invoice_q4.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    certificate = issue_certificate(demo_store, "run-test", proof)
    assert certificate.signature is not None
    assert verify_certificate(certificate, demo_store.key_bytes())


def test_cpc_tamper_is_rejected(demo_store) -> None:
    claim = plan_question("Was invoice_q4.exe downloaded and executed on WKSTN-04?", demo_store)
    proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
    certificate = issue_certificate(demo_store, "run-test", proof)
    tampered = certificate.model_copy(deep=True)
    tampered.proof.reason = "changed after signing"
    assert not verify_certificate(tampered, demo_store.key_bytes())
    assert not verify_certificate(certificate, b"wrong-key")


def test_report_has_all_sections(demo_store) -> None:
    certificates = []
    for index, question in enumerate(
        [
            "Was invoice_q4.exe downloaded and executed on WKSTN-04?",
            "Did WKSTN-04 initiate the outbound connection to 198.51.100.42 before "
            "FW-EDGE-01 logged the block?",
            "Did the process exfiltrate customer_db.sqlite to 198.51.100.42?",
            "Was svc_update.ps1 created before the operating system was installed?",
        ]
    ):
        claim = plan_question(question, demo_store)
        proof = prove_claim(claim, demo_store, qhat=0.42, alpha=0.05)
        certificates.append(issue_certificate(demo_store, f"run-{index}", proof))
    markdown = render_report("CASE-TEST-001", certificates, validation=demo_store.validate_case())
    for heading in (
        "Supported observations",
        "Qualified hypotheses",
        "Temporal conflicts",
        "Abstentions and missing predicates",
        "Injection IOCs neutralized",
        "design targets, not measured results",
    ):
        assert heading in markdown
