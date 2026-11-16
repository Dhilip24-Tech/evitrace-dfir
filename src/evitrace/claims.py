"""Field checks, lexical overlap, scoring and selective claim decisions."""

from __future__ import annotations

import re
from typing import Any

from evitrace.calibration import nonconformity, temporal_weight
from evitrace.models import (
    Claim,
    ClaimKind,
    ClaimType,
    EventRecord,
    FieldCheck,
    ProofPackage,
    ScoreBreakdown,
    TemporalOutcome,
    TemporalProof,
    Verdict,
)
from evitrace.store import CaseStore
from evitrace.temporal import verify_temporal

TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@/\-]{1,}")
STOPWORDS = {
    "the",
    "a",
    "an",
    "did",
    "was",
    "were",
    "is",
    "are",
    "to",
    "on",
    "of",
    "and",
    "or",
    "in",
    "at",
    "by",
    "for",
    "from",
    "with",
    "that",
    "this",
    "it",
    "its",
    "be",
    "been",
    "process",
    "host",
    "event",
    "record",
    "claim",
    "occurred",
    "before",
    "after",
}
EVENT_TYPE_KEYS = {
    "process_start",
    "process_exit",
    "file_download",
    "file_created",
    "file_read",
    "network_connect",
    "network_bytes_out",
    "firewall_block",
    "tls_connect",
    "http_request",
    "email_delivered",
    "os_install",
}
PREDICATE_KEYS = {"file_read", "network_bytes_out"}


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(child) for child in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(child) for child in value)
    return str(value)


def event_text(event: EventRecord) -> str:
    return " ".join(
        [
            event.event_id,
            event.host,
            event.event_type,
            _flatten(event.fields),
            _flatten(event.raw),
        ]
    )


def _predicate_present(event: EventRecord, predicate: str, value: str) -> bool:
    if predicate == "file_read":
        return event.event_type == "file_read" and value.lower() in event_text(event).lower()
    if predicate == "network_bytes_out":
        if event.event_type not in {"network_bytes_out", "network_flow"}:
            return False
        fields = event.fields
        bytes_out = fields.get("bytes_out") or fields.get("network_bytes_out") or 0
        try:
            has_bytes = float(bytes_out) > 0
        except (TypeError, ValueError):
            has_bytes = False
        return has_bytes and value.lower() in event_text(event).lower()
    return False


def check_fields(
    claim: Claim, cited: dict[str, EventRecord], missing: list[str], cross: list[str]
) -> FieldCheck:
    matched: dict[str, str] = {}
    absent: list[str] = []
    for key, value in claim.critical_identifiers.items():
        if key in PREDICATE_KEYS:
            found = any(_predicate_present(event, key, value) for event in cited.values())
        elif key in EVENT_TYPE_KEYS:
            found = any(event.event_type == key for event in cited.values())
        else:
            haystack = " ".join(event_text(event) for event in cited.values()).lower()
            found = str(value).lower() in haystack
        if found:
            matched[key] = str(value)
        else:
            absent.append(f"{key}={value}")
    passed = not missing and not cross
    return FieldCheck(
        matched=matched,
        missing=absent,
        missing_event_ids=missing,
        cross_case_event_ids=cross,
        passed=passed,
    )


def check_predicates(claim: Claim, cited: dict[str, EventRecord]) -> list[str]:
    missing: list[str] = []
    for predicate in claim.required_predicates:
        match = re.match(r"([a-z_]+)\((.+)\)$", predicate)
        if not match:
            missing.append(predicate)
            continue
        name, value = match.group(1), match.group(2)
        if not any(_predicate_present(event, name, value) for event in cited.values()):
            missing.append(predicate)
    return missing


def lexical_overlap(claim: Claim, cited: dict[str, EventRecord]) -> float:
    terms = {
        token.lower()
        for token in TOKEN_RE.findall(claim.text + " " + " ".join(claim.required_predicates))
        if token.lower() not in STOPWORDS
    }
    if not terms:
        return 0.0
    haystack = " ".join(event_text(event) for event in cited.values()).lower()
    hits = sum(1 for term in terms if term in haystack)
    return round(hits / len(terms), 4)


def _hard_failure(field: FieldCheck, temporal: TemporalProof) -> str | None:
    if field.missing_event_ids:
        return f"MISSING_EVENT: {', '.join(field.missing_event_ids)}"
    if field.cross_case_event_ids:
        return f"CROSS_CASE: {', '.join(field.cross_case_event_ids)}"
    if temporal.outcome is TemporalOutcome.UNSAT_CONFLICT:
        return "UNSAT_CONFLICT"
    if temporal.outcome is TemporalOutcome.MISSING_EVENT:
        return "MISSING_EVENT"
    return None


def prove_claim(claim: Claim, store: CaseStore, *, qhat: float, alpha: float) -> ProofPackage:
    all_events = store.events()
    cited, missing_events, cross_case = store.events_by_ids(claim.cited_event_ids)
    field = check_fields(claim, cited, missing_events, cross_case)
    temporal = verify_temporal(claim, all_events, store.config)
    missing_predicates = check_predicates(claim, cited)
    lexical = lexical_overlap(claim, cited)

    field_weight = 0.0
    if claim.critical_identifiers:
        field_weight = len(field.matched) / len(claim.critical_identifiers)
    elif field.passed:
        field_weight = 1.0
    if missing_predicates:
        # Missing evidence predicates are not partial credit: they zero the field
        # feature even when surrounding event identifiers resolve.
        field_weight = 0.0
    tw = temporal_weight(temporal.outcome)
    if temporal.outcome is TemporalOutcome.NOT_APPLICABLE and missing_predicates:
        tw = 0.5
    type_weight = 1.0 if claim.claim_type is ClaimType.RECORD_OBSERVATION else 0.5
    hard = _hard_failure(field, temporal)
    if claim.kind is ClaimKind.NEGATIVE and any(event.tainted for event in cited.values()):
        hard = "UNTRUSTED_INSTRUCTION"
    score = 1.0 if hard else nonconformity(field_weight, tw, lexical, type_weight)

    verdict = Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE
    reason = ""
    if hard == "UNTRUSTED_INSTRUCTION":
        verdict = Verdict.REJECTED
        reason = (
            "the only support is an instruction embedded in untrusted log text; "
            "instruction authority is none, so the claim is rejected"
        )
    elif hard == "UNSAT_CONFLICT":
        verdict = Verdict.REJECTED
        reason = temporal.reason
    elif hard and hard.startswith(("MISSING_EVENT", "CROSS_CASE")):
        verdict = Verdict.REJECTED
        reason = hard
    elif temporal.outcome is TemporalOutcome.AMBIGUOUS_SKEW:
        verdict = Verdict.QUALIFIED_HYPOTHESIS
        reason = temporal.reason
    elif score <= qhat and tw == 1.0:
        verdict = Verdict.ACCEPTED
        reason = "score within the calibrated threshold and the temporal relation is entailed"
    else:
        verdict = Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE
        reason = f"s = {score:.3f} > qhat = {qhat:.3f}, so the claim abstains"

    if missing_predicates and verdict is Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE:
        reason = f"s = {score:.3f} > qhat = {qhat:.3f}; missing " + ", ".join(missing_predicates)

    injection_flags = [flag for event in cited.values() for flag in event.injection_flags]
    return ProofPackage(
        claim=claim,
        field_check=field,
        temporal=temporal,
        score=ScoreBreakdown(
            field_weight=field_weight,
            temporal_weight=tw,
            lexical_weight=lexical,
            type_weight=type_weight,
            score=score,
            alpha=alpha,
            qhat=qhat,
            hard_failure=hard,
        ),
        verdict=verdict,
        reason=reason,
        missing_predicates=missing_predicates,
        injection_flags=injection_flags,
    )
