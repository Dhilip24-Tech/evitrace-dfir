"""Typed data contracts for the EviTrace-DFIR prototype."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Every external boundary rejects unknown fields."""

    model_config = ConfigDict(extra="forbid")


class TimeBasis(StrEnum):
    UTC = "UTC"
    EXPLICIT_OFFSET = "EXPLICIT_OFFSET"
    UNKNOWN_LOCAL = "UNKNOWN_LOCAL"


class TemporalOutcome(StrEnum):
    ENTAILED = "ENTAILED"
    AMBIGUOUS_SKEW = "AMBIGUOUS_SKEW"
    UNSAT_CONFLICT = "UNSAT_CONFLICT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MISSING_EVENT = "MISSING_EVENT"


class Verdict(StrEnum):
    ACCEPTED = "ACCEPTED"
    QUALIFIED_HYPOTHESIS = "QUALIFIED_HYPOTHESIS"
    ABSTAIN_INSUFFICIENT_EVIDENCE = "ABSTAIN_INSUFFICIENT_EVIDENCE"
    REJECTED = "REJECTED"


class ClaimKind(StrEnum):
    OBSERVATION = "observation"
    TEMPORAL = "temporal"
    CAUSAL = "causal"
    NEGATIVE = "negative"


class ClaimType(StrEnum):
    RECORD_OBSERVATION = "record_observation"
    CROSS_EVENT_INFERENCE = "cross_event_inference"


class HostConfig(StrictModel):
    host: str
    skew_seconds: float = 5.0

    @field_validator("skew_seconds")
    @classmethod
    def _non_negative(cls, value: float) -> float:
        if value < 0:
            raise ValueError("skew_seconds must be non-negative")
        return value


class CaseConfig(StrictModel):
    case_id: str
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hosts: dict[str, HostConfig] = Field(default_factory=dict)
    default_skew_seconds: float = 5.0
    description: str = ""

    @field_validator("case_id")
    @classmethod
    def _safe_case_id(cls, value: str) -> str:
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not value or any(ch not in allowed for ch in value):
            raise ValueError("case_id may contain only letters, digits, dot, underscore and hyphen")
        return value


class ArtifactSpec(StrictModel):
    artifact_id: str
    path: str
    format: str = "jsonl"
    sha256: str | None = None
    description: str = ""


class ArtifactRecord(StrictModel):
    artifact_id: str
    path: str
    sha256: str
    bytes: int
    registered_at: datetime
    format: str = "jsonl"


class InjectionFlag(StrictModel):
    event_id: str
    field: str
    pattern: str
    excerpt: str


class EventRecord(StrictModel):
    event_id: str
    case_id: str
    host: str
    event_type: str
    timestamp: datetime
    time_basis: TimeBasis = TimeBasis.UTC
    precision_seconds: float = 1.0
    earliest_utc: datetime
    latest_utc: datetime
    fields: dict[str, Any] = Field(default_factory=dict)
    source_artifact: str
    source_line: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)
    envelope_id: str
    tainted: bool = False
    injection_flags: list[InjectionFlag] = Field(default_factory=list)

    @field_validator("precision_seconds")
    @classmethod
    def _positive_precision(cls, value: float) -> float:
        if value < 0:
            raise ValueError("precision_seconds must be non-negative")
        return value


class EvidenceEnvelope(StrictModel):
    envelope_id: str
    case_id: str
    artifact_id: str
    trust: str = "untrusted"
    instruction_authority: str = "none"
    tainted: bool = False
    markers: list[str] = Field(default_factory=list)


class TemporalAssertion(StrictModel):
    left_event_id: str
    right_event_id: str
    relation: str = "before"


class Claim(StrictModel):
    claim_id: str
    case_id: str
    text: str
    kind: ClaimKind = ClaimKind.OBSERVATION
    claim_type: ClaimType = ClaimType.CROSS_EVENT_INFERENCE
    subject: str = ""
    predicate: str = ""
    object: str = ""
    host: str = ""
    cited_event_ids: list[str] = Field(default_factory=list)
    required_predicates: list[str] = Field(default_factory=list)
    temporal: TemporalAssertion | None = None
    critical_identifiers: dict[str, str] = Field(default_factory=dict)


class FieldCheck(StrictModel):
    matched: dict[str, str] = Field(default_factory=dict)
    missing: list[str] = Field(default_factory=list)
    missing_event_ids: list[str] = Field(default_factory=list)
    cross_case_event_ids: list[str] = Field(default_factory=list)
    passed: bool = True


class TemporalProof(StrictModel):
    outcome: TemporalOutcome
    sat_lt: bool | None = None
    sat_ge: bool | None = None
    left_range: tuple[float, float] | None = None
    right_range: tuple[float, float] | None = None
    overlap_seconds: float | None = None
    unsat_core: list[str] = Field(default_factory=list)
    reason: str = ""


class ScoreBreakdown(StrictModel):
    field_weight: float
    temporal_weight: float
    lexical_weight: float
    type_weight: float
    score: float
    alpha: float
    qhat: float
    hard_failure: str | None = None


class ProofPackage(StrictModel):
    claim: Claim
    field_check: FieldCheck
    temporal: TemporalProof
    score: ScoreBreakdown
    verdict: Verdict
    reason: str
    missing_predicates: list[str] = Field(default_factory=list)
    injection_flags: list[InjectionFlag] = Field(default_factory=list)


class Signature(StrictModel):
    alg: str = "HS256"
    key_id: str
    value: str


class Certificate(StrictModel):
    cpc_version: str = "1.0"
    certificate_id: str
    case_id: str
    run_id: str
    issued_at: datetime
    proof: ProofPackage
    signature: Signature | None = None


class RunRecord(StrictModel):
    run_id: str
    case_id: str
    question_id: str
    question: str
    verdict: Verdict
    certificate_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CalibrationRecord(StrictModel):
    alpha: float
    qhat: float
    n: int
    rank: int
    scores: list[float]
    weights: dict[str, float]
    method: str = "split-conformal finite-sample corrected quantile"
    dataset_sha256: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    notes: str = ""


class QuestionSpec(StrictModel):
    id: str
    question: str
    expected: str = ""


class DemoManifest(StrictModel):
    case_id: str
    name: str
    description: str = ""
    hosts: dict[str, float] = Field(default_factory=dict)
    artifacts: list[ArtifactSpec] = Field(default_factory=list)
    questions: list[QuestionSpec] = Field(default_factory=list)
    expected_outcomes: dict[str, str] = Field(default_factory=dict)


class SearchHit(StrictModel):
    event_id: str
    score: float
    lexical_rank: int | None = None
    semantic_rank: int | None = None
    exact_match: bool = False
    excerpt: str = ""


class ReportResult(StrictModel):
    question_id: str
    question: str
    certificate: Certificate
