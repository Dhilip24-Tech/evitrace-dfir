"""Deterministic nonconformity score and split-conformal calibration."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from evitrace.models import CalibrationRecord, TemporalOutcome
from evitrace.store import quantile_scores

FEATURE_WEIGHTS = {"field": 0.40, "temporal": 0.30, "lexical": 0.20, "type": 0.10}


def temporal_weight(outcome: TemporalOutcome) -> float:
    if outcome in {TemporalOutcome.ENTAILED, TemporalOutcome.NOT_APPLICABLE}:
        return 1.0
    if outcome is TemporalOutcome.AMBIGUOUS_SKEW:
        return 0.5
    return 1.0  # UNSAT and MISSING are hard failures handled before scoring


def nonconformity(
    field_weight: float, temporal: float, lexical: float, type_weight: float
) -> float:
    support = (
        FEATURE_WEIGHTS["field"] * field_weight
        + FEATURE_WEIGHTS["temporal"] * temporal
        + FEATURE_WEIGHTS["lexical"] * lexical
        + FEATURE_WEIGHTS["type"] * type_weight
    )
    return round(1.0 - support, 6)


def calibrate(
    scores: list[float],
    alpha: float = 0.05,
    *,
    dataset: Any | None = None,
    notes: str = "",
) -> CalibrationRecord:
    qhat, n, rank = quantile_scores(scores, alpha)
    payload = json.dumps(dataset, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return CalibrationRecord(
        alpha=alpha,
        qhat=qhat,
        n=n,
        rank=rank,
        scores=sorted(scores),
        weights=FEATURE_WEIGHTS,
        dataset_sha256=hashlib.sha256(payload).hexdigest(),
        created_at=datetime.now(UTC),
        notes=notes,
    )
