from __future__ import annotations

from evitrace.calibration import FEATURE_WEIGHTS, calibrate, nonconformity, temporal_weight
from evitrace.models import TemporalOutcome
from evitrace.store import quantile_scores


def test_nonconformity_formula() -> None:
    assert nonconformity(1.0, 1.0, 1.0, 0.5) == 0.05
    assert nonconformity(0.0, 0.5, 0.2, 0.5) == 0.76
    assert abs(sum(FEATURE_WEIGHTS.values()) - 1.0) < 1e-9


def test_temporal_weights() -> None:
    assert temporal_weight(TemporalOutcome.ENTAILED) == 1.0
    assert temporal_weight(TemporalOutcome.AMBIGUOUS_SKEW) == 0.5
    assert temporal_weight(TemporalOutcome.NOT_APPLICABLE) == 1.0


def test_conformal_quantile_uses_finite_sample_rank() -> None:
    scores = [i / 100 for i in range(1, 21)]  # 0.01 .. 0.20
    qhat, n, rank = quantile_scores(scores, 0.05)
    assert n == 20
    assert rank == 20
    assert qhat == 0.20
    qhat_90, _, rank_90 = quantile_scores(scores, 0.10)
    assert rank_90 == 19
    assert qhat_90 == 0.19


def test_calibration_record_is_deterministic() -> None:
    scores = [0.05, 0.1, 0.2, 0.3, 0.42]
    first = calibrate(scores, 0.05, dataset={"rows": scores})
    second = calibrate(scores, 0.05, dataset={"rows": scores})
    assert first.qhat == second.qhat
    assert first.dataset_sha256 == second.dataset_sha256
