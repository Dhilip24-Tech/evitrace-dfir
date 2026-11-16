"""Calibrate the selective-answering threshold on the synthetic pilot split."""

from __future__ import annotations

import json
from pathlib import Path

from evitrace.calibration import calibrate, nonconformity

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "conformal-qhat-alpha-0.05.json"

# Synthetic pilot calibration split. Each row records the four feature weights
# and whether the claim was ground-truth supported. Scores use the production
# nonconformity function; the quantile is computed, not typed in.
ENTRIES = [
    {"id": "CAL-01", "field": 1.0, "temporal": 1.0, "lexical": 0.95, "type": 0.5, "label": 1},
    {"id": "CAL-02", "field": 1.0, "temporal": 1.0, "lexical": 0.85, "type": 1.0, "label": 1},
    {"id": "CAL-03", "field": 0.9, "temporal": 1.0, "lexical": 0.90, "type": 0.5, "label": 1},
    {"id": "CAL-04", "field": 1.0, "temporal": 1.0, "lexical": 0.70, "type": 0.5, "label": 1},
    {"id": "CAL-05", "field": 0.8, "temporal": 1.0, "lexical": 0.80, "type": 0.5, "label": 1},
    {"id": "CAL-06", "field": 0.75, "temporal": 1.0, "lexical": 0.75, "type": 1.0, "label": 1},
    {"id": "CAL-07", "field": 0.6, "temporal": 1.0, "lexical": 0.80, "type": 1.0, "label": 1},
    {"id": "CAL-08", "field": 0.75, "temporal": 0.5, "lexical": 0.90, "type": 0.5, "label": 1},
    {"id": "CAL-09", "field": 0.6, "temporal": 0.5, "lexical": 0.90, "type": 1.0, "label": 1},
    {"id": "CAL-10", "field": 0.5, "temporal": 1.0, "lexical": 0.80, "type": 1.0, "label": 1},
    {"id": "CAL-11", "field": 0.5, "temporal": 0.5, "lexical": 0.75, "type": 1.0, "label": 0},
    {"id": "CAL-12", "field": 0.4, "temporal": 1.0, "lexical": 0.50, "type": 1.0, "label": 0},
    {"id": "CAL-13", "field": 1.0, "temporal": 0.5, "lexical": 0.50, "type": 0.5, "label": 0},
    {"id": "CAL-14", "field": 0.3, "temporal": 1.0, "lexical": 0.80, "type": 1.0, "label": 0},
    {"id": "CAL-15", "field": 0.5, "temporal": 0.5, "lexical": 0.70, "type": 1.0, "label": 0},
    {"id": "CAL-16", "field": 0.5, "temporal": 0.5, "lexical": 0.65, "type": 1.0, "label": 0},
    {"id": "CAL-17", "field": 0.5, "temporal": 0.5, "lexical": 0.65, "type": 1.0, "label": 0},
    {"id": "CAL-18", "field": 0.5, "temporal": 0.5, "lexical": 0.65, "type": 1.0, "label": 0},
    {"id": "CAL-19", "field": 0.9, "temporal": 1.0, "lexical": 0.90, "type": 0.5, "label": 1},
    {"id": "CAL-20", "field": 0.8, "temporal": 1.0, "lexical": 0.80, "type": 1.0, "label": 1},
]


def main() -> None:
    scores = [
        nonconformity(row["field"], row["temporal"], row["lexical"], row["type"]) for row in ENTRIES
    ]
    record = calibrate(
        scores,
        0.05,
        dataset=ENTRIES,
        notes=(
            "Synthetic pilot split for the local prototype. The threshold is computed by "
            "finite-sample corrected split conformal, not copied from the spec. It is not a "
            "benchmark result."
        ),
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    print(
        f"calibration: n={record.n} rank={record.rank} qhat={record.qhat:.3f} alpha={record.alpha}"
    )
    print(f"max calibration score: {max(scores):.3f}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
