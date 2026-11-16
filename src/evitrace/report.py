"""Markdown report exporter."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from evitrace.models import Certificate, Verdict

TARGETS = (
    "Unsupported accepted claims ≤5% at α=0.05 (target)",
    "Supported answer coverage ≥75% (target)",
    "Abstention precision ≥90% (target)",
    "TOR egress 0% and injection success 0% on 50+ payloads (target)",
    "50k events <20s, median query <4.5s, ≤6GB RAM (target)",
)


def _bullet(cert: Certificate, index: int) -> str:
    proof = cert.proof
    lines = [
        f"{index}. **{proof.verdict.value}** · {proof.claim.text}",
        f"   - reason: {proof.reason}",
        f"   - temporal: {proof.temporal.outcome.value}",
        f"   - score: s={proof.score.score:.3f} · qhat={proof.score.qhat:.3f} · "
        f"α={proof.score.alpha:.2f}",
    ]
    if proof.missing_predicates:
        lines.append(f"   - missing: {', '.join(proof.missing_predicates)}")
    if proof.temporal.overlap_seconds is not None:
        lines.append(f"   - overlap: {proof.temporal.overlap_seconds:.1f}s")
    if proof.temporal.unsat_core:
        lines.append(f"   - unsat core: {', '.join(proof.temporal.unsat_core)}")
    lines.append(f"   - certificate: `{cert.certificate_id}`")
    return "\n".join(lines)


def render_report(
    case_id: str,
    certificates: list[Certificate],
    *,
    generated_at: datetime | None = None,
    validation: dict[str, Any] | None = None,
) -> str:
    now = generated_at or datetime.now(UTC)
    counts = Counter(cert.proof.verdict for cert in certificates)
    accepted = [cert for cert in certificates if cert.proof.verdict is Verdict.ACCEPTED]
    qualified = [
        cert for cert in certificates if cert.proof.verdict is Verdict.QUALIFIED_HYPOTHESIS
    ]
    abstained = [
        cert for cert in certificates if cert.proof.verdict is Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE
    ]
    rejected = [cert for cert in certificates if cert.proof.verdict is Verdict.REJECTED]
    conflicts = [cert for cert in rejected if cert.proof.temporal.outcome.value == "UNSAT_CONFLICT"]
    other_rejected = [cert for cert in rejected if cert not in conflicts]
    injections = [flag for cert in certificates for flag in cert.proof.injection_flags]

    lines = [
        f"# EviTrace-DFIR report · {case_id}",
        "",
        f"Generated {now.isoformat()} from a local prototype run. "
        "Every accepted claim carries a signed CPC; unsupported claims abstain.",
        "",
        "## Run summary",
        "",
        f"- Questions answered: {len(certificates)}",
        f"- Accepted: {counts[Verdict.ACCEPTED]}",
        f"- Qualified hypotheses: {counts[Verdict.QUALIFIED_HYPOTHESIS]}",
        f"- Abstained: {counts[Verdict.ABSTAIN_INSUFFICIENT_EVIDENCE]}",
        f"- Rejected: {counts[Verdict.REJECTED]}",
        "",
    ]
    if validation:
        lines.extend(
            [
                "## Case validation",
                "",
                f"- Status: {'PASS' if validation.get('ok') else 'FAIL'}",
                f"- Events: {validation.get('events', 0)}",
                f"- Tainted events preserved: {validation.get('tainted', 0)}",
                "",
            ]
        )
        for check in validation.get("checks", []):
            lines.append(f"- {check}")
        for issue in validation.get("issues", []):
            lines.append(f"- ISSUE: {issue}")
        lines.append("")

    def add_section(title: str, items: list[Certificate], empty: str) -> None:
        lines.extend([f"## {title}", ""])
        if not items:
            lines.extend([empty, ""])
            return
        for index, cert in enumerate(items, start=1):
            lines.append(_bullet(cert, index))
        lines.append("")

    add_section("Supported observations", accepted, "None in this run.")
    add_section("Qualified hypotheses", qualified, "None in this run.")
    add_section("Temporal conflicts", conflicts, "None in this run.")
    add_section("Contradictory evidence and rejected claims", other_rejected, "None in this run.")
    add_section(
        "Abstentions and missing predicates",
        abstained,
        "None in this run.",
    )
    lines.extend(["## Injection IOCs neutralized", ""])
    if injections:
        for flag in injections:
            lines.append(
                f"- `{flag.event_id}` field `{flag.field}` matched **{flag.pattern}**: "
                f"“{flag.excerpt}”"
            )
        lines.append("")
        lines.append(
            "These strings are preserved as evidence. The control plane has no instruction "
            "channel from event fields, so they cannot alter a verdict."
        )
    else:
        lines.append("No injection markers found in the cited evidence.")
    lines.extend(["", "## Targets", ""])
    lines.append("Spec metrics are design targets, not measured results:")
    lines.append("")
    for target in TARGETS:
        lines.append(f"- {target}")
    lines.extend(
        [
            "",
            "---",
            "",
            "Prototype build v0.1.0, Apache-2.0. Zero egress; evidence remains read-only.",
            "",
        ]
    )
    return "\n".join(lines)
