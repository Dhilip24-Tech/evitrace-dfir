"""Command-line interface for the EviTrace-DFIR prototype."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer

from evitrace import __version__
from evitrace.claims import prove_claim
from evitrace.cpc import certificate_json, issue_certificate, verify_certificate
from evitrace.ingest import ingest_artifact
from evitrace.models import (
    CalibrationRecord,
    CaseConfig,
    Certificate,
    HostConfig,
    QuestionSpec,
    RunRecord,
)
from evitrace.planner import plan_question
from evitrace.report import render_report
from evitrace.store import CaseStore, StoreError, load_calibration_file

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Local, proof-carrying forensic timeline verification prototype.",
)
case_app = typer.Typer(no_args_is_help=True, help="Create and inspect isolated cases.")
app.add_typer(case_app, name="case")

DEFAULT_CALIBRATION = Path("artifacts/conformal-qhat-alpha-0.05.json")


def workspace_of(value: str | None) -> Path:
    selected = value or os.environ.get("EVITRACE_WORKSPACE")
    if selected is None:
        selected = "./workspace"
    return Path(selected).resolve()


def open_case(case_id: str, workspace: str | None) -> CaseStore:
    try:
        return CaseStore.open(workspace_of(workspace), case_id)
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def resolve_calibration(store: CaseStore, alpha: float) -> CalibrationRecord:
    record = store.latest_calibration(alpha)
    if record is None and DEFAULT_CALIBRATION.exists():
        candidate = load_calibration_file(DEFAULT_CALIBRATION)
        if abs(candidate.alpha - alpha) < 1e-9:
            store.save_calibration(candidate)
            record = candidate
    if record is None:
        typer.echo(
            f"error: no calibration for alpha={alpha}; run scripts/calibrate.py first",
            err=True,
        )
        raise typer.Exit(code=2)
    return record


def _hosts(raw: str | None) -> dict[str, HostConfig]:
    hosts: dict[str, HostConfig] = {}
    if not raw:
        return hosts
    for part in raw.split(","):
        piece = part.strip()
        if not piece:
            continue
        if "=" in piece:
            host, skew = piece.split("=", 1)
            hosts[host.strip()] = HostConfig(host=host.strip(), skew_seconds=float(skew))
        else:
            hosts[piece] = HostConfig(host=piece)
    return hosts


@case_app.command("create")
def case_create(
    case_id: str = typer.Option(..., "--case-id"),
    name: str = typer.Option(..., "--name"),
    description: str = typer.Option("", "--description"),
    hosts: str = typer.Option("", "--hosts", help="HOST=skew,HOST=skew"),
    workspace: str | None = typer.Option(None, "--workspace"),
    calibration: Path | None = typer.Option(None, "--calibration"),
) -> None:
    config = CaseConfig(
        case_id=case_id,
        name=name,
        description=description,
        hosts=_hosts(hosts),
        default_skew_seconds=5.0,
    )
    try:
        store = CaseStore.create(workspace_of(workspace), config)
    except StoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    calibration_path = calibration or (
        DEFAULT_CALIBRATION if DEFAULT_CALIBRATION.exists() else None
    )
    if calibration_path and calibration_path.exists():
        record = load_calibration_file(calibration_path)
        store.save_calibration(record)
        typer.echo(
            f"case {case_id} created with calibration "
            f"qhat={record.qhat:.3f} alpha={record.alpha:.2f}"
        )
    else:
        typer.echo(f"case {case_id} created (no calibration attached)")
    typer.echo(f"workspace {store.case_dir}")


@case_app.command("list")
def case_list(workspace: str | None = typer.Option(None, "--workspace")) -> None:
    root = workspace_of(workspace) / "cases"
    if not root.exists():
        typer.echo("no cases")
        return
    for entry in sorted(root.iterdir()):
        config_path = entry / "case.json"
        if config_path.exists():
            config = CaseConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
            typer.echo(f"{config.case_id}\t{config.name}")


@app.command()
def ingest(
    case_id: str = typer.Option(..., "--case-id"),
    artifact: Path = typer.Option(..., "--artifact"),
    artifact_id: str = typer.Option(..., "--artifact-id"),
    fmt: str = typer.Option("jsonl", "--format"),
    sha256: str | None = typer.Option(None, "--sha256"),
    workspace: str | None = typer.Option(None, "--workspace"),
) -> None:
    store = open_case(case_id, workspace)
    try:
        stats = ingest_artifact(
            store,
            artifact,
            artifact_id=artifact_id,
            fmt=fmt,
            expected_sha256=sha256,
            roots=(Path.cwd(), store.workspace.parent),
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary converts all ingest failures
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"ingested {stats.events} events from {artifact_id} "
        f"({stats.tainted} tainted, {stats.injection_flags} injection flags, "
        f"hosts: {', '.join(stats.hosts)})"
    )


@app.command("validate-case")
def validate_case(
    case_id: str = typer.Option(..., "--case-id"),
    workspace: str | None = typer.Option(None, "--workspace"),
) -> None:
    store = open_case(case_id, workspace)
    result = store.validate_case()
    typer.echo(f"validating {case_id}")
    typer.echo(f"  events       {result['events']}")
    typer.echo(f"  artifacts    {len(store.artifacts())}")
    for check in result["checks"]:
        typer.echo(f"  check        {check}")
    for issue in result["issues"]:
        typer.echo(f"  issue        {issue}")
    for flag in result["injection_flags"]:
        typer.echo(
            f"  injection    {flag['event_id']} field {flag['field']} matched {flag['pattern']}"
        )
    typer.echo(f"  status       {'PASS' if result['ok'] else 'FAIL'}")
    if not result["ok"]:
        raise typer.Exit(code=1)


@app.command()
def index(
    case_id: str = typer.Option(..., "--case-id"),
    workspace: str | None = typer.Option(None, "--workspace"),
) -> None:
    store = open_case(case_id, workspace)
    count = store.rebuild_index()
    typer.echo(f"indexed {count} events for {case_id} (FTS5 BM25)")


def _print_proof(case_id: str, question_id: str, question: str, cert: Certificate) -> None:
    proof = cert.proof
    typer.echo(f"{proof.verdict.value}  {proof.claim.claim_id}")
    typer.echo(f"  case        {case_id}")
    typer.echo(f"  question    {question}")
    typer.echo(f"  temporal    {proof.temporal.outcome.value}: {proof.temporal.reason}")
    if proof.temporal.left_range and proof.temporal.right_range:
        left = proof.temporal.left_range
        right = proof.temporal.right_range
        typer.echo(
            f"  ranges      [{left[0]:.1f}, {left[1]:.1f}] vs [{right[0]:.1f}, {right[1]:.1f}]"
        )
    if proof.temporal.unsat_core:
        typer.echo(f"  unsat core  {', '.join(proof.temporal.unsat_core)}")
    typer.echo(
        f"  field       matched {len(proof.field_check.matched)}"
        + (f", missing {', '.join(proof.field_check.missing)}" if proof.field_check.missing else "")
    )
    typer.echo(
        f"  score       s = {proof.score.score:.3f}; qhat = {proof.score.qhat:.3f}; "
        f"alpha = {proof.score.alpha:.2f}"
    )
    if proof.missing_predicates:
        typer.echo(f"  missing     {', '.join(proof.missing_predicates)}")
    for flag in proof.injection_flags:
        typer.echo(f"  injection   {flag.event_id} {flag.field}: {flag.excerpt}")
    typer.echo(f"  reason      {proof.reason}")
    typer.echo(f"  certificate {cert.certificate_id}")
    if cert.signature:
        typer.echo(f"  signature   {cert.signature.alg} {cert.signature.key_id}")


def _print_compact(certificate: Certificate, question: str) -> None:
    proof = certificate.proof
    temporal = proof.temporal.outcome.value
    if (
        proof.temporal.outcome.value == "AMBIGUOUS_SKEW"
        and proof.temporal.overlap_seconds is not None
    ):
        temporal += f", overlap {proof.temporal.overlap_seconds:.1f}s"
    elif proof.temporal.outcome.value == "ENTAILED":
        temporal += ", same-host skew cancels"
    typer.echo(f"{proof.verdict.value}  {proof.claim.claim_id}")
    typer.echo(f"  question    {question}")
    typer.echo(f"  temporal    {temporal}")
    typer.echo(f"  field       {', '.join(proof.field_check.matched) or 'none'}")
    relation = "<=" if proof.score.score <= proof.score.qhat else ">"
    typer.echo(
        f"  score       s = {proof.score.score:.3f} {relation} qhat {proof.score.qhat:.3f} "
        f"(alpha {proof.score.alpha:.2f})"
    )
    if proof.missing_predicates:
        typer.echo(f"  missing     {', '.join(proof.missing_predicates)}")
    if proof.temporal.unsat_core:
        typer.echo(f"  unsat core  {', '.join(proof.temporal.unsat_core)}")
    for flag in proof.injection_flags:
        typer.echo(f"  injection   {flag.event_id} {flag.field}: {flag.excerpt}")
    if certificate.signature:
        typer.echo(f"  certificate {certificate.certificate_id} ({certificate.signature.alg})")


@app.command()
def ask(
    case_id: str = typer.Option(..., "--case-id"),
    question: str = typer.Option(..., "--question"),
    alpha: float = typer.Option(0.05, "--alpha"),
    question_id: str = typer.Option("Q", "--question-id"),
    workspace: str | None = typer.Option(None, "--workspace"),
    json_out: bool = typer.Option(False, "--json", help="Print the full signed CPC JSON"),
    cpc_out: Path | None = typer.Option(None, "--cpc-out"),
    compact: bool = typer.Option(False, "--compact", help="Print the short evidence block"),
) -> None:
    store = open_case(case_id, workspace)
    calibration = resolve_calibration(store, alpha)
    claim = plan_question(question, store)
    proof = prove_claim(claim, store, qhat=calibration.qhat, alpha=alpha)
    run_id = f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{proof.claim.claim_id[-4:]}"
    certificate = issue_certificate(store, run_id, proof)
    store.save_run(
        RunRecord(
            run_id=run_id,
            case_id=case_id,
            question_id=question_id,
            question=question,
            verdict=proof.verdict,
            certificate_id=certificate.certificate_id,
        ),
        certificate,
    )
    if cpc_out:
        cpc_out.parent.mkdir(parents=True, exist_ok=True)
        cpc_out.write_text(certificate_json(certificate) + "\n", encoding="utf-8")
    if json_out:
        typer.echo(certificate_json(certificate))
        return
    if compact:
        _print_compact(certificate, question)
        return
    _print_proof(case_id, question_id, question, certificate)


@app.command()
def evaluate(
    case_id: str = typer.Option(..., "--case-id"),
    questions: Path = typer.Option(..., "--questions"),
    workspace: str | None = typer.Option(None, "--workspace"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    store = open_case(case_id, workspace)
    payload = json.loads(questions.read_text(encoding="utf-8"))
    specs = [QuestionSpec.model_validate(item) for item in payload.get("questions", payload)]
    certificates: list[Certificate] = []
    for spec in specs:
        calibration = resolve_calibration(store, 0.05)
        claim = plan_question(spec.question, store)
        proof = prove_claim(claim, store, qhat=calibration.qhat, alpha=0.05)
        run_id = (
            f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-"
            f"{spec.id.lower()}-{proof.claim.claim_id[-4:]}"
        )
        certificate = issue_certificate(store, run_id, proof)
        store.save_run(
            RunRecord(
                run_id=run_id,
                case_id=case_id,
                question_id=spec.id,
                question=spec.question,
                verdict=proof.verdict,
                certificate_id=certificate.certificate_id,
            ),
            certificate,
        )
        certificates.append(certificate)
        typer.echo(f"{spec.id}  {proof.verdict.value:<31} {spec.question}")
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps([cert.model_dump(mode="json") for cert in certificates], indent=2) + "\n",
            encoding="utf-8",
        )
        typer.echo(f"wrote {out}")


@app.command()
def report(
    case_id: str = typer.Option(..., "--case-id"),
    workspace: str | None = typer.Option(None, "--workspace"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    store = open_case(case_id, workspace)
    certificates = [
        cert for run in store.runs() if (cert := store.certificate(run.run_id)) is not None
    ]
    if not certificates:
        typer.echo("error: no runs to report", err=True)
        raise typer.Exit(code=2)
    markdown = render_report(case_id, certificates, validation=store.validate_case())
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
        typer.echo(f"wrote {out} ({len(certificates)} certificates)")
    else:
        typer.echo(markdown)


@app.command("verify-cpc")
def verify_cpc(
    file: Path = typer.Option(..., "--file"),
    case_id: str = typer.Option(..., "--case-id"),
    workspace: str | None = typer.Option(None, "--workspace"),
) -> None:
    store = open_case(case_id, workspace)
    certificate = Certificate.model_validate_json(file.read_text(encoding="utf-8"))
    valid = verify_certificate(certificate, store.key_bytes())
    typer.echo(f"{'VALID' if valid else 'INVALID'}  {certificate.certificate_id}")
    if not valid:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    typer.echo(f"evitrace {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
