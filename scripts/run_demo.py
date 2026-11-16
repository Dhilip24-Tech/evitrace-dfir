"""Run the real CLI pipeline against CASE-DEMO-2026 and capture artifacts."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)
WORKSPACE = ROOT / "workspace" / "demo"
OUT = ROOT / "artifacts"
QUESTIONS = ROOT / "examples" / "demo_case" / "questions.json"
MANIFEST = ROOT / "datasets" / "manifests" / "case_demo_2026.yaml"


def display(args: list[str]) -> str:
    return "evitrace " + " ".join(shlex.quote(part) for part in args[3:])


def run(args: list[str], transcript: list[str]) -> str:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [str(PYTHON), "-m", "evitrace.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    transcript.append(f"$ {display([str(PYTHON), '-m', 'evitrace.cli', *args])}")
    if result.stdout:
        transcript.append(result.stdout.rstrip("\n"))
    if result.stderr:
        transcript.append(result.stderr.rstrip("\n"))
    transcript.append("")
    if result.returncode != 0:
        command = display([str(PYTHON), "-m", "evitrace.cli", *args])
        print(f"command failed ({result.returncode}): {command}")
        print(result.stdout)
        print(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def main() -> None:
    if not PYTHON.exists():
        raise SystemExit(f"missing venv interpreter: {PYTHON}")
    OUT.mkdir(parents=True, exist_ok=True)
    if WORKSPACE.exists():
        shutil.rmtree(WORKSPACE)

    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    questions = json.loads(QUESTIONS.read_text(encoding="utf-8"))["questions"]
    transcript: list[str] = [
        "# EviTrace-DFIR CASE-DEMO-2026 · captured CLI transcript",
        "# Local prototype build v0.1.0. Synthetic evidence. No benchmark result is claimed.",
        "",
    ]

    base = ["--workspace", str(WORKSPACE)]
    run(
        [
            "case",
            "create",
            "--case-id",
            "CASE-DEMO-2026",
            "--name",
            "Spear-phishing download to blocked egress",
            "--description",
            manifest["description"],
            "--hosts",
            "WKSTN-04=5.0,FW-EDGE-01=5.0",
            *base,
        ],
        transcript,
    )
    for artifact in manifest["artifacts"]:
        run(
            [
                "ingest",
                "--case-id",
                "CASE-DEMO-2026",
                "--artifact",
                artifact["path"],
                "--artifact-id",
                artifact["artifact_id"],
                "--format",
                artifact["format"],
                "--sha256",
                artifact["sha256"],
                *base,
            ],
            transcript,
        )
    run(["validate-case", "--case-id", "CASE-DEMO-2026", *base], transcript)
    run(["index", "--case-id", "CASE-DEMO-2026", *base], transcript)

    for spec in questions:
        extra: list[str] = []
        if spec["id"] == "Q3":
            extra = ["--cpc-out", str(OUT / "case-demo-2026-cpc.json")]
        run(
            [
                "ask",
                "--case-id",
                "CASE-DEMO-2026",
                "--question",
                spec["question"],
                "--question-id",
                spec["id"],
                "--alpha",
                "0.05",
                "--compact",
                *extra,
                *base,
            ],
            transcript,
        )

    run(
        [
            "report",
            "--case-id",
            "CASE-DEMO-2026",
            "--out",
            str(OUT / "case-demo-2026-report.md"),
            *base,
        ],
        transcript,
    )

    (OUT / "case-demo-2026-cli.txt").write_text("\n".join(transcript) + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'case-demo-2026-cli.txt'}")
    for path in (
        OUT / "case-demo-2026-cpc.json",
        OUT / "case-demo-2026-report.md",
    ):
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
