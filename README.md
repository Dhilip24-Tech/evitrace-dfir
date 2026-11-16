# EviTrace-DFIR

Local, proof-carrying forensic timeline verification. This repository is a
working prototype built from the 53-page EviTrace-DFIR v1.0.0 design spec. It is
not a shipped product, and the benchmark numbers in the spec remain design
targets, not measured results.

The prototype demonstrates the spec's four diagnostic outcomes on the synthetic
`CASE-DEMO-2026`:

| Question | Outcome | Mechanism |
| --- | --- | --- |
| Q1 download then execution | `ACCEPTED` | same-host clock skew cancels; Z3 `ENTAILED` |
| Q2 outbound before firewall block | `QUALIFIED_HYPOTHESIS` | cross-host ±5 s ranges overlap by 8 s |
| Q3 customer database exfiltration | `ABSTAIN_INSUFFICIENT_EVIDENCE` | missing `file_read` and `network_bytes_out` predicates |
| Q4 backdated MFT | `REJECTED` | Z3 `UNSAT_CONFLICT` with an unsat core |
| Q4 User-Agent injection | `REJECTED` | untrusted instruction has no authority; IOC preserved |

## What is implemented

- Isolated SQLite case workspaces (WAL + FTS5), read-only artifact registration,
  SHA-256 provenance, and per-case HMAC keys.
- JSONL/CSV/EVTX-normalized/Plaso-style ingestion with interval timestamps,
  timezone uncertainty, and a 250 MB / 1 MB-line input sandbox.
- Taint isolation: passive prompt injections stay in the evidence, are flagged
  as IOCs, and never become control-plane instructions.
- Hybrid retrieval: FTS5 BM25, exact IOC/path/hash boost, and a bounded local
  hashing-vector cosine fallback. Every query is scoped by `case_id`.
- Z3 + Allen interval reasoning with per-host clock skew, same-host
  cancellation, cross-host ambiguity, and unsat cores.
- Deterministic field and predicate checks, the spec's nonconformity score,
  split-conformal calibration, selective answering, and signed JSON CPCs.
- CLI (`case create`, `ingest`, `validate-case`, `index`, `ask`, `report`,
  `evaluate`, `verify-cpc`), Markdown reports, and an optional loopback API.
- Tests for temporal overlap, skew cancellation, timestomping, missing-evidence
  abstention, injection taint isolation, CPC tampering, and API auth.

## Run it

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts\calibrate.py
.\.venv\Scripts\python.exe scripts\generate_demo_case.py
.\.venv\Scripts\python.exe scripts\run_demo.py
.\.venv\Scripts\python.exe -m pytest -q
```

The demo and calibration write:

- `artifacts/case-demo-2026-cli.txt`
- `artifacts/case-demo-2026-cpc.json`
- `artifacts/case-demo-2026-report.md`
- `artifacts/conformal-qhat-alpha-0.05.json`

## Safety

Zero network egress is the default. The API binds to `127.0.0.1` and requires a
bearer token with no default value. Evidence artifacts are hashed and never
rewritten. The pipeline has no `shell=True`, `eval`, `exec`, or `pickle`.

## Limits

This is a prototype. It does not ship the spec's 8B local model, the full
evaluation benchmark, or production hardening. The calibration split is
synthetic. The UI artifacts on the landing page are genuine outputs of this
local prototype, not screenshots of a shipped product.
