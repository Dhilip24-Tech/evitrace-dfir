# AGENTS.md — Operational Rules for EviTrace-DFIR

This workspace builds a local prototype of the EviTrace-DFIR design spec (v1.0.0).
The prototype is not a shipped product. Benchmark numbers in the spec are design
targets, not measured results.

## 1. Global skill and workflow rule

- Use the selected Hallmark skills automatically whenever a task matches what a
  skill does (for example UI design, documents, security review, testing).
- Do not stop after a phase in this session. Execute Phase 0 through the demo and
  website integration continuously, fixing failures along the way.
- Keep the Control Plane (`planner`, `deterministic`, `temporal`, `calibration`,
  `cpc`) strictly decoupled from the Quarantined Data Plane (`ingest`, raw event
  text). Untrusted log content never becomes an instruction.

## 2. Coding and architecture standards

- **Language:** Python `>=3.12,<3.14`. Public functions carry type annotations.
- **Data contracts:** Pydantic v2 with `extra="forbid"` for external inputs, LLM
  outputs, API requests/responses and proof certificates.
- **Formatting:** `ruff` with `line-length = 100`. No unused imports, bare
  `except:`, or mutable default arguments.
- **Modularity:** One SQLite database per case. All queries are parameterized.
  All event reads validate `case_id`.

## 3. Mandatory security rules

- **No hardcoded secrets.** Per-case HMAC keys are generated with
  `secrets.token_bytes(32)` and stored beside the case database.
- **Parameterized SQL only.** Never format user queries or artifact fields into
  SQL strings.
- **Path and input validation.** Resolve paths through `evitrace.security.sandbox`
  and enforce file-size and line-length limits on parsers.
- **Least privilege and zero egress.** No `shell=True`, `eval`, `exec`, `pickle`,
  or unrestricted network calls in the analysis pipeline. The API binds to
  `127.0.0.1`.
- **Read-only evidence.** Registered artifact files are never modified, renamed
  or deleted.
- **Taint isolation.** Passive prompt injections are preserved verbatim as evidence,
  flagged as IOCs, and stripped of instruction authority.

## 4. Commit conventions

- `feat(P2-T2): implement interval-aware timestamp normalizer`
- `test(P5-T1): add Z3 clock-skew and timestomp unsat-core tests`
- `fix(P3-T1): sanitize FTS5 tokens in the query planner`

## 5. How to run verification and tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe scripts\run_demo.py
```

## 6. Reporting

Every claim carries its proof or abstains. The demo report separates supported
observations, qualified hypotheses, temporal conflicts, contradictory evidence,
and abstentions with missing predicates. Spec target metrics stay labelled as
design targets.
