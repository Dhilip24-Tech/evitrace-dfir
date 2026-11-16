# Usage

This guide takes you from a clean clone to a verified certificate, then shows
how to use the same pipeline on your own normalized evidence.

For the design behind the commands, see [architecture.md](architecture.md).

## Requirements

- Python 3.12 or 3.13
- Git
- A shell (PowerShell, bash, zsh)
- No GPU, model download, or network service at runtime

## Install

```bash
git clone https://github.com/Dhilip24-Tech/evitrace-dfir.git
cd evitrace-dfir
python -m venv .venv
```

Activate the environment and install the package in editable mode:

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

**macOS / Linux:**

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

This installs the `evitrace` command. Verify it:

```bash
evitrace version
```

If PowerShell refuses to run the activation script, use
`.\.venv\Scripts\python.exe -m pip ...` and call the executable directly at
`.\.venv\Scripts\evitrace.exe`.

## Run the demo

The demo is reproducible and entirely synthetic. Run the three scripts in order:

```bash
python scripts/calibrate.py
python scripts/generate_demo_case.py
python scripts/run_demo.py
```

What each script does:

| Script | Output |
| --- | --- |
| `scripts/calibrate.py` | Computes `qhat` from a 20-row synthetic calibration split and writes `artifacts/conformal-qhat-alpha-0.05.json`. |
| `scripts/generate_demo_case.py` | Writes the synthetic evidence under `examples/demo_case/artifacts/` and the manifest under `datasets/manifests/`. |
| `scripts/run_demo.py` | Creates `workspace/demo`, ingests three artifacts, asks five questions, and writes the CLI transcript, Q3 certificate, and Markdown report under `artifacts/`. |

The expected verdicts are:

| ID | Verdict | Why |
| --- | --- | --- |
| Q1 | `ACCEPTED` | Same-host download → process order is entailed. |
| Q2 | `QUALIFIED_HYPOTHESIS` | Cross-host ranges overlap by 8.0 s. |
| Q3 | `ABSTAIN_INSUFFICIENT_EVIDENCE` | `file_read` and `network_bytes_out` predicates are absent. |
| Q4a | `REJECTED` | The timestomp order is `UNSAT_CONFLICT`. |
| Q4b | `REJECTED` | The only support is an instruction in untrusted log text. |

> [!IMPORTANT]
> `run_demo.py` deletes and recreates `workspace/demo` and rewrites the files in
> `artifacts/`. Re-running it changes timestamps, certificate IDs, and the
> per-case HMAC key. If you want to keep the IDs shown in the README and the
> landing page, do not re-run it. A fresh run is still valid; it is simply a
> different run.

The workspace is ignored by Git because it contains the case database and the
case key.

## Ask one question

```bash
evitrace ask \
  --case-id CASE-DEMO-2026 \
  --question "Was invoice_q4.exe downloaded and executed on WKSTN-04?" \
  --question-id Q1 \
  --alpha 0.05 \
  --workspace workspace/demo
```

The default output is the full proof block: verdict, claim ID, temporal
outcome and reason, interval ranges, unsat core when present, matched and
missing witnesses, score against `qhat`, injection flags, reason, and the
certificate ID.

Use `--compact` for the short form:

```text
ACCEPTED  claim_d3cf532608
  question    Was invoice_q4.exe downloaded and executed on WKSTN-04?
  temporal    ENTAILED, same-host skew cancels
  field       file_name, host, file_hash_sha256
  score       s = 0.150 <= qhat 0.420 (alpha 0.05)
  certificate cpc-CASE-DEMO-2026-run-20261115T091236-2608 (HS256)
```

Use `--json` to print the signed certificate, or `--cpc-out` to write it:

```bash
evitrace ask \
  --case-id CASE-DEMO-2026 \
  --question "Did the process exfiltrate customer_db.sqlite to 198.51.100.42?" \
  --question-id Q3 \
  --cpc-out artifacts/my-q3.json \
  --workspace workspace/demo
```

`--alpha` selects the calibration entry. The CLI looks in the case store first;
if no entry exists, it loads `artifacts/conformal-qhat-alpha-0.05.json` when
that file exists and the alpha matches. Otherwise it exits with an error asking
you to run `scripts/calibrate.py`.

## Verify a certificate

```bash
evitrace verify-cpc \
  --file artifacts/case-demo-2026-cpc.json \
  --case-id CASE-DEMO-2026 \
  --workspace workspace/demo
```

```text
VALID  cpc-CASE-DEMO-2026-run-20261115T091237-ad09
```

Verification loads the case key and recomputes the HMAC over the canonical
certificate payload. If a field was changed after signing, it prints `INVALID`
and exits with code 1.

## Create your own case

```bash
evitrace case create \
  --case-id CASE-LAB-01 \
  --name "Lab workstation review" \
  --description "Normalized exports from a single workstation" \
  --hosts WKSTN-01=5.0,FW-01=2.0 \
  --workspace ./workspace
```

Options:

| Option | Meaning |
| --- | --- |
| `--case-id` | Required. Also the directory name under `workspace/cases/`. |
| `--name` | Required. Human-readable case name. |
| `--description` | Optional free text stored in `case.json`. |
| `--hosts` | `HOST=skew_seconds` pairs, comma separated. A host without `=skew` uses the default. |
| `--calibration` | Optional calibration JSON. If omitted, `artifacts/conformal-qhat-alpha-0.05.json` is attached when present. |
| `--workspace` | Workspace root. Defaults to `EVITRACE_WORKSPACE` or `./workspace`. |

List cases:

```bash
evitrace case list --workspace ./workspace
```

## Ingest evidence

```bash
evitrace ingest \
  --case-id CASE-LAB-01 \
  --artifact ./exports/plaso.jsonl \
  --artifact-id plaso-export \
  --format jsonl \
  --sha256 <expected-sha256> \
  --workspace ./workspace
```

The `--sha256` check is optional but recommended. Without it, the file is hashed
at registration and re-hashed before reading; if it changed in between, ingestion
fails.

Accepted `--format` values:

| Value | Reader |
| --- | --- |
| `jsonl` (default) | One JSON object per line. |
| `json` | Treated as JSONL. Use one object per line. |
| `evtx` | Alias for JSONL, for EVTX-normalized exports. |
| `plaso` | Alias for JSONL, for Plaso-style exports. |
| `csv` | Header row plus flat records. |

The format labels are aliases for the two readers. They do not parse native
`.evtx` or Plaso storage files.

### JSONL record shape

```json
{
  "event_id": "EV-001",
  "host": "WKSTN-01",
  "event_type": "file_download",
  "timestamp": "2026-10-12T10:00:00Z",
  "time_basis": "UTC",
  "precision_seconds": 1.0,
  "fields": {
    "file_name": "invoice_q4.exe",
    "file_hash_sha256": "…"
  }
}
```

Field aliases:

| Canonical | Accepted keys |
| --- | --- |
| Event ID | `event_id`, `id`, `uuid`, `record_id` |
| Host | `host`, `hostname`, `host_name`, `computer`, `Computer`, `source_host`, `src_host` |
| Event type | `event_type`, `type`, `event`, `parser`, `EventType`, `action` |
| Timestamp | `timestamp`, `timestamp_utc`, `time`, `Time`, `datetime`, `@timestamp` |
| Precision | `precision_seconds`, `precision` |
| Time basis | `time_basis`, `basis` |

`fields` may be an object or a JSON-encoded object. `EventData` is merged into
`fields` when present. Top-level keys not consumed by the aliases are retained
in `fields`.

`time_basis` accepts `UTC`, `EXPLICIT_OFFSET`, or `UNKNOWN_LOCAL`. Unknown values
are an error. `UNKNOWN_LOCAL` widens the interval to the global UTC offset range
(`-14h` to `+12h`), so it is honest about the ambiguity rather than assuming a
timezone.

### CSV record shape

CSV rows are flat. Use header names that match the aliases above:

```csv
event_id,host,event_type,timestamp,action,src_ip,dst_ip,dst_port
EV-101,FW-01,firewall_block,2026-10-12T10:00:06Z,block,10.0.0.14,198.51.100.42,443
```

Non-alias columns become part of `fields`. Nested structures are not decoded
from CSV.

## Validate the case

```bash
evitrace validate-case --case-id CASE-LAB-01 --workspace ./workspace
```

This rehashes every registered artifact, checks that the FTS index covers every
event, checks that all events are scoped to the case, and prints taint flags. It
exits with code 1 when a check fails.

## Rebuild the index

```bash
evitrace index --case-id CASE-LAB-01 --workspace ./workspace
```

Ingestion maintains the index. Use this command after manual maintenance or to
rebuild the FTS5 index over the stored search text.

## Run a question set

```bash
evitrace evaluate \
  --case-id CASE-DEMO-2026 \
  --questions examples/demo_case/questions.json \
  --out artifacts/my-certificates.json \
  --workspace workspace/demo
```

The questions file is either a list of objects or an object with a `questions`
list:

```json
{
  "case_id": "CASE-LAB-01",
  "questions": [
    { "id": "Q1", "question": "Was invoice_q4.exe downloaded and executed on WKSTN-01?" }
  ]
}
```

`evaluate` always uses `alpha = 0.05`. It stores each run and can write a JSON
array of certificates. It does not compare the result with an `expected` field;
the expected values in the demo file are documentation.

## Render the report

```bash
evitrace report \
  --case-id CASE-DEMO-2026 \
  --workspace workspace/demo \
  --out artifacts/my-report.md
```

Without `--out`, the Markdown is printed to stdout. The report groups results
into supported observations, qualified hypotheses, temporal conflicts,
contradictory evidence, and abstentions with missing predicates. It also
includes case validation results and the spec targets, labelled as targets.

## Optional API

The API is a thin wrapper over the same planner, proof, and signing pipeline.

```powershell
$env:EVITRACE_API_TOKEN = "replace-with-a-long-random-value"
$env:EVITRACE_WORKSPACE = "./workspace/demo"
python -m uvicorn evitrace.api:create_app --factory --host 127.0.0.1 --port 8765
```

```bash
export EVITRACE_API_TOKEN="replace-with-a-long-random-value"
export EVITRACE_WORKSPACE="./workspace/demo"
python -m uvicorn evitrace.api:create_app --factory --host 127.0.0.1 --port 8765
```

The app refuses to start without `EVITRACE_API_TOKEN`. `GET /health` needs no
auth; the case routes require `Authorization: Bearer <token>`.

```bash
curl -s http://127.0.0.1:8765/health
```

```json
{"status":"ok","mode":"local-only"}
```

Ask a question:

```bash
curl -s -X POST http://127.0.0.1:8765/v1/cases/CASE-DEMO-2026/ask \
  -H "Authorization: Bearer $EVITRACE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question":"Was invoice_q4.exe downloaded and executed on WKSTN-04?","alpha":0.05}'
```

The response is the signed certificate JSON. Fetch a stored run:

```bash
curl -s http://127.0.0.1:8765/v1/cases/CASE-DEMO-2026/runs/<run_id> \
  -H "Authorization: Bearer $EVITRACE_API_TOKEN"
```

Status codes:

| Code | Meaning |
| --- | --- |
| `200` | Success. |
| `401` | Missing or invalid bearer token. |
| `404` | Unknown case or run. |
| `409` | The case has no calibration for the requested alpha. |
| `422` | The request body failed validation. |

The service has no TLS, user model, or rate limiting. Keep it on loopback.

## Environment variables

| Variable | Used by | Default | Notes |
| --- | --- | --- | --- |
| `EVITRACE_WORKSPACE` | CLI, API | `./workspace` | Overridden by `--workspace`. |
| `EVITRACE_API_TOKEN` | API | none | Required for the API. Generate a long random value. |

The application does not load `.env` automatically. Export variables in your
shell or set them in your process manager. `.env.example` documents the two
variables the code actually reads.

## Development checks

```bash
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
```

Or with `make`:

```bash
make test
make lint
make typecheck
```

## Troubleshooting

**`evitrace: command not found`**

The environment is not active, or the editable install did not complete. Run
`python -m pip install -e ".[dev]"` from the repository root and confirm
`evitrace version`.

**`error: no calibration for alpha=0.05`**

Run `python scripts/calibrate.py`, or create the case with `--calibration`
pointing at a calibration JSON with a matching alpha.

**`path escapes the allowed roots`**

The artifact is outside the current working directory and the case workspace
parent. Run the command from the repository root or move the artifact under an
allowed root. Paths are resolved before the check, so symlinks do not bypass it.

**`artifact hash mismatch`**

The `--sha256` value does not match the file on disk. Confirm the expected hash
and that the export was not modified after hashing.

**`EVITRACE_API_TOKEN must be set`**

The API has no default token by design. Set the variable before starting
Uvicorn.

**`case ... already exists`**

`case create` refuses to overwrite an existing database. Use a new case ID or
remove the workspace directory if it is disposable. Do not delete a case you
still need; the key is stored there.

**A question abstains that you expected to pass**

Check the full output, not only the verdict. The likely causes are a missing
required predicate, a critical identifier that did not resolve, or a score above
`qhat`. The certificate names the missing predicates. The planner also only
recognizes a fixed set of question shapes; see [architecture.md](architecture.md)
for the list.
