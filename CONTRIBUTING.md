# Contributing

Thanks for taking the time to look at EviTrace-DFIR. This is a prototype with a
deliberately narrow scope, and focused changes are the easiest to review.

## Before you start

- Read [docs/architecture.md](docs/architecture.md) to understand the data/control
  plane split.
- For anything larger than a bug fix or documentation correction, open an issue
  first so the design can be discussed before code is written.
- Do not include real evidence, case databases, `key.bin` files, certificates
  from live investigations, or credentials in an issue or pull request.

Security reports do not belong in public issues. See [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Python 3.12 or 3.13 and Git.

```bash
git clone https://github.com/Dhilip24-Tech/evitrace-dfir.git
cd evitrace-dfir
python -m venv .venv
```

Activate the environment, then install the editable package with development
tools:

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

## Checks

Run the same checks CI runs before opening a pull request:

```bash
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
```

With `make`:

```bash
make test
make lint
make typecheck
```

If you changed formatting intentionally, run `python -m ruff format src tests
scripts` and include the result.

## What to work on

Good candidates:

- a new deterministic question shape with tests for its accepted, qualified, and
  abstaining paths;
- a new normalized-input adapter that produces the existing `EventRecord`
  contract;
- a temporal axiom with an unsat-core test;
- documentation that corrects a claim the code does not support;
- a test that reproduces a bug before the fix.

Please avoid:

- adding an LLM or a network dependency to the analysis path;
- adding a database server, queue, or service that breaks the one-case-one-SQLite
  model;
- widening the planner into free-form natural language without a proof path;
- changing the certificate format without a version bump and a migration note;
- presentation-only churn in the Python package.

## Code conventions

- Python `>=3.12,<3.14`; public functions carry type annotations.
- Pydantic v2 contracts with `extra="forbid"` at external boundaries.
- `ruff` with `line-length = 100`. No unused imports, bare `except:`, or mutable
  default arguments.
- Parameterized SQL only. Never format user input or artifact fields into SQL.
- Resolve paths through `evitrace.security.sandbox`.
- Do not add `shell=True`, `eval`, `exec`, or `pickle` to the pipeline.
- Keep the control plane free of raw event text as an instruction channel.

## Tests

- Unit tests live in `tests/unit`; API tests live in `tests/integration`.
- A behavior change needs a test that fails before it and passes after it.
- For temporal changes, include a case with an unsat core.
- For parser changes, include malformed input and a size or line-limit case.
- For taint changes, assert that the raw text is preserved and the flag is
  recorded.

The demo fixture is built in `tests/conftest.py`. Do not regenerate
`artifacts/` or `workspace/` to make a test pass; tests use temporary
workspaces.

## Demo artifacts

The files under `artifacts/` and the images under `docs/images/` are captured
from a specific local run. Re-running `scripts/run_demo.py` changes timestamps,
certificate IDs, and the per-case HMAC key, which invalidates the captured
screenshots and IDs in the documentation.

Only regenerate them when the change genuinely requires it, and update the
screenshots and any quoted IDs in the same pull request.

## Commit messages

Use a short imperative subject with a scope when it helps:

```text
feat(P2-T2): implement interval-aware timestamp normalizer
test(P5-T1): add Z3 clock-skew and timestomp unsat-core tests
fix(P3-T1): sanitize FTS5 tokens in the query planner
docs: correct the API token requirement
```

Keep the subject under about 72 characters. Explain the reason in the body when
it is not obvious. One logical change per commit is preferred.

## Pull requests

A pull request should:

- explain the problem and the chosen approach;
- list the commands you ran and their results;
- call out behavior changes, schema changes, or new dependencies;
- update documentation when the public surface changes;
- avoid unrelated formatting or refactoring;
- confirm that no secrets, case keys, or real evidence are included.

The pull request template includes the same checklist.

## Review

Reviews focus on correctness, proof integrity, and whether the change preserves
the separation between untrusted evidence and the control plane. A change that
makes the demo pass by weakening a check will not be merged.

There is no guaranteed response time. This is a prototype maintained on a
best-effort basis.
