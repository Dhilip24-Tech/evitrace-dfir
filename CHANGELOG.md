# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project aims to follow [Semantic Versioning](https://semver.org/), with the
caveat that it is still a prototype and the public surface may change between
minor versions.

## [Unreleased]

### Added

- Repository presentation: README, banner, logo, architecture diagram, social
  preview, and genuine screenshots from the captured demo.
- Documentation for architecture, usage, and the security model under `docs/`.
- Contribution guide, code of conduct, security policy, changelog, editor
  configuration, issue templates, and pull request template.
- GitHub Actions workflow running ruff, mypy, and pytest on Python 3.12 and 3.13.
- Apache-2.0 `LICENSE` file matching the license already declared in
  `pyproject.toml`.

### Changed

- `Makefile` is now cross-platform and its `site` target serves the static
  landing page locally instead of invoking design tooling.
- `scripts/run_demo.py` uses the current interpreter instead of a hard-coded
  Windows virtualenv path.
- `.env.example` lists only the environment variables the code reads.
- Type annotations were tightened so `mypy src` passes without behavior changes.

### Fixed

- Missing `types-python-dateutil` development stub that prevented strict type
  checking.
- The API request model now rejects unknown fields with `extra="forbid"`,
  matching the documented contract.

## [0.1.0] - 2026-11-16

### Added

- Initial prototype of the EviTrace-DFIR v1.0.0 design.
- Per-case SQLite workspace with WAL, FTS5, provenance, runs, calibration, and
  audit tables.
- JSONL and CSV ingestion with interval timestamps and passive prompt-injection
  detection.
- Deterministic question planner for download-then-execute, cross-host ordering,
  exfiltration predicates, timestomping, and injection-authority questions.
- Z3 temporal model with per-host clock skew, precedence axioms, and unsat cores.
- Split-conformal calibration and the selective-answer verdict gate.
- HMAC-SHA256 Claim Proof Certificates with a verification command.
- Markdown report grouped by verdict category.
- Optional loopback FastAPI service with bearer-token authentication.
- Synthetic `CASE-DEMO-2026` evidence, captured CLI transcript, certificate, and
  report.
- Static landing page presenting the captured run.

[Unreleased]: https://github.com/Dhilip24-Tech/evitrace-dfir/commits/main
[0.1.0]: https://github.com/Dhilip24-Tech/evitrace-dfir/commits/main
