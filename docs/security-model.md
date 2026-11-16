# Security model

This document describes what the prototype protects, how it protects it, and
where the protection stops. It is written for someone who may run the tool
against real evidence.

EviTrace-DFIR is a local analysis prototype. It is not a hardened evidence
management system, and it does not replace chain-of-custody procedures.

## Scope and assumptions

The model assumes:

- the analyst runs the tool on a trusted workstation, under their own OS
  account;
- the case workspace is on a local disk with appropriate filesystem
  permissions;
- evidence exports are already acquired by a separate, trusted process;
- the analyst understands that synthetic demo data is not evidence.

The model does **not** assume that evidence content is trustworthy. Hostnames,
file names, User-Agent strings, and every other field in an export are treated
as untrusted input.

## Assets

| Asset | Why it matters |
| --- | --- |
| Source evidence files | Must remain unchanged for provenance and legal defensibility. |
| Case database (`case.db`) | Contains normalized events, raw records, runs, and certificates. |
| Case key (`key.bin`) | Signs and verifies certificates for one case. |
| Certificates (CPCs) | Carry the proof attached to a verdict. |
| Reports | Summarize verdicts and are often the artifact a reviewer reads. |
| Workspace path | Defines which files the tool may read. |

## Trust boundaries

```text
untrusted evidence exports
        │
        ▼
┌───────────────────────────────┐
│ sandbox + taint scan          │  path, size, line, and content checks
└───────────────┬───────────────┘
                │ normalized EventRecord values
                ▼
┌───────────────────────────────┐
│ deterministic control plane   │  no instruction channel from raw text
└───────────────┬───────────────┘
                │ signed certificate
                ▼
┌───────────────────────────────┐
│ CLI / loopback API / report   │  local operator surface
└───────────────────────────────┘
```

The important boundary is between raw text and the control plane. The planner
reads normalized fields and retrieval hits. It never executes or follows text
from an event.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Path traversal or symlink escape | `safe_resolve_path` resolves the path and requires it to remain under an allowed root. | A deliberately misconfigured allowed root still grants access to that root. |
| Oversized file or line | 250 MB per artifact; 1,000,000 characters per line. | Large but legal inputs can still consume memory and time. |
| Artifact modified after acquisition | SHA-256 recorded at registration; optional expected hash; re-hash before ingestion; `validate-case` re-verifies. | The tool cannot prevent a user with filesystem access from changing the source after verification. |
| SQL injection | All SQL uses parameters. FTS tokens are quoted and embedded quotes escaped before `MATCH`. | SQLite itself is trusted. |
| Cross-case data leakage | One database per case; every event read validates `case_id`; cited events return cross-case IDs explicitly and the claim is rejected. | A user who can read the workspace can read every case on disk. |
| Prompt injection in evidence | Passive markers are recorded, raw text is preserved, no instruction channel exists, and a negative claim that cites a tainted record is rejected. | Detection is pattern-based. An injection that matches no pattern is still untrusted text, but it is not flagged. |
| Forged or modified certificate | HMAC-SHA256 over canonical JSON; `hmac.compare_digest` during verification. | Anyone with the case key can forge a certificate. HMAC is symmetric and provides no non-repudiation. |
| Secret leakage through Git | No hardcoded secrets; `.env`, `workspace/`, and `*.db` are ignored; key generated per case with `secrets.token_bytes(32)`. | A user can still force-add a workspace or copy a key into a commit. |
| Arbitrary code execution from evidence | No `shell=True`, `eval`, `exec`, or `pickle` in the analysis pipeline. Parsers read data only. | A vulnerability in a dependency remains possible; dependencies are pinned by range, not vendored. |
| Outbound network calls | The analysis path makes no network calls. The optional API binds to `127.0.0.1`. | The API is a local HTTP service and has no TLS, rate limiting, or user model. |
| Unauthorized API use | `EVITRACE_API_TOKEN` is required, has no default, and is compared with `hmac.compare_digest`. | A token on a shared machine can be read by another local user; there is no rotation or audit of API callers. |
| Denial of service through question input | API question length is capped at 2,000 characters; alpha must be in `(0, 1)`. | CLI input is not length-capped; it is a local operator surface. |
| Key loss | The key is stored in `key.bin` beside the case database. | Losing the workspace loses the ability to verify that case's certificates. There is no recovery or escrow. |

## Evidence handling

### Read-only by construction

Registration resolves and hashes the file but never opens it for writing.
Ingestion opens it for reading only. The tool does not rename, move, or delete
source artifacts.

This is a code-level guarantee, not an OS-level one. If another process modifies
the file, `validate-case` will report a hash mismatch; it cannot undo the change.

### Provenance

Each artifact record stores the resolved path, SHA-256, byte size, format, and
registration time. Each event stores its source artifact ID and source line.
Each case stores an audit table with actions such as `case.create`,
`artifact.register`, and `events.ingest`.

The audit table is append-only through the public store API. It is not
cryptographically chained, so a user with direct database access can edit it.
Treat the database as part of the evidence package and hash it if you need
stronger integrity.

### Quarantine

Raw records are preserved in `raw_json` and never rewritten. The taint scanner
adds flags and marks the event. The planner does not read `raw_json` as
instructions; it reads normalized fields and retrieval text.

A tainted event can still be cited as evidence. That is intentional: the
injection itself is an observation. What it cannot do is establish a benign
conclusion. The demo's Q4b claim is rejected for exactly that reason.

### Taint detection is not a filter

The patterns in `security/taint.py` are a small, explicit set. They catch common
instruction overrides and forced verdicts. They do not catch every possible
injection, and they are not meant to. The architectural guarantee is that
untrusted text has no instruction authority, whether or not it matches a
pattern. Detection exists to flag evidence for the analyst, not to make the
system safe by itself.

## Certificates

A CPC is signed with HMAC-SHA256 using a 32-byte per-case key. The signature
covers the certificate payload with the `signature` field excluded. Verification
recomputes the HMAC and compares in constant time.

What the signature establishes:

- the certificate payload has not changed since it was signed;
- the signer had access to the case key.

What it does not establish:

- who signed it (no identity, no asymmetric key);
- that the underlying evidence is authentic;
- that the analysis was correct;
- that the certificate is fresh (there is no nonce or revocation check).

The `key_id` is `SHA-256(key)[:16]`. It identifies the key, not the person. Do
not present a CPC as a legal signature or as proof of analyst identity.

## API exposure

The API is optional and intended for a single operator on loopback. It has:

- bearer-token authentication with no default token;
- loopback binding in the documented command;
- Pydantic request validation with `extra="forbid"` on the request model;
- no TLS, user accounts, roles, rate limiting, or request logging.

Do not bind it to `0.0.0.0`. Do not put it behind a public reverse proxy without
adding authentication, TLS, and rate limiting first.

## Operational guidance

If you use the prototype on real evidence:

1. Run it under a dedicated OS account with access only to the case workspace.
2. Keep the workspace on an encrypted volume.
3. Record the hash of the source evidence outside the tool as well.
4. Treat `case.db`, `key.bin`, certificates, and reports as part of the case
   package. Hash and archive them together.
5. Use a new case for each investigation. Do not reuse a key across cases.
6. Re-run `evitrace validate-case` before relying on a stored case.
7. Keep the machine offline, or at minimum do not expose the API.
8. Review the full proof, not only the verdict. The verdict is a summary; the
   certificate is the argument.
9. Remember that the calibration split is synthetic. A threshold computed from
   it is a prototype threshold, not a validated error rate.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not
open a public issue with exploit details, real evidence, case keys, or
certificates from a live investigation.

See [SECURITY.md](../SECURITY.md) for the reporting process and scope.
