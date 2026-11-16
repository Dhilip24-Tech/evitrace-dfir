# Security policy

## Supported versions

EviTrace-DFIR is a prototype. Security fixes are applied to the current `main`
branch and the latest `0.1.x` line.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| Older | No |

There are no long-term support branches.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/Dhilip24-Tech/evitrace-dfir/security/advisories/new>

Please do not open a public issue with exploit details, and do not attach real
evidence, case databases, `key.bin` files, certificates from a live
investigation, or credentials.

A useful report includes:

- the affected version or commit;
- the component (`ingest`, `temporal`, `cpc`, `api`, `sandbox`, and so on);
- a minimal reproduction using synthetic data;
- the impact you believe it has;
- any proposed fix or mitigation.

If private reporting is unavailable, contact the maintainer through the contact
options on <https://github.com/Dhilip24-Tech> and ask for a private channel
before sharing details.

## What to expect

This is a best-effort prototype, not a staffed product. I will acknowledge a
report when I can, investigate it, and tell you whether I consider it in scope.
There is no guaranteed response time and no bug bounty.

Please give me a reasonable window to fix an issue before publishing it. I will
credit reporters in the fix commit or advisory unless you ask to remain
anonymous.

## Scope

In scope:

- sandbox escape or path traversal that reads outside an allowed root;
- SQL injection or FTS query injection;
- cross-case data access;
- certificate forgery or signature bypass without the case key;
- arbitrary code execution through an evidence parser;
- authentication bypass in the optional API;
- secret leakage in the repository or generated artifacts;
- a prompt-injection path that gives untrusted evidence instruction authority.

Out of scope, because they are documented prototype limits:

- the API has no TLS, rate limiting, or multi-user model;
- HMAC is symmetric, so anyone with `key.bin` can sign certificates;
- the case key is stored beside the case database;
- the calibration split is synthetic and is not a validated error rate;
- the planner supports only a fixed set of question shapes;
- native `.evtx` and Plaso storage files are not parsed;
- denial of service from large but within-limit inputs;
- issues that require an attacker to already have full control of the analyst's
  OS account or workspace.

The full threat model and residual risks are in
[docs/security-model.md](docs/security-model.md). Please read it before
reporting a design limitation as a vulnerability.

## Safe handling of evidence

If you believe you have found a vulnerability while working with real evidence,
do not send the evidence. Reproduce the issue with the synthetic case in
`examples/demo_case/`, or with a minimal record you created yourself, and
describe the real-world impact in words.
