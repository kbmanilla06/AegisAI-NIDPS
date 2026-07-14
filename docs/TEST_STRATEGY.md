# Test and Quality Strategy

## Quality gates

After implementation approval, every change runs relevant formatting, lint, type, unit, integration, migration, security, and documentation checks. CI results are evidence; missing/skipped required checks fail approval.

## Test layers

| Layer | Coverage |
|---|---|
| Unit | Validators, parsers, normalizers, rules, features, scoring, state/policy gates, authorization helpers |
| Contract | Canonical schemas, API, queue messages, feature order, model compatibility, adapter interface |
| Integration | API/DB, worker/queue, migrations, ingestion, inference registry, audit, WebSocket, simulation |
| Security | RBAC, auth lifecycle, injection, traversal, upload abuse, rate limits, errors/logs, artifact integrity, replay/allowlist |
| ML | Split/leakage, parity, determinism, corrupt/unseen inputs, metrics, threshold, activation/rollback |
| E2E | Login through ingestion, alert, investigation, incident, simulation, rollback, audit |
| Performance/resilience | Representative bursts, queues, DB contention, worker crash, dependencies, recovery, storage growth |
| Accessibility | Keyboard, focus, labels, contrast, semantic roles, screen-size behavior |

## Required negative cases

Empty/null/wrong-type/oversized/Unicode/malformed/truncated/duplicate/out-of-order data; expired/revoked identity; every unauthorized role; missing/corrupt/incompatible model; stale intelligence; invalid state transition; replayed idempotency key; concurrent simulation; allowlisted/critical/internal target; missing expiry/rollback; dependency outage; audit failure.

## Security tooling plan

Ruff format/lint, mypy, pytest, Bandit, pip-audit, frontend lint/type/unit/build, npm audit, secret scanning, and the simulation-only guard are current automated gates. Semgrep, Trivy/container scan, full browser E2E, accessibility automation, load testing, and authorized local OWASP ZAP remain future hardening gates. Exact tools may change only with documented equivalent coverage.

## Test data

Synthetic fixtures are default. Public dataset samples retain source/license and are never committed if prohibited or excessive. Secrets, private IP context, real credentials, and unauthorized PCAP are excluded. Golden fixtures are small, deterministic, sanitized, and versioned.

Sprint 2 fixtures cover valid, invalid, malformed, duplicate, Unicode, truncated, oversized, mixed-protocol, and out-of-order records. PCAP fixtures are generated in temporary test storage so packet binaries are not committed. Parser fuzzing is deterministic and bounded; every generated input must either produce a canonical v1 record or a controlled error, never an uncaught parser exception.

Sprint 2 ingestion gates cover content/declared-source mismatch, filename indifference, traversal-safe opaque storage, request/upload caps, record/unique-flow/time limits, stable duplicate keys, replay idempotency, sensor source scoping, six-role negative authorization, safe failure codes, raw/flow cleanup, JSON-only Celery envelopes, migration downgrade/upgrade, and repeated worker tasks across event loops.

## Release-blocking criteria

Any Critical/High security finding, failing required test, broken RBAC, unsafe upload handling, leakage, incompatible artifact acceptance, missing audit, unsafe migration, real prevention capability/default, untested idempotency/expiry/rollback, or materially incomplete documentation blocks release.

## Evidence format

For each review: command/check, version/environment, pass/fail/skipped, timestamp/commit, summarized output, linked defect, and residual limitation. Never convert an unrun or skipped check into a pass.
