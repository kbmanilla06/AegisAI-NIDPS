# AegisAI NIDPS Post-MVP Gate P3 Plan

**Status:** Planning only — owner approval required before implementation
**Gate:** P3 — security hardening and full quality assurance
**Baseline:** public `main` and cached `origin/main` at `fbb22fbbf5ec42c1c2b4196cd4d7fe45dd4a6f32`
**Hosted CI:** Run #38 recorded as successful for the report-publication SHA
**Predecessor:** Gate P2, `docs/POST_MVP_GATE_P2_COMPLETION_REPORT.md`
**Scope decision:** Synthetic/offline, simulation-preserving assurance only

## 1. Executive decision

Gate P3 is an assurance gate, not a feature sprint. It freezes the existing
synthetic/offline product and subjects it to a renewed threat-model review,
security hardening, complete regression testing, recovery validation, and
release-readiness review.

P3 may correct defects or harden existing controls when a separately approved
implementation authorization is provided. It does not add product capability,
new data sources, model functionality, observability features, or prevention
adapters. A P3 change must remain traceable to an identified security, quality,
privacy, reliability, accessibility, reproducibility, or documentation finding.

The gate remains strictly local and disposable:

- synthetic project-generated artifacts and existing accepted offline evidence only;
- no real or third-party dataset, including UNSW-NB15 or NUSW-NB15;
- no publisher contact or dataset acquisition;
- no live packet capture, public-network deployment, or online inference;
- no model activation, automatic training/promotion, or scoring expansion;
- no alert, detection, incident, assessment, registry, threshold, or prevention mutation;
- simulation remains the only prevention behavior;
- no firewall, host-state, socket, subprocess, packet, network-namespace,
  privileged-container, host-network, or enforcement capability.

P3 stops at an uncommitted completion checkpoint. Publication requires a
separate owner review and authorization.

## 2. Baseline and inherited evidence

The plan relies on the following recorded evidence and does not alter it:

| Evidence | Recorded result |
|---|---|
| Public baseline | `fbb22fbbf5ec42c1c2b4196cd4d7fe45dd4a6f32` |
| Gate P2 implementation | `d831fcd820959c97dbe209bb23c40213567678b1` |
| Hosted CI for implementation | Run #37 passed; database ID `29588353977` |
| Hosted CI for completion-report publication | Run #38 recorded as passed |
| Gate P2 decision | Approved and published |
| Working-tree boundary | Inherited Sprint 10 planning/preflight files remain uncommitted and are outside P3 |

The exact accepted Gate 5S-A/B/C identity set remains the set recorded in
`docs/POST_MVP_GATE_P2_PLAN.md` and the Gate 5S completion reports. P3 must
verify the set by hash and must not regenerate, replace, re-label, or broaden
it. The inherited synthetic limitation text and complete machine-readable
false-capability flags are immutable requirements on every relevant surface.

The owner-accepted Gate P2 residuals remain visible inputs to the P3 review:

1. the pre-existing feature-pipeline memory-threshold failure;
2. unavailable controlled artifact-volume helper validation; and
3. worker/scheduler SBOM output that was not persisted, although their
   vulnerability scans were clean.

P3 must classify, re-test where practical, and document these items. It must
not silently convert an accepted limitation into a pass or expand into an
unrelated feature-performance rewrite.

## 3. Scope and non-goals

### 3.1 In scope

1. Refresh the STRIDE/abuse-case review against the implemented Sprints 0–9,
   Gate 5S-A/B/C, Gate P1, and Gate P2 paths.
2. Re-run and, only when authorized, harden existing authentication, session,
   RBAC, CSRF/Origin, IDOR, rate-limit, safe-error, and audit controls.
3. Validate privacy, redaction, retention, artifact integrity, path isolation,
   and controlled-volume behavior.
4. Exercise migration upgrade/downgrade/re-upgrade, downgrade refusal, backup,
   restore, corruption, and partial-recovery handling in disposable projects.
5. Re-run full backend, frontend, contract, parser, feature, ML-artifact,
   anomaly, fusion, alert/incident, simulation, observability, and recovery
   regression suites.
6. Run bounded resource, retry, cancellation, concurrency, idempotency, and
   dependency-failure tests.
7. Complete dependency, SBOM, native-library, secret, large-file, static,
   container, and local penetration-test evidence.
8. Verify frontend accessibility, limitation language, false-capability flags,
   and safe degraded/`not_evaluable` rendering.
9. Reproducibly verify the Docker Compose topology, health endpoints, Celery
   registration, and simulation-only runtime boundary.
10. Update the threat model, risk register, test/security reports, runbooks,
    and P3 completion report with actual commands and outcomes.

### 3.2 Explicit non-goals

- no new detection rule, alert, incident, model, anomaly, ensemble,
  explainability, intelligence, feedback, or reporting feature;
- no model loading, activation, online inference, training, retraining,
  promotion, or scoring beyond existing offline synthetic evidence;
- no real dataset bytes, sample, mirror, tokenized URL, publisher message, or
  metadata inspection;
- no packet capture or interface monitoring;
- no firewall/host-state/socket/subprocess/enforcement adapter or capability;
- no Gate 10B/10C work, Sprint 6–15 implementation, or lab enforcement;
- no public deployment, public metrics endpoint, or external observability
  service;
- no broad refactor, dependency upgrade, performance rewrite, or UI redesign
  unrelated to a verified P3 finding;
- no commit, tag, release, or publication under this planning document.

## 4. Confirmed requirements

The following are fixed by the master prompt, implementation guide, decision
register, architecture, threat model, test strategy, deployment strategy, and
Gate P2 evidence:

- P3 is sequentially after approved Gate P2 and before reproducibility/portfolio
  work.
- The first release is IDS plus simulated IPS; simulation is the only adapter.
- PostgreSQL is authoritative; Redis is disposable coordination only.
- Browser auth is an opaque server-side cookie session with `Secure`,
  `HttpOnly`, `SameSite=Lax`, rotation, idle/absolute expiry, revocation,
  CSRF-token, and Origin enforcement.
- Authorization is centralized and server-side for all protected operations.
- Celery task payloads are JSON-only and UUID-only; workers resolve all other
  values server-side and use bounded time, memory, retry, row, and output caps.
- Accepted synthetic evidence is immutable, hash-bound, aggregate-safe, and
  carries the exact limitation text and false-capability flags.
- Raw payloads, raw endpoint values, credentials, tokens, internal paths,
  query strings, stack traces, and dataset bytes are not returned, logged, or
  placed in reports/screenshots.
- Controlled artifacts use opaque references, SHA-256, atomic writes, mode
  `0600` objects, controlled roots, and expiry/cleanup policy.
- Flows and feature/model/monitoring evidence are retained for 30 days;
  alerts, incidents, analyst notes, and audit records for 180 days; exceptional
  holds are disabled.
- Administrative, policy, review, cleanup, retention, and audit-sensitive
  actions fail closed when audit persistence is unavailable.
- A Critical or High finding, unexplained secret, unsafe default, broken
  migration/recovery path, misleading claim, or missing required evidence
  blocks P3 approval.

## 5. Assumptions

These assumptions are safe for planning and must be confirmed or revised in the
implementation authorization:

1. P3 runs on the existing ARM64 Apple M2 local development machine and in
   disposable Docker Compose projects only.
2. The current P2 residuals are owner-accepted non-security limitations unless
   new evidence shows a security, privacy, integrity, or release-blocking
   consequence.
3. Docker Scout remains the documented equivalent if Trivy is unavailable;
   the equivalence and scan scope must be recorded rather than implied.
4. Focused penetration testing is limited to localhost/disposable services and
   uses OWASP ZAP, Semgrep, or a documented equivalent only when installed and
   safely bounded.
5. P3 may make minimal additive documentation or test changes without changing
   the accepted synthetic hashes. Production-code hardening requires a finding,
   regression test, review, and explicit authorization.
6. Dependency upgrades are not a goal. They are allowed only when required to
   remediate a verified Critical/High issue or to restore reproducibility, with
   ARM64 compatibility evidence and a lockfile/SBOM update.
7. Existing synthetic reports and artifacts may expire during the gate. An
   expired source becomes `not_evaluable`; no exceptional hold is created.

## 6. P3 workstreams

### 6.1 Threat-model and risk-register refresh

- Map every implemented endpoint, task, migration, artifact path, browser
  surface, and container boundary to a threat/control/test.
- Revisit STRIDE and abuse cases for hostile uploads, parser/resource abuse,
  session theft, RBAC/IDOR, report and feedback injection, artifact swap/path
  traversal, Celery poisoning, audit failure, retention failure, backup/restore,
  dependency compromise, misleading synthetic claims, and simulation escape.
- Add evidence references and residual owner status; do not close a risk merely
  because a test was planned.
- Preserve Sprint 10 Gate 10A entries as planning-only and explicitly state that
  no attestation authorizes P3 enforcement work.

### 6.2 Identity, authorization, and audit assurance

Verify the complete six-role negative matrix for every existing protected route,
including the P2 observability routes:

- session rotation on login and privilege change;
- idle and absolute expiry, revocation, logout, concurrent sessions, and safe
  generic authentication errors;
- CSRF token binding, Origin allowlist, CORS behavior, unsafe-method rejection,
  and WebSocket reauthorization;
- IDOR and safe-not-found behavior for UUID resources, reports, artifacts,
  feedback, recovery evidence, alerts, incidents, and simulations;
- permission separation for creator/reviewer/finalizer/operator actions,
  including Security Administrator versus System Administrator boundaries;
- actor-scoped idempotency, optimistic versioning, row locks, and concurrent
  review/cleanup/finalization behavior;
- append-oriented audit fields, bounded reasons, before/after hashes, actor
  role, correlation ID, safe outcome, and fail-closed audit-write behavior.

No new privilege, role, approval route, or self-approval exception is proposed.

### 6.3 Privacy, claims, and retention assurance

- Search source, report, API, UI, log, audit, and error paths for restricted
  fields and secret patterns.
- Test Unicode/control characters, HTML/Markdown injection, JSON injection,
  path-like values, URLs, query strings, credentials, IPs, and stack traces.
- Confirm aggregate minimum support, dimension allowlists, cardinality caps,
  non-overlapping filters, and `not_evaluable` rendering.
- Verify exact limitation language and every false-capability flag on all
  synthetic monitoring, report, dashboard, model-card, and demo surfaces.
- Execute retention and cleanup with expired objects, failed cleanup, orphan
  metadata, audit-lineage dependencies, and repeated scheduler runs.
- Verify no exceptional hold, raw payload retention, or dataset artifact exists.

### 6.4 Artifact, migration, backup, and recovery assurance

- Verify canonical JSON and existing controlled Parquet artifacts by server-side
  hash, schema, size, opaque path, mode, root containment, and expiry.
- Reject client paths, symlinks, traversal, replacement, stale hashes, schema
  mismatches, and artifact references outside the allowlist.
- Run PostgreSQL upgrade/downgrade/re-upgrade on empty and populated disposable
  databases; verify downgrade refusal while live P2 evidence exists.
- Perform a disposable PostgreSQL backup/restore and controlled-volume manifest
  revalidation. If the helper image remains unavailable, record the exact
  blocked check and preserve the owner-accepted residual; do not claim pass.
- Inject missing, corrupt, partial, and mismatched artifacts and verify safe
  failure without repair, path disclosure, or model/prevention side effects.
- Confirm Redis loss cannot fabricate state-changing success.

### 6.5 Celery, resource, and resilience assurance

Exercise existing limits without creating a public load target:

- malformed, extra-field, non-UUID, oversized, and unregistered task envelopes;
- task timeout, cancellation, retry exhaustion, worker crash, late
  acknowledgement, Redis outage, PostgreSQL outage, and duplicate delivery;
- concurrent report, monitoring, feedback, cleanup, replay, detection, feature,
  anomaly, explanation, and simulation requests;
- CPU, memory, PID, disk, row, byte, queue-age, output-series, and artifact-size
  caps;
- bounded backpressure and degraded health, with no unbounded fan-out or retry;
- deterministic replay and no duplicate mutation after task retry.

Existing limits remain the ceiling unless a measured, reviewed reduction is
needed. Raising a limit is outside P3.

### 6.6 Dependency, SBOM, native, and container assurance

- Generate and retain SBOMs for API, migration, worker, scheduler, and dashboard
  images plus Python/Node/native dependencies.
- Run Docker Scout or Trivy-equivalent vulnerability scans and dependency/license
  checks. Any unresolved Critical/High finding blocks the gate.
- Confirm ARM64 import/runtime compatibility for NumPy/SciPy, PyArrow,
  scikit-learn/ONNX-runtime dependencies already present in the project, and
  transitive native libraries.
- Verify CI action pins, lockfiles, reproducible dependency resolution, no
  secret-bearing build arguments, and no unreviewed network fetch during tests.
- Inspect containers for non-root users, read-only root filesystems where
  configured, dropped capabilities, no Docker socket, no host network, no
  privileged mode, bounded resources, and only approved writable volumes.
- Static-search source, dependencies, images, and Compose for sockets,
  subprocesses, packet capture, firewall tools, host-state calls, and
  enforcement adapters; investigate every match rather than relying on a
  filename allowlist.

### 6.7 Frontend, accessibility, and safe UX

- Run lint, typecheck, unit tests, production build, and dependency audit.
- Verify keyboard navigation, focus order, labels, semantic roles, contrast,
  responsive behavior, and screen-reader names on auth, alerts, incidents,
  observability, recovery, reports, and simulation views.
- Confirm sensitive fields are redacted by server response, not only hidden in
  React, and that error states never render stack traces or internal paths.
- Verify degraded, failed, stale, expired, and `not_evaluable` states are
  visibly distinct from healthy/zero/green.
- Confirm UI controls cannot mutate alert, model, registry, detection, or
  prevention state beyond the existing simulation route permissions.

### 6.8 Local penetration and adversarial QA

Use only disposable localhost services and synthetic fixtures. Test:

- login/session fixation, CSRF, Origin/CORS, RBAC bypass, IDOR, rate limits,
  mass assignment, injection, XSS, path traversal, SSRF-shaped values, unsafe
  deserialization, and error disclosure;
- upload/parser/resource abuse, duplicate/replay, archive/decompression
  rejection, Unicode/control data, and content/filename confusion;
- report/feedback injection, aggregate inference, audit tampering, artifact
  replacement, stale hash, retention bypass, and Celery message poisoning;
- simulation policy bypass, model/anomaly-only evidence, allowlist/critical
  asset handling, duration/expiry/rollback/idempotency, and host-state negative
  checks.

No denial-of-service or public scanning is authorized. Resource tests use strict
limits in disposable projects and are stopped on degraded host health.

### 6.9 Simulation-only invariant verification

P3 must provide both static and runtime evidence that:

- exactly one data-only simulation adapter is present;
- no firewall binary, socket, subprocess, packet library, namespace change,
  host-state write, or enforcement dependency is reachable;
- prevention mode and database constraints accept only `simulation`;
- model/anomaly-only and failed-policy requests cannot simulate or mutate state;
- before/after host firewall and network state are unchanged during the entire
  simulation suite;
- no route, task, report, feedback, drift result, or dashboard action can invoke
  prevention, activation, online scoring, or alert/detection mutation;
- emergency/kill-switch language remains documentation-only and does not create
  an enforcement path.

## 7. Proposed evidence and command matrix

The implementation phase must record command, tool version, UTC timestamp,
commit, environment, result, skipped reason, and residual risk. Proposed checks:

| Area | Evidence |
|---|---|
| Format/lint/types | Ruff check/format, mypy, frontend lint/typecheck/build |
| Backend regression | Full pytest plus targeted P3 security/resilience suites |
| Frontend | Unit/build, accessibility automation and manual keyboard/focus review |
| Auth/RBAC | Six-role negative matrix, sessions, CSRF/Origin, IDOR, audit-failure tests |
| Contracts | All versioned schemas, limitation/flag, malformed/Unicode/control cases |
| ML/artifact | Synthetic hash binding, parity/integrity/closed-policy, corrupt/missing artifact |
| Ingestion/detection | Parser fuzz/malformed, duplicate/late evidence, suppression/flood limits |
| Celery | UUID-only JSON envelopes, retry/timeout/cancel/crash/concurrency/Redis failure |
| Migration | Upgrade, downgrade, populated downgrade refusal, re-upgrade, recovery |
| Recovery | PostgreSQL and controlled-volume restore, hash/permission/root revalidation |
| Supply chain | pip/npm audit, SBOM, Docker Scout/Trivy-equivalent, native imports/licenses |
| Containers | Compose config/build, non-root, read-only/cap-drop/no-host-network checks |
| Secrets/files | secret scan, large-file/dataset/model scan, `git diff --check` |
| Privacy | redaction, aggregate suppression, safe errors, report/API/UI claim scan |
| Simulation | static guard, runtime no-side-effect, policy/expiry/rollback/idempotency |
| Health | liveness/readiness, Celery ping/registered tasks, degraded dependency behavior |

P3 does not define a performance pass threshold where none is measured. It
requires documenting representative measurements and preserving the accepted
feature-memory limitation unless a separately approved remediation is made.

## 8. Required documentation outputs

If implementation is later authorized, it must update only affected documents:

- `docs/POST_MVP_GATE_P3_PLAN.md` with any approved deviations;
- `docs/POST_MVP_GATE_P3_COMPLETION_REPORT.md` with scope, findings, exact
  commands/results, hashes, scans, skipped checks, accepted residuals, and gate
  decision;
- `docs/THREAT_MODEL.md` and `docs/threat-model/THREAT_MODEL.md` as applicable;
- `docs/RISK_REGISTER.md` with evidence, owner, review date, and residual state;
- `docs/TEST_STRATEGY.md` and `docs/DEPLOYMENT_STRATEGY.md` for new checks;
- migration/API/architecture docs only when a verified hardening change alters
  their behavior;
- local security, SBOM, accessibility, recovery, and limitation reports with
  no unsupported claims.

No report may call synthetic evidence production telemetry, real-world efficacy,
validated prevention, or an online detection result.

## 9. Risks and mitigations

| ID | Risk | Mitigation / release trigger |
|---|---|---|
| P3-R1 | Security review misses a route or task | Generate route/task inventory from source and DB; map each to auth/audit/tests; missing mapping blocks gate |
| P3-R2 | A fix weakens a synthetic or simulation invariant | Hash/flag regression suite plus static/runtime guard; any mutation of accepted evidence blocks gate |
| P3-R3 | Accepted P2 residual is misreported as resolved | Keep explicit accepted/blocked/untested labels and owner references |
| P3-R4 | Native/dependency drift breaks ARM64 or adds vulnerability | Lock/SBOM/scan/import evidence; zero unresolved Critical/High |
| P3-R5 | Aggregate/report surface leaks row-level or sensitive data | Closed allowlists, minimum support, IDOR/redaction tests, hostile-input fixtures |
| P3-R6 | Cleanup or restore silently loses lineage | Hash revalidation, downgrade refusal, failed/partial recovery fixtures, audit evidence |
| P3-R7 | Resource tests harm the development host | Disposable stack, strict caps, bounded fixtures, health abort and cleanup procedure |
| P3-R8 | Frontend appears safe while API leaks data | Server-side projection tests and API/UI parity review |
| P3-R9 | P3 expands into enforcement or feature work | Scope checklist, separate authorization, static capability search, no unrelated edits |
| P3-R10 | External CI/tool outage is mistaken for a pass | Record unavailable checks as skipped/blocked and wait for required evidence or owner decision |

## 10. Owner decisions required

The following decisions must be explicit before P3 implementation:

1. Approve the P3 boundary as local synthetic/offline security hardening and QA
   only, with no feature expansion or prevention capability.
2. Confirm `fbb22fbbf5ec42c1c2b4196cd4d7fe45dd4a6f32` and recorded hosted CI Run
   #38 as the baseline, while preserving inherited uncommitted Sprint 10 files.
3. Approve zero unresolved Critical/High findings as a hard gate, with Medium,
   Low, and Informational findings requiring explicit owner disposition.
4. Approve Docker Scout as the documented Trivy equivalent when Trivy is not
   available, provided all target images are scanned and results are retained.
5. Approve focused localhost penetration testing with bounded OWASP ZAP,
   Semgrep/Bandit-equivalent, and manual adversarial tests; no public scanning.
6. Decide whether the previously unavailable controlled-volume helper must be
   reattempted during P3 or remains an accepted residual with a documented
   compensating test.
7. Confirm the pre-existing feature-memory performance failure remains accepted
   and outside P3 unless it becomes a security/availability blocker.
8. Approve full persisted SBOM evidence for API, migration, worker, scheduler,
   dashboard, Python, Node, and native dependencies.
9. Confirm no exceptional retention holds and no real/third-party data review
   are permitted while P3 runs.
10. Confirm P3 publication, commit, and any later P4 planning require separate
    owner approval after the uncommitted completion report.

## 11. Gate P3 acceptance criteria proposal

P3 is complete only if all applicable criteria below pass or have an explicit
owner-approved non-security residual:

1. Threat model, abuse cases, risk register, route/task inventory, and control
   traceability are refreshed against the implemented tree.
2. No unresolved Critical or High security, privacy, integrity, authorization,
   migration, supply-chain, or simulation-boundary finding remains.
3. All protected routes and tasks pass authorization, CSRF/Origin, IDOR,
   session, audit, idempotency, concurrency, and safe-error checks.
4. Synthetic/offline hashes, exact limitation text, false-capability flags,
   retention, and artifact integrity remain unchanged and verified.
5. No real dataset, publisher contact, live capture, model activation, online
   inference, alert/detection/incident mutation, or prevention capability is
   present or reachable.
6. Parser, feature, model/artifact, anomaly/fusion, alert/incident,
   observability, recovery, and simulation regression suites pass within
   documented resource limits.
7. Migrations upgrade/downgrade/re-upgrade safely and refuse unsafe populated
   downgrade; backup/restore and corrupt/partial recovery fail closed.
8. All target images/dependencies have current ARM64-compatible SBOM and
   vulnerability/license evidence; no unresolved Critical/High finding exists.
9. Frontend quality/accessibility and safe state rendering pass; every relevant
   synthetic surface displays the mandatory limitation and false flags.
10. Docker/Compose health, non-root/read-only/cap-drop/no-host-network, Celery
    registration, secret scan, large-file scan, and simulation-only checks pass.
11. Every skipped or unavailable check is recorded with reason and owner
    disposition; no skipped required check is labeled pass.
12. Completion report, runbooks, residual-risk decisions, and rollback notes are
    complete and truthful.

## 12. Deferred work and prohibited capabilities

P3 does not authorize or imply:

- Gate 10B/10C or any real/lab enforcement implementation;
- firewall, host-state, socket, subprocess, packet, network namespace, or
  privilege changes;
- live capture, public-network deployment, online inference, model activation,
  or automatic training/promotion;
- real datasets, UNSW/NUSW files, publisher outreach, mirrors, or downloads;
- new alerts, detections, incidents, models, anomaly/ensemble behavior,
  prevention state, or policy mutation;
- Gate P4 deployment reproducibility or Gate P5 portfolio publication;
- commit, push, merge, tag, release, or public upload before separate review.

## 13. Exact Gate P3 implementation authorization prompt

```text
Approve AegisAI NIDPS Gate P3 implementation using docs/POST_MVP_GATE_P3_PLAN.md.

Before proceeding, confirm public main is fbb22fbbf5ec42c1c2b4196cd4d7fe45dd4a6f32 and hosted CI Run #38 passed. Read the master prompt, implementation guide, all governing project documents, docs/POST_MVP_GATE_P2_PLAN.md, and docs/POST_MVP_GATE_P2_COMPLETION_REPORT.md completely. Preserve the inherited uncommitted Sprint 10 planning/preflight files; do not stage, rewrite, or delete them.

Authorize only Gate P3 security hardening and full QA for the existing synthetic/offline, simulation-only product: threat-model and risk refresh; route/task/control inventory; minimal finding-driven fixes; auth/session/RBAC/CSRF/Origin/IDOR/audit verification; privacy/redaction/retention/artifact-integrity checks; migration and disposable backup/restore evidence; bounded Celery/resource/concurrency/recovery tests; frontend/accessibility checks; dependency/license/SBOM/native/container/secret/large-file scans; focused localhost penetration testing; Docker/health validation; simulation-only static/runtime verification; tests and documentation.

Preserve the exact accepted Gate 5S-A/B/C hashes, Gate P1/P2 evidence, synthetic-demo limitation text, false-capability flags, 30/180-day retention defaults, controlled-volume/SHA-256 artifact policy, JSON-only UUID Celery rules, RBAC, CSRF/Origin, audit, and simulation-only guarantees. Treat the owner-accepted feature-memory performance limitation and unavailable artifact-volume helper as explicit residuals unless separately changed by owner decision. Do not claim any skipped or unavailable check passed.

Do not use real or third-party datasets; contact the publisher; download, preview, parse, or transfer dataset bytes; configure live capture; activate, load, train, promote, or score a model beyond existing offline synthetic evidence; mutate alerts, detections, incidents, assessments, rules, thresholds, registries, feedback, or prevention; add firewall, host-state, socket, subprocess, packet, public-network, privileged-container, host-network, or enforcement capability; begin Gate P4, Gate P5, Gate 10B/10C, Sprint 6–15 work, or unrelated refactors; commit or publish.

Run and record all applicable formatting, linting, typing, unit, integration, contract, parser/fuzz, feature/parity, ML-artifact, anomaly/fusion, alert/incident, observability, RBAC-negative, IDOR, CSRF/Origin, session, audit, privacy, retention, idempotency, concurrency, resource, Celery, migration upgrade/downgrade/re-upgrade, backup/restore, corruption/partial-recovery, dependency/license/SBOM/native, Docker, frontend/accessibility, health, secret, large-file, and simulation-only checks. Stop at the uncommitted Gate P3 completion gate and report findings, files changed, commands/results, skipped checks, hashes verified, residual risks, acceptance status, and the exact separate publication-review prompt. Do not commit, push, or begin Gate P4 without separate approval.
```

## 14. Planning status

This document is the sole deliverable of the P3 planning turn. No production
code, migration, task, API, UI, artifact, dependency, Docker configuration,
dataset, or enforcement capability was added or changed. Owner approval is
required before implementation.
