# AegisAI NIDPS Post-MVP Synthetic Roadmap

**Status:** Planning only — owner approval required before implementation
**Baseline reviewed:** `ec19068c787e4eedf0c9bef272a95a1c8256afca` (Sprint 9 public-main baseline)
**Hosted CI:** Run #32 passed for the Sprint 9 publication baseline
**Scope decision:** Synthetic-only, offline, simulation-preserving post-MVP work

## 1. Executive decision

This roadmap defines the next work after the Sprint 9 simulation-only MVP. It deliberately preserves the project's safety boundary:

- real prevention and automatic prevention are permanently deferred;
- live packet capture and monitoring of a real interface are permanently deferred;
- real and third-party datasets, including UNSW-NB15, are permanently deferred;
- publisher outreach and dataset acquisition are permanently deferred;
- public-network enforcement and uncontrolled deployment are permanently deferred.

Future work may improve synthetic evidence, offline scoring, analyst workflow, reporting, assurance, reproducibility, and portfolio presentation. It may not turn the product into an enforcement system. Any synthetic experiment must remain isolated from alert/detection mutation and must carry the existing synthetic-demo limitation and false-capability flags.

The roadmap is staged into separately reviewable gates. The first implementation authorization should cover only synthetic monitoring and feedback contracts. Later gates require their own acceptance and publication decisions.

## 2. Current state and inherited constraints

### 2.1 Confirmed baseline

- Sprints 0–9 are represented on the published baseline; Sprint 9 is simulation-only.
- The architecture remains a FastAPI API, Celery worker, React/Vite dashboard, PostgreSQL authority, Redis coordination, and controlled local artifact volume.
- Accepted model and anomaly evidence is synthetic-only. Gate 5S-C supports reviewed synthetic registry metadata and isolated offline batch scoring; it does not authorize online inference or activation.
- Sprint 10 Gate 10A planning/preflight artifacts exist, but no enforcement adapter, capability-bearing executor, firewall rule, socket, subprocess, host-state mutation, or production change was authorized.
- Decision C-31 selects Option A: keep IDS plus simulated IPS, defer real/lab enforcement, and allow only future synthetic experiments under separate authorization.

### 2.2 Inherited invariants

Every future change must preserve the following invariants:

1. Simulation is the only prevention behavior.
2. Synthetic artifacts are explicitly identified, hashed, retained under policy, and cannot be presented as real-world performance evidence.
3. Stored model/anomaly evidence cannot directly mutate alerts, detections, incidents, assessments, or prevention state.
4. Sensitive changes require centralized authorization, CSRF/Origin enforcement, and a complete safe audit event.
5. Uploaded or generated content is treated as hostile input; no uploaded content is executed.
6. Artifact paths are opaque and controlled; PostgreSQL references and SHA-256 hashes are authoritative.
7. JSON-only UUID Celery tasks are bounded, idempotent where applicable, and never receive arbitrary executable payloads.
8. Critical and High findings, unsafe defaults, missing audit, or unverified retention block release.

## 3. Scope and non-goals

### 3.1 In scope

- Synthetic model/data-quality monitoring and reproducible drift evidence.
- Analyst feedback and review workflows over synthetic/offline evidence.
- Structured observability, aggregate reporting, and performance/recovery evidence.
- Security hardening and full QA of the existing simulation-only product.
- Clean-environment deployment reproducibility using the existing local Compose topology.
- Portfolio documentation and a controlled synthetic-only demonstration.

### 3.2 Permanently out of scope

- Real or automatic prevention, including a lab-to-production promotion path.
- Firewall, nftables, host-state, socket, subprocess, packet, network-namespace, or privileged enforcement integration.
- Live capture, interface monitoring, or online inference.
- UNSW-NB15, NUSW-NB15, any real/third-party dataset, mirrors, samples, or publisher contact.
- Public-network deployment or enforcement.
- Automatic model training, promotion, activation, rollback, or policy changes based solely on drift or feedback.
- Claims of real-world detection, prevention, or performance.

## 4. Roadmap structure and gates

| Gate | Work | Exit evidence |
| --- | --- | --- |
| P1 | Synthetic monitoring and analyst-feedback foundations | Versioned monitoring/feedback contracts, deterministic fixtures, drift report, RBAC/audit/security tests |
| P2 | Observability, reporting, and recovery evidence | Metrics/log schema, aggregate reports, load/retention/backup-restore evidence |
| P3 | Security hardening and full QA | Threat-model refresh, full scans/tests, no Critical/High findings, invariant proof |
| P4 | Deployment reproducibility | Clean-machine start, pinned dependency/image evidence, reproducible test run |
| P5 | Portfolio and final demonstration | Reproducible synthetic demo, documentation/model cards, limitations, screenshots, release review |

P1–P5 are sequential by default. Each gate ends at an uncommitted completion checkpoint and requires explicit owner review before publication or the next gate. A gate may be split further if risk or resource measurements require it.

## 5. P1 — Synthetic monitoring and analyst feedback

### 5.1 Monitoring contract

Define a versioned `synthetic_monitoring/1.0.0` contract containing:

- source artifact hash and type (synthetic flow, feature artifact, target manifest, model/anomaly candidate);
- producer, generation seed, schema version, split identity, and created-at timestamp;
- model/transform/anomaly versions where applicable;
- eligible row/group counts and time coverage;
- synthetic-only limitation text and machine-readable false-capability flags;
- metric name, window, baseline identity, current identity, sample counts, and confidence/uncertainty fields;
- threshold policy version and reviewer state.

Monitoring records are metadata and aggregate evidence. Individual endpoint addresses, raw payloads, credentials, and model inputs must not be copied into monitoring reports.

### 5.2 Drift and quality evidence

The first implementation should measure, without auto-remediation:

- feature missingness, unseen-category, range, and schema failure rates;
- group/time coverage and duplicate/near-duplicate rates;
- distribution changes for approved model features using a documented deterministic statistic;
- score/distribution changes for accepted synthetic offline scoring artifacts;
- label mix changes only when a separately accepted synthetic target manifest is present;
- processing latency, rejected rows, stale artifacts, and failed task counts.

Proposed defaults are warning and critical bands plus a minimum eligible sample count, all versioned in policy rather than hard-coded. No threshold may create a prediction, alert, rule, incident, prevention action, model activation, or automatic retraining. A critical result creates review evidence only.

### 5.3 Reproducibility and baseline binding

Each baseline and comparison must bind to immutable artifact hashes, split identity, feature schema, preprocessing identity, environment/SBOM identity, and UTC time window. Re-running the same manifest and seed must produce the same aggregate values and report hash. Incomplete, mismatched, or stale inputs fail closed and are reported as `not_evaluable` rather than treated as normal drift.

### 5.4 Analyst feedback workflow

Provide a metadata-only review queue for synthetic/offline evidence:

- dispositions: `confirmed_synthetic_intrusion_like`, `confirmed_synthetic_benign_like`, `false_positive_demo`, `false_negative_demo`, `insufficient_evidence`, and `needs_review`;
- structured reason codes, bounded analyst notes, reviewer identity, timestamps, evidence hashes, and immutable revision history;
- explicit distinction between analyst observation and ground truth;
- separate request/approve roles for changing monitoring policy or report status;
- export limited to aggregates and redacted identifiers.

Feedback must never silently relabel an accepted manifest, alter a model, activate a registry entry, mutate a detection/alert, or change prevention simulation. Any future training use requires a new owner-approved gate and a new immutable dataset manifest.

### 5.5 P1 data, API, UI, and task boundaries

Planning assumptions for a later implementation:

- additive, reversible metadata migrations only; exact migration numbers are assigned during implementation after schema review;
- read APIs for monitoring runs, drift summaries, evidence hashes, and feedback queue; write APIs limited to feedback and review transitions;
- UI displays synthetic-only limitation text and false-capability flags on every monitoring, feedback, and report view;
- Celery tasks accept only UUIDs and server-resolved manifest references, use JSON serialization, enforce time/memory/row limits, and are idempotent by run identity;
- no endpoint accepts arbitrary URLs, file paths, model bytes, executable payloads, or browser-supplied artifact locations.

## 6. P2 — Observability, reporting, and recovery

### 6.1 Structured telemetry

Add a documented, bounded observability schema with correlation/request IDs, actor role (not secrets), operation, status, duration, row/task counts, and sanitized error category. Do not log cookies, tokens, raw endpoint addresses, query strings, internal paths, stack traces, model inputs, or dataset payloads.

Metrics should cover API latency/errors, queue depth and task age, ingestion/normalization outcomes, detection and simulated-prevention decisions, artifact integrity, drift runs, feedback transitions, retention cleanup, and readiness. Cardinality, label allowlists, and metric retention must be explicit.

### 6.2 Reports

Generate deterministic aggregate reports for:

- synthetic data and feature quality;
- monitoring/drift status and data-quality failures;
- analyst feedback counts and unresolved-review age;
- task/API performance and resource-limit outcomes;
- security-test, dependency, migration, backup/restore, and accessibility evidence.

Reports must include artifact hashes, policy versions, generation time, limitation language, and false-capability flags. They must not contain raw data or numeric claims that imply real-world performance.

### 6.3 Backup, restore, and retention

Test PostgreSQL backup/restore and controlled artifact-volume recovery on disposable local environments. Verify referential integrity, SHA-256 revalidation, idempotent replay, and safe failure on partial restore. Use existing policy defaults unless an owner changes them: flows 30 days, alerts/audit 180 days, monitoring/feature/model evidence 30 days where applicable, and no exceptional holds.

## 7. P3 — Security hardening and full QA

P3 freezes functional scope and focuses on assurance:

- rerun threat modeling for monitoring, feedback, reporting, and deployment;
- exercise RBAC-negative matrices, IDOR, CSRF/Origin, session expiry/revocation, audit tamper resistance, retention, artifact path/integrity, and safe error handling;
- run unit, contract, integration, migration upgrade/downgrade/re-upgrade, parser/fuzz, resource-limit, Celery/idempotency/concurrency, Docker, frontend, accessibility, and health checks;
- run formatter, linter, typing, dependency/license, secret, large-file, SBOM, native dependency, Trivy (or documented equivalent), and Semgrep/Bandit-equivalent scans;
- perform focused penetration testing against the local application only, with no public network exposure;
- verify simulation-only invariants by static search and runtime negative tests;
- require zero unresolved Critical/High findings and an explicit residual-risk review.

## 8. P4 — Deployment reproducibility

The reproducibility target is a clean ARM64 development machine using local Docker Compose. The implementation gate must prove:

- pinned image digests, dependency lock information, CI action versions, and an SBOM;
- clean checkout, environment-template setup with no credentials, database migration, readiness, and test execution;
- non-root/read-only/capability-drop container posture where supported;
- no host networking, privileged mode, firewall capability, enforcement dependency, or public bind address;
- deterministic synthetic fixture generation and report hashes across two clean runs;
- documented backup/restore and retention cleanup commands;
- safe failure when required dependencies, disk, memory, or health checks are unavailable.

No deployment target beyond local/disposable development is authorized by this roadmap.

## 9. P5 — Portfolio documentation and final demonstration

Create a reproducible demonstration package containing:

- README and quick-start instructions;
- architecture/data-flow and threat-model diagrams;
- sprint/gate history and decision register;
- synthetic dataset, feature, model/anomaly, monitoring, and limitation cards;
- test, security, dependency/SBOM, performance, backup/restore, and accessibility summaries;
- a scripted demo using only project-generated synthetic fixtures;
- screenshots or short recordings that show limitation text, false-capability flags, RBAC/audit evidence, monitoring/reporting, and simulated prevention;
- a clear statement that no real dataset, live capture, online inference, automatic prevention, or real-world performance claim is present.

The final demonstration must be runnable from a clean checkout without credentials or external services. Portfolio publication is a separate owner decision; no commit, tag, release, or public upload is authorized by this planning document.

## 10. Security, privacy, and governance controls

- Synthetic artifacts remain subject to the same controlled-volume, hash, retention, and deletion controls as other project artifacts.
- Monitoring and feedback views use least privilege and redact sensitive targets and internal paths.
- Administrative review, policy changes, report finalization, retention cleanup, and artifact deletion are audited with actor, reason, before/after hashes, and correlation ID.
- Analyst notes are bounded, sanitized, and retained according to the owner-approved policy; they cannot contain credentials or raw payloads.
- Every report/API/UI surface carries the exact synthetic-demo limitation text and machine-readable false-capability flags.
- No metric or chart may be labeled “production,” “real traffic,” “validated prevention,” or equivalent.
- Supply-chain evidence must cover Python, Node, native libraries, Docker images, CI actions, and any report-generation tools.

## 11. Dependencies and sequencing

P1 depends on the accepted Gate 5S-A/B/C synthetic manifests and existing offline scoring boundaries. P2 depends on stable P1 run/evidence identifiers. P3 depends on P1/P2 interfaces being frozen. P4 depends on P3 having no release-blocking findings. P5 depends on reproducibility and QA evidence from P4.

No phase depends on UNSW-NB15, a real dataset, publisher communication, live capture, a public network, or an enforcement adapter.

## 12. Test and acceptance matrix

| Area | Required evidence |
| --- | --- |
| Contracts | Valid/invalid/version-mismatch fixtures; exact schema and limitation flags |
| Determinism | Repeated runs match manifest, metric, and report hashes |
| Monitoring | Missing/unseen/range/schema, stale input, threshold, low-sample, and not-evaluable cases |
| Feedback | RBAC-negative matrix, audit, bounded notes, immutable history, IDOR/CSRF/Origin |
| Observability | Correlation IDs, sanitized errors, bounded cardinality, health/readiness, report integrity |
| Resource safety | Time, memory, rows, disk, queue, concurrency, retry, cancellation, retention |
| Security | Dependency/SBOM/native scans, secrets, large files, container posture, focused local penetration tests |
| Migration | Upgrade/downgrade/re-upgrade and rollback refusal on incompatible state |
| Reproducibility | Two clean local Compose runs with identical synthetic evidence |
| Portfolio | Demo script, screenshots, limitation text, false-capability flags, no real-world claims |

## 13. Major risks and mitigations

- **Misleading synthetic claims:** mandatory limitation text, flags, hash-bound reports, and review gates.
- **Drift interpreted as a production signal:** synthetic/offline labels, no automatic action, minimum-sample and `not_evaluable` states.
- **Feedback becomes an unreviewed training channel:** immutable evidence, role separation, new manifest required for any later training.
- **Observability leaks sensitive data:** field allowlists, redaction tests, cardinality limits, sanitized errors.
- **Dependency/native drift breaks ARM64 reproducibility:** lockfiles, image digests, SBOM, dual clean-run evidence.
- **Retention or backup failures:** scheduled cleanup tests, restore drills, hash revalidation, explicit failure reports.
- **Scope creep toward enforcement:** static/runtime simulation-only gates and a hard prohibition on adapters, capabilities, public networking, and live capture.
- **Portfolio overclaiming:** reviewer sign-off on README, model cards, demo text, and screenshots.

## 14. Decisions requiring explicit owner approval

1. Approve the five-gate sequence P1–P5 and whether each gate must be separately published.
2. Approve offline synthetic monitoring only; no online inference or model activation.
3. Approve the warning/critical drift statistic, minimum sample counts, and default thresholds during P1 design.
4. Approve feedback dispositions, note limits, retention period, and whether a second analyst role is required.
5. Approve the observability backend boundary (Prometheus-compatible local metrics and local reports only).
6. Approve the existing retention defaults for monitoring/feature/model evidence and confirm no exceptional holds.
7. Approve the local ARM64 Docker Compose reproducibility target and no public deployment.
8. Approve focused local penetration testing and Trivy/SBOM/native scans as release gates.
9. Approve portfolio publication format and whether screenshots/recordings may be made public.
10. Confirm that no owner decision may re-enable real prevention, automatic prevention, live capture, real datasets, publisher contact, or public-network enforcement under this roadmap.

## 15. Deferred work and prohibited capabilities

The following remain deferred indefinitely: Gate 10B/10C enforcement implementation, adapter or firewall work, real/lab prevention execution, live capture, real datasets, publisher outreach, public-network deployment, online inference, automatic model promotion/retraining, and any Sprint 11 work that would depend on them. A future project charter would be required to revisit a permanent deferral; this roadmap does not provide that authority.

## 16. Proposed post-MVP acceptance criteria

The post-MVP effort is complete only when all of the following are true:

- P1–P5 completion reports are present, hash-bound, and owner-reviewed.
- Monitoring and feedback are synthetic/offline, deterministic, audited, RBAC-protected, and incapable of changing detection/prevention state.
- Reports and observability evidence are aggregate-only, redacted, reproducible, retained, and restorable.
- Full QA and security gates have no unresolved Critical or High issue.
- A clean ARM64 local Compose setup reproduces the documented checks and synthetic evidence.
- Portfolio materials accurately describe the system as an academic/portfolio synthetic simulation and make no real-world performance or prevention claim.
- Static and runtime checks prove there is no live capture, real dataset, publisher contact, online inference, enforcement adapter, privileged container, host networking, firewall capability, or automatic prevention.

## 17. Exact implementation authorization prompt

Use this prompt only after reviewing this roadmap and approving the owner decisions in Section 14:

> Approve and begin AegisAI NIDPS post-MVP synthetic-only work using `docs/POST_MVP_SYNTHETIC_ROADMAP.md`.
>
> First confirm the published baseline, hosted CI result, clean working tree, and the accepted Gate 5S-A/B/C synthetic evidence. Read all governing documents and this roadmap completely. Preserve all existing limitation text, false-capability flags, hashes, retention rules, RBAC, CSRF/Origin, audit, Celery JSON-only, artifact-integrity, and simulation-only invariants.
>
> Authorize Gate P1 only: synthetic monitoring/drift contracts and evidence plus analyst feedback foundations. Use synthetic/offline artifacts only. Implement versioned monitoring and feedback schemas, deterministic fixtures, hash-bound baselines, quality/drift evidence, `not_evaluable` handling, RBAC/CSRF/Origin/audit, bounded JSON-only UUID Celery tasks, reversible metadata migrations, controlled artifacts, retention/cleanup, metadata-only APIs/UI, tests, and documentation.
>
> Do not use real or third-party datasets, UNSW-NB15, NUSW-NB15, mirrors, publisher contact, live capture, public networks, online inference, model activation, automatic training/promotion/retraining, firewall or host-state integration, sockets, subprocesses, packet handling, privileged containers, host networking, real or automatic prevention, alert/detection/incident/prevention mutation, or any later P2–P5 work.
>
> Run and record the applicable contract, determinism, monitoring, feedback, RBAC-negative, CSRF/Origin, audit, resource, retention, migration, Celery, Docker, frontend/accessibility, dependency/SBOM, secret, large-file, health, and simulation-only checks. Every artifact, report, API response, and UI view must carry the exact synthetic-demo limitation text and machine-readable false-capability flags. Stop at the uncommitted Gate P1 completion gate and report files, migrations/interfaces, hashes, commands, checks, failures/skips, assumptions, residual risks, acceptance status, and the exact separate Gate P2 authorization prompt. Do not commit or publish.

## 18. Planning status

**READY FOR OWNER REVIEW.** This document changes no production code and authorizes no implementation, experiment, dataset access, enforcement action, commit, publication, or deployment.
