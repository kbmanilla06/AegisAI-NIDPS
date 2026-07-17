# AegisAI NIDPS Post-MVP Gate P2 Implementation Plan

**Status:** Owner-authorized for Gate P2 implementation; stop at the uncommitted completion gate
**Scope:** Synthetic-only observability, aggregate reporting, dashboards, and recovery evidence
**Baseline:** Public `main` and local `HEAD` at `804846898e8bdd9b233450aaf180778690955fee`
**Hosted CI:** Run #36 completed successfully for the baseline (recorded GitHub run database ID `29563401477`)
**Predecessor:** Gate P1 published and approved; `docs/POST_MVP_GATE_P1_COMPLETION_REPORT.md`

## 1. Planning decision and gate boundary

Gate P2 is a separately reviewable post-MVP gate. It is limited to evidence about the existing synthetic/offline system:

- bounded structured observability;
- deterministic aggregate reports;
- metadata-only dashboard views;
- retention and cleanup evidence;
- disposable local backup/restore and recovery evidence; and
- the tests, documentation, and security controls needed to prove those boundaries.

Gate P2 does **not** authorize online telemetry, live packet capture, a public metrics endpoint, model activation, online inference, training, model promotion, real or third-party data, publisher contact, alert/detection/incident mutation, or any real prevention capability. A report or dashboard result is evidence only and cannot cause a prediction, alert, rule change, incident transition, policy change, model change, or simulated-prevention request.

The implementation must stop at an uncommitted Gate P2 completion checkpoint. Publication and Gate P3 require separate owner approval.

## 2. Baseline and inherited invariants

### 2.1 Confirmed baseline

- `git rev-parse HEAD` and the cached `origin/main` reference resolve to `804846898e8bdd9b233450aaf180778690955fee`.
- Hosted CI Run #36 is recorded as completed successfully for that SHA.
- Gate P1 is published and approved. It provides the `synthetic-monitoring-snapshot/1.0.0`, `synthetic-monitoring-result/1.0.0`, `synthetic-drift-default/1.0.0` contracts, accepted Gate 5S-A/B/C hash binding, aggregate-only validation, `not_evaluable`, RBAC, CSRF/Origin, audit, JSON-only UUID Celery tasks, controlled artifacts, and 30/180-day retention behavior.
- The working tree is not clean because it contains inherited, uncommitted Sprint 10 planning/preflight documents and related decision/threat/risk edits. Those files are outside Gate P2 and must be preserved without modification or staging.

### 2.2 Invariants that must remain true

1. Synthetic project-generated artifacts are the only permitted evidence source. UNSW-NB15, NUSW-NB15, mirrors, samples, and all other real or third-party datasets remain blocked.
2. Publisher outreach and acquisition remain cancelled and blocked.
3. Every monitoring/reporting surface carries the exact synthetic-demo limitation text and machine-readable false-capability flags.
4. No raw endpoint address, payload, credential, query string, token, internal path, stack trace, model input, or dataset payload is logged, stored in a report, exported, or returned by a metadata API.
5. PostgreSQL remains authoritative. Redis is disposable coordination only. Artifacts use opaque controlled-volume references and SHA-256 hashes.
6. Celery messages remain JSON-only and contain only bounded UUIDs; workers resolve all other values server-side.
7. Detection, alert, incident, assessment, model, registry, and prevention state are read-only from P2. Simulation remains the only prevention behavior.
8. No socket, subprocess, packet, firewall, host-state, privileged-container, host-network, or public-network capability may be introduced.
9. Sensitive state changes remain centrally authorized, CSRF/Origin protected, idempotent where applicable, and audited. Audit persistence failure fails closed for administrative/report-finalization/retention actions.
10. Critical or High security findings, unsafe defaults, unverifiable retention, invalid lineage, or misleading claims block the gate.

## 3. Confirmed requirements

The following are inherited requirements from the master prompt, implementation guide, roadmap, architecture, threat model, test strategy, deployment strategy, and Gate P1 report:

- Observability must be structured, bounded, correlation-aware, and sanitized.
- Metrics must cover latency, errors, queues, task age, health/readiness, artifact integrity, drift runs, feedback, and retention outcomes, with explicit label/cardinality allowlists.
- Reports must be deterministic, aggregate-only, hash-bound, policy-versioned, retained, and restorable.
- Low sample, missing, stale, incompatible, or hash-mismatched evidence must be `not_evaluable` or failed closed; it must not be presented as normal, healthy, or production evidence.
- Feedback and reporting must preserve distinction between analyst observation and ground truth.
- Backup/restore must be exercised on disposable local environments, including PostgreSQL and the controlled artifact volume, with referential-integrity and SHA-256 revalidation.
- Retention defaults are flows 30 days; feature/model/monitoring evidence 30 days; generated reports and stored predictions 30 days; alerts, incidents, notes, and audit 180 days; no exceptional holds.
- Any later export is least-privilege, redacted, explicitly audited, and limited to aggregates.
- P2 must use the existing ARM64 local Docker Compose topology and must not authorize non-local deployment.

## 4. Proposed P2 contracts

The exact names and versions below are proposed defaults and require owner approval before implementation.

### 4.1 `synthetic-observability-event/1.0.0`

Server-generated event envelope containing only:

- `event_id` and `correlation_id` as UUIDs;
- UTC `occurred_at` and bounded `duration_ms`;
- closed `operation` and `component` enumerations;
- `status` (`succeeded`, `failed`, `degraded`, `not_evaluable`);
- bounded counts (`rows`, `groups`, `tasks`, `bytes`) and safe error category;
- actor role class, never an email, token, credential, or raw identity;
- schema/policy/version identifiers and evidence hash references; and
- the synthetic limitation text and false-capability flags.

The contract rejects unknown fields, arbitrary labels, free-form paths, URLs, addresses, stack traces, and unbounded strings. It is not a packet/event log and contains no raw flow.

### 4.2 `synthetic-sli-snapshot/1.0.0`

An immutable aggregate snapshot with a fixed metric allowlist:

| Area | Metrics |
| --- | --- |
| API | request count, bounded latency buckets, 4xx/5xx counts, auth/CSRF rejection counts, readiness failures |
| Celery | submitted/completed/failed/not-evaluable counts, queue age buckets, duration buckets, retry/cancel counts |
| Monitoring | eligible/ineligible/stale/hash-mismatch counts, missing/unseen/range/schema rates, drift status counts |
| Feedback | disposition counts, unresolved age buckets, review transition counts, bounded note-rejection counts |
| Artifacts | accepted/rejected integrity checks, size buckets, expiry/cleanup counts, orphan counts |
| Retention | due/succeeded/failed/deferred cleanup counts and oldest-age bucket |
| Recovery | backup/restore attempt, integrity, replay, and rollback outcomes |
| Health | liveness/readiness outcome and dependency category, without dependency secrets |

Metrics are aggregate values, not row-level evidence. Each series binds to a source hash set, policy version, UTC window, bucket policy, and minimum-sample policy. The implementation may add no metric without updating the closed allowlist and contract version.

### 4.3 `synthetic-aggregate-report/1.0.0`

The canonical report envelope contains:

- report UUID, type, generation time, UTC time window, and generator code version;
- source artifact hashes and accepted Gate 5S-A/B/C identity set;
- source schema, monitoring policy, retention policy, and report policy versions;
- aggregate sections for quality/drift, feedback, API/worker health, resource outcomes, retention, and recovery;
- per-section status (`complete`, `partial`, `failed`, `not_evaluable`), sample counts, and safe reason codes;
- SHA-256 of canonical JSON payload and controlled artifact reference;
- exact limitation text and all false-capability flags; and
- no raw records, vectors, endpoint values, model inputs, notes, or uncontrolled identifiers.

Reports with any incomplete required section are not published as complete. A failed report is a safe status row without an internal exception or path.

### 4.4 `synthetic-dashboard-view/1.0.0`

UI/API responses expose only authorized aggregate report and SLI fields. Every response includes `synthetic_only=true`, the exact limitation text, and the complete false-capability flag set. A dashboard must not silently transform `not_evaluable` to zero, green, healthy, or “no drift.”

## 5. Evidence sources and lineage

P2 may read only server-resolved, accepted synthetic evidence:

- Gate 5S-A scenario, canonical-flow, target, split, quality, leakage, and feature artifacts;
- Gate 5S-B candidate/model-card/parity evidence, without loading or activating a model;
- Gate 5S-C registry metadata and isolated offline scoring aggregate outputs;
- Gate P1 monitoring snapshots/results and analyst-feedback metadata; and
- P2-generated local health, task, retention, backup, restore, and security-test evidence.

Each report must bind to the exact source SHA-256 values and fail closed if any source is missing, expired, superseded, incompatible, or outside the accepted synthetic identity set. Browser parameters may select a server-side report ID only; they may not select paths, URLs, artifact bytes, model bytes, SQL, or arbitrary metric names.

The accepted Gate 5S hashes remain unchanged. P2 must not rewrite, regenerate, or replace them. If a source artifact is expired under policy, the report is `not_evaluable` unless the owner separately changes retention policy; no exceptional hold is assumed.

The required identity set is:

| Evidence | SHA-256 |
| --- | --- |
| Scenario catalog | `72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87` |
| Feature schema | `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114` |
| Dataset content | `b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a` |
| Canonical-flow artifact | `96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac` |
| Target manifest | `90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70` |
| Feature artifact | `454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9` |
| Split manifest | `d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895` |
| Quality report | `c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4` |
| Leakage report | `2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d` |
| Training identity set | `25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7` |
| Validation identity set | `96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f` |
| Sealed-test identity set | `ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4` |

## 6. Observability design

### 6.1 Collection boundary

Collection is local and offline. The API and worker emit bounded structured events for their own synthetic operations; no production collector, host agent, live network input, external telemetry endpoint, or public Prometheus exposure is added. A Prometheus-compatible scrape format may be generated only on localhost or consumed inside the disposable Compose project, with authentication and RBAC if exposed through the API.

### 6.2 Field and label allowlists

Allowed dimensions are closed enums such as `component`, `operation`, `status`, `source_kind`, `report_type`, `task_name`, `policy_version`, and bounded role class. IDs are used only as opaque correlation references and never as metric labels. User email, IP, endpoint, target, URL, SQL, path, exception text, request body, and free-form note are forbidden.

Cardinality caps, time-bucket limits, maximum series, and maximum event size are enforced before persistence. The API returns redacted aggregate records, not log streams. Any validation failure is counted with a safe reason code and is not logged verbatim.

### 6.3 Correlation and clock policy

Every API request, task, report, cleanup, backup, and restore operation receives a UUID correlation ID. Workers carry only the UUID envelope and resolve the correlation row server-side. UTC is authoritative; event-time data is never used as a retention clock. Clock skew beyond the approved bound yields `not_evaluable` for time comparisons.

## 7. Aggregate reporting

### 7.1 Report types

The initial fixed report catalog is:

1. `synthetic_quality_drift` — source quality, schema/range/missingness, P1 drift, stale/hash failures, and `not_evaluable` reasons.
2. `synthetic_feedback_summary` — disposition and unresolved-review aggregates only; notes are not included.
3. `synthetic_operations` — API/task latency, queue age, retries, errors, health, and resource-limit outcomes.
4. `synthetic_retention_recovery` — expiry/cleanup, backup/restore, hash revalidation, replay, and partial-restore outcomes.
5. `synthetic_gate_evidence` — links and hashes for P1/P2 checks, never raw test payloads.

No report type may contain predictions for individual rows, alert/detection state changes, prevention decisions, endpoint lists, or model input values.

### 7.2 Determinism and finalization

The report generator sorts keys, metric names, dimensions, and source hashes; uses canonical JSON; fixes decimal/float serialization; and records the generator and policy versions. Re-running the same source identity, time window, policy, and environment must produce the same aggregate payload and SHA-256. Report finalization is a separately audited transition and requires the caller to have report-finalize permission. A finalized report is immutable; corrections create a new report linked to the prior hash.

### 7.3 Privacy-preserving aggregation

- Use UTC buckets and minimum group/sample thresholds. Proposed default minimum is 30 eligible rows per displayed subgroup; smaller groups become `not_evaluable` or are combined into an “other/insufficient” bucket.
- Do not display analyst note text, endpoint values, asset names, raw source identifiers, or single-row outcomes.
- Use synthetic scenario/source labels only when they are already approved metadata; never present them as real attack categories.
- Apply suppression to rare dimensions and cap report/export rows.
- A report query cannot be used to infer a single row by subtracting overlapping filters; filters are a closed, non-overlapping server-side catalog.

## 8. Dashboard and API boundaries

### 8.1 Metadata-only UI

Proposed views:

- overview: health, report freshness, aggregate status, and limitation banner;
- quality/drift: quality rates, baseline/current hashes, sample counts, threshold policy, and `not_evaluable` reasons;
- operations: queue age, task/resource outcomes, API status buckets, and readiness;
- feedback: disposition counts and unresolved age buckets, with no note text;
- retention/recovery: cleanup and backup/restore evidence; and
- reports: authorized list/detail with hash, status, policy version, and download-disabled-by-default metadata.

Every view must show the exact synthetic-demo limitation language and false-capability flags. No UI control mutates alerts, detections, incidents, models, registries, prevention requests, or policies.

### 8.2 API proposal

Proposed routes are read-only unless explicitly marked:

- `GET /observability/summary`
- `GET /observability/series`
- `GET /observability/reports`
- `GET /observability/reports/{report_id}`
- `POST /observability/reports` (metadata-only report request; CSRF/Origin and idempotency required)
- `POST /observability/reports/{report_id}/finalize` (separate report-finalize permission, CSRF/Origin, reason, and audit)
- `GET /observability/feedback-summary`
- `GET /observability/recovery`

The exact route names remain an owner decision. All responses are schema-validated, paginated, rate-limited, and aggregate-only. Report IDs are opaque UUIDs. No arbitrary filters, file paths, URLs, SQL, metric names, or exporter targets are accepted.

### 8.3 RBAC and IDOR

The centralized permission service must define and test a matrix at minimum:

| Role | Read aggregate evidence | Request report | Finalize report | Retention/recovery detail | Audit detail |
| --- | --- | --- | --- | --- | --- |
| Viewer | redacted | no | no | summary only | no |
| SOC Analyst | yes | yes | no | summary | no |
| Senior Analyst | yes | yes | no | detail | permitted audit subset |
| Security Administrator | yes | yes | yes | detail | yes |
| System Administrator | operational detail | yes | no | execute cleanup/recovery | operational audit |
| Auditor | redacted aggregate | no | no | read-only evidence | read-only audit |

Finalization, retention policy changes, cleanup, backup/restore, and report access are audited. No user can approve their own report finalization if a separate reviewer is required by the accepted policy. Every object fetch checks server-side ownership/permission and returns the same safe not-found response for unauthorized IDs.

## 9. Retention, cleanup, and recovery

### 9.1 Proposed retention defaults

| Item | Proposed retention |
| --- | --- |
| Monitoring snapshots/results and P2 operational aggregates | 30 days |
| Generated reports and stored predictions | 30 days |
| Controlled feature/model/synthetic artifacts | 30 days, per existing policy |
| Analyst notes, alerts, incidents, and audit records | 180 days |
| Backup evidence and immutable manifest/hash lineage | 180 days unless the owner selects a longer governance period |
| Exceptional investigation holds | disabled |

Expiry uses trusted `created_at`/`expires_at`, not hostile event time. Cleanup is bounded, idempotent, actor/audit recorded, and never deletes audit lineage needed to explain a retained report. A failed cleanup remains visible as failed/deferred and is retried within limits; it is never silently counted as success.

### 9.2 Backup and restore evidence

On disposable local Compose environments only:

1. Create a PostgreSQL backup and controlled-volume manifest with SHA-256 and object counts.
2. Destroy the disposable database/volume and restore into a fresh isolated project.
3. Revalidate migrations, foreign keys, report/source hashes, artifact mode/path controls, and audit immutability.
4. Replay an idempotent report/cleanup operation and prove no duplicate or mutation.
5. Inject a missing/corrupt artifact and confirm the report is `failed`/`not_evaluable`, not silently repaired.
6. Record recovery duration, resource usage, and safe failure code.

No backup is uploaded, emailed, published, or stored in Git. Restoration never enables a model, online inference, or prevention behavior.

## 10. Celery and resource limits

Proposed initial limits, subject to measurement during implementation:

- report task: 120-second soft / 135-second hard limit, maximum 100,000 aggregate input rows, maximum 10,000 output series, maximum 16 MiB canonical report;
- snapshot aggregation: 60-second soft / 75-second hard limit, maximum 100,000 source rows and 64 MiB working memory;
- cleanup task: 120/135 seconds, maximum 10,000 objects/rows per invocation;
- backup/restore verification: 300-second hard limit, one disposable run at a time, maximum 5 GiB temporary storage;
- queue: one-message prefetch, late acknowledgement, bounded retries (two retries unless a safe category disallows retry), no unbounded fan-out;
- task envelopes: registered task name plus one UUID and server-side correlation lookup, JSON-only;
- per-actor report requests: proposed 10 per 5 minutes, with a unique idempotency key;
- API aggregate page: maximum 100 rows, fixed server-side sort, no arbitrary pagination depth;
- controlled report artifact: mode `0600`, opaque UUID reference, SHA-256, and no executable media.

If measured ARM64 resource use exceeds these limits, the task must reduce scope or return a safe `resource_limit`/`not_evaluable` result. It must not raise limits silently.

## 11. Failure handling and safety behavior

- Invalid lineage, source hash, schema, policy, time window, or retention state: fail closed with a safe code.
- Low sample, stale data, missing baseline, or insufficient independent support: `not_evaluable`; never zero-fill or infer health.
- Duplicate request: return the original immutable report job/result for the same actor-scoped idempotency key.
- Concurrent finalization/cleanup: optimistic version check and database lock; one winner, deterministic conflict response, complete audit.
- Worker crash or timeout: late acknowledgement, bounded retry only for safe transient categories, and a persisted failed/reconciliation state.
- Redis unavailable: accept no untrackable asynchronous request; show degraded health.
- PostgreSQL unavailable: reject state-changing report/finalization/cleanup operations; do not claim success from cache.
- Artifact missing/corrupt: quarantine the report result, preserve source hashes and failure evidence, and never follow a client-supplied path.
- Partial backup restore: report failed recovery, stop further replay, retain safe audit, and require a fresh disposable restore.
- Metrics/reporting failure must not block deterministic detection or simulation, but it must be visible in health and audit evidence.

## 12. Security, privacy, and supply-chain controls

- Use strict Pydantic contracts with closed enums, bounds, canonical serialization, and output allowlists.
- Sanitize analyst notes before any aggregate count; never include note text in reports.
- Enforce session, CSRF token, Origin, CORS, RBAC, IDOR, rate limit, and audit checks for every route.
- Redact sensitive target/address fields and internal paths even for operational views; use role-specific projections.
- Add tests for report-injection strings, Unicode/control characters, oversized dimensions, integer overflow, NaN/Infinity, duplicate/late events, and attempted path/URL/SQL values.
- Re-run Ruff, mypy, Bandit/Semgrep-equivalent, pip-audit, npm audit, secret scanning, large-file scanning, SBOM, native dependency review, and Docker Scout/Trivy-equivalent. Any unresolved Critical/High finding blocks the gate.
- Keep ARM64 image/dependency pins and the P1 Perl-remediation posture; no Alpine or unreviewed native dependency substitution.
- Retain only sanitized evidence. Never expose cookies, CSRF tokens, signed URLs, credentials, or auth material in metrics, logs, reports, or screenshots.

## 13. Migration and artifact strategy (implementation gate only)

If implementation is later authorized, use one additive reversible migration after `0013_p1_monitoring`. Candidate metadata tables are:

- `synthetic_observability_events` (sanitized bounded event rows);
- `synthetic_sli_snapshots` (immutable aggregate metric snapshots);
- `synthetic_report_jobs` and `synthetic_reports` (request state, hash, policy/source lineage, status);
- `synthetic_recovery_runs` (backup/restore evidence); and
- any required report-policy/retention-version reference rows.

The exact migration number and columns require schema review. Downgrade must refuse while live report/evidence rows or controlled artifacts remain inventoried, then remove only P2 objects. Upgrade, downgrade, and re-upgrade must be proven on empty and populated disposable PostgreSQL instances. No migration is created by this planning turn.

Reports use canonical JSON and controlled local artifacts only. PostgreSQL stores opaque references, media type, byte count, SHA-256, schema/policy/source hashes, and expiry. No new model format, model loader, Parquet reader, packet parser, or network transport is introduced by P2.

## 14. Test and evidence matrix

### Contract and determinism

- valid, missing, wrong-type, unknown-field, Unicode/control, NaN/Infinity, oversized, duplicate, out-of-order, stale, and version-mismatch fixtures;
- exact limitation text and false-capability flag assertions on every contract/API/UI/report;
- canonical ordering, repeated-run hash equality, source-hash binding, policy-version binding, and immutable finalization tests;
- low-sample, missing-baseline, stale, corrupt, and `not_evaluable` cases.

### Security and privacy

- full six-role RBAC-negative matrix, IDOR, CSRF/Origin, session/revocation, safe errors, redaction, report-injection, path/URL/SQL rejection, audit immutability, and audit-failure fail-closed tests;
- aggregate subgroup suppression, minimum-sample, overlapping-filter inference, cardinality, row/byte cap, and export-denial tests;
- static/runtime guards proving no subprocess/socket/firewall/packet/host-state capability, no live capture, no real dataset references, and no alert/detection/incident/prevention mutation.

### Celery, resource, migration, and recovery

- JSON-only malformed envelope and unregistered-task rejection;
- idempotent replay, concurrent request/finalization/cleanup, late acknowledgement, retry exhaustion, cancellation, timeout, queue saturation, memory/row/disk/output caps;
- migration upgrade/downgrade/re-upgrade with empty and populated evidence, downgrade refusal, retention cleanup, backup/restore, corrupt-artifact and partial-restore handling;
- Docker Compose health/readiness, non-root/read-only/cap-drop/no-host-network checks, and ARM64 native compatibility.

### Frontend and operations

- ESLint, TypeScript, unit/build, keyboard/focus/labels/contrast/semantic accessibility checks;
- deterministic dashboard rendering of `not_evaluable`, degraded, failed, and stale states;
- report freshness, queue/health failure, retention failure, and recovery failure views;
- local disposable Compose run from clean checkout with no credentials or external services.

Every check must record command, environment, timestamp, commit, result, skipped reason (if any), and residual risk. A skipped required check is not a pass.

## 15. Acceptance criteria proposal

Gate P2 can be considered complete only if all criteria pass:

1. Versioned observability, SLI, report, and dashboard contracts are reviewed and fixtures cover hostile/edge cases.
2. Reports and dashboard/API responses are aggregate-only, deterministic, hash-bound, redacted, policy-versioned, and carry limitation text plus false-capability flags.
3. Source lineage accepts only the exact Gate 5S-A/B/C and P1 identities; mismatches fail closed.
4. `not_evaluable` is preserved for low sample, stale, missing, corrupt, incompatible, or insufficient evidence; no path silently converts it to healthy/zero.
5. Metrics have closed dimensions, bounded cardinality, row/byte/time limits, and no sensitive fields.
6. RBAC, CSRF/Origin, IDOR, audit, report finalization, retention, and cleanup behavior pass the complete negative/security matrix.
7. Celery is JSON-only, UUID-only, bounded, idempotent, and safe under retry, timeout, concurrency, and Redis failure.
8. Retention defaults and no-exception policy are enforced and evidenced; cleanup failures remain visible.
9. PostgreSQL and controlled artifact backup/restore succeeds in a disposable ARM64 Compose environment with SHA-256 and referential-integrity revalidation; corruption/partial restore fails closed.
10. Migration upgrade/downgrade/re-upgrade evidence passes on empty and populated databases, with safe downgrade refusal.
11. Docker, dependency, SBOM/native, secret, large-file, frontend, accessibility, health, and simulation-only checks pass with zero unresolved Critical/High findings.
12. Static and runtime evidence proves P2 cannot activate/load a model, enable online inference, mutate alerts/detections/incidents/prevention, acquire a dataset, contact the publisher, capture packets, or execute prevention.
13. Documentation, report schema, operator recovery runbook, and residual-risk record are complete, and no public commit or publication occurs before owner review.

## 16. Assumptions

- P2 uses the existing PostgreSQL/Redis/FastAPI/Celery/React/Vite Compose topology and does not add a hosted observability service.
- P1 monitoring rows are trusted server-side inputs but are still revalidated by P2 contracts and hash checks.
- Aggregate reports are local portfolio evidence, not production SLOs, threat intelligence, or real-network performance evidence.
- The proposed 30-row minimum subgroup and resource limits are conservative starting values and may be reduced, never silently increased, after measurement.
- Existing retention defaults and “no exceptional holds” remain active unless the owner explicitly changes them.
- Backup/restore evidence is disposable local evidence and is not a production disaster-recovery certification.

## 17. Decisions requiring explicit owner approval

1. Approve Gate P2 as synthetic-only, offline, aggregate-only, simulation-preserving work and keep all listed prohibitions permanent.
2. Approve the proposed contract names/versions: `synthetic-observability-event/1.0.0`, `synthetic-sli-snapshot/1.0.0`, `synthetic-aggregate-report/1.0.0`, and `synthetic-dashboard-view/1.0.0`.
3. Approve the fixed report catalog and metric allowlist, including whether a localhost-only Prometheus-compatible scrape is needed.
4. Approve minimum subgroup support of 30 eligible rows, UTC bucket policy, suppression behavior, and no overlapping arbitrary filters.
5. Approve the proposed RBAC matrix and whether Security Administrator finalization must always be distinct from the report requester.
6. Approve retention: monitoring/P2 aggregates 30 days; generated reports/stored predictions 30 days; alerts/incidents/notes/audit 180 days; backup evidence 180 days; no exceptional holds.
7. Approve proposed report/task/API limits, including 120/135-second report tasks, 60/75-second aggregation, 300-second recovery verification, 16 MiB report artifacts, 100,000 input rows, 10,000 output series, and per-actor rate limits.
8. Approve canonical JSON as the sole report artifact format and controlled local volume storage with PostgreSQL references and SHA-256 hashes.
9. Approve the disposable backup/restore and corruption-recovery evidence procedure.
10. Approve the P2 migration approach and downgrade-refusal rule, with the exact migration number deferred to implementation review.
11. Approve the requirement for zero unresolved Critical/High findings and the complete local security/dependency/SBOM/Docker/accessibility gate set.
12. Confirm that P2 cannot authorize model activation, online inference, real data, publisher contact, live capture, alert/detection/incident mutation, or any prevention capability.

## 18. Risks and mitigations

| Risk | Impact | Mitigation / release trigger |
| --- | --- | --- |
| Synthetic aggregates are mistaken for production telemetry | Misleading portfolio or operational claims | Mandatory limitation/flags, source hash binding, synthetic labels, reviewer sign-off; any overclaim blocks release |
| Report or metric fields leak sensitive data | Privacy harm | Closed field/label allowlists, redaction, minimum support, no raw exports, negative tests |
| `not_evaluable` is misread as healthy | Unsafe decisions | Explicit status/UX, no zero fill, contract and screenshot tests |
| High-cardinality dimensions exhaust storage/UI | Availability degradation | Enum allowlist, caps, suppression, pagination, queue/resource limits |
| Stale or corrupt lineage produces a plausible report | Invalid evidence | SHA/schema/policy checks and fail-closed report state |
| Feedback aggregates become an unreviewed training channel | Governance/leakage | Immutable observations, separate roles, no model mutation, new owner gate for later training |
| Retention cleanup or restore is incomplete | Privacy/integrity loss | Scheduled bounded cleanup, backup/restore drill, hash revalidation, visible failed state |
| Dependency/image/native drift breaks ARM64 | Reproducibility/security | Pins, SBOM, Docker Scout/Trivy-equivalent, native import checks, zero Critical/High gate |
| Report generation starves worker or DB | Service degradation | Separate bounded task limits, pagination, rate limits, idempotency, degraded health |
| Scope expands toward live monitoring or prevention | Safety boundary failure | Static/runtime simulation-only guards, explicit prohibited capabilities, separate authorization gate |
| Inherited uncommitted Sprint 10 documents are accidentally altered | History/governance confusion | Preserve untouched; P2 change review must include only the P2 plan until implementation approval |

## 19. Dependencies and deferred work

P2 depends on published P1 contracts/evidence and accepted Gate 5S-A/B/C hashes. P3 security hardening depends on frozen P2 contracts. P4 reproducibility depends on P3 passing. P5 portfolio demonstration depends on P4 evidence.

Deferred or prohibited work includes real/automatic/lab prevention, adapters, firewall/host-state/socket/subprocess integration, live capture, online inference, model activation/promotion/retraining, real datasets, publisher contact, public-network deployment, alert/detection/incident mutation, and Sprint 6+ changes.

## 20. Exact Gate P2 implementation authorization prompt

```text
Approve AegisAI NIDPS Gate P2 implementation using docs/POST_MVP_GATE_P2_PLAN.md.

Before proceeding, confirm public main is 804846898e8bdd9b233450aaf180778690955fee and hosted CI Run #36 passed. Read the plan, all governing documents, and docs/POST_MVP_GATE_P1_COMPLETION_REPORT.md completely. Confirm the working tree contains only explicitly reviewed inherited Sprint 10 planning/preflight changes plus the approved P2 implementation changes; do not rewrite or delete inherited history.

Authorize only synthetic/offline Gate P2: versioned bounded observability contracts, aggregate SLI snapshots and reports, metadata-only dashboard/API views, retention and cleanup evidence, disposable local PostgreSQL/controlled-artifact backup/restore evidence, reversible additive metadata migration, JSON-only UUID Celery tasks, RBAC/CSRF/Origin/IDOR/audit controls, resource limits, tests, and documentation.

Use only the accepted Gate 5S-A/B/C synthetic evidence and Gate P1 monitoring/feedback metadata. Preserve every accepted hash, exact synthetic-demo limitation text, false-capability flag, 30/180-day retention policy, controlled-volume/SHA-256 artifact policy, and simulation-only boundary. Keep UNSW-NB15/NUSW-NB15 acquisition blocked and publisher outreach cancelled.

Do not use real or third-party datasets; contact the publisher; download, preview, parse, or transfer dataset bytes; configure live packet capture; enable online inference; activate, train, promote, or load a model; mutate alerts, detections, incidents, assessments, rules, thresholds, registries, or prevention state; add firewall, host-state, socket, subprocess, packet, public-network, privileged-container, host-network, or enforcement capability; begin Gate P3, P4, P5, Sprint 6, or unrelated work; commit or publish.

Run and record all applicable contract, determinism, aggregate/privacy, not_evaluable, RBAC-negative, IDOR, CSRF/Origin, audit, retention, resource, Celery, migration upgrade/downgrade/re-upgrade, backup/restore, corruption/failure, Docker/health, dependency/SBOM/native, secret, large-file, frontend/accessibility, and simulation-only checks. Stop at the uncommitted Gate P2 completion gate and report files changed, migration/interfaces, hashes, commands, results, failures/skips, assumptions, residual risks, and the exact publication-review prompt. Wait for separate owner approval before committing, pushing, or beginning Gate P3.
```

## 21. Planning status

This document is the sole Gate P2 deliverable from this planning turn. No production code, migration, task, API, UI, artifact, report, test, dependency, Docker configuration, dataset, or enforcement capability was added or changed. Owner approval is required before implementation.
