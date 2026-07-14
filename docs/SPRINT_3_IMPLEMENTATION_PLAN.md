# Sprint 3 Implementation Plan — Deterministic Detection and Alert Generation

**Planning date:** 2026-07-14

**Status:** Planning artifact; recommended defaults were approved and implementation was authorized separately

**Target sprint:** Sprint 3 — Signature and Behavioral Detection

**Release boundary:** Sprints 0–9, IDS with simulated IPS
**Authorized baseline:** Public `main` at `29c2891f1e6bfe6686d4ef6c2489932d2f0a2fcd`

## 1. Planning gate and evidence

The Sprint 3 planning gate is satisfied:

- GitHub's public repository API reported `main` at commit `29c2891f1e6bfe6686d4ef6c2489932d2f0a2fcd`.
- GitHub Actions Run #4 (`29316924487`) reported `status=completed`, `conclusion=success`, `head_branch=main`, and the same head SHA.
- Local `HEAD` and the recorded `origin/main` both resolve to that SHA.
- `git status --short --branch` reported only the branch header and no tracked or untracked changes before this document was created.

The local checkout remains on `feature/sprint-2-ingestion`; local branch `main` is stale. Sprint 3 implementation must begin from the published SHA on a new short-lived Sprint 3 branch without rewriting history.

## 2. Governing documents read

This plan was reconciled against the complete contents of:

- `AegisAI-NIDPS-Master-Prompt.md`
- `AegisAI-NIDPS-Implementation-Guide.md`
- `docs/SPRINT_2_COMPLETION_REPORT.md`
- `docs/BACKLOG.md`
- `docs/DECISIONS.md`
- `docs/DEFINITION_OF_DONE.md`
- `docs/DATABASE.md`
- `docs/api/API.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/threat-model/THREAT_MODEL.md`
- `docs/TEST_STRATEGY.md`
- `docs/DEPLOYMENT_STRATEGY.md`
- `docs/RISK_REGISTER.md`
- `docs/DETECTION_ARCHITECTURE.md`

No application code, migration, scaffold, dependency, dataset, model, packet-capture configuration, prevention integration, commit, or publication is part of this plan.

## 3. Confirmed requirements

The following are already established and are not implementation choices:

1. Sprint 3 produces deterministic, reproducible signature and behavioral detections from authorized canonical telemetry.
2. Every detection carries evidence and the exact immutable rule or external-signature version that produced it.
3. Detection, prevention policy, and prevention execution remain separate. Detection must have no dependency on an enforcement adapter.
4. Prevention remains simulation-only. No rule, signal, alert, worker task, API, or UI action may alter firewall or network state.
5. PostgreSQL is authoritative. Redis and Celery provide recoverable coordination only.
6. Celery task serialization remains JSON-only; tasks carry bounded identifiers, never telemetry bodies, filesystem paths, credentials, or executable definitions.
7. Canonical flow schema v1 remains versioned and immutable.
8. Suricata `alert` records, deferred in Sprint 2, must be normalized as hostile reported evidence rather than treated as proof of compromise.
9. Initial behavioral categories are scan, repeated failure, high connection rate, suspicious DNS volume, possible beaconing, unusual outbound volume, and brute-force behavior, subject to actual input-schema support and false-positive controls.
10. Rule metadata includes key/ID, name, description, source/prerequisites, conditions, window, threshold, severity, MITRE mapping when defensible, evidence definition, false-positive guidance, investigation guidance, prevention recommendation, tests, and change rationale.
11. Duplicates, replays, concurrent evaluation, and alert floods must be bounded and idempotent.
12. Minimal rule, alert, evidence, and live-alert interfaces are required. Server-side authorization is authoritative.
13. Rule/threshold changes and sensitive detection administration are authorized and audited.
14. Alert and audit retention is 180 days; normalized flow retention remains 30 days; raw upload deletion remains after processing or within 24 hours.
15. Telemetry, endpoints, rule text, and metadata remain untrusted at every boundary. No raw packet payload is stored in an alert.
16. No dataset download, feature-engineering pipeline, ML model, anomaly model, ensemble score, threat-intelligence feed, incident workflow, or real/simulated prevention workflow is introduced in Sprint 3.
17. Every applicable quality, security, migration, authorization, concurrency, idempotency, resource, Docker, Celery, health, and documentation gate must produce actual recorded evidence before Sprint 3 can be declared complete.

## 4. Planning findings and constraints

### 4.1 Documentation-state drift

`docs/SPRINT_2_COMPLETION_REPORT.md`, `docs/BACKLOG.md`, and `docs/DEPLOYMENT_STRATEGY.md` still describe Sprint 2 publication or hosted CI as pending, although public `main` and CI Run #4 prove completion. Sprint 3 implementation should first update those status statements only; this planning task intentionally does not modify them.

### 4.2 Canonical-flow limits

Canonical flow v1 supplies endpoints, ports, protocol, time, counters, state, sensor/job provenance, and bounded metadata. It can support:

- destination-port/host scan indicators;
- repeated connection-failure indicators when the source adapter provides a recognized state;
- high connection-rate indicators;
- a basic outbound-volume rule when authoritative asset direction is available.

It does not provide a stable DNS-query contract, authentication outcomes, usernames, application response codes, or all fields needed to claim DNS tunneling or brute-force detection. Sprint 3 must not infer those semantics from arbitrary metadata.

### 4.3 Severity is not the later ensemble risk score

Sprint 3 may assign a deterministic rule severity and source confidence classification. It must not invent the Sprint 6 ensemble risk score, calibrated ML confidence, or automation eligibility. `risk_score`, ensemble `confidence`, and prevention eligibility must remain absent/null until their owning sprint.

### 4.4 Flow retention versus alert evidence retention

Flows expire after 30 days, while alerts/evidence remain for 180 days. Therefore, alert evidence cannot depend on a live flow foreign key alone. It needs a minimal immutable evidence snapshot plus hashes and optional references so the alert remains explainable after flow cleanup.

### 4.5 At-least-once delivery and out-of-order event time

Celery can redeliver tasks, and authorized offline telemetry can arrive out of order. Detection correctness must come from database uniqueness, deterministic time buckets, and transactional upserts—not assumed task ordering or exactly-once delivery.

## 5. Proposed Sprint 3 scope

### 5.1 Included

1. Strict `CanonicalSignatureEventV1` for supported Suricata EVE alert records.
2. A bounded extension of the Suricata adapter so one EVE upload may persist supported `flow` and `alert` records without accepting unrelated EVE event types.
3. Immutable, versioned behavioral-rule definitions using a closed evaluator registry and validated parameters.
4. Rule review, activation, retirement, and rollback-to-prior-version controls.
5. Enabled deterministic rules for port scan, repeated connection failures, and high connection rate.
6. Conditional outbound-volume rule only when asset direction is authoritative.
7. Draft/disabled definitions and fixtures for DNS volume, beaconing, and brute-force categories until their prerequisites are explicitly approved.
8. Detection runs, signature and behavioral signals, alert creation/update, evidence snapshots, fingerprinting, deduplication, suppression, and flood limits.
9. Minimal read APIs, controlled rule-administration APIs, alert list/detail APIs, detection metrics, and an authenticated bounded live-alert channel.
10. Minimal dashboard views for active rule versions, alerts, alert detail/evidence, and live update status.
11. Reversible PostgreSQL migration and permissions.
12. Unit, contract, integration, security, concurrency, migration, Celery, resource, Docker, health, and minimal UI tests.
13. Documentation updates and `docs/SPRINT_3_COMPLETION_REPORT.md` during the separately authorized implementation.

### 5.2 Explicitly excluded

- Live network-interface capture or sensor deployment changes.
- New PCAP parsing capabilities beyond the Sprint 2 interface.
- Generic executable rule languages, `eval`, dynamic Python imports, shell commands, or user-supplied code.
- Full Zeek DNS/authentication-log ingestion unless separately approved as a Sprint 3 prerequisite extension.
- Payload inspection, payload retention, deep packet inspection, or attack execution.
- Feature engineering, model training/loading/inference, anomaly scoring, ensemble risk scoring, threat-intelligence enrichment, or automatic MITRE inference.
- Alert investigation state transitions, analyst notes, assignment, incident cases, or false-positive feedback workflow; these remain Sprint 8 responsibilities.
- Prevention request, policy, preview, simulation workflow, firewall adapter, capability, privileged container, or host networking.
- Dataset acquisition or publication.
- Commit or publication without a separate review/publication authorization.

## 6. Proposed architecture

### 6.1 End-to-end flow

1. Sprint 2 ingestion validates and persists new canonical flows and supported signature events.
2. In the same authoritative transaction, it creates a pending `detection_run` for newly accepted records.
3. After commit, it enqueues only the detection-run UUID to the dedicated Celery detection queue.
4. A scheduled reconciler safely re-enqueues stale pending runs if post-commit dispatch failed.
5. The worker locks the run, loads the recorded active rule versions, and evaluates only bounded record/time scopes.
6. Signature events become normalized detection signals. Behavioral evaluators query canonical flows in deterministic event-time buckets.
7. Signals and their evidence identities are inserted idempotently.
8. Alert aggregation computes a versioned fingerprint and transactionally creates an alert or updates the existing alert's occurrence count and first/last-seen bounds.
9. After the transaction commits, a minimal alert-created/updated notification is published. PostgreSQL remains the source of truth if notification delivery fails.
10. REST returns current alert/evidence state; the live channel is only a hint that clients should fetch authoritative detail.

### 6.2 Dependency direction

The required dependency direction is:

`ingestion -> detection orchestration -> signature/behavior evaluators -> signals -> alert aggregation -> notification`

There is no dependency from detection or alerts to prevention policy/adapters. A repository guard test must reject imports from prevention modules and the Compose configuration must retain no enforcement capability.

### 6.3 Rule evaluator model

Rules use a closed, typed evaluator registry implemented in code. A stored rule version selects a known `evaluator_key` and supplies only schema-validated, bounded parameters. The implementation must never execute stored source, expressions, templates, regular expressions without limits, or arbitrary imports.

This approach preserves auditable database versions and controlled threshold changes while avoiding a generic rule-language interpreter in the MVP.

## 7. Detection-rule schema and versioning

### 7.1 Immutable rule version

Each rule version should contain:

| Field | Requirement |
|---|---|
| `id` | UUID primary key |
| `rule_key` | Stable lowercase namespaced identifier, 3–100 characters; never reused for a different meaning |
| `version` | Positive monotonically increasing integer per `rule_key` |
| `schema_version` | Rule-definition contract, initially `behavioral-rule/v1` |
| `name` / `description` | Bounded analyst-facing text; output-encoded by UI |
| `category` | Closed detection-category enum |
| `evaluator_key` | Closed code registry entry, not executable code |
| `source_requirements` | Required canonical schema, fields, protocols, and asset context |
| `parameters` | Strict JSON object validated for the evaluator; unknown keys rejected |
| `window_seconds` | Bounded allowed value; fixed per version |
| `grouping_fields` | Closed allowlist of canonical fields |
| `threshold` | Typed and bounded threshold object |
| `severity` | `informational`, `low`, `medium`, `high`, or `critical` |
| `mitre_mappings` | Optional bounded list of technique ID, rationale, confidence, source/version/date |
| `evidence_contract` | Exact fields/counts needed to reproduce the result |
| `false_positive_guidance` | Expected benign causes and scoped exclusions |
| `investigation_guidance` | Safe analyst verification steps |
| `prevention_recommendation` | Text only; explicitly non-executable and non-authoritative |
| `change_rationale` | Required for every version after v1 |
| `definition_hash` | SHA-256 of canonical JSON definition |
| `created_by` / `created_at` | Author provenance |
| `reviewed_by` / `reviewed_at` | Separate review provenance when approved |
| `lifecycle_state` | `draft`, `approved`, or `retired`; activation is tracked separately |

Database and service constraints must enforce uniqueness of `(rule_key, version)` and `definition_hash`, validate permitted transitions, and reject mutation of definition columns after insert. Corrections require a new version.

### 7.2 Activation and rollback

`rule_activations` should keep an append-oriented history containing rule key, new version, previous version, action (`activate`, `deactivate`, `rollback`), actor, reason, regression-evidence reference, and timestamp. A partial unique constraint or transactional current-pointer table permits at most one active version per rule key.

Activation requires:

1. an approved immutable version;
2. `rules:activate` permission;
3. CSRF and same-origin enforcement for browser requests;
4. a bounded reason and reference to passing rule regression evidence;
5. prerequisite compatibility with canonical schema and evaluator registry;
6. a transaction that records activation and audit together;
7. cache invalidation only after commit.

Rollback means activating a previously approved version and recording the reason; it never deletes later versions or historical alerts. Rule removal is deactivation/retirement, not deletion.

### 7.3 Proposed seed policy

Seeded rules are reviewed artifacts created by migration or a controlled bootstrap registry. The database stores their canonical definitions and hashes. Development/demo may start with the three low-ambiguity rules active only after their tests pass; ambiguous categories remain draft or inactive by default.

## 8. Initial deterministic rule categories

Thresholds below are proposed conservative development defaults, not claims of universal maliciousness. Every threshold change creates a new rule version.

| Category | Proposed v1 behavior | Default | Severity | Prerequisites / false-positive controls |
|---|---|---|---|---|
| Port scan | Same source contacts at least 20 unique destination ports on one destination in a fixed 60-second bucket | Active | Medium | Exclude approved scanner assets through versioned asset IDs; negative fixtures for admin discovery |
| Host sweep | Same source contacts at least 20 unique destination hosts on one destination port in 60 seconds | Approval requested | Medium | Can be separated from port scan to keep evidence precise; monitoring/discovery can be benign |
| Repeated failures | At least 10 recognized failed connection states for the same source, destination/service in 300 seconds | Active | Low/Medium | Only closed normalized failure-state set; missing/unknown state is not failure |
| High connection rate | At least 100 distinct accepted flows from a source in 60 seconds | Active | Medium | Proxies, NAT, monitors, and load tests require exclusions; count distinct event keys |
| Outbound volume | Internal source sends at least 100 MiB toward an external destination in 300 seconds | Conditional | Medium | Requires authoritative asset direction and directional byte semantics; backups/updates are common benign causes |
| Suspicious DNS volume | Query-rate/unique-name/failure thresholds over a DNS event contract | Draft/blocked | Low/Medium | Canonical flow v1 lacks DNS-query semantics; needs approved `CanonicalDnsEventV1` first |
| Possible beaconing | Repeated source/destination/service with sufficient observations and low inter-arrival variance | Draft/disabled | Low | Requires at least 8 observations over at least 15 minutes; health checks/agents create expected periodicity |
| Brute-force behavior | Repeated application authentication failures by source/target/service | Draft/blocked | Medium/High | Connection failures alone are insufficient; needs a trustworthy authentication-event contract |

No category may label a flow or user definitively malicious. Analyst text must say “indicator,” “reported signature,” or “possible behavior” and show the exact observed condition.

## 9. Canonical signature-event normalization

`CanonicalSignatureEventV1` should be distinct from canonical flow v1 and should include only bounded metadata required for detection:

- schema version and generated event identity;
- sensor ID, ingestion job ID, source event ID/Suricata flow ID when present;
- event time normalized to UTC;
- normalized source/destination IP and bounded ports;
- protocol;
- Suricata signature ID, revision, bounded message, category, numeric severity, and action as reported by the sensor;
- optional transaction/flow correlation identifiers;
- source type, source schema, raw-record SHA-256, and processing timestamp.

Unknown EVE fields are discarded, not copied into arbitrary JSON. Payload, packet, base64 payload, file content, full HTTP body, credentials, and unbounded metadata are never persisted. Non-finite/invalid values and malformed alert shapes receive controlled record rejection without traceback or content echo.

External signature identity is `suricata:<signature_id>:<revision>`. The reported signature is versioned by SID/revision and a canonical normalized metadata hash. A Suricata alert signal states that the sensor reported a match; it does not attest that the rule is trustworthy or the activity is malicious.

## 10. Event-time evaluation and late data

Behavioral v1 uses fixed, epoch-aligned, half-open event-time buckets: `[bucket_start, bucket_end)`. This removes dependence on worker wall-clock time and makes duplicate, replay, and out-of-order evaluation reproducible.

Rules must:

- compute the bucket from normalized `event_time` and versioned `window_seconds`;
- use database-controlled processing time only for operational delay/retention metrics;
- count distinct canonical event keys, never task deliveries;
- sort evidence identities before hashing;
- state how records exactly on a boundary are assigned;
- re-evaluate a bucket when a new late event arrives while its underlying flow is retained;
- upsert the same semantic signal/alert rather than create a second one;
- never query more than the configured window, maximum group count, or per-run record limit.

Fixed buckets trade some boundary sensitivity for determinism and bounded cost. Sliding-window or session-window logic is deferred until representative tests justify the added complexity.

## 11. Detection signals and alert-generation boundary

### 11.1 Detection signal

A signal is the immutable result of one evaluator version over one evidence scope. It includes:

- source type (`suricata_signature` or `behavioral_rule`);
- rule/external-signature version reference;
- category and rule severity;
- sensor and optional asset scope;
- event-time bucket/occurrence time;
- canonical grouping values;
- observed measurement and threshold;
- sorted evidence event identities and evidence hash;
- data-quality limitations and source-confidence classification;
- semantic signal key and creation time.

The semantic signal key hashes rule version, sensor scope, normalized group, event-time bucket, and evidence-contract version. A unique database constraint makes task replay harmless. If late evidence changes a measurement, the implementation must either version the signal revision append-only or update a bounded aggregate while preserving prior evidence occurrences; this choice requires approval in Section 23.

### 11.2 Alert boundary

A signal becomes alert-eligible only if:

1. its active rule/external-signature contract is recognized;
2. all required fields and source prerequisites exist;
3. the deterministic threshold is met;
4. the signal is not excluded by its exact versioned scope;
5. evidence persistence succeeds;
6. alert flood limits permit creation/update.

Alert aggregation is a separate service. Evaluators do not write alerts directly and never call prevention. A failed alert transaction leaves the detection run retryable; it must not publish a live notification.

### 11.3 No Sprint 6 assessment fields

Sprint 3 alerts store rule/source severity and category. Ensemble risk, calibrated confidence, uncertainty fusion, automation eligibility, and prevention-policy results remain null/absent and cannot be populated by Sprint 3 clients.

## 12. Fingerprinting, deduplication, suppression, and flood control

### 12.1 Fingerprint v1

Alert fingerprint input is canonical JSON containing:

- `fingerprint_schema="alert-fingerprint/v1"`;
- detection source and category;
- rule key plus exact version, or Suricata SID/revision;
- sensor/asset scope;
- normalized grouping endpoints/service without display text;
- epoch-aligned suppression bucket start and duration.

The stored fingerprint is SHA-256 over length-stable canonical JSON. Display names, free text, client filenames, correlation IDs, database UUIDs unrelated to semantics, and worker wall-clock time are excluded.

### 12.2 Exact duplicate handling

- Duplicate canonical events are already rejected by Sprint 2 identity constraints.
- Duplicate signature events use sensor scope, source event ID when stable, and canonical event hash.
- Duplicate signals are rejected/upserted by semantic signal key.
- Duplicate alerts are merged by fingerprint under a unique constraint.
- Celery retries and ingestion replays must leave alert cardinality unchanged while recording replay/deduplication metrics.

### 12.3 Suppression behavior

Suppression never discards evidence silently. Matching occurrences update bounded occurrence count, first/last seen, last signal reference, and evidence summary. Evidence links are unique and capped per alert; overflow increments a count and records a deterministic digest rather than creating unbounded rows.

Proposed defaults:

- behavioral alert suppression bucket equals the rule window;
- Suricata alert suppression is 60 seconds for the same SID/revision/endpoints/service/sensor;
- maximum 100 persisted evidence links per alert, with total occurrence count retained;
- maximum 1,000 newly created alerts and 10,000 signal occurrences per detection run;
- live notifications coalesce updates for the same alert for five seconds;
- exceeding a cap fails closed into a sanitized `resource_limit` run state and emits an operational metric/audit event, never silently truncates detection results.

These numeric defaults require load-based confirmation and owner approval.

## 13. Severity, confidence, and MITRE policy

### 13.1 Severity

Behavioral severity is fixed in the immutable rule version. Suricata numeric severity is mapped through a versioned closed table and stored alongside the original numeric value. Unknown or out-of-range values map to `informational` and a data-quality limitation rather than escalation.

Asset criticality may be displayed as context but must not silently rewrite Sprint 3 rule severity. Contextual risk fusion belongs to Sprint 6.

### 13.2 Source confidence

Sprint 3 may use a closed descriptive classification such as `reported`, `deterministic_condition_met`, or `data_incomplete`. It must not expose a fabricated probability. The API must distinguish this from later calibrated confidence.

### 13.3 MITRE ATT&CK

Mappings are optional and versioned. Every mapping includes technique ID, rationale, evidence basis, mapping-source/version/date, and mapping confidence. The UI must state that a network indicator can be consistent with a technique but does not prove actor intent. Unsupported categories remain unmapped.

## 14. Evidence and provenance

Each alert must remain reproducible after its source flow expires. The evidence design therefore stores:

- alert ID and signal ID;
- immutable rule/external-signature version and definition hash;
- canonical event IDs and source/sensor/job provenance;
- exact window, group, observed count/value, threshold, and comparison operator;
- bounded endpoint/service snapshot needed for investigation;
- first/last event times and processing time;
- evidence-contract and fingerprint-schema versions;
- SHA-256 of canonical evidence JSON;
- explicit missing/late/out-of-order/data-quality flags.

Evidence snapshots must use a fixed schema, reject unknown keys, cap lists/text/nesting, and contain no payload, credential, raw uploaded line, filesystem reference, stack trace, arbitrary EVE object, or unsafe HTML. Optional foreign keys to flows use deletion behavior compatible with 30-day flow cleanup; the snapshot preserves alert explainability for the 180-day alert retention period.

## 15. False-positive controls

1. Begin with three low-ambiguity active behavioral rules; ambiguous rules remain inactive.
2. Thresholds, grouping, prerequisites, exclusions, and suppression are part of an immutable version.
3. Exclusions use authoritative asset IDs or documented service scopes—not free-form regex or broad hidden allowlists.
4. Missing direction, state, or application semantics causes the affected rule to skip with a metric, not guess.
5. Positive fixtures have paired benign near-threshold and expected-administration fixtures.
6. Boundary values test `threshold-1`, `threshold`, and `threshold+1`.
7. Activation requires regression evidence and a documented false-positive review.
8. Dashboard alert text exposes the threshold and benign explanations.
9. Alert suppression bounds repeated notifications while preserving counts and evidence digests.
10. Sprint 8 analyst disposition will provide feedback later; Sprint 3 does not auto-tune thresholds from analyst actions.
11. No rule recommendation creates a prevention request or eligibility decision.

## 16. RBAC and audit plan

### 16.1 Proposed permissions

| Permission | Purpose | Proposed roles |
|---|---|---|
| `rules:read` | View rule versions, state, thresholds, and guidance | Viewer, SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `rules:write` | Create a bounded draft version from a known evaluator | Security Admin |
| `rules:review` | Approve or retire a rule version | Security Admin; owner decision on separate reviewer |
| `rules:activate` | Activate/deactivate/rollback a reviewed version | Security Admin |
| `alerts:read` | View alerts and redacted evidence | Viewer, SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `alerts:read_sensitive` | View full endpoint evidence retained by policy | SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `detections:read_metrics` | View run/skip/suppression/failure metrics | SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |

No public or sensor principal receives rule or alert administration. The frontend may hide unavailable actions, but every API and WebSocket scope is enforced through the centralized permission service and the six-role negative matrix.

### 16.2 Audited actions

Audit records cover draft creation, review, approval/rejection, activation, deactivation, rollback, attempted unauthorized change, manual re-evaluation request if approved, detection-run terminal failure, cap exhaustion, signature normalization rejection summary, alert creation, and administrative export/read of sensitive evidence where policy requires.

Audit metadata uses IDs, safe reason codes, hashes, counts, and version numbers. It excludes raw telemetry, evidence bodies, endpoints unless specifically approved, session/CSRF/sensor credentials, internal paths, and exceptions. Rule activation must fail closed if audit persistence fails.

## 17. Celery tasks and resource limits

### 17.1 Tasks

- `detection.evaluate_run(run_id: UUID)` — evaluates a persisted bounded detection run.
- `detection.reconcile_pending()` — scheduler task that re-enqueues stale pending runs by UUID.
- `detection.retention()` — removes expired unattached signals/signature records and 180-day alert/evidence data according to policy while preserving audit requirements.

No task accepts rule JSON, telemetry, filenames, object references, actor-controlled task names, or serialized Python objects.

### 17.2 Proposed limits

| Control | Proposed default |
|---|---|
| Detection soft/hard task time | 60 / 75 seconds |
| Bounded retries | 2 with backoff; terminal sanitized failure |
| Worker prefetch | 1 |
| Flows/signature events considered per run | 10,000 accepted Sprint 2 record ceiling |
| Groups per rule/run | 5,000 |
| New alerts per run | 1,000 |
| Signal occurrences per run | 10,000 |
| Evidence links per alert | 100 plus overflow count/digest |
| Active behavioral rule versions | 50 |
| Live queue per client | 100 summaries; close slow clients |
| REST page size | 100 maximum with bounded time range |

The implementation must measure elapsed time and cardinality during evaluation, use set-based queries/aggregation where safe, and stop with a controlled state before memory growth becomes unbounded. Limits are configuration values with safe upper bounds, not client-controlled overrides.

### 17.3 Failure behavior

- PostgreSQL unavailable: no signals/alerts/notifications; run remains safely retryable or fails with a sanitized dependency code.
- Redis unavailable after run persistence: run remains pending for reconciliation; no detection state is lost.
- Unknown evaluator/rule-schema mismatch: skip that version, record a compatibility failure, and do not activate it.
- Audit failure during rule administration: fail the state change.
- Notification failure: retain committed alert; clients recover through polling.
- Task crash after commit: idempotent rerun finds existing signal/alert keys.
- Resource cap: controlled failed/partial-forbidden state; no silent partial success.

## 18. Reversible PostgreSQL migration plan

The proposed `0003_sprint3_detection` migration should add, in dependency order:

1. `rule_versions` — immutable definition/version/hash/review metadata and lifecycle constraints.
2. `rule_activations` or an equivalent current-pointer plus append-oriented history — one active version per key.
3. `signature_events` — strict normalized Suricata evidence with sensor/job provenance and stable uniqueness.
4. `detection_runs` — source scope, state, rule-set hash, counts, limits, sanitized error, lifecycle timestamps, and retry/reconciliation indexes.
5. `detection_signals` — semantic key, exact version, group/window, measurement/threshold, evidence hash, data-quality fields, and optional source references.
6. `alerts` — fingerprint v1 uniqueness, severity/category, occurrence count, first/last seen, status fixed to `new` for Sprint 3, and nullable future assessment fields.
7. `alert_evidence` — unique alert/signal relation and bounded immutable evidence snapshot/hash.
8. Sprint 3 permission rows and approved role assignments.

Required constraints/indexes include:

- unique `(rule_key, version)` and `definition_hash`;
- one active version per rule key;
- unique signature identity within sensor/schema scope;
- unique detection-run idempotency scope;
- unique signal semantic key;
- unique alert fingerprint;
- unique `(alert_id, signal_id)` evidence link;
- check constraints for lifecycle states, severities, non-negative counts, time ordering, and bounded version/threshold fields;
- indexes on run state/created time, signal rule/window/group, alert last-seen/severity/category, signature event time, and retention-controlled trusted `created_at`.

Upgrade review must assess table/index locks on existing flow/job data and avoid backfilling unbounded derived detections inside the schema migration. Any initial backfill is a separately bounded worker operation after deployment. Downgrade deletes only Sprint 3 tables, indexes, permission assignments, and Sprint 3 permission rows; it must preserve Sprint 0–2 identity, audit, ingestion, and flow data. Downgrade behavior and loss of derived Sprint 3 alerts must be explicitly stated before execution.

Migration verification requires fresh upgrade, downgrade to `0002_sprint2_ingestion`, re-upgrade, constraint/partial-index inspection, and an existing-data test. Production-style destructive downgrade is not automatic.

## 19. Minimal API and UI plan

### 19.1 API

Proposed routes under `/api/v1`:

| Method/path | Purpose | Key controls |
|---|---|---|
| `GET /rules` | Paginated current catalog/active version | `rules:read`, bounded filters |
| `GET /rules/{rule_key}/versions` | Version/history/detail | `rules:read`, safe bounded definition |
| `POST /rules/{rule_key}/versions` | Create validated draft parameters for known evaluator | `rules:write`, CSRF+Origin, rate limit, audit |
| `POST /rule-versions/{id}/review` | Approve/reject with reason/evidence | `rules:review`, state check, audit fail-closed |
| `POST /rule-versions/{id}/activate` | Activate approved compatible version | `rules:activate`, expected current version, CSRF+Origin, audit |
| `POST /rules/{rule_key}/deactivate` | Disable current version | `rules:activate`, reason, idempotent, audit |
| `POST /rules/{rule_key}/rollback` | Activate selected prior approved version | `rules:activate`, reason/evidence, concurrency guard, audit |
| `GET /alerts` | Time-bounded paginated alert summaries | `alerts:read`, field redaction |
| `GET /alerts/{id}` | Alert, signal, evidence, provenance | field-level permission and redaction |
| `GET /detection/metrics` | Run/signal/alert/suppression/skip/failure counts | `detections:read_metrics`, no high-cardinality labels |
| `GET /detection/runs/{id}` | Sanitized run status | metrics permission; no internal error/path |

All write schemas use explicit fields, reject unknown keys, enforce optimistic/current-version checks, and return stable errors. No endpoint accepts evaluator code or permits arbitrary re-evaluation range in the default plan.

### 19.2 Live alerts

`/ws/v1/alerts` authenticates and authorizes before subscription, emits only alert ID, event type, event sequence, severity, category, and timestamps, and never sends full evidence. Per-client queues are bounded; slow clients are disconnected with a reconnect instruction. Heartbeat and last-event semantics allow clients to refetch through REST. WebSocket delivery is not an audit or persistence boundary.

### 19.3 Minimal dashboard

- Rule catalog with active version, status, thresholds, false-positive guidance, and version history.
- Admin-only bounded rule-version/review/activation controls if the owner approves runtime administration.
- Alert list with time, severity, category, endpoints subject to permission, occurrence count, and source.
- Alert detail with observed condition, threshold, evidence summary, rule/signature provenance, data-quality caveats, MITRE rationale, and investigation guidance.
- Live connection indicator and incremental refresh; polling fallback.
- Accessible labels, keyboard flow, focus behavior, semantic status text, and non-color-only severity indicators.

Alert status transitions, notes, assignment, incidents, bulk actions, and prevention buttons are absent.

## 20. Synthetic fixtures

Fixtures must be created before evaluators and contain only documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or sanitized identifiers.

Required fixture families:

1. Valid and malformed Suricata EVE alert records, including unknown event shapes, missing SID/revision, invalid severity, Unicode/control text, oversized strings, non-finite timestamps, duplicate source IDs, and flow correlation.
2. Port-scan positive, benign scanner-exclusion, threshold-minus/at/plus, bucket boundary, multi-sensor, duplicate, replay, and late-arrival flows.
3. Host-sweep fixtures if approved separately.
4. Repeated-failure positive and near-threshold cases for every recognized state plus unknown/missing states that must not count.
5. High-rate positive and benign proxy/load-test exclusion cases.
6. Outbound-volume direction-known positive and direction-unknown skip cases.
7. Beaconing periodic, jittered, insufficient-observation, and health-check benign cases; rule remains disabled.
8. DNS and brute-force schema-gap fixtures documenting controlled non-evaluation until approved event contracts exist.
9. Alert fingerprint golden vectors, suppression/overflow, and rule-version-change cases.
10. Cross-job, concurrent-run, worker-retry, and notification-failure cases.

Golden fixture expected results must include exact bucket, grouping, measurement, threshold, semantic signal key input, fingerprint input, evidence IDs, severity, and expected alert count.

## 21. Test matrix and required gates

### 21.1 Unit and contract

- Strict signature/rule schemas; unknown/oversized/wrong-type fields.
- Canonical JSON hashing stability and golden SHA-256 vectors.
- Every evaluator: positive, negative, threshold boundary, missing prerequisite, timezone, epoch boundary, late/out-of-order, duplicate, and false-positive fixture.
- Suricata severity mapping and unknown fallback.
- Rule lifecycle transition and immutable-definition tests.
- Signal semantic key, alert fingerprint, suppression, evidence cap, and overflow digest.
- No evaluator import or call path to prevention.
- API response and live-summary contract tests; future risk fields absent/null.

### 21.2 Integration and database

- Ingestion success creates a pending detection run without coupling transaction success to Redis availability.
- Sequential and concurrent Celery runs produce one semantic signal/alert.
- Suricata flow plus alert file persists supported records; unsupported types reject safely according to documented per-record policy.
- Alert creation/update/evidence/audit is transactional.
- Rule activation races leave exactly one active version.
- Late data updates the intended fingerprint without losing prior evidence/counts.
- Flow retention can delete a 30-day flow while 180-day alert evidence remains reproducible.
- Alert/evidence retention deletes at 180 days using trusted creation time.
- Upgrade/downgrade/re-upgrade and existing-data preservation pass on PostgreSQL.

### 21.3 Authorization and security

- Six-role allow/deny matrix for every new REST route and live subscription.
- CSRF, Origin, session expiry/revocation, and exact CORS behavior for all writes.
- Mass assignment, IDOR, rule-key/version confusion, activation of draft/incompatible rules, stale optimistic version, and unauthorized sensitive evidence.
- Stored/reflected XSS strings in signature/rule text rendered as text.
- SQL/injection-shaped grouping values and metadata.
- No raw line, payload, path, exception, credentials, endpoint list, or unsafe metadata in errors/logs/audit/live events.
- Malicious Celery envelope, unknown task, oversized identifier, and JSON-only serializer checks.
- Simulation-only repository/configuration/OS-state guard.

### 21.4 Resilience and performance

- Alert flood caps, high group cardinality, evidence overflow, slow-client queue, and pagination/time-bound enforcement.
- Redis unavailable after database commit, notification failure, worker crash before/after commit, PostgreSQL outage, scheduler reconciliation, and bounded retries.
- Representative 10,000-record detection job on the approved 8 GB ARM64 development host, recording latency, CPU, memory, signal/alert counts, and whether proposed task limits are realistic.
- Query plans/index use for active rule lookup, window aggregation, fingerprint upsert, alert list, and retention.

### 21.5 UI, Docker, and quality

- Dashboard lint, typecheck, component tests, production build, dependency audit, keyboard/semantic checks, live disconnect and polling fallback.
- Backend formatting/lint/type/unit/integration/security, Bandit, dependency audit, secret scan, and simulation-only guard.
- Container build/configuration, non-root user, read-only root, dropped capabilities, bounded resources, no privileged/host network/firewall capability.
- Fresh Compose start, API live/ready, dashboard HTTP, PostgreSQL/Redis, Celery worker ping, scheduler, real synthetic ingestion-to-alert flow, and no firewall state change.
- Documentation links, API/schema/rule catalog, migration/rollback, threat model, risk register, backlog, decision register, deployment/test strategies, and completion report.

No skipped required check is counted as a pass. Semgrep, Trivy, SBOM, full browser E2E, accessibility automation, and load tooling should be added if feasible; otherwise the completion report must identify them as residual hardening, not successful gates.

## 22. Security, privacy, performance, and failure controls

### Security

- Treat signature text, endpoints, rule parameters, and event metadata as hostile.
- Use typed comparisons only; no general expression engine, shell, template execution, or unsafe regex.
- Centralize permission enforcement and fail sensitive administrative writes closed on audit failure.
- Make rule definitions immutable and activations transactional/audited.
- Prevent detector-to-prevention dependencies with architecture and repository guard tests.

### Privacy

- Retain only metadata necessary for detection and investigation.
- Never store packet payloads or raw EVE objects in signals/evidence.
- Redact endpoint evidence by permission and exclude it from live summaries, metric labels, and ordinary audit metadata.
- Apply 30-day retention to flows and unattached detection material; apply 180-day alert/evidence retention only to the minimal alert record.
- Use synthetic/sanitized fixtures and screenshots.

### Performance

- Fixed time buckets, indexed set-based queries, distinct event IDs, bounded group cardinality, pagination, evidence caps, coalesced live updates, and Celery resource limits.
- No universal throughput claim before representative benchmark evidence.
- Queue depth, pending/delayed/failed detection runs, signals created/deduplicated, alerts created/suppressed, skipped prerequisites, and cap exhaustion are metrics without sensitive/high-cardinality labels.

### Failure handling

- Stable error codes and correlation IDs; never exception text.
- PostgreSQL transactions and uniqueness are authoritative for retry safety.
- Redis/live delivery failure degrades to pending reconciliation/polling.
- Incompatible active configuration fails that rule closed and surfaces health/metrics; it does not stop unrelated deterministic rules unless database integrity is uncertain.
- No silent partial success after a resource cap. Run state and counts explain what was or was not committed.

## 23. Assumptions and proposed defaults

These are not confirmed owner requirements:

| ID | Assumption / proposed default | Consequence if rejected |
|---|---|---|
| S3-A01 | Use fixed epoch-aligned event-time buckets instead of sliding windows for behavioral v1. | Evaluator, fingerprints, tests, and performance plan change. |
| S3-A02 | Use a closed code evaluator registry plus validated DB parameters, not a generic YAML/expression engine. | A rule-language threat model and sandbox would be required. |
| S3-A03 | Activate only port scan, repeated failure, and high-rate rules initially. | More event schemas and false-positive work enter the critical path. |
| S3-A04 | Treat DNS, beaconing, and brute-force rules as visible draft/disabled categories until data prerequisites are approved. | Sprint 3 scope expands or categories are removed. |
| S3-A05 | Store minimal endpoint evidence for 180 days with field-level RBAC; raw flows still expire at 30 days. | Evidence may need pseudonymization or shorter retention. |
| S3-A06 | Use append-oriented signal revisions for late evidence rather than mutating an immutable signal. | Schema/upsert behavior changes; a mutable aggregate needs history. |
| S3-A07 | Permit runtime threshold versions only for known evaluators and bounded parameters. | Rule changes become code-release-only or require a broader DSL. |
| S3-A08 | Security Administrator manages/reviews/activates rules; no self-review separation for the solo MVP. | A separate role/reviewer and workflow are needed. |
| S3-A09 | Live alerts use Redis-assisted fan-out with REST as authoritative fallback. | Polling-only or a different broker pattern is used. |
| S3-A10 | Proposed numeric thresholds/resource limits are development defaults subject to fixture and load evidence. | Owner supplies different defaults before implementation. |

## 24. Owner decisions required before implementation

The owner must approve or change all items below. Approval of this plan may approve the recommended choices as a group if stated explicitly.

1. **Core active rules:** approve port scan, repeated failure, and high connection rate as the only initially active behavioral rules.
2. **Additional categories:** choose whether host sweep and outbound volume enter Sprint 3 as active rules or remain inactive until more asset/direction evidence exists.
3. **Schema expansion:** choose whether Sprint 3 adds a strict DNS event contract (and Zeek/Suricata DNS normalization) or keeps DNS volume blocked for a later authorized ingestion extension.
4. **Brute force:** approve deferral until a trustworthy authentication-event contract exists; connection failures alone will not be called brute force.
5. **Beaconing:** approve draft/disabled implementation until a representative false-positive fixture set and longer-window benchmark pass.
6. **Window semantics:** approve fixed epoch-aligned buckets for v1.
7. **Rule administration:** approve controlled runtime parameter versioning for closed evaluators, or require code-release-only rule changes.
8. **Review separation:** approve Security Administrator self-review for a solo academic MVP, or require a distinct reviewer/second account.
9. **Evidence privacy:** approve retaining minimal endpoint/service evidence with alerts for 180 days and the proposed `alerts:read_sensitive` permission.
10. **Late evidence:** approve append-oriented signal revisions while alerts maintain bounded aggregate counts.
11. **Thresholds:** approve the proposed development thresholds or provide replacements.
12. **Resource/flood limits:** approve the proposed task, group, alert, signal, evidence, and live-client limits subject to measured adjustment.
13. **WebSocket:** approve an authenticated bounded live-alert channel in Sprint 3 rather than polling-only UI.
14. **MITRE mappings:** approve only explicitly rationalized mappings with no claim of intent; unmapped is acceptable.
15. **Manual re-evaluation:** approve deferral of arbitrary historical re-evaluation API; only automatic per-ingestion runs and reconciler are planned.

## 25. Dependencies

- Published Sprint 2 commit and passing hosted CI — satisfied.
- Clean Sprint 3 implementation branch based on `29c2891...` — required at authorization.
- Sprint 2 canonical flow/event identity, ingestion jobs, Celery, retention, and permissions — implemented.
- Sprint 1 cookie sessions, CSRF/Origin, centralized permissions, audit, assets/sensors — implemented.
- PostgreSQL migration head `0002_sprint2_ingestion` — required.
- Owner decisions in Section 24 — blocking.
- Existing safe synthetic fixture policy and approved development-host resource constraints — available.

DNS and application brute-force detection depend on new canonical event contracts not currently implemented. Model serialization decision D-13 does not block Sprint 3 because no model artifact is loaded.

## 26. Major risks and mitigations

| Risk | Severity | Mitigation / acceptance evidence |
|---|---|---|
| Alert flood exhausts DB/UI/clients | High | Multi-layer identity, signal/fingerprint uniqueness, suppression, caps, bounded pages/live queues, representative burst test |
| Rule/threshold tampering creates blind spots or floods | High | Immutable versions, closed evaluator registry, RBAC, review/activation transaction, audit fail-closed, rollback tests |
| False positives undermine analyst trust | High | Conservative active set, paired benign fixtures, versioned thresholds/exclusions, visible evidence/guidance, ambiguous rules disabled |
| Duplicate/replayed/concurrent tasks create multiple alerts | High | Semantic unique keys, transactional upsert, task retry/concurrency tests, PostgreSQL authority |
| Event-time/out-of-order behavior is irreproducible | High | Epoch-aligned buckets, explicit boundary rules, late-data regression vectors, evidence hashes |
| Alert evidence leaks sensitive network metadata | High | Minimal schema, field-level RBAC, no payload, redacted live/audit/metrics, 180-day owner approval |
| Flow deletion destroys alert explainability | High | Immutable bounded evidence snapshots and retention-specific FK behavior |
| Suricata content is trusted as fact or used for injection | High | Treat as hostile reported evidence, bounded strict mapping, output encoding, no raw JSON/payload |
| Generic rule definition enables code execution or DoS | Critical | No generic DSL/eval/imports; known evaluator allowlist and bounded typed parameters |
| Detection gains prevention capability | Critical | No adapter dependency/capability; simulation guard, Compose/OS-state review |
| Celery/Redis partial failure loses detection work | High | Pending run persisted before dispatch, scheduled reconciliation, bounded retry, polling authority |
| Resource defaults do not fit 8 GB ARM64 host | Medium/High | Measure 10,000-record job and tune downward before approval; no unsupported performance claim |
| Docs drift from published state/design | High | First implementation step corrects Sprint 2 statuses; traceability/doc gate before completion |

No Critical or High residual risk may be accepted silently. The Sprint 3 completion report must name its owner, mitigation evidence, review date, and explicit disposition.

## 27. Detailed implementation sequence after authorization

1. Reconfirm public SHA, hosted CI, clean tree, and create a new branch from the published commit.
2. Update only stale Sprint 2 publication/CI status documentation.
3. Record approved Section 24 decisions in `docs/DECISIONS.md`; update backlog/threat/risk/schema/API architecture before code where decisions change contracts.
4. Create synthetic signature and behavioral golden fixtures first.
5. Freeze and test `CanonicalSignatureEventV1`, rule v1, signal v1, evidence v1, and fingerprint v1 contracts.
6. Implement strict Suricata alert normalization and hostile-input unit tests.
7. Write and review reversible migration `0003_sprint3_detection`; run migration tests before service routes.
8. Implement closed evaluator interface and registry.
9. Implement port-scan evaluator with golden/boundary/late/duplicate tests.
10. Implement repeated-failure evaluator and explicit state normalization tests.
11. Implement high-rate evaluator and benign/high-cardinality tests.
12. Implement only owner-approved conditional/draft rule categories.
13. Implement persisted detection runs, post-commit dispatch, reconciliation, bounded Celery execution, idempotent signals, and failure states.
14. Implement alert aggregation, fingerprinting, suppression, evidence snapshots, caps, and retention.
15. Add rule lifecycle services, centralized RBAC, audit fail-closed controls, and six-role negative matrix.
16. Add minimal REST endpoints and authenticated bounded live-alert channel.
17. Add minimal accessible dashboard views and polling fallback.
18. Run unit/contract/integration/security/concurrency/resource/migration/Celery/Docker/health/UI gates and correct only Sprint 3 defects.
19. Update every affected design/reference document and create `docs/SPRINT_3_COMPLETION_REPORT.md` with commands and actual results.
20. Review the entire uncommitted diff for scope, Critical/High findings, secrets, fixtures, migrations, prevention separation, and documentation.
21. Stop at the uncommitted Sprint 3 completion gate. Do not commit or publish without separate authorization.

## 28. Proposed acceptance criteria

All criteria are **proposed/not executed** at this planning gate.

| Criterion | Planned evidence |
|---|---|
| Entry gate and documentation baseline corrected | SHA/CI/clean-tree evidence and updated status docs |
| Strict versioned rule/signature/signal/evidence/fingerprint contracts | Contract tests and schema documentation |
| Suricata alert normalization is safe and bounded | Valid/malformed/Unicode/oversized/duplicate fixtures and security tests |
| Approved deterministic rules are reproducible | Golden positive/negative/boundary/time/late/replay tests |
| Exact rule/signature provenance on every signal/alert | DB/API traceability integration tests |
| Idempotent Celery retry/replay/concurrency | Unique constraints and real worker tests |
| Alert fingerprinting/suppression bounds floods without erasing counts/evidence | Flood, cap, overflow-digest, and fingerprint regression tests |
| Severity is distinct from future risk/confidence | API/DB contract tests; future fields absent/null |
| Evidence survives 30-day flow deletion and expires with 180-day alert policy | Retention integration tests using trusted timestamps |
| Rule lifecycle is immutable, authorized, audited, and rollback-capable | Transition, race, CSRF/Origin, RBAC-negative, audit-failure tests |
| Minimal REST/UI/live alert experience works and is bounded | API/component/WebSocket/polling/accessibility tests |
| Resource and failure behavior is safe on approved host | 10,000-record benchmark, outage/retry/reconciliation tests |
| Reversible PostgreSQL migration works | Fresh upgrade/downgrade/re-upgrade and existing-data evidence |
| Quality/security/dependency/secret/container gates pass | Recorded commands and outputs; skips explicitly classified |
| Docker/Celery/health/synthetic end-to-end path passes | Fresh Compose verification and worker/alert evidence |
| Prevention remains simulation-only with no network capability or side effect | Source/config/container/OS-state guards |
| No dataset/model/live capture/Sprint 4 work or unrelated change | Diff and dependency review |
| Documentation and Sprint 3 completion report are current | Link/reference review |
| No unresolved Critical or High finding | Final uncommitted Sprint 3 review |

Sprint 3 is complete only when every applicable criterion passes, owner-approved deferrals are recorded, and the uncommitted completion report is reviewed. Planning approval alone does not satisfy implementation criteria.

## 29. Deferred work

- DNS event ingestion and DNS-volume detection if not approved for Sprint 3.
- Application authentication-event contract and genuine brute-force rules.
- Sliding/session windows and advanced periodicity methods.
- Feature engineering and train/serve parity (Sprint 4).
- Supervised ML (Sprint 5), anomaly/ensemble risk and calibrated confidence (Sprint 6).
- Threat intelligence and broader MITRE enrichment (Sprint 7).
- Alert state machine, notes, assignment, analyst false-positive feedback, incidents, and full SOC workflow (Sprint 8).
- Prevention requests, eligibility, previews, and simulated execution (Sprint 9).
- Real packet capture and any real enforcement remain outside the first release.

## 30. Plan decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The planning gate is complete and the architecture remains within Sprint 3 and the IDS/simulation-only safety boundary. Implementation must not begin until the owner resolves or explicitly approves the decisions in Section 24.

## 31. Exact Sprint 3 implementation authorization prompt

```text
Approve the AegisAI NIDPS Sprint 3 implementation plan and begin Sprint 3 implementation only.

Before proceeding:
- Confirm public main is still at 29c2891f1e6bfe6686d4ef6c2489932d2f0a2fcd or identify and review any newer authorized baseline.
- Confirm hosted CI Run #4 succeeded for that SHA.
- Confirm the working tree contains only the approved Sprint 3 planning document, then create a new Sprint 3 branch from the published baseline without rewriting history.
- Read and follow the governing documents and docs/SPRINT_3_IMPLEMENTATION_PLAN.md completely.

Use these owner decisions:
- Initially active behavioral rules: [port scan, repeated failure, high connection rate — approve/change]
- Host sweep: [include active / include inactive / defer]
- Outbound volume: [include active / include inactive / defer]
- DNS event contract and DNS-volume rule: [include in Sprint 3 / defer]
- Brute-force rule: [defer until authentication-event contract / define approved source]
- Beaconing rule: [draft-disabled / activate after defined evidence]
- Window semantics: [fixed epoch-aligned buckets / approved alternative]
- Rule administration: [closed evaluator with runtime parameter versions / code-release-only]
- Rule review separation: [solo Security Administrator self-review allowed / separate reviewer required]
- Alert evidence privacy: [retain minimal endpoint/service evidence for 180 days with field-level RBAC / approved alternative]
- Late evidence behavior: [append signal revisions with bounded alert aggregate / approved alternative]
- Development thresholds: [approve plan defaults / list replacements]
- Resource and flood limits: [approve plan defaults subject to benchmark / list replacements]
- Live alerts: [authenticated bounded WebSocket plus polling fallback / polling only]
- MITRE policy: [approve rationalized optional mappings / defer mappings]
- Historical manual re-evaluation API: [defer / include with defined authorization and bounds]

First update the stale Sprint 2 publication and hosted-CI status documentation, then implement only the approved Sprint 3 scope: strict Suricata signature normalization, versioned closed-registry deterministic rules, persisted bounded detection runs, evidence-bearing signals, idempotent alert generation, fingerprinting/deduplication/suppression/flood controls, rule lifecycle/RBAC/audit, reversible PostgreSQL migration, minimal APIs/UI/live updates, retention, metrics, and required tests/documentation.

Keep prevention simulation-only. Do not add feature engineering, datasets, model training/loading/inference, anomaly or ensemble scoring, threat-intelligence feeds, incident workflows, live capture, real prevention, privileged containers, host networking, firewall integration, Sprint 4 functionality, commits, or publication.

Run and record all applicable formatting, linting, typing, unit, contract, integration, authorization, CSRF/Origin, security, concurrency, idempotency, retention, resource/flood, migration upgrade/downgrade/re-upgrade, Celery, Docker, health, frontend, dependency, secret-scanning, simulation-only, and synthetic end-to-end checks.

Update all affected documentation and create docs/SPRINT_3_COMPLETION_REPORT.md. When finished, report findings, files changed, migrations, supported rules/signature mappings, thresholds/limits, commands actually run, test/security/Docker/Celery/health results, failures/skips, assumptions, residual risks, acceptance-criteria status, final Sprint 3 decision, and the exact Sprint 3 review/publication prompt.

Stop at the uncommitted Sprint 3 completion gate and wait for approval.
```
