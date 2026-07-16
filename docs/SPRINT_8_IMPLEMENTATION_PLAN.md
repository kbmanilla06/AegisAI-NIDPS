# Sprint 8 Implementation Plan — Alert and Incident Projection, and SOC Workflows

**Planning date:** 2026-07-16
**Status:** Planning only; owner approval required
**Target:** Sprint 8 — offline projection of synthetic evidence into alerts and incidents, and SOC triage/disposition workflows and dashboards
**Release boundary:** Sprints 0–9, IDS with simulated IPS
**Planning baseline:** public `main` at `1b62b035b3be5add1d5cf515c9558555f2eb81fb`, **after Sprint 7 is merged and published** (Sprint 7 work is committed on `feat/sprint-7-explainability-intelligence`: refactor `675712bbca5beb83c8c0f2e8617215b655668706`, feature `f6ffc3544432ad8a33c26d71a8e3bfed0da01dd3`)
**Synthetic boundary:** Gate 5S-A/B/C, Sprint 6 Gate 6A/6B, and Sprint 7 Gate 7A/7B evidence only; UNSW-NB15 acquisition remains blocked; no external network access; no prevention capability

## 1. Entry-gate evidence

Sprint 8 must not begin until the Sprint 7 publication gate is satisfied:

- Sprint 7 implementation commits `675712b` (shared feature-matrix refactor) and `f6ffc35` (explainability + threat-intelligence + MITRE) are merged into public `main` and green in hosted CI.
- The `docs/SPRINT_7_COMPLETION_REPORT.md` gate is recorded and the diff is reviewed for scope and Critical/High issues.
- Migration `0010_sprint7_explainability_intelligence` is applied and reversible; the Sprint 7 30-day row-level explanation/match lineage exists (it is the primary offline input Sprint 8 projects from).
- **Working-tree note:** at planning time the tree carries this planning document only. No production code, migration, or fixture is modified. Implementation must not begin until Sprint 7 is published, the tree is reconciled to a clean separately reviewed starting point, and the owner supplies the exact Sprint 8 authorization (Section 26).

This document is documentation-only. It authorizes no code, migration, model activation, online inference, real-dataset use, external network access, prevention capability, live capture, commit, or publication.

## 2. Governing material reconciled

This plan is reconciled against the complete governing documents and Sprint 5–7 evidence:

- `AegisAI-NIDPS-Master-Prompt.md` (Sprint 8 = alert/incident projection and SOC workflow)
- `AegisAI-NIDPS-Implementation-Guide.md` (§7 Sprint 8 procedure and exit gate)
- `docs/PRD.md`, `docs/REQUIREMENTS.md` (FR-010 alert status/assignment/notes/disposition, FR-011 alerts→incidents with timeline/ownership, FR-012 live notification *Should*, DET-001 alert evidence/version references, DET-004 deterministic duplicate/flood suppression, NFR-006, SEC-009, SEC-012)
- `docs/USE_CASES.md` (UC-04 detect and create an alert, UC-05 investigate an alert, UC-06 manage an incident)
- `docs/BACKLOG.md`, `docs/DECISIONS.md`, `docs/DEFINITION_OF_DONE.md`
- `docs/DATABASE.md`, `docs/SCHEMAS.md`, `docs/DETECTION_ARCHITECTURE.md`, `docs/architecture/DATA_FLOW.md`
- `docs/api/API.md`, `docs/architecture/ARCHITECTURE.md`
- `docs/threat-model/THREAT_MODEL.md` (TM-12, TM-13, TM-22, TM-39)
- `docs/TEST_STRATEGY.md`, `docs/DEPLOYMENT_STRATEGY.md`, `docs/RISK_REGISTER.md`, `docs/PREVENTION_SAFETY.md`
- `docs/SPRINT_5_*`, `docs/SPRINT_6_*`, and `docs/SPRINT_7_IMPLEMENTATION_PLAN.md` / `docs/SPRINT_7_COMPLETION_REPORT.md`

**Reconciliation note.** `alerts:read` and `alerts:read_sensitive` permissions already exist from earlier sprints, but **no alert, incident, or detection table exists in any migration** (`0001`–`0010`). The alert/incident data model is introduced for the first time in Sprint 8. Older API/backlog/schema text that describes alert, incident, or SOC routes is treated as proposed and confers no implementation authority; the lagging status lines in `docs/api/API.md`, `docs/DATABASE.md`, `docs/SCHEMAS.md`, and `docs/BACKLOG.md` must be reconciled during implementation, not silently.

## 3. Confirmed requirements and invariants

These are not new owner decisions:

1. The first release is Sprints 0–9: IDS with simulated IPS.
2. Alerts and incidents are **evidence and workflow state, never prevention authorization** (PREV-006). No alert, incident, disposition, or SOC action executes or authorizes any block, drop, quarantine, firewall change, or network change.
3. Detection, assessment/fusion, explainability/intelligence, alert/incident projection, and prevention remain separate concerns. Sprint 8 adds a projection-and-workflow layer over existing offline synthetic evidence; it is not a new detector and not an enforcement path.
4. Canonical flow v1, `flow_features/1.0.0`, the 39 ordered features, the seven provenance columns, Gate 5S-A/B/C hashes, Sprint 6 Gate 6A/6B hashes, and Sprint 7 explanation-method/intelligence/MITRE hashes are immutable inputs.
5. Labels, scenario family, group, partition, endpoint identity, exact event time, and raw vectors are never surfaced through alerts, incidents, notes, timelines, notifications, or SOC views.
6. Alert and incident **projection is offline batch only** over persisted synthetic evidence and the Sprint 7 row-level lineage. No API/worker startup loads or activates a model; no request-time scoring or projection from live traffic; no sealed test is reopened or retuned.
7. Every alert, alert occurrence, note, disposition, incident, incident membership, and timeline entry is versioned, hash-bound to its source evidence, and auditable (DET-001, SEC-009).
8. Duplicate and flood suppression are deterministic and observable (DET-004); identical synthetic evidence collapses to one alert with a bounded occurrence count, never silent loss.
9. PostgreSQL is authoritative. Celery messages are JSON-only and carry bounded UUIDs only. Redis is coordination, never source of truth.
10. Controlled local artifacts use opaque references, mode-0600 atomic writes, SHA-256 verification, bounded size, and retention cleanup.
11. Sprint 8 must not mutate detections, rules, models, model active state, prevention state, network state, or firewall state, and must not perform any external network access. It **creates and mutates only alert/incident/SOC-workflow objects it owns.**
12. Severity, priority, and disposition are **deterministic association labels over synthetic evidence, never real risk, real intrusion, or real-world maliciousness** (TM-39). No numeric effectiveness or detection-rate claim is made.
13. Stale, expired, or single-source intelligence carried into an alert can never become enforcement authority and is never sole proof (TM-13, PREV-006).

## 4. Sprint 8 scope

### 4.1 Included after separate implementation authorization

- A strict, versioned `AlertV1` contract projected deterministically from persisted synthetic evidence bundles (deterministic-rule detections, Sprint 6 anomaly assessments/fusion, and Sprint 7 explanation and intelligence-match lineage), binding source-signal and evidence hashes, category, deterministically-derived severity/priority band, synthetic event window, version references (DET-001), and a deterministic dedup key.
- Deterministic duplicate and flood suppression collapsing identical evidence within a bounded window into one alert with an occurrence count and first/last-seen (DET-004).
- A strict, versioned `IncidentV1` contract grouping alerts by a predeclared deterministic correlation key with an ordered timeline and ownership (FR-011); metadata-only, no endpoint or payload fields.
- SOC alert workflow: status transitions, assignment, bounded sanitized analyst notes, and false-positive/benign/synthetic-true-positive disposition (FR-010, UC-05), all manual and metadata-only.
- SOC incident workflow: incident status transitions, membership management, ownership, and closure with disposition (UC-06).
- Optional, owner-gated live alert notification over the **existing** authenticated bounded WebSocket channel, delivering only "alert projected" metadata events for already-persisted synthetic alerts (FR-012, Section 9).
- Additive reversible PostgreSQL metadata (`0011_sprint8_alert_incident_soc`) for alerts, alert occurrences, alert notes, alert disposition, incidents, incident membership, incident timeline, and Sprint 8 permissions.
- JSON-only UUID Celery tasks for offline alert projection and incident correlation, with resource, timeout, idempotency, reconciliation, and cleanup controls.
- Central RBAC, CSRF/Origin enforcement, assignment/creator/reviewer separation, safe append-only audit, controlled artifacts, and retention.
- Metadata/aggregate-only APIs and dashboard SOC views (alert queue, incident queue, timelines, aggregate distributions), all carrying the exact synthetic limitation and false-capability flags.
- Synthetic/hostile fixtures created before implementation, plus unit, contract, integration, security, migration, determinism, resource, Docker, Celery, frontend, accessibility, and simulation-only tests.

### 4.2 Explicitly excluded

- Real datasets, UNSW-NB15 acquisition, mirrors, tokenized URLs, samples, packets, PCAPs, payloads, or any network download.
- Any external network access, feed, provider lookup, DNS/WHOIS/reputation query, or outbound request; publisher or provider contact.
- Online or automatic inference, request-time scoring/projection from live traffic, model loading at API/detection startup, or model activation.
- **Any prevention, containment, blocking, dropping, quarantine, isolation, firewall integration, policy execution, or network-state change** (Sprint 9+). "Containment"-style incident states that imply enforcement are excluded; incident states are investigative only.
- Real live packet/flow capture, live sensor ingestion of real traffic, or any non-synthetic alert source.
- Auto-escalation from an alert/incident to a prevention action; automatic disposition; automatic assignment based on real risk; ML-driven triage or auto-close.
- Mutation of detections, detection rules, models, thresholds, ensemble policies, model active state, or Sprint 0–7 evidence.
- Arbitrary alert/incident/artifact/URL upload, browser-supplied paths/URLs/model input, privileged containers, host networking, firewall capabilities, commit, or publication.

## 5. Proposed Sprint 8 gates

Implementation should use three explicit stop gates:

### Gate 8A — Offline alert projection
Freeze the `AlertV1` contract, the evidence-bundle input contract, the deterministic severity/priority derivation, the dedup/flood-suppression rule, and the limitation text. Generate hostile/golden fixtures first. Deterministically project persisted synthetic evidence (rule detections, Sprint 6 assessments, Sprint 7 explanation/match lineage) into alerts, bind each alert to its source-evidence and version hashes, apply deterministic suppression, and produce alert artifact/report hashes. Do not activate any model, project from live traffic, or mutate any non-alert object.

### Gate 8B — Incident correlation and SOC workflow
Freeze the `IncidentV1` contract, the deterministic correlation key, alert/incident lifecycles, disposition vocabulary, and note sanitization rules. Deterministically correlate alerts into incidents with timelines and ownership. Implement manual SOC workflow (status, assignment, notes, disposition) and the aggregate/metadata-only APIs and dashboard views. If owner-approved, enable live "alert projected" notifications over the existing authenticated bounded channel (Section 9). Do not create or mutate any prevention, network, firewall, or detection/model state.

### Gate 8C — Completion review
Run the complete local gates, review the diff for scope and Critical/High issues, produce `docs/SPRINT_8_COMPLETION_REPORT.md`, and stop uncommitted. Publication and any later prevention integration require separate owner authorization.

## 6. Alert projection design (planning only)

### 6.1 Projection model
Alerts are produced by a deterministic **offline batch** projection over persisted synthetic evidence; they are never created at request time from live traffic. The projection consumes an evidence bundle — a deterministic-rule detection and/or a Sprint 6 anomaly assessment/fusion result, optionally enriched by Sprint 7 explanation and intelligence-match lineage — and emits at most one `AlertV1` per deduplicated evidence key.

### 6.2 Alert contract
`AlertV1` is strict and immutable at projection time and binds:
- source-signal reference and evidence references (detection, assessment/fusion, explanation, and intelligence-match hashes) — DET-001;
- category (from the deterministic rule / evidence class), and a **deterministically-derived severity and priority band** computed from fixed score bands, fusion assessment, and intelligence-match state, explicitly labelled association-only and non-authoritative;
- synthetic event window (first/last synthetic event time, coarsened), never exact event time or endpoint identity;
- a deterministic dedup key and occurrence count (DET-004);
- version references (feature/preprocessing/detector/policy/method hashes) and a canonical SHA-256 over the definition;
- machine-readable false-capability flags (`prevention_allowed=false`, `enforcement_authority=false`, `real_detection=false`, `synthetic_demo_only=true`) and the exact synthetic limitation.

Severity/priority derivation is a pure, seeded, documented function; it is never a real-risk score. Missing/incompatible version hashes, non-finite inputs, or unknown evidence classes fail closed. No alert is ever presented as a real detection, a real intrusion, a probability of attack, or prevention justification.

### 6.3 Deterministic suppression (DET-004)
Identical evidence (same dedup key) within a bounded window collapses into one alert whose occurrence count and last-seen advance deterministically. Flood suppression caps occurrences per key per window with an observable "suppressed" count in aggregate metadata; suppression never silently drops evidence lineage.

### 6.4 Safety
Alert-projection code cannot import or call prevention, firewall, shell, socket, or model-activation interfaces. It reads only persisted synthetic evidence and reviewed artifacts by opaque reference, and writes only bounded alert metadata.

## 7. Incident correlation design (planning only)

`IncidentV1` groups alerts by a **predeclared deterministic correlation key** (for example a shared synthetic-scenario provenance cluster within a bounded time window). Correlation is a pure documented function; it introduces no ML and no real-risk inference. Each incident records member alert references, an ordered timeline of evidence and workflow events, ownership, status, and a canonical hash. Incident output is metadata-only: it contains no endpoint addresses, payloads, labels, or raw vectors. Correlation may indicate a related synthetic scenario but never proves adversary intent or campaign attribution (consistent with DET-006 qualification).

## 8. SOC workflow and disposition design (planning only)

- **Alert lifecycle:** `new → acknowledged → investigating → closed`, with a required disposition on close (`false_positive`, `benign`, `synthetic_true_positive`). No `contained`/`blocked`/`prevented` state exists.
- **Incident lifecycle:** `open → investigating → resolved → closed`, with ownership and a closure disposition. No containment/enforcement state.
- **Assignment and notes (FR-010, UC-05):** alerts and incidents may be assigned to an analyst; bounded, sanitized, append-only notes are permitted (validated as hostile input — length-bounded, control/Unicode-normalized, endpoint-like strings redacted). Notes never carry raw vectors, endpoints, payloads, or labels.
- **Disposition:** manual only; there is no automatic disposition, auto-close, or ML-driven triage. Every workflow transition is optimistic-locked, audited, and reversible only through a new audited transition.
- **Separation of duties:** the analyst who closes/dispositions an alert or incident and the analyst who created a note are recorded; owner-approved separation rules mirror the existing creator/reviewer pattern where applicable.

## 9. Optional live notification channel (owner decision)

FR-012 (live alert notifications) is a **Should**. The project already ships an authenticated bounded WebSocket channel (`detection.ws_router`). Sprint 8 may, only if the owner approves, deliver **metadata-only "alert projected" events** for alerts that were already persisted by the offline projection job:

- The channel pushes bounded JSON metadata (alert id, category, severity band, synthetic limitation flag) only — no endpoint, payload, label, vector, or raw evidence.
- It is a notification of already-committed offline projections; it introduces no online inference, no request-time projection, and no prevention trigger.
- It reuses the existing authentication, Origin, rate-limit, and bounded-channel controls; permission `alerts:read` gates subscription.

Recommended default: **include** the notification as an offline-projection convenience, because UC-04/UC-05 expect analysts to see new alerts promptly. If the owner prefers minimal scope, defer FR-012 and ship SOC views as pull-only.

## 10. Evidence and provenance

Each alert, occurrence, incident, membership, and timeline entry binds to:
- accepted Gate 5S-A dataset/feature/split hashes and Gate 5S-B/C reviewed candidate hashes;
- Gate 6A detector/threshold and Gate 6B policy hashes, and Sprint 7 explanation-method/intelligence-source/indicator/MITRE hashes where the alert is enriched by them;
- source synthetic detection/assessment/explanation/match identities as restricted provenance;
- deterministic severity/priority and correlation function version;
- code commit and dependency/runtime lock hash;
- resource and task outcome metadata.

Reports and UI are aggregate. Restricted row-level alert/incident lineage may be stored for 30 days (matching prediction/flow/explanation retention) solely for deterministic replay and audit; it contains no endpoint addresses, payloads, labels, or raw vectors.

## 11. Lifecycle

- Alerts: `new → acknowledged → investigating → closed` (with disposition). Immutable projection core; workflow state is a separate audited mutable band.
- Incidents: `open → investigating → resolved → closed` (with disposition and ownership).
- Notes and timeline entries: append-only; a correction is a new entry, never an in-place edit.
- Severity/priority and correlation functions are versioned; a change creates a new function version and re-projects into new alert/incident versions, never rewriting prior ones.

## 12. PostgreSQL migration design (planning only)

Proposed additive migration: `0011_sprint8_alert_incident_soc` (follows `0010_sprint7_explainability_intelligence`).

Tables/metadata:
1. `alerts` — immutable projection core (source/evidence refs, category, severity/priority band, synthetic window, dedup key, version hashes, limitation flags), plus a mutable workflow band (status, assignee, disposition) guarded by state-transition and optimistic-lock constraints; expiry.
2. `alert_occurrences` — per-dedup-key occurrence records (occurrence count, first/last seen, suppressed count); no endpoint/payload fields.
3. `alert_notes` — append-only sanitized notes with author, created_at, correlation id; length-bounded; no raw vectors/endpoints.
4. `incidents` — correlation key, status, owner, disposition, timeline hash, version hashes, limitation flags, expiry.
5. `incident_alerts` — incident↔alert membership with unique membership and lineage foreign keys.
6. `incident_timeline` — ordered append-only evidence/workflow events; metadata only.
7. Sprint 8 permissions and role grants (reusing existing `alerts:read`/`alerts:read_sensitive`).

Required constraints: immutable projection-core fields (PostgreSQL trigger), valid state transitions, one-actor-per-transition audit, hash/size/band bounds, one idempotency key per actor and projection/correlation operation, foreign-key lineage to Sprint 6/7 evidence, no prevention/network state, expiry indexes, and retention-safe cleanup. Downgrade refuses while open alerts/incidents remain inventoried; after explicit closure/cleanup it removes only Sprint 8 objects and preserves Sprints 0–7. Migration tests cover fresh upgrade, existing-data upgrade, downgrade refusal, cleanup, downgrade, re-upgrade, immutable-field mutation, concurrent transition, and audit-failure rollback.

## 13. Celery tasks and resource limits

Registered JSON-only tasks carry one UUID only:
- `alerts.project_batch(batch_id)` — bounded offline alert projection over persisted synthetic evidence; idempotent single retry after reconciliation.
- `incidents.correlate_batch(batch_id)` — bounded deterministic correlation of persisted alerts into incidents; idempotent single retry.
- `sprint8.reconcile()` — recover stale persisted projection/correlation jobs safely.
- `sprint8.cleanup()` — expiry cleanup of closed alert/incident lineage with audit.

Proposed ARM64 host-aware defaults (aligned with Sprint 6/7): worker memory 4 GiB hard, CPU 2 cores, numerical threads 1, evidence rows per batch 10,000 max, alerts per batch ≤ 10,000, notes ≤ 4 KiB each, timeline entries per incident ≤ 1,000, soft/hard task time 120/135 s for projection and correlation, PIDs 128, concurrency 1. Workers use late acknowledgement, prefetch 1, **no outbound network**, read-only root, no privilege/host network/capabilities, and controlled writable volumes only. A resource breach terminates the job, deletes partial objects, records a stable code, and never emits partial evidence. The optional notification channel is bounded, backpressured, and drops to pull-only on overload.

## 14. Minimal APIs and UI (design only)

Proposed metadata/aggregate-only routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `POST /alert-projection-batches` and `GET .../{id}` | Request/status of offline alert projection | `alerts:project`, CSRF/Origin, idempotency, exact accepted hashes |
| `GET /alerts` and `/{id}` | Alert metadata/queue | `alerts:read` (sensitive fields require `alerts:read_sensitive`), bounded filters, no raw vectors |
| `POST /alerts/{id}/status` | Acknowledge/investigate/close with disposition | `alerts:triage`, CSRF/Origin, optimistic state check, audit |
| `POST /alerts/{id}/assign` | Assign alert to analyst | `alerts:triage`, audit |
| `POST /alerts/{id}/notes` | Append sanitized note | `alerts:triage`, sanitized bounded input, audit |
| `GET /alerts/summary` | Aggregate category/severity/disposition distributions | `detections:read_metrics`, bounded filters, no raw vectors |
| `POST /incident-correlation-batches` and `GET .../{id}` | Request/status of offline correlation | `incidents:correlate`, CSRF/Origin, idempotency |
| `GET /incidents` and `/{id}` | Incident metadata, membership, timeline | `incidents:read`, aggregate/metadata only |
| `POST /incidents/{id}/status` and `/assign` and `/notes` | Manage incident workflow | `incidents:manage`, optimistic state check, audit |
| `WS /ws/alerts` (optional, Section 9) | Live "alert projected" metadata events | `alerts:read`, authenticated bounded channel, Origin, rate limit |

There is no live-capture route, online projection endpoint, model activation route, prevention/containment/firewall route, detection/rule/model mutation route, raw vector/endpoint export, or browser-supplied task/model/path input. The dashboard adds authenticated SOC views (alert queue, incident queue, alert detail with evidence lineage, incident timeline, aggregate distributions) that carry the exact synthetic limitation and false-capability flags. Controls hide or disable when the server permission is absent; the UI is never the authorization boundary.

## 15. RBAC, CSRF, and audit

Proposed permissions (reusing existing `alerts:read` / `alerts:read_sensitive`):

| Permission | Role(s) |
|---|---|
| `alerts:read` (reuse) | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `alerts:read_sensitive` (reuse) | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `alerts:project` | System Administrator (and Security Administrator per owner choice) |
| `alerts:triage` | SOC Analyst, Senior Analyst, Security Administrator |
| `incidents:read` | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `incidents:correlate` | System Administrator (and Security Administrator per owner choice) |
| `incidents:manage` | Senior Analyst, Security Administrator |
| `detections:read_metrics` (reuse) | Senior Analyst, Security Administrator, System Administrator, Auditor |

Analysts cannot approve/close their own disposition where owner-approved separation applies. Unsafe requests require the existing opaque session, session-bound CSRF token, exact allowed Origin, rate limit, and optimistic expected-state checks. Audit covers alert projection request/start/success/failure, correlation batches, every status/assignment/note/disposition transition, suppression events, notification subscription (if enabled), artifact-integrity failures, cleanup, and downgrade refusal (SEC-009). Metadata contains hashes, counts, versions, actor IDs, reason codes, and correlation IDs only — never paths, tokens, endpoint identities, raw notes beyond bounded sanitized text, raw rows, exception text, or vectors (SEC-012). Audit persistence failure fails closed for projection acceptance and every workflow transition.

## 16. Retention and privacy

- Alert/incident workflow records: retained by version under audit policy; closed alert/incident lineage cleaned per policy.
- Row-level alert/incident projection lineage: 30 days, matching prediction/flow/explanation retention.
- Notes and timeline entries: retained with their alert/incident; sanitized at write time.
- Aggregate reports and manifests: retained by version.
- Temporary partial artifacts: immediate deletion with bounded cleanup within 24 hours; no exceptional investigation holds for the MVP.

Raw endpoints, labels, payloads, vectors, and probability arrays are never in ordinary reports/UI/notes/notifications. Small groups are suppressed or aggregated. Every surface carries the exact synthetic-demo limitation and machine-readable false-capability flags.

## 17. Security, privacy, and failure controls

### Security controls
- Treat evidence bundles, notes, disposition text, and correlation inputs as hostile input; validate canonical JSON and reject unknown fields, oversized payloads, symlinks, traversal, non-finite inputs, and incompatible hashes.
- Use opaque server-side references; no user path/URL/model input; no outbound socket in any Sprint 8 code path.
- Keep alert/incident/SOC code unable to call prevention, firewall, shell, socket, or model-activation interfaces; verify by dependency and OS-capability review.
- Verify all lineage hashes at every transition and quarantine on mismatch.
- Run dependency, SBOM, native-runtime, secret, container, and simulation-only checks; unresolved Critical/High findings block the gate.

### Privacy and claim controls
- Synthetic alerts/incidents are non-semantic software-test constructs only.
- No UNSW-NB15, real-network, real-detection, production, zero-day, causation, or prevention-suitability claim is permitted.
- Aggregate-only API/UI/report output; restricted sidecar lineage has short retention and no endpoints.

### Failure behavior

| Failure | Required response |
|---|---|
| Evidence/version hash mismatch | Reject projection batch; no partial alerts |
| Non-finite/out-of-range severity input | Reject source/batch per contract; never clip silently |
| Missing/corrupt/oversized evidence bundle | Quarantine; no implicit fallback |
| Unknown evidence class/category | Reject batch; audit stable reason |
| Invalid workflow transition | Reject; preserve current state; audit reason |
| Note fails sanitization | Reject note; no partial write |
| Any prevention/network/firewall call attempt in a Sprint 8 path | Fail closed; treated as a Critical defect |
| Any outbound-network attempt in a Sprint 8 path | Fail closed; treated as a Critical defect |
| Resource/time limit | Terminate, delete partial output, preserve safe counts |
| Duplicate/replayed task or transition | Return existing authoritative status; no duplicate rows |
| Database/audit failure | No projection/transition; fail closed |
| Worker crash | Lease/reconcile stale job; never duplicate a successful batch |
| Notification channel overload | Drop to pull-only; never block projection |
| Cleanup failure | Keep metadata, audit overdue item, retry boundedly |

## 18. Fixture-first and test matrix

Fixtures must be small, deterministic, synthetic, and created before implementation:
1. Evidence bundles: rule-only, anomaly-only, fused, intelligence-enriched, and explanation-enriched cases; empty, single-evidence, and non-finite-severity-input cases.
2. Dedup/flood fixtures: identical-evidence bursts, near-duplicate keys, and window-boundary cases proving deterministic suppression and occurrence counts.
3. Severity/priority derivation fixtures across score bands, fusion states, and intelligence-match states (active/expired/allowlist-conflict) proving non-authority.
4. Correlation fixtures: shared-cluster, disjoint, window-boundary, and single-alert incidents.
5. Workflow fixtures: valid/invalid status transitions, concurrent optimistic-lock cases, assignment, and disposition vocabulary.
6. Hostile note/disposition text, endpoint-like strings, Unicode/control, and redaction fixtures; oversized/wrong-hash/traversal/symlink artifact fixtures.
7. Duplicate/out-of-order/replayed projection and correlation batches.
8. Optional notification fixtures: subscribe/receive/backpressure/drop cases proving no endpoint leakage and no prevention trigger.

Required gates:
- schema/hash/unknown-field and version compatibility;
- deterministic repeated projection and correlation runs and function-version parity;
- offline-only proof (no network syscall) and no-prevention proof (no firewall/network/model-activation call) for all Sprint 8 paths;
- dedup/flood-suppression, severity-derivation, and no-sole-authority behavior;
- exact evidence/provenance hash binding and no endpoint/label/vector leakage in alerts/incidents/notes/timelines/notifications;
- artifact operator/shape/external-data/size/path/integrity tests;
- Celery JSON-only UUID, idempotency, leases, crash/reconcile, resource, and no-network tests;
- RBAC role-matrix negative, self-disposition denial where applicable, CSRF/Origin, IDOR, rate limits, and audit fail-closed tests;
- migration upgrade/downgrade/re-upgrade and immutable constraints;
- retention cleanup and rollback-predecessor protection;
- Docker health, non-root/read-only/cap-drop/no-host-network, Celery registration, and simulation-only OS-state checks;
- frontend lint/type/build/unit/accessibility and limitation/false-flag assertions;
- secret, large-file, dependency, SBOM/Trivy or documented equivalent, and native ARM64 scans;
- if the notification channel is approved: bounded-channel, backpressure, auth/Origin, and no-leakage tests.

## 19. Resource, performance, and reproducibility evidence

Every run records code commit, dependency lock/SBOM hash, feature/preprocessing/detector/policy/method/correlation-function hashes, seed, thread settings, evidence/alert/incident counts, elapsed time, peak RSS, CPU, artifact size, and safe terminal status. Synthetic observations are not capacity, detection-performance, triage-accuracy, or real-risk claims. The completion report must include measured host results for projection, correlation, workflow transitions, and cleanup; failing a proposed limit rejects the run or requires a measured reduction and owner approval. Limits must not be raised silently.

## 20. Dependencies, assumptions, and deferred work

### Confirmed dependencies
- Published Sprint 7 baseline and hosted CI success: **required before Sprint 8 begins** (not yet satisfied at planning time; Sprint 7 is committed but unmerged).
- Accepted Gate 5S-A/B/C, Gate 6A/6B, and Sprint 7 explanation/intelligence/MITRE hashes and the synthetic-only limitation.
- Canonical flow/feature v1, deterministic rules, reviewed candidates, Sprint 7 row-level lineage, RBAC/audit, controlled artifacts, Celery/Redis/PostgreSQL, the existing authenticated WebSocket channel, Docker health: existing.
- No new native or ML dependency is required; alert projection and correlation are deterministic pure functions over persisted evidence.

### Assumptions
- Persisted synthetic detection/assessment/explanation/match evidence may be referenced only by offline projection/correlation jobs; nothing is active or online.
- Synthetic alerts/incidents are software-contract constructs, not real detections or real incidents.
- Row-level alert/incident lineage may be stored for deterministic replay for 30 days without exposing it through ordinary APIs.
- Distinct SOC Analyst/Senior Analyst/Security Administrator/System Administrator accounts are the available technical separation in this solo project.

### Deferred work
- Real dataset acquisition, all publisher/provider contact, external feeds/lookups, and live capture.
- Online inference/model activation, request-time projection, and any live telemetry integration.
- **Prevention policy, prevention adapters, containment, blocking, and firewall integration (Sprint 9+).**
- ML-driven triage, automatic disposition, real-risk scoring, and cross-incident campaign attribution.

## 21. Decisions requiring owner approval

1. Approve the three-gate Sprint 8 boundary (8A alert projection, 8B incident correlation + SOC workflow, 8C completion review).
2. Approve **offline projection from persisted synthetic evidence only** as the sole alert/incident source; keep live capture, real detection sources, and any online projection out of scope.
3. Approve the `AlertV1` contract, the deterministic severity/priority derivation as association-only, and the dedup/flood-suppression rule (DET-004).
4. Approve the `IncidentV1` contract and the deterministic correlation key.
5. Approve the alert and incident lifecycles and the disposition vocabulary, with **no containment/enforcement state**.
6. Approve the note-sanitization and separation-of-duties rules.
7. **Decide whether to enable the optional live "alert projected" notification over the existing authenticated bounded channel (recommended) or defer FR-012 to pull-only.**
8. Approve the additive reversible `0011_sprint8_alert_incident_soc` migration and downgrade-inventory refusal.
9. Approve the proposed permissions (new `alerts:project`, `alerts:triage`, `incidents:read`, `incidents:correlate`, `incidents:manage`; reuse of `alerts:read`/`alerts:read_sensitive`), assignment/creator/reviewer separation, and offline-only APIs/UI.
10. Approve the resource/time/note/timeline limits and retry policy.
11. Approve the exact mandatory limitation text and false-capability flags on every surface (Section 25).
12. Confirm Sprint 8 must not create or mutate detections, rules, models, model active state, prevention records, network state, or firewall state, and performs no external network access, live capture, or prevention.

No unanswered decision is inferred as approval.

## 22. Major risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Synthetic alert/incident presented as a real detection or intrusion (TM-39) | High | Association-only labels, exact limitation, false flags, language tests, publication review |
| Alert/incident or severity treated as prevention authority | Critical | `prevention_allowed=false`/`enforcement_authority=false` fixed, no prevention imports/calls, OS-capability scan, dependency guard |
| Scope expands into prevention/containment (Sprint 9+) | Critical | No containment states, explicit exclusions, no firewall/network dependency, diff review, completion gate |
| Non-deterministic projection or correlation | High | Fixed seed/settings, pure documented functions, repeated-run hash tests, function-version binding |
| Endpoint/label/vector leakage via alerts/incidents/notes/timeline/notification | High | No endpoint fields, sanitized bounded notes, aggregate APIs, 30-day expiry, redaction and no-leakage tests |
| Stale/single-source intelligence carried into an alert treated as proof (TM-13) | High | Expiry/confidence gating inherited from Sprint 7, no-sole-authority tests, allowlist-conflict propagation |
| Alert flood / resource exhaustion | High | Deterministic dedup/flood suppression (DET-004), bounded batches, bounded workers, observable suppressed counts |
| Live notification channel leaks data or adds an online surface | High | Metadata-only events, bounded/backpressured channel, auth/Origin/rate limits, no-leakage tests, owner-gated |
| Workflow race / lost update | Medium | Optimistic expected-state checks, state-transition constraints, concurrent-transition tests |
| Migration orphans or unsafe downgrade | High | Additive reversible `0011`, downgrade-inventory refusal, upgrade/downgrade/re-upgrade tests |
| Any outbound network in a Sprint 8 path | Critical | No transport, no URL/file input, offline-only, no-network tests, OS-capability review |
| Native/supply-chain dependency issue | Critical | No new native dependency; pinned versions, SBOM, Trivy/equivalent, pip-audit, no unresolved Critical/High |

No Critical or High residual risk may be accepted silently; the completion report must name owner, evidence, review date, and disposition.

## 23. Proposed Sprint 8 acceptance criteria

Sprint 8 is complete only if every applicable criterion passes:
1. Published Sprint 7 SHA/CI and reconciled-tree entry evidence is recorded.
2. Synthetic-evidence-only projection and the mandatory limitation/false flags are proven; live capture, real detection sources, external lookups, and prevention remain excluded with no network egress.
3. Fixtures exist before alert/incident/SOC implementation and contain no real data/detection/model artifacts.
4. `AlertV1` and `IncidentV1` contracts are immutable, hash-bound, and bound to source evidence and version hashes; projection and correlation are deterministic.
5. Alert projection is offline batch only; no model is activated or loaded online; no projection occurs from live traffic; no sealed test is reopened.
6. Severity/priority and disposition state association, not real risk, real detection, or real-world maliciousness, and carry the exact limitation and false flags.
7. Deterministic duplicate/flood suppression (DET-004) is proven and observable.
8. Alerts, incidents, notes, timelines, and any notification produce metadata-only output and cannot create/mutate detections, rules, models, prevention, network, or firewall state.
9. SOC workflow (status, assignment, notes, disposition) is manual, optimistic-locked, audited, and reversible only via new audited transitions.
10. If enabled, the notification channel is bounded, authenticated, metadata-only, and cannot trigger prevention or leak endpoints; otherwise SOC views are pull-only.
11. PostgreSQL migration `0011` upgrades, downgrades safely after inventory, and re-upgrades without orphaning prior metadata.
12. RBAC/CSRF/Origin, separation of duties, IDOR/redaction, audit, idempotency, retention, and cleanup tests pass.
13. JSON-only UUID Celery tasks, resource/time limits, crash reconciliation, no-network and no-prevention behavior, Docker security, and health gates pass.
14. Frontend quality/accessibility and exact limitation/false-capability assertions pass.
15. Formatting, linting, typing, unit/contract/integration/security/dependency/secret/SBOM/container/resource checks pass, with skips recorded honestly.
16. No Critical or High issue remains; no model is active or online; no real dataset/feed, capture, prevention capability, external network access, commit, or publication is introduced.
17. `docs/SPRINT_8_COMPLETION_REPORT.md` records hashes, commands, results, limitations, failures/skips, and the final gate decision.

## 24. Implementation sequence after authorization

1. Reconfirm published Sprint 7 baseline, hosted CI, and a clean/reconciled inherited diff; preserve history.
2. Update only the affected design/threat/risk/schema/API/test/deployment records required by the approved plan (including the lagging alert/incident status lines noted in Section 2).
3. Create hostile/golden alert-projection, correlation, and SOC-workflow fixtures before implementation.
4. Add strict `AlertV1`/`IncidentV1` contracts, deterministic severity and correlation functions, limitation flags, and permissions.
5. Add migration `0011` and controlled artifact/reconciliation interfaces.
6. Implement Gate 8A offline alert projection with deterministic suppression; bind evidence/version hashes; parity/determinism checks.
7. Stop and review Gate 8A alert hashes.
8. Implement Gate 8B incident correlation, SOC workflow, aggregate/metadata-only APIs and dashboard views, optional notification channel, and tests.
9. Stop before any prevention, containment, firewall, live capture, model activation, online projection, external lookup, or real-data work.
10. Run completion gates, update the completion report, review the complete diff, and stop uncommitted for approval.

## 25. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The proposed design follows the master prompt's Sprint 8 definition (alert/incident projection and SOC workflow) and FR-010/FR-011/FR-012, UC-04/05/06, DET-001/DET-004; preserves the accepted synthetic-only, offline, no-activation, no-network, **no-prevention** boundary; keeps alerts and incidents strictly as evidence and workflow state; and adds explicit stop gates. Implementation remains blocked until Sprint 7 is published, the owner approves the Section 21 decisions, reconciles the working tree, and supplies the exact Sprint 8 authorization (Section 26).

## 26. Exact Sprint 8 implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_8_IMPLEMENTATION_PLAN.md and begin AegisAI NIDPS Sprint 8 using its three-gate boundary: Gate 8A offline alert projection, Gate 8B incident correlation and SOC workflow, and Gate 8C completion review.

Before proceeding:
- Confirm public main contains the published Sprint 7 explainability/intelligence/MITRE work and that hosted CI is green for it.
- Confirm the working tree contains only separately reviewed prior changes plus this authorized Sprint 8 work.
- Read all governing documents, Sprint 5/6/7 plans and reports, and docs/SPRINT_8_IMPLEMENTATION_PLAN.md completely.
- Do not rewrite published history.

Use only accepted synthetic Gate 5S-A/B/C, Sprint 6 Gate 6A/6B, and Sprint 7 explanation/intelligence/MITRE evidence and the persisted Sprint 7 row-level lineage. Keep UNSW-NB15 acquisition blocked, publisher and provider contact cancelled, all external lookups deferred with zero network egress, and all prevention deferred to Sprint 9+. Do not use real or third-party datasets, feeds, mirrors, tokenized links, samples, packets, PCAPs, payloads, network downloads, or live capture.

Approve these Sprint 8 defaults:
- Gate 8A/8B/8C boundaries as defined in the plan.
- Offline deterministic alert projection from persisted synthetic evidence only: strict AlertV1 with source/evidence hash binding, association-only severity/priority derivation, deterministic duplicate/flood suppression (DET-004), synthetic event window, version references (DET-001), and the mandatory limitation and false-capability flags. No projection from live traffic, no online endpoint, no model activation.
- Strict IncidentV1 with a deterministic correlation key, ordered timeline, and ownership (FR-011); metadata-only.
- Manual SOC workflow (status, assignment, sanitized bounded notes, disposition) per FR-010 and UC-05/UC-06, with no containment/enforcement state, no automatic disposition, and no ML-driven triage.
- [Choose one] Enable live metadata-only "alert projected" notifications over the existing authenticated bounded channel (recommended, FR-012), OR defer and ship SOC views pull-only.
- Additive reversible migration 0011_sprint8_alert_incident_soc; distinct creator/assignee/reviewer separation; JSON-only UUID Celery tasks; resource, timeout, retention, cleanup, audit, CSRF/Origin, and RBAC controls from the plan (new alerts:project/alerts:triage/incidents:read/incidents:correlate/incidents:manage; reuse alerts:read/alerts:read_sensitive/detections:read_metrics).
- Offline projection and correlation jobs plus aggregate/metadata-only APIs and dashboard SOC views. No online endpoint, model activation, API/detection startup load, external lookup, live capture, or prevention/network/firewall change.

Implement only Gate 8A, Gate 8B, and their tests/documentation. Create fixtures before implementation. Bind every alert, occurrence, note, incident, membership, and timeline entry to the accepted Gate 5S-A/B/C, Gate 6A/6B, and Sprint 7 hashes and exact feature/preprocessing/runtime hashes. Preserve the mandatory limitation text exactly:

SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. Alerts and incidents are offline projections of synthetic evidence for software-contract testing; they are not real detections or real incidents and confer no authority to prevent, block, contain, or act. The system is offline-only and cannot create or modify prevention actions or network state.

Every alert, occurrence, note, incident, timeline entry, metric, artifact, manifest, report, API response, notification, and UI view must carry that limitation and machine-readable false-capability flags. Never claim real, production, zero-day, real-detection, causation, real-risk, triage-accuracy, or prevention effectiveness.

Do not acquire/contact/download/read any real dataset or threat-intelligence feed; perform any external lookup or outbound request; configure live capture; fit on or retune any sealed test; activate/load a model online; create alerts/incidents through an online endpoint or from live traffic; mutate detections, rules, models, thresholds, ensemble policies, or model active state; create or execute any prevention, containment, block, drop, quarantine, or firewall action; change network state; use privileged containers, host networking, firewall capabilities, or enforcement dependencies; begin Sprint 9 or later; commit; or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, projection/correlation-parity, offline-no-network, no-prevention, dedup/flood-suppression, severity-derivation, leakage, artifact-integrity, migration, RBAC-negative-matrix, CSRF/Origin, audit, idempotency, resource, retention, Docker, Celery, frontend, accessibility, dependency, SBOM/Trivy or documented equivalent, secret, large-file, health, and simulation-only checks. Stop at the uncommitted Gate 8C completion gate and wait for separate owner review/publication approval.
```
