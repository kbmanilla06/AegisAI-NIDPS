# Sprint 8 Implementation Plan — Alert SOC Workflow and Incident Correlation

**Planning date:** 2026-07-16 (revised same day after codebase reconciliation)
**Status:** Planning only; owner approval required
**Target:** Sprint 8 — unlock the alert SOC workflow on the existing Sprint 3 alerts, add incident correlation/timeline/ownership, and SOC dashboards
**Release boundary:** Sprints 0–9, IDS with simulated IPS
**Planning baseline:** public `main` at `1b62b035b3be5add1d5cf515c9558555f2eb81fb`, **after Sprint 7 is merged and published** (Sprint 7 work committed on `feat/sprint-7-explainability-intelligence`: refactor `675712bbca5beb83c8c0f2e8617215b655668706`, feature `f6ffc3544432ad8a33c26d71a8e3bfed0da01dd3`)
**Synthetic boundary:** Gate 5S-A/B/C, Sprint 6 Gate 6A/6B, and Sprint 7 Gate 7A/7B evidence only; UNSW-NB15 acquisition remains blocked; no external network access; no prevention capability

> **Scope correction (2026-07-16).** An earlier draft of this plan wrongly assumed alerts were greenfield. They are not: the `alerts` and `alert_evidence` tables and their fingerprint dedup, occurrence counting (DET-004), severity, category, and evidence-snapshot logic already shipped in **Sprint 3** (`0003_sprint3_detection.py`, `detection_processor.py`). Sprint 3 also **deliberately locked alert `status` to `new`** via `CheckConstraint("status = 'new'", name="ck_alerts_sprint3_status")`, reserving the workflow for this sprint. Sprint 8 therefore does **not** re-project alerts. It (1) **unlocks the alert SOC workflow** on existing alerts, (2) adds **incidents** (genuinely new), and (3) optionally adds **live notifications**.

## 1. Entry-gate evidence

Sprint 8 must not begin until the Sprint 7 publication gate is satisfied:

- Sprint 7 implementation commits `675712b` and `f6ffc35` are merged into public `main` and green in hosted CI.
- `docs/SPRINT_7_COMPLETION_REPORT.md` is recorded and the diff is reviewed for scope and Critical/High issues.
- Migration `0010_sprint7_explainability_intelligence` is applied and reversible.
- **Working-tree note:** at planning time the tree carries this planning document only. Implementation must not begin until Sprint 7 is published, the tree is reconciled to a clean separately reviewed starting point, and the owner supplies the exact Sprint 8 authorization (Section 26).

This document is documentation-only. It authorizes no code, migration, model activation, online inference, real-dataset use, external network access, prevention capability, live capture, commit, or publication.

## 2. Governing material reconciled

This plan is reconciled against the complete governing documents and Sprint 3–7 evidence:

- `AegisAI-NIDPS-Master-Prompt.md` (Sprint 8 = alert/incident workflow) and `AegisAI-NIDPS-Implementation-Guide.md` (§7 Sprint 8 procedure and exit gate)
- `docs/PRD.md`, `docs/REQUIREMENTS.md` (FR-010 alert status/assignment/notes/disposition, FR-011 alerts→incidents with timeline/ownership, FR-012 live notification *Should*, DET-001 alert evidence/version references, DET-004 deterministic duplicate/flood suppression, NFR-006, SEC-009, SEC-012)
- `docs/USE_CASES.md` (UC-04 detect and create an alert, UC-05 investigate an alert, UC-06 manage an incident)
- `docs/BACKLOG.md`, `docs/DECISIONS.md`, `docs/DEFINITION_OF_DONE.md`, `docs/DATABASE.md`, `docs/SCHEMAS.md`, `docs/DETECTION_ARCHITECTURE.md`, `docs/architecture/DATA_FLOW.md`
- `docs/api/API.md`, `docs/architecture/ARCHITECTURE.md`, `docs/threat-model/THREAT_MODEL.md` (TM-12, TM-13, TM-22, TM-39)
- `docs/TEST_STRATEGY.md`, `docs/DEPLOYMENT_STRATEGY.md`, `docs/RISK_REGISTER.md`, `docs/PREVENTION_SAFETY.md`
- `docs/SPRINT_3_*` (existing alert model), `docs/SPRINT_5_*`, `docs/SPRINT_6_*`, and `docs/SPRINT_7_IMPLEMENTATION_PLAN.md` / completion report

**Reconciliation (verified against code).** `alerts`, `alert_evidence`, `detection_runs`, `detection_signals`, `assessment_batches`, and `decision_assessments` already exist (migrations `0003`, `0009`). Alerts are populated by `detection_processor.py` from deterministic detection signals with fingerprint dedup and occurrence counting. **No incident table exists.** The alert `status` column exists but is constrained to `new`. Older API/backlog/schema text describing incident or SOC-workflow routes is proposed only; the lagging status lines in `docs/api/API.md`, `docs/DATABASE.md`, `docs/SCHEMAS.md`, and `docs/BACKLOG.md` must be reconciled during implementation, not silently.

## 3. Confirmed requirements and invariants

These are not new owner decisions:

1. The first release is Sprints 0–9: IDS with simulated IPS.
2. Alerts and incidents are **evidence and workflow state, never prevention authorization** (PREV-006). No alert, incident, disposition, or SOC action executes or authorizes any block, drop, quarantine, firewall change, or network change.
3. Detection, assessment/fusion, explainability/intelligence, alert/incident workflow, and prevention remain separate concerns. Sprint 8 adds a workflow-and-correlation layer over existing alerts; it is not a new detector, not a re-projector of alerts, and not an enforcement path.
4. The existing alert projection, fingerprint dedup, occurrence counting (DET-004), severity/category, and evidence snapshots are immutable Sprint 3 behavior and are **not** modified except to unlock the `status` lifecycle.
5. Canonical flow v1, the 39 features, the seven provenance columns, and all Gate 5S/6A/6B/Sprint 7 hashes remain immutable inputs.
6. Labels, scenario family, group, partition, endpoint identity, exact event time, and raw vectors are never surfaced through alerts, incidents, notes, timelines, notifications, or SOC views.
7. Every workflow transition, note, disposition, incident, incident membership, and timeline entry is versioned, audited, and hash/lineage-bound (DET-001, SEC-009).
8. Incident correlation is **offline batch and deterministic**; no ML, no real-risk inference, no live-traffic input.
9. PostgreSQL is authoritative. Celery messages are JSON-only and carry bounded UUIDs only. Redis is coordination, never source of truth.
10. Controlled local artifacts use opaque references, mode-0600 atomic writes, SHA-256 verification, bounded size, and retention cleanup.
11. Sprint 8 must not mutate detections, rules, models, model active state, prevention state, network state, or firewall state, and must not perform any external network access. It **creates and mutates only the alert-workflow fields and incident/SOC objects it owns.**
12. Severity, priority, and disposition are **workflow/association labels over synthetic evidence, never real risk, real intrusion, or real-world maliciousness** (TM-39). No numeric effectiveness or detection-rate claim is made.
13. Stale, expired, or single-source intelligence carried into an alert or incident can never become enforcement authority and is never sole proof (TM-13, PREV-006).

## 4. Sprint 8 scope

### 4.1 Included after separate implementation authorization

- **Alert SOC workflow (FR-010, UC-05).** Unlock the alert `status` lifecycle (`new → acknowledged → investigating → closed`); add assignment, closure disposition (`false_positive`, `benign`, `synthetic_true_positive`), and append-only sanitized analyst notes. No change to how alerts are projected, deduplicated, or scored.
- **Incident correlation (FR-011, UC-06).** New `IncidentV1` grouping existing alerts by a predeclared deterministic correlation key, with ordered timeline, ownership, status lifecycle, and closure disposition. Offline, deterministic, metadata-only.
- **SOC dashboards.** Authenticated alert queue, alert detail with existing evidence lineage, incident queue, and incident timeline views; aggregate distributions; exact synthetic limitation on every surface.
- **Optional live notifications (FR-012, Section 9).** "Alert projected"/"alert updated" metadata events over the existing authenticated bounded WebSocket channel; owner-gated.
- Additive reversible migration `0011_sprint8_alert_incident_soc`: **alter** `alerts` (relax the Sprint-3 status constraint; add workflow columns), **add** `alert_notes`, `incidents`, `incident_alerts`, `incident_timeline`, and Sprint 8 permissions.
- JSON-only UUID Celery task for offline incident correlation with resource, timeout, idempotency, reconciliation, and cleanup controls. (Alert-workflow transitions are synchronous request-time state changes; they need no batch task.)
- Central RBAC, CSRF/Origin enforcement, assignment/separation-of-duties, safe append-only audit, and retention.
- Metadata/aggregate-only APIs and dashboard SOC views carrying the exact synthetic limitation and false-capability flags.
- Synthetic/hostile fixtures created before implementation, plus unit, contract, integration, security, migration, determinism, resource, Docker, Celery, frontend, accessibility, and simulation-only tests.

### 4.2 Explicitly excluded

- Re-projecting alerts, changing fingerprint/dedup/severity/evidence logic, or mutating Sprint 3–7 evidence, detections, rules, models, thresholds, or ensemble policies.
- Real datasets, UNSW-NB15 acquisition, mirrors, tokenized URLs, samples, packets, PCAPs, payloads, or any network download or live capture.
- Any external network access, feed, provider lookup, DNS/WHOIS/reputation query, or outbound request; publisher or provider contact.
- Online or automatic inference, request-time scoring/projection, model loading at API/detection startup, or model activation.
- **Any prevention, containment, blocking, dropping, quarantine, isolation, firewall integration, policy execution, or network-state change** (Sprint 9+). No `contained`/`blocked`/`prevented` alert or incident state exists; workflow states are investigative only.
- Auto-escalation from an alert/incident to a prevention action; automatic disposition/assignment; ML-driven triage or auto-close.
- Arbitrary alert/incident/artifact/URL upload, browser-supplied paths/URLs/model input, privileged containers, host networking, firewall capabilities, commit, or publication.

## 5. Proposed Sprint 8 gates

### Gate 8A — Alert SOC workflow
Freeze the alert workflow state machine, disposition vocabulary, assignment rules, note sanitization, and limitation text. Generate hostile/golden fixtures first. Relax `ck_alerts_sprint3_status`, add workflow columns and `alert_notes`, and implement synchronous, audited, optimistic-locked triage endpoints (status, assignment, notes, disposition) on the existing alerts. Do not touch projection, dedup, severity, or any non-alert object.

### Gate 8B — Incident correlation, SOC views, and notifications
Freeze the `IncidentV1` contract, deterministic correlation key, incident lifecycle, and timeline model. Deterministically correlate existing alerts into incidents with ownership and timelines via an offline batch. Implement incident management endpoints, the SOC dashboard views, and (if owner-approved) the live notification channel. Do not create or mutate any prevention, network, firewall, detection, or model state.

### Gate 8C — Completion review
Run the complete local gates, review the diff for scope and Critical/High issues, produce `docs/SPRINT_8_COMPLETION_REPORT.md`, and stop uncommitted. Publication and any later prevention integration require separate owner authorization.

## 6. Alert SOC workflow design (planning only)

### 6.1 State machine
Alert workflow status: `new → acknowledged → investigating → closed`. `closed` requires a disposition (`false_positive`, `benign`, `synthetic_true_positive`) and records `closed_by`/`closed_at`. Transitions are validated by a pure documented function; invalid transitions fail closed. Re-opening is a new audited `investigating` transition, never an in-place rewrite. The Sprint 3 projection continues to insert alerts as `new`; existing alerts are unaffected until an analyst acts.

### 6.2 Assignment, notes, disposition (FR-010)
- Assignment sets an `assignee_id` (a valid analyst user); reassignment is audited.
- Notes are append-only, length-bounded, sanitized as hostile input (control/Unicode-normalized, endpoint-like strings redacted); they never carry raw vectors, endpoints, payloads, or labels.
- Disposition is manual only; there is no automatic disposition, auto-close, or ML-driven triage. Every transition is optimistic-locked (expected-state check), audited, and reversible only via a new audited transition.

### 6.3 Safety
Workflow code cannot import or call prevention, firewall, shell, socket, or model-activation interfaces; it mutates only alert-workflow columns and appends notes. Severity remains the Sprint 3 value; the workflow adds no new risk score and asserts association-only in every surface.

## 7. Incident correlation design (planning only)

`IncidentV1` groups existing alerts by a **predeclared deterministic correlation key** (for example a shared `series_key`/grouping cluster within a bounded time window). Correlation is a pure documented function run as an offline batch over persisted alerts; it introduces no ML and no real-risk inference. Each incident records member alert references, an ordered append-only timeline of evidence and workflow events, ownership, status (`open → investigating → resolved → closed`), a closure disposition, and a canonical hash. Incident output is metadata-only: no endpoint addresses, payloads, labels, or raw vectors. Correlation may indicate a related synthetic scenario but never proves adversary intent or campaign attribution (DET-006 qualification).

## 8. SOC dashboard design (design only)

Authenticated offline-only views: an alert queue with status/assignment/severity filters; an alert detail showing existing evidence lineage plus workflow history; an incident queue; an incident detail with membership and timeline; and aggregate distributions (status, disposition, severity). Every surface carries the exact synthetic limitation and false-capability flags. Controls hide or disable when the server permission is absent; the UI is never the authorization boundary.

## 9. Optional live notification channel (owner decision)

FR-012 (live alert notifications) is a **Should**. The project already ships an authenticated bounded WebSocket channel (`detection.ws_router`). Sprint 8 may, only if the owner approves, deliver **metadata-only** "alert projected"/"alert updated" events (alert id, category, severity, workflow status, synthetic-limitation flag) — no endpoint, payload, label, vector, or raw evidence. It reuses existing authentication, Origin, rate-limit, and bounded-channel controls; `alerts:read` gates subscription; it introduces no online inference and no prevention trigger. **Recommended default: include** (UC-04/UC-05 expect analysts to see alerts promptly); otherwise defer to pull-only.

## 10. Evidence and provenance

Each workflow transition, note, incident, membership, and timeline entry binds to: the existing alert/evidence lineage and Sprint 3 fingerprint/evidence hashes; the correlation-function version (for incidents); actor id and reason code; code commit and dependency/runtime lock hash; and resource/task outcome metadata. Reports and UI are aggregate. Restricted row-level incident lineage may be stored for 30 days (matching prediction/flow/explanation retention) solely for deterministic replay and audit; it contains no endpoints, payloads, labels, or raw vectors.

## 11. Lifecycle

- Alerts: projection core immutable (Sprint 3); workflow band `new → acknowledged → investigating → closed` (with disposition) is the new audited mutable state.
- Incidents: `open → investigating → resolved → closed` (with disposition and ownership).
- Notes and timeline entries: append-only; a correction is a new entry, never an in-place edit.
- The correlation function is versioned; a change creates a new function version and new incident versions, never rewriting prior ones.

## 12. PostgreSQL migration design (planning only)

Proposed additive migration: `0011_sprint8_alert_incident_soc` (follows `0010`).

1. **Alter `alerts`:** drop `ck_alerts_sprint3_status`; add `ck_alerts_status IN ('new','acknowledged','investigating','closed')`; add nullable `assignee_id` (FK users RESTRICT), `disposition` (checked vocabulary, required only when closed, enforced in app), `closed_by` (FK users), `closed_at`, and an `updated_by` audit column. No change to projection columns.
2. **`alert_notes`** — append-only sanitized notes (alert FK RESTRICT, author FK, body ≤ 4 KiB, created_at, correlation id); no endpoint/vector fields.
3. **`incidents`** — correlation key, status, owner (FK users), disposition, timeline hash, correlation-function version, limitation flags, created_by/reviewed lineage, expiry.
4. **`incident_alerts`** — incident↔alert membership with a unique (incident_id, alert_id) and RESTRICT FKs.
5. **`incident_timeline`** — ordered append-only evidence/workflow events; metadata only.
6. Sprint 8 permissions and role grants (reusing `alerts:read`/`alerts:read_sensitive`/`detections:read_metrics`).

Required constraints: valid state transitions, one-actor-per-transition audit, disposition-required-on-close, size bounds, one idempotency key per actor and correlation operation, FK lineage, no prevention/network state, expiry indexes, and retention-safe cleanup. Downgrade re-locks alert status to `new` only after open workflow/incident inventory is cleared, then removes Sprint 8 objects and preserves Sprints 0–7. Migration tests cover fresh upgrade, existing-data upgrade (existing `new` alerts survive), downgrade refusal while inventory remains, cleanup, downgrade, re-upgrade, invalid-transition, concurrent transition, and audit-failure rollback.

## 13. Celery tasks and resource limits

Registered JSON-only tasks carry one UUID only:
- `incidents.correlate_batch(batch_id)` — bounded deterministic correlation of persisted alerts into incidents; idempotent single retry after reconciliation.
- `sprint8.reconcile()` — recover stale persisted correlation jobs safely.
- `sprint8.cleanup()` — expiry cleanup of closed incident lineage with audit.

Alert-workflow transitions are synchronous API operations and register no task. Proposed ARM64 host-aware defaults (aligned with Sprint 6/7): worker memory 4 GiB hard, CPU 2 cores, threads 1, alerts scanned per correlation batch ≤ 10,000, incidents per batch ≤ 10,000, notes ≤ 4 KiB, timeline entries per incident ≤ 1,000, soft/hard task time 120/135 s, PIDs 128, concurrency 1. Workers use late acknowledgement, prefetch 1, **no outbound network**, read-only root, no privilege/host network/capabilities, and controlled writable volumes only. A resource breach terminates the job, deletes partial objects, records a stable code, and never emits partial evidence. The optional notification channel is bounded, backpressured, and drops to pull-only on overload.

## 14. Minimal APIs and UI (design only)

Proposed metadata/aggregate-only routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `GET /alerts` and `/{id}` | Alert queue/detail with evidence lineage and workflow state | `alerts:read` (sensitive fields require `alerts:read_sensitive`), bounded filters, no raw vectors |
| `POST /alerts/{id}/status` | Acknowledge/investigate/close with disposition | `alerts:triage`, CSRF/Origin, optimistic state check, audit |
| `POST /alerts/{id}/assign` | Assign alert to analyst | `alerts:triage`, audit |
| `POST /alerts/{id}/notes` and `GET .../notes` | Append/read sanitized notes | `alerts:triage` / `alerts:read`, sanitized bounded input, audit |
| `GET /alerts/summary` | Aggregate status/severity/disposition distributions | `detections:read_metrics`, bounded filters, no raw vectors |
| `POST /incident-correlation-batches` and `GET .../{id}` | Request/status of offline correlation | `incidents:correlate`, CSRF/Origin, idempotency |
| `GET /incidents` and `/{id}` | Incident metadata, membership, timeline | `incidents:read`, aggregate/metadata only |
| `POST /incidents/{id}/status` and `/assign` and `/notes` | Manage incident workflow | `incidents:manage`, optimistic state check, audit |
| `WS /ws/alerts` (optional, Section 9) | Live alert metadata events | `alerts:read`, authenticated bounded channel, Origin, rate limit |

There is no live-capture route, online projection endpoint, model activation route, prevention/containment/firewall route, detection/rule/model mutation route, raw vector/endpoint export, or browser-supplied task/model/path input. The dashboard adds authenticated SOC views per Section 8.

## 15. RBAC, CSRF, and audit

Proposed permissions (reusing `alerts:read` / `alerts:read_sensitive` / `detections:read_metrics`):

| Permission | Role(s) |
|---|---|
| `alerts:triage` | SOC Analyst, Senior Analyst, Security Administrator |
| `incidents:read` | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `incidents:correlate` | System Administrator (and Security Administrator per owner choice) |
| `incidents:manage` | Senior Analyst, Security Administrator |

Analysts cannot approve/close their own disposition where owner-approved separation applies. Unsafe requests require the existing opaque session, session-bound CSRF token, exact allowed Origin, rate limit, and optimistic expected-state checks. Audit covers every alert status/assignment/note/disposition transition, correlation batches, incident transitions, notification subscription (if enabled), artifact-integrity failures, cleanup, and downgrade refusal (SEC-009). Metadata contains hashes, counts, versions, actor IDs, reason codes, and correlation IDs only — never paths, tokens, endpoint identities, raw notes beyond bounded sanitized text, raw rows, exception text, or vectors (SEC-012). Audit persistence failure fails closed for every workflow transition and correlation acceptance.

## 16. Retention and privacy

- Alert-workflow and incident records: retained by version under audit policy; closed incident lineage cleaned per policy.
- Row-level incident lineage: 30 days, matching prediction/flow/explanation retention.
- Notes and timeline entries: retained with their alert/incident; sanitized at write time.
- Aggregate reports and manifests: retained by version.
- Temporary partial artifacts: immediate deletion with bounded cleanup within 24 hours.

Raw endpoints, labels, payloads, vectors, and probability arrays are never in ordinary reports/UI/notes/notifications. Small groups are suppressed or aggregated. Every surface carries the exact synthetic-demo limitation and machine-readable false-capability flags.

## 17. Security, privacy, and failure controls

### Security controls
- Treat notes, disposition text, correlation inputs, and filters as hostile input; validate canonical JSON and reject unknown fields, oversized payloads, symlinks, traversal, non-finite inputs, and incompatible hashes.
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
| Invalid workflow/incident transition | Reject; preserve current state; audit reason |
| Close without disposition | Reject; no partial state change |
| Note fails sanitization | Reject note; no partial write |
| Correlation evidence/version hash mismatch | Reject correlation batch; no partial incidents |
| Missing/corrupt/oversized correlation input | Quarantine; no implicit fallback |
| Any prevention/network/firewall call attempt in a Sprint 8 path | Fail closed; treated as a Critical defect |
| Any outbound-network attempt in a Sprint 8 path | Fail closed; treated as a Critical defect |
| Resource/time limit | Terminate, delete partial output, preserve safe counts |
| Duplicate/replayed task or transition | Return existing authoritative status; no duplicate rows |
| Database/audit failure | No transition/correlation; fail closed |
| Worker crash | Lease/reconcile stale job; never duplicate a successful batch |
| Notification channel overload | Drop to pull-only; never block a transition |
| Cleanup failure | Keep metadata, audit overdue item, retry boundedly |

## 18. Fixture-first and test matrix

Fixtures must be small, deterministic, synthetic, and created before implementation:
1. Alerts in each workflow state; valid and invalid transition sequences; concurrent optimistic-lock cases.
2. Disposition vocabulary, close-without-disposition, and re-open cases.
3. Assignment/reassignment and self-disposition-separation cases.
4. Hostile note/disposition text, endpoint-like strings, Unicode/control, oversized, and redaction fixtures.
5. Correlation fixtures: shared-cluster, disjoint, window-boundary, and single-alert incidents; deterministic-repeat cases.
6. Duplicate/out-of-order/replayed correlation batches.
7. Optional notification fixtures: subscribe/receive/backpressure/drop, proving no endpoint leakage and no prevention trigger.

Required gates:
- schema/hash/unknown-field and version compatibility;
- deterministic repeated correlation runs and function-version parity;
- offline-only proof (no network syscall) and no-prevention proof (no firewall/network/model-activation call) for all Sprint 8 paths;
- workflow transition validity, disposition-on-close, and no-sole-authority behavior;
- no endpoint/label/vector leakage in alerts/incidents/notes/timelines/notifications;
- Celery JSON-only UUID, idempotency, leases, crash/reconcile, resource, and no-network tests;
- RBAC role-matrix negative, self-disposition denial where applicable, CSRF/Origin, IDOR, rate limits, and audit fail-closed tests;
- migration upgrade/existing-data/downgrade-refusal/re-upgrade and constraint tests;
- retention cleanup and rollback-predecessor protection;
- Docker health, non-root/read-only/cap-drop/no-host-network, Celery registration, and simulation-only OS-state checks;
- frontend lint/type/build/unit/accessibility and limitation/false-flag assertions;
- secret, large-file, dependency, SBOM/Trivy or documented equivalent, and native ARM64 scans.

## 19. Resource, performance, and reproducibility evidence

Every run records code commit, dependency lock/SBOM hash, correlation-function hash, seed, thread settings, alert/incident counts, elapsed time, peak RSS, CPU, and safe terminal status. Synthetic observations are not capacity, detection-performance, triage-accuracy, or real-risk claims. The completion report must include measured host results for correlation, workflow transitions, and cleanup; failing a proposed limit rejects the run or requires a measured reduction and owner approval. Limits must not be raised silently.

## 20. Dependencies, assumptions, and deferred work

### Confirmed dependencies
- Published Sprint 7 baseline and hosted CI success: **required before Sprint 8 begins** (not yet satisfied; Sprint 7 committed but unmerged).
- Existing Sprint 3 alerts/evidence, Sprint 6 assessments, Sprint 7 lineage, RBAC/audit, controlled artifacts, Celery/Redis/PostgreSQL, the existing authenticated WebSocket channel, Docker health.
- No new native or ML dependency: workflow transitions and correlation are deterministic pure functions over persisted alerts.

### Assumptions
- Existing alerts are the sole workflow subject; nothing is re-projected or activated.
- Synthetic alerts/incidents are software-contract constructs, not real detections or incidents.
- Row-level incident lineage may be stored for deterministic replay for 30 days without exposing it through ordinary APIs.
- Distinct SOC Analyst/Senior Analyst/Security Administrator/System Administrator accounts are the available technical separation.

### Deferred work
- Real dataset acquisition, publisher/provider contact, external feeds/lookups, and live capture.
- Online inference/model activation, request-time projection, and live telemetry integration.
- **Prevention policy, prevention adapters, containment, blocking, and firewall integration (Sprint 9+).**
- ML-driven triage, automatic disposition, real-risk scoring, and cross-incident campaign attribution.

## 21. Decisions requiring owner approval

1. Approve the three-gate Sprint 8 boundary (8A alert workflow, 8B incidents + SOC views/notifications, 8C completion review).
2. Approve unlocking the alert `status` lifecycle on existing Sprint 3 alerts with **no change** to projection/dedup/severity/evidence.
3. Approve the alert and incident lifecycles and disposition vocabulary, with **no containment/enforcement state**.
4. Approve the note-sanitization and separation-of-duties rules.
5. Approve the `IncidentV1` contract and the deterministic correlation key.
6. **Decide whether to enable the optional live notification over the existing authenticated bounded channel (recommended) or defer FR-012 to pull-only.**
7. Approve the additive reversible `0011_sprint8_alert_incident_soc` migration (alter alerts + new incident/notes tables) and downgrade-inventory refusal.
8. Approve the proposed permissions (`alerts:triage`, `incidents:read`, `incidents:correlate`, `incidents:manage`; reuse `alerts:read`/`alerts:read_sensitive`/`detections:read_metrics`) and offline-only APIs/UI.
9. Approve the resource/time/note/timeline limits and retry policy.
10. Approve the exact mandatory limitation text and false-capability flags on every surface (Section 25).
11. Confirm Sprint 8 must not create or mutate detections, rules, models, model active state, prevention records, network state, or firewall state, re-project alerts, perform external network access, live capture, or any prevention.

No unanswered decision is inferred as approval.

## 22. Major risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Synthetic alert/incident presented as a real detection or intrusion (TM-39) | High | Association-only labels, exact limitation, false flags, language tests, publication review |
| Alert/incident or disposition treated as prevention authority | Critical | `prevention_allowed=false`/`enforcement_authority=false`, no prevention imports/calls, OS-capability scan, dependency guard |
| Scope expands into prevention/containment (Sprint 9+) | Critical | No containment states, explicit exclusions, no firewall/network dependency, diff review, completion gate |
| Unlocking status corrupts existing alerts or Sprint 3 projection | High | Additive columns only, projection untouched, existing-`new`-alert migration test, constraint tests |
| Non-deterministic correlation | High | Fixed settings, pure documented function, repeated-run hash tests, function-version binding |
| Endpoint/label/vector leakage via notes/timeline/notification | High | No endpoint fields, sanitized bounded notes, aggregate APIs, 30-day expiry, redaction/no-leakage tests |
| Stale/single-source intelligence carried into an incident treated as proof (TM-13) | High | Expiry/confidence gating inherited from Sprint 7, no-sole-authority tests |
| Workflow race / lost update | Medium | Optimistic expected-state checks, state-transition constraints, concurrent-transition tests |
| Live notification channel leaks data or adds an online surface | High | Metadata-only events, bounded/backpressured channel, auth/Origin/rate limits, no-leakage tests, owner-gated |
| Migration downgrade unsafe / re-locks live alerts | High | Downgrade-inventory refusal, existing-data + upgrade/downgrade/re-upgrade tests |
| Any outbound network in a Sprint 8 path | Critical | No transport, no URL/file input, offline-only, no-network tests, OS-capability review |

No Critical or High residual risk may be accepted silently; the completion report must name owner, evidence, review date, and disposition.

## 23. Proposed Sprint 8 acceptance criteria

Sprint 8 is complete only if every applicable criterion passes:
1. Published Sprint 7 SHA/CI and reconciled-tree entry evidence is recorded.
2. Existing alert projection/dedup/severity/evidence is unchanged; only the status lifecycle is unlocked.
3. Fixtures exist before workflow/incident implementation and contain no real data/detection/model artifacts.
4. Alert workflow (status/assignment/notes/disposition) is manual, optimistic-locked, audited, and reversible only via new audited transitions.
5. `IncidentV1` and correlation are deterministic, hash/lineage-bound, and offline batch; no live-traffic input.
6. Severity/disposition state association, not real risk/detection/maliciousness, and carry the exact limitation and false flags.
7. Alerts, incidents, notes, timelines, and any notification produce metadata-only output and cannot create/mutate detections, rules, models, prevention, network, or firewall state.
8. If enabled, the notification channel is bounded, authenticated, metadata-only, and cannot trigger prevention or leak endpoints; otherwise SOC views are pull-only.
9. Migration `0011` upgrades (existing `new` alerts survive), downgrades safely after inventory, and re-upgrades without orphaning prior metadata.
10. RBAC/CSRF/Origin, separation of duties, IDOR/redaction, audit, idempotency, retention, and cleanup tests pass.
11. JSON-only UUID Celery correlation task, resource/time limits, crash reconciliation, no-network and no-prevention behavior, Docker security, and health gates pass.
12. Frontend quality/accessibility and exact limitation/false-capability assertions pass.
13. Formatting, linting, typing, unit/contract/integration/security/dependency/secret/SBOM/container/resource checks pass, with skips recorded honestly.
14. No Critical or High issue remains; no model is active or online; no real dataset/feed, capture, prevention capability, external network access, commit, or publication is introduced.
15. `docs/SPRINT_8_COMPLETION_REPORT.md` records hashes, commands, results, limitations, failures/skips, and the final gate decision.

## 24. Implementation sequence after authorization

1. Reconfirm published Sprint 7 baseline, hosted CI, and a clean/reconciled inherited diff; preserve history.
2. Update only the affected design/threat/risk/schema/API/test/deployment records (including the lagging status lines in Section 2).
3. Create hostile/golden alert-workflow, correlation, and note fixtures before implementation.
4. Add the workflow state machine, disposition vocabulary, correlation function, note sanitization, `IncidentV1` contract, and permissions.
5. Add migration `0011` (alter `alerts`; add `alert_notes`, `incidents`, `incident_alerts`, `incident_timeline`).
6. Implement Gate 8A synchronous alert-workflow endpoints; determinism/transition-validity checks.
7. Stop and review Gate 8A.
8. Implement Gate 8B incident correlation batch, incident management endpoints, SOC dashboard views, optional notification channel, and tests.
9. Stop before any prevention, containment, firewall, live capture, model activation, online projection, or external lookup.
10. Run completion gates, update the completion report, review the complete diff, and stop uncommitted for approval.

## 25. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The corrected design follows the master prompt's Sprint 8 definition (alert/incident workflow) and FR-010/FR-011/FR-012, UC-04/05/06, DET-001/DET-004; builds on the existing Sprint 3 alerts rather than re-projecting them; preserves the accepted synthetic-only, offline, no-activation, no-network, **no-prevention** boundary; keeps alerts and incidents strictly as evidence and workflow state; and adds explicit stop gates. Implementation remains blocked until Sprint 7 is published, the owner approves the Section 21 decisions, reconciles the working tree, and supplies the exact Sprint 8 authorization (Section 26).

## 26. Exact Sprint 8 implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_8_IMPLEMENTATION_PLAN.md and begin AegisAI NIDPS Sprint 8 using its three-gate boundary: Gate 8A alert SOC workflow, Gate 8B incident correlation and SOC views, and Gate 8C completion review.

Before proceeding:
- Confirm public main contains the published Sprint 7 work and that hosted CI is green for it.
- Confirm the working tree contains only separately reviewed prior changes plus this authorized Sprint 8 work.
- Read all governing documents, Sprint 3/5/6/7 plans and reports, and docs/SPRINT_8_IMPLEMENTATION_PLAN.md completely.
- Do not rewrite published history.

Build on the existing Sprint 3 alerts; do not re-project alerts or change fingerprint/dedup/severity/evidence logic. Use only accepted synthetic evidence. Keep UNSW-NB15 acquisition blocked, publisher/provider contact cancelled, all external lookups deferred with zero network egress, and all prevention deferred to Sprint 9+. Do not use real datasets, feeds, packets, payloads, network downloads, or live capture.

Approve these Sprint 8 defaults:
- Gate 8A/8B/8C boundaries as defined in the plan.
- Unlock the alert status lifecycle (new -> acknowledged -> investigating -> closed) with required closure disposition (false_positive/benign/synthetic_true_positive), assignment, and append-only sanitized notes (FR-010, UC-05); synchronous, optimistic-locked, audited; no change to projection.
- Strict IncidentV1 with a deterministic correlation key, ordered timeline, ownership, and lifecycle (open -> investigating -> resolved -> closed) grouping existing alerts (FR-011, UC-06); offline deterministic batch; metadata-only; no containment/enforcement state.
- [Choose one] Enable live metadata-only alert notifications over the existing authenticated bounded channel (recommended, FR-012), OR defer and ship SOC views pull-only.
- Additive reversible migration 0011_sprint8_alert_incident_soc (alter alerts to relax the Sprint-3 status lock and add workflow columns; add alert_notes, incidents, incident_alerts, incident_timeline); distinct creator/assignee/reviewer separation; JSON-only UUID Celery correlation task; resource, timeout, retention, cleanup, audit, CSRF/Origin, and RBAC controls (new alerts:triage/incidents:read/incidents:correlate/incidents:manage; reuse alerts:read/alerts:read_sensitive/detections:read_metrics).
- Offline correlation plus aggregate/metadata-only APIs and dashboard SOC views. No online endpoint, model activation, API/detection startup load, external lookup, live capture, alert re-projection, or prevention/network/firewall change.

Implement only Gate 8A, Gate 8B, and their tests/documentation. Create fixtures before implementation. Bind every workflow transition, note, incident, membership, and timeline entry to the existing alert/evidence lineage and Sprint 3–7 hashes. Preserve the mandatory limitation text exactly:

SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. Alerts and incidents are workflow state over synthetic evidence for software-contract testing; they are not real detections or real incidents and confer no authority to prevent, block, contain, or act. The system is offline-only and cannot create or modify prevention actions or network state.

Every alert, note, incident, timeline entry, metric, artifact, manifest, report, API response, notification, and UI view must carry that limitation and machine-readable false-capability flags. Never claim real, production, zero-day, real-detection, causation, real-risk, triage-accuracy, or prevention effectiveness.

Do not acquire/contact/download/read any real dataset or feed; perform any external lookup or outbound request; configure live capture; activate/load a model online; re-project alerts or create them from live traffic; mutate detections, rules, models, thresholds, ensemble policies, or model active state; create or execute any prevention, containment, block, drop, quarantine, or firewall action; change network state; use privileged containers, host networking, firewall capabilities, or enforcement dependencies; begin Sprint 9 or later; commit; or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, correlation-parity, offline-no-network, no-prevention, workflow-transition, leakage, migration, RBAC-negative-matrix, CSRF/Origin, audit, idempotency, resource, retention, Docker, Celery, frontend, accessibility, dependency, SBOM/Trivy or documented equivalent, secret, large-file, health, and simulation-only checks. Stop at the uncommitted Gate 8C completion gate and wait for separate owner review/publication approval.
```
