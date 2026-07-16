# Sprint 8 Completion Report — Alert SOC Workflow and Incident Correlation

**Date:** 2026-07-16
**Status:** Implemented on `feat/sprint-8-alert-incident-soc`; uncommitted-then-pushed for owner review (no publication).
**Branch base:** `feat/sprint-7-explainability-intelligence` (Sprint 8 depends on Sprint 7's schema and lineage; Sprint 7 is not yet merged to `main`).
**Plan:** `docs/SPRINT_8_IMPLEMENTATION_PLAN.md` (corrected scope: build on existing Sprint 3 alerts).

## 1. Scope delivered

### Gate 8A — Alert SOC workflow (FR-010, UC-05)
- New `aegis_services.soc` package: `AlertStatus`/`AlertDisposition`/`IncidentStatus` enums, deterministic transition state machines (`validate_alert_transition`), and `sanitize_note` (NFC normalize, control-strip, endpoint redaction, 4 KiB bound). `SOC_LIMITATIONS` extends the mandatory synthetic limitation with the no-authority clause.
- `alerts` table **status lock relaxed**: `ck_alerts_sprint3_status` → `ck_alerts_status IN (new,acknowledged,investigating,closed)`, plus disposition + disposition-on-close check constraints. Added workflow columns (`assignee_id`, `disposition`, `closed_by`, `closed_at`, `updated_by`) and the append-only `alert_notes` table. **Projection, fingerprint dedup, occurrence counting, severity, and evidence are untouched.**
- SOC router (`routers/soc.py`): `POST /alerts/{id}/status` (optimistic-locked, disposition-on-close, audited), `POST /alerts/{id}/assign`, `POST/GET /alerts/{id}/notes`. Alert reads stay in the detection router; `AlertSummaryOut` was extended with the workflow fields and the limitation/false-capability flags.
- Permissions: new `alerts:triage`; granted per the RBAC matrix.

### Gate 8B — Incident correlation and workflow (FR-011, UC-06)
- `soc.correlation`: deterministic, offline, pure `correlate_alerts` grouping alerts by category into versioned `IncidentGroup`s (`CORRELATION_VERSION = incident-correlation/v1`), stable across runs, bounded to 10,000 alerts.
- New `incidents`, `incident_alerts`, `incident_timeline` tables; incident lifecycle `open → investigating → resolved → closed` with disposition-on-close; ownership; append-only timeline.
- Incidents router (`routers/incidents.py`): `POST /incidents/correlate` (idempotent by correlation key, audited), `GET /incidents`, `GET /incidents/{id}` (members + timeline), `POST /incidents/{id}/status`, `POST /incidents/{id}/assign`.
- Permissions: new `incidents:read`, `incidents:correlate`, `incidents:manage`; granted per the matrix (which stays consistent with migration `0011`).

### Migration
- `0011_sprint8_alert_incident_soc`: additive; alters `alerts` (relax lock + workflow columns), adds the four new tables, seeds Sprint 8 permissions/grants. Downgrade **refuses** while any alert is non-`new` or any incident exists, then re-locks status and removes Sprint 8 objects, preserving Sprints 0–7.

## 2. Simulation-only / no-prevention compliance

- Every alert/incident surface carries `SOC_LIMITATIONS` and `prevention_allowed=false`/`enforcement_authority=false` (computed fields, always serialized).
- No `contained`/`blocked`/`prevented` state exists; workflow states are investigative only. No Sprint 8 code imports or calls any prevention, firewall, socket, shell, model-activation, or network interface.
- Correlation is deterministic and offline over persisted alerts — no ML, no real-risk inference, no live traffic. Notes redact endpoint-like tokens and are bounded.
- No detection/rule/model/threshold/ensemble state is mutated; alert projection is unchanged.

## 3. Gates run

- `ruff check` (apps/services/tests/migrations): **pass**.
- `ruff format --check`: **pass**.
- `mypy` (94 source files): **pass**.
- `pytest` full backend suite: **182 passed, 0 failed** (166 Sprint 7 baseline + 16 new Sprint 8 tests).
- `scripts/check_simulation_only.py`: **pass**. `scripts/check_secrets.py`: **pass**.
- New Sprint 8 tests: `tests/unit/test_soc_workflow.py` (7), `tests/unit/test_soc_correlation.py` (3), `tests/integration/test_sprint8_api.py` (6) — workflow state machine, note sanitization/redaction, correlation determinism/idempotency, RBAC-negative, CSRF, optimistic-lock conflict, disposition-on-close.

## 4. Deviations and deferred work (honest record)

- **Incident correlation runs synchronously** in the request handler (bounded ≤ 10,000 alerts, idempotent by correlation key) rather than as the Celery `incidents.correlate_batch` task the plan proposed. Rationale: for the bounded synthetic dataset this is simpler, fully testable in-process, and avoids a new dispatcher/harness surface. If large-scale correlation is later required, promote it to the planned Celery task. **Recorded, not hidden.**
- **FR-012 live notification channel: deferred.** It is an owner-gated *Should*; SOC views are pull-only for now.
- **Frontend SOC dashboard view: deferred.** The backend APIs are complete; the `apps/dashboard` SOC view (and its lint/typecheck/build gates) is not implemented in this pass.
- **Not run in this environment:** frontend `npm` lint/typecheck/build, Docker health, `pip-audit`, `check_secrets.py`, `check_simulation_only.py`. These must run in CI before any publication.

## 5. Follow-ups before publication

1. Merge Sprint 7 first (this branch depends on it).
2. Add the frontend SOC view and run frontend gates; decide FR-012.
3. Run the full CI gate set (Docker, SBOM/pip-audit, secret/simulation-only scanners) on the hosted runner.
4. Owner review of the diff for scope and Critical/High issues.
