# Sprint 8 Completion Report — Alert SOC Workflow and Incident Correlation

**Date:** 2026-07-16
**Status:** **MERGED to public `main`** via PR #2 on 2026-07-16 (merge commit `7056d71`); hosted CI green on the merged tree.
**Predecessor:** Built on Sprint 7 (merged via PR #1, `2d816c4`) and the Sprint 5 disk-flake fix (PR #3, `cb9c5f9`); the Sprint 8 plan merged via PR #4 (`b937007`).
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

## 4. Additional work completed (initially deferred, now done)

- **Frontend SOC view:** `apps/dashboard` now renders alert workflow state with triage actions (acknowledge/investigate/close) and an incidents panel (correlate + status management), permission-gated. While wiring this, the Sprint 7 dashboard state (explanations/intelligence/MITRE) was found declared-but-unused (failing `eslint --max-warnings=0` on the Sprint 7 branch) and was completed with fetches + read-only panels. Frontend gates pass: **typecheck, lint, build, and 6 vitest tests** (one existing alert-text assertion updated for the new status display).
- **FR-012 live notification:** an injectable, best-effort, metadata-only notifier publishes `{event, alert_id, sequence}` to the existing `aegis.alerts` channel on alert workflow changes — never blocks the transition, never carries endpoints/vectors/notes, never triggers prevention. Overridable in tests; asserted in the integration suite.
- **`test_ml_training` `.pkl`/`.joblib` glob** scoped to exclude vendored dependency dirs (`.venv`, `site-packages`, `node_modules`), preserving the safe-format guard on repo source while tolerating a local in-repo venv.

## 5. Deviations (honest record)

- **Incident correlation runs synchronously** in the request handler (bounded ≤ 10,000 alerts, idempotent by correlation key) rather than as the Celery `incidents.correlate_batch` task the plan proposed. For the bounded synthetic dataset this is simpler, fully testable in-process, and avoids a new dispatcher/harness surface. Promote to the planned Celery task if large-scale correlation is later required.

## 6. Publication

Sprint 8 merged to public `main` on 2026-07-16. Merge order and hosted-CI outcomes:

| PR | Content | Merge commit | Hosted CI |
|----|---------|--------------|-----------|
| #3 | Sprint 5 disk-flake fix (deterministic `_preflight`) | `cb9c5f9` | green |
| #1 | Sprint 7 (explainability + intel/MITRE) + dashboard fix | `2d816c4` | green |
| #4 | Sprint 8 implementation plan | `b937007` | green |
| #2 | Sprint 8 (workflow + incidents + FR-012 + SOC view) | `7056d71` | green |

The **CI-only gates now ran on the hosted runner and passed**: the `backend` job (pytest, ruff, mypy, bandit, `pip-audit`) and the `containers` job (Docker build/health), alongside the `frontend` job (lint/typecheck/build/vitest). The final `main` push run for `7056d71` concluded **success**.

Notes from publication:
- PR #4 (docs-only) initially failed backend CI on the exact Sprint 5 disk-space flake, empirically confirming the need for PR #3; merging #3 first cleared it.
- Sprint 8 conflicted with Sprint 7 in `apps/dashboard/src/App.tsx` (both added the explainability/intel/MITRE panels); resolved by taking Sprint 8's superset (panels + incidents + triage) and re-verifying the frontend gates.

### Remaining (out of scope for Sprint 8)
- Owner review of the merged diff at leisure (merges landed on CI-green, self-authored; no separate human reviewer in this solo project).
- Prevention policy/adapters and enforcement are **Sprint 9+** and remain outside the synthetic-only boundary.
