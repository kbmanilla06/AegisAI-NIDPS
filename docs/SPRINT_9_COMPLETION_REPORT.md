# Sprint 9 Completion Report — Simulation-Only Prevention Preview (Level 1)

**Date:** 2026-07-17
**Status:** **Implemented and locally green; uncommitted, pending owner review** (Gate 9C completion stop). Not published.
**Plan:** `docs/SPRINT_9_IMPLEMENTATION_PLAN.md`.
**Baseline:** public `main` at `b46a3d8` (release `v0.8.0`, Sprints 0–8 merged and green).
**Boundary reaffirmed:** synthetic-only, offline, no model activation, no external network — and, new this sprint, **no real prevention adapter, no firewall/network/host-state change; simulation representation and records only.** Real/lab enforcement is **Sprint 10**, separately authorized, and is **not** implemented here.

## 1. Scope delivered

### Gate 9A — Policy, gates, and preview
- New `aegis_services.prevention` package:
  - `schema.py` — `PREVENTION_LIMITATIONS` (the mandatory verbatim clause, extending `SOC_LIMITATIONS`), `FALSE_CAPABILITY_FLAGS`, `SIMULATION_MODE`/`SIMULATION_ADAPTER` pinned to the single literal `simulation`, canonical action/target enums, deterministic target validity/scope helpers (internal ranges classified explicitly, not via the version-dependent `is_private`), and `canonical_policy_hash`.
  - `gates.py` — the **13 mandatory gates** from `docs/PREVENTION_SAFETY.md` as pure, deterministic functions over a fully-resolved `GateContext`. Every gate is always evaluated (no short-circuit); the request is eligible only if all pass; each result carries a stored reason code. Includes `PREV-006` model/anomaly-only ineligibility, intelligence-never-sole-proof, internal stricter denial, allowlist-denies, critical-asset denial, positive-bounded duration + mandatory expiry, mandatory rollback, and duplicate/rate gates.
  - `policy.py` — one immutable reviewed baseline policy definition + hash; `max_duration_seconds` ceiling (no permanent action exists).
  - `adapter.py` — the **data-only** simulation adapter. `preview()` returns a safe structured representation with `executable_command: null` and `network_call: null`, validated by a recursive executable-string guard (`ExecutableRepresentationError` on violation). `execute()` persists a `simulated` result with `verify` evidence; `rollback()` records a simulated reversal. A single-entry `ADAPTER_REGISTRY` is the only adapter.
  - `state_machine.py` — `Draft → Evaluated → Rejected | Previewed → Simulated → Expired | RolledBack`; invalid/skipped transitions fail closed; terminal states have no successors.

### Gate 9B — Simulated execution, rollback, no-enforcement verification, APIs, UI
- Seven ORM models + additive reversible migration `0012_sprint9_prevention_sim` (seven tables; `prevention_executions.mode` and `prevention_previews.adapter` **check-constrained to `simulation`**; `duration_seconds > 0`; `expires_at`/`rollback_plan` NOT NULL; per-request unique preview/execution; idempotency-key uniqueness; policy reviewer-distinct-from-creator; downgrade **refuses** while any non-terminal request or any execution remains).
- New permission `prevention:simulate` (granted to Senior Analyst, Security Administrator, System Administrator; seeded in `0012` and mirrored in the code RBAC matrix). `prevention:read`/`prevention:manage` reused.
- Router `routers/prevention.py` with the exact Section 13 routes: `GET /prevention/policies`, `POST /prevention/requests` (Idempotency-Key required; idempotent replay), `POST /prevention/requests/{id}/preview` (evaluate gates → previewed|rejected), `POST /prevention/requests/{id}/simulate` (one execution per request; `mode=simulation`; records verify evidence), `POST /prevention/executions/{id}/rollback` (idempotent), `GET /prevention/requests/{id}`. Sensitive-target redaction for read-only actors (Auditor sees `[redacted-target]`). Every mutation is CSRF+Origin protected and audited (metadata only). **No approval route, real-execution route, adapter-selection input, executable-command field, or browser-supplied command exists.**
- Dashboard prevention-simulation view (permission-gated on `prevention:read`) listing reviewed policies with the mandatory limitation text and machine-readable false-capability flags, and describing the simulated lifecycle. No block/enforce/apply control exists.

### No-enforcement verification evidence (the core of the sprint, PREV-008)
- **Dependency/import proof:** `tests/security/test_no_real_enforcement.py` AST-scans every prevention source file (package + router) and asserts none import `subprocess`, `socket`, `os`, `ctypes`, `fcntl`, or any firewall/raw-packet library.
- **Single-adapter proof:** the registry contains exactly `{"simulation"}`; the adapter name is immutably `simulation`.
- **Immutable mode proof:** `execute()` returns `mode == "simulation"` and `verify` evidence with `real_side_effect_invoked/outbound_socket_opened/firewall_state_changed` all `false`.
- **Preview-is-data proof:** the representation carries `executable_command: null`/`network_call: null` and passes the executable-string detector (which is separately proven to catch `iptables …`, `/bin/sh -c …`, etc.).
- **Static guard:** `scripts/check_simulation_only.py` extended with additional call-specific markers (`subprocess.Popen(`, `socket.socket(`, `pfctl`/`nft` invocation forms, `NET_RAW`/`NET_BROADCAST`) — call forms only, so the data-only detection regex that *names* those tools is not itself flagged.

## 2. Simulation-only / no-prevention compliance

- Every prevention surface (policy, request, gate result, preview, execution, rollback, API response, dashboard view) carries the verbatim `PREVENTION_LIMITATIONS` and false-capability flags; requests also serialize `mode=simulation`, `prevention_allowed=false`, `enforcement_authority=false`.
- No prevention code imports or calls any firewall, socket, shell, subprocess, model-activation, or network interface. `mode`/`adapter` are DB-check-constrained to `simulation`.
- Model/anomaly-only evidence is ineligible; alerts are corroborated only from deterministic detection sources. Duration is positive-bounded with mandatory expiry and rollback; no automatic/scheduled/permanent path exists.
- No detection/rule/model/alert/incident state is mutated beyond referencing it.

## 3. Gates run (local)

- `ruff check` (apps/services/tests/scripts/migrations): **pass**.
- `ruff format --check`: **pass**.
- `mypy` (strict, 102 source files): **pass**.
- `bandit -r apps services`: **pass** (0 issues).
- `pytest` full backend suite: **247 passed, 0 failed** (182 Sprint 8 baseline + 65 new Sprint 9 tests).
- `scripts/check_simulation_only.py`: **pass**. `scripts/check_secrets.py`: **pass**.
- Frontend: `npm run lint` / `typecheck` / `build` **pass**; **7 vitest tests pass** (+1 new prevention-view test).
- **Migration verified on real PostgreSQL 16** (throwaway container): `alembic upgrade head` seeds the seven tables + baseline policy + `prevention:simulate` grant; with a live `simulated` request present, `downgrade` **refuses** (`resolve open prevention simulation inventory before downgrade`); after clearing inventory, `downgrade` removes only Sprint 9 objects (Sprint 8 `incidents` intact, `prevention:simulate` removed) and `upgrade head` re-applies cleanly. `docker compose config` passes.

New Sprint 9 tests: `tests/unit/test_prevention_gates.py` (21 — full 13-gate matrix, determinism, fail-closed per gate), `tests/unit/test_prevention_state_machine.py` (10), `tests/unit/test_prevention_contract.py` (1), `tests/security/test_no_real_enforcement.py` (6), `tests/integration/test_sprint9_api.py` (15 — full lifecycle, idempotency, allowlist/internal/critical/model-only rejection, fresh/stale/unknown indicator, RBAC-negative, CSRF, request + preview-representation redaction, Idempotency-Key), `tests/integration/test_prevention_maintenance.py` (2 — expiry sweep + rollback-of-expired conflict), and 12 parametrized RBAC cases in `tests/security/test_rbac_matrix.py`.

## 4. Self-review findings fixed

A high-effort review of the working tree ran before commit; three real defects were found and fixed (regression tests added for the first two):

1. **Sensitive-target leak through the preview** — `_build_detail` redacted `request.target_value` but returned the preview `representation` (which embeds `target.display`) unredacted, so a read-only Auditor still saw the raw target. Now the representation's target is redacted for non-authoring viewers.
2. **Rollback of an expired request → HTTP 500** — `rollback_execution` called the transition validator without a status guard; once a request had expired (via the new maintenance sweep), `validate_request_transition(EXPIRED, ROLLED_BACK)` raised an uncaught `ValueError`. Now returns a clean `409 prevention_not_simulated`.
3. **Concurrent preview → unique-constraint 500** — two simultaneous previews on one draft double-inserted gate results; the commit now catches `IntegrityError` and fails closed to the persisted decision.
4. **API health failure from eager native-ML imports** — the API image intentionally excludes the optional ML dependency set, but the anomaly and explainability package initializers imported NumPy/ONNX at API startup. Package exports are now lazy; native ML modules load only when worker-side processing calls them. The API and dashboard health checks pass without adding ML dependencies to the API image.

## 5. Deviations (honest record)

- **Gate evaluation, preview, simulate, rollback run synchronously** in the request handler (bounded, no external work, no side effect) rather than as Celery tasks — consistent with Sprint 8's synchronous-correlation choice and fully testable in-process. A synchronous `expire_due_simulations` maintenance function (`apps/api/aegis_api/prevention_maintenance.py`) provides the `cleanup` path; it is not yet registered as a scheduled Celery task.
- **Intelligence freshness is now exercised via the API**: a request may optionally cite an `indicator_id`; the freshness gate treats an expired indicator as ignored-not-fatal and never lets intelligence be sole proof. Wiring intelligence in as automatic corroboration (vs. an explicit reference) remains future work.
- The baseline reviewed policy is **seeded by the migration** for production and **seeded in-test** where needed (conftest is unchanged).

## 5. Boundary / not done (by design)

- No real or lab enforcement; no real adapter; no outbound socket; no OS firewall/network/host-state change; no privileged/host-network/`NET_ADMIN` container; no approval or real-execution route; no executable-command representation. **These are Sprint 10 and are not authorized by this work.**
- Not committed and not published: the tree stops at the Gate 9C completion gate for owner review. This closes the Sprints 0–9 first release (IDS + simulated IPS).
