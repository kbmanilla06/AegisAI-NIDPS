# Sprint 9 Implementation Plan — Simulation-Only Prevention Preview (Level 1)

**Planning date:** 2026-07-17
**Status:** Planning only; owner approval required
**Target:** Sprint 9 — policy-controlled **simulation** of prevention (preview + simulated execution/rollback), with **zero real enforcement**
**Release boundary:** Sprints 0–9, IDS with **simulated** IPS (`C-02`); Sprint 9 is the final sprint of the first release
**Planning baseline:** public `main` at `b46a3d8` (release `v0.8.0`, Sprints 0–8 merged and green)
**Boundary:** synthetic-only, offline, no model activation, no external network; and — new for this sprint — **no real prevention adapter, no firewall/network/host-state change; simulation representation and records only**

> **Hard boundary (read first).** Sprint 9 implements **Level 1 simulation only**, exactly as `docs/PREVENTION_SAFETY.md` and `PREV-001` scope it: a proposed defensive action is evaluated against documented gates, **previewed as a safe structured representation (never an executable command)**, and recorded as a `simulated` result. It performs **no** firewall change, packet drop, block, quarantine, isolation, routing/network-state change, or any real side effect. `execute` persists a `simulated` row; `verify` asserts **no real side-effect path was invoked** and that **OS firewall state is byte-identical before and after** (`PREV-008`). **Real/lab enforcement is Sprint 10, separately authorized, and is explicitly excluded here.** No part of this plan authorizes a real adapter.

## 1. Entry-gate evidence

- Sprints 0–8 are merged on public `main` (`b46a3d8`), released as `v0.8.0`, with hosted CI green (backend/frontend/containers).
- `prevention:read` and `prevention:manage` permissions already exist (seeded in `0001_sprint1_identity`). The prevention tables/routes/contracts are **specified but not implemented** (`docs/DATABASE.md`, `docs/api/API.md`, `docs/SCHEMAS.md`, `docs/PREVENTION_SAFETY.md`).
- **Working-tree note:** at planning time the tree carries this document only. Implementation must not begin until the owner approves the Section 21 decisions and supplies the exact Sprint 9 authorization (Section 26).

This document is documentation-only. It authorizes no code, migration, real adapter, firewall/network change, enforcement, commit, or publication.

## 2. Governing material reconciled

- `AegisAI-NIDPS-Master-Prompt.md` / `AegisAI-NIDPS-Implementation-Guide.md` (§8 Sprint 9 = simulated prevention) and `C-02` (first release = IDS + **simulated** IPS).
- `docs/PREVENTION_SAFETY.md` — the authoritative safety model (gates, adapter contract, state machine, invariants, Sprint 9 verification evidence). This plan implements it; it introduces nothing beyond it.
- `docs/REQUIREMENTS.md`: **FR-013** (preview and simulate policy-controlled prevention, Must); **PREV-001** (Sprints 0–9 simulation only, no network changes); **PREV-005** (idempotency/uniqueness prevent duplicate execution records); **PREV-006** (anomaly-only/model-only never eligible for automatic prevention); **PREV-007** (permanent actions and automatic enforcement prohibited); **PREV-008** (verified to leave OS firewall state unchanged); **NFR-004**, **SEC-009**, **SEC-012**.
- `docs/DATABASE.md` (prevention tables), `docs/api/API.md` (prevention routes), `docs/SCHEMAS.md` (Prevention request v1), `docs/DECISIONS.md` (`C-02`, `C-04` no real prevention; `D-13` safe formats), `docs/threat-model/THREAT_MODEL.md`, `docs/RISK_REGISTER.md`.
- Sprint 3–8 delivery (`docs/BACKLOG.md`): alerts, incidents, assessments, and evidence lineage are the inputs a prevention **request** references.

## 3. Confirmed requirements and invariants

These are not new owner decisions:

1. The first release is Sprints 0–9: IDS with **simulated** IPS (`C-02`, `C-04`).
2. Detection, assessment/fusion, explainability/intelligence, alert/incident workflow, and prevention are separate concerns. Prevention **consumes** evidence; it never detects, scores, or enforces.
3. **Simulation is the only mode.** `mode` is fixed to `simulation`; there is no real adapter, approval route, or execution path. High-impact, permanent, and automatic actions do not exist (`PREV-007`).
4. **Evidence gating (`PREV-006`):** anomaly-only or model-only evidence is never sufficient; corroboration by a deterministic rule/detection is required by policy design. Stale/expired intelligence is ignored and never sole proof (TM-13).
5. Every policy version, request, gate result, preview, simulated execution, and rollback is versioned, hash/lineage-bound, idempotent, and audited (`SEC-009`, `PREV-005`).
6. No prevention object mutates detections, rules, models, alerts (beyond referencing them), incidents, network state, or firewall state.
7. Duration is positive and below the policy maximum; expiration and structured rollback metadata are mandatory (`PREV-007`).
8. PostgreSQL is authoritative; Celery messages are JSON-only bounded UUIDs; Redis is coordination only.
9. No `execute`/`preview` path constructs an executable shell string, opens an outbound socket, or touches OS firewall/network state.

## 4. Sprint 9 scope

### 4.1 Included after separate implementation authorization

- **Immutable `PreventionPolicyVersionV1`** (name+version, definition, gates config, hash, lifecycle, creator/reviewer) and **allowlist entries** (target type/value, scope, reason, expiry).
- **`PreventionRequestV1`**: references an alert/incident + current versioned evidence; carries a canonical **action type** and **canonical supported target** (no arbitrary command/input), reason, requested duration (>0, ≤ policy max), mandatory `expires_at`, mandatory structured `rollback_plan`, idempotency key.
- **Deterministic gate evaluation** producing per-gate `policy_gate_results` (the 13 gates of Section 6), fail-closed, with stored reason codes and evidence refs.
- **`preview`**: a safe **structured representation** of what *would* occur — data only, never an executable command or network call — persisted in `prevention_previews` (`adapter="simulation"`).
- **`simulate`**: records a `prevention_executions` row with `mode` checked = `simulation` only; **no real side effect**; idempotent/unique (`PREV-005`).
- **`rollback`**: records a simulated reversal (`prevention_rollbacks`); idempotent.
- **`verify`**: confirms the simulated record and asserts no real side-effect path was invoked (dependency + OS-capability + firewall-state evidence, Section 8).
- Additive reversible migration `0012_sprint9_prevention_sim` for the seven prevention tables + any new permission.
- Central RBAC, CSRF/Origin, creator/reviewer separation, safe append-only audit, retention.
- Metadata/aggregate-only APIs and a dashboard prevention-simulation view, each carrying the exact simulation limitation and false-capability flags.
- Synthetic/hostile fixtures created before implementation, plus unit, contract, integration, security, migration, determinism, resource, Docker, Celery, frontend, accessibility, and — mandatory for this sprint — **no-real-enforcement** tests.

### 4.2 Explicitly excluded

- **Any real prevention/enforcement**: firewall integration, iptables/nft/pf, packet drop/block/reset, quarantine, isolation, routing/DNS sinkhole, rate-limit on real traffic, agent/EDR action, or any outbound socket or OS-state change. **No real adapter exists in the codebase or dependency graph.**
- Approval workflow and **lab/real execution** (Sprint 10, separately authorized).
- Automatic, scheduled, permanent, or high-impact actions; model/anomaly-only eligibility.
- Executable command representation, browser-supplied targets/commands/paths, privileged containers, host networking, `NET_ADMIN`/firewall capabilities, commit, or publication.
- Real datasets/feeds, model activation, online inference, live capture (unchanged synthetic-only boundary).

## 5. Proposed Sprint 9 gates

### Gate 9A — Policy, gates, and preview
Freeze `PreventionPolicyVersionV1`, allowlist, `PreventionRequestV1`, the 13-gate evaluator, and the preview representation contract. Generate hostile/golden fixtures first. Implement immutable reviewed policies, request creation, deterministic gate evaluation (fail-closed), and safe structured preview (`adapter="simulation"`, no executable string). Do not record any execution.

### Gate 9B — Simulated execution, rollback, and no-enforcement verification
Freeze the state machine and `verify` evidence. Record `simulated` executions and rollbacks (idempotent/unique), and produce the **verification evidence** proving no real enforcement path exists (Section 8). Wire the APIs and dashboard view. Do not add a real adapter or any OS/network/firewall interaction.

### Gate 9C — Completion review (first-release close-out)
Run the complete local gates, review the diff for scope and Critical/High issues, produce `docs/SPRINT_9_COMPLETION_REPORT.md`, and stop uncommitted. This closes the Sprints 0–9 first release. Any real/lab enforcement (Sprint 10) requires separate owner authorization.

## 6. Mandatory gates (from `PREVENTION_SAFETY.md`)

Every request is evaluated against all gates; any failure fails the request closed with a stored reason code. Gates are pure, deterministic, versioned functions:

| Gate | MVP behavior |
|---|---|
| Environment | Must equal controlled `simulation`; anything else denies |
| Authorization | Requester holds explicit simulation permission |
| Target validity | Canonical supported target only; no arbitrary command/input |
| Internal/external | Unknown fails eligibility; internal receives stricter default denial |
| Allowlist | A match denies the proposal and records the reason |
| Critical asset | Critical target denies (high-impact workflow deferred) |
| Evidence | Referenced, current, versioned signals required |
| Model/anomaly-only | Always insufficient (`PREV-006`) |
| Intelligence freshness | Expired intelligence ignored; never sole proof |
| Duration | Positive and below policy maximum; expiration mandatory |
| Rollback | Structured rollback metadata mandatory |
| Duplicate/replay | Idempotency + unique request/execution checks (`PREV-005`) |
| Rate/cooldown | Evaluated even in simulation to validate future design |

## 7. Adapter contract and state machine (simulation only)

**Adapter (`adapter="simulation"`):**
- `validate` — validate the typed proposal and that `mode=simulation`.
- `preview` — return a **safe structured representation** (JSON data), never an executable shell string or network call.
- `execute` — persist a `simulated` result only; **no real side effect**.
- `verify` — confirm the simulated record and confirm **no real side-effect path was invoked**.
- `rollback` — record a simulated reversal.
- `status` — return lifecycle and audit references.

**State machine:** `Draft → Evaluated → Rejected | Previewed → Simulated → Expired | RolledBack`. Invalid/skipped transitions fail closed. Replays return the existing result or a conflict; they never create a second execution (`PREV-005`).

## 8. No-enforcement verification evidence (the core of this sprint)

Sprint 9 is only complete if it **proves** it cannot enforce (`PREV-008`, `PREVENTION_SAFETY.md`):

- **Dependency-graph proof:** no real enforcement adapter, firewall library, or raw-socket dependency is importable from any prevention path (static import scan + `check_simulation_only.py` extended markers).
- **OS-capability proof:** runtime containers lack `privileged`, host networking, and `NET_ADMIN`/firewall capabilities (compose + runtime assertion).
- **Firewall-state proof:** OS firewall state is **byte-identical before and after** the full simulation E2E suite (captured, diffed, asserted).
- **Code-path proof:** `execute`/`preview` never build an executable string, never open an outbound socket; a test asserts the simulation adapter is the only registered adapter and `mode` is immutably `simulation`.
- **No-side-effect assertion in `verify`:** each simulated execution's `verify` records that no real path was reachable.

## 9. Evidence and provenance

Each policy, request, gate result, preview, execution, and rollback binds to: referenced alert/incident + detection/assessment evidence hashes; policy version + gate-config hash; requester/reviewer identities and reason codes; code commit and dependency/runtime lock hash; and resource/task outcome metadata. Reports/UI are aggregate; sensitive targets are redacted by role. Restricted row-level lineage has 30-day retention and no endpoints/vectors.

## 10. Lifecycle

- Policies/allowlists: `draft → reviewed → retired`; immutable definitions; a change creates a new version + review event. Reviewer distinct from creator.
- Requests/executions: the Section 7 state machine; append-only gate results, previews, executions, rollbacks.

## 11. PostgreSQL migration design (planning only)

Additive migration `0012_sprint9_prevention_sim` (follows `0011`) creates the seven tables already specified in `docs/DATABASE.md`: `prevention_policy_versions`, `allowlist_entries`, `prevention_requests`, `policy_gate_results`, `prevention_previews`, `prevention_executions`, `prevention_rollbacks`, with the stated constraints (immutable definitions; `mode` check = `simulation`; `duration_seconds > 0`; `expires_at`/`rollback_plan` NOT NULL; per-request unique preview/execution; idempotency-key uniqueness) plus any new permission (Section 15). Downgrade refuses while non-terminal requests/executions remain, then removes only Sprint 9 objects, preserving Sprints 0–8. Migration tests cover fresh/existing-data upgrade, downgrade refusal, cleanup, re-upgrade, immutable-field mutation, concurrent transition, and audit-failure rollback.

## 12. Celery tasks and resource limits

Gate evaluation, preview, simulate, rollback, and verify are **synchronous, bounded** request-time operations (no external work, no real side effect); they register no batch task. Optional `sprint9.reconcile()` recovers stale persisted requests and `sprint9.cleanup()` expires simulated lifecycle records with audit. Bounded defaults align with Sprints 6–8 (memory/CPU/threads/PIDs/timeouts); workers have **no outbound network, no privilege, no host network, no firewall capability**, read-only root, controlled volumes only.

## 13. Minimal APIs and UI (design only)

The routes already specified in `docs/api/API.md` (unchanged):

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| GET `/prevention/policies` | View policy versions | `prevention:read` | read-only |
| POST `/prevention/requests` | Create simulation request | `prevention:simulate` | Idempotency-Key; duration/rollback/evidence validated; audit |
| POST `/prevention/requests/{id}/preview` | Evaluate gates + preview | `prevention:simulate` | unique preview; no executable command/network call; audit |
| POST `/prevention/requests/{id}/simulate` | Record simulated execution | `prevention:simulate` | Idempotency-Key; all gates pass; `mode=simulation` fixed; audit |
| POST `/prevention/executions/{id}/rollback` | Record simulated rollback | `prevention:simulate` | idempotent; audit |
| GET `/prevention/requests/{id}` | Inspect lifecycle/gates | `prevention:read` | sensitive-target redaction by role |

There is **no** approval route, real-execution route, adapter-selection input, executable-command field, network/firewall route, or browser-supplied target/command. The dashboard adds an authenticated simulation-only view (policies, request lifecycle, gate results, preview representation, simulated status) carrying the exact limitation and false-capability flags. `No approval or real-execution route exists in the Sprints 0–9 API.`

## 14. RBAC, CSRF, and audit

Reuse `prevention:read` (view; Senior Analyst / Security Administrator / Auditor) and `prevention:manage` (policy/allowlist authoring + review; Security Administrator). Add **`prevention:simulate`** (create request/preview/simulate/rollback; Senior Analyst + Security Administrator) so "requester needs explicit simulation permission." Policy reviewers cannot review their own policy. Unsafe requests require the opaque session, session-bound CSRF token, exact allowed Origin, rate limit, and optimistic expected-state checks. Audit covers policy/allowlist create+review, request create, each gate evaluation, preview, simulated execution, rollback, expiry, and cleanup — metadata (hashes/counts/versions/actor/reason/correlation) only, never targets in the clear, executable strings, raw rows, or exception text. Audit-persistence failure fails closed.

## 15. Retention, privacy, security, and failure controls

- Simulated lifecycle records retained by version; row-level lineage 30 days; sensitive targets redacted; every surface carries the mandatory simulation limitation and false-capability flags.
- Treat policy/target/reason input as hostile: canonical JSON, reject unknown fields, oversized input, symlinks, traversal, non-finite values, executable strings, and any network/host target outside the canonical supported set.
- **Fail-closed failure table** (representative): any real-enforcement or outbound-socket attempt → Critical defect, fail closed; unknown/critical/allowlisted target → deny with reason; model/anomaly-only evidence → ineligible; missing duration/rollback → reject; expired intelligence as sole proof → ineligible; duplicate/replay → existing result or conflict; invalid transition → reject; DB/audit failure → no state change.

## 16. Fixture-first and test matrix

Fixtures (synthetic, deterministic, created first): valid/critical/allowlisted/unknown/internal/external targets; model-only and anomaly-only evidence; expired-intelligence; missing-duration and missing-rollback; duplicate/replay/concurrency; each gate pass/fail; hostile executable-string and network-target inputs; oversized/traversal inputs. Required gates: schema/hash/unknown-field; **deterministic gate-evaluation parity**; **no-network and no-real-enforcement proofs (Section 8)**; state-machine validity; allowlist/critical/model-only/anomaly-only/expiry/duration/rollback behavior; idempotency/replay/concurrency; leakage/redaction; migration upgrade/downgrade/re-upgrade; retention cleanup; Docker non-root/read-only/cap-drop/no-host-network + **firewall-state-unchanged E2E**; Celery registration; RBAC-negative/self-review/CSRF/Origin/IDOR/rate-limit/audit-fail-closed; frontend lint/type/build/a11y + limitation/false-flag assertions; secret/large-file/dependency/SBOM/native scans.

## 17. Resource and reproducibility evidence

Every run records code commit, dependency lock/SBOM hash, policy/gate-config hash, seed, counts, elapsed time, peak RSS, CPU, and terminal status, plus the **before/after firewall-state hashes** proving no change. Synthetic simulation is never a real-prevention effectiveness claim.

## 18. Dependencies, assumptions, deferred work

- **Depends on:** merged Sprints 0–8 (`v0.8.0`), existing alerts/incidents/assessments as evidence, RBAC/audit, controlled artifacts, Docker health. No new native/enforcement dependency; gate evaluation and preview are pure functions.
- **Assumptions:** simulation is the only mode; the referenced evidence is immutable; there is no real adapter anywhere in scope.
- **Deferred:** **Sprint 10 approval-based lab/real enforcement** (separately approved), high-impact/critical-asset workflow, automatic actions, real feeds/capture/activation.

## 19. Decisions requiring owner approval

1. Approve the three-gate Sprint 9 boundary (9A policy/preview, 9B simulated execution + no-enforcement verification, 9C completion).
2. Approve **simulation-only** as the sole mode, with **no real adapter** and the Section 8 no-enforcement verification as a completion requirement.
3. Approve the `PreventionPolicyVersionV1` / allowlist / `PreventionRequestV1` contracts and the canonical supported action/target set (no arbitrary command/input).
4. Approve the 13-gate evaluator and fail-closed semantics, including `PREV-006` model/anomaly-only ineligibility and expired-intelligence handling.
5. Approve the state machine, mandatory duration/expiry/rollback, and idempotency/uniqueness (`PREV-005`/`PREV-007`).
6. Approve the additive reversible `0012_sprint9_prevention_sim` migration and downgrade-inventory refusal.
7. Approve the new **`prevention:simulate`** permission plus reuse of `prevention:read`/`prevention:manage`, creator/reviewer separation, and the simulation-only APIs/UI.
8. Approve the exact simulation limitation text and false-capability flags on every surface.
9. Confirm Sprint 9 performs **no** real prevention/firewall/network/host-state change and that real/lab enforcement remains **Sprint 10**, separately authorized.

No unanswered decision is inferred as approval.

## 20. Major risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Any real enforcement / firewall / network change | Critical | No real adapter; no outbound socket; dependency + OS-capability + firewall-state proofs (Section 8); `check_simulation_only.py`; fail-closed |
| Preview emits an executable command | Critical | Representation is structured data only; contract + tests forbid executable strings/shell |
| Model/anomaly-only evidence drives a proposal (`PREV-006`) | High | Evidence gate requires deterministic corroboration; ineligibility tests |
| Permanent/automatic/high-impact action appears (`PREV-007`) | High | Mandatory positive-bounded duration + expiry; no automatic/scheduled path; tests |
| Duplicate/replayed execution record (`PREV-005`) | High | Idempotency keys + unique constraints; replay returns existing/conflict |
| Simulation presented as real prevention effectiveness (TM-39) | High | Mandatory limitation + false-capability flags; no effectiveness claim; publication review |
| Sensitive target leakage | Medium | Role-based target redaction; aggregate APIs; 30-day lineage |
| Scope creep into Sprint 10 enforcement | Critical | Explicit exclusions; no adapter/capability; diff review; completion gate |

## 21. Implementation sequence after authorization

1. Reconfirm the `v0.8.0` baseline and a clean/reconciled tree.
2. Update only the affected design/threat/risk/schema/API/test records.
3. Create hostile/golden prevention fixtures before implementation.
4. Add contracts, the 13-gate evaluator, the simulation adapter, permissions.
5. Add migration `0012`.
6. Implement Gate 9A (policies, allowlist, request, gate evaluation, preview). Stop and review.
7. Implement Gate 9B (simulated execution, rollback, `verify`, no-enforcement evidence, APIs, UI). Stop before any real adapter/enforcement.
8. Run completion gates, write `docs/SPRINT_9_COMPLETION_REPORT.md`, review the full diff, stop uncommitted for approval. This closes the Sprints 0–9 first release.

## 22. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The design implements the master prompt's simulated-IPS definition and `docs/PREVENTION_SAFETY.md` exactly, satisfies FR-013 and PREV-001/005/006/007/008, keeps prevention strictly a simulation of evidence-gated proposals, and makes "no real enforcement" a *verified* completion requirement. Implementation remains blocked until the owner approves the Section 19 decisions and supplies the exact Sprint 9 authorization. **Real/lab enforcement is Sprint 10 and is not authorized by this plan.**

## 23. Exact Sprint 9 implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_9_IMPLEMENTATION_PLAN.md and begin AegisAI NIDPS Sprint 9 using its three-gate boundary: Gate 9A policy/gates/preview, Gate 9B simulated execution + no-enforcement verification, and Gate 9C completion review (first-release close-out).

Before proceeding:
- Confirm public main is at the v0.8.0 baseline (Sprints 0–8 merged, hosted CI green).
- Confirm the working tree contains only separately reviewed prior changes plus this authorized Sprint 9 work.
- Read all governing documents, especially docs/PREVENTION_SAFETY.md, and this plan completely.
- Do not rewrite published history.

Implement SIMULATION ONLY. Build no real prevention: no firewall/iptables/nft/pf, no packet drop/block/reset, no quarantine/isolation, no routing/DNS change, no rate-limit on real traffic, no agent/EDR action, no outbound socket, and no OS firewall/network/host-state change. There is no real adapter and no approval/real-execution route. mode is fixed to simulation; execute persists a simulated record only; preview returns a safe structured representation, never an executable command; verify asserts no real side-effect path was invoked and that OS firewall state is byte-identical before and after.

Approve these Sprint 9 defaults:
- Immutable PreventionPolicyVersionV1 + allowlist; PreventionRequestV1 referencing an alert/incident and current versioned evidence, with a canonical supported action/target (no arbitrary command/input), mandatory positive-bounded duration, mandatory expiry, and mandatory structured rollback plan.
- The 13 mandatory gates from PREVENTION_SAFETY.md, fail-closed, deterministic, with stored reason codes; model-only and anomaly-only evidence are always ineligible (PREV-006); expired intelligence is ignored and never sole proof.
- The simulation adapter contract (validate/preview/execute→simulated/verify/rollback/status) and the state machine Draft→Evaluated→Rejected|Previewed→Simulated→Expired|RolledBack; idempotency + uniqueness prevent duplicate executions (PREV-005); permanent/automatic/high-impact actions do not exist (PREV-007).
- Additive reversible migration 0012_sprint9_prevention_sim (the seven prevention tables) with immutable definitions, mode=simulation checks, and downgrade-inventory refusal; new prevention:simulate permission plus reuse of prevention:read/prevention:manage; creator/reviewer separation; CSRF/Origin, idempotency, audit, retention, and RBAC controls.
- Simulation-only APIs and a dashboard prevention-simulation view; no approval/real-execution route.

Produce the no-enforcement verification evidence as a completion requirement (PREV-008): dependency-graph proof of no real adapter/firewall/raw-socket dependency; container proof of no privileged/host-network/NET_ADMIN capability; before/after OS firewall-state identical across the E2E simulation suite; and a test proving the simulation adapter is the only registered adapter.

Preserve the mandatory limitation text exactly:

SIMULATION ONLY. Prevention in this system is a policy-gated simulation over synthetic evidence. It previews and records what a defensive action WOULD be, never performs one: no firewall, network, host, or traffic change occurs, and OS firewall state is unchanged. Alerts, incidents, models, and intelligence are evidence, never enforcement authority. Real or lab enforcement is a separately authorized later sprint and is not present.

Every policy, request, gate result, preview, simulated execution, rollback, metric, artifact, report, API response, notification, and UI view must carry that limitation and machine-readable false-capability flags. Never claim real prevention, blocking, containment, firewall, or enforcement effectiveness.

Do not implement or test any real/lab enforcement; add any real adapter; open any outbound socket; change OS firewall/network/host state; use privileged containers, host networking, or firewall capabilities; create an approval or real-execution route; represent an action as an executable command; mutate detections/rules/models/alerts/incidents beyond referencing them; begin Sprint 10 or later; commit; or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, gate-parity, offline-no-network, NO-REAL-ENFORCEMENT (dependency/capability/firewall-state), state-machine, allowlist/critical/model-only/anomaly-only/expiry/duration/rollback, idempotency/replay/concurrency, leakage/redaction, migration, RBAC-negative, CSRF/Origin, audit, resource, retention, Docker, Celery, frontend, accessibility, dependency, SBOM/Trivy or documented equivalent, secret, large-file, health, and simulation-only checks. Stop at the uncommitted Gate 9C completion gate and wait for separate owner review/publication approval.
```
