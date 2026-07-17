# Sprint Backlog and Forward Plan

## Sprint 0 planning items

| ID | Item | Dependencies | Acceptance/status |
|---|---|---|---|
| S0-01 | PRD and scope | Governing prompts | Complete and owner-approved |
| S0-02 | Requirements and use/abuse cases | S0-01 | Complete |
| S0-03 | Architecture and data flows | S0-01/02 | Complete |
| S0-04 | STRIDE model/security backlog | S0-03 | Complete |
| S0-05 | Canonical schemas/data design | S0-03 | Complete |
| S0-06 | API contracts | S0-05 | Complete |
| S0-07 | Detection/prevention design | S0-03/04/05 | Complete |
| S0-08 | ML/dataset plan | S0-02/04/05 | Complete for Sprint 0; no dataset downloaded |
| S0-09 | Test/deployment strategy | All designs | Complete |
| S0-10 | Risks/DoD/repository/governance | All designs | Complete |
| S0-11 | Owner decision review | S0-01–10 | Complete; D-13 intentionally deferred to before Sprint 5 |
| S0-12 | Repository/API/UI/Compose/CI/test scaffold | S0-11 | Complete and locally verified |
| S0-13 | Health checks and clean-start validation | S0-12 | Complete; all five containers healthy and worker ping passed |
| S0-14 | Sprint 0 implementation review | S0-13 | Complete; published commit `44dbc59`, hosted CI Run #1 passed |

## Forward epics

S1 identity/RBAC/assets/sensors; S2 ingestion; S3 deterministic detection; S4 features; S5 supervised ML; S6 anomaly/ensemble; S7 explainability/intelligence; S8 SOC workflows; S9 simulation policy. Each is blocked until the preceding sprint gate is approved.

## Sprint delivery status

Sprint 1 identity/RBAC/assets/sensors/audit is complete, published as `61ef2cc9`, and hosted CI Run #2 passed.

Sprint 2 order: fixtures/schema → normalized adapter → Zeek → Suricata flow events → offline PCAP → storage/worker/idempotency → APIs/UI → migration/security/resource tests → documentation. **Status: complete and published on `main` at `29c2891f`; hosted CI Run #4 passed.**

Sprint 3 deterministic detection was published on `main` as `b514aa3592487a65b8de8e1cfa14f4f9b80c5976`; hosted CI Run #5 (`29325828604`) passed all backend, frontend, and container jobs.

Sprint 4 feature engineering and the versioned data pipeline were published on `main` as `72c97b15f9bb31ddb6810a397afc682893497bab`; hosted CI Run #7 (`29332025235`) passed all jobs. Publisher outreach is cancelled and UNSW-NB15 acquisition is blocked/deferred.

Sprint 5 synthetic-only track (Gate 5S-A synthetic generation, 5S-B preprocessing/supervised training, 5S-C dashboard evidence) is complete and published on `main`. UNSW-NB15 acquisition remains blocked; all work is synthetic, offline, and no model is activated. The pre-acquisition disk-space preflight test flake (CI Run #14) was fixed deterministically and merged via PR #3 (`cb9c5f9`).

Sprint 6 offline anomaly detection and transparent fusion were published on `main` as `e11f103` (Gate 6A isolation-forest ONNX detector, Gate 6B fusion policy, Gate 6C review). Offline batch only; no activation, online inference, or alert/prevention mutation.

Sprint 7 explainability, synthetic threat-intelligence, and MITRE ATT&CK context merged via PR #1 (`2d816c4`): deterministic offline permutation/occlusion attribution, bundled hash-only indicators (RFC 5737/3849/.invalid), qualified MITRE mappings, migration `0010`. Every invariant (real_feed/external_lookup/online_inference/prevention/enforcement) is pinned false.

Sprint 8 alert SOC workflow and incident correlation merged via PR #2 (`7056d71`): unlocked the Sprint-3 alert status lifecycle (status/assignment/notes/disposition, FR-010), added deterministic offline incident correlation with timeline/ownership (FR-011), optional metadata-only alert notifications (FR-012), a frontend SOC view, and migration `0011`. No prevention/containment/network state; correlation runs synchronously (bounded, idempotent) rather than as a Celery batch. The Sprint 8 plan and completion report are on `main` (PRs #4 `b937007`, #5). Hosted CI is green on the merged tree.

Sprint 9 prevention **simulation** (Level 1, FR-013) is implemented on branch `docs/sprint-9-implementation-plan` (uncommitted, pending owner review): the `aegis_services.prevention` package (13-gate fail-closed evaluator, data-only simulation adapter, request state machine), migration `0012` with the seven prevention tables (`mode`/`adapter` check-constrained to `simulation`), the new `prevention:simulate` permission, simulation-only APIs (`/prevention/policies|requests|.../preview|.../simulate|executions/.../rollback`), a dashboard prevention view, and the no-enforcement verification suite (import-scan, single-adapter, preview-is-never-a-command). **No real adapter, firewall/network/host-state change, outbound socket, approval route, or real-execution route exists.** Real/lab enforcement is **Sprint 10**, separately authorized, and is not implemented. This closes the Sprints 0–9 first release (IDS + simulated IPS).
