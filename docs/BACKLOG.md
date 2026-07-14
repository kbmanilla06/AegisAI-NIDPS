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

Sprint 3 deterministic detection was authorized on 2026-07-14 using the approved defaults in `docs/SPRINT_3_IMPLEMENTATION_PLAN.md`. Implementation and local verification are complete on `feature/sprint-3-detection` and remain uncommitted pending the Sprint 3 review/publication gate. No Sprint 4, dataset, model, live-capture, or real-prevention work is authorized.
