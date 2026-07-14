# Risk Register

| ID | Risk | Likelihood/impact | Mitigation and trigger | Owner/status |
|---|---|---|---|---|
| R-01 | Scope exceeds solo-project capacity | High/High | Stop first release at Sprint 9; vertical slices; sprint gates | Owner/Open |
| R-02 | Dataset leakage inflates results | High/High | Source/time-aware splits; feature ban list; independent review | ML/Open |
| R-03 | Public dataset fails to represent real traffic | High/High | Honest limitations; second-source validation; no enterprise claims | ML/Open |
| R-04 | False positives make dashboard unusable | High/High | Rule tests, calibration, suppression, analyst feedback | Detection/Open |
| R-05 | Parser/upload creates security or availability issue | Medium/Critical | Content/schema validation, opaque storage, non-root/read-only worker, hard limits, deterministic fuzz/malformed tests implemented; broader native-parser fuzz/load hardening remains | Security/Controlled for Sprint 2 |
| R-06 | Artifact serialization enables code execution | Medium/Critical | Safe-format policy, integrity/provenance, controlled registry | Security/Open |
| R-07 | RBAC error exposes sensitive actions/data | Medium/High | Central policy and full six-role negative matrix implemented; repeat for every new route | Security/Controlled for Sprint 1 |
| R-08 | Simulation accidentally gains real capability | Low/Critical | No adapter/capability/privilege; OS-state E2E assertion | Architecture/Open |
| R-09 | Duplicate/replayed jobs corrupt state | High/High | Canonical event hash, unique flow/ledger constraints, row locking, actor-scoped replay key, repeated-task and replay tests implemented | Backend/Controlled for Sprint 2 |
| R-10 | Sensitive telemetry leaks through logs/reports/demo | Medium/High | Payload excluded, client names/MIME/internal paths ignored or hidden, bounded canonical metadata and safe errors; report/export controls remain later | Privacy/Partially controlled |
| R-11 | Supply-chain compromise | Medium/Critical | Pinning, scanning, provenance, least-privilege CI | DevSecOps/Open |
| R-12 | Local machine cannot support planned stack | Low/Medium for foundation; rises with ML/monitoring | Minimal stack verified on approved host; profile and stage optional services | Owner/Monitored |
| R-13 | Architecture docs diverge from implementation | Medium/High | Traceability, ADRs, PR doc checks, sprint reviews | Lead/Open |
| R-14 | Unsupported performance claims harm credibility | Medium/High | Representative benchmarks and explicit environment | QA/Open |
| R-15 | License prevents distribution of data/model | Medium/High | Academic-only intent recorded; no dataset redistribution; recheck before acquisition/publication | Owner/Controlled for Sprint 0 |
| R-16 | Cookie session/CSRF configuration allows cross-origin state changes | Medium/High | Secure attributes, hashed opaque tokens, rotation/revocation, idle/absolute expiry, token+Origin validation, exact CORS, tests | Security/Controlled for Sprint 1 |
| R-17 | Celery unsafe serialization or broker exposure compromises worker | Medium/Critical | JSON-only serializers, registered bounded-ID tasks, private Redis, time/resource limits, bounded retries, and malformed-envelope tests implemented | Backend/Controlled for Sprint 2 |
| R-18 | Scheduled cleanup fails and retention limits are exceeded | Medium/High | Beat jobs, expiry indexes, immediate success deletion, hourly/daily cleanup, cleanup tests; add operational alerting/reconciliation before non-local use | Operations/Partially controlled |

Critical/High residual risk requires explicit acceptance with owner, due date, evidence, and review date.
