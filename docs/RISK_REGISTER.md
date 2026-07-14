# Risk Register

| ID | Risk | Likelihood/impact | Mitigation and trigger | Owner/status |
|---|---|---|---|---|
| R-01 | Scope exceeds solo-project capacity | High/High | Stop first release at Sprint 9; vertical slices; sprint gates | Owner/Open |
| R-02 | Dataset leakage inflates results | High/High | Source/time-aware splits; feature ban list; independent review | ML/Open |
| R-03 | Public dataset fails to represent real traffic | High/High | Honest limitations; second-source validation; no enterprise claims | ML/Open |
| R-04 | False positives make dashboard unusable | High/High | Rule tests, calibration, suppression, analyst feedback | Detection/Open |
| R-05 | Parser/upload creates security or availability issue | Medium/Critical | Isolation and hard resource limits; fuzzing | Security/Open |
| R-06 | Artifact serialization enables code execution | Medium/Critical | Safe-format policy, integrity/provenance, controlled registry | Security/Open |
| R-07 | RBAC error exposes sensitive actions/data | Medium/High | Central policy and full negative matrix | Security/Open |
| R-08 | Simulation accidentally gains real capability | Low/Critical | No adapter/capability/privilege; OS-state E2E assertion | Architecture/Open |
| R-09 | Duplicate/replayed jobs corrupt state | High/High | Idempotency, unique constraints, locking, replay tests | Backend/Open |
| R-10 | Sensitive telemetry leaks through logs/reports/demo | Medium/High | Metadata minimization, redaction, review, export audit | Privacy/Open |
| R-11 | Supply-chain compromise | Medium/Critical | Pinning, scanning, provenance, least-privilege CI | DevSecOps/Open |
| R-12 | Local machine cannot support planned stack | Low/Medium for foundation; rises with ML/monitoring | Minimal stack verified on approved host; profile and stage optional services | Owner/Monitored |
| R-13 | Architecture docs diverge from implementation | Medium/High | Traceability, ADRs, PR doc checks, sprint reviews | Lead/Open |
| R-14 | Unsupported performance claims harm credibility | Medium/High | Representative benchmarks and explicit environment | QA/Open |
| R-15 | License prevents distribution of data/model | Medium/High | Academic-only intent recorded; no dataset redistribution; recheck before acquisition/publication | Owner/Controlled for Sprint 0 |
| R-16 | Cookie session/CSRF configuration allows cross-origin state changes | Medium/High | Secure attributes, rotation, token+Origin validation, exact CORS, tests | Security/Open |
| R-17 | Celery unsafe serialization or broker exposure compromises worker | Medium/Critical | JSON-only serializers and private Redis implemented; add task allowlist/envelope limits with real tasks | Backend/Partially controlled |

Critical/High residual risk requires explicit acceptance with owner, due date, evidence, and review date.
