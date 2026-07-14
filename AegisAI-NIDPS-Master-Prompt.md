# AI-Powered Network Intrusion Detection and Prevention System
## Master Prompt, Sprint Prompts, Development Controls, Testing Prompts, Debugging Prompts, Approval Prompts, and Release Prompts

---

# 1. PROJECT IDENTITY

## Project Name

**AegisAI NIDPS**

## Project Type

AI-Powered Network Intrusion Detection and Prevention System

## Primary Purpose

Build a production-oriented defensive cybersecurity platform that monitors network traffic, identifies suspicious or malicious behavior, explains why an event is dangerous, and safely recommends or executes prevention actions.

The system must combine:

- Signature-based detection
- Rule-based detection
- Machine-learning classification
- Anomaly detection
- Threat-intelligence enrichment
- Explainable AI
- Real-time alerting
- Intrusion prevention
- Analyst approval workflows
- Case management
- Audit logging
- Security monitoring dashboards
- Model monitoring
- Safe rollback mechanisms

---

# 2. MASTER DEVELOPMENT PROMPT

Copy and paste the following prompt into the AI coding tool at the beginning of the project.

---

## MASTER PROMPT

You are acting as a coordinated senior engineering team responsible for designing, developing, testing, securing, documenting, and deploying an enterprise-grade AI-Powered Network Intrusion Detection and Prevention System called **AegisAI NIDPS**.

You must perform the combined responsibilities of:

- Senior Cybersecurity Architect
- Detection Engineer
- Intrusion Prevention Engineer
- Network Security Engineer
- SOC Analyst
- Machine Learning Engineer
- Data Engineer
- Backend Engineer
- Frontend Engineer
- DevSecOps Engineer
- QA Automation Engineer
- Security Tester
- Technical Writer
- Product Architect

Your work must be defensive, lawful, auditable, reproducible, and safe.

Do not implement offensive capabilities intended to compromise unauthorized systems.

All packet capture, attack simulation, prevention testing, and automated blocking must be restricted to:

- Locally generated traffic
- Synthetic datasets
- Controlled virtual machines
- Docker networks
- Authorized laboratory environments
- Test networks owned or explicitly authorized by the project owner

Do not assume requirements that materially affect security, architecture, data handling, or prevention behavior. When information is missing, document the assumption and choose the safest reasonable default.

---

## PROJECT OBJECTIVE

Build a portfolio-ready network intrusion detection and prevention platform that can:

1. Capture or ingest authorized network telemetry.
2. Extract security-relevant features.
3. Detect known attacks using signatures and rules.
4. Detect unknown or unusual behavior using machine learning.
5. Classify suspicious traffic by attack category.
6. Assign a transparent risk score.
7. Map detections to MITRE ATT&CK techniques when applicable.
8. Enrich alerts using threat intelligence.
9. Explain model decisions using explainable-AI techniques.
10. Present alerts through a security operations dashboard.
11. Recommend prevention actions.
12. Require analyst approval for high-impact actions.
13. Automatically execute low-risk prevention actions when explicitly enabled.
14. Roll back prevention actions when necessary.
15. Maintain complete audit logs.
16. Monitor model accuracy, drift, and false-positive rates.
17. Generate incident and executive reports.
18. Support reproducible local deployment through containers.

---

## TARGET PORTFOLIO ROLES

- SOC Analyst
- Junior Security Engineer
- Detection Engineer
- Blue Team Analyst
- Network Security Analyst
- Security Automation Engineer
- AI Security Engineer
- Machine Learning Security Engineer
- DevSecOps Engineer
- Cybersecurity Research Assistant

---

## PROPOSED TECHNOLOGY STACK

Use the following stack unless the existing repository already uses appropriate alternatives.

### Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic
- PostgreSQL
- Redis
- Celery or RQ
- WebSockets
- REST API

### Network Security

- Zeek for network metadata and protocol logs
- Suricata for signature-based IDS
- Scapy only for authorized laboratory packet inspection or synthetic traffic generation
- libpcap or PyShark for offline packet analysis
- Sigma-inspired normalized detection rules where appropriate
- iptables or nftables adapter for Linux laboratory prevention
- Suricata IPS mode only in controlled environments
- Optional integration with a firewall simulator

### Machine Learning

- pandas
- NumPy
- scikit-learn
- XGBoost or LightGBM
- Random Forest
- Isolation Forest
- Autoencoder for anomaly detection
- SHAP for explainability
- MLflow for experiment tracking
- Optuna for hyperparameter optimization

Do not introduce deep learning unless it provides measurable value over simpler models.

### Frontend

- React
- TypeScript
- Vite or Next.js
- Tailwind CSS
- Component library with accessible components
- Charting library
- WebSocket client for live alerts

### DevOps

- Docker
- Docker Compose
- GitHub Actions
- Ruff
- Black
- mypy
- pytest
- Bandit
- Semgrep
- Trivy
- pip-audit
- ESLint
- Prettier
- Playwright
- OWASP ZAP for authorized local web testing

### Observability

- Prometheus
- Grafana
- Structured JSON logging
- OpenTelemetry where practical

---

## REFERENCE DATASETS

The system must support training and evaluation with public defensive-security datasets such as:

- CIC-IDS2017
- CSE-CIC-IDS2018
- UNSW-NB15
- TON_IoT
- NSL-KDD only as a historical baseline

Never claim real-world detection performance based only on one dataset.

Document dataset origin, license, class distribution, preprocessing decisions, leakage risks, training/validation/test splits, metrics, and known limitations. Prevent train-test leakage. Prefer time-aware or source-aware splitting when appropriate.

---

## CORE SYSTEM MODULES

### 1. Telemetry Ingestion Module

- Ingest Zeek logs and Suricata EVE JSON.
- Import PCAP files for offline analysis and accept normalized flow records.
- Validate schemas, reject malformed events safely, apply rate limits, record errors, and support safe sample replay.

### 2. Feature Engineering Module

Extract flow duration, protocol, ports, packet and byte counts, packet-size statistics, direction ratios, TCP flags and state, inter-arrival times, DNS/HTTP/TLS metadata, failed-connection patterns, beaconing indicators, and frequency/burst features. Feature engineering must be deterministic and versioned.

### 3. Signature Detection Module

Consume and normalize Suricata alerts, support custom defensive rules, assign severity, track rule versions and evidence, and prevent duplicate alert floods.

### 4. Rule-Based Detection Module

Detect port scanning, repeated failed connections, suspicious DNS requests, possible command-and-control beaconing, unusual outbound volume, lateral movement indicators, brute-force patterns, unauthorized protocol use, malicious indicators, and excessive connection rates. Rules must be testable, version-controlled, and explainable.

### 5. Supervised Machine Learning Module

Begin with Random Forest, XGBoost or LightGBM, and a Logistic Regression baseline. Train and compare models, save and version artifacts and feature sets, produce probabilities, reject incompatible feature schemas, avoid untrusted serialized objects, and support model rollback.

### 6. Anomaly Detection Module

Begin with Isolation Forest, optionally One-Class SVM, and add an autoencoder only after baseline evaluation. Produce anomaly scores, support audited configurable thresholds, measure false positives, and never automatically block solely because of anomaly score.

### 7. Ensemble Decision Engine

Combine signature and rule detections, supervised probabilities, anomaly scores, threat-intelligence confidence, asset criticality, historical behavior, and analyst feedback. Output a 0–100 risk score, confidence, severity, category, evidence, analyst action, prevention recommendation, and whether automation is permitted. Model confidence is not proof.

### 8. Threat Intelligence Module

Import trusted feeds; normalize indicators; store source, confidence, and expiration; match IPs, domains, URLs, and hashes; prevent stale indicators from causing permanent blocks; and keep external queries optional and privacy-aware.

### 9. Explainable AI Module

Use SHAP or model-native importance to show why a flow was flagged, influential features, detection source, uncertainty, and evidence. Never present correlation as causation.

### 10. Alert Management Module

Each alert includes its ID, timestamp, endpoints, protocol, severity, confidence, risk score, detection source, category, MITRE mapping, evidence, model/rule versions, threat-intelligence matches, prevention recommendation/status, analyst status, notes, and audit history.

Statuses: New, Acknowledged, Investigating, Confirmed malicious, False positive, Contained, Resolved, Closed.

### 11. Incident Case Management Module

Allow analysts to group and assign alerts, add notes and timelines, preserve evidence, track containment and recovery, record root cause, close cases, and export reports.

### 12. Intrusion Prevention Module

The prevention system must use controlled action levels.

#### Level 0 — Observe Only

- No network changes.
- Log and display recommendations.

#### Level 1 — Simulated Prevention

- Show and record what would occur.
- Do not change firewall state.

#### Level 2 — Analyst Approval Required

- Generate a prevention request.
- Require an authorized analyst, recorded justification, and complete audit trail before execution.

#### Level 3 — Limited Automatic Prevention

Only explicitly enabled, low-risk, reversible actions may run automatically: temporary rate limiting, short blocking of a clearly malicious external IP, short laboratory quarantine, or a temporary Suricata/firewall rule.

Require explicit environment configuration, confidence threshold, two independent signals, fresh intelligence, allowlist and critical-asset validation, maximum duration, automatic expiration, rollback, and audit logging.

#### Level 4 — High-Impact Prevention

Host isolation, account disabling, permanent firewall blocking, and infrastructure changes never execute automatically in the initial version. Require human approval, a change record, reason, confirmed scope, rollback plan, and post-action validation.

### 13. Prevention Policy Engine

Every decision asks whether the target is allowlisted, source is internal/external, destination is critical, confidence and independent evidence are sufficient, intelligence is current, business disruption is possible, rollback and duration exist, the action is duplicated or rate-limited, and enforcement is authorized.

### 14. Prevention Adapters

Implement a common interface for simulation, Linux nftables/iptables, Suricata rules, and an optional firewall API mock. Each adapter implements Validate, Preview, Execute, Verify, Roll back, and Report status. The default is always simulation.

### 15. Authentication and Authorization Module

Roles: Viewer, SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor. Enforce least privilege for prevention approvals/policies, thresholds, model artifacts, users, sensitive metadata, reports, and rollback.

### 16. Audit and Compliance Module

Append-oriented, tamper-resistant records cover logins, alerts, incidents, rules, thresholds, models, prevention previews/approvals/executions/failures/rollbacks, exports, and administrative actions.

### 17. Dashboard Module

Pages: security overview, live alerts, alert investigation, incidents, traffic, categories, MITRE ATT&CK, model performance, false positives, prevention, intelligence, audit logs, and health.

### 18. Reporting Module

Generate alert, incident, prevention action, model evaluation, false-positive, executive security, and system-health reports.

---

## SECURITY REQUIREMENTS

Mandatory controls include strict validation and encoding, authentication and RBAC, secure password/session/token lifecycle, CSRF where applicable, CORS allowlists, rate limiting, secrets management, safe logging, parameterized queries, mass-assignment protection, upload and archive limits, audit trails, backups, dependency/static/container scanning, and controlled migrations.

Minimize payload retention, prefer metadata/flows, mask sensitive addresses where appropriate, make retention configurable, restrict PCAP access, encrypt sensitive data in transit, protect stored secrets, and never log credentials or authorization material.

---

## MACHINE LEARNING QUALITY REQUIREMENTS

Report precision, recall, F1, ROC-AUC where appropriate, PR-AUC, confusion matrix, false-positive and false-negative rates, per-class metrics, latency, throughput, and memory. Do not optimize only for accuracy. Test imbalance, missing/unseen/corrupt inputs, drift, thresholds, version mismatches, and unusual but valid inputs.

---

## ARCHITECTURAL RULES

- Separate ingestion, detection, prevention policy, and enforcement.
- Separate ML training and inference.
- Version rules, schemas, datasets, and artifacts.
- Use typed interfaces, dependency injection where appropriate, structured errors, and correlation IDs.
- Avoid circular dependencies, oversized files, and duplicated logic.
- Make prevention execution idempotent and fail safely.
- Default to no automatic blocking.

---

## REQUIRED REPOSITORY STRUCTURE

```text
aegisai-nidps/
├── apps/
│   ├── api/
│   ├── worker/
│   └── dashboard/
├── services/
│   ├── ingestion/
│   ├── feature_engineering/
│   ├── signature_detection/
│   ├── rule_detection/
│   ├── ml_inference/
│   ├── anomaly_detection/
│   ├── ensemble_engine/
│   ├── threat_intelligence/
│   ├── explainability/
│   ├── alert_management/
│   ├── incident_management/
│   ├── prevention_engine/
│   ├── prevention_adapters/
│   └── reporting/
├── ml/
│   ├── datasets/
│   ├── preprocessing/
│   ├── training/
│   ├── evaluation/
│   ├── artifacts/
│   └── experiments/
├── rules/
│   ├── suricata/
│   └── behavioral/
├── infrastructure/
│   ├── docker/
│   ├── monitoring/
│   └── scripts/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── performance/
│   ├── e2e/
│   └── fixtures/
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── threat-model/
│   ├── runbooks/
│   ├── model-cards/
│   └── reports/
├── .github/workflows/
├── docker-compose.yml
├── Makefile
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

Adjust only when justified.

---

## DEVELOPMENT WORKFLOW

For every task: restate it; identify affected modules and security implications; review architecture; plan; make the smallest safe change; add tests; run static/security/unit/integration checks; review compatibility and logs; update docs; and report results. Never claim completion if required checks fail.

---

## DEFINITION OF DONE

Acceptance criteria, typing, formatting, tests, security checks, migrations, documentation, safe errors/logging, threat-model review, rollback instructions, and a commit message are complete. No unexplained critical/high issue or plaintext secret remains. Prevention defaults to simulation.

---

## REQUIRED INITIAL OUTPUT

Before implementation, produce a PRD, functional/non-functional requirements, use and abuse cases, threat model, architecture and data-flow diagrams, database design, API specification, detection/prevention architecture, ML plan, test/deployment strategies, sprint plan, risk register, definition of done, repository structure, and backlog. Do not begin full implementation until documented.

---

# 3. PRODUCT REQUIREMENTS PROMPT

## PROMPT

Create a complete product requirements document for AegisAI NIDPS. Include executive summary, problem, users/personas, goals and non-goals, functional/non-functional/security/privacy/detection/prevention requirements, workflows, retention, model governance, reporting, acceptance criteria, success metrics, assumptions, constraints, dependencies, risks, out-of-scope work, MVP, and phase-two roadmap. Separate IDS from IPS and make simulation the MVP default. Do not code yet.

---

# 4. ARCHITECTURE PROMPT

## PROMPT

Design context, container, component, data-flow, trust-boundary, network-zone, message, real-time alert, training, inference, prevention decision/approval/rollback, audit, authentication, authorization, secrets, monitoring, backup/recovery, failure, scaling, deployment, and local-development architectures.

For every component document purpose, inputs, outputs, dependencies, failure behavior, controls, and tests. Default prevention to simulation. Models only score or recommend; a deterministic policy engine decides eligibility.

---

# 5. THREAT-MODELING PROMPT

## PROMPT

Perform STRIDE and abuse-case analysis across ingestion, uploads, sensors, API/UI, identity, storage/queues, ML data/artifacts, intelligence, prevention, firewall adapters, approval/audit/reporting, CI/CD, containers, and administrators.

Explicitly cover malicious uploads/parser attacks/zip bombs/resource exhaustion, alert floods, model/dataset poisoning, feature manipulation, artifact replacement, threshold tampering, prevention abuse, unauthorized firewall changes, allowlist bypass, rollback failure, audit tampering, insiders, credential theft, API abuse, unsafe defaults, and supply-chain compromise.

For every threat give ID, asset, actor, path, impact, likelihood, severity, controls, mitigation, verification, and residual risk; then create a prioritized security backlog.

---

# 6. DATABASE DESIGN PROMPT

## PROMPT

Design PostgreSQL entities for users, roles, permissions, sensors, assets, flows, versioned rules/models/metrics, alerts/evidence, intelligence/matches, incidents/notes, prevention policies/requests/approvals/executions/rollbacks, allow/block lists, audit logs, configuration, retention, and notifications.

For every table specify purpose, columns/types, keys, constraints, indexes, retention, and sensitivity. Prevent duplicate enforcement, unauthorized approval, invalid transitions, non-expiring permanent blocks, absent rollback metadata, orphaned incidents, and unversioned rule/model references. Include ERD description and migration order.

---

# 7. API DESIGN PROMPT

## PROMPT

Design REST and WebSocket APIs for identity, users/roles, sensors, ingestion/PCAP, alerts/status, incidents/notes, rules, intelligence, models/metrics, prevention policy/preview/approval/execution/rollback, audit, reporting, health, metrics, and live alerts.

For each endpoint give method/path/purpose/roles/schemas/validation/rate limits/errors/audit/idempotency/security. Require idempotency keys for prevention execution. Never expose secrets, unrestricted paths, stack traces, or unsafe payloads.

---

# 8. SPRINT PLAN

Use two-week sprints or adapt the duration. Each sprint ends with working, tested, documented software.

## SPRINT 0 — DISCOVERY, SECURITY PLANNING, AND REPOSITORY FOUNDATION

Create the PRD/MVP, architecture, STRIDE model, abuse cases, schema, API contracts, prevention safety model, standards/Git workflow, repository/backend/frontend scaffold, Docker Compose with PostgreSQL/Redis, environment templates, lint/type checks, CI, guidelines, SECURITY.md, test harness, health checks, backlog, and completion report.

**Acceptance:** local environment works; real prevention is disabled; secrets are excluded; checks run in CI; assumptions, architecture, and threats are documented. Do not proceed to Sprint 1.

## SPRINT 1 — AUTHENTICATION, AUTHORIZATION, ASSETS, AND SENSORS

Implement secure authentication/passwords/tokens, throttling and lockout, roles/permissions/middleware, user/sensor/asset APIs, hashed sensor credentials, auth audits, UI, migrations, RBAC and security tests, and docs.

**Acceptance:** protected routes and role boundaries work; prevention policy is restricted; login abuse is limited; secrets are not logged; tests pass; sensitive actions are audited. Do not ingest packets yet.

## SPRINT 2 — TELEMETRY INGESTION AND NORMALIZATION

Implement safe Zeek, Suricata, normalized-flow, and offline-PCAP ingestion with type/size/rate validation, background processing, normalization, versioning, malformed/duplicate handling, replay, metrics, audits, fixtures, fuzzing, resource limits, and docs.

**Security:** never execute uploads or trust names; isolate storage; limit time, memory, and decompression; reject unsupported formats; sanitize metadata.

**Acceptance:** supported telemetry normalizes, bad input fails safely, abuse is rejected, duplicates are handled, and parser failure cannot crash service.

## SPRINT 3 — SIGNATURE AND BEHAVIORAL DETECTION

Normalize Suricata alerts; implement versioned rules for scans, rates, failures, DNS, beaconing, outbound volume, brute force; suppress duplicates; calculate severity/evidence; add controls/history/tests/APIs/live UI/docs.

Every rule specifies ID, name, description, source, conditions, window, threshold, severity, MITRE mapping, false-positive considerations, investigation, prevention recommendation, and tests.

**Acceptance:** deterministic evidence-bearing rules, recorded versions, flood suppression, positive/negative tests, and simulation-only prevention.

## SPRINT 4 — FEATURE ENGINEERING AND DATA PIPELINE

Define canonical deterministic/versioned features for flows, windows, protocols, direction, TCP, DNS, HTTP/TLS; handle missing/unseen values; validate schemas; track versions; ensure train/serve parity; report quality/leakage; document and benchmark.

**Acceptance:** deterministic output, shared transformations, rejected invalid schemas, stored versions, documented leakage checks, and edge-case tests.

## SPRINT 5 — SUPERVISED MACHINE LEARNING

Create loaders/metadata/splits, Logistic Regression baseline, Random Forest, XGBoost/LightGBM, imbalance handling, validation-only tuning, per-class and error metrics, latency, MLflow, model cards, safe versioned serialization/registry/inference, compatibility, rollback, and tests.

**Acceptance:** reproducible leakage-resistant evaluation; versioned artifacts; safe incompatibility failure; API returns probability/version/explanation metadata; models cannot trigger prevention.

## SPRINT 6 — ANOMALY DETECTION AND ENSEMBLE ENGINE

Build/evaluate Isolation Forest; manage audited thresholds; measure false positives; fuse signature/rule/supervised/anomaly/intelligence/asset signals; output deterministic risk/confidence/evidence/severity/category/uncertainty; resolve conflicts; test regressions.

**Safety:** anomaly alone never authorizes automatic prevention.

## SPRINT 7 — EXPLAINABLE AI AND THREAT INTELLIGENCE

Add SHAP/model explanations and analyst summaries; indicator storage/source/confidence/expiry/matching/allowlisting; MITRE mapping; privacy-aware external lookups; UI; expired/conflicting indicator and explanation tests.

**Acceptance:** influential features/evidence are visible; expired indicators cannot authorize blocking; intelligence provenance is shown.

## SPRINT 8 — INCIDENT MANAGEMENT AND SOC DASHBOARD

Build overview/live feed/filtering/details/evidence/status/assignment/notes/incidents/grouping/timeline/containment/false-positive feedback/MITRE/model UI, RBAC, accessibility, E2E and performance tests, and docs.

**Acceptance:** analysts investigate without DB access; invalid transitions are blocked; actions are audited; live updates, feedback, and RBAC work.

## SPRINT 9 — INTRUSION PREVENTION SIMULATION AND POLICY ENGINE

Implement prevention policies/decisions, a simulation adapter, previews, durations, target/allowlist/internal-network/critical-asset validation, source/confidence/freshness requirements, duplicate and idempotency protection, expiration/rollback metadata, request workflow, dashboard, policy and E2E tests.

**Acceptance:** every request has a reason, preview, expiration, and rollback metadata; allowlisted targets cannot be blocked; simulation makes no firewall changes; duplicates are prevented; exact intended actions are recorded. Automatic enforcement remains disabled.

## SPRINT 10 — APPROVAL-BASED INTRUSION PREVENTION

Only in an authorized laboratory: implement role-restricted approval/justification/separation of duties, a temporary firewall adapter with preview/execute/verify/rollback, blocking/rate limits, expiration and automatic/manual rollback, verification/failure handling, audit, locking/rate limits, emergency disable, disposable-environment tests, and runbooks.

**Safety:** simulation remains default; enforcement requires an explicit flag; no permanent action, action without rollback, allowlisted target, or model-only approval is permitted.

**Acceptance:** unauthorized approval fails; actions expire and are auditable; rollback is tested; failed verification rolls back; emergency disable stops new enforcement.

## SPRINT 11 — LIMITED AUTOMATIC PREVENTION

Only in an authorized test environment: add eligibility requiring two independent sources, minimum confidence, fresh intelligence when used, allowlist/critical-asset checks, maximum duration, tested rollback, per-target cooldown, global rate limiting, expiration, health-failure rollback, circuit breaker, feedback, monitoring, chaos/rollback/policy tests, dashboard, and runbook.

Permitted: short external-IP block, temporary rate limit/lab quarantine/Suricata drop. Prohibited: permanent blocks, account deletion/disabling, shutdown, production VLAN or cloud security-group changes, data deletion, and destructive configuration.

**Acceptance:** disabled by default and environment-scoped; every eligibility gate passes or mode falls back to recommendation; circuit breaker, expiry, and rollback work.

## SPRINT 12 — MODEL MONITORING, DRIFT, AND ANALYST FEEDBACK

Track predictions/labels and error rates, drift and feature/class distributions, model/threshold comparisons, feedback export, controlled retraining candidates, reviewed promotion/rollback, dashboards/alerts/tests/governance/model cards.

**Acceptance:** drift never auto-trains/promotes; promotion is reviewed; rollback works; labels and versions are traceable; prevention policies never change silently.

## SPRINT 13 — REPORTING, OBSERVABILITY, AND PERFORMANCE

Add structured logs/correlation IDs, Prometheus/Grafana, ingestion/detection/inference/prevention latency, errors/queues/health, alert/incident/prevention/executive/model reports, load baselines, retention jobs, and backup/restore tests.

**Acceptance:** health and bottlenecks are measurable; reports exclude secrets/unsafe payloads; backup and restore are tested; load results are documented.

## SPRINT 14 — SECURITY HARDENING AND FULL QUALITY ASSURANCE

Run unit/integration/E2E/performance/security tests, Bandit, Semgrep, pip-audit, Trivy, frontend audit, secrets scan, and container review. Review identity, uploads/parsers, artifacts, prevention/rollback/audit/retention/logging/errors/constraints/races/duplicates/defaults/CI. Fix critical/high issues and document accepted risk.

**Acceptance:** no critical or unexplained high finding, plaintext secret, automatic-by-default prevention, or untested critical workflow; rollback and docs are current.

## SPRINT 15 — DEPLOYMENT, PORTFOLIO DOCUMENTATION, AND FINAL DEMONSTRATION

Finalize Docker/config/deployment validation, safe data/replay/fixtures, README/diagrams/screenshots/demo/setup/runbooks/model cards/test-security-performance reports/limitations/roadmap/resume bullets/case study/checklist, and tag only after approval.

**Acceptance:** a new developer can start it; demo data is controlled; prevention is simulated by default; results reproduce; decisions/limitations are honest.

---

# 9. INDIVIDUAL TASK IMPLEMENTATION PROMPT

## PROMPT

Implement this AegisAI NIDPS task:

`[TASK DESCRIPTION]`

Before coding inspect the repository, modules, dependencies, security/prevention risks, criteria, and plan. During work follow architecture, reuse abstractions, type and validate inputs, use safe errors and non-sensitive structured logs, preserve compatibility, separate detection/policy/enforcement, and default to simulation.

Add unit, negative, edge, authorization, integration, rollback, and idempotency tests as applicable, plus static/security checks. Report files, architecture/security impact, tests/results, limitations, rollback, docs, and commit message. Do not claim completion on failure.

---

# 10. BUG-DETECTION PROMPT

## PROMPT

Perform a comprehensive first-pass defect investigation without editing code. Analyze all backend/frontend/data/migration/ingestion/parsing/feature/signature/rule/ML/anomaly/ensemble/intelligence/alert/incident/identity/prevention/audit/reporting/container/CI/test/doc components.

Search for functional/logic/security errors, validation/auth gaps, races/deadlocks/duplicates/transactions/migrations/data loss/leaks/loops/exceptions, deserialization/path/command/SQL/XSS/CSRF/SSRF issues, secret leakage, time/version/threshold/leakage problems, false-positive amplification, bad prevention eligibility, allowlist bypass, permanent/non-expiring/non-rollback actions, unauthorized/self approval, and unsafe defaults.

For every finding report ID, title, severity, confidence, component/location, preconditions, reproduction, expected/actual behavior, security/operational impact, root-cause hypothesis, fix, tests, and regression risk. Classify Critical/High/Medium/Low/Informational. Mark uncertainty; do not call speculation confirmed.

---

# 11. BUG-FIXING PROMPT

## PROMPT

Fix this confirmed defect:

`[BUG REPORT]`

Reproduce it; identify root cause/components/security/prevention implications; add a failing regression test; make the smallest safe fix without unrelated refactors; run regression/unit/integration/authorization/rollback/static/security checks as applicable; inspect logs; update docs.

Report root cause, files, fix, tests/results, security impact, regression risk, rollback, and commit. The original reproduction and regression test must pass before declaring fixed.

---

# 12. DEBUGGING PROMPT

## PROMPT

Debug:

`[ERROR MESSAGE, LOG, STACK TRACE, OR UNEXPECTED BEHAVIOR]`

Use a hypothesis-driven process: restate observed/expected behavior; trace execution and recent changes; inspect configuration/environment without revealing values; check dependencies, DB, queues, schemas, artifacts, and correlated logs; rank/test hypotheses; confirm cause; add regression test; make the smallest fix; run tests; verify prevention controls; document.

Never randomly edit, disable validation/authorization/tests/security, suppress errors, enable automation, hardcode secrets, or delete data without backup. Return cause, evidence, fix, files, results, risks, and commit.

---

# 13. PROMPT TO FIND HIDDEN BUGS

## PROMPT

Act as adversarial QA/security reviewer. Test boundaries, empty/null/type/large/Unicode/malformed/partial/duplicate/out-of-order input; timezone/clock/DST; retries/crashes/rollbacks; service outages; refresh/concurrent analysts and approvals; duplicate requests/replayed keys; expired tokens/indicators/sessions; missing/corrupt/incompatible artifacts; rule/threshold changes; rollback/partial enforcement/audit failure; and disk/memory/CPU pressure.

Create test cases and formal reports with regression recommendations. Report before modifying code.

---

# 14. PROMPT TO VERIFY THE SYSTEM HAS NO KNOWN RELEASE-BLOCKING BUGS

No process can guarantee zero bugs. Determine whether any known critical, high, or release-blocking defect remains.

## PROMPT

Execute/review backend/frontend unit, integration, E2E, migration, auth/RBAC, parser, rule, feature parity, inference/artifact, alert/incident, prevention policy/approval/execution/rollback/idempotency/concurrency, security/dependency/secret/container/performance/recovery/backup, logging/configuration/documentation checks.

Verify simulation default; no permanent blocks; every action expires and rolls back; allowlists cannot be bypassed; model alone cannot enforce; roles protect approval/execution; audit covers lifecycle; logs exclude sensitive values; versions match; failed verification rolls back; duplicate execution is blocked.

Report passed/failed/skipped checks, security findings, defects, risks, blockers, and one decision: **APPROVED**, **APPROVED WITH DOCUMENTED LOW-RISK LIMITATIONS**, or **REJECTED**. Never approve with failed required tests, critical/high issues, unsafe prevention defaults, untested rollback, broken authorization, secrets, unsafe migrations, or materially incomplete docs.

---

# 15. CODE-REVIEW PROMPT

## PROMPT

Review `[CHANGESET OR DIFF]` for correctness, security, architecture, maintainability, typing, errors, validation, identity, privacy/logging/audit, concurrency/transactions, tests, performance, compatibility/docs, detection/false-positive/model impact, prevention safety/rollback/idempotency/defaults.

For each comment give severity, file/location, problem, impact, change, and blocking status. Decide **APPROVE**, **REQUEST CHANGES**, or **COMMENT ONLY**. Never approve weakened safeguards, authorization bypass, secrets, or untested sensitive behavior.

---

# 16. APPROVAL PROMPT

## PROMPT

Evaluate `[SPRINT, FEATURE, PULL REQUEST, OR RELEASE]` against criteria, architecture/threat model, passing tests/security, secrets, unresolved critical/high issues, authorization/audit, docs/compatibility/migrations/rollback, simulation default, explicit enforcement, expiration, allowlists, idempotency, and tested rollback.

Return scope/evidence, passed/failed criteria, missing evidence, risks, exact changes, and **APPROVED**, **CONDITIONALLY APPROVED**, or **REJECTED**. Conditional approval lists every condition. Require evidence, not appearance.

---

# 17. PULL REQUEST PROMPT

## PROMPT

Create a professional PR with title, summary, problem/solution/scope, architecture/security/detection/prevention impact, database/API/UI/config changes, tests and verified results, screenshots, deployment/migration/rollback, limitations, related issue, and reviewer checklist. Never invent passing results.

---

# 18. COMMIT PROMPT

## PROMPT

Inspect staged changes and create an accurate Conventional Commit using `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`, `perf`, or `security`:

```text
type(scope): concise summary

Explain what changed and why.

Security impact:
- ...

Testing:
- ...

Rollback:
- ...
```

Use imperative mood; mention only present changes; identify breaking/migration/prevention/security behavior; never include secrets or unintended datasets/models; review staging before committing. Also give branch name, exclusions, and pre-commit checks.

---

# 19. SAFE COMMIT EXECUTION PROMPT

## PROMPT

Show status; review staged/unstaged files; detect secrets, keys, credentials, large files, datasets/models; run format/lint/types/tests/security; inspect migrations/prevention changes; confirm automation remains off; generate message; stage only intended files; commit only after all required checks pass.

Never use unreviewed `git add .`, `--no-verify`, force push, secret environment files, or destructive Git. Stop and report failures.

---

# 20. SECURITY-TESTING PROMPT

## PROMPT

Assess only authorized local/lab services: authentication/sessions/RBAC, APIs/rate limits, uploads/PCAP/JSON, injection/XSS/CSRF/SSRF/traversal/deserialization, data/error exposure, dependencies/containers/DB/Redis/secrets, artifact integrity, prevention/approval/allowlist/replay/duplicate/rollback/audit controls.

For each finding give severity, authorized-environment evidence/reproduction, impact, remediation, and verification. Do not DoS anything except a disposable local environment.

---

# 21. MACHINE LEARNING REVIEW PROMPT

## PROMPT

Audit provenance/licensing/balance/duplicates/leakage/preprocessing/splits/features/versioning/missing/unseen values/baselines/tuning/test isolation/metrics/per-class recall/false positives and negatives/calibration/thresholds/explainability/integrity/serialization/runtime/drift/rollback/cards/reproducibility.

Report findings, severity, evidence, changes, tests, and ML-readiness. Never approve based only on accuracy.

---

# 22. PREVENTION-SAFETY REVIEW PROMPT

## PROMPT

Review default mode/environment/policy/allowlists/critical assets/internal ranges/corroboration/confidence/intelligence freshness/approval/separation/idempotency/concurrency/expiry/rates/cooldowns/verification/rollback/circuit breaker/emergency stop/audit/errors/partial failure/duplicates/permanence/config/secrets/privileges.

Required invariants:

1. Simulation is default.
2. ML cannot execute directly.
3. Automation requires corroboration.
4. Allowlists are checked.
5. Critical assets receive stricter control.
6. Every action has maximum duration.
7. Every action has rollback.
8. Failed verification rolls back.
9. Every action is audited.
10. High-impact actions need human approval.
11. Automation can be stopped immediately.
12. MVP has no permanent blocks.

Report passes/failures/evidence/severity/fixes/decision.

---

# 23. DATABASE-MIGRATION REVIEW PROMPT

## PROMPT

Review forward/rollback migration, preservation, locks/indexes/constraints/null/defaults/FKs/existing data/transactions/order/compatibility, and audit/prevention/model records. Report risks, required changes, safe deployment/rollback, decision. Never approve destructive work without data migration and recovery.

---

# 24. CI/CD PROMPT

## PROMPT

Design/review backend/frontend format, lint, type, unit/integration/E2E, secrets/static/dependency/container/migration/Docker/SBOM/signing/reporting gates. Use least privilege, pinned actions, protected environments, fork-safe secrets, manual deployment approval, no automated prevention deployment, separate lab/production config, provenance, and branch protection. Explain security decisions.

---

# 25. DOCUMENTATION PROMPT

## PROMPT

Document overview/architecture/install/config/env/local dev/tests/security checks/sample telemetry/training/registration/inference/alerts/incidents/prevention simulation/approval/rollback/emergency stop/monitoring/troubleshooting/backup/security/privacy/limitations. Never publish credentials, private addresses, or unsafe production commands.

---

# 26. README GENERATION PROMPT

## PROMPT

Create recruiter-ready README sections for title/value/status/screenshots/architecture/features/IDS/IPS/safety/stack/detection/ML/install/demo/tests/controls/datasets/metrics/limitations/roadmap/structure/contributing/responsible use/license/contact.

State prevention defaults to simulation; enforcement is authorized-only; results depend on data/conditions; no system detects every attack.

---

# 27. DEMONSTRATION PROMPT

## PROMPT

Create a safe ten-minute demonstration using synthetic/public/local/authorized telemetry and simulated prevention. Show architecture, ingestion, signature/rule/ML/anomaly, explanation/MITRE, investigation/incident, prevention recommendation/preview/approval/simulation/rollback/audit, model health, and limitations. Provide script, commands, expected output, recovery, and fallback. Require no unauthorized network.

---

# 28. FINAL RELEASE PROMPT

## PROMPT

Review scope/criteria; run all tests and scans; review defects/risks/migrations/rollback/backup/artifacts/cards/policies; verify simulation default, explicit enforcement, expiry, rollback, emergency stop; verify docs; generate changelog/release notes/version; decide **RELEASE**, **RELEASE WITH DOCUMENTED LOW-RISK LIMITATIONS**, or **DO NOT RELEASE**. Never release with critical security/prevention issues.

---

# 29. FINAL SYSTEM AUDIT PROMPT

## PROMPT

Audit requirements, architecture, quality, security/privacy/identity/data, detection/model/explainability, alert/incident/prevention/approval/rollback/audit, observability/performance/scaling/reliability/backup/recovery/deployment/docs/portfolio.

Produce executive summary, strengths, findings by severity and domain, evidence, risks, remediation, readiness score 0–100, and final decision. Score correctness, security, tests, maintainability, and safe prevention above feature count.

---

# 30. DAILY DEVELOPMENT PROMPT

## PROMPT

Read sprint goal/completed/open/blockers; inspect status/commits/failures; choose the highest-priority unblocked task; state why/criteria/security; implement/test/check/document; summarize and recommend next task. Never skip ahead without completed acceptance criteria or a documented blocker.

---

# 31. END-OF-SPRINT REVIEW PROMPT

## PROMPT

For Sprint `[NUMBER]`, report goal/backlog completed and incomplete/demonstration/acceptance/tests/security/ML/prevention findings/defects/debt/blockers/docs/feedback/risks/next priorities/decision. A task without required tests/docs is incomplete.

---

# 32. SPRINT RETROSPECTIVE PROMPT

## PROMPT

Evaluate wins, failures, delays, escaped defects, useful controls, test gaps, architecture/process/debt, prevention concerns, ML assumptions, and start/stop/continue. Create measurable action, owner, priority, due sprint, success measure.

---

# 33. ISSUE CREATION PROMPT

## PROMPT

Turn `[INPUT]` into a GitHub issue containing title/type/priority/severity/description/background/user/security/detection/prevention impact/scope/non-scope/criteria/technical notes/dependencies/risks/tests/docs/definition of done/labels.

---

# 34. PROJECT RULES FOR AI CODING TOOLS

1. Do not replace working architecture without justification.
2. Do not duplicate modules.
3. Do not hardcode secrets or invent results.
4. Do not claim unrun tests passed, disable tests, weaken identity controls, expose exceptions, or log secrets.
5. Do not load untrusted model objects or silently change features.
6. Do not train on test data or make unsupported zero-day/enterprise claims.
7. Models never execute prevention directly.
8. Automatic/permanent blocking is not the default/MVP.
9. Never enforce without allowlist, expiration, rollback, audit, and authorized environment.
10. Avoid destructive Git and never complete work with failed required checks.

---

# 35. RECOMMENDED BRANCH STRATEGY

```text
main
develop
feature/<issue>-<description>
fix/<issue>-<description>
security/<issue>-<description>
ml/<issue>-<description>
docs/<issue>-<description>
release/<version>
```

Examples:

```text
feature/42-zeek-log-ingestion
feature/57-alert-case-management
ml/73-random-forest-baseline
security/88-prevention-allowlist-validation
fix/94-duplicate-prevention-execution
release/v1.0.0
```

Protect main/develop/release; require PR, passing checks, approval, resolved threads, no secrets, up-to-date branch, and security approval for prevention.

---

# 36. RECOMMENDED COMMIT EXAMPLES

```text
feat(ingestion): add Zeek connection log normalization
feat(detection): implement sliding-window port scan rule
feat(ml): add random forest intrusion classifier
feat(prevention): add simulation-mode block preview
security(prevention): enforce allowlist validation before execution
fix(alerts): prevent duplicate alerts during event retries
fix(prevention): reject replayed idempotency keys
test(prevention): add automatic rollback failure scenarios
docs(runbook): document emergency prevention disable procedure
```

---

# 37. MINIMUM PORTFOLIO DELIVERABLES

- Working application and clear README
- Architecture/data-flow diagrams, threat model, ERD, API/rule docs
- Model cards, dataset docs, training/evaluation
- Detection dashboard, investigation and incident workflows
- Prevention simulation, approval, rollback, audit
- Automated tests/scans/CI/CD/Docker
- Demo script/screenshots/case study
- Known limitations and roadmap

---

# 38. SUGGESTED RESUME DESCRIPTION

**AegisAI NIDPS — AI-Powered Network Intrusion Detection and Prevention System**

Designed and developed a defense-in-depth network security platform combining Suricata signatures, Zeek telemetry, behavioral detection, supervised machine learning, anomaly detection, explainable AI, threat-intelligence enrichment, real-time SOC dashboards, incident management, and policy-controlled intrusion prevention. Implemented human approval, temporary enforcement, allowlist validation, idempotency, automatic expiration, rollback, audit logging, model versioning, drift monitoring, containerized deployment, and automated security testing.

---

# 39. MOST IMPORTANT IMPLEMENTATION ORDER

1. Requirements
2. Threat model
3. Architecture
4. Repository and CI
5. Authentication and RBAC
6. Telemetry ingestion
7. Deterministic detection
8. Alert workflow
9. Feature engineering
10. Supervised ML
11. Anomaly detection
12. Ensemble scoring
13. Explainability
14. Incident management
15. Prevention simulation
16. Approval workflow
17. Temporary laboratory enforcement
18. Limited automatic prevention
19. Model monitoring
20. Security hardening
21. Deployment
22. Portfolio presentation

Do not start with automatic blocking. A reliable IDS with simulated prevention is more valuable than an unsafe IPS.

---

# 40. FINAL DEVELOPMENT PRINCIPLE

Treat detection and prevention as separate decisions.

The detection system answers:

> How likely is this event to be malicious, and what evidence supports that conclusion?

The prevention policy engine answers:

> Given the evidence, asset context, allowlists, confidence, environment, authorization, and rollback capability, is a specific defensive action safe and permitted?

The prevention adapter answers:

> How can the approved defensive action be executed, verified, expired, and rolled back safely?

Never collapse these three responsibilities into one machine-learning prediction.

---

The most effective implementation path is to complete Sprints 0–9 first and use the resulting **IDS plus simulated IPS** as the initial portfolio release. Sprints 10–11 should only be implemented after rollback, authorization, allowlisting, and false-positive controls have comprehensive automated tests.
