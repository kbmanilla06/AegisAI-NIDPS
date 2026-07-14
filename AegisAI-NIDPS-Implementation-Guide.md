# AegisAI NIDPS — Step-by-Step Implementation and Development Guide

## Document status

- **Purpose:** Convert `AegisAI-NIDPS-Master-Prompt.md` into a practical development procedure.
- **Current project state:** Planning only. No application code, repository scaffold, services, dependencies, or infrastructure have been created by this guide.
- **Recommended first release:** Complete Sprints 0–9 to deliver a working IDS with a simulated IPS.
- **Safety boundary:** Real enforcement must remain disabled until the approval, rollback, allowlist, authorization, and false-positive controls have been independently tested in an isolated lab.

---

# 1. Understand the Product Before Building It

AegisAI NIDPS is not one machine-learning model. It is a security operations platform made of separate systems:

1. **Telemetry collection** receives Zeek, Suricata, flow, and authorized offline-PCAP data.
2. **Normalization** converts different telemetry formats into canonical records.
3. **Deterministic detection** applies signatures and behavioral rules.
4. **Feature engineering** creates stable, versioned inputs for machine learning.
5. **Supervised ML** classifies known attack patterns.
6. **Anomaly detection** identifies unusual behavior without calling every anomaly malicious.
7. **Decision fusion** combines evidence into transparent risk and confidence scores.
8. **Threat intelligence** adds time-limited, source-attributed indicator context.
9. **Explainability** shows why a model or engine produced a result.
10. **Alert and incident management** gives analysts a controlled investigation workflow.
11. **Prevention policy** decides whether a proposed action is allowed.
12. **Prevention adapters** preview, execute, verify, expire, and roll back an approved action.
13. **Audit, reporting, and monitoring** make every sensitive operation observable and reviewable.

Never combine detection, prevention eligibility, and prevention execution into one component. A model may supply evidence; it must never directly modify a firewall.

---

# 2. Define the Release Strategy

Build the project as three controlled releases rather than trying to deliver every feature at once.

## Release A — Portfolio MVP: IDS with simulated prevention

Complete Sprints 0–9.

The MVP should:

- Ingest controlled telemetry.
- Normalize Zeek and Suricata events.
- Detect selected patterns with signatures and behavioral rules.
- Train and serve a defensible supervised baseline.
- Produce anomaly scores.
- Combine evidence into risk scores.
- Explain alerts.
- Support analyst investigation and incident cases.
- Preview and audit prevention actions without changing the network.

This is the recommended first public portfolio release.

## Release B — Human-approved laboratory prevention

Complete Sprint 10 only after Release A is stable.

This release adds short-lived, reversible enforcement inside a disposable, authorized laboratory. Every action requires an authorized analyst, justification, expiration, verification, audit records, and tested rollback.

## Release C — Limited automatic laboratory prevention

Complete Sprints 11–15 only after Release B has strong evidence of safety.

Automatic action must remain narrowly scoped, reversible, rate-limited, environment-restricted, and disabled by default. It must fall back to a recommendation whenever any policy gate fails.

---

# 3. Establish Non-Negotiable Project Rules

Record these rules in the PRD, threat model, architecture decision records, and contributor guidance before coding:

1. Only process public, synthetic, locally owned, or explicitly authorized traffic.
2. Live packet capture is not required for the first MVP.
3. Prefer network metadata and flows; do not retain payloads by default.
4. Prevention defaults to simulation in every environment.
5. ML output is evidence, not authorization.
6. An anomaly score alone can never authorize prevention.
7. Permanent blocking is outside the MVP.
8. Every later enforcement action needs a maximum duration and rollback method.
9. Allowlists and critical-asset checks occur before execution.
10. Sensitive actions require RBAC and immutable-looking, append-oriented audit records.
11. Dataset, feature, rule, threshold, and model versions must be traceable from every alert.
12. A feature is not complete without tests and documentation.
13. Test results and performance claims must be produced by actual runs.
14. No sprint advances while its release-blocking acceptance criteria remain unmet.

---

# 4. Make the Key Decisions Before Sprint 0 Ends

Create an Architecture Decision Record for each decision. Do not leave these as undocumented assumptions.

## 4.1 MVP input formats

Recommended order:

1. Normalized CSV or JSON flow fixtures for fast development.
2. Zeek `conn.log` or JSON.
3. Suricata EVE JSON.
4. Offline PCAP processing.
5. Optional live sensor integration after offline paths are stable.

## 4.2 Dataset strategy

Choose one primary dataset for initial supervised work, then use another dataset only for external validation or schema-adapter testing. Do not merge datasets until their semantics, labels, timestamps, capture environments, and feature definitions have been reconciled.

For each dataset, record:

- Official source and license.
- Download checksum and acquisition date.
- Raw and processed data locations.
- Class labels and class distribution.
- Duplicate and missing-value counts.
- Leakage risks.
- Split strategy.
- Transformations and feature version.
- Known limitations and intended use.

## 4.3 Initial detection scope

Start with a small set of explainable behaviors:

- Port-scan indicators.
- Repeated connection failures.
- High connection-rate behavior.
- Suspicious DNS request volume.
- Possible periodic beaconing.
- Unusual outbound-transfer volume.

Implement fewer rules with strong tests and clear evidence before expanding coverage.

## 4.4 Initial ML scope

Use this sequence:

1. Majority-class or rule-only reference.
2. Logistic Regression baseline.
3. Random Forest candidate.
4. XGBoost or LightGBM only if justified by measured improvement.
5. Isolation Forest for anomaly detection.
6. Autoencoder only if simpler methods fail to meet a documented need.

## 4.5 Data-retention policy

Decide what is stored and for how long:

- Raw uploaded files.
- Normalized flows.
- Alerts and evidence.
- Model features.
- Incidents and notes.
- Audit records.
- Reports.

Prefer derived metadata, configurable retention, restricted PCAP access, and deletion procedures that preserve required audit evidence.

## 4.6 Identity model

Define permissions for Viewer, SOC Analyst, Senior Analyst, Security Administrator, System Administrator, and Auditor. Explicitly define who may:

- Change rules and thresholds.
- Register or activate models.
- Approve prevention.
- Execute prevention.
- Roll back prevention.
- Manage allowlists.
- Read raw telemetry.
- Export reports.
- View audit records.

## 4.7 Definition of done

Every issue should require:

- Acceptance criteria met.
- Typed and formatted code.
- Unit and relevant integration tests.
- Negative and authorization tests when applicable.
- Security checks with no unexplained blocking finding.
- Safe, non-sensitive logs and errors.
- Migration and rollback review if data changes.
- Documentation updates.
- Evidence of commands actually run.
- A suggested Conventional Commit.

---

# 5. Use a Repeatable Workflow for Every Task

Apply this procedure to every development issue.

## Step 1 — Select one bounded issue

Choose the highest-priority unblocked item from the current sprint. Do not bundle unrelated refactors or later-sprint features into it.

## Step 2 — Restate the expected outcome

Write the observable behavior, affected user or service, inputs, outputs, failure cases, and acceptance criteria.

## Step 3 — Inspect before changing

Review the relevant architecture, interfaces, schemas, migrations, security controls, tests, recent changes, and known defects.

## Step 4 — Identify risks

Record effects on confidentiality, integrity, availability, authentication, authorization, privacy, data retention, detection accuracy, false positives, auditability, and prevention safety.

## Step 5 — Plan the smallest safe change

List exact modules to change, interfaces to preserve, tests to add, documentation to update, and rollback approach.

## Step 6 — Implement one vertical slice

A vertical slice should produce testable behavior from its input boundary to its output boundary. Avoid placeholder systems that appear complete but have no verified behavior.

## Step 7 — Test at the correct layers

Add unit tests first, then integration, authorization, negative, edge, concurrency, performance, or end-to-end coverage as the risk requires.

## Step 8 — Run quality and security checks

Run formatting, linting, type checking, unit tests, relevant integration tests, dependency/security checks, and migration validation. Record the exact results.

## Step 9 — Review the diff

Check for unrelated changes, credentials, sensitive data, debug output, generated artifacts, unbounded files, weakened controls, or misleading claims.

## Step 10 — Update documentation

Document behavior, configuration, limitations, security implications, testing, operations, and rollback.

## Step 11 — Request approval

Compare evidence against acceptance criteria. Use `APPROVED`, `CONDITIONALLY APPROVED`, or `REJECTED`; do not treat missing evidence as a pass.

## Step 12 — Commit narrowly

Stage only reviewed files and use a Conventional Commit that accurately describes the completed change.

---

# 6. Detailed Sprint-by-Sprint Procedure

## Sprint 0 — Discovery, security planning, and foundation

### Goal

Produce enough approved design evidence to build safely, then create only the minimal development foundation.

### Procedure

1. Write the PRD with users, goals, non-goals, MVP boundaries, functional requirements, quality requirements, security/privacy requirements, success metrics, and limitations.
2. Separate IDS capabilities from IPS capabilities. State that the MVP IPS is simulation-only.
3. Write primary user journeys: ingest telemetry, review alerts, investigate evidence, create an incident, preview prevention, review audit history, and inspect model performance.
4. Write abuse cases for malicious uploads, parser exhaustion, alert floods, stolen credentials, role abuse, data/model poisoning, threshold tampering, audit tampering, and prevention abuse.
5. Produce the system context, container, component, data-flow, trust-boundary, deployment, training, inference, alert, and prevention diagrams.
6. Define service boundaries and contracts. Keep ingestion, detection, ML inference, policy, and enforcement separate.
7. Define canonical event, flow, alert, evidence, incident, model-version, rule-version, and prevention-request schemas.
8. Design the database, constraints, indexes, sensitive fields, retention, migration order, and rollback expectations.
9. Design REST and WebSocket contracts, including roles, validation, errors, rate limits, audit behavior, and idempotency.
10. Create the ML plan: dataset choice, split strategy, leakage controls, baselines, metrics, artifact format, versioning, promotion, and rollback.
11. Define the test pyramid and quality gates.
12. Define local development and deployment topology.
13. Create a prioritized backlog with dependencies and acceptance criteria.
14. Only after documents are reviewed, scaffold the repository, health checks, local containers, environment templates, CI, and empty test harness.

### Required documents

- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DATA_FLOW.md`
- `docs/THREAT_MODEL.md`
- `docs/ABUSE_CASES.md`
- `docs/DATABASE.md`
- `docs/API.md`
- `docs/ML_PLAN.md`
- `docs/TEST_STRATEGY.md`
- `docs/DEPLOYMENT_STRATEGY.md`
- `docs/RISK_REGISTER.md`
- `docs/DEFINITION_OF_DONE.md`
- `docs/BACKLOG.md`
- `SECURITY.md`
- `CONTRIBUTING.md`

### Exit gate

Do not start Sprint 1 unless the environment can be started reproducibly, health checks work, CI runs the initial gates, no secret is committed, simulation is the only prevention mode, and the design/threat assumptions are documented.

## Sprint 1 — Authentication, authorization, assets, and sensors

### Procedure

1. Implement user, role, permission, asset, and sensor data models with reversible migrations.
2. Implement password hashing using an accepted password-hashing library and safe parameters.
3. Choose session or token behavior, document the lifecycle, and implement secure expiration/revocation.
4. Add login throttling, lockout behavior, generic authentication errors, and audit records.
5. Implement centralized authorization checks; do not scatter role-name comparisons through handlers.
6. Create a permission matrix and test every protected route against allowed and denied roles.
7. Protect sensor credentials at rest and show them only at safe creation/rotation boundaries.
8. Add asset criticality and network-zone metadata needed by later policy decisions.
9. Build the minimum UI for authentication, users, assets, and sensors.
10. Add unit, integration, negative, token/session, throttling, and RBAC tests.

### Exit gate

All protected operations enforce server-side authorization, sensitive actions are audited, credential values do not appear in logs, and prevention settings remain inaccessible except to explicitly permitted roles.

## Sprint 2 — Telemetry ingestion and normalization

### Procedure

1. Finalize version 1 of the canonical telemetry schema.
2. Create small, synthetic positive and malformed fixtures before writing parsers.
3. Implement the normalized-flow adapter first to prove the ingestion interface.
4. Implement Zeek parsing with strict field mapping, timestamp normalization, and safe missing-value handling.
5. Implement Suricata EVE JSON parsing without assuming every event type has the same schema.
6. Implement offline-PCAP processing as an isolated, resource-limited background job.
7. Validate file type from content and schema, not filename alone.
8. Enforce size, record-count, decompression, processing-time, memory, and rate limits.
9. Make ingestion idempotent or detect duplicates using stable source/event identity.
10. Store processing status and errors without leaking filesystem paths or internal exceptions.
11. Add metrics for accepted, rejected, duplicated, delayed, and failed events.
12. Fuzz parsers and test empty, truncated, malformed, huge, Unicode, duplicate, and out-of-order inputs.

### Exit gate

Each supported source reliably becomes a canonical record, invalid input fails safely, uploads are never executed, parser failure cannot crash the API, and duplicate replay does not create uncontrolled duplicate data.

## Sprint 3 — Signature and behavioral detection

### Procedure

1. Normalize Suricata alerts into the canonical alert/evidence model.
2. Define a versioned behavioral-rule schema containing rule ID, description, conditions, window, threshold, severity, MITRE mapping, evidence, false-positive notes, investigation guidance, and tests.
3. Implement one rule at a time with deterministic fixtures and a reference time source.
4. Start with scan, repeated failure, and high-rate rules before more ambiguous beaconing or volume rules.
5. Add deduplication, suppression windows, aggregation, and alert-flood limits.
6. Store the exact rule version and contributing events on every alert.
7. Expose read-only rule, alert, and evidence APIs before adding rule-management UI.
8. Publish live alert updates through a bounded WebSocket mechanism.
9. Test positive, negative, threshold-boundary, timing, duplicate, replay, and high-volume cases.

### Exit gate

Every alert is reproducible from its evidence and versioned rule. False-positive considerations are documented, floods are bounded, and no rule directly invokes prevention.

## Sprint 4 — Feature engineering and data pipeline

### Procedure

1. Define a feature dictionary with name, type, unit, valid range, missing-value policy, source, security meaning, and model use.
2. Explicitly ban labels, row identifiers, post-incident fields, and label-derived fields from model inputs.
3. Implement deterministic per-flow transformations.
4. Add windowed features using clearly defined event time, ordering, and late-event behavior.
5. Create one shared transformation package for both training and inference.
6. Version the canonical input schema, feature code, feature list, categorical vocabulary, and preprocessing configuration.
7. Define handling for unseen categories, missing values, infinities, corrupt types, and out-of-range values.
8. Add train/serve parity tests using identical raw samples.
9. Add deterministic-output tests, leakage tests, schema compatibility tests, and performance benchmarks.
10. Generate a data-quality report for each processed dataset.

### Exit gate

The same raw record produces the same ordered feature vector in training and inference, incompatible schemas fail closed, and the leakage review is documented.

## Sprint 5 — Supervised machine learning

### Procedure

1. Freeze the dataset manifest and feature version for the experiment.
2. Create train, validation, and untouched test splits. Prefer time-aware, host-aware, or capture-aware splits where random splitting would leak behavior.
3. Fit all preprocessing only on training data.
4. Establish a simple baseline and record its metrics.
5. Train Logistic Regression and Random Forest candidates.
6. Handle imbalance using documented class weighting, sampling, or threshold methods applied without contaminating validation/test data.
7. Tune only with training/validation data. Open the test set once for final candidate evaluation.
8. Report per-class precision, recall, F1, PR-AUC where applicable, false-positive/negative rates, confusion matrix, calibration, latency, throughput, memory, and artifact size.
9. Review errors by attack class, data source, time range, and important feature groups.
10. Produce a model card with intended use, prohibited use, data, features, metrics, limitations, ethical considerations, and rollback.
11. Save the preprocessing and model pipeline with a signed/checksummed manifest and compatibility metadata.
12. Implement a registry with staged, active, and retired states plus controlled promotion and rollback.
13. Serve inference through a typed interface that returns probability, model version, feature version, and explanation metadata.
14. Test corrupt artifacts, incompatible features, missing models, concurrent loading, and rollback.

### Exit gate

Evaluation is reproducible and leakage-resistant, the artifact is traceable and safely loaded, failure is explicit, and no model output can initiate prevention.

## Sprint 6 — Anomaly detection and ensemble decision engine

### Procedure

1. Define what population represents normal behavior and document contamination risk.
2. Train an Isolation Forest baseline using versioned features.
3. Calibrate thresholds on validation data and document sensitivity tradeoffs.
4. Measure false positives by protocol, asset class, time, and traffic pattern.
5. Define normalized inputs for signatures, rules, supervised predictions, anomalies, intelligence, asset criticality, and history.
6. Write a transparent, configurable fusion formula.
7. Separate risk score, confidence, severity, category, and automation eligibility.
8. Define conflict behavior—for example, strong signatures versus low ML confidence.
9. Attach every contributing signal and version to the result.
10. Add golden-case tests, threshold-boundary tests, missing-signal tests, conflict tests, and scoring-regression tests.

### Exit gate

The same evidence produces the same score, scoring logic is inspectable, uncertainty is visible, and anomaly-only evidence is categorically ineligible for automatic prevention.

## Sprint 7 — Explainability and threat intelligence

### Procedure

1. Select the cheapest faithful explanation method for each model.
2. Generate top contributing features with raw values, transformed meaning, direction, and uncertainty.
3. Translate technical evidence into an analyst summary without overstating causation.
4. Store explanation version and model version together.
5. Define indicator types, normalization, source, confidence, first/last seen, expiry, and permitted use.
6. Import a small trusted feed or controlled fixtures first.
7. Expire stale indicators and prevent expired intelligence from authorizing action.
8. Add allowlist conflict handling and display conflicting sources.
9. Keep external lookups optional, rate-limited, cached, and privacy-aware.
10. Add MITRE ATT&CK mapping with evidence and mapping provenance.
11. Test expired, malformed, duplicated, conflicting, allowlisted, and low-confidence indicators.

### Exit gate

Analysts can see why an alert exists, which evidence came from which source, and whether intelligence is current. No stale or single-source intelligence silently becomes enforcement authority.

## Sprint 8 — Incident management and SOC dashboard

### Procedure

1. Implement the alert state machine and reject invalid transitions at the service/database boundary.
2. Add assignment, notes, evidence view, false-positive feedback, and complete audit history.
3. Implement incidents that group alerts while preserving each alert's original evidence.
4. Add incident owner, severity, status, timeline, containment, recovery, root cause, and closure fields.
5. Build dashboard pages incrementally: overview, live alerts, alert detail, incidents, MITRE, model performance, false positives, and health.
6. Enforce field-level and action-level RBAC server-side.
7. Add accessible labels, keyboard behavior, focus handling, color-safe severity indicators, and responsive layouts.
8. Limit queries, paginate large lists, index filters, and bound live-update queues.
9. Add E2E tests for investigation, state transitions, assignment, feedback, grouping, and authorization.

### Exit gate

An analyst can complete a realistic investigation without direct database access, invalid actions fail safely, every change is audited, and dashboard performance remains usable with representative data.

## Sprint 9 — Prevention simulation and policy engine

### Procedure

1. Define the prevention-request lifecycle independently from alerts.
2. Define action types, target types, reason, evidence, duration, rollback metadata, requested-by, and status.
3. Implement deterministic eligibility rules for environment, target, internal/external scope, allowlists, critical assets, signal count, confidence, intelligence freshness, duration, cooldown, and authorization.
4. Implement idempotency keys and database constraints that prevent duplicate execution records.
5. Build the simulation adapter with `Validate`, `Preview`, `Execute`, `Verify`, `Rollback`, and `Status`; its execution method records only a simulation result.
6. Make every preview show the exact command or policy effect in a safely represented form, without executing it.
7. Record the policy version and each passed/failed gate.
8. Add automatic expiration and rollback metadata even though the action is simulated.
9. Build analyst request/review UI and audit views.
10. Test allowlisted targets, critical assets, internal ranges, expired intelligence, insufficient signals, low confidence, duplicate requests, replayed idempotency keys, concurrency, expiry, and simulated rollback.
11. Verify at the operating-system level that simulation creates no firewall change.

### Exit gate

Every proposed action is explainable, time-bounded, idempotent, auditable, and reversible in its model. Simulation changes no network state. This is the preferred first public release boundary.

## Sprint 10 — Approval-based laboratory prevention

### Preconditions

- Release A is stable.
- An isolated, disposable, explicitly authorized lab exists.
- Rollback and recovery runbooks are approved.
- Simulation tests include duplicates, races, partial failure, and expiry.

### Procedure

1. Add an explicit environment-level enforcement flag that defaults off.
2. Require a role-authorized approver and recorded justification.
3. Implement separation of duties where risk warrants it; prevent unauthorized self-approval.
4. Implement only short-lived firewall actions through a narrow adapter interface.
5. Validate the target and command arguments without shell interpolation.
6. Preview, execute, verify, and persist results transactionally where possible.
7. If verification fails, immediately attempt rollback and raise a high-severity operational event.
8. Schedule automatic expiration and make manual rollback idempotent.
9. Add per-target locks, rate limits, cooldowns, and an emergency disable control.
10. Test in disposable environments, including service crashes, adapter failure, partial state, duplicate calls, and audit failure.

### Exit gate

No unauthorized approval succeeds; all actions expire; verification and rollback are proven; emergency disable prevents new enforcement; and simulation remains the default everywhere.

## Sprint 11 — Limited automatic laboratory prevention

### Procedure

1. Define an explicit allowlist of permitted automatic action types.
2. Require at least two independent evidence sources.
3. Require minimum confidence, fresh intelligence when used, safe target classification, duration, tested rollback, and healthy dependencies.
4. Enforce per-target cooldowns and global rate limits.
5. Implement a circuit breaker that falls back to recommendations.
6. Automatically roll back on expiry, health failure, or failed verification.
7. Keep high-impact and permanent actions categorically prohibited.
8. Run chaos, concurrency, replay, expiration, policy-mutation, and rollback tests.

### Exit gate

Any failed gate produces recommendation-only behavior; the circuit breaker is proven; actions expire and roll back; and automation is disabled outside the authorized test environment.

## Sprint 12 — Model monitoring, drift, and feedback

### Procedure

1. Store predictions with model/feature versions and later analyst labels.
2. Track input quality, feature distributions, class distributions, score distributions, and error metrics.
3. Define warning and critical drift thresholds with minimum sample sizes.
4. Separate drift detection from retraining and model promotion.
5. Create reviewed retraining candidates; never auto-promote.
6. Compare candidate and active models on fixed regression suites and recent reviewed data.
7. Add promotion approval, rollback, and model-card updates.
8. Confirm model changes never silently change prevention policy.

### Exit gate

Every label, prediction, artifact, and threshold is traceable; drift creates review work rather than autonomous promotion; and rollback is tested.

## Sprint 13 — Reporting, observability, and performance

### Procedure

1. Standardize structured logs and correlation IDs without sensitive payloads.
2. Add metrics for ingestion, queues, detection, inference, alerts, policy decisions, prevention, errors, and health.
3. Build dashboards around service-level indicators and failure modes.
4. Establish representative load profiles and baseline latency, throughput, CPU, memory, and storage growth.
5. Test backpressure, queue saturation, slow dependencies, and degraded mode.
6. Generate alert, incident, prevention, model, executive, and health reports with RBAC.
7. Implement retention jobs with audit-safe behavior.
8. Test backup and restore, not just backup creation.

### Exit gate

Operators can detect failures and bottlenecks, reports do not expose secrets, performance limits are documented, and a clean restore has been demonstrated.

## Sprint 14 — Security hardening and full QA

### Procedure

1. Freeze features except for required remediation.
2. Run the complete unit, integration, E2E, migration, security, performance, recovery, and rollback suites.
3. Run static analysis, secret scanning, dependency auditing, and container scanning.
4. Review authentication, authorization, sessions, uploads, parsers, errors, logs, artifacts, migrations, race conditions, defaults, audit, and retention.
5. Perform adversarial tests for boundary values, malformed data, replay, concurrency, partial failures, expired objects, corrupt artifacts, and resource pressure.
6. Re-run the threat model against the implemented system.
7. Fix Critical and High issues before release; document accepted lower risks with owner and review date.
8. Verify every prevention-safety invariant from the master prompt.

### Exit gate

No Critical or unexplained High finding remains, no secret is committed, simulation is still default, and every critical workflow has current tests and runbooks.

## Sprint 15 — Deployment and portfolio presentation

### Procedure

1. Validate a clean setup from documented prerequisites.
2. Pin and document dependencies and container images appropriately.
3. Provide controlled demo data and safe replay procedures.
4. Finalize the README, architecture diagrams, model cards, security report, test report, performance report, limitations, and roadmap.
5. Capture screenshots using synthetic or sanitized data.
6. Create a ten-minute demo showing ingestion, detection, explanation, investigation, incident handling, simulated prevention, rollback, audit, and limitations.
7. Reproduce the demo on a clean environment.
8. Prepare the portfolio case study and honest resume bullets.
9. Run the final release review and system audit.
10. Tag a release only after approval.

### Exit gate

A new developer can reproduce the project; claims match recorded evidence; demo data is safe; limitations are explicit; and prevention is simulated by default.

---

# 7. Testing Strategy by Layer

## Unit tests

Cover parsers, validators, normalizers, feature transformations, rules, scoring, state machines, policy gates, authorization helpers, and adapter behavior.

## Integration tests

Cover API-to-database flows, queue workers, migrations, sensor ingestion, model registry/inference, WebSockets, audit creation, policy decisions, and simulation.

## Contract tests

Freeze canonical event, feature, model, alert, and prevention interfaces. Reject incompatible versions deliberately.

## Security tests

Cover authentication bypass, role boundaries, token/session expiry, injection, traversal, unsafe upload types, parser abuse, rate limits, sensitive errors, secret logging, artifact integrity, allowlist bypass, replay, self-approval, and audit tampering.

## ML tests

Cover deterministic preprocessing, leakage, split integrity, missing/unseen/corrupt inputs, calibration, threshold boundaries, artifact compatibility, inference latency, drift calculations, promotion, and rollback.

## End-to-end tests

Cover complete analyst journeys from telemetry ingestion to alert, investigation, incident, prevention preview, approval where applicable, simulation, rollback, and audit review.

## Performance and resilience tests

Cover representative throughput, bursts, queues, slow dependencies, database contention, WebSocket fan-out, disk pressure, worker crash, duplicate delivery, retry, and graceful degradation.

## Release regression suite

Maintain fixed golden scenarios for benign traffic, each supported detection type, expected false-positive boundaries, model compatibility, incident transitions, allowlisted targets, insufficient prevention evidence, duplicate execution, expiration, failed verification, rollback, and emergency disable.

---

# 8. Documentation That Must Evolve with the Code

Update these continuously rather than at the end:

- Requirements traceability matrix.
- Architecture and data-flow diagrams.
- Threat model and risk register.
- API and schema references.
- Rule catalog and false-positive guidance.
- Dataset datasheets and feature dictionary.
- Model cards and evaluation reports.
- Migration and rollback notes.
- Operations, backup, restore, and troubleshooting runbooks.
- Prevention approval, expiry, rollback, and emergency-disable runbooks.
- Test, security, and performance reports.
- Known limitations and accepted risks.

---

# 9. How to Use the Prompt Library During Development

Use the prompts in the master document at specific checkpoints:

1. **Master prompt:** Begin a new AI coding task or restore full project context.
2. **PRD, architecture, threat-model, database, and API prompts:** Use during Sprint 0 and whenever a material design change is proposed.
3. **Individual task prompt:** Use for one backlog issue at a time.
4. **Daily development prompt:** Select the next task only within the active sprint.
5. **Bug-detection prompt:** Investigate without editing first.
6. **Debugging prompt:** Use when concrete failing behavior or logs exist.
7. **Bug-fixing prompt:** Use after a defect is confirmed and reproducible.
8. **Hidden-bug prompt:** Use before sprint approval and during hardening.
9. **ML review prompt:** Use before model promotion.
10. **Prevention-safety prompt:** Use before merging any prevention change.
11. **Database-migration prompt:** Use for every schema change.
12. **Code-review and approval prompts:** Use before merge.
13. **Commit prompt:** Use only after checks pass and the diff is reviewed.
14. **End-of-sprint and retrospective prompts:** Use at every sprint boundary.
15. **Release and final-audit prompts:** Use only when all earlier evidence is available.

Do not paste the entire prompt library into every task. Use the master context plus the one specialized prompt relevant to the current activity.

---

# 10. Recommended Work and Branch Discipline

1. Keep `main` releasable and protected.
2. Use `develop` only if the project genuinely needs an integration branch; a solo project can use short-lived branches directly into `main` with strict PR checks.
3. Name branches by issue and domain, such as `feature/42-zeek-ingestion` or `ml/73-random-forest-baseline`.
4. Keep each PR small enough to review completely.
5. Separate schema migrations, broad refactors, and behavior changes when practical.
6. Never commit raw datasets, PCAPs, secrets, private addresses, large model artifacts, or local environment files without an explicit reviewed policy.
7. Require stronger review for authentication, model activation, prevention, audit, and migration changes.
8. Record commands and outcomes in the PR; never claim an unrun check passed.

---

# 11. Practical Milestones

Use these milestones to measure progress independently of sprint numbers.

## Milestone 1 — Approved design

The PRD, architecture, threat model, data model, API contracts, ML plan, test plan, and backlog agree with each other.

## Milestone 2 — Secure platform shell

The local stack, CI, authentication, RBAC, assets, sensors, audit foundation, and health checks work.

## Milestone 3 — Deterministic IDS

Controlled telemetry produces reproducible, evidence-bearing signature and behavioral alerts.

## Milestone 4 — Defensible AI detection

Training and inference share versioned features; evaluation avoids leakage; artifacts and model cards are traceable; model output is explainable.

## Milestone 5 — Usable SOC workflow

Analysts can investigate alerts, manage incidents, record feedback, and review evidence without database access.

## Milestone 6 — Safe simulated IPS

Policy gates, previews, idempotency, expiry, rollback metadata, allowlists, and audit work while making no network changes.

## Milestone 7 — Portfolio MVP release

Sprints 0–9 are tested, documented, reproducible, honestly measured, and demonstrated with controlled data.

## Milestone 8 — Optional lab enforcement

Only after separate authorization: short-lived actions execute, verify, expire, and roll back safely in a disposable lab.

---

# 12. Common Failure Modes to Avoid

- Building the dashboard before stable schemas and workflows exist.
- Starting with deep learning instead of a measurable baseline.
- Randomly splitting traffic records that share hosts, sessions, or capture periods across train and test sets.
- Training and serving with different preprocessing code.
- Treating model accuracy as the main result.
- Calling anomalies attacks without corroboration.
- Hiding risk-score calculations.
- Allowing unversioned rule, feature, threshold, or model changes.
- Storing raw payloads unnecessarily.
- Letting filenames determine upload trust.
- Creating alert floods without deduplication or suppression.
- Embedding authorization logic only in the frontend.
- Letting the detection engine call firewall code.
- Enabling real prevention merely because simulation passes happy-path tests.
- Adding permanent or non-expiring blocks.
- Testing rollback only after release.
- Treating generated documentation or AI claims as evidence of passing tests.
- Expanding scope before the current sprint exit gate passes.

---

# 13. What to Do When Development Is Authorized to Begin

When you are ready to start, begin with Sprint 0 only:

1. Confirm the project name and repository location.
2. Confirm whether the first release stops after Sprint 9.
3. Confirm the development machine and Docker resources available.
4. Confirm the preferred frontend choice: React with Vite or Next.js.
5. Confirm the initial dataset and its license/source.
6. Confirm that live capture and real prevention are out of scope for the MVP.
7. Generate the Sprint 0 planning documents before application code.
8. Review and approve those documents.
9. Create the minimal repository and CI foundation.
10. Run and record the Sprint 0 acceptance checks.
11. Conduct the Sprint 0 review.
12. Start Sprint 1 only after explicit approval.

The first implementation task should not be model training or firewall integration. It should be the approved Sprint 0 foundation derived from the documented architecture and threat model.

---

# 14. Final Readiness Checklist for This Guide

Before implementation begins, verify that you can answer yes to all of the following:

- Is the MVP explicitly limited to IDS plus simulated IPS?
- Are authorized data sources and lab boundaries documented?
- Are raw payload retention and privacy defaults decided?
- Is the initial dataset selected with a leakage-aware split plan?
- Is the initial deterministic detection scope small and testable?
- Are detection, policy, and enforcement separate components?
- Are user roles and sensitive permissions defined?
- Are canonical event, feature, alert, incident, and prevention schemas planned?
- Are versioning rules defined for data, features, rules, models, and thresholds?
- Are test and release gates documented?
- Are simulation, allowlists, expiration, rollback, idempotency, and audit non-negotiable?
- Is automatic enforcement explicitly deferred?
- Is Sprint 0 approval required before coding begins?

If any answer is no, resolve it during Sprint 0 rather than hiding it in implementation assumptions.

---

# 15. Recommended Immediate Next Step

Do not create the application yet. Review this guide alongside `AegisAI-NIDPS-Master-Prompt.md`, decide the seven Sprint 0 choices listed in Section 13, and then authorize the creation of the planning documents. Once those documents are internally consistent and approved, the project can move into a controlled implementation cycle.
