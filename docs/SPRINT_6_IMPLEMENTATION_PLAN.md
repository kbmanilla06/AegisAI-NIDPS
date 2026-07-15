# Sprint 6 Implementation Plan — Anomaly Detection and Transparent Decision Fusion

**Planning date:** 2026-07-15
**Status:** Planning only; owner approval required
**Target:** Sprint 6 — anomaly scoring and transparent decision fusion
**Release boundary:** Sprints 0–9, IDS with simulated IPS
**Planning baseline:** public `main` at `9cc643dba4a9d15284eb1a812bf661f848a801ce`
**Synthetic boundary:** Gate 5S-A/B/C evidence only; UNSW-NB15 acquisition remains blocked

## 1. Entry-gate evidence

The Sprint 5 Gate 5S-C publication gate is satisfied:

- Gate 5S-C implementation commit `445b75009b6021da5020cce788e54082208a129e` is published on `main`.
- The CI-only dashboard stabilization commit `38fb0eda30c545de57d6d5c84399e93435982174` is published.
- Hosted CI Run #11 passed for the Gate 5S-C implementation lineage.
- Publication-documentation commit `9cc643dba4a9d15284eb1a812bf661f848a801ce` is on public `main`.
- Hosted CI Run #12 completed successfully for the current public SHA: [Run #12](https://github.com/kbmanilla06/AegisAI-NIDPS/actions/runs/29393145507).
- The working tree was clean before this planning document was created.

This document is documentation-only. It authorizes no code, migration, model activation, online inference, real dataset use, prevention capability, commit, or publication.

## 2. Governing material reconciled

This plan is reconciled against the complete governing project documents and Sprint 5 evidence:

- `AegisAI-NIDPS-Master-Prompt.md`
- `AegisAI-NIDPS-Implementation-Guide.md`
- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/BACKLOG.md`
- `docs/DECISIONS.md`
- `docs/DEFINITION_OF_DONE.md`
- `docs/DATABASE.md`
- `docs/SCHEMAS.md`
- `docs/ML_PLAN.md`
- `docs/api/API.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/DATA_FLOW.md`
- `docs/threat-model/THREAT_MODEL.md`
- `docs/TEST_STRATEGY.md`
- `docs/DEPLOYMENT_STRATEGY.md`
- `docs/RISK_REGISTER.md`
- `docs/SPRINT_4_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_4_COMPLETION_REPORT.md`
- `docs/SPRINT_5_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md`
- `docs/SPRINT_5_PHASE_5A_PREACQUISITION_REPORT.md`
- `docs/SPRINT_5_PHASE_5A_BLOCKER_RESOLUTION_PLAN.md`
- `docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md`
- `docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md`
- `docs/SPRINT_5_GATE_5SB_COMPLETION_REPORT.md`
- `docs/SPRINT_5_GATE_5SC_COMPLETION_REPORT.md`

The Sprint 5 reports are the current evidence for the synthetic-only boundary. Where older API/backlog text describes future model routes, this plan treats those routes as proposed and does not infer implementation authority.

## 3. Confirmed requirements and invariants

These are not new owner decisions:

1. The first release is Sprints 0–9: IDS with simulated IPS.
2. Anomaly scores and ensemble assessments are evidence, never prevention authorization.
3. Detection, assessment/fusion, prevention policy, and prevention adapters remain separate.
4. Canonical flow v1 and `flow_features/1.0.0` are immutable; all 39 model features retain their approved order and the seven provenance columns remain non-model data.
5. Gate 5S-A hashes and the accepted Gate 5S-B/C synthetic evidence are immutable inputs. No real or third-party dataset is used.
6. Labels, scenario family, group, partition, endpoint identity, exact event time, alert/rule results, and assessment outputs are never anomaly or fusion model inputs.
7. Anomaly fitting and all learned normalization use training identities only. Thresholds and fusion parameters are chosen on validation evidence only. The sealed test is opened once for a locked final evidence run.
8. Every detector, threshold, policy, artifact, assessment, and report is versioned, hash-bound, and auditable.
9. ONNX plus canonical JSON is the approved safe artifact direction; pickle/joblib/Python-object loading is prohibited. Unsupported operators or conversion/parity failures reject a candidate.
10. PostgreSQL is authoritative. Celery messages are JSON-only and carry bounded UUIDs only. Redis is coordination, never source of truth.
11. Controlled local artifacts use opaque references, mode-0600 atomic writes, SHA-256 verification, bounded size, and retention cleanup.
12. No API or worker startup loads an anomaly or supervised model. Sprint 6 is offline batch evaluation only.
13. Sprint 6 must not mutate alerts, detections, rules, incidents, prevention state, network state, or firewall state. Alert projection is deferred to Sprint 8.
14. Publisher outreach is cancelled; UNSW-NB15 acquisition remains blocked; the two `NUSW-...` files remain excluded.

## 4. Sprint 6 scope

### 4.1 Included after separate implementation authorization

- A strict anomaly-detector contract and versioned threshold contract.
- A bounded Isolation Forest baseline trained only on an explicitly declared synthetic normal population.
- Training-only score normalization and validation-only threshold selection.
- Deterministic, offline batch anomaly evaluation over the accepted synthetic feature artifact.
- A versioned fusion-input contract for deterministic signals, supervised probabilities, anomaly scores, optional intelligence, and optional asset context.
- A transparent, deterministic fusion policy producing risk, confidence, severity, category, uncertainty, and evidence provenance.
- Missing-signal, disagreement, stale-version, and incompatible-input behavior.
- Candidate metadata, model-card-like anomaly cards, policy manifests, and aggregate-only reports with the mandatory synthetic limitation.
- Additive reversible PostgreSQL metadata for anomaly candidates, threshold versions, fusion policies, assessment batches, and bounded assessment results.
- JSON-only UUID Celery tasks with resource, timeout, idempotency, reconciliation, and cleanup controls.
- Central RBAC, CSRF/Origin enforcement, creator/reviewer separation, safe append-only audit, controlled artifacts, and retention.
- Minimal metadata-only APIs and dashboard views for candidate/threshold/policy review and offline batch status.
- Synthetic fixtures before implementation and unit, integration, security, migration, determinism, parity, resource, Docker, Celery, frontend, accessibility, and simulation-only tests.

### 4.2 Explicitly excluded

- UNSW-NB15, the `NUSW-...` files, any real/third-party dataset, mirrors, tokenized URLs, publisher contact, or network download.
- Live packet capture, network-interface monitoring, payload processing, or PCAP acquisition.
- Automatic or online inference, API request-time scoring, model loading at API/detection startup, or model activation.
- Alert creation or mutation, detection-rule mutation, incident creation, risk updates to existing alerts, prevention recommendations, policy execution, or firewall integration.
- Threat-intelligence acquisition or external lookups (Sprint 7), explainability/SHAP (Sprint 7), incident/SOC workflows (Sprint 8), and prevention work (Sprint 9+).
- Auto-training, auto-promotion, auto-threshold drift changes, hyperparameter search beyond the predeclared bounded set, or test-set retuning.
- One-Class SVM, autoencoders, deep learning, boosting, ensembles of anomaly models, or any native dependency not separately reviewed.
- Arbitrary model/artifact upload, custom operators, external ONNX data, dynamic shapes, executable code, notebooks in runtime paths, privileged containers, host networking, firewall capabilities, commit, or publication.

## 5. Proposed Sprint 6 gates

To preserve explicit stop points, implementation should use three sub-gates:

### Gate 6A — anomaly contract and candidate evidence

Freeze normal-population, detector, score, threshold, artifact, and limitation contracts. Generate hostile/golden fixtures first. Fit the bounded Isolation Forest on training-only synthetic vectors, select the threshold on validation, and produce candidate artifact and anomaly-card hashes. Do not expose or activate the candidate.

### Gate 6B — transparent fusion evidence

Freeze signal normalization, missing-signal behavior, score formula, severity/category rules, evidence/provenance contract, and policy hash. Evaluate offline against deterministic synthetic signal fixtures and the locked Gate 6A candidate. Produce aggregate reports and assessment hashes. Do not write alerts or prevention state.

### Gate 6C — completion review

Run the complete local gates, review the diff for scope and Critical/High issues, produce `docs/SPRINT_6_COMPLETION_REPORT.md`, and stop uncommitted. Publication and any later online/alert integration require a separate owner authorization.

## 6. Anomaly population and contract

### 6.1 Normal population

The recommended default is a predeclared `synthetic_benign_like` training-only reference population from the accepted Gate 5S-A training identities. The target sidecar is used only by the dataset-governance step to select the frozen reference identity set; target values are removed before fitting and never enter the detector. The manifest records the selection rationale, identity hash, row count, source snapshot hash, and limitation that this is not real normal traffic.

An owner may instead approve a mixed unlabeled population, but that choice must record contamination assumptions and cannot be inferred from the presence of labels. Any normal-population change creates a new detector version.

### 6.2 Detector defaults

The first candidate is Isolation Forest only:

| Parameter | Proposed default |
|---|---|
| algorithm | `isolation_forest` |
| seed | `20260714` |
| estimators | 100 |
| max samples | `min(256, training_reference_rows)` |
| max features | 1.0 |
| bootstrap | false |
| threads | 1 |
| contamination | declared in manifest; not learned from test labels |
| input | exactly the 39 ordered model features, float32 after approved preprocessing |

The detector emits a raw score, a bounded normalized anomaly score in `[0,1]`, an out-of-range/invalid-input status, and the exact detector/feature/preprocessing hashes. The raw score is never presented as probability or maliciousness.

### 6.3 Score normalization and threshold

The proposed normalization fits only training-reference score anchors (lower/upper robust quantiles) and stores them in a canonical threshold manifest. Non-finite or degenerate anchors fail closed. Validation selects one threshold under a predeclared policy; the recommended policy is the 95th percentile of validation-reference anomaly scores, with the quantile and minimum-support rule fixed before evaluation. The threshold is immutable after selection. A second threshold or test retuning requires a new detector version and owner review.

No numeric performance gate is proposed for synthetic evidence. Reports must show false-positive/false-negative counts only as synthetic-demo observations and carry the mandatory limitation text.

### 6.4 Safe anomaly artifact

The recommended artifact is ONNX plus canonical JSON metadata, using a closed operator/opset allowlist shared with Gate 5S-B. The manifest binds detector, feature schema, preprocessing, normal-population, threshold, runtime, dependency, code, size, and SHA-256 hashes. No Python estimator object, pickle, joblib, external data, custom operator, dynamic shape, or arbitrary model input is accepted. If conversion, structural validation, or parity fails, the candidate is rejected; no unsafe fallback is introduced.

The precise ONNX operator/opset support for Isolation Forest is an owner decision before Gate 6A implementation. A candidate is never loaded by API startup or detection workers.

## 7. Fusion input and output contracts

### 7.1 Input signals

`FusionInputV1` is a strict immutable contract. Each signal has a source, source-version hash, event/window identity, normalized score in `[0,1]`, confidence/quality state, provenance reference, and optional reason code. The initial implemented sources are:

- `signature`: normalized Suricata signature severity/evidence from Sprint 3;
- `behavioral_rule`: versioned deterministic rule severity/evidence from Sprint 3;
- `supervised`: bounded synthetic-only probability from the accepted Gate 5S-B/C artifact;
- `anomaly`: Gate 6A normalized anomaly score and threshold state.

The contract reserves, but does not implement, `intelligence`, `asset_criticality`, and `historical_behavior` sources for Sprint 7/8. Missing reserved sources are explicit `absent`, never silently treated as zero or as evidence.

### 7.2 Output assessment

`DecisionAssessmentV1` is a new versioned sidecar assessment, not an alert mutation. It contains:

- assessment and policy versions/hashes;
- source flow/window identity as restricted provenance;
- contributing signal IDs and source-version hashes;
- risk score `0–100`;
- confidence `0–1`;
- severity and category;
- uncertainty/reason codes;
- evidence summary and completeness state;
- `automation_eligible=false` and `prevention_mode="simulation"`;
- synthetic limitation text and machine-readable false-capability flags.

Raw endpoint addresses, payloads, vectors, labels, full probability arrays, filesystem paths, and exceptions are prohibited in ordinary API/UI output and audit metadata.

## 8. Transparent fusion policy

### 8.1 Proposed default formula

The first policy uses predeclared weights over present sources:

| Source | Weight |
|---|---:|
| signature | 0.40 |
| behavioral rule | 0.30 |
| supervised | 0.20 |
| anomaly | 0.10 |

For present, valid signals only, `weighted_mean = sum(weight × score) / sum(weight)`, `risk_score = round_half_even(100 × weighted_mean)`. Absent sources are recorded as absent and do not contribute a zero. If no valid source is present, risk is `0`, confidence is `0`, severity is `informational`, and reason `NO_VALID_SIGNAL` is required.

### 8.2 Confidence, disagreement, and uncertainty

The recommended confidence is deterministic and bounded:

`confidence = min(source_count / 3, 1) × provenance_completeness × agreement`

where `provenance_completeness` is the fraction of present signals with valid version/hash/evidence references, and `agreement = 1 - (max_score - min_score)` for two or more present sources, or `0.5` for one source. All terms are rounded to six decimal places after calculation. Single-source confidence is capped at `0.5`; missing, invalid, stale, or disagreeing sources add explicit uncertainty codes.

### 8.3 Severity and category

Proposed severity bands are informational `0–24`, low `25–49`, medium `50–74`, high `75–89`, and critical `90–100`. Category precedence is signature category, then behavioral-rule category, then supervised class, then `unusual_behavior`; all contributing categories remain in evidence. A high-severity deterministic signature may set a documented risk floor of 75, but the owner must approve that exception before implementation. Severity is not an authorization decision.

### 8.4 Conflict and failure behavior

- A strong signature is retained as evidence even when model/anomaly scores are low; no source is discarded to make the score look consistent.
- A stale, incompatible, unverified, or non-finite source is marked unavailable and cannot contribute.
- A missing anomaly artifact removes only the anomaly component; deterministic evaluation continues.
- A missing supervised candidate removes only the supervised component; no fallback model is selected implicitly.
- Conflicting source categories produce `SIGNAL_DISAGREEMENT` uncertainty and preserve all source evidence.
- Any integrity, schema, threshold, or policy mismatch fails the batch; it does not produce partial assessments.

## 9. Evidence and provenance

Each batch and assessment binds to:

- accepted Gate 5S-A dataset/feature/split hashes;
- accepted Gate 5S-B candidate and preprocessing hashes;
- Gate 5S-C reviewed registry row and scoring-job identity;
- anomaly detector, normal-population, threshold, and policy hashes;
- source flow/detection-run/signal identities;
- code commit and dependency/runtime lock hash;
- resource and task outcome metadata.

Assessment evidence is aggregate in reports and UI. Restricted row-level lineage may be stored for 30 days solely to support deterministic replay and later Sprint 8 projection; it contains no endpoint addresses or payloads. Governance manifests, model cards, policies, hashes, and audit records are retained by version.

## 10. Candidate and policy lifecycle

### 10.1 Anomaly candidates

`candidate → reviewed_synthetic → rejected | quarantined | retired`

There is deliberately no `active` or `staged` state in Sprint 6. A reviewed candidate may be referenced only by an explicitly persisted offline evaluation job. Registry review requires a distinct Security Administrator account from the generating System Administrator.

### 10.2 Fusion policies

`draft → reviewed → retired`

Offline jobs name an exact reviewed policy hash. There is no mutable global policy and no online activation. Policy definitions are immutable; a change creates a new version and review event.

## 11. PostgreSQL migration design (planning only)

Proposed additive migration: `0009_sprint6_anomaly_ensemble`.

Tables/metadata:

1. `anomaly_detector_versions`: immutable algorithm/config/feature/preprocessor/normal-population/artifact hashes, runtime, lifecycle, creator/reviewer, limitation flags, and retention.
2. `anomaly_threshold_versions`: immutable score-normalization anchors, validation threshold, support, policy, detector hash, creator/reviewer, and audit reference.
3. `ensemble_policy_versions`: immutable input-source definitions, weights, formula version, bands, category precedence, missing-source policy, and review state.
4. `assessment_batches`: persisted offline UUID job, exact source/artifact/policy hashes, status, aggregate counts, safe error, resource evidence, actor, and expiry.
5. `decision_assessments`: bounded assessment sidecars linked to source flow/window and signal IDs, score/confidence/severity/category/uncertainty, version hashes, limitation flags, and expiry; no endpoint/payload/vector fields.
6. Sprint 6 permissions and role grants.

Required constraints include immutable definition fields, one reviewer distinct from creator, valid state transitions, hash/size/row/score bounds, one idempotency key per actor and operation, foreign-key lineage, no active model state, and retention-safe cleanup. Downgrade refuses while candidate artifacts or assessment rows remain inventoried; after explicit cleanup/retirement it removes only Sprint 6 objects and preserves Sprints 0–5.

Migration tests must cover fresh upgrade, existing-data upgrade, downgrade refusal, explicit inventory cleanup, downgrade, re-upgrade, immutable-field mutation, concurrent review, and audit-failure rollback.

## 12. Celery tasks and resource limits

Registered tasks carry one UUID only:

- `anomaly.fit_candidate(run_id)` — training-only candidate fit, no automatic retry;
- `anomaly.validate_candidate(run_id)` — artifact/hash/operator/parity validation;
- `anomaly.evaluate_batch(batch_id)` — bounded offline anomaly evidence;
- `ensemble.evaluate_batch(batch_id)` — bounded offline fusion assessments;
- `anomaly_ensemble.reconcile()` — recover stale persisted jobs safely;
- `anomaly_ensemble.cleanup()` — expiry cleanup with audit.

Proposed ARM64 host-aware defaults:

| Limit | Default |
|---|---:|
| worker memory | 4 GiB hard limit |
| worker CPU | 2 cores |
| numerical-library threads | 1 |
| rows per batch | 10,000 maximum |
| synthetic Gate 5A rows | 7,200 maximum |
| candidate artifact | 16 MiB |
| assessment report | 16 MiB |
| soft/hard task time | 600/720 seconds fit; 120/135 seconds evaluation |
| PIDs | 128 |
| concurrency | 1 |
| fit retries | 0; one explicit owner retry only after failure review |
| evaluation retries | one idempotent retry after reconciliation |

Workers use late acknowledgement, prefetch 1, no outbound network, read-only root, no privilege/host network/capabilities, and controlled writable volumes only. A resource breach terminates the job, deletes partial objects, records a stable code, and never emits partial assessments.

## 13. Minimal APIs and UI (design only)

Proposed metadata-only routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `GET /anomaly-detectors` and `/{id}` | Candidate/card/status metadata | `models:read`, bounded, no artifact path |
| `POST /anomaly-detectors/{id}/review` | Review/reject candidate | `models:review`, creator separation, CSRF/Origin, audit |
| `GET /anomaly-thresholds/{id}` | Threshold evidence | `models:read`, safe aggregate fields |
| `GET /ensemble-policies` | Reviewed policy metadata | `detections:read_metrics`, no mutable definition |
| `POST /assessment-batches` | Request offline fusion/anomaly batch | explicit permission, CSRF/Origin, idempotency, exact accepted hashes |
| `GET /assessment-batches` and `/{id}` | Status/counts/safe errors | authorized metadata only |
| `GET /assessments/summary` | Aggregate risk/severity/source counts | `detections:read_metrics`, bounded filters |

There is no online score endpoint, arbitrary artifact upload, activation route, alert mutation route, prevention route, raw vector endpoint, endpoint-address export, or browser-supplied task/model/path input.

The dashboard adds an authenticated offline-only view showing candidate/policy hashes, source coverage, aggregate assessment counts, uncertainty distribution, resource status, and the exact synthetic limitation. Controls are hidden or disabled when the server permission is absent; the UI never becomes the authorization boundary.

## 14. RBAC, CSRF, and audit

Proposed permissions:

| Permission | Role(s) |
|---|---|
| `models:read` | Senior Analyst, Security Administrator, System Administrator, Auditor |
| `models:review` | Security Administrator only |
| `anomaly:fit` | System Administrator only |
| `anomaly:evaluate` | Senior Analyst, Security Administrator, System Administrator |
| `ensemble:review` | Security Administrator only |
| `ensemble:evaluate` | Senior Analyst, Security Administrator, System Administrator |
| `detections:read_metrics` | Senior Analyst, Security Administrator, System Administrator, Auditor |

Viewer and SOC Analyst receive no new model/assessment write access. Reviewers cannot review their own candidate/policy. Unsafe requests require the existing opaque session, session-bound CSRF token, exact allowed Origin, rate limit, and optimistic expected-state checks.

Audit covers candidate creation/fit/validation, threshold selection, policy creation/review, batch request/start/success/failure, test-open event, artifact integrity failures, stale/incompatible source rejection, cleanup, and downgrade refusal. Metadata contains hashes, counts, versions, actor IDs, reason codes, and correlation IDs only—never paths, tokens, endpoint identities, raw rows, exception text, or full probability vectors. Audit persistence failure fails closed for review and batch acceptance.

## 15. Retention and privacy

Recommended defaults:

- candidate anomaly artifacts: 30 days after rejection or final decision;
- reviewed synthetic detector/policy artifacts: 180 days or until superseded plus rollback review;
- row-level assessment sidecars: 30 days, matching flow/prediction retention;
- aggregate assessment reports and manifests: retained by version under audit policy;
- temporary partial artifacts: immediate deletion, with bounded cleanup within 24 hours;
- no exceptional investigation holds for the MVP.

Raw endpoints, labels, payloads, vectors, and probability arrays are never in ordinary reports/UI. Small groups are suppressed or aggregated. All reports and UI surfaces carry the exact synthetic-demo limitation and machine-readable false-capability flags.

## 16. Security, privacy, and failure controls

### Security controls

- Treat feature artifacts, signal metadata, candidate graphs, thresholds, policies, and model-card text as hostile.
- Validate canonical JSON and ONNX structure; reject unsupported operators, external data, dynamic shapes, oversized files, symlinks, traversal, non-finite tensors, and incompatible hashes.
- Use opaque server-side artifact references; no user path/URL/model input.
- Keep detector/fusion code unable to call alert, incident, prevention, shell, socket, or firewall interfaces.
- Verify all lineage hashes at every transition and quarantine on mismatch.
- Run dependency, SBOM, native-runtime, secret, container, and simulation-only checks; unresolved Critical/High findings block the gate.

### Privacy and claim controls

- Synthetic labels are non-semantic software-test labels only.
- No UNSW-NB15 or real-network performance claim, production claim, zero-day claim, or prevention suitability claim is permitted.
- Aggregate-only API/UI/report output; restricted sidecar lineage has a short retention and no endpoints.

### Failure behavior

| Failure | Required response |
|---|---|
| Feature/preprocessing hash mismatch | Reject batch; no partial assessment |
| Missing/corrupt/unsupported anomaly artifact | Quarantine candidate; deterministic sources remain separate; no implicit fallback |
| Invalid threshold/policy/version | Reject batch and audit stable reason |
| Missing source signal | Mark absent; apply explicit missing policy; never fabricate zero evidence |
| Non-finite or out-of-range score | Reject source/batch according to contract; never clip silently |
| Resource/time limit | Terminate, delete partial output, preserve safe counts |
| Duplicate/replayed task | Return existing authoritative status; no duplicate rows |
| Database/audit failure | No review/acceptance/state transition; fail closed |
| Worker crash | Lease/reconcile stale job; never duplicate a successful batch |
| Fusion conflict | Preserve all evidence, add uncertainty code, use deterministic formula |
| Cleanup failure | Keep metadata, audit overdue item, retry boundedly |

## 17. Fixture-first and test matrix

Fixtures must be small, deterministic, synthetic, and created before implementation:

1. Normal-reference, intrusion-like, novel-but-benign, constant-feature, empty, single-row, and non-finite vectors.
2. Detector determinism, threshold-boundary, contamination, score-anchor, and sealed-test fixtures.
3. Corrupt/oversized/wrong-hash/traversal/symlink/unsupported-ONNX fixtures.
4. Signature-only, rule-only, supervised-only, anomaly-only, all-source, no-source, stale-source, and conflicting-source fusion cases.
5. Category-precedence, severity-band, confidence-cap, missing-signal, disagreement, and strong-signature-floor cases.
6. Duplicate/out-of-order/replayed batches and concurrent expected-state review cases.
7. Malicious limitation/card text, oversized metrics, endpoint-like strings, Unicode/control, and redaction fixtures.

Required gates:

- schema/hash/unknown-field and version compatibility;
- training-only normal-population and score-normalization fit;
- deterministic repeated runs and feature/preprocessor parity;
- validation-only threshold and sealed-test-once enforcement;
- score bounds, non-finite/range handling, missing/unseen behavior;
- fusion formula truth-table, weighted arithmetic, rounding, confidence, category/severity, conflict, and uncertainty;
- exact evidence/provenance hash binding and no endpoint/label/vector leakage;
- artifact operator/opset/shape/external-data/size/path/integrity tests;
- Celery JSON-only UUID, idempotency, leases, crash/reconcile, resource and no-network tests;
- RBAC six-role negative matrix, self-review denial, CSRF/Origin, IDOR, rate limits, and audit fail-closed tests;
- migration upgrade/downgrade/re-upgrade and immutable constraints;
- retention cleanup and rollback-predecessor protection;
- Docker health, non-root/read-only/cap-drop/no-host-network, Celery registration, and simulation-only OS-state checks;
- frontend lint/type/build/unit/accessibility and limitation/false-flag assertions;
- secret, large-file, dependency, SBOM/Trivy or documented equivalent, and native ARM64 scans.

## 18. Resource, performance, and reproducibility evidence

Every run records code commit, dependency lock/SBOM hash, feature/preprocessing/dataset/split/model/policy hashes, seed, thread settings, row counts, elapsed time, peak RSS, CPU, artifact size, and safe terminal status. Synthetic observations are not capacity or detection-performance claims.

The acceptance report must include measured host results for fit, validation, fusion, and cleanup. A failure to meet the proposed limits rejects the candidate or requires a measured reduction and owner approval; limits must not be raised silently.

## 19. Dependencies, assumptions, and deferred work

### Confirmed dependencies

- Published Gate 5S-C baseline and hosted CI success: satisfied.
- Accepted Gate 5S-A/B hashes and synthetic-only limitation: satisfied.
- Canonical flow/feature v1, deterministic rules, RBAC/audit, controlled artifacts, Celery/Redis/PostgreSQL, Docker health: existing.
- Sprint 5 Gate 5C registry/scoring is offline-only and has no active model state: required invariant.

### Assumptions

- Gate 5S-C reviewed synthetic candidate metadata may be referenced only by persisted offline jobs; it is not active or online.
- Synthetic benign-like rows are a software-contract normal reference, not a real-world baseline.
- Row-level assessment lineage may be stored for deterministic replay for 30 days without exposing it through ordinary APIs.
- Distinct System Administrator/Security Administrator accounts are the available technical separation in this solo project.

### Deferred work

- Real dataset acquisition and all publisher contact.
- Online inference/model activation and any live telemetry integration.
- Threat intelligence, asset-criticality enrichment, historical behavior, SHAP, MITRE, alert projection, incidents, reports beyond aggregate evidence, and prevention policy.
- Second anomaly algorithm, autoencoder, boosting, drift monitoring, feedback learning, automatic promotion, and real enforcement.

## 20. Decisions requiring owner approval

1. Approve the three-gate Sprint 6 boundary (6A anomaly, 6B fusion, 6C completion review).
2. Approve synthetic-only Gate 5S-A/B/C evidence as the sole Sprint 6 input and keep UNSW-NB15 acquisition blocked.
3. Approve the Isolation Forest baseline and the exact seed/estimator/sample/thread defaults.
4. Approve the declared normal population and whether target-sidecar selection is allowed only as governance metadata.
5. Approve score normalization anchors and validation 95th-percentile threshold policy, or specify alternatives.
6. Resolve the Isolation Forest ONNX operator/opset allowlist and reject-on-conversion-failure policy.
7. Approve the fusion weights, rounding, confidence formula, severity bands, category precedence, missing-source behavior, and optional strong-signature floor.
8. Approve whether restricted row-level assessment sidecars are retained for 30 days, or require aggregate-only persistence.
9. Approve the proposed `0009_sprint6_anomaly_ensemble` migration and downgrade-inventory refusal.
10. Approve the proposed permissions, creator/reviewer separation, and offline-only APIs/UI.
11. Approve the resource/time/artifact limits and the no-automatic-retry policy for fitting.
12. Approve the exact mandatory limitation text and machine-readable false-capability flags on every surface.
13. Confirm Sprint 6 must not create or mutate alerts, detections, incidents, rules, models' active state, or prevention records.

No unanswered decision is inferred as approval.

## 21. Major risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Synthetic scenario artifacts are learned as anomaly behavior | High | Frozen normal manifest, group/time split, leakage reports, no numeric claim, independent review |
| Anomaly score is presented as maliciousness/probability | High | Separate score/uncertainty fields, exact limitation, UI/report language tests |
| Fusion weights hide a strong or missing signal | High | Canonical formula, source coverage, evidence preservation, truth-table tests, owner-reviewed policy hash |
| Single-source confidence is overstated | High | Source-count cap, provenance completeness, agreement term, explicit uncertainty |
| Threshold/test leakage | High | Training-only fit, validation-only threshold, sealed-test-once audit, immutable hashes |
| Unsafe Isolation Forest serialization/runtime | Critical | ONNX closed policy, structural/hash/parity checks, no Python-object load, quarantine on failure |
| Artifact replacement/path traversal/resource exhaustion | High | Opaque refs, mode-0600 atomic files, size/shape/path/hash checks, bounded workers |
| Offline assessment reaches alerts or prevention | Critical | Sidecar-only contract, dependency guard, no alert/prevention imports/writes, OS capability scan |
| Native ARM64 dependency or supply-chain issue | Critical | Pinned versions, SBOM, Trivy/equivalent, pip-audit, no unresolved Critical/High findings |
| Stale/incompatible source silently changes score | High | Version/hash binding, explicit absent state, whole-batch rejection on mismatch |
| Row-level assessments leak sensitive context | High | No endpoint fields, restricted access, aggregate APIs, 30-day expiry, redaction tests |
| Solo reviewer separation is nominal | Medium | Distinct accounts, creator/reviewer checks, complete audit, limitation recorded |
| Scope expands into Sprint 7–9 | High | Explicit exclusions, migration/API boundaries, diff review, completion gate |

No Critical or High residual risk may be accepted silently; a completion report must name owner, evidence, review date, and disposition.

## 22. Proposed Sprint 6 acceptance criteria

Sprint 6 is complete only if every applicable criterion passes:

1. Published Gate 5S-C SHA/CI and clean-tree entry evidence is recorded.
2. Synthetic-only source and mandatory limitation/false flags are proven; UNSW acquisition and outreach remain blocked/cancelled.
3. Fixtures exist before detector/fusion implementation and contain no real data/model artifacts.
4. Anomaly contract, normal population, feature/preprocessor compatibility, score normalization, and threshold manifests are immutable and hash-bound.
5. Isolation Forest training is deterministic, bounded, training-only, and uses no target values as estimator input.
6. Threshold selection is validation-only; the sealed test is opened once for a locked evidence run and never retuned.
7. Anomaly artifact policy is closed, integrity-checked, ARM64-reviewed, and rejects unsupported ONNX/runtime behavior.
8. Fusion inputs/outputs are strict, versioned, transparent, and preserve all contributing evidence.
9. Risk, confidence, severity, category, uncertainty, and automation eligibility are deterministic and covered by golden truth tables.
10. Missing, stale, invalid, conflicting, and incompatible signals fail or degrade exactly as documented without fabricated evidence.
11. Assessment output cannot create/mutate alerts, detections, incidents, rules, prevention, or network state.
12. PostgreSQL migration upgrades, downgrades safely after inventory, and re-upgrades without orphaning prior metadata.
13. RBAC/CSRF/Origin, creator/reviewer separation, IDOR/redaction, audit, idempotency, retention, and cleanup tests pass.
14. JSON-only UUID Celery tasks, resource/time limits, crash reconciliation, no-network behavior, Docker security, and health gates pass.
15. Frontend quality/accessibility and exact limitation/false-capability assertions pass.
16. Formatting, linting, typing, unit/integration/security/dependency/secret/SBOM/container/fuzz/resource checks pass, with skips recorded honestly.
17. No Critical or High issue remains; no model is active or online; no real dataset, capture, prevention capability, commit, or publication is introduced.
18. `docs/SPRINT_6_COMPLETION_REPORT.md` records hashes, commands, results, limitations, failures/skips, and the final gate decision.

## 23. Implementation sequence after authorization

1. Reconfirm public baseline, hosted CI, and clean inherited diff; preserve history.
2. Update only the affected design/threat/risk/schema/API/test/deployment records required by the approved plan.
3. Create hostile/golden anomaly and fusion fixtures before implementation.
4. Add strict contracts, manifests, limitation flags, and permissions.
5. Add migration and controlled artifact/reconciliation interfaces.
6. Implement Gate 6A normal-population binding, Isolation Forest fit, normalization, threshold evidence, and parity checks.
7. Stop and review Gate 6A candidate hashes.
8. Implement Gate 6B signal adapters, deterministic fusion policy, assessments, aggregate evidence, APIs/UI, and tests.
9. Stop before any alert projection, model activation, online inference, real dataset use, or prevention work.
10. Run completion gates, update the completion report, review the complete diff, and stop uncommitted for approval.

## 24. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The proposed design follows the master prompt's separation of detection, assessment, policy, and enforcement; preserves the accepted synthetic-only Gate 5S-C boundary; and adds explicit anomaly/fusion stop gates. Implementation remains blocked until the owner approves the decisions in Section 20 and supplies the exact Sprint 6 authorization.

## 25. Exact Sprint 6 implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_6_IMPLEMENTATION_PLAN.md and begin AegisAI NIDPS Sprint 6 using its three-gate boundary: Gate 6A anomaly evidence, Gate 6B transparent fusion evidence, and Gate 6C completion review.

Before proceeding:
- Confirm public main contains Gate 5S-C publication commit 445b75009b6021da5020cce788e54082208a129e, CI stabilization commit 38fb0eda30c545de57d6d5c84399e93435982174, and publication documentation commit 9cc643dba4a9d15284eb1a812bf661f848a801ce.
- Confirm hosted CI Run #12 succeeded for 9cc643dba4a9d15284eb1a812bf661f848a801ce and the working tree contains only separately reviewed Sprint 5 changes plus this authorized Sprint 6 work.
- Read all governing documents, Sprint 5 plans/reports, and docs/SPRINT_6_IMPLEMENTATION_PLAN.md completely.
- Do not rewrite published history.

Use only the accepted synthetic Gate 5S-A/B/C evidence. Keep UNSW-NB15 acquisition blocked, publisher outreach cancelled, and the NUSW-NB15_features.csv/NUSW-NB15_GT.csv candidates excluded. Do not use real or third-party datasets, mirrors, tokenized links, samples, packets, PCAPs, payloads, or network downloads.

Approve these Sprint 6 defaults:
- Gate 6A/6B/6C boundaries as defined in the plan.
- Isolation Forest only for the first anomaly candidate, seed 20260714, 100 estimators, max_samples=min(256, training-reference rows), max_features=1.0, bootstrap=false, one numerical thread, and exactly the approved 39 float32 model features.
- A predeclared synthetic_benign_like training-only normal reference population, with target values removed before fitting and the exact identity/hash manifest audited.
- Training-only robust score anchors and one validation-only 95th-percentile threshold with minimum support; no test retuning and one sealed-test opening for the locked evidence run.
- ONNX plus canonical JSON only, the closed operator/opset policy, no external data/custom operators/dynamic shapes/Python-object artifacts, 16 MiB candidate limit, and reject-on-conversion/parity/integrity failure.
- Fusion sources signature 0.40, behavioral rule 0.30, supervised 0.20, anomaly 0.10; renormalized weighted mean over present valid sources; round-half-even risk 0–100; confidence formula, source-count cap, severity bands, category precedence, uncertainty codes, and missing-source behavior exactly as defined in the plan.
- No automatic strong-signature risk floor unless separately confirmed in the action-time review; no threat-intelligence, asset-criticality, historical-behavior, SHAP, incident, or prevention inputs.
- Additive reversible migration 0009_sprint6_anomaly_ensemble; distinct System Administrator creator and Security Administrator reviewer; JSON-only UUID Celery tasks; resource, timeout, retention, cleanup, audit, CSRF/Origin, and RBAC controls from the plan.
- Offline batch assessment sidecars and aggregate-only metadata APIs/UI only. No online endpoint, model activation, API/detection startup load, alert/detection/rule/incident/prevention mutation, or network state change.

Implement only Gate 6A, Gate 6B, and their tests/documentation. Create fixtures before detector/fusion code. Bind every artifact, threshold, policy, and assessment to the accepted Gate 5A/B/C hashes and exact feature/preprocessing/runtime hashes. Preserve the mandatory limitation text exactly:

SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. The model is offline-only and cannot create or modify alerts or prevention actions.

Every metric, artifact, manifest, report, API response, and UI view must carry that limitation and machine-readable false capability flags. Never claim real, production, zero-day, or prevention effectiveness.

Do not acquire/contact/download/read any real dataset; fit on test data; retune after test opening; activate/load a model online; create predictions through an online endpoint; mutate alerts, detections, rules, incidents, or prevention; configure live capture; add firewall integration; use privileged containers, host networking, firewall capabilities, or enforcement dependencies; begin Sprint 7 or later; commit; or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, preprocessing-parity, threshold/test-isolation, fusion-truth-table, leakage, artifact-integrity/operator, migration, RBAC-negative-matrix, CSRF/Origin, audit, idempotency, resource, retention, Docker, Celery, frontend, accessibility, dependency, SBOM/Trivy or documented equivalent, secret, large-file, health, and simulation-only checks. Stop at the uncommitted Gate 6C completion gate and wait for separate owner review/publication approval.
```
