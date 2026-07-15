# Sprint 5 Implementation Plan — Supervised ML, Registry, and Offline Scoring

**Planning date:** 2026-07-14

**Status:** Planning only; owner approval required

**Target:** Sprint 5 — supervised model training, evaluation, registry, and controlled offline scoring

**Release boundary:** Sprints 0–9, IDS with simulated IPS

**Authorized baseline:** public `main` at `72c97b15f9bb31ddb6810a397afc682893497bab`

## 1. Entry gate and publication evidence

The Sprint 5 planning entry gate is satisfied:

- Local `HEAD`, local `main`, and recorded `origin/main` resolve to `72c97b15f9bb31ddb6810a397afc682893497bab`.
- Public GitHub Actions Run #7 (`29332025235`) completed successfully for that exact SHA.
- Its backend, frontend, and container jobs passed.
- The working tree was clean before the authorized Sprint 4 publication-documentation updates and this plan.
- Sprint 4 is recorded as `APPROVED` in its completion report.

This task is documentation-only. It does not authorize a dataset transfer, parser or adapter implementation, migration, training, serialization, model loading, registry mutation, prediction, scoring, dependency installation, commit, or publication.

## 2. Governing documents read completely

This plan is reconciled against the complete contents of:

- `AegisAI-NIDPS-Master-Prompt.md`
- `AegisAI-NIDPS-Implementation-Guide.md`
- `docs/SPRINT_4_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_4_COMPLETION_REPORT.md`
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

## 3. Confirmed requirements

These are already approved requirements rather than Sprint 5 choices:

1. The first release ends at Sprint 9 and remains an IDS with simulated IPS.
2. Supervised ML supplies versioned evidence; it cannot authorize or invoke prevention.
3. Training and inference are separate components and use the same immutable feature/preprocessing contracts.
4. Feature schema v1 is canonical flow v1 only, with 39 ordered model features: 17 direct and 11 for each inclusive 60/300-second event-time window.
5. The 7 reserved Parquet provenance columns are not model inputs.
6. Labels, attack categories, row IDs, raw endpoint identities, exact timestamps, sensor/job/event IDs, split names, detection results, alerts, risk, confidence, incident data, and prevention data remain prohibited model values.
7. Dataset, source terms, files, mappings, quality reports, leakage reviews, splits, preprocessing, experiments, models, metrics, thresholds, and artifacts are immutable/versioned and traceable.
8. Preprocessing, category vocabularies, statistics, sampling, calibration fitting, and selection fit on training data only.
9. Validation is used for candidate selection and threshold decisions. The final test partition remains untouched until one final locked-candidate evaluation.
10. Evaluation reports per-class precision, recall, F1 and support; macro/weighted metrics; confusion matrix; false-positive/negative rates; PR-AUC; meaningful ROC-AUC; calibration; latency; throughput; memory; and artifact size.
11. A model must fail closed when its dataset, split, feature schema, preprocessing manifest, runtime, or artifact integrity is missing or incompatible.
12. Model promotion and rollback require centralized authorization, complete audit, immutable lifecycle records, and an available compatible predecessor.
13. PostgreSQL is authoritative. Redis is coordination only. Celery tasks carry JSON-only bounded UUIDs.
14. Controlled artifacts use opaque local-volume references with SHA-256 metadata in PostgreSQL. Paths and artifact bytes are not ordinary API inputs or outputs.
15. Raw datasets, derived matrices, model binaries, PCAPs, secrets, and private telemetry never enter Git.
16. Repository code is MIT licensed; dataset rights remain separate. Intended use is academic/portfolio only.
17. UNSW-NB15 is only a primary candidate. Current metadata has `acquisition_authorized=false` and no files.
18. The approximately 100 GB UNSW-NB15 raw PCAP is excluded.
19. No live capture, privileged container, host networking, firewall capability, enforcement dependency, or real prevention is allowed.
20. Stored predictions expire after 30 days; exceptional investigation holds are disabled for the MVP.

## 4. Planning findings and blockers

### 4.1 Dataset acquisition is still unauthorized

Sprint 4 investigated only the official publisher page. No file, checksum, prepared schema, label distribution, mapping, or split has been verified locally. The metadata-only seed cannot be changed into an acquired dataset: a new immutable dataset version and explicit owner authorization are required.

### 4.2 Dataset compatibility is unproven

UNSW-NB15's published columns are not automatically canonical flow v1. Training is blocked unless the selected official tabular files provide trustworthy source/destination endpoints, paired ports, protocol, duration, packet/byte totals, connection state, event time, and grouping/capture provenance needed to reproduce all 39 features. Missing window context cannot be replaced silently with zeros.

### 4.3 Safe model serialization decision D-13 is unresolved

Arbitrary pickle and joblib loading are prohibited. Sprint 5 implementation must approve a non-executable serving format, a closed runtime/operator policy, compatibility metadata, integrity verification, and rollback behavior before any model artifact is written or loaded.

### 4.4 The development host requires strict ML limits

The approved Apple M2 host has 8 CPU cores, 8 GB RAM, ARM64, and approximately 300 GiB free at the original approval. Dataset processing and training cannot assume x86 wheels, unbounded pandas frames, all-core training, or full-dataset in-memory operation.

### 4.5 Model quality cannot be guaranteed in planning

No numeric detection-performance claim is approved before acquisition, mapping, leakage review, and measured evaluation. Sprint 5 can complete with every candidate rejected from activation if quality, safety, compatibility, or resource gates fail.

### 4.6 Existing dataset governance needs a staged workflow

The safe order is acquisition authorization → transfer and manifest → bounded quality/mapping/leakage analysis → owner dataset acceptance → split freeze → training authorization → evaluation → model review → optional offline activation. Dataset acceptance cannot be inferred from successful download or parsing.

## 5. Sprint 5 scope

### 5.1 Included only after separate authorization

1. A controlled operator-only acquisition workflow for explicitly named official UNSW-NB15 tabular/documentation files.
2. Immutable file, dataset, mapping, quality, leakage, and split manifests.
3. A strict dataset adapter producing canonical flow v1 plus separately typed label/group provenance.
4. Streaming/chunked profiling and deterministic feature materialization using feature schema v1.
5. Training-only fitted preprocessing and an immutable preprocessing manifest.
6. Majority-class reference, Logistic Regression baseline, and Random Forest candidate.
7. Optional single gradient-boosting candidate only after dependency review and measured justification.
8. Reproducible, resource-bounded Celery training/evaluation jobs.
9. Binary intrusion classification as the proposed release target; multiclass attack-category evaluation as a separately reported research target.
10. Validation-only candidate selection, calibration, and threshold selection, followed by one locked final test evaluation.
11. Canonical experiment manifests, evaluation reports, error analysis, and model cards.
12. Safe ONNX serving artifacts under a closed operator/runtime policy, subject to owner approval of D-13.
13. PostgreSQL model registry, review, activation, retirement, and rollback metadata.
14. Controlled offline batch scoring of approved feature artifacts only.
15. Reversible migration `0005_sprint5_ml`, minimal APIs/UI, RBAC, audit, cleanup, tests, and documentation.

### 5.2 Explicitly excluded

- Raw UNSW-NB15 PCAP or any packet-capture acquisition.
- Mirrors, Kaggle, user-provided URLs, search-result downloads, torrents, or unofficial repackaging.
- Live packet capture or interface monitoring.
- Online request-time scoring, streaming scoring, automatic alert generation, risk fusion, anomaly detection, ensemble logic, SHAP, intelligence, incidents, or Sprint 6+ work.
- Model-driven rule changes, alert dispositions, prevention recommendations, or prevention eligibility.
- Auto-training, auto-tuning against test data, auto-promotion, or auto-rollback decisions based only on metrics.
- Deep learning, autoencoders, neural-network frameworks, distributed training, GPU dependencies, ML notebooks in runtime paths, arbitrary custom estimators, dynamic imports, or executable model code.
- Pickle/joblib/cloudpickle/dill model artifacts, untrusted `skops` types, ONNX custom operators, external tensor data, or arbitrary model upload.
- Dataset rows, feature rows, labels tied to endpoints, artifact paths, or model bytes in the normal UI/API.
- Real prevention, privileged containers, host networking, firewall integration, commit, or publication without separate approval.

## 6. Staged Sprint 5 gates

Sprint 5 must be executed as two separately approved phases.

### Phase 5A — acquisition, mapping, quality, and split evidence

1. Revalidate the official source and current terms.
2. Obtain owner authorization naming exact files, expected sizes, source, limits, storage, intended use, and retention.
3. Acquire only those files into controlled storage.
4. Generate file and dataset manifests before parsing.
5. Profile in bounded chunks and validate the canonical mapping.
6. Produce quality, label, duplicate, relationship, and leakage reports.
7. Propose and verify a deterministic split manifest.
8. Stop for explicit dataset acceptance.

Phase 5A cannot fit preprocessing, train, serialize, register, load, activate, or score a model.

### Phase 5B — training, evaluation, registry, and offline scoring

Phase 5B begins only after the owner approves the exact dataset/mapping/quality/leakage/split hashes and resolves D-13. It implements the fixed preprocessing/training/evaluation/registry/scoring scope, then stops at an uncommitted Sprint 5 completion gate.

This staged boundary prevents a successful download from becoming implicit authority to train.

## 7. Official UNSW-NB15 source and terms revalidation

The currently recorded official page is:

`https://research.unsw.edu.au/projects/unsw-nb15-dataset`

The 2026-07-14 publisher-only review records academic research use, required citation, author agreement for commercial use, no repository redistribution authority, and an excluded raw PCAP. These facts must be revalidated immediately before acquisition because terms and access paths may change.

Required procedure:

1. Access the official UNSW page directly over HTTPS.
2. Follow only publisher-controlled links reached from that page; record every redirect host before transfer.
3. Record retrieval time, page title, publisher, page revision if shown, advertised filenames/sizes, access instructions, citations, and terms text/reference.
4. Hash a legally permissible local text/PDF evidence snapshot or a normalized terms summary.
5. Compare it with `docs/data/UNSW_NB15_OFFICIAL_SOURCE_REVIEW_2026-07-14.md` and `docs/DATASET_REVIEW_UNSW_NB15.md`.
6. Any changed, ambiguous, authentication-gated, or commercial-use term blocks transfer pending owner/legal clarification.
7. Confirm the work remains academic/portfolio only, code/data licensing stays separate, citation is mandatory, redistribution is not authorized, and raw PCAP remains excluded.
8. Record when the publisher does not provide checksums; never invent an upstream checksum. Compute local SHA-256 immediately during transfer.
9. Never place browser cookies, access tokens, SharePoint session URLs, or query credentials into manifests, logs, shell history, audit, or Git.

## 8. Proposed prepared-file selection

The proposed initial acquisition is the official full tabular source needed to construct an independent leakage-aware split, not the approximately 100 GB PCAP and not unofficial mirrors.

Candidate logical files, whose exact current official names and advertised sizes must be copied into the Phase 5A authorization prompt, are:

1. The four official principal UNSW-NB15 tabular CSV data parts commonly identified as parts 1–4.
2. The official feature-description/data-dictionary file.
3. The official event/ground-truth listing only if required to establish label provenance and capture grouping.

The publisher-prepared training/test CSV pair is not proposed as the authoritative split because its relationship leakage and grouping semantics have not been proven. It may be recorded as a comparison artifact only under a separately named authorization, and it must never override the project split manifest.

If the current official page does not expose the exact expected tabular files, or if the files lack fields required for canonical flow v1 and 60/300-second windows, acquisition or training stops. No substitute dataset or mirror is selected automatically.

## 9. Download, storage, extraction, and deletion limits

Proposed Phase 5A defaults:

| Control | Proposed limit/policy |
|---|---|
| Source | Exact official HTTPS URL and publisher-controlled redirect hosts only |
| Combined transfer bytes | 5 GiB hard maximum |
| Single file | 2 GiB hard maximum |
| File count | 10 maximum |
| Redirects | 5 maximum; HTTPS only; no downgrade |
| Connection/idle timeout | 30/120 seconds |
| Whole-file deadline | 30 minutes |
| Retries | 2 after the initial attempt; no resume across changed ETag/size |
| Free-space preflight | At least 3× declared transfer size plus a protected 50 GiB reserve |
| Staging | Opaque mode-0600 files under the controlled artifact volume, outside Git |
| Hash | Streaming SHA-256 during transfer and before every later read |
| Media/schema | Content and strict tabular-schema validation; filenames are metadata only |
| Archives | Disabled by default for the initial authorization |
| Network after acquisition | Training and scoring jobs perform no outbound fetch |

If an archive is the only current official distribution, Phase 5A must stop for a revised authorization. Proposed revised extraction ceilings are 10 GiB expanded bytes, 25 regular files, depth 1, compression ratio 20:1, 30-minute deadline, no links/devices/FIFOs, no absolute or parent paths, and no nested archives.

Raw official files are proposed to remain controlled through Sprint 5 review/publication and no longer than 90 days after acquisition without renewed owner approval. Rejected or superseded temporary files are deleted immediately. Derived feature matrices expire after 30 days unless an approved reproducibility package names them. Governance manifests, hashes, terms evidence, reports, cards, and audit lineage are retained by version without raw rows.

## 10. Dataset manifest and acceptance lifecycle

A newly acquired dataset is a new immutable `dataset_versions` row; the Sprint 4 metadata-only row remains unchanged.

Lifecycle:

`proposed -> acquired -> profiled -> mapping_reviewed -> accepted | rejected -> retired`

Required manifest fields:

- official source and redirect provenance;
- terms/citation hashes and restrictions;
- authorized actor, approval reference, acquisition timestamp/method;
- exact official and opaque local file identities, sizes, media types, SHA-256, and status;
- schema/header/encoding/delimiter evidence;
- capture environment, generation tools, time coverage, labels, known errors, and limitations;
- adapter version/hash and feature schema compatibility;
- row counts, class distribution, missing/invalid/outlier/duplicate summaries;
- relationship/leakage report and split manifest hashes;
- code commit, dependency/runtime versions, reviewer, decision, and timestamps.

Acquired does not mean accepted. Acceptance requires an audited Security Administrator decision after mapping, quality, leakage, and split evidence exists. The acquisition actor cannot accept the same dataset under the proposed separation policy.

## 11. Canonical-flow mapping and compatibility review

The adapter produces two separate immutable types:

```text
DatasetFlowExample {
  canonical_flow: CanonicalFlowV1,
  dataset_identity_hash,
  capture/group provenance,
}

DatasetTarget {
  dataset_identity_hash,
  binary_label,
  attack_category,
  label_source,
}
```

The target object never enters `FeaturePipeline`.

Every selected official column requires a mapping record containing source name, documented meaning, unit, type, direction, missing policy, transformation, canonical destination, inference availability, and reviewer disposition. At minimum, compatibility must prove:

- trustworthy event time and stable ordering;
- canonical source/destination IPs used only for grouping/provenance;
- paired source/destination ports;
- protocol normalization;
- duration conversion to integer milliseconds without silent unit assumptions;
- packet and byte totals with explicit directional aggregation and overflow checks;
- connection state semantics or explicit missing state;
- capture/sensor scope needed to prevent unrelated context mixing;
- label and attack category separated before feature transformation.

The dataset is incompatible with feature schema v1 if any required direct feature or window context cannot be reproduced faithfully. Unsupported publisher-generated features are ignored rather than renamed into Aegis features. No label-derived, post-event, generator-ID, split, or row-order value may enter a vector.

## 12. Quality, poisoning, and leakage analysis

Phase 5A produces `docs/data/UNSW_NB15_QUALITY_<manifest-hash>.md` and `docs/data/UNSW_NB15_LEAKAGE_<manifest-hash>.md` containing measured facts and separately labeled interpretations.

Required analysis:

1. File/header/schema consistency and mapping coverage.
2. Row counts and exact label/category distribution.
3. Missing, malformed, non-finite, negative, overflow, range, and unknown-category counts.
4. Exact duplicate raw identities, canonical flows, feature vectors, and label conflicts.
5. Near-duplicate/session relationships where a deterministic method is defensible.
6. Endpoint, time, capture, file, generator, session, and event relationships.
7. Capture artifacts or fields that identify attack generation rather than behavior.
8. Cross-file distribution shifts and label/time inconsistencies.
9. Feature quality flags, rate clipping, zero denominators, and unseen categories.
10. Candidate split cross-partition duplicate/group leakage.
11. Exclusions with stable reason codes and counts; no silent row deletion.
12. Poisoning indicators, ambiguous labels, residual limitations, reviewer, and decision.

Any unresolved label conflict, cross-partition duplicate, missing required mapping, unbounded category, terms ambiguity, or integrity mismatch blocks dataset acceptance.

## 13. Immutable split design

Proposed order of preference:

1. Capture/group plus time-aware split.
2. Endpoint-group plus time-aware split.
3. Capture/file-group split with chronological boundaries.
4. Random stratified split only if relationship analysis proves no related identities can cross partitions and the owner explicitly accepts the residual risk.

Proposed proportions are 70% training, 15% validation, and 15% untouched test by eligible groups/time, adjusted only to preserve meaningful class support. The split manifest records deterministic rules, grouping keys, boundaries, exclusions, counts, class summaries, ordered identity hashes, code version, and SHA-256.

Required invariants:

- no exact canonical identity or feature-vector hash crosses partitions;
- no approved grouping identity crosses partitions;
- split assignment occurs before fitted preprocessing or sampling;
- validation/test labels are used only for evaluation, never fitting;
- the final test set remains sealed until a candidate/configuration/threshold hash is locked;
- opening the test set creates an immutable audit event; a second test evaluation requires a new dataset/split/model version and owner review.

## 14. Feature and preprocessing compatibility

Feature schema is fixed to `flow_features/1.0.0` and its exact definition hash from Sprint 4. Dataset materialization must use the shared `aegis_services.features` package without a dataset-only feature path.

The fitted preprocessing manifest records:

- feature schema ID/hash and ordered 39 names;
- split manifest and training-partition identity hash;
- missing/unknown tokens;
- every learned vocabulary/statistic and its source count;
- categorical encoding and output column order;
- numeric conversion/scaling/clipping/dtype;
- class/sampling configuration when part of the training pipeline;
- library/runtime versions, canonical JSON hash, creator, and audit reference.

Proposed preprocessing defaults:

- continuous/rate/count values: training-only robust scaling for Logistic Regression; no scaling for Random Forest unless measured necessary;
- booleans: stable 0/1;
- categories: fixed schema vocabulary with reserved missing/unknown tokens, then one-hot encoding with immutable order;
- output dtype: float32 only as an explicit preprocessing-output contract; fit-free vectors remain their Sprint 4 typed values;
- no feature selection, PCA, target encoding, hash encoding, or test-derived clipping;
- fail closed on feature order/hash mismatch, missing transform state, non-finite output, unexpected output width, or unknown runtime contract.

Golden training and offline-scoring entry points must produce identical transformed matrices for the same frozen vectors and preprocessing manifest.

## 15. Baselines and candidate models

### 15.1 Reference

- Majority-class and prevalence-only reference metrics.
- Existing deterministic rule results are reported separately and never used as labels or model features.

### 15.2 Logistic Regression baseline

- scikit-learn Logistic Regression with fixed seed/configuration.
- `class_weight=balanced` proposed initially.
- L2 regularization; validation chooses from a small predeclared `C` grid.
- This is the interpretability, calibration, latency, and complexity baseline.

### 15.3 Random Forest candidate

- Fixed seed, bounded depth/trees/features, `class_weight=balanced_subsample`, and at most two worker threads.
- Small predeclared validation grid; no unconstrained search.
- Must materially improve validation macro-F1/PR-AUC or error tradeoff over Logistic Regression to justify its larger artifact/runtime cost.

### 15.4 Optional boosting candidate

XGBoost or LightGBM is deferred by default. At most one may enter Sprint 5 only after an ARM64/native dependency, license, serialization, SBOM, memory, and measured-value review. It cannot replace the required Logistic Regression and Random Forest evidence.

### 15.5 Target policy

Proposed release target is binary `benign` versus `intrusion`. Multiclass attack-category metrics are required research evidence when labels are adequate, but multiclass activation is deferred unless every category has sufficient independent test support and acceptable error behavior. Unknown/ambiguous labels are excluded with recorded reasons, never relabeled opportunistically.

## 16. Reproducible and resource-bounded training

A dedicated optional `trainer` Compose profile is proposed so training cannot starve ingestion/detection workers. It has no published port, no privileged/host network, a read-only root, controlled artifact mounts, and outbound network disabled after acquisition.

Proposed host-aware limits:

| Control | Default |
|---|---|
| Trainer memory | 4 GiB hard limit |
| Trainer CPU | 2 cores |
| PIDs | 128 |
| Threads per numerical library/model | 2 maximum |
| Input chunk | 25,000 rows |
| Logistic Regression training rows | 500,000 maximum after deterministic training-only sampling |
| Random Forest training rows | 250,000 maximum after deterministic training-only sampling |
| Random Forest trees/depth | 300 / 20 maximum |
| Parameter configurations | 12 per algorithm maximum |
| Concurrent training jobs | 1 |
| Soft/hard time | 2,400 / 2,700 seconds per candidate job |
| Candidate model artifact | 128 MiB maximum |
| Preprocessing artifact | 32 MiB maximum |
| Evaluation output | 16 MiB maximum; aggregate/sanitized |
| Retries | 0 for fitting; one explicit idempotent owner retry after failure review |

Sampling, if required, is deterministic, group-aware, and applied only to the training partition. Validation and test are never resampled. Each run captures random seeds, thread/environment controls, parameters, input hashes, elapsed time, peak RSS, CPU, row counts, dependency lock hash, code commit, and status.

## 17. Imbalance, calibration, and threshold policy

1. Report original class prevalence before any weighting or sampling.
2. Use class weights as the proposed first control.
3. Do not use SMOTE or synthetic examples by default; any later sampler fits inside training folds only and requires separate evidence.
4. Hyperparameters are selected on training/validation only.
5. Probability calibration uses training-only cross-validation with sigmoid calibration by default. Isotonic calibration requires sufficient independent calibration support and explicit justification.
6. Decision threshold is selected once on validation under the approved cost/quality policy, then frozen in the model manifest.
7. Test-set probabilities are evaluated at that frozen threshold without retuning.
8. Calibration and thresholds are model-version fields. Activation never changes them in place.

Proposed binary staging targets, subject to owner approval and dataset support:

- intrusion recall at least 0.80;
- benign false-positive rate at most 0.02;
- macro-F1 at least 0.70;
- PR-AUC reported against class prevalence and better than the prevalence reference;
- no material calibration failure hidden by thresholding;
- no unexplained subgroup/capture collapse;
- candidate complexity justified over Logistic Regression.

Failure to meet a target rejects activation but does not justify changing the test threshold or hiding the result.

## 18. Evaluation and error analysis

Every candidate report includes:

- dataset, files, split, feature, preprocessing, experiment, model, runtime, and code hashes;
- reference, training, validation, and one final test results clearly separated;
- per-class precision/recall/F1/support;
- macro/micro/weighted F1 as applicable;
- PR-AUC per relevant class and macro aggregate;
- ROC-AUC only when class support and interpretation make it meaningful;
- confusion matrix, false-positive rate, false-negative rate, specificity, and balanced accuracy;
- Brier score and bounded reliability/calibration view;
- selected threshold and validation-only selection rationale;
- latency distributions, throughput, peak RSS/CPU, and artifact sizes on the approved host;
- bootstrap confidence intervals when group-aware resampling is statistically defensible;
- failed/abstained/incompatible input counts;
- comparison against references and complexity costs.

Error analysis groups false positives and negatives by attack category, capture/file/time, protocol, service/port class, missingness/unknown state, quality flag, duration/rate band, and score band. Raw endpoint values are not published. Small groups are suppressed or aggregated to avoid privacy leakage and misleading rates.

No report may claim zero-day, production, enterprise, or real-world detection effectiveness from UNSW-NB15 alone.

## 19. Model card and artifact manifest

Each candidate produces immutable canonical JSON plus an analyst-readable Markdown model card under `docs/model-cards/` only after redaction review.

Required fields:

- model name/version/purpose/algorithm and lifecycle;
- intended academic/offline use and prohibited production/prevention use;
- dataset/source/terms/citation/manifest and split hashes;
- feature/preprocessing contract hashes and ordered input/output shapes;
- class definitions, prevalence, exclusions, and sampling/weights;
- parameters, seeds, runtime/dependency versions, code commit, and training resource evidence;
- validation/test metrics, calibration, threshold, confidence intervals, and error analysis;
- fairness/coverage limitations by traffic/capture/class;
- known failure modes, abstention/incompatibility behavior, monitoring needs, and security assumptions;
- artifact kind, byte size, SHA-256, ONNX opset/operator allowlist, runtime version, and signature status;
- reviewer, approval evidence, activation history, rollback predecessor, retention, and retirement reason.

Cards never contain raw rows, endpoints, internal paths, credentials, or unsupported claims.

## 20. Proposed D-13 safe serialization decision

Proposed default: use ONNX for the complete fitted preprocessing-plus-classifier serving artifact and canonical JSON for all manifests. Do not persist or load Python estimator objects in API/worker runtime.

Required ONNX controls:

- artifacts are created internally from an approved training run; no user upload/import endpoint;
- fixed supported opset and closed operator/domain allowlist;
- custom operators, Python callbacks, external tensor files, remote references, and dynamic libraries are prohibited;
- artifact maximum 128 MiB and bounded input/output tensor shapes;
- `onnx.checker`, structural policy validation, SHA-256, and a fresh-process inference smoke test before registration;
- ONNX Runtime is version-pinned, dependency-audited, thread-limited, and reviewed for ARM64 availability;
- conversion parity is measured against the in-process training pipeline on golden, validation, missing/unknown, boundary, and random samples;
- maximum absolute/probability tolerance is versioned; class/threshold decisions must match exactly on the regression suite;
- runtime verifies manifest/hash/feature/preprocessor/operator compatibility before session creation;
- model load occurs only in the isolated offline-scoring worker, never during API import/startup;
- the last compatible active artifact remains available until rollback evidence passes.

If ONNX conversion or parity fails, the model is not registrable. The fallback is to reject that candidate and reconsider a safe format in a new owner-reviewed plan—not to use pickle/joblib.

## 21. Registry lifecycle, activation, and rollback

Lifecycle:

`candidate -> reviewed -> staged -> active -> retired | rejected | quarantined`

Rules:

1. Model definition/artifact/metrics/card fields are immutable.
2. Only one active supervised model exists per declared purpose and feature contract.
3. Registration verifies every referenced manifest and artifact hash.
4. Review verifies quality, leakage, card, security, compatibility, and conversion parity.
5. Activation uses expected-current locking and records the prior active version.
6. Activation changes registry state only; it does not start online inference, create alerts, change rules, or affect prevention.
7. Rollback selects an already reviewed compatible version and is idempotent/audited.
8. Corrupt or incompatible artifacts become quarantined and cannot activate.
9. Retired metadata is retained; artifact cleanup cannot remove the active model or required rollback predecessor.

Proposed separation of duties: a System Administrator/training operator requests a run; a distinct Security Administrator reviews the dataset/model and may stage/activate it. The creator cannot review or activate its own model. For this solo project, distinct accounts rather than distinct people satisfy the technical test boundary, with the limitation documented.

## 22. Offline batch scoring boundary

Sprint 5 scoring accepts only:

- an active model version;
- an available controlled Sprint 4 feature artifact;
- matching feature schema, preprocessing, source snapshot, shape, and hashes;
- a persisted idempotent scoring-job UUID.

The scorer:

1. verifies DB lifecycle and RBAC-authorized request provenance;
2. verifies artifact paths through opaque references and SHA-256;
3. loads the approved ONNX session under resource/operator limits;
4. transforms using the exact preprocessing contract or consumes the approved exported pipeline input contract;
5. scores in bounded chunks;
6. stores class, bounded probabilities, model/feature/preprocessing/source versions, latency, and 30-day expiry;
7. records aggregate metrics and safe error codes;
8. never creates or changes an alert, rule, risk score, incident, or prevention record.

The API/UI expose aggregate scoring status and individually authorized prediction metadata only when required. They never expose raw feature rows, endpoints, artifact references, paths, or arbitrary model inputs. Online/streaming scoring is deferred until a later contract and load/privacy review.

## 23. Artifact retention and integrity

Proposed retention:

| Artifact | Retention |
|---|---|
| Download staging/failed partial | Immediate deletion; safety cleanup within 24 hours |
| Authorized raw UNSW tabular files | Through Sprint 5 review, maximum 90 days without renewal |
| Dataset feature matrices | 30 days unless named by an approved reproducibility package |
| Candidate/rejected model artifact | 30 days after final decision |
| Staged/active model artifact | While staged/active |
| Rollback predecessor | While needed plus 180 days after replacement |
| Other retired model artifact | 180 days after retirement, then reviewed cleanup |
| Predictions | 30 days |
| Manifests, metrics, cards, audit, hashes | Retained by version under governance/audit policy |

Every write is mode-0600 staging plus atomic rename. Every read verifies UUID-derived path, expected media type, byte cap, SHA-256, lifecycle, and compatibility. Integrity failure quarantines the artifact, fails scoring safely, audits a stable code, and never falls back silently to a different model.

## 24. Proposed PostgreSQL migration `0005_sprint5_ml`

The migration should add metadata and bounded prediction records only:

1. `dataset_artifacts` — immutable dataset version/file identity, opaque reference, media type, size, SHA-256, role, retention, status.
2. `dataset_mapping_reviews` — dataset/feature schema, adapter/hash, field mapping artifact, coverage, decision, reviewer, audit provenance.
3. `training_runs` — dataset/split/feature/preprocessor references, algorithm/config hash, requester, idempotency key, status, resource counts, safe error, timestamps.
4. `model_versions` — immutable purpose/version/algorithm, ONNX artifact metadata, dataset/split/feature/preprocessor/runtime/card hashes, threshold, lifecycle, creator/reviewer.
5. `model_metrics` — immutable model/split/class/metric/value/context identity with uniqueness constraints.
6. `model_activations` — append-only stage/activate/retire/rollback history, actor, expected/prior version, reason/evidence, time.
7. `scoring_jobs` — requester, model/feature artifact, idempotency key, status/counts/safe error/timestamps.
8. `predictions` — scoring job, stable source-event provenance, model/feature/preprocessor hashes, class, bounded probability JSON, latency, expiry.
9. Sprint 5 permissions and role grants.

`dataset_split_versions` and governance records from Sprint 4 are reused rather than duplicated.

Required database constraints include unique semantic/model/config hashes, one active version per purpose, expected-active transactional locking, immutable artifact/model/metric fields, valid lifecycle transitions, creator/reviewer separation, bounded probabilities/counts/text, prediction expiry, one actor/idempotency scope, lineage foreign keys, and no path/raw row/label payload.

Downgrade refuses while active/staged models, required rollback artifacts, or predictions remain. After explicit inventory/export/delete/retire actions, it removes only Sprint 5 tables/permissions and preserves Sprints 0–4. Fresh upgrade, existing-data upgrade, downgrade, re-upgrade, lock behavior, artifact-inventory refusal, and PostgreSQL immutability tests are mandatory.

## 25. RBAC and audit

Proposed permissions:

| Permission | Purpose | Roles |
|---|---|---|
| `models:read` | View safe registry/cards/metrics/job metadata | SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `models:train` | Request bounded approved training/evaluation | System Admin, Security Admin |
| `models:review` | Approve/reject candidate evidence | Security Admin |
| `models:activate` | Stage/activate/retire/rollback reviewed models | Security Admin |
| `models:score` | Request controlled offline scoring | Senior Analyst, Security Admin, System Admin |
| `predictions:read` | View authorized prediction metadata/aggregates | SOC Analyst, Senior Analyst, Security Admin, Auditor |
| `datasets:acquire` | Execute named operator acquisition plan | System Admin only; operator/CLI, no browser URL input |
| `datasets:accept` | Accept/reject acquired dataset evidence | Security Admin, distinct from acquisition actor |

Every dataset terms check, authorization, transfer attempt, hash result, mapping/quality/leakage/split decision, training request/start/success/failure, test opening, registration/rejection/quarantine, review, activation/retirement/rollback, scoring request/success/failure, integrity mismatch, and cleanup is audited.

Audit metadata contains IDs, hashes, versions, aggregate counts, reason/evidence references, and safe outcomes. It excludes URLs with credentials, local paths, raw rows, endpoint-linked labels, full probability arrays, exceptions, and secrets. Dataset acceptance, model review, activation, and rollback fail closed if audit persistence fails.

## 26. Celery responsibilities and failure recovery

Proposed registered tasks:

- `ml.profile_dataset(job_id)` — Phase 5A bounded chunk profiling after acquisition.
- `ml.materialize_dataset(job_id)` — accepted dataset to controlled feature matrix.
- `ml.train_candidate(run_id)` — one fixed algorithm/config, no network, no automatic retry.
- `ml.evaluate_candidate(run_id)` — validation or one authorized final test evaluation.
- `ml.validate_artifact(model_id)` — ONNX/operator/hash/parity smoke validation.
- `ml.score_batch(scoring_job_id)` — offline bounded feature-artifact scoring.
- `ml.reconcile()` — re-enqueue stale pending and reclaim safely stale processing jobs using leases/hard-limit evidence.
- `ml.cleanup()` — retention-selected artifact/prediction cleanup with audit.

Messages contain one UUID only. Tasks reject rows, labels, parameters, paths, URLs, artifact bytes, class objects, import names, serialized Python, credentials, and arbitrary task names.

Jobs persist before dispatch, use actor-scoped idempotency, late acknowledgment, prefetch 1, explicit resource/time limits, safe terminal codes, and authoritative state transitions. Fit jobs do not retry automatically because repeated nondeterministic resource failure can waste or duplicate work. A crash before/after artifact move is reconciled through staging identity, DB row locks, leases, and orphan inventory; an existing successful artifact is never overwritten.

## 27. Minimal APIs

Proposed routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `GET /training-runs` and `/{id}` | Safe run status/config/provenance | `models:read`, bounded page, no paths/rows |
| `POST /training-runs` | Request approved bounded run | `models:train`, CSRF+Origin, idempotency, accepted dataset/split/schema only |
| `GET /models` and `/{id}` | Registry/card/compatibility metadata | `models:read`, safe fields |
| `GET /models/{id}/metrics` | Versioned aggregate metrics | `models:read`, bounded class/metric list |
| `POST /models/{id}/review` | Approve/reject candidate | `models:review`, creator separation, reason/evidence, CSRF+Origin, audit |
| `POST /models/{id}/activate` | Activate reviewed compatible model | `models:activate`, expected-current, CSRF+Origin, audit |
| `POST /models/{id}/retire` | Retire active/staged model | `models:activate`, expected state, reason, audit |
| `POST /models/{id}/rollback` | Restore reviewed predecessor | `models:activate`, expected-current, idempotency, audit |
| `POST /scoring-jobs` | Score approved feature artifact offline | `models:score`, CSRF+Origin, idempotency, compatibility gate |
| `GET /scoring-jobs` and `/{id}` | Status/counts/safe failure/aggregate | `models:read`, bounded page |
| `GET /predictions` | Bounded authorized prediction metadata | `predictions:read`, strict time/job filters, no raw vector/address |

There is no dataset URL-fetch endpoint, model upload/download endpoint, arbitrary model registration, raw data/vector preview, online prediction endpoint, alert-generation endpoint, or prevention integration.

## 28. Minimal supporting UI

Add one authenticated ML area with:

- training-run status and immutable configuration/provenance hashes;
- candidate/staged/active/retired model list;
- model card summary, intended/prohibited use, dataset/split/feature/preprocessor versions;
- validation/test metrics, confusion matrix, calibration summary, latency/memory/artifact size, and limitations;
- authorized review/activate/retire/rollback controls with reason, expected-state confirmation, and CSRF/Origin;
- offline scoring request from an available compatible feature artifact;
- scoring status and aggregate prediction counts;
- explicit banners: offline only, academic/portfolio evidence, no alert/prevention effect.

The UI never shows or accepts raw dataset rows, feature vectors, raw endpoints, object references, filesystem paths, model bytes, arbitrary URLs, custom code, or prevention controls. Server permissions remain authoritative. Accessibility covers labels, keyboard/focus, semantic tables, non-color status, reduced motion, and bounded responsive layouts.

## 29. Synthetic fixtures before implementation

Required small fixtures:

1. Dataset file/manifest valid, changed-terms, missing-checksum, tampered, duplicate-name, oversized, and acquisition-false cases.
2. Canonical mapping valid, unit mismatch, missing required column, paired-port mismatch, invalid time, label-in-feature, and unsupported publisher-feature cases.
3. Exact/near duplicates, conflicting labels, cross-group/time relationships, and split leakage cases.
4. Imbalanced binary and multiclass synthetic datasets with sealed train/validation/test identities.
5. Missing/unknown category, zero/range/rate-clipped, non-finite, and incompatible feature vectors.
6. Training-only preprocessing golden manifests and deliberate validation/test contamination attempts.
7. Majority, Logistic Regression, and Random Forest deterministic micro-training fixtures.
8. Calibration/threshold boundary and one-final-test-open guard cases.
9. ONNX valid, corrupt, wrong hash, oversized, unsupported op/domain/opset, external-data, wrong shape/type, and conversion-parity cases.
10. Registry review/activation/rollback expected-current, self-review, concurrent activation, corrupt predecessor, and audit-failure cases.
11. Scoring valid, duplicate, incompatible, expired feature artifact, missing model, corrupt model, non-finite output, resource limit, crash, and cleanup cases.
12. UI hostile model/card text, large metric sets, unauthorized controls, and accessibility cases.

No real dataset rows or trained model artifact is committed as a fixture. Tiny synthetic ONNX fixtures may enter Git only after license, size, provenance, and non-executable operator review; generating them during tests is preferred.

## 30. Complete test matrix

### 30.1 Dataset and leakage

- Official-source allowlist/redirect/HTTPS/size/timeout/hash behavior without real network in ordinary tests.
- Acquisition false, changed terms, unsupported file/archive, cleanup, and no Git artifact.
- Strict CSV schema/encoding/delimiter/header/content validation and bounded chunk behavior.
- Mapping units/directions/missingness/event-time/window parity and label separation.
- Exact/near duplicate, conflict, group/time/capture, exclusion, and cross-split leakage tests.
- Split determinism, proportions/support, sealed test, and immutable manifest hash.

### 30.2 Preprocessing and training

- Shared 39-feature order/hash and 7-provenance-column exclusion.
- Training-only vocabulary/statistic/scaler/calibrator/sampler fit guards.
- Missing/unseen/non-finite/range/type/width/order/version failures.
- Fixed seed/thread/config repeatability within documented numerical tolerance.
- Majority/Logistic/Random Forest metric calculations and imbalance policy.
- Validation-only tuning and frozen threshold; test-open-once guard.
- Resource/time/thread/row/config/artifact/output limits and cleanup.

### 30.3 Evaluation and model cards

- Per-class/macro/weighted metrics, PR/ROC applicability, FPR/FNR, confusion matrix, Brier/calibration, latency/resource summaries.
- Empty/single-class/small-class/undefined metric handling with explicit unavailable values, not fabricated zeros.
- Error-analysis aggregation and small-group/privacy suppression.
- Card completeness, provenance, prohibited-use, limitations, hash, and no unsupported claims.

### 30.4 Artifact and registry

- ONNX structural/operator/opset/external-data/size/shape/hash/runtime validation.
- Training-versus-ONNX probability and threshold parity.
- Corrupt/replaced/partial/path-traversal/symlink/permission artifacts fail closed.
- Immutable model definitions/metrics/cards and one-active-purpose constraint.
- Creator/reviewer separation, six-role negative matrix, expected-current concurrency, lifecycle, activate/retire/rollback, and audit failure.
- Migration fresh upgrade, existing-data upgrade, downgrade refusal, inventory cleanup, downgrade, and re-upgrade.

### 30.5 Scoring and runtime

- Persist-before-dispatch, JSON-only UUID, idempotency, duplicate delivery, lease/reconcile, crash before/after artifact move, no-network worker.
- Compatible batch scoring, bounded chunking, probabilities sum/range, stable class order, safe errors, 30-day prediction expiry.
- No alert/rule/risk/prevention mutation and simulation-only OS/capability guard.
- API IDOR/mass assignment/CSRF/Origin/session/CORS/redaction/pagination/rate limits.
- Frontend lint/type/component/build/audit/accessibility and unauthorized-control tests.
- Clean Docker build/start, PostgreSQL/Redis health, trainer/worker registration, synthetic train/register/review/activate/score/rollback path.

### 30.6 Quality and supply chain

- Ruff, formatting, mypy, pytest, Bandit, pip-audit, npm audit, secret scan, simulation-only guard, and diff/large-file review.
- Dependency license/native-wheel/ARM64 review for scikit-learn, ONNX, ONNX Runtime, and any optional booster.
- Container image/SBOM/Trivy is proposed as a Sprint 5 release gate because model runtimes add a new native trust boundary.
- No skipped required check counts as pass.

## 31. Security, privacy, and supply-chain controls

### Security

- Treat official files, CSV headers/cells, labels, cards, manifests, model graphs, probabilities, and metrics as hostile data.
- Never execute dataset content, formulas, macros, scripts, notebooks, binaries, model callbacks, or custom operators.
- No arbitrary outbound fetch or user-controlled storage path.
- Strict schemas, bounded nesting/cardinality/text/tensors, canonical hashes, parameterized SQL, atomic files, non-root/read-only containers, and least privilege.
- Verify every lineage hash at each transition; incompatibility or integrity mismatch fails closed.

### Privacy

- Raw endpoints remain grouping/provenance only and are never model values, reports, ordinary UI, logs, metrics labels, or public model cards.
- Dataset labels tied to endpoints remain restricted training metadata.
- Predictions are sensitive, permissioned, minimally stored, and expire after 30 days.
- No external telemetry/model explainability service is used.
- Published reports suppress small groups and contain aggregate sanitized evidence only.

### Supply chain

- Pin supported versions and lock hashes where the project tooling permits.
- Review package source, license, release cadence, ARM64 wheel provenance, transitive native libraries, CVEs, and container size.
- Generate an SBOM and scan final API/worker/trainer/dashboard images before Sprint 5 approval.
- GitHub Actions remain pinned and least privilege; no dataset/model artifact is uploaded to CI.
- Hosted CI uses synthetic fixtures only.

## 32. Failure handling and rollback

| Failure | Required behavior |
|---|---|
| Terms/source ambiguity | Block acquisition; audit safe reason |
| Transfer timeout/size/hash mismatch | Delete partial; fail; never parse |
| Schema/mapping incompatibility | Reject dataset; do not fit |
| Quality/leakage failure | Dataset remains rejected/proposed |
| Split conflict | Reject and create a new reviewed split revision |
| Resource/time limit | Terminate job, clean staging, preserve safe counts |
| Redis unavailable | No untracked dispatch; persisted pending job is reconcilable |
| PostgreSQL unavailable | No acquisition acceptance, run, registry, activation, or scoring state change |
| Training crash | Failed run; no automatic retry/promotion |
| Evaluation undefined | Report unavailable; never coerce to passing zero/one |
| ONNX conversion/parity failure | Reject candidate; no unsafe fallback format |
| Artifact integrity/unsupported operator | Quarantine model; block load/activation/scoring |
| Activation race | Expected-current conflict; no partial active state |
| Active scorer load failure | Fail scoring; deterministic IDS continues; no fallback to arbitrary model |
| Rollback failure | Preserve current state, raise high-severity operational/audit event; no silent switch |
| Cleanup failure | Keep metadata/status; retry bounded; expose overdue counts |
| Audit failure | Fail closed for acceptance/review/activation/rollback and other sensitive changes |

Rollback is registry and metadata rollback only. It never changes rules, alerts, prevention, or network state. Database downgrade requires artifact inventory and explicit retirement/deletion; it never deletes controlled files implicitly.

## 33. Assumptions and proposed defaults

These recommendations are not owner decisions yet:

| ID | Proposed default | Consequence if rejected |
|---|---|---|
| S5-A01 | Execute Sprint 5 as separately approved Phase 5A then Phase 5B. | A combined authorization increases implicit dataset/training authority and must define equivalent stop gates. |
| S5-A02 | Acquire only official full tabular parts plus feature/ground-truth documentation; exclude raw PCAP and unofficial/pre-split duplicates by default. | File scope, leakage evidence, transfer limits, and mapping plan change. |
| S5-A03 | Use 5 GiB combined transfer, no archives, 50 GiB disk reserve, 90-day raw maximum. | Storage/security/retention review changes. |
| S5-A04 | Require full canonical flow v1 and 60/300-window compatibility; no partial feature schema or zero-filled context. | A new feature schema/version and parity review are required. |
| S5-A05 | Use group/time-aware 70/15/15 split; random split requires explicit exception. | Leakage risk and acceptance evidence change. |
| S5-A06 | Binary intrusion classification is the release target; multiclass is reported research evidence. | Metrics, support gates, UI, and artifact purpose change. |
| S5-A07 | Majority reference, Logistic Regression baseline, Random Forest candidate; booster deferred unless justified. | Dependency/resource/test scope changes. |
| S5-A08 | Class weights first; no SMOTE; sigmoid calibration; validation-frozen threshold. | Leakage/calibration/test plan changes. |
| S5-A09 | Adopt Section 17 staging thresholds as rejection gates, not claims. | Owner supplies different cost targets or accepts research-only non-activation. |
| S5-A10 | Approve ONNX plus canonical JSON as D-13; no Python-object serving artifacts. | Another safe format requires a new threat/runtime/parity review. |
| S5-A11 | Use a 4 GiB/2 CPU optional trainer profile and Section 16 job limits. | Host capacity and availability controls change. |
| S5-A12 | Require creator/reviewer separation using distinct System/Security Administrator accounts. | Governance risk needs explicit owner acceptance and stronger audit caveat. |
| S5-A13 | PostgreSQL registry is authoritative; do not add MLflow to the MVP runtime. | MLflow adds service/dependency/auth/storage/backup scope. |
| S5-A14 | Offline batch scoring only; no alert generation or online endpoint. | Architecture/privacy/load/threat models must be reopened. |
| S5-A15 | Use Section 23 retention defaults and no exceptional holds. | Cleanup, reproducibility, disk, and privacy plan changes. |
| S5-A16 | Add migration/tables, APIs, UI, permissions, tasks, SBOM/Trivy gates as proposed. | Implementation sequence and acceptance matrix change. |

## 34. Decisions requiring owner approval

Before Phase 5A:

1. Approve the two-phase Sprint 5 boundary.
2. Approve the exact official filenames and advertised sizes after revalidation.
3. Approve full tabular parts plus documentation and exclude raw PCAP, mirrors, and publisher pre-split duplicates by default.
4. Approve transfer, disk, archive, staging, retry, timeout, and 90-day raw retention limits.
5. Approve the current terms/citation/non-redistribution disposition for academic/portfolio use.
6. Approve the canonical mapping requirement and the rule that incompatibility blocks training.
7. Approve dataset acquisition-actor versus acceptance-reviewer separation.

Before Phase 5B:

8. Approve the exact acquired file/dataset/mapping/quality/leakage/split manifest hashes.
9. Approve group/time-aware 70/15/15 split or a documented alternative.
10. Approve binary release target and multiclass research-only default.
11. Approve candidate sequence and optional-booster deferral.
12. Approve class weighting, no-SMOTE, calibration, and threshold policy.
13. Approve or replace the proposed numeric staging targets.
14. Resolve D-13 by approving ONNX/canonical JSON and its closed runtime policy.
15. Approve the trainer resource limits and deterministic training row caps.
16. Approve PostgreSQL registry without MLflow for the MVP.
17. Approve model creator/reviewer/activator separation.
18. Approve offline-only scoring and no alert/prevention side effects.
19. Approve model/dataset/prediction retention.
20. Approve migration, permissions, APIs/UI, Celery tasks, and SBOM/Trivy as Sprint 5 gates.

No unspecified answer is inferred as approval.

## 35. Dependencies

- Sprint 4 final SHA and hosted CI: satisfied.
- Canonical flow v1, feature schema v1, controlled Parquet, PostgreSQL/Celery/Redis, RBAC/audit, and simulation-only guards: implemented.
- Current official terms/source revalidation: blocking Phase 5A transfer.
- Explicit named-file acquisition authorization: blocking Phase 5A transfer.
- Acquired dataset mapping/quality/leakage/split acceptance: blocking Phase 5B.
- D-13 safe serialization decision: blocking any model artifact or loading.
- ARM64 dependency/native-runtime/SBOM review: blocking training and scoring images.
- Owner decisions in Section 34: blocking their corresponding phase.

## 36. Major risks and mitigations

| Risk | Severity | Mitigation / disposition needed |
|---|---|---|
| Malicious/corrupt official file or native parser exploit | Critical | Exact source, byte/schema caps, no execution/archive default, non-root isolation, hash, scans, bounded parser tests |
| Terms/citation/redistribution breach | High | Current revalidation, named authorization, academic-only use, no Git/artifact publication, required citation |
| Dataset-native semantics do not match serving features | High | Per-field mapping and full-window compatibility gate; reject rather than approximate |
| Label/capture/endpoint leakage inflates metrics | High | Typed target separation, denylist, duplicates/relationships, group/time split, sealed test, independent review |
| Test set influences tuning or thresholds | High | Immutable split, permissions/audit, test-open-once guard, locked candidate hash |
| Unsafe serialization or model graph compromises worker | Critical | ONNX closed operators/no external data/custom ops, internal-only artifact, size/hash/runtime isolation, no pickle |
| Conversion changes probabilities/classes | High | Golden/validation parity tolerance plus exact decision parity; reject on failure |
| Model activation tampering or self-approval | High | Immutable definitions, creator separation, expected-current lock, audit, negative matrix, rollback |
| Training exhausts 8 GB ARM64 host | High | Dedicated 4 GiB/2 CPU profile, row/config/time/thread caps, streaming, peak-RSS evidence |
| Native dependencies/supply chain compromise | Critical | Pins, license/CVE review, SBOM, Trivy, pip-audit, provenance, no optional booster by default |
| Class imbalance hides minority failures | High | Per-class/PR metrics, class weights, validation threshold, minimum recall/FPR gates, error analysis |
| Public-dataset performance is overstated | High | Honest card, external validity limitations, no production/zero-day claim, later second-dataset validation |
| Scoring leaks endpoints/features/probabilities | High | Metadata-only UI/API, RBAC, aggregation, 30-day retention, safe logs/audit, no raw vector endpoint |
| Model signal reaches alerts/prevention prematurely | Critical | Offline-only scorer, dependency/schema guard, no alert/risk/prevention imports or writes, simulation-only check |
| Cleanup removes active rollback artifact | High | DB lifecycle selection, active/predecessor protection, inventory refusal, atomic status and cleanup tests |
| Solo-project separation is nominal | Medium | Distinct accounts and complete audit; document lack of independent human reviewer |

No Critical or High residual risk may be silently accepted. The completion report must name owner, evidence, review date, and disposition for every remaining one.

## 37. Deferred work

- Any dataset other than the explicitly approved UNSW-NB15 files.
- External validation on CIC-IDS2017/CSE-CIC-IDS2018/TON_IoT.
- XGBoost/LightGBM unless separately justified inside Sprint 5.
- MLflow service, Optuna, distributed training, GPU, deep learning, notebooks in runtime paths.
- Online/streaming inference, automatic alert generation, supervised signal integration into ensemble/risk.
- SHAP and analyst explanations beyond card/coefficient/feature-importance evidence (Sprint 7).
- Isolation Forest/anomaly and ensemble engine (Sprint 6).
- Threat intelligence, incidents, SOC workflow, prevention simulation, all real prevention, and live capture.
- Automated retraining, drift, analyst-feedback learning, model monitoring, and promotion automation.

## 38. Implementation sequence after approvals

### Phase 5A sequence

1. Reconfirm final public SHA/CI/clean tree and create a short-lived Sprint 5 branch.
2. Record approved owner decisions and update architecture/threat/risk/schema/API/test/deployment documents.
3. Create synthetic acquisition/mapping/quality/leakage/split fixtures and tests.
4. Revalidate the current official page/terms and stop on ambiguity.
5. Obtain exact named-file authorization; preflight disk and limits.
6. Transfer/hash/validate only approved files into controlled storage; create immutable file/dataset manifests.
7. Implement the strict streaming adapter and typed target separation.
8. Run bounded quality, mapping, duplicate, relationship, leakage, and candidate-split analysis.
9. Produce reports and an immutable proposed split manifest.
10. Run Phase 5A quality/security/resource/privacy checks.
11. Stop at the uncommitted dataset acceptance gate. Do not fit or train.

### Phase 5B sequence

12. After explicit dataset-hash acceptance and D-13 approval, freeze split and preprocessing contracts.
13. Add migration and synthetic ML/ONNX/registry/scoring fixtures.
14. Implement training-only preprocessing and parity/contamination guards.
15. Implement majority and Logistic Regression evidence, then Random Forest.
16. Select configuration/threshold on validation only and lock the candidate hash.
17. Open the final test once, produce evaluation/error/resource evidence and model card.
18. Convert to ONNX and pass structural, integrity, operator, runtime, and conversion-parity gates.
19. Implement registry lifecycle, RBAC/audit, activation/rollback, and retention.
20. Implement controlled offline scoring, APIs, minimal UI, and cleanup.
21. Run every local quality/security/dependency/SBOM/container/migration/ML/runtime/frontend/E2E gate.
22. Update documentation and create `docs/SPRINT_5_COMPLETION_REPORT.md`.
23. Review the complete diff for scope, unauthorized data/models, secrets, large files, terms, leakage, unsafe serialization, prevention separation, and Critical/High findings.
24. Stop at the uncommitted Sprint 5 completion gate. Do not commit or publish.

## 39. Proposed Sprint 5 acceptance criteria

| Criterion | Required evidence |
|---|---|
| Entry and Sprint 4 publication records are correct | Final SHA, CI Run #7, clean-tree evidence, updated docs |
| Acquisition is explicit, official, bounded, and lawful | Current terms/citations, exact file authorization, transfer/hash/limit/audit evidence |
| Raw PCAP and unofficial sources remain excluded | Manifest/diff/network/source review |
| Dataset manifest and file integrity are immutable | Strict contracts, SHA-256, DB triggers/constraints, tamper tests |
| Full feature-schema compatibility is proven | Per-field mapping, units/direction/time/window parity, rejection tests |
| Labels/provenance never enter vectors | Typed separation, denylist and Parquet/model-input column tests |
| Quality, duplicates, poisoning, and leakage are reviewed | Versioned measured reports, exclusions, relationship analysis, owner acceptance |
| Split is deterministic and leakage-resistant | Immutable group/time manifest, cross-partition duplicate/group zero findings, sealed test |
| Preprocessing is training-only and inference-compatible | Fit guards, manifest hashes, golden matrix parity, unseen/missing tests |
| Baselines/candidates are reproducible and bounded | Fixed configs/seeds, host resource evidence, repeat tests, no uncontrolled search |
| Imbalance/calibration/threshold policy is honest | Prevalence, class weights, validation-only calibration/threshold, frozen test behavior |
| Evaluation is complete and test is used once | Per-class/error/calibration/resource metrics, test-open audit, locked candidate hash |
| Model card/provenance/limitations are complete | Canonical JSON + reviewed Markdown, no unsupported claims/raw data |
| D-13 safe format is resolved | ONNX closed policy, no Python object artifacts, structural/operator/hash/parity tests |
| Registry lifecycle and rollback are safe | Immutable definitions, one-active constraint, separation, locking, audit, rollback tests |
| Offline scoring fails closed and has no side effects | Compatibility/integrity/resource/idempotency tests; no alert/rule/prevention writes |
| Migration is reversible without orphaning artifacts | Fresh/existing upgrade, refusal/inventory, downgrade/re-upgrade, S0–4 preservation |
| RBAC/CSRF/Origin/privacy hold | Six-role negative matrix, self-review denial, IDOR/redaction/log/audit tests |
| Celery and Docker remain bounded and non-privileged | UUID-only tasks, trainer limits, crash/reconcile, clean-stack health/registration |
| Native/supply-chain gates pass | ARM64 review, pins, pip/npm audit, SBOM, Trivy, container build |
| Retention and cleanup protect active/rollback artifacts | Prediction/model/dataset expiry and cleanup/inventory tests |
| Documentation and traceability are current | Governing docs, dataset reports, card, completion report, exact evidence |
| No Sprint 6+, live capture, or real prevention enters scope | Dependency/diff/capability/OS-state review |
| No unresolved Critical or High issue | Final independent uncommitted review |

Sprint 5 is complete only when every applicable criterion passes. A rejected dataset or model remains a valid honest outcome; it is not permissible to weaken gates to force activation.

## 40. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The design is consistent with the Sprint 4 feature contract and the Sprints 0–9 safety boundary. Phase 5A remains blocked on current official-source/terms revalidation and exact named-file acquisition authority. Phase 5B remains blocked on accepted dataset/mapping/quality/leakage/split hashes and approval of D-13 safe ONNX serialization/runtime policy.

## 41. Exact Sprint 5 Phase 5A pre-acquisition authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_5_IMPLEMENTATION_PLAN.md and begin Sprint 5 Phase 5A pre-acquisition work only.

Before proceeding:
- Confirm public main is still at 72c97b15f9bb31ddb6810a397afc682893497bab or identify and review any newer authorized baseline.
- Confirm hosted CI Run #7 succeeded for that SHA.
- Confirm the working tree contains only the approved Sprint 4 publication-documentation updates and docs/SPRINT_5_IMPLEMENTATION_PLAN.md.
- Read all governing documents and docs/SPRINT_5_IMPLEMENTATION_PLAN.md completely.
- Create a short-lived Sprint 5 branch without rewriting published history.

Use these owner decisions:
- Sprint boundary: approve separate Phase 5A dataset gate and Phase 5B training gate.
- Intended use: academic/portfolio only; repository MIT license does not apply to dataset files.
- Official source: current UNSW publisher page and only publisher-controlled HTTPS redirects reached from it.
- Candidate scope for the later acquisition decision: the four principal official tabular data parts plus the official feature description and only required ground-truth/event documentation.
- Exclusions: raw approximately 100 GB PCAP, unofficial mirrors, arbitrary URLs, publisher pre-split duplicate files unless separately named, and every unlisted file.
- Transfer/storage limits: 5 GiB combined, 2 GiB/file, 10 files, 5 HTTPS redirects, 30/120-second connect/idle timeouts, 30-minute file deadline, two retries, no archives, mode-0600 opaque staging, streaming SHA-256, 50 GiB protected disk reserve.
- Raw retention: through Sprint 5 review, maximum 90 days without renewed approval; no exceptional holds.
- Mapping gate: require complete canonical flow v1 and 39-feature 60/300-second compatibility; no partial schema, invented semantics, or zero-filled missing context.
- Split proposal: group/time-aware 70/15/15; random split prohibited without a later explicit exception.
- Governance: acquisition by System Administrator/operator; acceptance by a distinct Security Administrator account; complete audit.

Implement only the synthetic fixtures, strict contracts, controlled-storage foundations, acquisition state machine, bounded transfer client, manifest/integrity interfaces, RBAC/audit controls, safe failure handling, and tests needed to make a later explicitly authorized transfer fail closed. The transfer interface must accept only a server-side allowlist created from a separately approved exact file manifest; it must not accept a browser-supplied or arbitrary URL.

Then revalidate the current official source, terms, citation requirements, commercial-use restriction, redistribution status, exact filenames, advertised sizes, media/archive formats, checksums if published, and redirect hosts. Record metadata and legally permissible evidence only. Do not download any dataset file or sample during this authorization.

If anything differs materially from the recorded review, is ambiguous, requires unapproved credentials, exceeds proposed limits, uses archives, or lacks the candidate files, report the blocker. Otherwise produce the exact proposed acquisition manifest containing every official filename, advertised size, source/redirect host, expected media type, role, and applicable checksum status for owner approval.

Run and record all applicable formatting, linting, typing, unit, contract, parser, mapping, leakage, split, integrity, authorization, CSRF/Origin, audit, retention, resource, dependency, secret, Docker, Celery, health, frontend, and simulation-only checks. Update affected documentation and create the Phase 5A dataset-review report.

Do not download or parse dataset payloads; materialize real dataset features; fit preprocessing; train, tune, evaluate, serialize, register, load, activate, or score a model; create predictions or alerts; add online inference, anomaly/ensemble functionality, live capture, real prevention, privileged containers, host networking, firewall integration, Sprint 6 work, commit, or publication.

Stop at the uncommitted Phase 5A acquisition-authorization gate. Report the source/terms findings, exact proposed file manifest and limits, files changed, migrations/interfaces added, commands and checks run, failures/skips, assumptions, residual risks, and the exact controlled-acquisition authorization prompt. Wait for explicit owner approval naming every file before transferring any dataset byte. Dataset acceptance and Phase 5B training remain later, separate gates; D-13 must be resolved before any model artifact work.
```
