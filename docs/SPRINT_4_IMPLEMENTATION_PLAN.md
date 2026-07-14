# Sprint 4 Implementation Plan — Feature Engineering and Versioned Data Pipeline

**Planning date:** 2026-07-14

**Status:** Defaults approved and Sprint 4 implementation authorized on 2026-07-14; completion evidence is recorded separately

**Target sprint:** Sprint 4 — Feature Engineering and Data Pipeline

**Release boundary:** Sprints 0–9, IDS with simulated IPS

**Authorized baseline:** Public `main` at `b514aa3592487a65b8de8e1cfa14f4f9b80c5976`

## 1. Planning gate and evidence

The Sprint 4 planning entry gate is satisfied:

- Public GitHub `main` resolves to Sprint 3 commit `b514aa3592487a65b8de8e1cfa14f4f9b80c5976`.
- GitHub Actions Run #5 (`29325828604`) completed successfully for that exact SHA on its first attempt.
- The hosted backend, frontend, and container jobs all passed.
- Local `HEAD` and recorded `origin/main` resolve to the same SHA.
- The working tree was clean before Sprint 3 publication records and this plan were edited.

The planning task itself was documentation-only. The owner subsequently approved every recommended default and authorized the exact Section 33 implementation prompt, with canonical flow v1, 60/300-second windows, controlled Parquet, 30-day feature-artifact retention, and solo Security Administrator review. Dataset work remains limited to official-source investigation; acquisition is not authorized and the raw PCAP is excluded.

## 2. Governing documents read

This plan was reconciled against the complete contents of:

- `AegisAI-NIDPS-Master-Prompt.md`
- `AegisAI-NIDPS-Implementation-Guide.md`
- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/USE_CASES.md`
- `docs/DECISIONS.md`
- `docs/BACKLOG.md`
- `docs/DEFINITION_OF_DONE.md`
- `docs/ML_PLAN.md`
- `docs/DATASET_REVIEW_UNSW_NB15.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/DATA_FLOW.md`
- `docs/DATABASE.md`
- `docs/SCHEMAS.md`
- `docs/api/API.md`
- `docs/threat-model/THREAT_MODEL.md`
- `docs/TEST_STRATEGY.md`
- `docs/DEPLOYMENT_STRATEGY.md`
- `docs/RISK_REGISTER.md`
- `docs/PREVENTION_SAFETY.md`
- `docs/REPOSITORY_STRUCTURE.md`
- `docs/DETECTION_ARCHITECTURE.md`
- `docs/SPRINT_3_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_3_COMPLETION_REPORT.md`

## 3. Confirmed requirements

These requirements are already approved and are not Sprint 4 implementation choices:

1. One shared, deterministic, versioned transformation package must serve both later training and inference.
2. The same ordered input and context must produce the same ordered feature vector and feature hash.
3. Canonical flow v1 remains immutable. Incompatible input schemas fail closed rather than being coerced silently.
4. Features, feature order, code, preprocessing configuration, categorical vocabulary, input schema, dataset, split, and artifacts must be versioned and traceable.
5. Labels, row identifiers, post-incident fields, label-derived values, detection results, alert data, and other leakage fields must never enter serving vectors.
6. Fitted preprocessing is fit on training data only. Validation and test partitions cannot influence imputation, scaling, vocabulary, selection, sampling, or thresholds.
7. Missing, unseen, invalid, infinite, and out-of-range values require explicit, tested policies.
8. Windowed features use defined event-time, ordering, cutoff, and late-data semantics; worker wall-clock order is not feature meaning.
9. Dataset provenance, official terms, citation, integrity, non-redistribution, quality, duplicates, leakage, and split construction must be reviewed before training.
10. UNSW-NB15 remains only a conditionally suitable primary candidate. No acquisition is authorized by the existing review or this plan.
11. Repository code is MIT licensed, but dataset terms remain separate. Intended use is academic/portfolio only.
12. Raw datasets, dataset extracts, PCAPs, generated feature matrices, secrets, and large artifacts must not enter Git.
13. Controlled local artifact storage uses opaque references; PostgreSQL stores metadata and SHA-256 hashes.
14. Raw uploads expire after processing or within 24 hours, flows after 30 days, alerts/audit after 180 days, and predictions after 30 days. Feature retention still requires an explicit owner decision.
15. PostgreSQL remains authoritative. Celery messages remain JSON-only bounded identifiers. Redis is coordination, not the source of truth.
16. Sprint 4 cannot train, load, register, activate, or score a model. Safe model serialization decision D-13 remains a Sprint 5 blocker.
17. Detection, feature engineering, ML, prevention policy, and prevention adapters remain separate. Prevention stays simulation-only and Sprint 4 adds no prevention workflow.
18. No live packet capture, privileged container, host network, firewall capability, or enforcement dependency may be introduced.

## 4. Planning findings and constraints

### 4.1 Current canonical data is intentionally narrow

Canonical flow v1 provides event time, endpoints, paired ports, protocol, duration, packet/byte totals, optional connection state, sensor/job provenance, and bounded scalar metadata. It does not contain packet-size samples, packet inter-arrival samples, TCP flag counters, DNS queries, HTTP fields, TLS handshake fields, application-authentication outcomes, or authoritative bidirectional counters.

Sprint 4 must not invent unavailable semantics from arbitrary metadata. DNS, HTTP/TLS, detailed TCP, beaconing-periodicity, and true forward/backward ratio features remain blocked until their own canonical contracts and ingestion adapters are separately approved.

### 4.2 UNSW-NB15 does not automatically equal the serving schema

The public dataset has its own published feature representation. Its columns cannot be renamed and treated as canonical live features without a semantic mapping that proves units, direction, timing, missingness, and inference availability. Dataset-native fields may support a benchmark adapter, but every selected model input must map to a versioned Aegis feature definition available in both training and serving.

### 4.3 Event identifiers and network identities are leakage-prone

Raw IP addresses, sensor/job IDs, row numbers, source event IDs, exact capture timestamps, dataset file names, split names, and dataset-specific generator artifacts can let a model memorize a capture rather than learn network behavior. They may remain provenance, grouping, or audit fields, but they are banned from model vectors unless a later review proves a defensible bounded derivation.

### 4.4 Online feature storage is not yet required

Sprint 5 needs compatible inference inputs, but Sprint 4 does not need to persist every vector in PostgreSQL. The proposed default is immutable feature artifacts plus job/schema/manifest metadata in PostgreSQL, with an optional per-flow materialization table deferred until measured inference or audit requirements justify the privacy and storage cost.

### 4.5 Development host limits shape the data pipeline

The approved host has 8 GB RAM and ARM64 architecture. UNSW-NB15 is too large for unbounded in-memory processing. Dataset profiling and transformation must stream in bounded chunks, use atomic artifact writes, record peak memory and elapsed time, and fail safely before exhausting disk or memory.

## 5. Sprint 4 scope

### 5.1 Included after separate implementation authorization

1. Versioned feature-contract and feature-dictionary schemas.
2. Synthetic golden fixtures written before transformation code.
3. A shared fit-free transformation interface for canonical flow v1.
4. Deterministic per-flow and approved fixed-window feature groups.
5. Explicit missing/unseen/range/non-finite policies and quality flags.
6. A versioned preprocessing configuration and categorical-vocabulary contract.
7. Training/inference parity, schema compatibility, determinism, leakage, and resource tests.
8. Dataset-manifest, split-manifest, data-quality-report, and artifact-manifest contracts.
9. An official-source investigation and acquisition runbook for UNSW-NB15; actual download only if separately and explicitly authorized after the investigation gate.
10. Bounded Celery feature jobs that carry only persisted UUIDs.
11. Reversible PostgreSQL metadata migration, minimal APIs, and minimal job/schema/data-quality UI.
12. Documentation updates and an uncommitted Sprint 4 completion report.

### 5.2 Explicitly excluded

- Downloading, extracting, copying, publishing, or redistributing any dataset under this planning authorization.
- Model training, tuning, evaluation, serialization, loading, registry activation, prediction, probability, or explanation.
- Feature selection based on label correlation, model importance, or test-set performance.
- New DNS, HTTP, TLS, authentication, packet-sample, or live-capture schemas unless separately approved as a prerequisite scope change.
- Raw IP addresses, event IDs, job/sensor IDs, labels, attack categories, alerts, rule results, or prevention data as model inputs.
- Generic user-authored transformation code, expressions, templates, imports, notebooks in runtime paths, or executable artifacts.
- Arbitrary historical materialization ranges controlled by clients.
- Changes to Sprint 3 rule evaluation or alert fingerprints.
- Anomaly, ensemble, intelligence, explainability, incident, or prevention functionality.
- Real prevention, privileged containers, host networking, firewall integration, commit, or publication.

## 6. Proposed architecture

### 6.1 Dependency direction

The required direction is:

`canonical flow/dataset adapter -> validated feature input -> shared feature pipeline -> ordered vector + quality report -> controlled artifact metadata`

Training and future inference import the same `aegis_services.features` package. Feature code must not import model, alert, incident, intelligence, policy, prevention, dashboard, or dataset-label modules.

### 6.2 Transformation interfaces

Proposed typed interfaces:

```text
FeaturePipeline.validate_input(record, input_schema) -> ValidatedFeatureInput
FeaturePipeline.transform_one(record, context, feature_schema) -> FeatureVector
FeaturePipeline.transform_batch(records, context, feature_schema) -> FeatureBatch
Preprocessor.fit(training_vectors, config) -> FittedPreprocessorManifest
Preprocessor.transform(vectors, fitted_manifest) -> OrderedNumericMatrix
DatasetAdapter.iter_records(manifest, limits) -> ValidatedDatasetRecord
```

Sprint 4 may implement `fit` only for deterministic preprocessing metadata such as training-only imputation statistics and vocabularies on synthetic fixtures or an explicitly authorized dataset. It must not fit or invoke a predictive model.

### 6.3 Determinism boundary

Determinism requires all of the following inputs to be explicit:

- canonical input schema version;
- feature-schema ID, semantic version, definition hash, and ordered feature list;
- preprocessing configuration and fitted-manifest hash where applicable;
- categorical vocabulary version and unknown token;
- event-time cutoff and stable tie-break key;
- window definition and sensor/asset scope;
- source snapshot identity/hash;
- feature-code package version and source commit.

Locale, process hash randomization, dictionary insertion order, current time, filesystem order, task delivery order, database default ordering, and host floating-point formatting must not change output.

## 7. Feature contract and versioning

### 7.1 Feature schema

Each immutable feature schema should contain:

| Field | Requirement |
|---|---|
| `schema_id` | UUID |
| `name` | Stable namespaced name, initially `flow_features` |
| `version` | Semantic contract version, initially `1.0.0` |
| `input_schema` | Exact compatible canonical input contract, initially flow `1` |
| `ordered_features` | Immutable ordered feature definitions |
| `window_definitions` | Exact cutoff, inclusion, grouping, and duration rules |
| `preprocessing_config` | Missing, scaling, encoding, clipping, dtype, and precision policy |
| `categorical_vocabularies` | Named vocabulary versions or fitted-manifest references |
| `banned_fields` | Explicit leakage denylist |
| `definition_hash` | SHA-256 of canonical JSON over every semantic field |
| `code_version` | Source commit/package version |
| `lifecycle_state` | `draft`, `approved`, or `retired`; no active model state in Sprint 4 |
| `created/reviewed` | Actor, time, rationale, and review evidence |

Any change to feature name, meaning, unit, dtype, range, missing policy, order, window, encoding, vocabulary, or preprocessing creates a new feature-schema version. Description-only corrections that do not change semantics still require an audited new immutable document revision unless proven non-semantic.

### 7.2 Feature vector contract

`FeatureVectorV1` should contain:

- contract version and feature-schema ID/hash;
- input flow identity as provenance outside the model values;
- cutoff time and source snapshot hash;
- ordered typed raw feature values;
- ordered missingness/quality indicators defined by the schema;
- ordered encoded values only when a fitted preprocessing manifest is supplied;
- preprocessing manifest ID/hash or null for fit-free output;
- deterministic vector hash over canonical representation;
- creation time as provenance, excluded from the vector hash.

Labels, partition names, and evaluation outcomes are separate training-example metadata and never fields inside the serving vector.

## 8. Initial feature dictionary proposal

The implementation must create a machine-readable dictionary and an analyst-readable `docs/features/FEATURE_DICTIONARY_V1.md`. The following is the proposed conservative v1 scope.

### 8.1 Direct per-flow features

| Feature | Type/unit | Valid range | Missing policy | Source/meaning |
|---|---|---|---|---|
| `duration_ms` | int64 milliseconds | 0–604,800,000 | required | Canonical flow duration |
| `packet_count` | int64 packets | 0–2^63-1 | required | Total reported packets |
| `byte_count` | int64 bytes | 0–2^63-1 | required | Total reported bytes |
| `src_port_present` / `dst_port_present` | bool | 0/1 | never missing | Distinguishes absent from numeric zero |
| `src_port` / `dst_port` | int32 | 0–65,535 | sentinel 0 plus presence indicator | Canonical paired ports |
| `src_port_class` / `dst_port_class` | closed category | none/well-known/registered/dynamic | `none` | Stable IANA numeric bands, not service claims |
| `protocol` | category | bounded lowercase canonical token | `__UNKNOWN__` at encoding | Transport/network protocol token |
| `connection_state` | category | bounded canonical token | `__MISSING__`; unseen=`__UNKNOWN__` | Source-reported state, not attack label |
| `bytes_per_packet` | float64 bytes/packet | finite, >=0 | 0 when packet count is 0 plus denominator flag | Safe derived density |
| `packets_per_second` | float64 packets/s | finite, >=0, capped by schema | 0 when duration is 0 plus denominator flag | Rate over reported duration |
| `bytes_per_second` | float64 bytes/s | finite, >=0, capped by schema | 0 when duration is 0 plus denominator flag | Throughput over reported duration |
| `zero_duration` / `zero_packets` | bool | 0/1 | never missing | Makes safe division policy explicit |

Rate caps are data-quality safeguards, not silent winsorization. The unclipped invalid/outlier condition is represented by a quality indicator and counted in the report. Exact cap values require profiling and owner approval.

### 8.2 Fixed-window features

Proposed windows are 60 and 300 seconds, aligned to each target flow's event-time cutoff rather than wall-clock execution. Grouping includes authenticated sensor scope plus canonical source address for computation; raw addresses remain provenance/grouping values and are not output model values.

For each approved window:

- distinct prior/current flow count;
- unique destination-address count;
- unique destination-port count;
- total packet count and byte count with checked overflow;
- recognized Zeek failure-state count;
- mean and maximum flow duration;
- mean bytes per flow;
- time since prior flow for the same source/destination/service when available, with missing indicator.

DNS name volume, HTTP methods/status, TLS versions/fingerprints, TCP flag counts, packet-size statistics, detailed inter-arrival distributions, beaconing variance, and directional ratios are not v1 features because current canonical inputs do not support their semantics reliably.

### 8.3 Explicitly banned model inputs

- `label`, `attack_cat`, target class, one-hot label derivatives, or human disposition;
- dataset row/index ID, source filename, partition/split name, capture-file ID, or acquisition order;
- `event_key`, source event ID, ingestion/detection job ID, database UUID, correlation ID, or artifact path;
- raw source/destination IP address, raw sensor ID, username, hostname, or asset name;
- alert presence, rule/signature match, severity, risk/confidence, incident state, notes, intelligence match, or prevention outcome;
- processing/creation/completion wall-clock timestamps and any post-event field;
- exact event timestamp or capture-day token unless a future leakage review approves a bounded cyclic derivation;
- any field unavailable or semantically different at inference time.

## 9. Missing, unseen, invalid, and numeric policy

1. Missing is distinct from zero and from unknown.
2. Required canonical fields missing at the contract boundary cause rejection.
3. Optional categorical missing values map to `__MISSING__`; unseen valid values map to `__UNKNOWN__`.
4. Vocabulary tokens are normalized once, bounded, and never generated from validation/test/inference data.
5. Optional numeric missing values require an explicit indicator and training-only fitted imputation statistic; no global-data fit is permitted.
6. Division by zero follows the documented zero value plus denominator indicator; infinity and NaN are never emitted.
7. Wrong types, non-finite values, overflow, and values outside canonical hard ranges are controlled failures.
8. Plausible but extreme values are retained or clipped only according to the immutable schema; clipping emits a quality flag and report count.
9. Numeric output dtype and rounding are fixed. Proposed default is float64 for fit-free golden vectors; conversion to float32 for a later model is a versioned preprocessing decision.
10. Sparse/dense representation and feature order are fixed in the preprocessing manifest.

## 10. Categorical vocabulary design

- Reserved tokens are ordered first: `__MISSING__`, `__UNKNOWN__`.
- Protocol normalization uses canonical lowercase input. A fixed bootstrap vocabulary may cover known canonical fixture protocols, but any data-derived vocabulary is fit on training only.
- Connection-state vocabulary is source-aware. A Zeek state must not be conflated with a similarly spelled token from another source without an explicit mapping.
- Vocabulary manifests record name, version, ordered tokens, normalization policy, fit partition manifest, minimum frequency if used, unknown policy, hash, and code version.
- Validation/test/inference cannot add or reorder tokens.
- High-cardinality raw identifiers are banned rather than encoded.
- Hashing tricks are deferred because collision behavior reduces explainability and must be separately justified.

## 11. Event-time, ordering, windows, and late data

### 11.1 As-of ordering

Each flow is ordered by `(event_time_utc, event_key)`. The target flow's context includes records in the half-open lower bound and inclusive as-of tuple:

`event_time >= cutoff - window` and `(event_time, event_key) <= (target.event_time, target.event_key)`.

This makes ties deterministic and prevents future events from entering a target vector. Counts use distinct canonical event keys, not task deliveries.

### 11.2 Late evidence

Offline/out-of-order arrival can reveal an event whose event time precedes a previously materialized target. The proposed policy is:

1. fit-free transformation of an explicitly frozen source snapshot is immutable;
2. the snapshot hash and maximum source-ingestion watermark are part of provenance;
3. a material late event creates a new materialization revision with a new snapshot/vector hash;
4. previous artifacts are retained according to policy and never overwritten silently;
5. dataset training uses a frozen manifest/snapshot, so later arrivals cannot mutate an experiment;
6. future inference uses the exact context available at scoring time and records its cutoff/snapshot provenance.

The implementation must not claim that a vector computed before late evidence is equivalent to a later recomputation.

## 12. Training/inference parity and preprocessing lifecycle

1. Both callers import the same package and immutable feature schema.
2. Dataset adapters produce the same validated intermediate contract used by canonical-flow inference; adapter-only provenance and labels remain outside the vector.
3. Fit-free raw features are computed before any split-aware fitting.
4. Split membership is frozen before `fit` is allowed.
5. Imputers, scalers, vocabularies, encoders, samplers, and selectors fit on training only.
6. Validation and test call `transform` only; the API provides no accidental `fit_transform` path outside a training context.
7. A fitted preprocessing manifest lists every statistic/token, training split hash, feature schema, library/runtime version, checksum, and compatible input/output contracts.
8. Golden raw samples are passed through both training and inference entry points; ordered vectors and hashes must match byte-for-byte or within an explicitly versioned floating tolerance.
9. Incompatible or missing schema/vocabulary/preprocessor versions fail closed with stable non-sensitive codes.
10. The pipeline has no model import, activation, prediction, or prevention dependency in Sprint 4.

## 13. Leakage-prevention plan

### 13.1 Static controls

- Machine-readable denylist enforced against feature definitions and dataset mappings.
- Separate types for provenance, label, split metadata, raw features, and serving vectors.
- No generic `dict` pass-through from dataset rows into transforms.
- Feature dictionary requires inference availability and leakage rationale for every feature.
- Contract test fails if banned names or source-only fields enter ordered vectors.

### 13.2 Dataset controls

- Detect exact and near duplicates before splitting.
- Analyze host, flow/session, time, capture, generator, and file relationships.
- Prefer capture/time/host/source-aware partitions; random row splits require explicit evidence that related records cannot cross partitions.
- Fit preprocessing only after the split manifest is immutable.
- Keep the final test partition unopened for tuning and feature decisions.
- Record every exclusion and mapping; never delete inconvenient records silently.
- Compare label distributions and quality across partitions without using the test partition to tune the pipeline.

### 13.3 Review output

`docs/data/LEAKAGE_REVIEW_<dataset-version>.md` must list suspected leakage fields, relationship analysis, duplicate policy, split choice, rejected alternatives, residual leakage risk, reviewer, and approval status. No Sprint 5 experiment may start without an approved leakage review.

## 14. Dataset manifest and split manifest

### 14.1 Dataset manifest

The canonical JSON manifest should include:

- manifest schema/version and dataset version;
- official source URL, publisher, page-review date, acquisition authorization, acquisition time, and acquisition method;
- terms/license text reference and hash, permitted/prohibited use, commercial-use restriction, required citations, and redistribution policy;
- original filenames, byte sizes, detected media types, and SHA-256 hashes;
- raw storage opaque reference and access classification, never an unrestricted filesystem path;
- capture environment, dates, tools, schema/feature-description source, units, labels, and known limitations;
- row/file counts, duplicate/missing/invalid/class-distribution summary;
- adapter version/hash and canonical mapping review;
- related manifest predecessors, code commit, and reviewer.

### 14.2 Split manifest

The split manifest should include:

- immutable dataset-manifest hash;
- split strategy and rationale;
- grouping keys and time/source boundaries;
- deterministic seed only where randomness is unavoidable;
- ordered row-identity hashes per partition or a deterministic selection rule;
- train/validation/test counts and class summaries;
- exact/near-duplicate cross-partition checks;
- excluded rows and reason counts;
- creation code/version, timestamp, reviewer, and SHA-256.

Labels and row identities stay in controlled training metadata. They are never sent to an inference transform.

## 15. UNSW-NB15 official-source investigation and acquisition gate

The existing review found UNSW-NB15 conditionally suitable for academic use and recorded the official UNSW page. That review does not authorize acquisition. Immediately before any future download, the implementation task must stop at this gate:

1. Open the current official UNSW source over HTTPS; do not use mirrors, Kaggle copies, or search-result downloads as authority.
2. Record the page URL, retrieval timestamp, publisher identity, advertised files/sizes, feature-description links, citations, and any access instructions.
3. Capture a local text/PDF evidence snapshot or hash of the current terms where legally permitted; never copy credentials or session material.
4. Reconfirm academic/portfolio use, MIT-code separation, non-redistribution, citation requirements, and the need for author agreement before commercial use.
5. Compare the current page with `docs/DATASET_REVIEW_UNSW_NB15.md`; any changed or ambiguous terms block acquisition pending owner/legal clarification.
6. Estimate disk needs for download, temporary extraction, raw preservation, processed artifacts, and safety margin on the approved host.
7. Define exact requested files. Default to the prepared tabular files and feature documentation for Sprint 4; the approximately 100 GB raw capture is out of scope unless separately justified and approved.
8. Define maximum download size, timeout/retry behavior, staging location outside Git, restrictive permissions, and cleanup behavior before network transfer.
9. Obtain explicit owner authorization naming the source, files, expected size, terms disposition, and storage location.
10. Only after authorization, download to an opaque temporary file, enforce byte limits, calculate SHA-256 locally, validate content/media type, and atomically move it to controlled storage.
11. If archives are supplied, inspect without executing and extract only with file-count, total-size, compression-ratio, nesting, path-traversal, link, device-file, and timeout limits. Unsupported archives fail closed.
12. Create the dataset manifest before parsing; record when the official publisher provides no independent checksum rather than inventing one.
13. Run schema/quality/leakage profiling in bounded read-only chunks. Never execute macros, scripts, notebooks, binaries, or content from the dataset.
14. Do not commit raw data, extracts, transformed rows, generated matrices, or publisher material whose redistribution is not authorized.
15. Stop again for dataset acceptance approval before feature fitting or Sprint 5 model work.

No step above has been executed by this planning task, and no dataset bytes have been acquired.

## 16. Artifact provenance and storage

- Controlled feature/dataset artifacts use opaque generated references under the existing local artifact volume; no client supplies a storage path.
- Staging uses restrictive permissions, atomic rename, bounded temporary storage, and cleanup on success/failure.
- PostgreSQL stores artifact kind, manifest/schema version, SHA-256, byte size, detected media type, creator/job, timestamps, expiry/retention class, and lifecycle status.
- Every derived artifact links to its source manifest hash, split manifest where relevant, feature-schema hash, preprocessing manifest, code commit, and parent artifact hashes.
- Hash verification occurs before every read and after every write. A mismatch fails closed, records a safe audit event, and never falls back silently.
- Proposed feature-matrix format is Parquet with an explicit Arrow schema plus canonical JSON manifests. This requires dependency/security/resource review before approval. JSONL remains the golden-fixture interchange format.
- Pickle, joblib, executable notebooks, dynamic imports, macros, and arbitrary object deserialization are prohibited.
- Artifact references, internal paths, raw rows, and sensitive addresses never appear in ordinary API errors, logs, audit metadata, or UI.

## 17. Proposed PostgreSQL migration

Implementation would add one reversible `0004_sprint4_features` migration containing metadata only:

1. `feature_schema_versions` — immutable name/version/input contract/ordered definition/preprocessing config/banned fields/hash/code version/lifecycle/review provenance.
2. `dataset_versions` — source/terms/citation/acquisition/manifest hashes and controlled raw-artifact metadata; rows may exist in `proposed` state without downloaded content.
3. `dataset_split_versions` — immutable dataset reference, strategy, grouping/boundary summary, manifest reference/hash, counts, and review state.
4. `feature_materialization_jobs` — actor, source scope, schema/split references, idempotency key, status/counts/quality/error/timestamps, and controlled output artifact reference/hash.
5. `feature_artifacts` — immutable source/schema/preprocessing/code provenance, reference, media type, size, SHA-256, row/column counts, retention class, and lifecycle.
6. Sprint 4 permissions and approved role assignments.

Required constraints include unique semantic versions/hashes, immutable manifest/definition fields, one actor/source/idempotency scope, valid lifecycle transitions, non-negative bounded counts/sizes, no output artifact before successful completion, and restricted lineage foreign keys. No unbounded feature vector JSON, label column, raw dataset row, or filesystem path is stored in PostgreSQL.

Downgrade removes only Sprint 4 metadata/permissions and restores Sprint 3 head. It must not delete Sprint 0–3 state or raw/derived files implicitly. Before downgrade, controlled Sprint 4 artifacts require an explicit inventory/export/delete decision because dropping metadata while leaving orphaned files is unsafe. Fresh upgrade, downgrade to `0003_sprint3_detection`, re-upgrade, existing-data preservation, immutability, uniqueness, and orphan-prevention tests are mandatory.

## 18. RBAC and audit

### 18.1 Proposed permissions

| Permission | Purpose | Proposed roles |
|---|---|---|
| `features:read` | View feature schemas, safe dictionary, job status, and quality summaries | SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `features:materialize` | Request a bounded materialization from an approved source | Security Admin, System Admin |
| `features:review` | Approve/retire immutable feature schemas and preprocessing manifests | Security Admin |
| `datasets:read` | View safe dataset/terms/manifest metadata, never raw rows/paths | Senior Analyst, Security Admin, System Admin, Auditor |
| `datasets:manage` | Record proposed/accepted manifests and acquisition evidence | Security Admin |

Viewer receives no dataset or feature-job detail by default. Sensor principals receive none of these permissions. Raw dataset access is not provided by an API in Sprint 4.

### 18.2 Audit events

Audit schema/manifest creation, review, retirement, materialization request/success/failure, compatibility rejection, integrity mismatch, quality/leakage gate result, artifact cleanup, and administrative metadata reads where required. Metadata contains IDs, hashes, versions, counts, safe reason codes, and outcomes—not raw rows, labels tied to endpoints, terms credentials, paths, or exceptions. Schema approval and dataset acceptance fail closed if audit persistence fails.

## 19. Celery tasks and resource limits

### 19.1 Tasks

- `features.materialize(job_id: UUID)` — resolves one persisted bounded job and emits one controlled artifact.
- `features.profile_dataset(job_id: UUID)` — profiles an explicitly accepted dataset manifest in chunks; unavailable until acquisition is separately authorized.
- `features.reconcile_pending()` — re-enqueues stale pending UUIDs.
- `features.cleanup()` — deletes expired feature artifacts only after authoritative DB selection and records counts/audit.

No task accepts rows, feature definitions, labels, paths, URLs, credentials, task names, Python objects, or artifact bytes.

### 19.2 Proposed safe defaults

| Control | Proposed default |
|---|---|
| Feature schemas supported concurrently | 10 |
| Features per schema | 128 maximum |
| Windows per schema | 4 maximum; v1 uses 60 and 300 seconds |
| Canonical flows per online materialization | 10,000 |
| Dataset processing chunk | 25,000 rows, reduced if measured memory requires |
| Output rows per job | 100,000 unless an owner-approved dataset job profile overrides it |
| Soft/hard task time | 120/135 seconds for flow jobs; dataset profile may use separately bounded chunks |
| Retries | 2 with backoff and sanitized terminal failure |
| Worker prefetch | 1 |
| Temporary/output bytes | explicit per-job estimates and hard caps; never remaining-disk based alone |
| Pending reconciliation | 60 seconds |
| API page size | 100 |

The approved 8 GB host requires measured peak RSS, elapsed time, output size, and rows/second for 10,000 synthetic flows before defaults are accepted. A dataset-scale job must be chunk-restartable and must never rely on loading all rows or windows into memory.

## 20. Minimal API and UI

Proposed routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `GET /feature-schemas` | List approved/draft safe schema metadata | `features:read`, bounded page |
| `GET /feature-schemas/{id}` | Ordered dictionary and compatibility metadata | `features:read`, no code/path |
| `POST /feature-schemas/{id}/review` | Approve/retire immutable schema | `features:review`, CSRF+Origin, reason/evidence, audit |
| `POST /feature-jobs` | Request bounded materialization from approved persisted source | `features:materialize`, idempotency, CSRF+Origin, no path/range override |
| `GET /feature-jobs` | List safe status/quality summaries | `features:read`, bounded filters/page |
| `GET /feature-jobs/{id}` | Inspect counts, versions, safe error, artifact hash metadata | `features:read`, no raw vector/path |
| `GET /datasets` | List proposed/accepted manifest metadata | `datasets:read`, no raw rows/path |
| `GET /datasets/{id}` | Terms/citation/provenance/quality/split summary | `datasets:read`, field redaction |

Dataset acquisition is not an API endpoint. It remains an operator/owner-approved controlled procedure. Arbitrary URL fetch, server-side download, archive upload, raw artifact download, feature-row preview, model endpoint, or historical free-form query is excluded.

The minimal UI shows feature versions/order/units/missing policies, job status/counts/quality, dataset terms/citations/provenance, compatibility failures, and explicit planning/approval state. It contains no model metrics, prediction, activation, prevention, or raw-data browser.

## 21. Synthetic fixtures

Fixtures must precede implementation and use documentation IP ranges only. Required families:

1. Golden canonical flows for every direct feature, including IPv4/IPv6, port absence/zero/boundaries, protocol/state missing/unseen, zero duration/packets, and maximum counters.
2. Exact ordered vectors and canonical hashes for fit-free v1.
3. Threshold-minus/at/plus numeric range and clipping-policy cases.
4. NaN/infinity/wrong-type/overflow/Unicode/control/extra-field inputs that fail safely.
5. 60/300-second event-time windows with exact lower/cutoff boundaries, equal timestamps, duplicates, multi-sensor separation, out-of-order input, and late revisions.
6. Vocabulary training-only fixture with validation/test-only unseen categories.
7. Training/inference parity fixture entering through both adapters.
8. Leakage fixture containing tempting labels, row IDs, IPs, timestamps, job IDs, alerts, and split fields that must be rejected from the vector.
9. Dataset-manifest/split-manifest valid, missing, tampered-hash, changed-terms, duplicate, and cross-split-leakage cases.
10. Artifact corruption, partial write, path traversal, oversized output, cancellation, retry, and cleanup cases.
11. Representative 10,000-flow bounded benchmark generated in temporary storage, never committed as a large fixture.

## 22. Test matrix and gates

### 22.1 Unit and contract

- Feature schema/dictionary/vector/manifest strict validation and unknown-field rejection.
- Feature order, names, types, units, ranges, missing policy, definition hash, and semantic-version behavior.
- Safe division, overflow, finite output, rounding/dtype, port class, protocol/state normalization.
- Every window boundary, stable tie-break, duplicate, sensor scope, cutoff, out-of-order, and late revision.
- Vocabulary ordering, reserved tokens, training-only fit, unseen categories, and no accidental mutation.
- Banned-field/leakage tests and separation of label/provenance/vector types.
- Golden training/inference parity and repeat-process/platform determinism.

### 22.2 Integration/database/Celery

- Persisted job before dispatch, JSON-only UUID task, bounded retry, reconciliation, idempotent replay, and terminal safe failure.
- Feature-schema/manifest immutability and concurrent idempotency constraints on PostgreSQL.
- Artifact atomic write/hash verification/corruption rejection/cleanup and DB lineage.
- Upgrade/downgrade/re-upgrade and preservation of all Sprint 0–3 rows.
- Redis unavailable before/after persistence, worker crash before/after artifact move, PostgreSQL outage, disk/full-cap behavior, and orphan reconciliation.

### 22.3 Security/privacy/RBAC

- Complete six-role allow/deny matrix for every new route and schema review action.
- CSRF, Origin, session expiry/revocation, CORS, IDOR, mass assignment, stale review state, and unauthorized artifact metadata.
- Malicious manifest text, spreadsheet-formula prefixes, HTML/script strings, path/URL injection, archive metadata, and safe rendering/logging.
- No raw endpoint, row, label, vector, source path, URL credential, exception, or secret in API errors, logs, audits, metrics, or UI.
- No arbitrary outbound fetch, code execution, pickle/joblib loading, generic expression, model import, or prevention dependency.
- Simulation-only/container capability guard unchanged.

### 22.4 Data and ML-quality gates without model training

- Exact/near duplicate report, missing/invalid/outlier distribution, label/class summary, and mapping coverage.
- Split relationship audit and cross-partition duplicate/group checks.
- Train-only fitting assertion for every fitted preprocessing object.
- Final-test isolation guard preventing test-derived fitting or feature decisions.
- Dataset adapter versus canonical inference mapping parity.
- No performance/detection claim derived from feature completion alone.

### 22.5 Performance/frontend/runtime

- 10,000 synthetic flows under approved worker memory/time limits with recorded RSS/CPU/time/output.
- High-cardinality groups, four-window maximum, 128-feature maximum, chunk restart, queue retry, and disk-cap tests.
- Backend format/lint/type/unit/integration/security/dependency/secret gates.
- Frontend lint/type/component/build/audit and accessibility/keyboard checks.
- Fresh Compose build/start, migration round trip, API health, dashboard, Celery ping/registration, synthetic feature job, cleanup, and no firewall-state change.

No skipped required check is a pass. Semgrep, Trivy, SBOM, long-running fuzz/load, full browser E2E, backup/restore, and non-local TLS remain explicit hardening unless added as Sprint 4 gates.

## 23. Data-quality report

Every accepted dataset or synthetic benchmark produces a versioned report containing source/manifest hashes, schema mapping coverage, row/file counts, class distribution, exact/near duplicates, missing/invalid/non-finite/out-of-range counts, categorical cardinality, suspected capture artifacts, leakage candidates, split integrity, excluded rows/reasons, processing limits, elapsed time, peak memory, and residual limitations.

The report must distinguish measured facts from assumptions and must not include raw sensitive rows. A quality report does not approve a dataset for model training; owner acceptance and leakage review are separate gates.

## 24. Security, privacy, and failure behavior

### Security

- Treat datasets, CSV headers/cells, manifests, terms text, feature definitions, artifact metadata, and categorical values as hostile.
- Never execute content or allow spreadsheet formulas to become active exports.
- Use strict typed schemas, bounded text/nesting/cardinality, canonical JSON hashing, parameterized SQL, and atomic controlled file operations.
- Feature schema and accepted dataset-manifest changes are immutable, authorized, reviewed, and audited.

### Privacy

- Raw endpoints and sensor identities are computation context/provenance only, not model values or ordinary UI output.
- Feature artifacts remain sensitive because aggregated behavior can identify systems. Apply RBAC, opaque storage, retention, and sanitized demos.
- Do not send dataset values to external services. Official-source browsing discloses no internal telemetry.
- Dataset and feature exports remain out of Sprint 4 unless separately reviewed.

### Failure behavior

- Incompatible schema/vocabulary/preprocessor: fail closed with a stable code.
- Integrity mismatch or partial artifact: quarantine/mark failed; never consume or overwrite the last good artifact.
- Resource cap: fail before unbounded allocation; retain safe counts and cleanup temporary data.
- Redis unavailable: persisted pending jobs remain reconcilable.
- PostgreSQL unavailable: no untrackable job or artifact is accepted.
- Late evidence: new immutable revision; never silently mutate a frozen dataset or vector.
- Dataset terms/source ambiguity: block acquisition and processing.
- Audit failure: fail schema/dataset approval and other high-sensitivity changes.

## 25. Retention proposal

Feature and dataset retention is not fully decided. Proposed defaults:

| Data | Proposed retention |
|---|---|
| Temporary feature-job files | Delete on completion/failure; safety cleanup within 24 hours |
| Flow-derived feature artifacts | 30 days, aligned with stored predictions and source-flow development policy |
| Synthetic golden fixtures | Retain in Git when small and sanitized |
| Dataset manifests, terms evidence hashes, split manifests, feature schemas, dictionaries, and quality/leakage reports | Retain by version as governance evidence |
| Raw UNSW-NB15 files | Controlled local storage only; retain only while authorized experiments require them, with owner-approved deletion review |
| Processed dataset feature matrices | Proposed 30 days unless linked to an approved reproducibility package; no exceptional holds in MVP |

Retention cleanup must preserve hashes, minimal governance metadata, audit lineage, and documented reproducibility requirements without preserving raw rows unnecessarily.

## 26. Assumptions and proposed defaults

These are recommendations, not confirmed owner decisions:

| ID | Proposed default | Consequence if rejected |
|---|---|---|
| S4-A01 | Feature v1 uses only semantics available in canonical flow v1; DNS/HTTP/TLS/detailed TCP/auth features remain deferred. | New canonical contracts and ingestion work enter Sprint 4. |
| S4-A02 | Use direct flow features plus fixed as-of 60/300-second windows. | Feature dictionary, resource bounds, and parity tests change. |
| S4-A03 | Use `(event_time,event_key)` ordering and immutable late-data materialization revisions. | Window identity and historical reproducibility change. |
| S4-A04 | Keep raw IP/sensor/event identities out of model values. | Privacy/leakage threat review must be reopened. |
| S4-A05 | Store vectors as controlled artifacts, not unbounded PostgreSQL rows. | Migration/storage/query design changes. |
| S4-A06 | Use Parquet plus canonical JSON manifests after Arrow dependency review; JSONL for golden fixtures. | Choose another typed, streamable format and update compatibility tests. |
| S4-A07 | Fit vocabularies/imputation/scaling only on the frozen training partition; reserved missing/unknown tokens are fixed. | Leakage controls would be weakened and require rejection or redesign. |
| S4-A08 | Add the five proposed feature/dataset permissions to existing roles; no raw-data API. | RBAC matrix and UI scope change. |
| S4-A09 | Use the proposed Celery limits and chunk sizes subject to measured reduction on the 8 GB host. | Owner supplies stricter bounds. |
| S4-A10 | Retain flow-derived/processed feature artifacts for 30 days and governance manifests by version. | Cleanup/schema/storage plan changes. |
| S4-A11 | Official-source investigation is part of Sprint 4, but acquisition requires a distinct explicit authorization after that gate. | A single implementation authorization may instead name exact files and authorize bounded acquisition. |
| S4-A12 | No feature rows or dataset extracts are displayed in the UI or committed to Git. | Privacy/export design requires separate review. |

## 27. Owner decisions required before implementation

The owner must approve or change each item:

1. Approve canonical-flow-only feature v1 and defer unavailable DNS/HTTP/TLS/detailed TCP/authentication features.
2. Approve the direct feature list and 60/300-second as-of window feature list.
3. Approve stable `(event_time,event_key)` ordering and immutable late-data revisions.
4. Approve the banned-field policy, especially raw IPs, exact timestamps, sensor IDs, event IDs, and all detection/label fields.
5. Approve feature-vector artifact storage instead of PostgreSQL vector rows.
6. Approve Parquet/Arrow subject to dependency review, or select another artifact format.
7. Approve training-only vocabulary/imputation/scaling and fixed missing/unknown tokens.
8. Approve the proposed Sprint 4 RBAC assignments and no raw-data API.
9. Approve task/chunk/feature/window limits subject to measured downward adjustment.
10. Approve feature/dataset artifact retention periods.
11. Choose acquisition boundary: investigation only with a later acquisition prompt, or explicitly authorize named prepared UNSW-NB15 files after the official-source gate passes.
12. Approve prepared tabular UNSW-NB15 files as the maximum candidate scope; raw approximately 100 GB PCAP remains excluded.
13. Approve no dataset row/vector preview or export UI in Sprint 4.
14. Approve migration `0004_sprint4_features` metadata tables and downgrade artifact-inventory requirement.
15. Decide whether feature-schema review may be self-reviewed by a solo Security Administrator or needs a second account.

## 28. Dependencies and deferred work

### Dependencies

- Published Sprint 3 SHA and hosted CI — satisfied.
- Canonical flow v1, controlled artifact volume, PostgreSQL/Celery/Redis, RBAC/audit, retention, and CI — implemented.
- Owner decisions in Section 27 — blocking implementation.
- Current official-source/terms investigation and explicit acquisition authority — blocking any download.
- Approved feature artifact-format dependency review — blocking Parquet implementation.

### Deferred

- DNS/HTTP/TLS/authentication/packet-sample canonical contracts and features.
- Dataset acquisition until separately authorized.
- Supervised training, model artifacts/registry/inference and safe model serialization (Sprint 5).
- Anomaly and ensemble work (Sprint 6), explainability/intelligence (Sprint 7), incidents (Sprint 8), and prevention simulation (Sprint 9).
- Live capture and all real prevention.

## 29. Major risks and mitigations

| Risk | Severity | Mitigation / approval evidence |
|---|---|---|
| Label or capture leakage inflates later results | High | Typed separation, banned fields, duplicate/relationship audit, group/time split, train-only fit, independent leakage review |
| Training and inference transformations diverge | High | One shared package/schema, golden dual-entry parity tests, immutable preprocessing manifest |
| Dataset-native columns lack serving semantics | High | Per-field semantic mapping and inference-availability proof; unsupported columns excluded |
| Out-of-order/late events rewrite features | High | Explicit as-of order, snapshot hashes, immutable revisions, frozen experiment manifests |
| Raw endpoints or derived behavior leaks | High | Raw identities excluded from vectors/UI, sensitive classification, RBAC, opaque artifacts, retention |
| Malicious dataset/artifact exploits parser or filesystem | Critical | Official source, no execution, content checks, extraction caps, controlled paths, non-root worker, integrity verification |
| Dataset terms or redistribution are violated | High | Current official review, owner acquisition gate, citations, no Git/data redistribution, commercial-use prohibition |
| Artifact corruption or replacement breaks reproducibility | High | SHA-256 before read/after write, immutable lineage, atomic writes, controlled volume, audit |
| Feature jobs exhaust 8 GB host/disk | High | Streaming chunks, hard row/feature/window/byte/time limits, peak-memory benchmark, cleanup/restartability |
| Vocabulary or imputation sees validation/test data | High | Split freeze before fit, training-split hash in fitted manifest, API type/contract guards |
| Feature schema changes silently | High | Complete canonical definition hash, immutable versions, review/audit, compatibility tests |
| New dependencies create supply-chain risk | High | Pinning, pip-audit, provenance, container build review; Parquet dependency needs explicit review |
| Sprint 4 accidentally becomes model or prevention work | Critical | Scope/dependency guards; no ML model/prevention imports, endpoints, dependencies, or capabilities |

No Critical or High residual risk may be accepted silently. The Sprint 4 completion report must state owner, mitigation evidence, review date, and disposition for any remaining one.

## 30. Implementation sequence after authorization

1. Reconfirm public SHA, Run #5, clean tree, and create a short-lived Sprint 4 branch from the published baseline.
2. Record approved Section 27 decisions and update architecture/threat/risk/schema/API/test/deployment documents before code where contracts change.
3. Create strict synthetic golden, leakage, missing/unseen, boundary, window, late-data, and manifest fixtures.
4. Freeze `FeatureDefinitionV1`, `FeatureSchemaV1`, `FeatureVectorV1`, dataset/split/artifact/preprocessing manifest contracts and canonical hashes.
5. Implement the shared fit-free feature package and direct transformations.
6. Implement deterministic as-of window context with bounded indexed queries and pure batch parity path.
7. Implement categorical/missing/non-finite/range policies and quality accounting.
8. Add training/inference entry-point parity and leakage guards before dataset adapters.
9. Review and implement migration `0004_sprint4_features`; run PostgreSQL round-trip tests.
10. Add persisted jobs, JSON-only Celery tasks, idempotency/reconciliation/cleanup, controlled atomic artifacts, and integrity checks.
11. Add minimal RBAC/audit APIs and UI.
12. Execute the official UNSW source investigation gate and stop if acquisition is not separately authorized.
13. If and only if specifically authorized, acquire only named prepared files under the documented bounds, create manifests, and run bounded quality/leakage profiling. No model training.
14. Run all unit/contract/integration/security/privacy/RBAC/migration/Celery/Docker/frontend/performance/parity/leakage gates.
15. Update all affected documents and create `docs/SPRINT_4_COMPLETION_REPORT.md`.
16. Review the entire uncommitted diff for scope, secrets, dataset files, artifacts, large files, licenses, leakage, prevention separation, and Critical/High issues.
17. Stop at the uncommitted Sprint 4 completion gate. Do not commit or publish without separate authorization.

## 31. Proposed acceptance criteria

| Criterion | Required evidence |
|---|---|
| Entry gate and Sprint 3 publication records are correct | SHA/CI/clean-tree evidence and documentation diff |
| Strict immutable feature/dataset/split/artifact contracts | Contract tests, canonical hashes, schema docs |
| Feature dictionary is complete and conservative | Machine-readable dictionary plus analyst documentation/review |
| Direct and window features are deterministic | Golden repeat/order/boundary/timezone tests |
| Missing/unseen/non-finite/range policies are safe | Negative and exact-output tests; no NaN/infinity |
| Training/inference parity is proven | Same raw samples through both entry points with identical order/hash |
| Incompatible versions fail closed | Schema/vocabulary/preprocessor compatibility tests |
| Leakage controls and split policy are documented | Denylist tests, duplicate/relationship audit, approved leakage review |
| Late/out-of-order behavior preserves history | Snapshot/revision and frozen-manifest tests |
| Dataset manifest and official-source gate are auditable | Terms/citation/source/acquisition decision evidence; no unauthorized bytes |
| Artifact provenance and integrity are complete | Atomic write, SHA-256, corruption, lineage, cleanup tests |
| Celery work is bounded/idempotent/recoverable | JSON-only UUID, retry/reconcile/resource/concurrency tests |
| RBAC/audit/privacy boundaries hold | Six-role negative matrix, CSRF/Origin, redaction/log/error tests |
| Reversible PostgreSQL migration works | Fresh upgrade/downgrade/re-upgrade and Sprint 0–3 preservation |
| Resource bounds fit approved host | 10,000-flow benchmark with time/RSS/output; chunk tests |
| Minimal API/UI exposes metadata only | API/component/accessibility tests; no raw data/model control |
| Quality/security/dependency/secret/container gates pass | Recorded commands and actual results; skips classified |
| Docker/Celery/health/synthetic feature path passes | Fresh isolated stack and job evidence |
| No dataset/model/live capture/Sprint 5/prevention scope entered | Diff, dependency, Git large-file, and capability review |
| Documentation and completion report are current | Link/reference/traceability review |
| No unresolved Critical or High issue | Final uncommitted Sprint 4 review |

Sprint 4 is complete only when all applicable criteria pass and any dataset acquisition performed was separately authorized. Planning approval alone is not implementation approval.

## 32. Plan decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The proposed design satisfies the Sprint 4 planning boundary and keeps dataset acquisition, model work, live capture, and prevention unauthorized. Implementation must not begin until Section 27 decisions are approved and any future UNSW-NB15 download receives explicit authority.

## 33. Exact Sprint 4 implementation authorization prompt

```text
Approve the AegisAI NIDPS Sprint 4 implementation plan and begin Sprint 4 implementation only.

Before proceeding:
- Confirm public main is still at b514aa3592487a65b8de8e1cfa14f4f9b80c5976 or identify and review any newer authorized baseline.
- Confirm hosted CI Run #5 succeeded for that SHA.
- Confirm the working tree contains only the approved Sprint 3 publication-documentation updates and docs/SPRINT_4_IMPLEMENTATION_PLAN.md.
- Create a new Sprint 4 branch from the published baseline without rewriting history.
- Read and follow all governing documents and docs/SPRINT_4_IMPLEMENTATION_PLAN.md completely.

Use these owner decisions:
- Feature input scope: [canonical flow v1 only / approved additional canonical contracts]
- Direct and window features: [approve Section 8 defaults / list changes]
- Window/late-data semantics: [approve as-of ordering and immutable revisions / approved alternative]
- Banned fields: [approve Section 8.3 / list exceptions with leakage rationale]
- Vector storage: [controlled artifacts / PostgreSQL rows with approved bounds]
- Artifact format: [Parquet after Arrow review / approved alternative]
- Missing/vocabulary/fitted preprocessing: [approve training-only defaults / list changes]
- RBAC and raw-data API: [approve Section 18 and no raw-data API / list changes]
- Resource limits: [approve Section 19 defaults subject to measured reduction / replacements]
- Feature/dataset retention: [approve Section 25 defaults / replacements]
- UNSW-NB15 boundary: [official-source investigation only, no download / authorize only explicitly named prepared files after the gate passes]
- Raw UNSW-NB15 PCAP: [excluded / separately justified scope]
- Dataset/vector UI preview/export: [excluded / approved bounded design]
- Migration metadata tables: [approve Section 17 / changes]
- Feature-schema review separation: [solo Security Administrator self-review / distinct reviewer]

Implement only the approved Sprint 4 scope: strict versioned feature/dataset/split/preprocessing/artifact contracts, synthetic fixtures, shared deterministic flow transformations, approved fixed-window features, missing/unseen/range policies, training/inference parity and leakage guards, bounded feature jobs, controlled artifact provenance, reversible metadata migration, RBAC/audit, minimal APIs/UI, tests, and documentation.

Do not download any dataset unless the owner selection above explicitly names and authorizes the prepared files after the official-source/terms gate succeeds. Do not train, tune, serialize, load, register, activate, or score a model. Do not add DNS/HTTP/TLS/authentication features without approved canonical contracts. Do not add anomaly/ensemble/intelligence/incident functionality, live capture, real prevention, privileged containers, host networking, firewall integration, Sprint 5 work, commit, or publication.

Run and record all applicable formatting, linting, typing, unit, contract, parity, determinism, leakage, missing/unseen, late-data, artifact-integrity, authorization, CSRF/Origin, privacy, security, concurrency, idempotency, resource, migration upgrade/downgrade/re-upgrade, Celery, Docker, health, frontend, dependency, secret-scanning, simulation-only, and synthetic end-to-end checks.

Update affected documentation and create docs/SPRINT_4_COMPLETION_REPORT.md. Stop at the uncommitted Sprint 4 completion gate and wait for separate review/publication approval.
```
