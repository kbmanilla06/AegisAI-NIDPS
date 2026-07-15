# Sprint 5 Synthetic-Only Fallback Plan

**Planning date:** 2026-07-14

**Status:** Gate 5S-A defaults approved and implemented locally; Gate 5S-B/5S-C remain unauthorized. See `docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md`.

**Target:** Sprint 5 synthetic-only engineering demonstration

**Release boundary:** Sprints 0–9, IDS with simulated IPS

**Published baseline:** public `main` at `72c97b15f9bb31ddb6810a397afc682893497bab`

**Working branch:** `codex/sprint-5a-pre-acquisition`

**UNSW-NB15 status:** Blocked and deferred; acquisition remains false

## 1. Planning outcome

Publisher outreach is cancelled. The prepared Gmail draft must not be sent, and the publisher must not be contacted through another channel. This plan replaces publisher-dependent Sprint 5 work with a synthetic-only fallback that can demonstrate deterministic dataset, preprocessing, safe-artifact, registry, and offline-scoring engineering without presenting synthetic results as evidence of real intrusion-detection performance.

This plan originally authorized no implementation. The owner subsequently approved all recommended defaults and authorized Gate 5S-A only. Gate 5S-A implementation evidence is recorded separately; this plan still does not authorize fitting preprocessing, training or evaluating a model, creating an ONNX artifact, registering/activating/scoring a model, Gate 5S-B/5S-C, committing, or publishing.

## 2. Documents read and governing order

This plan was reconciled against the complete contents of:

- `AegisAI-NIDPS-Master-Prompt.md`
- `AegisAI-NIDPS-Implementation-Guide.md`
- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/USE_CASES.md`
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
- `docs/features/FEATURE_DICTIONARY_V1.md`
- `docs/features/FEATURE_DICTIONARY_V1.json`
- `docs/SPRINT_4_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_4_COMPLETION_REPORT.md`
- `docs/SPRINT_5_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_5_PHASE_5A_PREACQUISITION_REPORT.md`
- `docs/SPRINT_5_PHASE_5A_BLOCKER_RESOLUTION_PLAN.md`
- `docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md`

If this plan conflicts with a governing safety boundary, the stricter boundary applies. A later authorization may narrow this plan but must not silently broaden it.

## 3. Confirmed requirements

The following are already decided and are not defaults introduced by this plan:

1. The MVP is an IDS with simulated IPS through Sprint 9. No component in this fallback may alter network or firewall state.
2. UNSW-NB15 acquisition is blocked and deferred. No real dataset, sample, prepared split, mirror, cached copy, tokenized link, or dataset payload may be used.
3. `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` remain excluded.
4. No publisher contact, metadata probe, `HEAD`/`GET`, source browsing, token handling, acquisition manifest, approval transition, or transfer task is permitted.
5. Synthetic inputs must be project-generated from canonical flow schema v1 only.
6. Feature schema `flow_features/1.0.0` is fixed at 39 ordered model features: 17 direct features and 11 features for each inclusive 60- and 300-second event-time window.
7. Controlled Parquet contains the 39 model features and the 7 reserved `__aegis_` provenance columns. Training selectors must select exactly the 39 feature names in the approved dictionary.
8. Raw endpoint identities, event timestamps, event/job/sensor IDs, labels, split identifiers, scenario identifiers, detection results, alerts, risk/confidence, incidents, and prevention data are prohibited model values.
9. One shared versioned feature/preprocessing path must serve training and later offline scoring. Fitted state is derived from training only.
10. ONNX plus canonical JSON remains the approved D-13 safe-artifact policy. Pickle, joblib, cloudpickle, dill, custom operators, external tensor data, and arbitrary user model upload remain prohibited.
11. PostgreSQL is authoritative; Redis is coordination only; Celery messages are JSON-only and contain bounded persisted UUIDs.
12. Controlled artifacts use opaque local-volume references, restrictive permissions, atomic promotion, and SHA-256 metadata in PostgreSQL.
13. Secure cookie sessions, centralized RBAC, CSRF plus Origin validation, append-oriented audit, safe errors, and six-role negative authorization tests apply to every later protected interface.
14. Predictions and flow-derived feature artifacts retain the approved 30-day limit. Audit records retain the approved 180-day limit. Exceptional holds remain disabled.
15. No model-only evidence may mutate an alert, rule, assessment, incident, prevention request, or prevention simulation.
16. No online or streaming inference, live packet capture, privileged container, host networking, firewall capability, or enforcement dependency is allowed.
17. A synthetic score is not evidence of UNSW-NB15 performance, real-network effectiveness, generalization, zero-day detection, deployment readiness, or production suitability.

## 4. Cancellation and dataset boundary

The following state is frozen throughout this fallback:

- publisher outreach: `cancelled_do_not_send`;
- UNSW-NB15 acquisition: `blocked_deferred`;
- official candidate file manifest: absent;
- real dataset bytes received: zero;
- accepted dataset version: absent;
- real dataset feature materialization: absent;
- real-dataset performance claim: prohibited.

The existing pre-acquisition proposal contracts may remain in the uncommitted branch for separate review, but synthetic work must not call, extend, enable, or weaken them. No synthetic manifest may reuse an official dataset name, official source URL, publisher identity, official citation, or `UNSW`/`NUSW` filename. The word `UNSW-NB15` may appear only in governance status, negative tests, or limitations language stating that it was not acquired or evaluated.

## 5. Objective and non-objectives

### 5.1 Objective

Demonstrate that Aegis can safely and reproducibly carry a small, labeled, project-generated set of canonical flows through immutable dataset and split manifests, training-only preprocessing, bounded baseline training, safe ONNX conversion/parity, reviewed demo registry metadata, and isolated offline scoring—without creating evidence about real NIDPS quality.

### 5.2 Non-objectives

- validating detection efficacy on real traffic or a public benchmark;
- estimating production false-positive or false-negative rates;
- reproducing UNSW-NB15 or another dataset's distributions, labels, generators, or attacks;
- generating packets, PCAPs, payloads, exploit traces, credentials, or operational attack instructions;
- replacing Sprint 3 deterministic detections or creating alerts from model output;
- activating a model for online use;
- implementing anomaly detection, ensemble fusion, intelligence, incidents, explainability, drift, or Sprint 6+ functionality;
- enabling real or simulated prevention from model output.

## 6. Staged authorization model

Synthetic-only Sprint 5 is divided into three gates. Approval of one gate does not approve the next.

### Gate 5S-A — contracts, generator, dataset, and split

After separate authorization, implement strict synthetic scenario/generator contracts, generate only the approved bounded canonical-flow fixtures, materialize the existing 39-feature contract, create immutable synthetic dataset and split manifests, produce quality/leakage reports, and stop for owner acceptance.

No preprocessing may be fit and no model may be trained, converted, registered, loaded, activated, or scored at Gate 5S-A.

### Gate 5S-B — preprocessing, training, evaluation, and ONNX evidence

Only after the owner approves the exact synthetic dataset, split, feature, quality, and leakage hashes may a separate authorization permit training-only preprocessing, bounded baselines, demo-only evaluation, ONNX conversion/parity, and candidate artifact creation.

No model activation, online loading, production inference, alert mutation, or prevention integration is permitted at Gate 5S-B.

### Gate 5S-C — reviewed registry metadata and controlled offline scoring

Only after the owner approves the exact Gate 5S-B experiment, model-card, evaluation, runtime, and ONNX hashes may a separate authorization permit reviewed synthetic registry metadata and isolated offline batch scoring of approved synthetic feature artifacts.

The lifecycle remains synthetic-only and cannot become the general `active` supervised model used by later detection. Publication requires its own full-diff review and authorization.

## 7. Synthetic scenario and label contract

### 7.1 Proposed contract

`synthetic-flow-scenario/v1` describes bounded generation inputs but contains no executable code or user expression. Required fields are:

- contract/version and scenario catalog hash;
- opaque scenario key and immutable scenario version;
- fixed UTC start/end and event-count bound;
- fixed seed and deterministic generator version;
- one or more opaque group identities;
- allowed protocol, state, port-class, duration, packet, byte, interval, and destination-cardinality distributions selected from a closed registry;
- target label and label rationale;
- expected quality flags and invariant assertions;
- prohibition flags for payload, PCAP, real address, official-dataset emulation, alert mutation, and prevention.

Unknown fields, free-form Python, templates, shell text, dynamic imports, arbitrary distributions, network destinations, and user-supplied paths are rejected.

### 7.2 Proposed labels

Use only two explicitly synthetic target values:

- `synthetic_benign_like` (`0`)
- `synthetic_intrusion_like` (`1`)

These values mean only that the scenario generator was configured for one of two controlled demonstration families. They do not assert that a real flow is benign or malicious. The UI, reports, model cards, APIs, audit metadata, and exported aggregate metrics must retain the `synthetic_..._like` names and must not shorten them to `benign`, `attack`, or `intrusion` without the qualifier.

Labels are stored in a separate controlled target manifest keyed by a stable synthetic example identity hash. They never enter `CanonicalFlowV1`, `FeatureVectorV1.ordered_values`, or the 46-column Parquet artifact.

### 7.3 Proposed scenario families

The later generator should use a small closed catalog:

1. `background_mixed_services`: varied TCP/UDP, duration, packet/byte totals, and destination services.
2. `background_sparse_idle`: sparse events and missing prior-service context.
3. `background_bursty`: bounded benign-like bursts that deliberately overlap simple rate behavior.
4. `scan_like_fanout`: increased unique destination-port/address counts within fixed windows.
5. `failure_like_sequence`: bounded recognized Zeek failure-state sequences.
6. `connection_rate_like`: bounded dense event windows.
7. `ambiguous_overlap`: feature ranges intentionally shared by both labels to prevent a perfectly separable toy set.
8. `missing_unknown_boundary`: valid missing/unknown categories, zero denominators, port boundaries, and clipped-rate quality cases.

Scenario names and group identities are provenance only and are banned from the model matrix. No scenario creates payloads, packets, credentials, exploit steps, targets, or traffic on a network.

### 7.4 Canonical-flow constraints

- Use canonical flow schema literal `1` with strict validation and no extra fields.
- Use only IANA documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) or non-address opaque generation identities before canonicalization.
- Generate UTC timestamps from fixed scenario epochs, never current wall time.
- Generate paired ports, bounded protocol/state tokens, duration `0..604800000`, and non-negative signed-64 packet/byte totals.
- Use stable source event IDs that reveal no label or partition.
- Keep metadata bounded to approved scalar fields and exclude label/scenario/split information.
- Never write or transmit a packet, PCAP, archive, payload, credential, domain query, or actual network connection.

## 8. Approved 39-feature contract

The model matrix order is exactly:

```text
duration_ms, packet_count, byte_count, src_port_present, dst_port_present,
src_port, dst_port, src_port_class, dst_port_class, protocol,
connection_state, bytes_per_packet, packets_per_second, bytes_per_second,
zero_duration, zero_packets, rate_clipped,
w60_flow_count, w60_unique_dst_address_count, w60_unique_dst_port_count,
w60_packet_total, w60_byte_total, w60_failure_count, w60_mean_duration_ms,
w60_max_duration_ms, w60_mean_bytes_per_flow, w60_seconds_since_prior_service,
w60_prior_service_missing,
w300_flow_count, w300_unique_dst_address_count, w300_unique_dst_port_count,
w300_packet_total, w300_byte_total, w300_failure_count, w300_mean_duration_ms,
w300_max_duration_ms, w300_mean_bytes_per_flow, w300_seconds_since_prior_service,
w300_prior_service_missing
```

The seven reserved non-model provenance columns remain source event key, cutoff time, feature-schema hash, feature-schema version, source-snapshot hash, vector hash, and bounded quality flags under the `__aegis_` prefix. A matrix selector must fail unless the artifact has exactly those 46 approved columns, each required model column appears once in the approved order, and only the 39 model columns are selected.

Window semantics remain the Sprint 4 contract: grouping by authenticated synthetic sensor scope and source address, stable `(event_time,event_key)` ordering, inclusive lower time bound, inclusive as-of tuple, duplicate event keys counted once, and conflicting duplicates rejected. Late or out-of-order input creates a new immutable source snapshot/materialization revision rather than changing an approved dataset.

## 9. Immutable synthetic dataset manifest

### 9.1 Proposed `synthetic-dataset-manifest/v1`

The canonical JSON manifest records:

- `dataset_kind=project_generated_synthetic` and `synthetic_demo_only=true`;
- immutable name/version and manifest SHA-256;
- generator contract/version, code commit, dependency lock, scenario catalog hash, global seed, UTC/timezone, locale, and numeric settings;
- canonical-flow schema and exact feature-schema ID/version/hash;
- every scenario version/hash, group count, event count, label count, time range, and exclusion count;
- ordered canonical input identity hashes, source snapshot hash, feature artifact SHA-256, shape, media type, and controlled opaque reference;
- target-manifest SHA-256 and exact label vocabulary;
- quality/leakage report hashes;
- creator, reviewer, approval reference, creation/review times, retention, and lifecycle;
- mandatory limitations-text version/hash;
- `real_dataset_used=false`, `unsw_nb15_acquired=false`, and `network_traffic_generated=false`.

The manifest has no publisher, official source, acquisition URL, download actor, official citation, dataset license inheritance, or raw-data file entry. It cannot be used as an acquisition manifest and cannot transition to a real dataset type.

### 9.2 Immutability and lifecycle

Proposed lifecycle:

`draft -> generated -> quality_reviewed -> accepted_synthetic | rejected -> retired`

Definition, generator, input, target, feature, quality, leakage, and limitations hashes are immutable. Corrections create a new dataset version. Acceptance is an audited Security Administrator decision and must fail closed if audit persistence fails. Acceptance means only that the synthetic engineering fixture is fit for Gate 5S-B contract testing.

## 10. Group/time-aware split manifest

### 10.1 Proposed split

Use deterministic group/time-aware 70/15/15 train/validation/test proportions by eligible rows, with a tolerance of five percentage points where indivisible groups prevent an exact ratio. Random row splitting is prohibited.

- Each scenario execution receives one opaque group ID derived from generator/scenario/version/seed material.
- A group is assigned wholly to one partition; no group identity crosses partitions.
- Partition time bands are non-overlapping: training precedes validation, which precedes test.
- Each label and each core scenario family must have at least three independent groups in every partition, otherwise the split is invalid.
- Exact canonical identity, source snapshot, and feature-vector hashes cannot cross partitions.
- Near-duplicate checks use an approved deterministic projection and threshold documented before the split is viewed.
- The final test partition remains sealed until one Gate 5S-B candidate/configuration/threshold hash is locked.

### 10.2 Proposed `synthetic-split-manifest/v1`

Record the dataset manifest hash, split algorithm/version, grouping rule, temporal boundaries, ordered group/identity hashes per partition, row/group/scenario/label counts, exclusions, duplicate/near-duplicate report, deterministic seed, code version, creator/reviewer, test-seal state, test-open audit reference, and canonical SHA-256.

Split names, group IDs, time-band identifiers, scenario keys, and identity hashes remain controlled provenance and are never model inputs.

## 11. Leakage controls

### 11.1 Static denylist

In addition to the Sprint 4 banned fields, prohibit:

- target label and any encoded/derived label;
- scenario family/key/version, generator name/version/seed, and distribution selector;
- partition/split/group/time-band identity;
- target-manifest position, row order, fixture filename, source event prefix, or hash prefix correlated with label;
- feature-artifact order or creation time;
- deterministic-rule results, signatures, detection signals, alert fingerprints, and severity;
- any post-generation quality disposition or manual review outcome.

### 11.2 Generator leakage controls

1. Source event identifiers are randomized deterministically independent of labels and partitions.
2. Documentation address blocks, protocol sets, port classes, timestamps, missingness, and quality flags must occur in both labels where semantically valid.
3. Every scenario has overlapping nuisance distributions; no single provenance-like feature should perfectly identify a label by construction unless the test explicitly documents that toy mechanism.
4. Scenario groups are created before split assignment, and split assignment occurs before preprocessing fit.
5. Generator code cannot read split labels when producing feature distributions.
6. Labels are joined only after feature materialization and matrix allowlist validation.

### 11.3 Measured leakage report

Gate 5S-A must report exact/cross-split duplicates, near duplicates, feature/label associations, single-feature separability, scenario/group/time correlations, missingness/quality-label correlation, and prohibited-column inspection. High association is not silently removed or tuned away; it is disclosed as a limitation or causes a new dataset version.

Synthetic leakage controls can demonstrate process hygiene but cannot prove freedom from leakage in a future real dataset.

## 12. Deterministic reproducibility

Proposed defaults:

- global seed: `20260714`;
- named per-scenario seeds derived with SHA-256, not Python's process-randomized hash;
- UTC only, locale `C`, canonical JSON with sorted keys, fixed Unicode normalization, and no current-time dependency;
- stable sorting by `(event_time,event_key)` and explicit tie handling;
- fixed numerical dtypes and rounding from feature schema v1;
- pinned generator, feature, preprocessing, ML, converter, and ONNX Runtime versions;
- numerical thread counts fixed and recorded;
- source commit and dependency-lock hashes required;
- repeated clean-process generation must produce identical manifest, input, target, split, vector, and artifact hashes;
- ARM64 host results are authoritative for this portfolio demo; cross-platform numerical tolerance is documented rather than assumed byte-identical for fitted models.

Any seed, scenario, distribution, row count, feature definition, code, dependency, split, preprocessing, parameter, or threshold change creates new immutable evidence.

## 13. Training and preprocessing interfaces — design only

No interface in this section is implemented by this planning authorization.

```text
SyntheticGenerator.generate(scenario_manifest, limits) -> CanonicalFlowV1 stream
SyntheticDataset.freeze(input_stream, target_manifest, feature_schema) -> DatasetManifest
SplitPlanner.plan(dataset_manifest, policy) -> SplitManifest
MatrixSelector.select(feature_artifact, feature_schema_hash) -> Ordered39Matrix
Preprocessor.fit(train_matrix, split_manifest, config) -> PreprocessorManifest
Preprocessor.transform(matrix, manifest) -> Float32Matrix
Trainer.fit(train_matrix, train_targets, experiment_manifest) -> CandidateState
Evaluator.evaluate(candidate, partition, locked_threshold) -> EvaluationReport
OnnxExporter.convert(candidate, closed_policy) -> CandidateOnnxArtifact
OnnxParity.compare(reference, onnx, matrices, tolerance) -> ParityReport
OfflineScorer.score(model_id, synthetic_feature_artifact_id) -> ScoringJobResult
```

All calls consume persisted immutable IDs/hashes, not client paths, rows, labels, URLs, Python classes, import names, or artifact bytes. Dataset/generator code cannot be imported by the offline scorer. Training and offline scoring call the same ordered matrix/preprocessing contract.

### 13.1 Proposed preprocessing

- categorical vocabularies retain the fixed feature-schema tokens and immutable order;
- Logistic Regression uses training-only robust scaling for approved continuous/count/rate values and stable one-hot encoding;
- Random Forest receives the same stable encoded categories and unscaled numeric values unless a later measured decision says otherwise;
- booleans are `0/1`; output dtype is explicit `float32`;
- no target encoding, feature hashing, PCA, label-based selection, SMOTE, or fit on validation/test;
- preprocessing manifest records training partition hash, every fitted statistic, output names/order/width, library versions, and SHA-256;
- validation/test/offline paths expose `transform` only and fail closed on fit attempts, width/order/version mismatch, or non-finite output.

### 13.2 Proposed candidates

Later Gate 5S-B should implement:

1. majority/prevalence reference;
2. fixed-seed Logistic Regression baseline;
3. bounded fixed-seed Random Forest candidate.

No booster, neural network, anomaly model, automatic search, or new native ML dependency is included. Candidate comparison demonstrates pipeline behavior and complexity costs only.

## 14. ONNX safety and parity — design only

D-13 remains in force:

- export the complete fitted preprocessing-plus-classifier graph to one internally generated ONNX artifact;
- keep canonical JSON manifests outside the graph;
- fixed opset and closed standard-domain operator allowlist;
- no custom domains/operators, external tensor data, dynamic libraries, Python callbacks, scripts, or user upload;
- maximum candidate artifact 128 MiB and explicit bounded input/output shapes;
- `onnx.checker`, graph policy validation, SHA-256, runtime compatibility, and fresh-process smoke validation before registration;
- isolated offline runtime only, fixed thread/memory/time limits, no network;
- probability maximum absolute difference proposed at `1e-6` on golden/boundary matrices and `1e-5` on the full synthetic validation/test matrices;
- predicted class at the locked threshold must match exactly for every parity row;
- feature order, preprocessing output width, class order, probability bounds/sum, and non-finite behavior must match;
- conversion or parity failure rejects the candidate; there is no pickle/joblib fallback.

ONNX parity demonstrates equivalence between two implementations on synthetic inputs, not real-world model correctness.

## 15. Demo-only evaluation policy

### 15.1 Threshold and selection defaults

- Use a predeclared binary decision threshold of `0.50` for the initial synthetic demonstration.
- Do not optimize the threshold to maximize synthetic test metrics.
- Use validation only to compare fixed candidate configurations and detect mechanical failure.
- Lock the candidate/configuration/preprocessing/threshold hash before opening the final synthetic test partition once.
- Report majority reference, per-class precision/recall/F1/support, macro/weighted F1, confusion matrix, FPR/FNR, PR-AUC, applicable ROC-AUC, Brier score, latency, throughput, peak RSS/CPU, and artifact size.
- Undefined metrics are `unavailable` with a reason; they are never coerced to zero or one.

There is no minimum accuracy, recall, FPR, F1, PR-AUC, or calibration gate. High synthetic scores are neither a success criterion nor a model-promotion justification. Engineering acceptance depends on contract, leakage, parity, safety, reproducibility, and resource evidence.

### 15.2 Mandatory limitations language

The following text, with only version/hash substitutions, must appear prominently in every synthetic dataset report, evaluation, model card, registry view, UI metric panel, scoring result, README demonstration, screenshot intended for publication, and generated report:

> SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. The model is offline-only and cannot create or modify alerts or prevention actions.

Machine-readable records also require:

```json
{
  "synthetic_demo_only": true,
  "real_dataset_used": false,
  "unsw_nb15_evaluated": false,
  "online_inference_allowed": false,
  "alert_side_effects_allowed": false,
  "prevention_allowed": false
}
```

Missing or false limitation flags make the artifact/report ineligible for review.

## 16. Registry and lifecycle design

### 16.1 Synthetic-only lifecycle

Use a purpose separate from future real-data models, proposed as `synthetic_contract_demo/v1`, with lifecycle:

`candidate -> reviewed_synthetic | rejected | quarantined -> retired`

There is no `staged` or `active` transition in the synthetic fallback. `reviewed_synthetic` means only that provenance, limitations, safety, parity, and contract evidence passed. It does not make the model available to detection, online inference, alerts, or prevention.

### 16.2 Review and rollback

- System Administrator/training operator creates a candidate.
- A distinct Security Administrator account reviews or rejects it; creator self-review is denied.
- Definitions, artifacts, metrics, cards, hashes, and review decisions are immutable.
- A correction creates a new candidate version and append-only supersession record.
- Rollback in this fallback means reverting a demo selection/display reference to a previously `reviewed_synthetic` compatible version after integrity and limitation checks. It does not load a runtime model or alter detections.
- If audit persistence, artifact integrity, or compatibility fails, the transition fails closed.
- A quarantined artifact cannot be selected, reviewed, scored, or used as a rollback target.

Any future `staged`/`active` model lifecycle requires a new plan based on an accepted real dataset and cannot be obtained by renaming a synthetic registry row.

## 17. Artifact integrity and storage

Proposed controlled artifacts:

- canonical-flow JSONL fixture artifact;
- separate synthetic target manifest;
- 46-column feature Parquet artifact;
- dataset, split, preprocessing, experiment, evaluation, parity, artifact, and model-card canonical JSON;
- internally generated ONNX candidate at Gate 5S-B;
- aggregate offline scoring result at Gate 5S-C.

Controls:

1. Opaque UUID-derived references under the existing controlled local volume; no client path.
2. Mode-0600 staging, controlled-root/symlink checks, byte limits, SHA-256 during/after write, and atomic rename.
3. Hash and lifecycle verification before every read.
4. Partial, corrupt, oversized, unsupported, or incompatible artifacts fail closed and are quarantined or deleted according to state.
5. No artifact bytes, paths, raw feature rows, addresses, labels tied to identities, or full probability arrays in ordinary API/UI/log/audit output.
6. No dataset/model artifact enters Git or hosted CI. Only small sanitized source fixtures/contracts and aggregate reviewed documentation may be committed after a separate publication gate.
7. No artifact loader accepts external upload, arbitrary URL, Python object, custom operator, or untrusted manifest reference.

## 18. RBAC, CSRF, Origin, and audit design

### 18.1 Proposed permissions

| Permission | Purpose | Roles |
|---|---|---|
| `synthetic_datasets:read` | Safe manifest/quality/split metadata | Senior Analyst, Security Admin, System Admin, Auditor |
| `synthetic_datasets:generate` | Request bounded approved scenario generation | System Admin |
| `synthetic_datasets:review` | Accept/reject synthetic dataset and split evidence | Security Admin |
| `models:read` | Safe synthetic registry/card/aggregate metrics | SOC Analyst, Senior Analyst, Security Admin, System Admin, Auditor |
| `models:train_synthetic` | Request approved bounded synthetic run | System Admin |
| `models:review_synthetic` | Review/reject synthetic candidate evidence | Security Admin |
| `models:score_synthetic` | Request offline synthetic scoring | Senior Analyst, Security Admin, System Admin |

Viewer and sensor principals receive none of these permissions. Synthetic permissions do not imply existing `datasets:acquire`, `datasets:accept`, general model activation, raw artifact, or prevention permissions.

Every unsafe cookie-authenticated request requires CSRF and exact allowed Origin. Server-side authorization is authoritative; UI visibility is not a control. IDOR, mass assignment, stale expected-state, creator self-review, and cross-purpose model use are denied.

### 18.2 Audit events

Audit scenario/catalog review, generation request/start/success/failure, dataset/split acceptance/rejection, test-seal/open, preprocessing/training/evaluation request and outcome, ONNX validation/parity, model review/rejection/quarantine/retirement/supersession, demo rollback, offline score request/outcome, integrity mismatch, retention cleanup, and blocked cross-boundary attempts.

Audit metadata contains IDs, versions, hashes, aggregate counts, fixed limitation version, safe reason codes, and outcomes. It excludes flows, feature values, labels tied to identities, paths, URLs, seeds when treated as sensitive internal provenance, full parameters that could leak test design, exceptions, credentials, and probability arrays.

## 19. Celery and resource design

No task is implemented now. Proposed future registered tasks carry one persisted UUID only:

- `synthetic.generate_dataset(job_id)` — Gate 5S-A only;
- `synthetic.materialize_features(job_id)` — invokes the existing approved feature path;
- `synthetic.validate_split(job_id)` — deterministic leakage/manifest checks;
- `ml.train_synthetic(run_id)` — Gate 5S-B only;
- `ml.evaluate_synthetic(run_id)` — validation or one authorized test open;
- `ml.validate_synthetic_onnx(model_id)` — structural/integrity/parity validation;
- `ml.score_synthetic(scoring_job_id)` — Gate 5S-C only;
- `ml.reconcile_synthetic()` and `ml.cleanup_synthetic()` — authoritative stale-work and retention processing.

Tasks reject scenario definitions, rows, labels, parameters, paths, URLs, bytes, Python objects/classes, task names, credentials, and model graphs in messages. Jobs persist before dispatch, use actor-scoped idempotency, late acknowledgement, prefetch 1, leases, bounded reconciliation, safe errors, and no automatic retry for model fitting.

### 19.1 Proposed host-aware limits

| Control | Proposed default |
|---|---:|
| Generated canonical flows | 10,000 total maximum |
| Scenario families | 8 maximum |
| Scenario groups | 120 maximum |
| Minimum independent groups | 3 per label/family/partition where applicable |
| Feature width | exactly 39 model + 7 provenance |
| Feature artifact | 64 MiB maximum |
| Generator/split soft-hard time | 120/135 seconds |
| Training memory/CPU | 4 GiB / 2 CPUs |
| Training rows | all accepted synthetic rows, 10,000 maximum |
| Candidate configurations | 6 per algorithm maximum |
| Random Forest | 300 trees, depth 20, 2 threads maximum |
| Concurrent training jobs | 1 |
| Training soft-hard time | 1,200/1,350 seconds per candidate |
| ONNX artifact | 128 MiB maximum |
| Preprocessing artifact | 32 MiB maximum |
| Evaluation/parity output | 16 MiB maximum, aggregate/sanitized |
| Offline score batch | 10,000 rows maximum |
| Retries | 2 for deterministic generation; 0 automatic for fitting |

Measured peak RSS, CPU, elapsed time, rows/second, artifact sizes, cleanup, and failure behavior on the approved 8 GB ARM64 host are required. Limits may be reduced automatically on evidence; increases require owner approval.

## 20. Retention and cleanup

Proposed defaults:

| Data/artifact | Retention |
|---|---|
| Temporary generation/training/scoring files | Delete on success/failure; safety cleanup within 24 hours |
| Synthetic canonical-flow and target artifacts | 30 days after dataset decision |
| Synthetic feature matrices | 30 days |
| Rejected candidate ONNX/preprocessing artifacts | 30 days after decision |
| `reviewed_synthetic` ONNX/preprocessing artifact | 180 days maximum, then re-review or delete |
| Offline synthetic predictions/results | 30 days |
| Manifests, hashes, cards, aggregate reports | Retain by version as governance evidence |
| Audit events | 180 days under current development policy |
| Exceptional holds | Disabled |

Cleanup is selected from authoritative PostgreSQL state and cannot remove an artifact required by a non-expired review or demo rollback reference. It marks metadata and audits before/after deletion, handles missing/corrupt objects safely, and exposes overdue counts without internal paths.

## 21. Proposed database, API, and UI boundaries — later gates only

This plan creates no migration, route, component, or task. If Gate 5S-A is authorized, the proposed migration is additive and reversible and stores metadata only for synthetic scenario catalogs, generation jobs, target artifacts, dataset/split reviews, and permissions. Gate 5S-B/5S-C would add training, model, metric, review, scoring, and aggregate prediction metadata in a separately reviewed migration or revision.

Required database invariants include immutable hashes, dataset-kind separation, legal lifecycle transitions, one actor/idempotency scope, creator/reviewer separation, test-open-once, bounded counts/probabilities/text, expiry, and no path/raw row/unbounded vector/official acquisition fields.

Proposed minimal APIs are metadata/control surfaces only:

- list approved synthetic scenario catalog metadata;
- request bounded generation from a server-side approved catalog;
- inspect synthetic dataset/split/quality/leakage status;
- review/reject exact dataset/split hashes;
- later request and inspect bounded synthetic training runs;
- later inspect aggregate metrics/cards and review/reject candidates;
- later request controlled offline scoring of approved synthetic feature artifacts.

There is no free-form scenario editor, arbitrary seed/row distribution control, dataset/model upload/download, URL, raw row/vector/target preview, online predict endpoint, activation endpoint, alert endpoint, or prevention control.

The UI must show the mandatory synthetic banner on every page, preserve server permissions, expose only safe aggregate metadata, and provide no control that suggests production activation. Accessibility, hostile-text rendering, bounded tables, keyboard/focus, and unauthorized-control tests are required.

## 22. Failure and rollback behavior

| Failure | Required result |
|---|---|
| Real dataset/source/file/URL detected | Reject and audit `real_dataset_prohibited`; no read/network action |
| `UNSW`/`NUSW` artifact identity used as input | Reject except fixed negative-test/governance text |
| Invalid canonical flow or generator contract | Reject before artifact promotion |
| Resource/time/disk limit | Terminate, clean staging, preserve safe aggregate status |
| Duplicate generation request | Return/reuse actor-scoped idempotent result |
| Nondeterministic repeated hash | Reject dataset version and block training |
| Cross-split identity/group/near-duplicate | Reject split; create a new version after correction |
| Leakage field/column present | Reject matrix/dataset; no automatic dropping after review |
| Training-only fit violation | Fail run and invalidate candidate |
| Test partition opened early/twice | Deny and audit; require new split/version for another final test |
| ONNX conversion/operator/parity/integrity failure | Reject/quarantine; no unsafe fallback |
| PostgreSQL or audit unavailable | No review, test open, registry, rollback, or scoring state change |
| Redis unavailable | Persisted pending work remains reconcilable; no untracked work |
| Registry race/stale state | Expected-state conflict; no partial transition |
| Offline scorer requests real/online/alert purpose | Reject before model load |
| Model or scorer fails | Deterministic Sprint 3 IDS continues unchanged |
| Cleanup fails | Preserve metadata/status; bounded retry and overdue metric |

Database downgrade requires artifact inventory and explicit cleanup/retirement. It never deletes controlled artifacts implicitly. Demo rollback changes only an append-only display/selection reference and cannot load a model or mutate detection state.

## 23. Complete test matrix

### 23.1 Generator and canonical contracts

- Valid deterministic scenarios for each approved family and both labels.
- Empty, null, wrong type, extra field, Unicode/control, oversized count/text/nesting, invalid seed/time/range/distribution, and forbidden code/path/URL fields.
- Canonical-flow v1 validation, documentation-address-only, paired ports, boundary counters/duration, missing state, unknown protocol/state, zero denominators, clipped rates, IPv4/IPv6, duplicate/conflicting keys, equal timestamps, out-of-order and late input.
- No socket, HTTP client, PCAP library path, shell, subprocess, dynamic import, or packet writer invoked.
- Repeated clean-process hashes match exactly.

### 23.2 Feature and artifact contracts

- Exact 39-feature order and 7 reserved provenance columns.
- Selector rejects 38/40 features, reordered/duplicate columns, label/scenario/split/provenance inclusion, wrong schema/hash/type, non-finite values, corrupt/oversized/path/symlink artifacts.
- Reference/optimized Sprint 4 parity and exact 60/300 boundary behavior.
- Target sidecar join cannot leak target or identity into model matrix.

### 23.3 Dataset, split, leakage, and reproducibility

- Manifest strictness, canonical hash, immutability, lifecycle, review, and limitations flags.
- 70/15/15 group/time behavior, row tolerance, minimum group/class support, no group/time overlap, sealed test, and deterministic rerun.
- Exact and near duplicate, conflicting target, scenario/time/seed/source-ID proxy, missingness/quality-label association, and single-feature separability cases.
- Validation/test contamination attempts fail; correction creates a new version.

### 23.4 Preprocessing/training/evaluation — Gate 5S-B

- Training-only fit for vocabulary, scaler, imputer, calibrator if later approved, and every fitted statistic.
- Fixed feature/output order, missing/unknown behavior, float32 width/type, non-finite rejection, and shared training/scoring transform parity.
- Majority, Logistic Regression, and Random Forest deterministic micro-fixtures.
- Fixed seeds/threads/configs, bounded candidate count/time/memory, no automatic fit retry.
- Validation-only comparison, fixed `0.50` threshold, test-open-once, complete metric math, undefined metric handling, and no numeric performance pass gate.
- Mandatory limitations text/flags on every output and hostile omission/tampering cases.

### 23.5 ONNX, registry, and offline scoring — Gates 5S-B/5S-C

- Valid internally generated graph plus corrupt/hash/oversized/opset/domain/operator/external-data/shape/type/class-order/non-finite cases.
- Reference/ONNX probability tolerance and exact threshold-decision parity.
- Candidate/reviewed-synthetic/rejected/quarantined/retired transitions, immutability, self-review denial, expected-state races, supersession, demo rollback, and audit failure.
- Offline synthetic-only scoring, actor idempotency, bounded chunks, crash/reconcile, expiry/cleanup, and safe aggregate output.
- Explicit negative tests prove no online endpoint, startup model load, detection import, alert/rule/assessment/incident write, prevention import/write, or fallback model load.

### 23.6 Security, runtime, and quality gates

- Six-role negative matrix, IDOR, mass assignment, CSRF, Origin, session revocation/expiry, CORS, rate, pagination, hostile text, log/error/audit redaction.
- Migration fresh upgrade, existing-data preservation, downgrade refusal with artifacts, inventory cleanup, downgrade, and re-upgrade.
- JSON-only Celery configuration/task envelopes, registered-task review, broker/DB outage, duplicate delivery, stale lease, worker hard kill, and cleanup.
- Ruff, formatting, mypy, pytest, Bandit, pip-audit, npm audit, secret scan, simulation-only guard, dependency/license/native ARM64 review, SBOM, Trivy, frontend lint/type/component/build/accessibility, Docker health/readiness, and clean-stack synthetic E2E.
- Git/diff/large-file scan proves no dataset/model/Parquet/target/prediction artifact, credential, token, PCAP, archive, or unauthorized binary is staged.

### 23.7 Required boundary assertions

Automated tests and a final dependency/diff review must prove:

1. no network request path can retrieve a dataset;
2. no real dataset bytes or official-dataset-derived rows exist;
3. no string or report claims UNSW-NB15 was evaluated;
4. no synthetic metric is presented without the mandatory disclaimer;
5. no model is loaded by API startup, detection workers, or live request paths;
6. no online inference endpoint, WebSocket message, or stream consumer exists;
7. no model result creates or mutates a detection signal, alert, risk/confidence assessment, incident, rule, or suppression state;
8. no model result creates, recommends, authorizes, previews, or simulates prevention;
9. no privileged/host-network/firewall capability or dependency is added;
10. deterministic Sprint 3 detection and simulation-only guards remain unchanged.

No skipped required test is a pass.

## 24. Acceptance criteria

### 24.1 Gate 5S-A acceptance

| Criterion | Required evidence |
|---|---|
| Scope and no-contact boundary preserved | Diff/network/dependency review; zero external requests and zero real bytes |
| Strict closed scenario/generator contracts | Positive/negative/boundary tests; no executable/free-form input |
| Canonical-flow v1 fixtures are bounded and deterministic | Exact repeated hashes, resource evidence, schema tests |
| Approved 39+7 feature boundary holds | Column/order/type/hash tests and controlled artifact inspection |
| Labels remain separate and explicitly synthetic | Target-manifest and matrix-selector tests |
| Dataset manifest is immutable and honest | Strict contract, hash, lifecycle, limitation flags, audit |
| Split is deterministic group/time-aware 70/15/15 | No overlap/duplicates, support/tolerance, sealed-test evidence |
| Leakage analysis is complete | Static denylist and measured association/duplicate report |
| RBAC/CSRF/Origin/audit and migration are safe | Six-role matrix, sensitive-write failure, migration round trip |
| Celery/artifact/resource/cleanup boundaries pass | UUID-only tasks, hash/path/atomic/limit/crash tests |
| No model work exists | Diff/task/route/dependency/artifact review |
| No unresolved Critical or High issue | Final uncommitted review and explicit residual-risk disposition |

Gate 5S-A stops at owner acceptance of exact dataset, split, feature artifact, quality, and leakage hashes.

### 24.2 Gate 5S-B acceptance

In addition to accepted Gate 5S-A hashes: training-only preprocessing, fixed candidate definitions, deterministic bounded runs, validation/test isolation, complete demo metrics, mandatory limitations, ONNX closed-policy/integrity/parity, safe model card, native dependency/SBOM/container checks, and no unresolved Critical/High issue must pass. No activation or scoring is implied.

### 24.3 Gate 5S-C acceptance

In addition to approved Gate 5S-B hashes: synthetic-only registry separation, distinct-account review, immutable lifecycle, expected-state concurrency, quarantine/supersession/demo rollback, controlled offline scoring, retention/cleanup, RBAC/privacy, and explicit no-side-effect tests must pass. The result remains offline and synthetic-only.

## 25. Assumptions

1. The approved 8 GB ARM64 development host can handle no more than 10,000 synthetic flows and one bounded baseline job at a time; actual measurements may require lower limits.
2. Existing Sprint 4 transforms and controlled Parquet remain the authoritative feature implementation.
3. Documentation address ranges and generated opaque identities are adequate for sanitized fixtures.
4. Distinct System Administrator and Security Administrator accounts provide a technical separation boundary, while independent-human review remains absent in this solo project.
5. Synthetic scenarios can exercise software paths but cannot establish external validity, dataset suitability, operational class prevalence, or real-world threshold quality.
6. ONNX conversion availability on the ARM64 host must be proven before Gate 5S-B; inability to prove it is a valid rejected-candidate outcome.

## 26. Proposed defaults requiring approval

| ID | Proposed default | Consequence if changed |
|---|---|---|
| S5S-A01 | Three separate gates: dataset/split, training/ONNX, then registry/offline scoring. | Authority and stop points must be redesigned. |
| S5S-A02 | Binary labels `synthetic_benign_like` and `synthetic_intrusion_like`. | Target contracts, metrics, UI, and limitation text change. |
| S5S-A03 | Closed eight-family scenario catalog in Section 7.3. | Generator, coverage, leakage, and resource tests change. |
| S5S-A04 | Maximum 10,000 flows, 120 groups, fixed seed `20260714`. | Resource/reproducibility evidence changes. |
| S5S-A05 | Group/time-aware 70/15/15 with ±5 percentage-point row tolerance and minimum support. | Leakage and test-isolation evidence changes. |
| S5S-A06 | Separate target manifest; existing 46-column Parquet remains label-free. | Storage/privacy/training selector design changes. |
| S5S-A07 | Logistic Regression and Random Forest only; majority reference. | Dependency/resource/evaluation scope changes. |
| S5S-A08 | Fixed threshold `0.50`; no numeric performance gate or threshold optimization. | Claim risk and test-isolation design change. |
| S5S-A09 | ONNX parity tolerances `1e-6` golden and `1e-5` full matrices, exact decisions. | Compatibility evidence changes. |
| S5S-A10 | Synthetic registry lifecycle has no `active` state. | Online/detection architecture would require a new plan and real-data gate. |
| S5S-A11 | Distinct System/Security Administrator accounts enforce creator/reviewer separation. | Governance limitation needs explicit acceptance. |
| S5S-A12 | Proposed task/resource limits in Section 19.1, subject only to measured reduction. | Host safety plan changes. |
| S5S-A13 | Retention defaults in Section 20; no exceptional holds. | Cleanup, disk, privacy, and reproducibility change. |
| S5S-A14 | Metadata-only APIs/UI; no raw row/vector/target/artifact access. | Privacy/threat/API scope changes. |
| S5S-A15 | Mandatory limitation text and machine-readable flags are immutable review gates. | Portfolio-credibility risk becomes unacceptable. |
| S5S-A16 | SBOM and Trivy become Gate 5S-B release checks because ONNX/native ML expands supply-chain trust. | A documented equivalent control is required. |

## 27. Every owner decision required before later implementation

### Before Gate 5S-A

1. Approve the three-gate synthetic-only boundary.
2. Approve the exact label names and their non-semantic meaning.
3. Approve or modify the closed scenario catalog.
4. Approve the 10,000-flow, 120-group, fixed-seed and generator limits.
5. Approve the documentation-address-only/no-packet/no-payload generation rules.
6. Approve the separate target manifest and unchanged 39+7 Parquet contract.
7. Approve group/time-aware 70/15/15, tolerance, minimum support, duplicate/near-duplicate policy, and test sealing.
8. Approve the static leakage denylist and measured leakage report.
9. Approve synthetic dataset/split lifecycle and Security Administrator review.
10. Approve Gate 5S-A migration metadata, permissions, API/UI surface, Celery tasks, resource limits, retention, and checks.
11. Confirm UNSW-NB15 remains blocked/deferred and publisher outreach remains cancelled.

### Before Gate 5S-B

12. Approve the exact Gate 5S-A dataset, target, split, feature artifact, quality, leakage, code, and dependency hashes.
13. Approve Logistic Regression, Random Forest, and majority reference only.
14. Approve the exact preprocessing definitions and output matrix contract.
15. Approve fixed `0.50` threshold, no performance pass gate, and one final test opening.
16. Approve all metric definitions and mandatory limitations text/flags.
17. Reconfirm D-13 ONNX policy, exact opset/operator allowlist, runtime version, shapes, size, and parity tolerances after dependency review.
18. Approve trainer resource limits, candidate grids, native dependencies, SBOM, and Trivy gates.
19. Approve Gate 5S-B migration/task/API/UI additions, artifact retention, and no activation.

### Before Gate 5S-C

20. Approve the exact experiment, evaluation, test-open, model card, preprocessing, ONNX, parity, runtime, and limitation hashes.
21. Approve the synthetic-only registry purpose/lifecycle and prohibition on `active` state.
22. Approve creator/reviewer separation, quarantine, supersession, and demo rollback semantics.
23. Approve exact offline scoring inputs, outputs, prediction retention, permissions, resource limits, APIs/UI, and audit fields.
24. Approve the no-side-effect evidence proving no online inference, alert mutation, or prevention path.

No unspecified answer is inferred as approval.

## 28. Dependencies and deferred work

### Dependencies

- Sprint 4 published feature contract and hosted CI: satisfied.
- Existing uncommitted Phase 5A work: requires its own review/publication disposition before synthetic implementation is committed.
- Owner decisions in Section 27: blocking their corresponding gate.
- Gate 5S-A exact-hash acceptance: blocking Gate 5S-B.
- ARM64 ONNX/converter/runtime and native dependency review: blocking Gate 5S-B artifact creation.
- Gate 5S-B exact-hash acceptance: blocking Gate 5S-C.

### Deferred

- UNSW-NB15 acquisition and any publisher contact until a new explicit owner authorization.
- Every real or third-party dataset and related performance claim.
- Production model activation and online/streaming inference.
- Supervised model integration into detection, alerts, ensemble, risk/confidence, incidents, or prevention.
- Anomaly detection and fusion (Sprint 6), explainability/intelligence (Sprint 7), SOC workflows (Sprint 8), and prevention simulation policy work (Sprint 9).
- Live capture and all real prevention.

## 29. Major risks and mitigations

| Risk | Severity | Required control/disposition |
|---|---|---|
| Synthetic results are presented as NIDPS performance | High | Immutable disclaimer/flags, no numeric quality gate, UI/report/card tests, publication review |
| Generator leaks labels through scenario/provenance proxies | High | Separate target type, denylist, overlapping distributions, measured association and separability report |
| Group/time split still contains related examples | High | Whole-group temporal partitions, identity/vector/near-duplicate checks, sealed test |
| Synthetic fixtures make model behavior unrealistically easy | High | Ambiguous overlap scenarios, disclose construction, no external-validity claim |
| Training/serving preprocessing diverges | High | One contract, training-only manifest, exact order, golden matrix and ONNX parity |
| Unsafe ONNX/native runtime compromises worker | Critical | Internal-only closed graph, no custom/external data, hash/size/operator checks, isolated no-network worker, SBOM/scan |
| Artifact replacement/path attack | Critical | Opaque controlled references, root/symlink checks, mode-0600 atomic writes, SHA-256 every read |
| Synthetic model accidentally becomes active/online | Critical | Separate purpose/lifecycle with no active state, no loader/endpoint, dependency and negative mutation tests |
| Model output mutates alerts or prevention | Critical | No imports/writes/schema path; DB snapshots and OS/capability no-side-effect tests |
| Training exhausts the 8 GB host | High | 4 GiB/2 CPU, one job, 10,000 rows, time/thread/artifact caps, measured RSS and cleanup |
| Creator self-approves misleading evidence | High | Distinct account, server-side separation, audit, self-review denial; disclose lack of independent person |
| Current dirty Phase 5A branch mixes scopes | High | Preserve separate review history, full diff classification, no commit/publication until authorized |
| Retention cleanup removes evidence or exceeds limits | High | Authoritative expiry, protected review/rollback refs, inventory/refusal tests, overdue metrics |
| Scope creep reaches Sprint 6 or prevention | Critical | Gate-specific prompts, dependency/route/task/diff guards, simulation-only OS-state check |

No Critical or High residual risk may be silently accepted. Each must have an owner, evidence, review date, and explicit disposition at the applicable gate.

## 30. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** A synthetic-only continuation is technically viable as an engineering-contract demonstration if the project preserves the three separate gates, explicit synthetic labels, immutable limitation language, no numeric performance claim, no active/online model state, and strict separation from alerts and prevention.

UNSW-NB15 remains blocked and deferred. Publisher outreach remains cancelled. No dataset, model, migration, API, UI, Celery task, production code, commit, or publication was created or authorized by this plan.

## 31. Exact Gate 5S-A implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md and begin AegisAI NIDPS Sprint 5 Gate 5S-A only: synthetic contracts, generation, dataset, feature, quality, leakage, and split evidence.

Before proceeding:
- Confirm public main remains at 72c97b15f9bb31ddb6810a397afc682893497bab or identify and review any newer separately authorized baseline.
- Confirm hosted CI Run #7 succeeded for the published Sprint 4 SHA.
- Review and classify every current uncommitted Phase 5A change; preserve it without rewriting published history and identify any conflict with the synthetic-only scope.
- Read all governing documents and docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md completely.
- Keep publisher outreach cancelled and do not use Gmail or contact the publisher through any channel.

Use these owner decisions:
- Sprint boundary: three separate gates, with this authorization limited to Gate 5S-A.
- Dataset boundary: project-generated synthetic canonical-flow-v1 only; no real or third-party dataset.
- Labels: synthetic_benign_like and synthetic_intrusion_like only, with the exact non-semantic meaning in Section 7.
- Scenario catalog: approve the eight closed families in Section 7.3.
- Limits: at most 10,000 canonical flows, 120 groups, fixed global seed 20260714, and the Section 19.1 resource limits subject only to measured reduction.
- Feature contract: exact approved flow_features/1.0.0 order of 39 model features plus 7 reserved non-model provenance columns; labels remain in a separate target manifest.
- Split: deterministic group/time-aware 70/15/15, plus or minus five percentage points by eligible rows, whole groups, non-overlapping time bands, minimum support, duplicate/near-duplicate checks, and sealed test.
- Governance: generation by System Administrator; exact dataset/split acceptance by a distinct Security Administrator account; complete audit.
- Retention: Section 20 Gate 5S-A defaults; no exceptional holds.
- Claims: mandatory exact synthetic-demo limitation text and machine-readable flags on every artifact/report/UI view; no numeric performance claim.

Implement only:
1. strict closed synthetic scenario/generator/target/dataset/split contracts and small hostile/golden fixtures before generator code;
2. bounded deterministic canonical-flow-v1 generation using documentation addresses, with no packet, PCAP, payload, credential, network, URL, or official-dataset emulation;
3. feature materialization through the existing approved Sprint 4 pipeline only;
4. exact 39-feature selector and 7-provenance-column integrity checks, with labels stored separately;
5. immutable synthetic dataset/target/split manifests, canonical hashes, quality report, leakage report, and reproducibility evidence;
6. group/time-aware split and sealed-test controls;
7. additive reversible metadata migration, centralized RBAC, CSRF/Origin, complete safe audit, bounded JSON-only UUID Celery tasks, controlled artifacts, retention/cleanup, and minimal metadata-only APIs/UI required for Gate 5S-A;
8. all Gate 5S-A tests and documentation, including a Gate 5S-A completion report.

Do not use UNSW-NB15, NUSW-named files, mirrors, tokenized links, HEAD/GET, downloads, samples, real dataset payloads, or another public dataset. Do not fit preprocessing; train, tune, calibrate, evaluate, serialize, convert, register, review, load, activate, or score a model; create predictions; open the final test for model evaluation; add online inference; mutate detection signals, rules, alerts, assessments, incidents, or prevention; begin Gate 5S-B, Gate 5S-C, Sprint 6, live capture, or real prevention. Do not use privileged containers, host networking, firewall capabilities, or enforcement dependencies. Do not commit or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, reproducibility, canonical-flow, 39+7 column, label-separation, feature-parity, window, missing/unseen/range, dataset/split, duplicate/near-duplicate, leakage, artifact-integrity/path, RBAC-negative-matrix, CSRF/Origin, audit, idempotency, concurrency, retention, resource, migration upgrade/downgrade/re-upgrade, Celery, Docker, health, frontend, accessibility, dependency, secret-scanning, large-file, and simulation-only checks.

When finished, report files changed, migrations/interfaces added, generated scenario and label counts, exact dataset/target/feature/split/quality/leakage hashes, resource results, commands and checks, failures/skips, assumptions, residual risks, Gate 5S-A acceptance status, and the exact separate Gate 5S-B authorization prompt.

Stop at the uncommitted Gate 5S-A synthetic-dataset acceptance gate. Wait for explicit owner approval of every exact hash before fitting preprocessing or performing any model work.
```
