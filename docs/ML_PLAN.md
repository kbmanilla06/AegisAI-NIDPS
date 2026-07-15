# Machine Learning and Dataset Plan

**Status:** Sprint 5 Gate 5S-A synthetic evidence implemented locally and uncommitted; publisher outreach cancelled and acquisition blocked; no real dataset downloaded and no model/preprocessor trained

## Objectives

Provide calibrated, explainable evidence for known attack categories and unusual behavior while demonstrating reproducibility, leakage resistance, safe artifacts, and honest limitations. ML supplements deterministic detection.

## Primary candidate and other datasets

UNSW-NB15 is the primary candidate, not an approved download. The current pre-acquisition review is recorded in `docs/data/UNSW_NB15_PREACQUISITION_REVIEW_2026-07-14.md`: the official page still names the four principal CSVs, feature dictionary, ground-truth, event listing, academic-use/citation terms, and raw approximately 100 GB PCAP. Its download link now reaches a Microsoft authentication gate, so exact sizes, media/archive status, direct credential-free objects, and checksums remain unverified. Acquisition remains false. CIC-IDS2017, CSE-CIC-IDS2018, or TON_IoT may later provide independent validation after their own source/license review. NSL-KDD may be used only as a historical baseline.

## Dataset acceptance checklist

Official source; license; checksum; acquisition date; capture environment; schema/units; label definitions; class counts; missing/invalid values; duplicates; host/session/time relationships; leakage fields; known errors; allowed use; raw/processed separation; manifest and adapter version.

## Split strategy

Prefer capture-day, time, host, session, or source-aware splits. Random row splits are prohibited when related flows could cross partitions. Fit imputation, scaling, encoding, sampling, and feature selection on training only. Tune on validation only. Keep the test split untouched until one final candidate evaluation.

For synthetic Gate 5S-A, generation fixes 7,200 rows in 120 whole groups with non-overlapping time bands: 5,040 training, 1,080 validation, and 1,080 sealed test rows. Exact event, vector, group, and rounded-full-vector duplicates across partitions are zero. The two labels are scenario-test metadata, not claims about maliciousness, and no numeric model-performance statement is permitted.

## Experiments

1. Majority/rule-only reference.
2. Logistic Regression baseline.
3. Random Forest candidate.
4. XGBoost or LightGBM only if it adds measured value relative to complexity.
5. Isolation Forest anomaly baseline using a documented normal population.
6. Autoencoder only after an approved evidence-based need.

## Metrics

Per-class precision/recall/F1/support; macro and weighted F1; confusion matrix; false-positive/negative rates; PR-AUC for imbalanced classes; ROC-AUC where meaningful; calibration/Brier or reliability view; threshold tradeoffs; latency/throughput/memory/artifact size. Metrics always name dataset version, split, feature version, and model version.

## Error analysis

Review false positives and negatives by class, source/capture, time, asset/protocol, missingness, score band, and feature group. Record ambiguous labels and distribution differences. Never claim real-world or zero-day effectiveness from a single public dataset.

## Train/serve parity

One shared versioned transformation package produces ordered vectors. Feature schema v1 uses canonical flow v1 only: 17 direct values and 11 values for each inclusive 60/300-second event-time window. The machine-readable and analyst-readable dictionaries define order, type, unit, range, missing/unseen policy, source, relevance, and banned leakage fields. Reference and optimized transforms must match exactly; fitting vocabularies/statistics requires training partition evidence.

## Artifact safety and registry

Each artifact has model/version, algorithm/config, dataset/split manifest, feature/preprocessing version, runtime/dependency versions, metrics, intended/prohibited uses, checksum/signature policy, model card, creation identity/time, status, and rollback predecessor. Candidate → staged → active → retired is permissioned and audited. Safe serialization format is an approval decision; arbitrary untrusted pickle/joblib loading is prohibited.

## Explainability

Use coefficients/model-native importance/SHAP appropriate to the candidate. Store top contributions, values, direction, explanation version, uncertainty, and human-readable caveat. Explanations describe association, not causation.

## Governance

No auto-retraining or auto-promotion. Analyst feedback is reviewed and versioned. Drift creates alerts/review work. Model activation cannot change detection rule thresholds or prevention policy. Rollback must be tested before activation.

## Reproducibility evidence

Dataset manifest/checksum, environment lock, fixed seeds where applicable, code commit, feature version, split manifest, parameter configuration, executed commands, outputs, model card, and evaluation report.
