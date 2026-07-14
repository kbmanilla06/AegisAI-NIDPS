# Machine Learning and Dataset Plan

**Status:** Planning only; no data downloaded and no model trained

## Objectives

Provide calibrated, explainable evidence for known attack categories and unusual behavior while demonstrating reproducibility, leakage resistance, safe artifacts, and honest limitations. ML supplements deterministic detection.

## Primary candidate and other datasets

UNSW-NB15 is the approved primary candidate, not yet an approved download. The official UNSW review and restrictions are recorded in `docs/DATASET_REVIEW_UNSW_NB15.md`. Repository visibility, project license, and intended use must be resolved first. CIC-IDS2017, CSE-CIC-IDS2018, or TON_IoT may later provide independent validation after their own source/license review. NSL-KDD may be used only as a historical baseline.

## Dataset acceptance checklist

Official source; license; checksum; acquisition date; capture environment; schema/units; label definitions; class counts; missing/invalid values; duplicates; host/session/time relationships; leakage fields; known errors; allowed use; raw/processed separation; manifest and adapter version.

## Split strategy

Prefer capture-day, time, host, session, or source-aware splits. Random row splits are prohibited when related flows could cross partitions. Fit imputation, scaling, encoding, sampling, and feature selection on training only. Tune on validation only. Keep the test split untouched until one final candidate evaluation.

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

One shared versioned transformation package produces ordered vectors. A feature dictionary defines type, unit, range, missing policy, source, relevance, and banned leakage fields. Golden samples must produce identical results in training and inference.

## Artifact safety and registry

Each artifact has model/version, algorithm/config, dataset/split manifest, feature/preprocessing version, runtime/dependency versions, metrics, intended/prohibited uses, checksum/signature policy, model card, creation identity/time, status, and rollback predecessor. Candidate → staged → active → retired is permissioned and audited. Safe serialization format is an approval decision; arbitrary untrusted pickle/joblib loading is prohibited.

## Explainability

Use coefficients/model-native importance/SHAP appropriate to the candidate. Store top contributions, values, direction, explanation version, uncertainty, and human-readable caveat. Explanations describe association, not causation.

## Governance

No auto-retraining or auto-promotion. Analyst feedback is reviewed and versioned. Drift creates alerts/review work. Model activation cannot change detection rule thresholds or prevention policy. Rollback must be tested before activation.

## Reproducibility evidence

Dataset manifest/checksum, environment lock, fixed seeds where applicable, code commit, feature version, split manifest, parameter configuration, executed commands, outputs, model card, and evaluation report.
