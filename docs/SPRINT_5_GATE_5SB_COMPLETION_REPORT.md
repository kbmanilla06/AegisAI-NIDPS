# Sprint 5 Gate 5S-B Completion Report

**Status:** UNCOMMITTED — exact candidate-hash acceptance required

Gate 5S-A evidence was accepted exactly as authorized. UNSW-NB15 acquisition remains blocked, publisher outreach remains cancelled, and no real or third-party dataset bytes were used. This gate produced only bounded synthetic-demo candidate evidence. No registry activation, scoring, online inference, alert mutation, detection mutation, or prevention capability was added.

## Scope implemented

- Training-only deterministic preprocessing manifests derived from the training partition.
- Majority/prevalence reference plus Logistic Regression and bounded Random Forest candidates.
- Validation-only selection at threshold `0.50`; the sealed test was opened once for the selected Logistic Regression candidate and audited.
- ONNX classifier artifacts with canonical JSON metadata, SHA-256 integrity, fixed float32 `[1,39]` input, closed operator/domain policy, no external data/custom operators, and 16 MiB limits. Preprocessing remains an immutable canonical-JSON contract applied before the classifier artifact; no Python-object artifact is persisted.
- Candidate lifecycle is permanently `unreviewed_candidate`; API and dashboard expose metadata only and explicitly set all false-capability flags.
- Additive reversible migration `0007_sprint5_synthetic_training`, JSON-only UUID Celery task, retention cleanup, RBAC, CSRF/Origin, idempotency, safe audit, and metadata-only APIs/UI.

## Exact deterministic Gate 5S-B evidence

| Item | SHA-256 |
|---|---|
| Selected algorithm | `logistic_regression` |
| Selected candidate lock | `34a364f8cf8012d489ad951ceead9bee22949cd5bcbc6162bf9a0227c73912ee` |
| One-time test-opening audit | `8e27c5fed7ba0b469057a610b7bb8c5bb64b6f6777d39833ced559ef3087cc1c` |
| Logistic Regression ONNX | `4957e7bd33fb4136ce7e7c8c99c20ac02c411265ca803e6009298ebe6dd34413` |
| Logistic Regression metadata | `c51427b5d6397ed8ec85ae50b51b8f9422140855497dab3815e1bc3a0f3ebdad` |
| Logistic Regression preprocessor | `77ebe8ad02d63cf2183435ca5b9c5ea5d4b45821c29a464d76b06a328a7a8d11` |
| Logistic Regression evaluation | `ed3e27b65fbefa863bd065d4b05a92f0943e2afdfded80cf9af91ed9251f6e1d` |
| Logistic Regression model card | `5e139acf5e96a7df523bcefceefc8d2132334825b2e1d0294e3de0b48d83be38` |
| Random Forest ONNX | `c7f37616e6c4b3720645a01035b4f5bf084ea5421f88d412a75d2b21ede1892b` |
| Random Forest metadata | `67aa102c59faf06151edca2d362c1b54911b711414e69a1b391685cffc17f2b4` |
| Random Forest preprocessor | `6a544a654f98edc874349e4b175eda95ebebc4bda1fc328718883cc05f276354` |
| Random Forest evaluation | `5894865b5d9c8170b98e2a5dcf9452d9b414e719bc0e448f1e700f69572c00cc` |
| Random Forest model card | `3ddb0842af4e260bc24978153bc747db9a01fb1a2d8a936d94d73e85d176623f` |

Validation selected Logistic Regression by macro-F1. The sealed test was not used for retuning. Metrics are synthetic-demo evidence only; no numeric result is a real-dataset or production claim. Every metric and artifact carries the mandatory limitation text and false flags for real-dataset use, UNSW acquisition/evaluation, network generation, online inference, alert side effects, scoring, and prevention.

## Checks run

- ARM64-compatible worker image build with pinned ML dependencies: passed.
- Bounded training smoke test and deterministic ONNX parity: passed.
- Gate 5S-B unit tests: **7 passed**.
- Synthetic Gate 5S-A/5S-B integration tests: **6 passed**.
- Full backend suite: **130 passed, 1 unrelated pre-existing WebSocket revocation timing failure** (`tests/integration/test_detection.py::test_live_alert_channel_rechecks_revoked_session`). No Gate 5S-B failure was observed.
- Ruff check/format, mypy, Bandit: passed with no findings.
- Secret and simulation-only guards: passed.
- Dashboard lint, typecheck, tests (6), and build: passed.
- Dependency lock, SBOM, and documented Trivy 0.69.2 scan: zero unresolved Critical/High findings.

## Acceptance status

Gate 5S-B is implemented but remains **pending owner acceptance of every exact candidate hash above**. No candidate is active, reviewed-synthetic, registered for scoring, loadable by API/detection startup, or allowed to affect alerts or prevention.

## Exact next authorization prompt

> Accept the exact Gate 5S-B candidate, preprocessing, evaluation, model-card, ONNX, and one-time test-opening hashes in `docs/SPRINT_5_GATE_5SB_COMPLETION_REPORT.md`. Authorize Gate 5S-C only: reviewed synthetic registry metadata and isolated offline batch scoring of the accepted synthetic feature artifact. Do not authorize registry activation for online inference, live capture, alert mutation, detection changes, prevention, real or third-party datasets, UNSW-NB15 acquisition, publisher contact, or Sprint 6. Require the same ONNX closed policy, RBAC/CSRF/Origin, audit, resource, retention, rollback, and mandatory synthetic-demo limitations. Stop after the uncommitted Gate 5S-C completion gate and wait for separate publication approval.
