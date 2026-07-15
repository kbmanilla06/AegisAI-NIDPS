# Sprint 5 No-Publisher-Contact Fallback

**Date:** 2026-07-14
**Decision:** Do not send publisher email
**UNSW-NB15 acquisition:** Blocked and deferred
**Model-performance claims:** Prohibited without an accepted real dataset
**Current continuation:** Gate 5S-A synthetic-only evidence implemented locally and uncommitted; no model work authorized

## Outcome

Publisher outreach is no longer the active Sprint 5 path. The prepared Gmail draft must not be sent. No follow-up, alternate address, social-media message, phone call, metadata probe, tokenized URL, HEAD/GET request, dataset transfer, or mirror search is authorized.

UNSW-NB15 remains a documented candidate whose source gate could not be satisfied. The `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` objects remain excluded, and no acquisition manifest may be produced from rounded SharePoint metadata.

## Permitted continuation

Aegis may continue with a synthetic-only Sprint 5 planning path that:

- uses only project-generated synthetic canonical-flow-v1 and approved 39-feature fixtures;
- validates dataset, split, preprocessing, registry, artifact-integrity, RBAC, audit, Celery, resource-limit, rollback, and offline-scoring contracts;
- clearly labels every dataset, metric, model card, UI view, report, and artifact as synthetic/demo-only;
- prohibits claims about UNSW-NB15 accuracy, real-network effectiveness, generalization, deployment readiness, or comparative benchmark performance;
- keeps model activation, online inference, alert generation from model output, live capture, and real prevention outside scope;
- keeps preprocessing/training unauthorized until the exact Gate 5S-A hashes are explicitly accepted through a separate Gate 5S-B authorization.

## Prohibited shortcuts

- Do not infer exact bytes from rounded display sizes.
- Do not silently accept the two `NUSW-...` spellings.
- Do not use unofficial mirrors, cached copies, GitHub datasets, Kaggle copies, search-engine results, or publisher-prepared duplicate splits.
- Do not loosen the query-free URL, checksum, provenance, mapping, leakage, or split gates.
- Do not describe synthetic evaluation as empirical NIDPS performance.
- Do not commit or publish the current Phase 5A work without its separate review/publication gate.

## Reopening the UNSW-NB15 gate

The gate may be reopened only through a new explicit owner authorization. That authorization must name the permitted contact or metadata method and preserve the existing no-transfer boundary until a complete manifest is approved.

## Exact next prompt

```text
Cancel AegisAI NIDPS Sprint 5 publisher outreach. Do not send the prepared Gmail draft or contact the publisher through any channel.

Keep UNSW-NB15 acquisition blocked and deferred. Keep NUSW-NB15_features.csv and NUSW-NB15_GT.csv excluded. Do not use mirrors, tokenized links, HEAD/GET requests, dataset downloads, samples, or real dataset payloads.

Begin Sprint 5 synthetic-only fallback planning only. Read all governing documents, docs/SPRINT_5_IMPLEMENTATION_PLAN.md, docs/SPRINT_5_PHASE_5A_PREACQUISITION_REPORT.md, docs/SPRINT_5_PHASE_5A_BLOCKER_RESOLUTION_PLAN.md, and docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md completely.

Prepare docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md defining:
- generation of labeled synthetic canonical-flow-v1 fixtures and the approved 39-feature contract;
- immutable synthetic dataset and group/time-aware split manifests;
- leakage controls and deterministic reproducibility;
- training/preprocessing/ONNX parity interfaces without implementation;
- demo-only evaluation thresholds and mandatory limitations language;
- registry, artifact integrity, RBAC, audit, Celery, resource, retention, and rollback design;
- tests proving no real dataset, UNSW-NB15 claim, online inference, alert mutation, or prevention capability is introduced;
- acceptance criteria and every later implementation decision requiring approval.

Do not generate a synthetic dataset, train/load/register/activate/score a model, create migrations/APIs/UI/tasks, modify production code, commit, or publish. Stop after the planning document and provide the exact synthetic-only implementation authorization prompt.
```
