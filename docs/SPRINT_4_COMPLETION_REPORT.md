# AegisAI NIDPS Sprint 4 Completion Report

**Completion date:** 2026-07-14
**Baseline:** public `main` at `b514aa3592487a65b8de8e1cfa14f4f9b80c5976`; hosted CI Run #5 (`29325828604`) passed
**Branch:** `feature/sprint-4-features`
**Publication:** final commit `72c97b15f9bb31ddb6810a397afc682893497bab` on public `main`; hosted CI Run #7 (`29332025235`) passed
**Gate:** Sprint 4 publication complete
**Decision:** APPROVED

## 1. Authorized boundary

Implemented canonical flow v1 only, 17 direct plus 60/300-second windows, controlled Parquet after dependency review, 30-day feature-artifact retention, and solo Security Administrator schema/dataset review with complete audit. The official UNSW-NB15 publisher page was investigated only. No dataset file or download link was opened; acquisition remains false and the raw approximately 100 GB PCAP remains excluded.

No model was trained, serialized, loaded, registered, activated, or scored. No live capture, Sprint 5, anomaly/ensemble/intelligence/incident function, real prevention, privileged container, host networking, firewall capability, commit, or publication was added.

## 2. Implementation summary

### Contracts and transformations

- Strict immutable Pydantic contracts for feature definitions/schema/vector, dataset/split/vocabulary/preprocessor manifests, canonical hashing, bounds, and compatibility.
- Feature schema v1 has 39 ordered model values: 17 direct and 11 for each 60/300-second window.
- Stable event-time ordering uses `(event_time,event_key)`, inclusive lower bounds, inclusive as-of upper tuple, deterministic duplicate handling, sensor/source grouping, and explicit immutable snapshot/vector hashes.
- Missing ports, zero denominators, missing/unseen categories, non-finite inputs, range caps, integer overflow, input schema mismatch, and conflicting duplicate keys fail or signal according to the dictionary.
- Raw IPs, identifiers, timestamps, labels, alert/detection fields, and other denylisted values never enter `ordered_values`.
- Reference and optimized batch paths are tested for exact parity. Vocabulary/statistic manifests require training-partition evidence.

### Artifact and worker path

- PyArrow 23.0.1 ARM64 wheel was installed under reviewed bound `pyarrow>=18,<24`.
- Parquet writes use an opaque UUID, mode-0600 temporary file, Zstandard compression, byte cap, SHA-256, atomic replace, and controlled-root verification.
- Artifacts carry 7 reserved provenance columns plus 39 model features. APIs/UI expose metadata only, never object references, paths, vectors, or raw endpoint fields.
- Feature jobs accept one approved schema and one succeeded ingestion job, cap input at 10,000 flows/output at 64 MiB, persist before dispatch, use actor-scoped idempotency, and enqueue only a UUID through JSON-only Celery.
- Worker tasks have 120/135-second soft/hard limits, two retries, pending and stale-processing reconciliation, sanitized terminal errors, success/failure audit, and 30-day artifact cleanup.
- API and worker images pre-create both shared artifact subdirectories as the non-root `aegis` user with mode `0700`.

### Governance, APIs, and UI

- Five permissions: `features:read`, `features:materialize`, `features:review`, `datasets:read`, and `datasets:manage`.
- Security Administrator alone receives review/manage permissions. System Administrator may materialize/read but cannot approve schemas or dataset metadata.
- Fresh migration seeds schema v1 as `draft`, never pre-approved. Review requires CSRF plus allowed Origin, validates the complete definition hash, records reviewer/reason/evidence, and writes append-oriented audit.
- Dataset proposal endpoints reject acquisition authorization and file entries. Sprint 4 stores only official-source review metadata.
- Minimal React/Vite UI lists feature definitions/windows/status/hashes/expiry and dataset governance, and can submit bounded jobs from successful ingestion. It has no dataset/vector preview/export or model control.

## 3. Files created

- `services/aegis_services/features/{__init__,schema,pipeline,preprocessing,artifacts}.py`
- `apps/api/aegis_api/{feature_dispatch,feature_processor}.py`
- `apps/api/aegis_api/routers/features.py`
- `migrations/versions/0004_sprint4_features.py`
- `tests/fixtures/features/{canonical_flow_cases,window_cases,leakage_cases}.json`
- `tests/unit/test_feature_pipeline.py`
- `tests/integration/test_features.py`
- `tests/performance/test_feature_pipeline_performance.py`
- `docs/features/FEATURE_DICTIONARY_V1.{json,md}`
- `docs/data/UNSW_NB15_OFFICIAL_SOURCE_REVIEW_2026-07-14.md`
- `docs/data/SYNTHETIC_FEATURE_QUALITY_REPORT.md`
- `docs/SPRINT_4_IMPLEMENTATION_PLAN.md`
- `docs/SPRINT_4_COMPLETION_REPORT.md`

## 4. Files changed

Environment/configuration, API models/schemas/router registration, centralized permissions, worker/Celery registration, API/worker Dockerfiles, dashboard UI/tests, test harness/matrices, PyArrow dependency, test image, README, Sprint 3 publication evidence, and governing backlog/decision/database/schema/API/architecture/data-flow/threat/test/deployment/risk/ML documents were updated. The Sprint 3 WebSocket route received one narrow regression correction: every timeout heartbeat path now reauthorizes the session before sending.

## 5. Database migration

`0004_sprint4_features` creates `feature_schema_versions`, `dataset_versions`, `dataset_split_versions`, `feature_materialization_jobs`, and `feature_artifacts`. It seeds five permissions, role grants, draft feature schema v1, and metadata-only UNSW-NB15 investigation. PostgreSQL triggers protect feature schema, dataset, split, and artifact definition fields. Downgrade refuses while feature artifacts exist, requiring inventory/removal first, then removes Sprint 4 objects/permissions only.

Fresh PostgreSQL upgrade reached `0004_sprint4_features (head)`. A definition mutation failed with `feature schema definitions are immutable`. Downgrade to `0003_sprint3_detection` and re-upgrade to head both succeeded before final materialization.

## 6. Validation and resource limits

| Boundary | Limit/policy |
|---|---|
| Compatible input | canonical flow schema `1` only |
| Feature width | 39 model values; schema cap 128 |
| Windows | exactly 60 and 300 seconds; configured cap 4 |
| Materialization input | 1–10,000 flows from one succeeded ingestion job |
| Artifact output | maximum 100,000 rows by configuration; job v1 input limits it to 10,000; 64 MiB |
| Celery time | 120-second soft, 135-second hard, two retries |
| Pending reconciliation | 60 seconds |
| Rate cap | `1e12` plus `rate_clipped` evidence |
| Storage | opaque controlled local Parquet; DB reference/shape/SHA-256 |
| Retention | 30 days; cleanup marks metadata deleted and audits |
| Review | Security Administrator only; CSRF+Origin; complete audit |

## 7. Commands and results

### Quality and tests

- Ruff tracked-source lint: passed.
- Ruff format check: passed, 76 files.
- mypy: passed, 52 source files.
- pytest: **99 passed**, one upstream Starlette/httpx deprecation warning, total coverage 75%, 27.60 seconds.
- Focused audited-review tests: 4 passed.
- 10,000-flow resource test passed its `<30s` and `<256 MiB incremental max RSS` assertions.
- Frontend ESLint/typecheck: passed.
- Vitest: **5 passed**; component coverage 53.55% statements / 55.12% lines.
- Production dashboard build: passed; JS bundle 204.61 kB before gzip, 63.80 kB gzip.

### Security and dependencies

- Full configured Bandit gate: passed with no findings. The two feature-vocabulary sentinels carry narrow `B105` suppressions because they are categorical missing/unknown markers, not credentials.
- `pip-audit`: no known vulnerabilities; the local `aegisai-nidps` package was correctly skipped because it is not a PyPI distribution.
- `npm audit --audit-level=high`: 0 vulnerabilities.
- Secret-assignment guard: passed.
- Simulation-only static guard: passed.
- `git diff --check`: passed.
- Oversized-file review found only ignored tool/dependency caches; no dataset, PCAP, Parquet artifact, model, credential, or large binary is in the diff.

### Docker, Celery, health, and synthetic end-to-end

- Publication-review rerun used isolated project `aegis-sprint4-review` with fresh PostgreSQL/artifact volumes and freshly rebuilt images.
- PostgreSQL, Redis, API, worker, scheduler, and dashboard reached healthy/running state.
- Liveness: `status=ok`, `prevention_mode=simulation`.
- Readiness: PostgreSQL and Redis `ok`; dashboard HTTP 200.
- Celery ping: one node online. Registered feature tasks: materialize, reconcile, cleanup; JSON serialization remains enforced.
- Separate System Administrator created a separate Security Administrator through the audited users API.
- Fresh schema state was `draft`; the Security Administrator approved it through CSRF/Origin protection, producing an audit record with actor, complete definition hash, reason, and regression evidence.
- One synthetic canonical flow was accepted; the raw upload was deleted immediately.
- Feature job `f086098d-9a59-4998-af1f-fca0c57d06ba` succeeded with one input/output and no quality flags.
- Artifact was 16,140 bytes, 1 row, 46 columns, SHA-256 `a2f757b3b27ec5a9c3b613863270ed167d97bb11517e995d002ebafc032a3287`, and expires 2026-08-13.
- Worker-side inspection matched the DB hash and confirmed all 7 provenance fields plus no `src_address`/`dst_address` columns.
- Audit API showed schema review, feature request, and feature success records tied to the Security Administrator.
- Migration downgrade to Sprint 3 and re-upgrade to head succeeded before materialization. After materialization, the downgrade correctly refused until artifact inventory/removal, and PostgreSQL rejected an attempted immutable definition mutation.
- The disposable Compose project and both review volumes were removed after evidence capture.

## 8. Findings encountered and corrected

| Severity before fix | Finding | Correction/status |
|---|---|---|
| High governance | Seeded schema was initially approved without a runtime reviewer/audit event | Seed now starts `draft`; dedicated audited Security Administrator review implemented and tested; resolved |
| High availability/correctness | Fresh shared volume allowed uploads but non-root worker could not create the feature directory | API/worker images pre-create `uploads` and `features` as `aegis` mode `0700`; clean-volume E2E passed; resolved |
| High recovery/correctness | A hard-killed worker could leave a job permanently `processing`; redelivery and pending-only reconciliation would not reclaim it | Added bounded stale-processing reconciliation/reclaim after hard-limit plus reconciliation delay and an integration regression test; resolved |
| Medium provenance | Initial Parquet held model columns but not per-row lineage fields | Added 7 reserved non-model provenance columns and integrity/privacy tests; resolved |
| Medium regression | Revoked WebSocket session could receive a timeout heartbeat before reauthorization | Timeout path reauthorizes first; regression test passed; resolved |
| Low/mechanical | Initial lint/import/line-wrap issues and three first-pass test failures | Corrected; complete suite now passes |

No unresolved Critical or High finding remains.

## 9. Failures and skipped checks

- The first local default Compose attempt encountered an existing PostgreSQL-volume password mismatch. That user-owned volume was preserved; all migration/runtime evidence used a new isolated project and disposable volumes.
- The first final-stack feature job exposed the feature-directory ownership defect above and failed safely with `feature_processing_failed`; it wrote no artifact. The disposable stack/volumes were deleted, images corrected, and a fresh clean-volume run passed.
- The first publication-review `npm audit` attempt could not resolve the registry inside the restricted sandbox; the authorized network rerun completed with 0 vulnerabilities.
- Hosted CI Run #6 first stopped at Bandit because its all-severity command rejected two documented feature-vocabulary sentinel false positives. Narrow `B105` suppressions corrected only that Sprint 4 CI mismatch; the exact hosted command then passed locally before republishing the amended single Sprint 4 commit.
- Semgrep, Trivy/SBOM, browser E2E/accessibility automation, ZAP, and representative multi-user/load tests remain documented future hardening gates, not current CI requirements.
- No real-dataset quality/class/split analysis ran because downloading a dataset was expressly prohibited.

## 10. Assumptions and residual risks

- Feature semantics are valid only for canonical flow v1 fields; dataset-native columns require a separately reviewed adapter and mapping.
- The 10,000-flow synthetic bound fits the approved 8 GB ARM64 development host in tests; it is not a production throughput claim.
- PyArrow is a native dependency. Hash/path/size/container controls and dependency audits reduce risk, but image scanning/SBOM remain future hardening.
- Migration `0004` constructs the initial immutable v1 definition through the versioned shared package. Future schema versions must be additive and must not alter the v1 factory; freezing an external migration snapshot is recommended before long-lived multi-version deployment.
- A solo Security Administrator may self-review as explicitly approved; there is no two-person separation for Sprint 4.
- Artifact cleanup is scheduled and tested, but operational alerting for missed cleanup remains future work.
- UNSW-NB15 suitability, integrity, prepared-file checksums, semantic mapping, and leakage remain unknown until separate acquisition authorization and review.

## 11. Acceptance criteria

All applicable Section 31 criteria pass: entry evidence, strict contracts, dictionary, deterministic direct/window transformations, missing/unseen/range handling, reference/batch parity, incompatibility rejection, leakage controls, immutable snapshot behavior, auditable official-source gate, artifact integrity/provenance/cleanup, bounded/idempotent/recoverable Celery, RBAC/CSRF/audit/privacy, reversible migration, synthetic resource bounds, metadata-only API/UI, security/dependency/container gates, clean-stack synthetic path, scope exclusion, current documentation, and no unresolved Critical/High issue.

**Final Sprint 4 decision: APPROVED.** The independent full-diff review found and resolved the stale-processing High issue, all local gates passed, final commit `72c97b15f9bb31ddb6810a397afc682893497bab` was published on `main`, and hosted CI Run #7 passed all backend, frontend, and container jobs. No Critical or High issue remains.

## 12. Publication evidence

- Final public commit: `72c97b15f9bb31ddb6810a397afc682893497bab`.
- Hosted CI Run #7: `29332025235`, completed successfully for the exact final SHA.
- Backend, frontend, and container jobs passed.
- Local `main`, recorded `origin/main`, and the public workflow SHA matched at the publication gate.
- The working tree was clean after publication.
- Sprint 5 remained unstarted and dataset acquisition remained false.
