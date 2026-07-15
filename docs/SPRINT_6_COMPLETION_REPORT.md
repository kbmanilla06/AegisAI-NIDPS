# AegisAI NIDPS Sprint 6 Completion Report (Uncommitted Gate 6C)

Status: **READY FOR SEPARATE REVIEW — UNCOMMITTED**
Decision: **CONDITIONALLY COMPLETE at Gate 6C; publication and activation are not authorized**
Baseline: public Gate 5S-C `9cc643dba4a9d15284eb1a812bf661f848a801ce`; hosted CI Run #12 passed.

## Scope and safety boundary

Only the approved synthetic Gate 5S-A/B/C evidence was used. UNSW-NB15 acquisition remains blocked, publisher outreach remains cancelled, and `NUSW-NB15_features.csv` / `NUSW-NB15_GT.csv` remain excluded. No real or third-party dataset bytes, packet capture, endpoint address, payload, credential, URL, model activation, online inference, alert/detection/incident mutation, or prevention adapter was added.

Every anomaly, threshold, fusion policy, assessment, API response, UI surface, and report carries the exact synthetic-demo limitation and false-capability flags. The implementation cannot activate a model or create/update alerts or prevention actions.

## Gate 6A evidence

The bounded Isolation Forest uses 100 estimators, `max_samples=min(256, normal_training_rows)`, `max_features=1.0`, `bootstrap=false`, seed `20260714`, one CPU thread, and the 39 approved model features only. The normal population is the training-only synthetic benign-like identity set. Score normalization anchors are fit on training scores; the threshold is the 95th percentile of validation benign-like scores. The sealed test is opened once for evidence and is never used for threshold tuning.

ONNX is the only model representation. The validator rejects external data, dynamic input shape, unsupported domains/operators, oversized artifacts, non-finite input/output, and incompatible opsets. The approved graph has one float32 `[1,39]` input and one score output; no Python estimator, pickle, joblib, custom operator, or online loader is present.

The conversion gate compares 32 deterministic ONNX scores against the Isolation Forest reference with absolute tolerance `1e-6`; candidates fail closed on any mismatch.

Gate 6A hashes:

| Evidence | SHA-256 |
|---|---|
| detector manifest | `68407ca974ac8c0c02dd957c3892e6064f34f0fd445f67a304f7dc0fe0d8727f` |
| threshold manifest | `fc4b3a1769e804492455f2bb79bfcb202980bf75145478a4a5bf11090fb82a41` |
| ONNX candidate | `44a446fb5f8e3ebb294dbb612eaefbdcc82b481a7e77c6bd2772cc8178f44b64` |
| candidate metadata | `26655adabbd51af22449b7e5cbf7f3d384923ecfabe50d02f069e05004b6c66e` |
| sealed-test normalized scores | `2d8cbf74b5b3371a7a7aa9d2904671311294f917eebc26110383da95d11a38f5` |
| sealed-test decisions | `696e47513e6583c1f02ff3762068fdb4110b756b6640ac4bf626fe74ebf11d5c` |
| Gate 6A evidence bundle | `36c4f95b583427eea95ee6a655df537f6bae0f8ff915571a14a83f20416ad231` |

## Gate 6B evidence

`FusionInputV1` strictly normalizes signal source, version hash, identity, bounded score, quality, and evidence hash. Missing, invalid, stale, or disagreeing inputs produce explicit uncertainty codes. The policy uses signature `.4`, behavioral `.3`, supervised `.2`, and anomaly `.1` weights; confidence is provenance- and agreement-aware and capped for single-source assessments. Category precedence and severity bands are deterministic. Fusion writes only aggregate offline assessment metadata and non-sensitive decision sidecars; it never calls the alert or prevention paths.

Gate 6B hashes:

| Evidence | SHA-256 |
|---|---|
| default policy | `a2ae6b623dfa8a365692650dda0b7c8065d53405b52e333b6c8efb8d55205a40` |
| Gate 6B evidence bundle | `dda3375076ac8be716cad85876074a31501ed1ed0e8f6956a7b6140b0269804c` |

## Persistence and interfaces

- Migration `0009_sprint6_anomaly_ensemble` adds immutable detector, threshold, policy, assessment-batch, and decision-assessment metadata with creator/reviewer separation, hash/size/score bounds, idempotency, foreign keys, retention timestamps, and reversible downgrade checks.
- JSON-only UUID Celery tasks: `aegis.anomaly.fit`, `aegis.ensemble.evaluate`, and retention cleanup. Tasks receive UUIDs only; no uploaded paths or model objects cross the queue.
- API: metadata-only detector listing/fit/review, policy listing/create/review, and offline assessment listing/request. All mutating routes require secure session, CSRF token, Origin enforcement, permission checks, idempotency, and sanitized audit events.
- Dashboard: limitation-labeled anomaly, policy, and aggregate assessment view; no activation, scoring, alert, or prevention control.

## Commands and results

- Docker test image build: passed.
- `pytest -q`: **141 passed**. One existing Starlette/httpx deprecation warning remains.
- Sprint 6 anomaly unit/API tests: **7 passed** (included in the full suite).
- `ruff check` (Sprint 6 files and migration): passed.
- `mypy apps/api/aegis_api apps/worker/aegis_worker services/aegis_services`: passed, no issues.
- Bandit over new anomaly/fusion code: passed with no findings.
- Dashboard `npm run lint`, `npm run typecheck`, `npm run build`: passed.
- Celery registration check: `aegis.anomaly.fit`, `aegis.ensemble.evaluate`, and `aegis.anomaly.cleanup` registered; JSON serializer configuration verified.
- PostgreSQL migration: upgrade through `0009`, downgrade to `0008`, and re-upgrade to `0009`: passed on a disposable PostgreSQL 16 container.
- Final containerized quality gate: Ruff check and format check passed; mypy passed with no issues in 75 source files.
- Artifact cleanup: expired anomaly model and metadata objects are deleted only through validated opaque references under the controlled anomaly volume, then metadata is retired.
- Health unit checks: **3 passed**.
- Secret-pattern scan (`rg` for private keys, cloud keys, and common API tokens): no matches.
- Docker Compose PostgreSQL/Redis services: started for local verification; the pre-existing Compose volume had an unknown password, so migration verification used a separate disposable PostgreSQL container. No credentials were written to the repository.
- `pip-audit --strict`: skipped as a pass gate because the local project distribution `aegisai-nidps==0.1.0` is not resolvable on PyPI; this is an audit-tool limitation, not a claimed clean dependency result.

## Acceptance status

Gate 6A anomaly evidence: **satisfied**.
Gate 6B transparent fusion evidence: **satisfied**.
Gate 6C completion review: **pending owner review of this uncommitted diff and the exact hashes above**.
Publication, model registry activation, online inference, real data, and prevention: **not authorized and not implemented**.

## Residual risks and assumptions

- ONNX Runtime/skl2onnx native dependencies are pinned by the existing ML lock set; a hosted SBOM/Trivy scan remains a publication-gate check.
- The worker performs deterministic synthetic evidence generation in a bounded task; production capacity is not inferred from synthetic elapsed time.
- The API intentionally exposes metadata and aggregate counts only; row-level decision sidecars are hash-bound and retention-limited.
- No numeric detection-performance claim is made or permitted.

## Exact next approval prompt

> Review the complete uncommitted AegisAI NIDPS Sprint 6 implementation and `docs/SPRINT_6_COMPLETION_REPORT.md`. Confirm the diff remains within Gates 6A–6C and synthetic-only scope; verify the exact Gate 6A/Gate 6B hashes, ONNX closed policy, validation-only thresholding, transparent fusion, creator/reviewer separation, migration reversibility, Celery JSON-only UUID behavior, aggregate-only privacy, RBAC/CSRF/Origin/audit controls, retention, and absence of model activation, online inference, alert/detection/incident/prevention mutation, real data, live capture, or Sprint 7 work. Re-run all applicable local quality, security, migration, Docker, Celery, frontend, accessibility, health, and synthetic-only gates. If no Critical or High issue remains, create one reviewed Sprint 6 commit, push it to public `main`, run hosted CI, correct only Sprint 6 CI failures, update this report with the final SHA and CI result, and stop. Do not activate a model, enable online inference, acquire data, contact the publisher, add prevention, or begin Sprint 7.
