# Post-MVP Gate P1 Completion Report

**Status:** APPROVED — published to public `main`
**Completed at:** 2026-07-17T07:25:30Z
**Authorized scope:** Synthetic monitoring/drift contracts and analyst-feedback foundations only
**Baseline:** `ec19068c787e4eedf0c9bef272a95a1c8256afca`; hosted CI Run #32 was previously recorded as passing
**Gate P1 publication commits:** `9d5e4ed` (reviewed implementation), `301d16a` (hosted-CI formatting correction)
**Final public-main SHA:** `301d16af3398d0c5bde922469dcd2d462562cb2e`
**Hosted CI:** Run `29562380063` passed after the failed-job rerun (backend, containers, and frontend all green)

## 1. Scope outcome

Gate P1 was implemented as an offline, metadata-only synthetic capability. It evaluates bounded aggregate snapshots and stores reviewable evidence. It does not load or activate models, run online inference, ingest packets, create predictions, mutate alerts/detections/incidents, or perform prevention.

The accepted Gate 5S-A/B/C evidence remains the only permitted source identity. UNSW-NB15 acquisition remains blocked, publisher outreach remains cancelled, and the `NUSW-NB15_features.csv`/`NUSW-NB15_GT.csv` candidates remain excluded.

## 2. Files created or changed

### Gate P1 implementation

- `services/aegis_services/monitoring/schema.py` and package exports: versioned aggregate snapshot, policy, result, limitation text, false-capability flags, deterministic hash, drift evaluation, minimum-sample `not_evaluable` behavior, and closed metric allowlist.
- `apps/api/aegis_api/models.py`: monitoring-run, metric, and analyst-feedback metadata models.
- `apps/api/aegis_api/routers/monitoring.py`: read-only run/metric/feedback APIs, CSRF/Origin-protected run submission and feedback transitions, accepted-hash binding, idempotency, reviewer separation, and audit.
- `apps/api/aegis_api/monitoring_processor.py` and `monitoring_dispatch.py`: bounded worker processing, 30-day monitoring-evidence cleanup, and 180-day analyst-feedback cleanup.
- `apps/api/aegis_api/schemas.py`: strict request/response contracts.
- `apps/api/aegis_api/security/permissions.py`: centralized monitoring and feedback permissions with role-specific grants.
- `apps/worker/aegis_worker/celery_app.py`: JSON-only UUID evaluation and cleanup tasks with time limits and retry bounds.
- `apps/dashboard/src/App.tsx`: metadata-only monitoring/feedback view with limitation text and false-capability flags.
- `migrations/versions/0013_post_mvp_monitoring_feedback.py`: additive reversible migration; downgrade refuses while evidence rows remain.
- `apps/api/Dockerfile` and `apps/worker/Dockerfile`: remove the unused vulnerable `perl-base` runtime and use native `groupadd/useradd` helpers while retaining the pinned glibc ARM64 Python base and native wheels.

### Documentation and tests

- `docs/POST_MVP_SYNTHETIC_ROADMAP.md`
- `docs/POST_MVP_GATE_P1_COMPLETION_REPORT.md`
- `docs/DECISIONS.md` (C-32)
- `docs/RISK_REGISTER.md` (R-39–R-42)
- `docs/threat-model/THREAT_MODEL.md` was preserved with the inherited Sprint 10 planning extension; no enforcement capability was added.
- `tests/unit/test_monitoring_contracts.py`
- `tests/integration/test_monitoring.py`
- `tests/conftest.py` and `tests/unit/test_worker.py`

Existing uncommitted Sprint 10 planning/preflight documents remain preserved and uncommitted. They are historical planning evidence only and do not authorize Gate 10B or enforcement.

## 3. Contracts and behavior

- Contract: `synthetic-monitoring-snapshot/1.0.0`.
- Result: `synthetic-monitoring-result/1.0.0`.
- Policy default: `synthetic-drift-default/1.0.0`, minimum 30 samples, warning delta 0.20, critical delta 0.50.
- Source kinds: `synthetic_flow`, `synthetic_feature`, `synthetic_score`, and `synthetic_anomaly`.
- Metrics are aggregate-only and closed to a fixed allowlist; raw endpoints, payloads, URLs, credentials, internal paths, and model inputs cannot be submitted.
- Unknown/mismatched accepted artifact hashes fail closed.
- Low-sample or missing-metric comparisons return `not_evaluable`, never a normal/healthy status.
- Monitoring results are evidence only. No automatic retraining, promotion, activation, scoring, alert mutation, detection mutation, incident mutation, or prevention action exists.
- Analyst feedback supports bounded dispositions and notes. Review requires a distinct Security Administrator account and records a complete audit event.

## 4. Accepted synthetic evidence binding

The implementation preserves these owner-accepted Gate 5S hashes:

| Evidence | SHA-256 |
|---|---|
| Scenario catalog | `72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87` |
| Feature schema | `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114` |
| Dataset content | `b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a` |
| Canonical-flow artifact | `96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac` |
| Target manifest | `90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70` |
| Feature artifact | `454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9` |
| Split manifest | `d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895` |
| Quality report | `c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4` |
| Leakage report | `2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d` |
| Training identity | `25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7` |
| Validation identity | `96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f` |
| Sealed-test identity | `ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4` |

## 5. Database migration

`0013_p1_monitoring` follows `0012_sprint9_prevention_sim` and adds:

- `synthetic_monitoring_runs`
- `synthetic_monitoring_metrics`
- `synthetic_analyst_feedback`
- four permission rows and role grants

The downgrade refuses to delete live monitoring or feedback evidence. It must be retried only after explicit expiry/cleanup. Migration source SHA-256: `11463c3e2fdd9a51d294dd214b6378f2692fd52e7ee41ae269a5a6cb04f1b529`.

## 6. Checks run

| Check | Result |
|---|---|
| Focused Gate P1 tests | Passed: 12 tests |
| Full local pytest suite | Passed: 253 tests, 1 existing Starlette/httpx deprecation warning |
| Ruff Gate P1 files | Passed |
| Targeted mypy | Passed: 6 source files |
| Simulation-only static guard | Passed |
| Secret-assignment guard | Passed |
| Celery JSON-only and malformed UUID task tests | Passed |
| RBAC/CSRF/Origin/feedback reviewer-separation tests | Passed |
| Deterministic drift/not-evaluable/contract tests | Passed |
| Docker/health checks | Passed in isolated disposable `aegis-p1` Compose project: ARM64 images rebuilt without cache, migration upgraded to `0013_p1_monitoring`, PostgreSQL/Redis/API/dashboard healthy, `/api/v1/health/live` and `/api/v1/health/ready` returned OK; stack and volumes torn down |
| Frontend lint/typecheck/tests | Passed: ESLint, TypeScript, and 7 Vitest tests |
| Frontend production build | Passed: Vite build |
| Accessibility checks | Existing frontend test suite passed; dedicated automated accessibility scan not available in the repository toolchain |
| Database migration execution | Fresh disposable PostgreSQL upgrade, downgrade to `0012_sprint9_prevention_sim`, and re-upgrade to `0013_p1_monitoring` all passed with empty evidence; offline `alembic upgrade head --sql` remains blocked by the pre-existing `0001` literal-rendering issue |
| Python dependency consistency | Passed: `python -m pip check` reported no broken requirements |
| Dashboard dependency audit | Passed: `npm audit --omit=dev --audit-level=high` found 0 vulnerabilities |
| Container SBOM/CVE scan before remediation | Blocked: Docker Scout found 1 Critical plus 2 High CVEs in inherited `perl 5.40.1-6` from pinned `python:3.12-slim` digest `64695412729f` |
| Container SBOM/CVE scan after remediation | Passed: Docker Scout indexed API (174 packages), migration (174), worker (188), and scheduler (188); all reported `0 Critical / 0 High / 0 vulnerable packages` |
| Native dependency compatibility | Passed: rebuilt ARM64 API/migration and ML worker/scheduler images installed and imported PyArrow, NumPy, SciPy, scikit-learn, ONNX, ONNX Runtime, and skl2onnx successfully |
| Base-image remediation behavior | Passed: ephemeral runtime test confirmed Python/FastAPI/PyArrow remain importable after `perl-base` removal; native `groupadd/useradd` account creation succeeds |

## 7. Assumptions and residual risks

- Monitoring snapshots are aggregate metadata supplied by a trusted server-side synthetic workflow; the API still validates schema, bounds, source kind, and accepted artifact hashes.
- The default drift statistic is absolute metric delta. It is a software-contract default, not a statistical claim about production drift.
- P1 does not add a metrics backend, online telemetry, automatic threshold response, or report exporter; those belong to P2.
- The remediation intentionally removes an unused essential Debian Perl runtime; future base-image refreshes must repeat native-wheel and Docker Scout checks. Alpine was not selected because it would introduce a musl/native-wheel compatibility change.
- Existing uncommitted Sprint 10 planning/preflight files remain in the worktree and must be reviewed separately before any publication.

No Critical or High issue remains in the reviewed Gate P1 application or rebuilt container images. The initial base-image finding was resolved by removing the unused `perl-base` package and replacing its account-helper dependency with native tools. The first remediation build exposed and corrected that helper dependency; the final full suite and image checks are green.

## 8. Gate P1 acceptance status

**APPROVED — published.** Functional Gate P1 evidence, remediated Docker images, Docker startup/health, Celery, migration upgrade/downgrade/re-upgrade, frontend checks, Python/npm dependency checks, full local tests, Docker Scout, and hosted CI Run `29562380063` pass. Dedicated accessibility scanning was unavailable in the repository toolchain; populated-evidence downgrade-refusal testing remains a residual review item. No Gate P2 or real enforcement capability was introduced.

## 9. Exact next authorization prompt

> Gate P1 is published as `301d16af3398d0c5bde922469dcd2d462562cb2e` and hosted CI Run `29562380063` passed. Review the final report and authorize Gate P2 planning only if desired. Do not implement Gate P2, activate models, enable online inference, use real datasets, contact the publisher, configure live capture, mutate alerts/detections/prevention, or add real prevention.

Stop at the Gate P1 publication gate and wait for owner approval.
