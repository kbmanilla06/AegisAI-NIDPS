# Sprint 5 Gate 5S-A Completion Report

**Date:** 2026-07-14
**State:** implementation reviewed and verified locally; publication gate authorized; exact-hash owner acceptance remains pending
**Published baseline:** `72c97b15f9bb31ddb6810a397afc682893497bab`
**Branch:** `codex/sprint-5a-pre-acquisition`
**Decision:** **CONDITIONALLY APPROVED — STOP AT GATE 5S-A**

## 1. Outcome

Gate 5S-A is complete within its synthetic-only boundary. The implementation creates bounded project-generated canonical-flow-v1 evidence, materializes only through the existing Sprint 4 feature pipeline, stores labels separately, produces immutable dataset/split/quality/leakage evidence, enforces distinct-account review, and exposes only minimal aggregate metadata.

No real or third-party dataset was read or transferred. No publisher was contacted. No HEAD/GET dataset request, tokenized link, mirror, sample, packet, PCAP, payload, preprocessor fit, training, model artifact, registry, model load, scoring, prediction, online inference, alert mutation, or prevention capability was introduced. No commit or publication occurred.

The exact hashes in Section 7 are the owner-acceptance boundary. Gate 5S-B remains unauthorized until the owner explicitly accepts each one.

## 2. Entry-gate evidence

- Local `HEAD`, `main`, and `origin/main` were all `72c97b15f9bb31ddb6810a397afc682893497bab`.
- `git ls-remote` confirmed public `main` at the same SHA in `kbmanilla06/AegisAI-NIDPS`.
- Hosted GitHub Actions Run #7, database ID `29332025235`, was `completed/success` for that exact SHA.
- Published history was not rewritten.
- Existing uncommitted work was classified and preserved. It consists of owner-authorized Phase 5A pre-acquisition contracts, migration `0005`, metadata-only routes/docs/tests, and the no-contact/synthetic planning documents. It has no enabled transport or transfer task. It does not conflict with Gate 5S-A, and Gate 5S-A was added through migration `0006` without invoking or weakening acquisition controls.
- Publisher outreach remains cancelled. `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` remain excluded; acquisition remains blocked.

## 3. Findings encountered and corrected

| Severity | Finding | Resolution |
|---|---|---|
| High if unresolved | The first deterministic layout allowed a rounded full-vector near-duplicate across partitions. | Changed deterministic scenario construction; the closed build now rejects any cross-partition exact event, feature-vector, group, or rounded-full-vector collision. |
| High if unresolved | Initial partition timestamps could cross their intended time bands for sparse groups. | Assigned separate fixed training/validation/test epochs and verified strict non-overlap. |
| Medium | Initial deployment wiring did not subscribe the worker to the `synthetic` queue. | Added the queue to the non-root worker command and verified registration in the live stack. |
| Medium | API/worker images did not pre-create the synthetic artifact root. | Added a mode-`0700` controlled root in both images; all generated objects are mode `0600`. |
| Medium | Generation-request audit could have observed an unset ORM UUID before flush. | Flush now occurs before audit creation; uniqueness failure is handled with a safe conflict. |
| High if unresolved | Dataset review validated stored hash metadata but did not re-hash controlled files at action time. | Review now revalidates split/quality/leakage contracts, artifact metadata bindings, bounded file sizes, and streaming SHA-256 for all three objects; a replacement-object integration test returns a safe `409`. |
| Low | Bandit/Ruff flagged deterministic `random.Random`. | Added a narrow dual-scanner suppression with an explanatory comment. It is used only for reproducible fixture data, never secrets or security decisions. |
| High if unresolved | The completion report claimed every synthetic API response carried the mandatory limitation and false capability flags, but generation-job responses omitted them. | Added the exact limitation and all false capability flags to scenario, generation-job, and dataset responses, with integration assertions. |
| Medium | Exact owner-acceptance hashes were documented and independently reproduced but were not pinned as regression expectations. | Added exact assertions for all 12 accepted content, artifact, report, and partition hashes. |

No Critical or High issue remains in the implemented Gate 5S-A boundary.

## 4. Files and interfaces added or changed

### Gate 5S-A implementation

- `services/aegis_services/synthetic/schema.py` — strict frozen scenario, target, artifact, quality, leakage, split, and dataset manifest contracts.
- `services/aegis_services/synthetic/generator.py` — closed deterministic generator and group/time split evidence.
- `services/aegis_services/synthetic/artifacts.py` — atomic mode-`0600` flow/target writes, existing Parquet writer integration, exact 39-feature selector, safe opaque path resolution.
- `apps/api/aegis_api/synthetic_processor.py` and `synthetic_dispatch.py` — persisted job processing, reconciliation, safe failure, and retention cleanup.
- `apps/api/aegis_api/routers/synthetic.py` — catalog/job/dataset metadata and distinct review APIs.
- `migrations/versions/0006_sprint5_synthetic_gate.py` — additive reversible metadata migration.
- Worker/config/model/schema/permission wiring in API and Celery.
- Minimal dashboard panel for limitation text, aggregate hashes/counts, authorized generation, and distinct review.
- Golden/hostile fixture plus unit/integration/RBAC/worker/frontend tests.
- Governing architecture, database, API, schema, ML, risk, threat, test, deployment, backlog, decision, README, and completion documentation.

### Preserved inherited Phase 5A work

The uncommitted diff also retains migration `0005`, `services/aegis_services/datasets/`, acquisition metadata API/tests, and Phase 5A source/blocker/no-contact documents. These remain pre-acquisition-only and do not authorize or execute transfer.

## 5. Migration and authorization design

Migration `0006_sprint5_synthetic_gate` is additive over `0005_sprint5_preacquisition` and creates:

- `synthetic_generation_jobs` with actor/idempotency uniqueness, fixed seed `20260714`, fixed requested count `7200`, bounded generated counts, safe lifecycle, and approved feature-schema reference;
- `synthetic_dataset_versions` with immutable manifest/evidence/artifact definitions, fixed `7200` flows, `120` groups, `46` Parquet columns, 30-day retention, creator/reviewer separation, and lifecycle `generated → accepted_synthetic|rejected → retired`;
- `synthetic_datasets:read`, `synthetic_datasets:generate`, and `synthetic_datasets:review`.

Role assignment is centralized:

- System Administrator: read and generate, never review;
- Security Administrator: read and review, never generate;
- Senior Analyst and Auditor: read only;
- Viewer and SOC Analyst: no synthetic permission.

Unsafe routes require the existing cookie session, CSRF token, and exact Origin checks. Reviews lock the dataset row, deny creator self-review, revalidate manifest and evidence hashes, and persist safe audit metadata transactionally.

The downgrade refuses while any synthetic artifact remains inventoried. A fresh PostgreSQL upgrade, downgrade to `0005`, and re-upgrade to `0006` passed in the disposable stack.

## 6. Generated counts and split evidence

| Evidence | Exact result |
|---|---:|
| Global seed | `20260714` |
| Canonical flows | 7,200 |
| Groups | 120 |
| Feature columns | 46 = 7 reserved non-model provenance + 39 ordered model features |
| `synthetic_benign_like` | 3,670 |
| `synthetic_intrusion_like` | 3,530 |
| Each of eight scenario families | 900 |
| Training | 5,040 rows / 72 groups / 70% |
| Validation | 1,080 rows / 24 groups / 15% |
| Sealed test | 1,080 rows / 24 groups / 15% |
| Invalid rows | 0 |
| Real-dataset rows | 0 |
| Network requests | 0 |
| Banned model columns | none |
| Cross-partition exact event/vector/group/near duplicates | 0 / 0 / 0 / 0 |
| Perfect single-feature separators | none |

The partition bands are non-overlapping: training ends `2025-03-14T00:12:47.000183Z`, validation runs from `2025-07-02T00:00:00.000010Z` through `2025-07-25T00:08:06.000161Z`, and test starts `2025-10-02T00:00:00.000013Z`.

## 7. Exact owner-acceptance hashes

| Evidence | SHA-256 |
|---|---|
| Scenario catalog | `72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87` |
| Approved feature schema `flow_features/1.0.0` | `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114` |
| Dataset content | `b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a` |
| Canonical-flow JSONL artifact | `96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac` |
| Target manifest/artifact | `90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70` |
| 39+7 Parquet feature artifact | `454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9` |
| Split manifest | `d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895` |
| Quality report | `c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4` |
| Leakage report | `2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d` |
| Training identity set | `25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7` |
| Validation identity set | `96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f` |
| Test identity set | `ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4` |

The flow artifact is 2,368,941 bytes, target artifact 2,249,431 bytes, and feature artifact 1,063,226 bytes. All were generated in ephemeral controlled storage and removed automatically. A second clean run reproduced every content/report/artifact hash exactly. Runtime database-manifest hashes intentionally also bind fresh opaque object references and creation time; owner acceptance is therefore over the canonical content and evidence hashes above, while each persisted runtime manifest still receives its own audited exact review.

## 8. Mandatory limitation

Every manifest, API response, report, and UI view uses this exact text:

> SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. The model is offline-only and cannot create or modify alerts or prevention actions.

Machine-readable flags also fix real dataset use, UNSW acquisition/evaluation, network generation, online inference, alert side effects, and prevention to `false`.

## 9. Resource and controlled-artifact results

- Deterministic feature build: `1.985138` seconds.
- Peak process RSS: `143,928 KiB` (about 140.6 MiB), below the 384 MiB worker limit.
- Feature output: 1,063,226 bytes, below the 67,108,864-byte limit.
- All three objects: mode `0600`; artifact directory: mode `0700`.
- Worker: 384 MiB, 0.75 CPU, 128 PIDs, concurrency 1, 120/135-second soft/hard task limits.
- API: 384 MiB, 1 CPU, 128 PIDs.
- API and worker: non-privileged, read-only root filesystem, `cap_drop=ALL`, no host network.
- Prevention remains `simulation`; no firewall capability or enforcement dependency exists.

## 10. Commands and checks actually run

Representative commands, with the disposable password value omitted:

```text
git rev-parse HEAD main origin/main
git ls-remote <public repository> refs/heads/main
GitHub Actions API query for Run #7
git status --short
git diff --stat
git diff --check

docker run ... ruff format .
docker run ... ruff check . --fix
docker run ... mypy apps/api apps/worker services
docker run ... pytest -q
docker run ... bandit -c pyproject.toml -r apps services
docker run ... pip-audit
docker run ... python scripts/check_secrets.py
docker run ... python scripts/check_simulation_only.py

npm run lint
npm run typecheck
npm run test
npm run build
npm audit --audit-level=high

docker compose config --quiet
docker compose build
docker compose -p aegisgate5sa up -d --wait postgres redis
docker compose -p aegisgate5sa run --rm migrate
docker compose -p aegisgate5sa run --rm migrate alembic downgrade 0005_sprint5_preacquisition
docker compose -p aegisgate5sa run --rm migrate alembic upgrade head
docker compose -p aegisgate5sa up -d --wait
curl /api/v1/health/live
curl /api/v1/health/ready
curl dashboard root
docker compose -p aegisgate5sa exec -T worker celery ... inspect ping
docker inspect API and worker security/resource settings
two independent ephemeral synthetic generation/artifact runs
```

## 11. Test and security results

| Gate | Result |
|---|---|
| Ruff format/lint | Pass; 93 files |
| mypy | Pass; 61 source files |
| Backend unit/integration/security/contract/worker | Pass; 123 tests; 76% aggregate coverage |
| Gate 5S-A determinism/reproducibility | Pass; two exact clean-run content and artifact hash sets |
| Canonical-flow, 39+7, label separation, window, missing/unseen/range | Pass |
| Split, support, duplicate/near-duplicate, leakage, sealed test | Pass |
| RBAC negative matrix, CSRF/Origin, audit, self-review, idempotency, cleanup | Pass |
| Migration fresh upgrade/downgrade/re-upgrade | Pass on PostgreSQL 16 |
| Bandit | Pass; no findings |
| pip-audit | Pass; no known vulnerabilities; local package correctly skipped as not on PyPI |
| Secret assignment guard | Pass |
| Simulation-only guard | Pass |
| Frontend lint/type/component/accessibility/build | Pass; 6 tests; production build |
| npm audit | Pass; 0 vulnerabilities |
| Compose config/build | Pass; API, worker, scheduler, dashboard images built |
| Clean stack | Pass; all services healthy; liveness/readiness and dashboard HTTP passed |
| Celery | Pass; one node pong; synthetic generate/reconcile/cleanup registered; `synthetic` queue consumed |
| Container security | Pass; no privilege/host network; read-only; all capabilities dropped; bounds verified |
| Diff/large-file review | Pass; only ignored caches/dependencies exceed 5 MiB; no dataset/model/PCAP/Parquet/target/prediction artifact is in the worktree diff |

## 12. Failures and skipped checks

- The first `npm audit` attempt failed because the sandbox could not resolve the registry; the authorized network retry passed with zero vulnerabilities.
- The first security chain stopped on a Low Bandit deterministic-PRNG finding. After a narrow documented non-security suppression, Bandit passed with no findings.
- Two evidence scripts initially used an unavailable unmounted package and then a wrong field name; neither changed files or retained artifacts. The corrected evidence runs passed and were independently reproduced.
- Trivy/container CVE scanning and a retained SBOM were not run because Trivy/Syft are not installed and these are configured as Gate 5S-B requirements when ONNX/native ML dependencies enter scope. Docker Compose build, pip-audit, npm audit, pinned base-image digest review, and container security inspection passed. This is not treated as a Gate 5S-A pass for Trivy.
- Full browser automation, ZAP, representative load/fault-kill testing, and independent-human review are not configured. Component accessibility assertions and clean-stack HTTP checks passed. These are residual hardening items, not claims of completion.
- Hosted CI is pending the authorized publication step recorded in Section 17.

## 13. Assumptions and residual risks

1. Synthetic scenarios validate software contracts only; they do not approximate real prevalence, semantics, or operational performance.
2. Creator/reviewer separation is by distinct accounts; this solo portfolio has no independent second person.
3. The aggregate leakage report proves no banned columns, cross-partition duplicates, or perfect single-feature separator. It does not establish absence of multivariate scenario learnability; Gate 5S-B must treat that as a demo limitation.
4. The exact Parquet byte hash was produced with PyArrow `23.0.1` on Linux ARM64. A dependency/runtime change may change Parquet bytes and must fail the hash gate or create a new reviewed version.
5. The inherited pre-acquisition transfer abstraction remains disabled but should be reviewed separately before any eventual publication. Acquisition stays blocked.
6. Retention cleanup is locally tested; production-grade overdue monitoring, backup/restore, container CVE scanning, and hard-kill recovery remain future hardening.
7. No numeric model performance claim is authorized now or by acceptance of these hashes.

## 14. Acceptance criteria status

| Gate 5S-A criterion | Status |
|---|---|
| Scope/no-contact/no-real-data boundary | Pass |
| Strict closed scenarios and hostile fixtures before generator | Pass |
| Bounded deterministic canonical-flow v1 | Pass |
| Existing Sprint 4 feature pipeline only | Pass |
| Exact 39+7 and separate labels | Pass |
| Immutable manifests and limitation flags | Pass |
| Group/time 70/15/15, minimum support, sealed test | Pass |
| Duplicate/near-duplicate and leakage evidence | Pass |
| RBAC/CSRF/Origin/audit/distinct reviewer | Pass |
| Additive reversible migration | Pass |
| UUID-only Celery/resource/artifact/cleanup | Pass |
| Minimal metadata-only API/UI | Pass |
| No preprocessing/model/detection/prevention work | Pass |
| No unresolved Critical/High issue | Pass locally |
| Owner acceptance of every exact hash | **Pending — current stop gate** |

## 15. Final Gate 5S-A decision

**CONDITIONALLY APPROVED.** The implementation and local verification satisfy Gate 5S-A with no unresolved Critical or High issue. The condition is explicit owner acceptance of every hash in Section 7. Until that occurs, Gate 5S-B is blocked. Publication of this checkpoint does not accept the hashes and does not authorize model work.

## 16. Exact separate Gate 5S-B authorization prompt

```text
Accept the exact AegisAI NIDPS Sprint 5 Gate 5S-A synthetic evidence and authorize Gate 5S-B only: training-only preprocessing, bounded synthetic-demo baseline training/evaluation, controlled ONNX conversion/parity, model card, and candidate artifacts. Do not authorize registry activation or scoring.

Before proceeding, read all governing documents, docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md, and docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md completely. Confirm the worktree contains only the reviewed inherited Phase 5A and Gate 5S-A changes, no real dataset/model artifact, and no newer separately authorized baseline.

I explicitly accept these exact Gate 5S-A hashes:
- scenario catalog: 72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87
- feature schema: 17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114
- dataset content: b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a
- canonical-flow artifact: 96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac
- target manifest/artifact: 90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70
- 39+7 feature artifact: 454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9
- split manifest: d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895
- quality report: c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4
- leakage report: 2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d
- training identity set: 25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7
- validation identity set: 96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f
- sealed test identity set: ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4

Use only the accepted synthetic canonical-flow-v1 evidence. Keep UNSW-NB15 and every real/third-party dataset blocked; keep publisher outreach cancelled. Approve only majority reference, Logistic Regression, and Random Forest with the exact deterministic bounded definitions in the plan. Fit all vocabulary, missing-value handling, scaling, and any approved preprocessing on training only. Compare candidates on validation only at fixed threshold 0.50. Open the sealed test exactly once for the final selected candidate, record the audit event, and prohibit retuning afterward. There is no numeric performance pass gate and every metric, artifact, model card, report, API response, and UI view must carry the exact synthetic-demo limitation and machine-readable false capability flags.

Before creating any model artifact, revalidate and record exact ARM64-compatible versions and hashes for scikit-learn, skl2onnx, ONNX, ONNX Runtime, NumPy/SciPy, PyArrow, and transitive native dependencies. Freeze the exact environment, produce an SBOM, run Trivy or a documented equivalent container/native scan, and fail closed on any unresolved Critical/High finding. Use ONNX plus canonical JSON only; no pickle/joblib/Python-object artifact, custom operator/domain, external data, dynamic shape, arbitrary graph, or untrusted model input. Fix the approved opset/operator allowlist, two-class output order, float32 input shape, 16 MiB artifact limit, golden probability tolerance 1e-6, full-matrix tolerance 1e-5, and exact threshold-decision parity.

Implement only the additive reversible Gate 5S-B metadata, JSON-only UUID Celery tasks, controlled artifacts, RBAC/CSRF/Origin/audit, resource/retention/rollback handling, minimal metadata UI/API, tests, and documentation required for preprocessing, bounded training, validation, one test opening, evaluation, ONNX conversion/parity, model cards, and unreviewed candidate artifacts. No candidate may become active, reviewed-synthetic, registered for scoring, loaded by API/detection startup, or used online.

Do not acquire/download/read a real dataset; contact the publisher; use mirrors or tokenized links; modify the accepted Gate 5S-A evidence; create online inference, scoring, predictions, alerts, detection/incident/prevention mutations; add anomaly/ensemble work; begin Gate 5S-C or Sprint 6; use privileged containers, host networking, firewall capability, or enforcement dependencies; commit or publish.

Run and record all Gate 5S-B quality, preprocessing parity, train-only fit, determinism, validation/test isolation, metric, one-time sealed-test, ONNX closed-policy/integrity/parity, model-card/limitation, RBAC/audit, migration, Celery/resource, retention, dependency/SBOM/Trivy, Docker/health, frontend/accessibility, secret, large-file, and simulation-only gates. Stop at the uncommitted Gate 5S-B exact-candidate-hash acceptance gate and wait for separate owner approval before any registry or scoring work.
```

## 17. Publication review

The complete inherited Phase 5A and Gate 5S-A diff was reviewed against security, correctness, privacy, migration, artifact-integrity, deterministic-generation, feature-contract, label-separation, split, leakage, reproducibility, retention, Celery, RBAC, CSRF/Origin, audit, dataset-governance, misleading-claim, and authorization boundaries.

Confirmed publication boundaries:

- UNSW-NB15 acquisition is blocked and publisher outreach is cancelled.
- No real or third-party dataset byte, NUSW-named candidate file, dataset payload, model artifact, prediction, PCAP, or generated Parquet artifact is present in the repository diff.
- No preprocessor was fitted and no model was trained, loaded, registered, activated, or scored.
- No online inference, alert mutation, live capture, or real prevention capability was introduced.
- The exact 12 hashes in Section 7 are pinned by tests and match regenerated evidence.
- Scenario, job, dataset, manifest, report, audit, and UI surfaces carry the mandatory synthetic limitation and/or the applicable machine-readable false capability flags; metadata responses were regression-tested after the review correction.

Publication evidence:

- Reviewed checkpoint commit: pending commit creation.
- Public branch: pending push to `main`.
- Hosted CI: pending.
- Gate 5S-B: unauthorized and blocked pending explicit owner acceptance of every Section 7 hash.
