# AegisAI NIDPS Post-MVP Gate P4 Completion Report

**Status:** UNCOMMITTED — ready for separate review/publication approval

**Scope:** ARM64 local Docker Compose reproducibility and synthetic/offline
release assurance only

## Publication result

- Reviewed Gate P4 implementation commit: `20a5e4c273045202db9facbe37de086e6ab9dbbb`
- Hosted CI Run `29675771383`: **passed** (backend, frontend, containers)
- The implementation commit contains only the six reviewed Gate P4 files;
  inherited Sprint 10 files remain excluded.
- This report update is documentation-only; no Gate P5 or prohibited capability
  was introduced.

## 1. Baseline and authorization

- Public `main`: `720c5e33960212c6f2130e4ac1fe9a1948b5fcb2`
- Hosted CI Run `29594167997`: completed successfully (`ci`)
- Accepted Gate 5S-A/B/C evidence: unchanged and hash-bound
- Working tree classification: P4 files are listed below; inherited Sprint 10
  planning/preflight files remain unmodified and excluded
- Publication: not performed; no commit, push, tag, or release was created

## 2. Scope review

The P4 diff is limited to a pure metadata-only reproducibility helper, its
offline CLI, focused tests, and runbook/report documentation. No migration,
API route, UI behavior, Celery task, model behavior, dataset handling, packet
capture, prevention adapter, firewall/host-state integration, socket,
subprocess, privileged container, host network, or enforcement dependency was
added. Existing inherited Sprint 10 files were preserved and excluded.

## 3. Files created for Gate P4

- `services/aegis_services/reproducibility.py`
- `scripts/create_reproducibility_evidence.py`
- `tests/unit/test_reproducibility.py`
- `docs/POST_MVP_GATE_P4_PLAN.md`
- `docs/POST_MVP_GATE_P4_REPRODUCIBILITY_RUNBOOK.md`
- `docs/POST_MVP_GATE_P4_COMPLETION_REPORT.md`

No database migration or new runtime interface was necessary. The helper uses
the versioned `deployment_reproducibility/1.0.0` metadata contract, allowlisted
control/source hashes, aggregate posture, exact accepted synthetic hashes,
retention, limitation text, and machine-readable false-capability flags. Its
output is canonical JSON written mode `0600` with no raw payloads or paths.

## 4. Accepted synthetic evidence binding

The helper retains these exact immutable identities:

| Evidence | SHA-256 |
| --- | --- |
| Scenario catalog | `72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87` |
| Feature schema | `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114` |
| Dataset content | `b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a` |
| Canonical-flow artifact | `96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac` |
| Target artifact | `90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70` |
| 39+7 feature artifact | `454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9` |
| Split manifest | `d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895` |
| Quality report | `c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4` |
| Leakage report | `2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d` |
| Training identity set | `25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7` |
| Validation identity set | `96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f` |
| Sealed-test identity set | `ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4` |

The report and helper carry the exact synthetic-demo limitation and all false
capability flags as `false`: real dataset used, UNSW-NB15 acquired, live
capture enabled, online inference allowed, model activation allowed, alert
side effects allowed, and prevention allowed.

## 5. Reproducibility evidence

Two offline helper runs produced the same stable identity:

- `identity_sha256`: `840c387ac9d44203f96259372cc05c3a50d9e67e582bc87e78cb2817392782f3`
- Canonical output SHA-256 (both runs):
  `e719711420d87ec6fc2ff886b84bdc662f8ec52f3f14bdc7e987c52c216b99bd`
- Byte comparison: `cmp` passed
- Output mode: `0600`
- Raw payloads/credentials: not included

## 6. Commands and results

### Quality and security

| Check | Result |
| --- | --- |
| Ruff lint | PASS |
| Ruff format | PASS (175 files) |
| Mypy | PASS (113 source files) |
| Bandit | PASS; 0 findings, 3 explicitly disabled existing rules |
| `pip check` | PASS |
| `pip-audit` | PASS; no known vulnerabilities (local package skipped as not on PyPI) |
| npm lint/typecheck/tests/build | PASS; 7 frontend tests |
| `npm audit --audit-level=high` | PASS; 0 vulnerabilities |
| Secret scan | PASS |
| Simulation-only scan | PASS |
| Python compileall | PASS |
| New reproducibility unit tests | PASS (4) |

The complete local test command was `.venv/bin/pytest -q`: 260 tests passed;
one pre-existing timing-sensitive WebSocket test failed once and then passed
when rerun alone. No test was disabled or altered.

The full local suite reached 260 passing tests with one timing-sensitive
pre-existing WebSocket revocation failure, the same residual documented at
Gate P3. Its targeted rerun passed (`1 passed`); no new P4 failure was found.

### Docker, health, migration, and Celery

- Final ARM64 Compose build with `--force-recreate --wait`: PASS.
- API liveness: PASS (`status=ok`, `prevention_mode=simulation`).
- API readiness: PASS (PostgreSQL and Redis `ok`).
- Dashboard: PASS (HTTP 200 on localhost-only port).
- Celery: PASS (one worker ping/pong; existing allowlisted task inventory).
- Migration downgrade `0014_post_mvp_observability -> 0013_p1_monitoring`:
  PASS; upgrade back to head: PASS.
- Disposable PostgreSQL backup/restore: PASS; restored migration head
  `0014_post_mvp_observability`. The custom-format backup SHA-256 was
  `3e867395b661d149a1e2957fe94f7aae75e4137de8e55d24e757e1293a2b3d0f`.
  A first restore attempt rejected source owner-role metadata in the disposable
  target; the safe `--no-owner --no-privileges --exit-on-error` replay then
  passed and was recorded as the supported cross-environment procedure.
- Retention/integrity regression subset: PASS (4 tests covering flow cleanup,
  age-boundary handling, synthetic cleanup, and hashed Parquet integrity).
- Compose services: API/dashboard/PostgreSQL/Redis healthy; worker/scheduler
  running with bounded settings.
- Initial default-port collision was handled by documented localhost-only
  alternate ports `18000`/`15173`; this is not a product failure.

### Image and SBOM evidence

Docker Scout was used as the documented equivalent because Trivy/Syft binaries
were unavailable. All final ARM64 images reported **0 Critical / 0 High**:

| Image | Local image digest | SBOM SHA-256 |
| --- | --- | --- |
| API | `f00e1228684d2f91435832682f7db444f8cfdb6645ddcf4b821ce7a0da7668d2` | `2dc9528dc5867762f7106883245e8bca9671e79ae7e54aae834e694fbe9f1404` |
| Migration | `47eb0f3af22e1061b294bdeb2a77ccf015326f6ee561cc73890f2ac0e6245476` | `1f48302c0364b531ee506abfa2bc9cf2d516b53d0f96c61c92f6a108880fd697` |
| Worker | `0d1e7b1dc7fd51a894e82a9be731a21143a65f8139ab1f4e1774da7d1b18e011` | `06f2391943c21d545ff2946c0547da673129e4bdd762ef42ce95571782a6d3cb` |
| Scheduler | `25f17fbf8a4c219ac9956a4a252eaf5a7946720984c994c8365618583671004b` | `74b5dd7ae4cacdcb558526f74a78c23505a17af09c94083eaf1162048743cdec` |
| Dashboard | `61a094a9dd4822069d8c74dd45ac58d6c5f858f1e1fcece5b84af0a148be1257` | `66addf6cf4d08513d6411589244dcc2922b7cff0a10b37e09b61f8b525bd52ea` |

Scout provenance resolved to the reviewed baseline and each scan reported no
vulnerable package. No credentials or dataset URLs were used.

## 7. Residuals, failures, and skips

1. The full suite retained the pre-existing WebSocket timing flake; the
   targeted rerun passed. This is a non-security residual and does not change
   session or revocation behavior.
2. Trivy and Syft executables were unavailable; Docker Scout provided the
   equivalent CVE and CycloneDX SBOM evidence. No Critical/High finding remains.
3. A harmless ONNX Runtime ARM64 CPU-vendor warning appeared during Celery
   ping; it did not affect health, task registration, or results.
4. The first migration probe used an invalid revision name and failed safely
   before the corrected downgrade/upgrade pass; no database change resulted.
5. The first disposable backup restore attempted to replay the source
   `aegis` owner role, which is intentionally absent from the generic target;
   ownership/privilege replay was disabled and the restore then passed.

No Critical or High security issue was identified. No P4 code path can access
real data, activate a model, enable online inference, mutate alert/detection/
incident/prevention state, or perform enforcement.

## 8. Acceptance status

| Criterion | Status |
| --- | --- |
| Clean ARM64 Compose start, health, bounded Celery, teardown | PASS |
| Pinned image/dependency/SBOM evidence; zero Critical/High | PASS |
| Two-run deterministic synthetic evidence comparison | PASS |
| Gate 5S-A/B/C hashes and limitation/flags unchanged | PASS |
| Backup/restore and migration round-trip | PASS |
| Isolation, resource, localhost-only posture | PASS |
| Quality, security, frontend/accessibility, secret/simulation checks | PASS; known P3 timing residual recorded |
| Documentation, recovery, retention, failure handling | PASS |
| No activation, online inference, data acquisition, or prevention | PASS |

**Gate P4 decision:** CONDITIONALLY COMPLETE — READY FOR SEPARATE REVIEW.
The only recorded residuals are non-security/tool-availability items above;
publication requires an explicit owner review and must be a separate action.

The large-file/payload scan passed. It found no PCAP, CSV payload, model, or
third-party dataset file; the only UNSW/NUSW-named results are inherited
metadata/review documents, and acquisition remains blocked.

## 9. Exact next prompt

> Review the complete uncommitted AegisAI NIDPS Gate P4 implementation and
> `docs/POST_MVP_GATE_P4_COMPLETION_REPORT.md`. Confirm that the diff contains
> only Gate P4 reproducibility, recovery, security/QA, and documentation files
> and excludes inherited Sprint 10 files. Re-run the applicable local quality,
> security, dependency/SBOM, Docker, health, migration, Celery, backup/restore,
> retention, frontend, accessibility, and simulation-only gates. Confirm the
> accepted Gate 5S-A/B/C hashes, exact limitation text, false-capability flags,
> synthetic-only boundary, and simulation-only posture remain unchanged.
>
> If no Critical or High issue remains, create one reviewed Gate P4 commit,
> push it to public `main`, run hosted CI, correct only Gate P4 CI failures,
> update this report with the final SHA and hosted CI result, and stop. Do not
> begin Gate P5, activate models, enable online inference, use real datasets,
> contact the publisher, configure live capture, add firewall/host-state
> capability, mutate alerts/detections/incidents, add prevention, or publish
> anything beyond that separately authorized commit.

Stop at this uncommitted Gate P4 completion gate. No commit or publication was
performed by this implementation.
