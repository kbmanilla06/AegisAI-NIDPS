# Sprint 2 Completion Report — Telemetry Ingestion and Normalization

**Date:** 2026-07-14
**Branch:** `feature/sprint-2-ingestion`
**Authorized base:** `61ef2cc9e79dbd987debc226e4349bd3cb8571a5`
**Status:** Locally complete and reviewed; publication authorized, commit and hosted CI pending

## Entry gate

Before implementation, local `HEAD` and published `origin/main` were confirmed at Sprint 1 commit `61ef2cc9e79dbd987debc226e4349bd3cb8571a5`. GitHub Actions CI Run #2 (`29312141925`) was confirmed `completed/success` for that exact SHA. The working tree was clean. The Sprint 1 completion report was then updated to preserve the publication SHA and hosted-CI result.

## Scope delivered

- Finalized immutable canonical flow schema v1 and deterministic, sensor-scoped SHA-256 event identity.
- Added synthetic fixtures before parser implementation for valid, invalid, malformed, duplicate, Unicode, truncated, oversized, out-of-order, and mixed-protocol cases. PCAP is generated in temporary tests rather than committed.
- Implemented adapters in the authorized order: normalized JSONL, strict Zeek connection TSV/JSON, Suricata EVE `flow` events without assuming other EVE shapes, then offline PCAP/PCAPNG.
- Added controlled streaming upload storage using opaque generated references, exclusive no-follow creation, mode `0600`, a `0700` parent, SHA-256, and database metadata. Client filenames and MIME declarations are ignored.
- Added user and sensor ingestion, status/list/metrics, replay, and canonical flow APIs with centralized permissions, CSRF/Origin on user writes, hashed sensor authentication, sensor source scoping, and Redis throttling.
- Added an isolated Celery ingestion queue carrying only a job UUID; JSON-only serialization, late acknowledgement, one-message prefetch, two bounded retries, soft/hard task time limits, and sanitized terminal failure handling.
- Added atomic flow plus processed-event persistence, stable duplicate handling, actor-scoped replay idempotency, safe job errors, audit events, immediate success deletion, hourly raw cleanup, and daily 30-day flow/ledger cleanup.
- Added the minimal React/Vite upload and job-status view.
- Added reversible migration `0002_sprint2_ingestion`, tests, container resource limits, and Celery Beat. Prevention remains simulation-only.

No live packet/interface capture, dataset download, model training/loading, detection rule, alert generation, real prevention adapter, privileged container, host network, firewall capability, commit, or publication was added.

## Review findings encountered during implementation

| Severity | Finding | Resolution/status |
|---|---|---|
| High | A clean named artifact volume was root-owned, so the non-root API could not create the upload directory. The public response was safe but classified as malformed input. | API/worker images now pre-create the owned `0700` upload directory. Storage unavailability returns sanitized `503`; verified with a fresh volume. Resolved. |
| High | Sequential Celery tasks reused an async SQLAlchemy pool bound to the prior `asyncio.run` event loop, leaving a replay pending with an event-loop error. | Every worker task disposes the async engine inside the same loop; processing has two bounded retries and sanitized final-failure persistence. A fresh upload and replay both succeeded sequentially. Resolved. |
| High | Flow cleanup initially used hostile source `event_time`; a future-dated record could evade the required 30-day retention indefinitely. | Retention now uses indexed, database-controlled `created_at`. A regression test proves a far-future event is deleted once its trusted ingestion age exceeds 30 days. Resolved. |
| Medium | A rejected content-mismatch object could outlive the request if deletion itself failed. | The job preserves only the opaque controlled reference and a maximum 24-hour expiry so scheduled cleanup can retry; no path is exposed. Resolved with residual reliance on scheduler health. |
| Medium | The upload directory and an existing opaque object path did not explicitly reject symlink substitution, although generated creation already used exclusive `O_NOFOLLOW`. | Upload-root creation and object resolution now reject symlinks and verify the resolved controlled parent; regression tests cover both cases. Resolved. |
| Medium | Non-finite hostile numeric values could escape selected timestamp/duration conversions and consume bounded worker retries rather than produce a controlled record rejection. | All numeric timestamps/durations and PCAP timestamps now require finite values; targeted Zeek and Suricata tests verify safe rejection. Resolved. |
| Low | A Linux Alpine frontend test container inherited macOS `node_modules`, causing a missing optional native binding. | This was a verification-environment mismatch, not an application defect. The platform-correct host dependency tree passed lint, typecheck, tests, build, and audit. |
| Low | The Redis ingestion counter set its TTL in a second command and created a client per request without deterministic closure. | Counter increment and first-expiry assignment are now one Redis transaction; the request dependency closes its client deterministically. Resolved. |

No known Critical or High issue remains after correction.

## Files created

- API ingestion boundary: `body_limits.py`, `ingestion_dispatch.py`, `ingestion_processor.py`, `ingestion_storage.py`, `ingestion_throttle.py`, `routers/ingestion.py`, and `security/sensors.py`.
- Canonical services: `services/aegis_services/ingestion/{__init__.py,schema.py,adapters.py}`.
- Database: `migrations/versions/0002_sprint2_ingestion.py`.
- Tests/fixtures: `tests/integration/test_ingestion.py`, `tests/unit/test_ingestion_adapters.py`, `tests/unit/test_ingestion_storage.py`, and `tests/fixtures/telemetry/*`.
- Documentation: this completion report.

## Files changed

- Runtime/configuration: `.env.example`, `Makefile`, both API/worker Dockerfiles, API config/main/models/schemas/permissions, Celery application, `docker-compose.yml`, and `pyproject.toml`.
- Dashboard: `App.tsx`, `App.test.tsx`, and `api.ts`.
- Existing tests: shared fixtures, worker tests, and RBAC negative matrix.
- Documentation: README, Sprint 1 completion report, backlog, decisions, database, schemas, API, architecture, threat model, test/deployment strategies, and risk register.

## Database migration

`0002_sprint2_ingestion` creates:

- `ingestion_jobs`, including one-actor, state/source, non-negative count/size, replay, idempotency, expiry, and lifecycle constraints/indexes;
- `processed_events`, unique on `(event_key, schema_version)`;
- `flows`, unique on `(event_key, schema_version)`, with port/count/duration checks and query indexes;
- permissions `telemetry:read`, `ingestion:submit`, and `ingestion:replay`, assigned to the approved roles.

Downgrade removes the three tables and only the Sprint 2 permission assignments/rows. Upgrade, downgrade to `0001_sprint1_identity`, and re-upgrade passed against PostgreSQL.

## Supported inputs and canonical mappings

| Input | Accepted shape | Mapping summary |
|---|---|---|
| Normalized | One strict canonical v1 JSON object per line | Direct field mapping; unknown fields rejected |
| Zeek | Connection TSV with `#fields`/`#types`, or strict JSON connection records | timestamp, origin/responder endpoints, protocol, duration, counters, connection state, optional UID |
| Suricata EVE | JSONL; only `event_type=flow` | timestamp, endpoints, protocol, flow age/state/counters, optional flow ID; alert/DNS/etc. shapes rejected |
| PCAP/PCAPNG | Offline capture file only | Packet headers aggregate to canonical endpoint/protocol/counter/duration metadata; payload is not stored |

All timestamps require or receive an explicit UTC interpretation from their source format; IPs are canonicalized; ports are paired and bounded; counters are non-negative; metadata is scalar and bounded. The full field contract is in `docs/SCHEMAS.md`.

## Validation and resource limits

| Control | Sprint 2 default |
|---|---|
| Raw request/upload | 8 MiB file plus 64 KiB multipart overhead; streaming hard stop |
| Records per job | 10,000 |
| Unique PCAP flows | 5,000 |
| Worker processing | 120-second soft / 135-second hard limit |
| Upload rate | 5 per authenticated identity per 60 seconds |
| Delayed metric | pending longer than 60 seconds |
| Raw retention | delete immediately after success or within 24 hours |
| Flow and event-key retention | 30 days from trusted database ingestion time, not hostile event time |
| API page/window | at most 100 rows; flow query at most 31 days |
| Containers | API 384 MiB/1 CPU/128 PIDs; worker 384 MiB/0.75 CPU/128 PIDs; scheduler 128 MiB/0.25 CPU/64 PIDs |

Archive inputs are not supported, eliminating archive paths and decompression bombs. Uploaded content is never imported, executed, passed to a shell, or opened by filename. Temporary/object paths are generated internally and validated under the controlled root.

## Commands actually run

Representative commands used for entry, implementation, and final evidence included:

```text
git status --short
git rev-parse HEAD
git ls-remote origin refs/heads/main
gh run view 29312141925
git switch -c feature/sprint-2-ingestion
docker build -f infrastructure/docker/Dockerfile.test -t aegisai-nidps-sprint2-test .
docker run ... ruff format --check apps services tests migrations
docker run ... ruff check apps services tests migrations
docker run ... mypy apps services
docker run ... pytest -q
docker run ... bandit -c pyproject.toml -r apps services
docker run ... pip-audit
docker run ... python scripts/check_secrets.py
docker run ... python scripts/check_simulation_only.py
npm --prefix apps/dashboard run lint
npm --prefix apps/dashboard run typecheck
npm --prefix apps/dashboard run test
npm --prefix apps/dashboard run build
npm --prefix apps/dashboard audit --audit-level=high
POSTGRES_PASSWORD=... docker compose config --quiet
POSTGRES_PASSWORD=... docker compose -p aegisai-sprint2verify up --build --wait
POSTGRES_PASSWORD=... docker compose -p aegisai-sprint2verify run --rm migrate alembic downgrade 0001_sprint1_identity
POSTGRES_PASSWORD=... docker compose -p aegisai-sprint2verify run --rm migrate alembic upgrade head
POSTGRES_PASSWORD=... docker compose -p aegisai-sprint2verify2 build worker scheduler
POSTGRES_PASSWORD=... docker compose -p aegisai-sprint2verify2 up -d --force-recreate worker scheduler
curl ... POST /api/v1/ingestion/jobs
curl ... GET /api/v1/ingestion/jobs/{id}
curl ... POST /api/v1/ingestion/jobs/{id}/replay
curl -fsS http://127.0.0.1:8000/api/v1/health/live
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
docker compose ... celery ... inspect ping
docker inspect ... resource/privilege/capability/read-only/user checks
git diff --check
```

Disposable credentials and database passwords were used only in ignored `/tmp` files or process-local verification input and are not recorded here or in the repository.

## Test, fuzzing, security, Docker, Celery, and health results

| Gate | Result |
|---|---|
| Ruff format/lint | Pass; 58 files checked, no lint or format findings |
| mypy | Pass; 39 source files, no issues |
| Backend unit/integration/security | Pass; 69 tests after publication-review corrections |
| Backend coverage | 74%; no project-wide threshold configured |
| Parser malformed/resource/fuzz suite | Pass as part of pytest; deterministic generated cases and all committed fixture classes handled safely |
| Six-role RBAC negative matrix | Pass, including Sprint 2 read/submit/replay permissions |
| Bandit | Pass; 0 findings across 3,029 lines |
| pip-audit | Pass; no known vulnerabilities; unpublished local package skipped |
| Secret assignment guard | Pass |
| Simulation-only guard | Pass |
| Frontend lint/type/test/build | Pass; 3 tests; production bundle built |
| Frontend coverage | 60.95% statements / 59.78% lines; no configured threshold |
| npm audit | Pass; 0 vulnerabilities |
| Compose configuration | Pass |
| PostgreSQL migration upgrade/downgrade/re-upgrade | Pass |
| Clean stack | Pass; PostgreSQL, Redis, API, and dashboard healthy; worker/scheduler running |
| Liveness/readiness/dashboard | Pass; simulation mode, PostgreSQL/Redis `ok`, dashboard HTTP 200 |
| Celery | Pass; registered worker ping; sequential upload and replay tasks succeeded |
| Real ingestion/replay | Pass; 2 accepted out-of-order records, raw deleted, replay recorded 2 duplicates |
| Container isolation | Pass; non-root `aegis`, read-only roots, all capabilities dropped, bounded memory/CPU/PIDs, non-host networks, not privileged |

One upstream Starlette test-harness deprecation warning remains (`httpx`-backed `TestClient` migration to `httpx2`); runtime is unaffected.

## Failures and skipped checks

- Three High findings were corrected and reverified: two discovered through clean real-stack verification and the hostile-timestamp retention bypass found during the publication review.
- The first final health command used `/health/*` without the documented `/api/v1` base and returned 404; the corrected URLs passed.
- The Alpine frontend verification attempt failed because it mounted the macOS optional native dependency tree. Platform-correct host checks passed; hosted Linux CI must still install from the lockfile on publication.
- Semgrep, Trivy/container vulnerability scanning, SBOM generation, OWASP ZAP, full browser E2E, accessibility automation, long-running property fuzzing, representative load/soak testing, packet-parser sandboxing beyond the bounded container, backup/restore, and non-local TLS were not configured gates and were not run. These omissions are residual hardening work, not represented as passes.

## Assumptions

- Inputs are synthetic, public, locally owned, or explicitly authorized; no real capture was used.
- Zeek input is connection-log shaped, and Suricata input uses EVE flow events. Other logs/events are intentionally rejected.
- PCAP/PCAPNG sizes suitable for this portfolio MVP fit within the 8 MiB/5,000-flow/120-second bounds.
- PostgreSQL is authoritative; Redis/queued work is recoverable coordination state.
- Local development remains localhost-only and uses an HTTPS terminator before any non-local secure-cookie demonstration.

## Residual risks

- Sensor authentication prevents forgery without the secret and duplicate identities prevent repeated persistence, but no independent timestamp replay window exists yet. A compromised sensor can submit novel hostile events within rate/resource limits.
- `dpkt` processes hostile binary formats inside a tightly limited non-root worker, not a separate seccomp/microVM parser sandbox. Broader coverage-guided fuzzing and container scanning remain advisable before untrusted public uploads.
- Rate limits are per process identity/window in Redis, but global storage quotas and queue-depth admission control are not implemented. Representative load/soak testing is deferred.
- Scheduled retention depends on Celery Beat/worker availability. Expiry is indexed and immediate success deletion works, but operational alerting and an orphan-object reconciler remain future work.
- A terminal worker failure attempts to persist a safe failed state; if PostgreSQL is also unavailable then automated reconciliation is not yet implemented.
- Canonical metadata still includes endpoint addresses and can be sensitive. The project remains local/academic; report/export privacy controls are later work.
- Dependency and base-image findings can change after this report; hosted CI and stronger image/SBOM scanning remain required publication evidence.

## Sprint 2 acceptance criteria

| Criterion | Status |
|---|---|
| Sprint 1 published SHA, hosted CI Run #2, clean entry tree confirmed | Pass |
| Sprint 1 completion documentation updated | Pass |
| Canonical schema v1 finalized/versioned | Pass |
| Fixtures precede and cover required parser cases | Pass |
| Normalized, Zeek, Suricata EVE flow, offline PCAP/PCAPNG adapters | Pass |
| Content/schema validation and hostile-upload controls | Pass |
| Size/record/flow/time/rate/container limits | Pass |
| Stable duplicate/replay behavior | Pass |
| Safe status/errors/metrics/audit | Pass |
| Reversible PostgreSQL migration | Pass |
| Minimal API/UI | Pass |
| Unit/integration/security/parser/resource/Celery/migration/Docker/health gates | Pass, with explicit deferred hardening list |
| Raw 24-hour and flow 30-day retention | Pass locally |
| Simulation-only/no prohibited capability | Pass |
| Documentation and completion report | Pass |
| Owner review | Pass; publication authorized after corrections |
| Sprint 2 commit/publication and hosted CI | Pending completion of the current gate |

## Final Sprint 2 decision

**CONDITIONALLY APPROVED.** The authorized Sprint 2 implementation is complete and locally verified with no known unresolved Critical or High finding. It remains intentionally uncommitted. Final approval requires owner review of the full diff, one authorized commit/publication, and successful hosted CI. Sprint 3 remains prohibited.

## Exact Sprint 2 review/publication prompt

```text
Review the complete uncommitted AegisAI NIDPS Sprint 2 implementation and docs/SPRINT_2_COMPLETION_REPORT.md.

Do not begin Sprint 3.

Confirm the diff remains within Sprint 2 scope and review it for Critical or High security, correctness, privacy, migration, parser, resource-limit, idempotency, Celery, retention, and authorization issues. Re-run all applicable local quality, security, migration, parser/fuzz, Docker, Celery, and health gates.

If no Critical or High issue remains:
1. Create one reviewed Sprint 2 commit.
2. Push it to the existing public GitHub repository on main.
3. Run hosted CI.
4. Correct only Sprint 2 CI failures if necessary.
5. Report the final commit SHA and hosted CI result.

Do not implement detection rules, alert generation, telemetry live capture, dataset download, model training/loading, real prevention, privileged containers, host networking, firewall integration, or any Sprint 3 functionality.

Stop after the Sprint 2 publication gate and wait for my approval.
```
