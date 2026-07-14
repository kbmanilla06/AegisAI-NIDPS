# Local Development and Deployment Strategy

**Status:** Sprint 2 local ingestion foundation implemented and verified; publication pending

## MVP topology

Docker Compose runs a React/Vite dashboard, FastAPI API, Celery worker, Celery Beat scheduler, PostgreSQL, and Redis. PostgreSQL and Redis are isolated on the internal data network; the API and dashboard bind only to localhost. Uploaded files use a controlled named volume outside Git under opaque generated references; PostgreSQL stores the reference, SHA-256, detected media type, byte size, and expiry. Raw data is removed after successful processing or by 24 hours, and normalized flows are removed after 30 days. No model loader exists.

Celery accepts JSON-serialized task envelopes containing only a bounded job UUID; pickle serialization and untrusted object deserialization are disabled. The ingestion queue uses late acknowledgements, one-message prefetch, a 120-second soft limit, a 135-second hard limit, and two bounded retries. Beat schedules hourly raw cleanup and daily flow/ledger cleanup. Redis is a broker/coordination dependency, not authoritative state.

## Environment separation

- `development`: synthetic fixtures; debug tooling without sensitive output; simulation fixed.
- `test`: isolated databases/queues; deterministic fixtures; simulation fixed.
- `demo`: sanitized/public data; restricted accounts; simulation fixed.
- No production or enforcement environment is defined in Sprints 0–9.

## Container security requirements

Non-root users, minimal pinned base images, read-only filesystem where practical, explicit writable volumes, health checks, resource limits, no Docker socket, no privileged mode, no host network, no added firewall capability, private DB/Redis, secret references, and image scanning/SBOM in CI.

Sprint 2 runtime limits are: API 384 MiB/1 CPU/128 PIDs, worker 384 MiB/0.75 CPU/128 PIDs, and scheduler 128 MiB/0.25 CPU/64 PIDs. Each runs as `aegis`, drops all Linux capabilities, and uses a read-only root filesystem. API and worker images pre-create the upload directory as the unprivileged runtime user with mode `0700`; only their controlled artifact volume is writable.

## Configuration

Typed startup validation; safe defaults; environment-specific non-secret templates; secrets through local ignored files or platform storage; no secret values in images, Compose, logs, reports, or frontend. Prevention mode is not a permissive string—MVP code supports simulation only.

## CI design

Protected branches and PR checks for formatting, lint, types, unit/integration, migrations, secrets, SAST, dependencies, container build/scan, frontend checks, and documentation links. Workflow permissions are least privilege; third-party actions are pinned; forked PRs receive no secrets; deployment is manual/approval-gated.

## Persistence and recovery

PostgreSQL is authoritative. Redis data is disposable/derivable. Storage locations, ownership, retention, backup, restore, and migration rollback are documented before persistent demo data is relied on. Backup creation alone is not proof; a clean restore test is required in Sprint 13.

## Observability

Structured JSON logs with correlation IDs, safe error codes, health/live and health/ready, queue and processing metrics, and later Prometheus/Grafana. No packet payload, credential, token, unrestricted address list, or high-cardinality unbounded value enters logs/metric labels.

## Clean-start evidence

Sprint 1 was verified in an isolated Compose project with a fresh PostgreSQL volume. Migration `0001_sprint1_identity` upgraded, downgraded to base, and upgraded again successfully. PostgreSQL, Redis, API, worker, and dashboard reached healthy/running state; liveness reported simulation mode and readiness reported PostgreSQL/Redis healthy. The interactive bootstrap CLI created the first System Administrator without accepting a password through command arguments or environment variables, and a real API login persisted one hashed server-side session and safe audit records.

Sprint 2 was verified in isolated Compose projects with fresh PostgreSQL and artifact volumes. Migration `0002_sprint2_ingestion` upgraded, downgraded to `0001_sprint1_identity`, and re-upgraded. The six-service stack started; API readiness reported PostgreSQL/Redis `ok`; dashboard returned HTTP 200; Celery ping passed. A normalized upload accepted two out-of-order records, deleted its raw object, and an authorized replay completed as two duplicates. Repeated worker tasks succeeded after explicit per-task async-engine disposal. No live capture or network enforcement capability was present.

## Deferred decisions

Safe model serialization must be approved before Sprint 5. TLS termination for any non-local demo, dependency update policy, and backup location are operational decisions for their owning sprints. They do not authorize exposing the current development stack beyond localhost.
