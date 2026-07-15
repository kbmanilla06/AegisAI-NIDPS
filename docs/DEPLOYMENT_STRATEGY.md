# Local Development and Deployment Strategy

**Status:** Sprint 5 Phase 5A pre-acquisition gate on branch `codex/sprint-5a-pre-acquisition`; Sprint 4 baseline `72c97b15f9bb31ddb6810a397afc682893497bab` and hosted CI Run #7 passed

## MVP topology

Docker Compose runs a React/Vite dashboard, FastAPI API, Celery worker, Celery Beat scheduler, PostgreSQL, and Redis. PostgreSQL and Redis are isolated on the internal data network; the API and dashboard bind only to localhost. Uploaded files use a controlled named volume outside Git under opaque generated references; PostgreSQL stores the reference, SHA-256, detected media type, byte size, and expiry. Raw data is removed after successful processing or by 24 hours, and normalized flows are removed after 30 days. No model loader exists.

Celery accepts JSON-serialized task envelopes containing only a bounded job/run UUID; pickle serialization and untrusted object deserialization are disabled. Ingestion uses 120/135-second soft/hard limits; deterministic detection uses 60/75 seconds; feature materialization uses 120/135 seconds with 10,000 input-flow and 64 MiB output caps. Tasks use late acknowledgment, one-message prefetch, and bounded retries. Beat schedules raw, flow, detection, feature-artifact, and orphan-job cleanup/reconciliation. Redis carries work and minimal live notifications but is never authoritative state.

Sprint 5 pre-acquisition adds strict proposal contracts, append-only proposal metadata, safe RBAC/audit APIs, and an injected bounded transfer orchestrator. No concrete HTTP transport, dataset transfer Celery task, download API, model runtime, or new exposed service exists. A later exact file authorization must preserve the 5 GiB combined/2 GiB file/10 file/5 redirect/30-120 second timeout/30 minute deadline/two retry/50 GiB reserve/no-archive limits.

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

Sprint 3 was verified in disposable Compose project `aegisai-sprint3verify`. Migration `0003_sprint3_detection` upgraded from Sprint 2, downgraded, and re-upgraded. Its PostgreSQL trigger permitted activation-only changes and rejected definition mutation with the intended error. PostgreSQL/Redis/API/worker/scheduler/dashboard reached healthy state; Celery ping and registered-task inspection passed. An authenticated synthetic Suricata alert traversed the real upload and both Celery stages, produced one persisted alert, and deleted the raw object immediately. No dataset, model, live capture, privileged/host-network container, firewall capability, or enforcement dependency was introduced.

Sprint 4 verification uses disposable Compose project `aegis-sprint4-test`. Migration `0004_sprint4_features` upgraded from Sprint 3, rejected feature-definition mutation, downgraded after artifact inventory, and re-upgraded. Final stack, Celery, API/dashboard health, and synthetic materialization evidence are recorded in `docs/SPRINT_4_COMPLETION_REPORT.md`; the disposable volume is removed after verification.

## Deferred decisions

D-13 approves ONNX plus canonical JSON in principle, but exact operator/opset/runtime/native-dependency policy remains blocked until Gate 5S-B review. TLS termination for any non-local demo, dependency update policy, and backup location are operational decisions for their owning sprints. They do not authorize exposing the current development stack beyond localhost.

## Gate 5S-A verification profile

Disposable Compose project `aegisgate5sa` verified migration `0006_sprint5_synthetic_gate` through fresh upgrade, downgrade to `0005`, and re-upgrade. PostgreSQL, Redis, API, worker, scheduler, and dashboard reached healthy state; API liveness/readiness and Celery ping passed. API/worker were non-privileged, read-only, `cap_drop=ALL`, without host networking; worker limits were 384 MiB, 0.75 CPU, and 128 PIDs. The controlled `synthetic` volume path is created mode `0700`, and generated objects are mode `0600`. Exact results are in `docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md`.
