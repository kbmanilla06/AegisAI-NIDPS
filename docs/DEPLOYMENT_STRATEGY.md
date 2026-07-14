# Local Development and Deployment Strategy

**Status:** Sprint 0 local foundation implemented and verified

## MVP topology

Docker Compose runs a React/Vite dashboard, FastAPI API, Celery worker, PostgreSQL, and Redis. PostgreSQL and Redis are isolated on the internal data network; the API and dashboard bind only to localhost. Monitoring components may be added when their sprint arrives. Uploaded files/artifacts use a controlled named volume outside Git; the approved design requires PostgreSQL to store opaque references and SHA-256 hashes when artifact records are implemented. No model loader exists.

Celery accepts JSON-serialized task envelopes containing only bounded IDs and metadata; pickle serialization and untrusted object deserialization are disabled. Redis is a broker/coordination dependency, not authoritative state.

## Environment separation

- `development`: synthetic fixtures; debug tooling without sensitive output; simulation fixed.
- `test`: isolated databases/queues; deterministic fixtures; simulation fixed.
- `demo`: sanitized/public data; restricted accounts; simulation fixed.
- No production or enforcement environment is defined in Sprints 0–9.

## Container security requirements

Non-root users, minimal pinned base images, read-only filesystem where practical, explicit writable volumes, health checks, resource limits, no Docker socket, no privileged mode, no host network, no added firewall capability, private DB/Redis, secret references, and image scanning/SBOM in CI.

## Configuration

Typed startup validation; safe defaults; environment-specific non-secret templates; secrets through local ignored files or platform storage; no secret values in images, Compose, logs, reports, or frontend. Prevention mode is not a permissive string—MVP code supports simulation only.

## CI design

Protected branches and PR checks for formatting, lint, types, unit/integration, migrations, secrets, SAST, dependencies, container build/scan, frontend checks, and documentation links. Workflow permissions are least privilege; third-party actions are pinned; forked PRs receive no secrets; deployment is manual/approval-gated.

## Persistence and recovery

PostgreSQL is authoritative. Redis data is disposable/derivable. Storage locations, ownership, retention, backup, restore, and migration rollback are documented before persistent demo data is relied on. Backup creation alone is not proof; a clean restore test is required in Sprint 13.

## Observability

Structured JSON logs with correlation IDs, safe error codes, health/live and health/ready, queue and processing metrics, and later Prometheus/Grafana. No packet payload, credential, token, unrestricted address list, or high-cardinality unbounded value enters logs/metric labels.

## Clean-start evidence

From the new local repository, `POSTGRES_PASSWORD=validation-only docker compose up --build --wait` created the two networks, two named volumes, built the three application images, and brought all five services to healthy/running state. The API liveness/readiness endpoints, dashboard HTTP response/security headers, and Celery worker ping passed. Migrations, bootstrap accounts, and fixtures are Sprint 1 or later work and therefore were not invented for this foundation.

## Deferred decisions

Safe model serialization must be approved before Sprint 5. TLS termination for any non-local demo, dependency update policy, and backup location are operational decisions for their owning sprints. They do not authorize exposing the current development stack beyond localhost.
