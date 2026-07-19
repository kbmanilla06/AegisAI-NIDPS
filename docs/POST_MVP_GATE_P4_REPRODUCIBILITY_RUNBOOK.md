# Gate P4 Local Reproducibility and Recovery Runbook

**Status:** Uncommitted Gate P4 evidence; local synthetic/offline use only

**Authoritative baseline:** `720c5e33960212c6f2130e4ac1fe9a1948b5fcb2`

This runbook verifies the existing AegisAI NIDPS synthetic/offline product on
an ARM64 development machine. It never downloads or reads a real dataset,
contacts the UNSW publisher, activates a model, enables online inference,
mutates alerts/detections/incidents, or performs prevention.

## Preconditions

- Use a clean local checkout of the reviewed baseline and an ARM64 host.
- Use only `.env.example` and non-secret validation values. Never paste a
  credential, cookie, token, signed URL, dataset URL, or internal path into an
  evidence file.
- Keep at least the documented protected disk reserve and do not silently raise
  Compose CPU, memory, PID, queue, or wall-clock limits.
- Use a disposable Compose project name and localhost-only ports.

## 1. Static and dependency gates

```bash
./.venv/bin/ruff check apps services tests scripts migrations
./.venv/bin/ruff format --check apps services tests scripts migrations
./.venv/bin/mypy
./.venv/bin/bandit -c pyproject.toml -r apps services
./.venv/bin/pip check
./.venv/bin/pip-audit
python scripts/check_secrets.py
python scripts/check_simulation_only.py
python -m compileall -q apps services scripts migrations
npm --prefix apps/dashboard run lint
npm --prefix apps/dashboard run typecheck
npm --prefix apps/dashboard run test -- --run
npm --prefix apps/dashboard run build
npm --prefix apps/dashboard audit --audit-level=high
```

Docker Scout is the documented equivalent when Trivy is unavailable. Scan all
five built ARM64 images and require zero Critical and zero High findings:

```bash
for image in aegisai-nidps-api aegisai-nidps-migrate aegisai-nidps-worker \
  aegisai-nidps-scheduler aegisai-nidps-dashboard; do
  docker scout cves --only-severity critical,high "${image}:latest"
  docker scout sbom --format cyclonedx \
    --output "/tmp/${image}.cdx.json" "local://${image}:latest"
  shasum -a 256 "/tmp/${image}.cdx.json"
done
```

SBOM files are temporary evidence and are removed after the review package is
recorded. They must not contain credentials, dataset bytes, model inputs, or
raw endpoint data.

## 2. Build and start a disposable ARM64 Compose project

```bash
export POSTGRES_PASSWORD=ci-validation-only
export AEGIS_API_PORT=18000
export AEGIS_DASHBOARD_PORT=15173
docker compose -p aegis-p4 up -d --build --force-recreate --wait
curl --fail --silent http://127.0.0.1:18000/api/v1/health/live
curl --fail --silent http://127.0.0.1:18000/api/v1/health/ready
curl --fail --silent --head http://127.0.0.1:15173/
```

An existing process on the default port is not a product failure; use the
documented localhost-only alternate ports above and record the safe reason.
Readiness must report PostgreSQL and Redis as healthy. Dashboard access must
return HTTP 200. Prevention must remain `simulation`.

## 3. Reproducibility evidence

The helper hashes allowlisted control/source files and records aggregate input
identities only. It does not execute commands or inspect payloads.

```bash
PYTHONPATH=apps/api:apps/worker:services \
  .venv/bin/python scripts/create_reproducibility_evidence.py \
  --project-root . --output /tmp/aegis-p4-run-a.json
PYTHONPATH=apps/api:apps/worker:services \
  .venv/bin/python scripts/create_reproducibility_evidence.py \
  --project-root . --output /tmp/aegis-p4-run-b.json
cmp /tmp/aegis-p4-run-a.json /tmp/aegis-p4-run-b.json
shasum -a 256 /tmp/aegis-p4-run-a.json /tmp/aegis-p4-run-b.json
```

The `identity_sha256`, accepted Gate 5S-A/B/C hashes, retention policy,
limitation text, and false-capability flags must match exactly. Runtime host
details and timestamps are not part of the stable identity. Output files are
created mode `0600` and contain no project path.

## 4. Migration, Celery, and bounded runtime checks

```bash
docker compose -p aegis-p4 exec -T worker \
  celery --app aegis_worker.celery_app inspect ping --timeout=10
docker compose -p aegis-p4 run --rm migrate alembic downgrade 0013_p1_monitoring
docker compose -p aegis-p4 run --rm migrate alembic upgrade head
docker compose -p aegis-p4 ps
```

The downgrade/re-upgrade must complete transactionally. Celery must report one
healthy worker, JSON-only task serialization, and only existing bounded
allowlisted task families. A failed migration, health check, task ping, or
resource preflight is `failed_closed`; do not accept partial evidence.

## 5. Isolation and resource evidence

Inspect every application container and record only aggregate posture:

- ARM64 platform and pinned image digest;
- `privileged=false`, non-root user, read-only root where supported;
- all capabilities dropped, bounded CPU/memory/PID settings;
- no host network, host filesystem, Docker socket, packet/interface access,
  firewall/host-state capability, socket/subprocess enforcement path, or public
  bind; and
- API/dashboard ports published only on `127.0.0.1`.

Do not place container IDs, host paths, environment values, credentials, or
raw logs in the report. Any unsafe posture blocks the gate.

## 6. Backup, restore, retention, and teardown

Create a disposable PostgreSQL custom-format backup, restore it into a
disposable PostgreSQL instance, and verify the migration head and aggregate
row/reference integrity. A corrupt, partial, or mismatched backup is quarantined
and rejected. Retention cleanup may delete only expired controlled evidence;
flows remain 30 days, alerts/audit 180 days, and P4 evidence 30 days. There are
no exceptional holds. Cleanup and restore actions require RBAC, reason, and
audit records.

After evidence capture:

```bash
docker compose -p aegis-p4 down -v --remove-orphans
rm -f /tmp/aegis-p4-run-a.json /tmp/aegis-p4-run-b.json \
  /tmp/aegisai-nidps-*.cdx.json
```

Only disposable P4 containers, volumes, and temporary files may be removed.
Never delete retained project evidence or inherited Sprint 10 files.

## Failure handling and review

Stop on any hash mismatch, unsafe capability, missing dependency, health or
migration failure, insufficient disk/memory, unresolved Critical/High finding,
unexpected network access, or limitation/flag omission. Record a sanitized
reason code and `not_evaluable`/`failed_closed`; never expose an exception,
path, credential, payload, or stack trace. A known timing-sensitive WebSocket
revocation test is a pre-existing P3 residual and must be rerun separately; it
does not authorize weakening the test or the session controls.

This runbook is not a production deployment procedure and does not authorize
Gate P5, Gate 10B/10C, real data, online inference, model activation, or any
prevention capability.
