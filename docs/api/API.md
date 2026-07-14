# REST and WebSocket API Specification

**Status:** Sprint 1 identity/inventory and Sprint 2 ingestion/flow routes implemented; later routes remain approved design
**Base:** `/api/v1`
**Common:** authenticated unless public health; JSON; correlation ID; stable error `{code,message,correlation_id,details?}`; pagination on collections.

## Identity and administration

| Method/path | Purpose | Roles | Validation/rate/audit |
|---|---|---|---|
| POST `/auth/login` | Authenticate | Public | Strict credential schema; aggressive rate limit; audit success/failure without secret |
| POST `/auth/logout` | Revoke current credential | Authenticated | Idempotent; audit |
| GET `/auth/me` | Restore current browser session | Authenticated | Returns user and effective permission keys; no credential |
| GET `/auth/csrf` | Obtain/rotate session-bound CSRF token | Authenticated | No caching; same-origin; token contains no session secret |
| GET/POST `/users` | List/create users | System Admin | Explicit fields; pagination; audit create |
| PATCH `/users/{id}` | Status/allowed profile changes | System Admin | Concurrency check; prevent privilege mass assignment; audit |
| GET `/roles` | List roles/permissions | Admin/Auditor | Read-only |
| PUT `/users/{id}/roles` | Assign roles | System Admin | Cannot remove last required admin without safe policy; audit |
| GET/POST `/assets` | List/create assets | Analyst read; Security Admin write | Canonical address/criticality/zone; audit writes |
| GET/POST `/sensors` | List/register sensors | Security Admin | Never return stored secret; rate limit; audit |
| POST `/sensors/{id}/rotate` | Rotate credential | Security Admin | One-time display; stored SHA-256 hash only; audit |
| PATCH `/sensors/{id}` | Activate/deactivate sensor | Security Admin | Expected-version check; audit |
| PUT `/assets/{id}` | Update asset | Security Admin | Expected-version check; audit |

## Ingestion

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| POST `/ingestion/jobs` | Multipart offline upload | Security/System Admin (`ingestion:submit`) | CSRF+Origin; `source_type` plus one file; 8 MiB body/content validation; five/minute/identity; returns `202`; filename/MIME ignored; audit |
| POST `/ingestion/sensor/jobs` | Sensor upload | Active authenticated sensor | `Authorization: Sensor <id>.<secret>`; `X-Aegis-Source`; raw bounded body; sensor-type/source scope; pre/post-auth throttle; audit |
| GET `/ingestion/jobs` | Recent processing status | `telemetry:read` | `limit` 1–100; newest first; safe fields only |
| GET `/ingestion/jobs/{id}` | Processing status | `telemetry:read` | Safe error code; never returns object reference/path or exception |
| POST `/ingestion/jobs/{id}/replay` | Authorized sample replay | Security Admin | Idempotency key; bounded; audit |
| GET `/ingestion/metrics` | Aggregate ingestion state | `telemetry:read` | Accepted/rejected/duplicate counts, failed jobs, delayed pending jobs; no high-cardinality labels |
| GET `/flows` | Query normalized metadata | Analyst/Admin | Time range required, pagination, field redaction |
| GET `/flows/{id}` | Flow detail | `telemetry:read` | Canonical metadata only; no raw object reference |

`source_type` is one of `normalized`, `zeek`, `suricata`, or `pcap`. The first three accept bounded textual records; PCAP/PCAPNG is processed only by the isolated Celery worker. The API stores each upload under an opaque generated reference with SHA-256, queues only the UUID, and never executes content. Replays require an 8–128 character safe `Idempotency-Key` and are valid only for successful jobs with accepted records.

Job states are `pending`, `processing`, `succeeded`, `failed`, or `rejected`. Responses expose only `error_code`; traceback text, filenames, client MIME, and filesystem paths are excluded. Flow collection queries require timezone-aware `start`/`end`, allow at most a 31-day window, and return at most 100 rows.

## Detection, alerts, incidents

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| GET `/rules` | List versions/status | Analyst/Admin | Pagination |
| POST `/rules` | Create version | Security Admin | Definition schema; review status; audit |
| POST `/rules/{id}/activate` | Activate approved version | Security Admin | Regression evidence reference; audit |
| GET `/alerts` | Filter alerts | Analyst/Viewer scoped | Pagination/time bounds; field RBAC |
| GET `/alerts/{id}` | Evidence and history | Analyst/Viewer scoped | Redact restricted raw data |
| PATCH `/alerts/{id}/status` | Valid transition | Analyst | Expected version; state validation; audit |
| POST `/alerts/{id}/notes` | Add note | Analyst | Length/content validation; audit |
| GET/POST `/incidents` | List/create case | Analyst | Alert access validation; audit create |
| GET/PATCH `/incidents/{id}` | Review/update valid fields | Analyst | State/concurrency checks; audit |
| POST `/incidents/{id}/alerts` | Add alert | Analyst | Prevent duplicate/orphan; audit |
| POST `/incidents/{id}/timeline` | Append event/note | Analyst | Append-only semantics; audit |

## Intelligence and ML

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| GET/POST `/intelligence/indicators` | Query/import | Analyst read; Security Admin write | Type normalization, provenance, expiry required by policy; audit write |
| GET `/models` | List model metadata/status | Analyst/Admin/Auditor | No unrestricted artifact path |
| POST `/models/register` | Register candidate manifest | Security Admin | Provenance/hash/compatibility/card required; audit |
| POST `/models/{id}/activate` | Activate reviewed model | Security Admin | Evaluation evidence and rollback target; audit |
| POST `/models/{id}/rollback` | Restore prior model | Security Admin | Idempotent; audit |
| GET `/models/{id}/metrics` | Evaluation/operational metrics | Analyst/Admin | Dataset/split context required |

## Prevention simulation

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| GET `/prevention/policies` | View policy versions | Senior Analyst/Security Admin/Auditor | Read-only |
| POST `/prevention/requests` | Create simulation request | Senior Analyst | `Idempotency-Key` required; duration/rollback/evidence validated; audit |
| POST `/prevention/requests/{id}/preview` | Evaluate gates and preview | Senior Analyst | Unique preview; no executable command/network call; audit |
| POST `/prevention/requests/{id}/simulate` | Record simulated execution | Senior Analyst | `Idempotency-Key`; all gates pass; mode fixed to simulation; audit |
| POST `/prevention/executions/{id}/rollback` | Record simulated rollback | Senior Analyst | Idempotent; audit |
| GET `/prevention/requests/{id}` | Inspect lifecycle/gates | Analyst/Admin/Auditor | Sensitive target redaction by role |

No approval or real-execution route exists in the Sprints 0–9 API.

## Audit, reports, health

| Method/path | Purpose | Roles | Controls |
|---|---|---|---|
| GET `/audit/events` | Search audit | Auditor/Admin | Time range, pagination, no mutation route |
| POST `/reports` | Request report | Authorized by type | Async, validated filters, export audit, expiry |
| GET `/reports/{id}` | Status/download reference | Requester/permitted role | Short-lived access; audit download |
| GET `/health/live` | Process liveness | Public/local policy | No dependency or secret details |
| GET `/health/ready` | Readiness | Operations | Minimal PostgreSQL/Redis status |
| GET `/metrics` | Prometheus | Monitoring identity/network | Not public; no sensitive labels |

## WebSocket

`/ws/v1/alerts` authenticates before upgrade, authorizes subscription scope, sends minimal alert summaries plus event IDs, bounds per-client queues, uses heartbeat/reconnect semantics, and closes slow clients. Detailed evidence is fetched through REST with current authorization.

## Error and rate-limit policy

Use 400 schema, 401 unauthenticated, 403 unauthorized, 404 non-disclosing absence, 409 state/idempotency conflict, 413 size, 415 format, 422 semantic validation, 429 limit, 503 dependency/degraded. Authentication defaults are 10 login attempts per IP per 300 seconds and account lockout for 15 minutes after 5 failed attempts. Ingestion defaults are five submissions per identity per 60 seconds, an 8 MiB upload, 10,000 records, 5,000 unique PCAP flows, and a 120-second processing limit.

## Cookie-session and CSRF policy

The browser receives only an opaque session identifier in a `Secure`, `HttpOnly`, `SameSite=Lax`, path-scoped cookie. The server rotates session identity at authentication and privilege changes, enforces idle and absolute expiry, and supports immediate revocation. Unsafe methods require a session-bound CSRF token in a custom header and a valid same-origin `Origin` value. CORS is disabled by default or restricted to the exact Vite origin in development; credentials are never allowed with wildcard origins.
