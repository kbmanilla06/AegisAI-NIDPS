# REST and WebSocket API Specification

**Status:** Sprint 1 identity/inventory, Sprint 2 ingestion/flow, Sprint 3 detection, and Sprint 4 feature/dataset metadata routes implemented; later workflow routes remain approved design
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
| GET `/rules` | List active/all rule versions | `rules:read` | `active_only`; immutable definition hash and lifecycle metadata |
| GET `/rules/{rule_key}/versions` | List one rule's history | `rules:read` | newest version first |
| POST `/rules/{rule_key}/versions` | Create draft version | `rules:write` | CSRF+Origin; closed evaluator registry; strict parameters; complete definition SHA-256; audit |
| POST `/rule-versions/{id}/review` | Approve/reject draft | `rules:review` | reason and regression-evidence reference; audit |
| POST `/rule-versions/{id}/activate` | Activate approved version | `rules:activate` | expected active version; transactional replacement; audit |
| POST `/rules/{rule_key}/deactivate` | Deactivate a rule | `rules:activate` | expected active version; reason; audit |
| POST `/rules/{rule_key}/rollback` | Restore approved version | `rules:activate` | target and expected active versions; audit |
| GET `/detection/metrics` | Aggregate run/signal/alert counts | `detections:read_metrics` | bounded aggregate; no sensitive labels |
| GET `/detection/runs` | List run status | `detections:read_metrics` | limit 1–100; optional `source_job_id` |
| GET `/detection/runs/{id}` | Inspect one run | `detections:read_metrics` | safe status/error only |
| GET `/alerts` | List new alerts | `alerts:read` | limit 1–100; endpoint fields redacted without sensitive permission |
| GET `/alerts/{id}` | Alert plus bounded evidence | `alerts:read` | `alerts:read_sensitive` controls endpoint evidence; no internal exception/path |
| PATCH `/alerts/{id}/status` | Valid transition | Analyst | Expected version; state validation; audit |
| POST `/alerts/{id}/notes` | Add note | Analyst | Length/content validation; audit |
| GET/POST `/incidents` | List/create case | Analyst | Alert access validation; audit create |
| GET/PATCH `/incidents/{id}` | Review/update valid fields | Analyst | State/concurrency checks; audit |
| POST `/incidents/{id}/alerts` | Add alert | Analyst | Prevent duplicate/orphan; audit |
| POST `/incidents/{id}/timeline` | Append event/note | Analyst | Append-only semantics; audit |

The PATCH/note/incident routes in the final rows are deferred to Sprint 8 and do not exist in Sprint 3. Sprint 3 alerts remain status `new`; there is no assignment, disposition, incident, model, risk, confidence, or prevention action.

## Intelligence and ML

### Sprint 4 feature and dataset metadata

| Method/path | Purpose | Permission | Controls |
|---|---|---|---|
| GET `/feature-schemas` | List schema metadata | `features:read` | Bounded list; no raw vectors |
| GET `/feature-schemas/{id}` | Inspect immutable definition | `features:read` | Definition/hash/review provenance |
| POST `/feature-schemas/{id}/review` | Approve or retire | `features:review` | Security Administrator only; CSRF+Origin; reason/evidence; audit |
| POST `/feature-jobs` | Materialize successful ingestion flows | `features:materialize` | Approved schema; 1–10,000 rows; actor idempotency; UUID-only Celery task; audit |
| GET `/feature-jobs` and `/{id}` | Inspect safe status/artifact metadata | `features:read` | No object ref, path, vector, or raw endpoint output |
| GET `/datasets` and `/{id}` | Inspect dataset governance metadata | `datasets:read` | No payload/file path |
| POST `/datasets` | Record metadata-only proposal | `datasets:manage` | Acquisition/files rejected; CSRF+Origin; audit |
| POST `/datasets/{id}/review` | Accept/retire metadata | `datasets:manage` | Security Administrator only; no acquisition side effect; audit |

Feature jobs accept only flows from one succeeded ingestion job, order by `(event_time,event_key)`, write an opaque controlled Parquet artifact, and expose SHA-256/shape/expiry metadata. They do not train, load, score, or register a model.

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

`/ws/v1/alerts` requires an exact allowed Origin, an unexpired opaque cookie session, and `alerts:read` before upgrade, then rechecks session expiry/revocation, user state, and permission at most every 15 seconds. It sends only `connected`, heartbeat, and minimal `{event,alert_id,sequence}` notifications. Each client has a 100-message queue; a slow client is closed with retry-later semantics. Detailed evidence is fetched through REST under current authorization, and 30-second UI polling is the fallback.

## Error and rate-limit policy

Use 400 schema, 401 unauthenticated, 403 unauthorized, 404 non-disclosing absence, 409 state/idempotency conflict, 413 size, 415 format, 422 semantic validation, 429 limit, 503 dependency/degraded. Authentication defaults are 10 login attempts per IP per 300 seconds and account lockout for 15 minutes after 5 failed attempts. Ingestion defaults are five submissions per identity per 60 seconds, an 8 MiB upload, 10,000 records, 5,000 unique PCAP flows, and a 120-second processing limit.

## Cookie-session and CSRF policy

The browser receives only an opaque session identifier in a `Secure`, `HttpOnly`, `SameSite=Lax`, path-scoped cookie. The server rotates session identity at authentication and privilege changes, enforces idle and absolute expiry, and supports immediate revocation. Unsafe methods require a session-bound CSRF token in a custom header and a valid same-origin `Origin` value. CORS is disabled by default or restricted to the exact Vite origin in development; credentials are never allowed with wildcard origins.
