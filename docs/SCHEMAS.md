# Canonical Contract Schemas

**Status:** Conceptual v1; exact JSON Schema/OpenAPI definitions are Sprint implementation work

## Common envelope

All internal records include `id`, `schema_version`, `occurred_at` or `created_at`, `correlation_id`, `source`, and provenance. Timestamps are UTC ISO-8601; IP addresses use canonical textual representation; ports are integers 0–65535; unknown is distinct from zero.

## Canonical telemetry event v1

Required: event ID/key, event time, ingest time, sensor/source, source/destination address, protocol, direction or unknown, schema version, provenance. Optional by protocol: ports, packet/byte counts, duration, TCP flags/state, DNS/HTTP/TLS metadata, source-native reference. Payload content is excluded by default.

Validation rules: finite non-negative counts; bounded metadata; known protocol vocabulary plus explicit `other`; no ground-truth attack label in serving record; deterministic event fingerprint.

## Feature vector v1

Required: flow/window identity, event cutoff time, ordered feature schema version/hash, preprocessing version, numeric/categorical encoded values, missingness indicators where defined. Labels are stored only in training examples outside the serving vector.

Candidate feature groups: duration, protocol/ports, forward/backward packet/byte counts, packet-size/inter-arrival statistics, TCP state/flags, rates, direction ratios, connection failure/frequency/burst windows, and privacy-limited DNS/HTTP/TLS metadata.

## Detection signal v1

Fields: signal ID, source type (`signature`, `behavioral_rule`, `supervised_ml`, `anomaly`, `intelligence`), category, score, confidence, severity suggestion, evidence references, event/window time, detector/rule/model/threshold version, uncertainty, and human-readable rationale.

## Decision assessment v1

Fields: assessment version, contributing signal IDs, asset context version, risk score 0–100, confidence 0–1, severity, category, uncertainty/reason codes, recommended analyst action, prevention recommendation, and `automation_eligible=false` for MVP.

## Alert v1

Fields: alert ID/fingerprint, first/last seen, endpoints/protocol, risk/confidence/severity/category, status, assignee, MITRE mappings with provenance, evidence IDs, rule/model/feature/assessment versions, intelligence matches, prevention recommendation/status, notes/history links.

## Incident v1

Fields: incident ID, title, severity, status, owner, alert IDs, timeline, evidence references, containment, recovery, root cause, opened/closed times, concurrency version, and audit link.

## Prevention request v1

Fields: request ID, idempotency key, related alert/incident, action/target type and value, reason, requester, policy version, requested duration, mandatory expiration, rollback plan, evidence IDs, gate results, preview, mode=`simulation`, lifecycle status, and audit links.

Prohibited: permanent duration, shell command as executable input, missing rollback metadata, real adapter mode, model/anomaly-only eligibility.

## Versioning policy

- Additive optional fields may be backward-compatible within a major schema.
- Required-field removal, meaning/type change, or ordering change creates a new major version.
- Consumers declare supported versions and fail safely on incompatibility.
- Stored alerts preserve the versions that produced them; re-evaluation creates a new assessment rather than rewriting history.
