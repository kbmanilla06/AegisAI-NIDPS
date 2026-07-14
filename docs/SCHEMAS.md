# Canonical Contract Schemas

**Status:** Canonical telemetry flow v1 implemented; later contracts remain conceptual

## Common envelope

All internal records include `id`, `schema_version`, `occurred_at` or `created_at`, `correlation_id`, `source`, and provenance. Timestamps are UTC ISO-8601; IP addresses use canonical textual representation; ports are integers 0–65535; unknown is distinct from zero.

## Canonical telemetry flow v1

The implemented contract is `CanonicalFlowV1` in `services/aegis_services/ingestion/schema.py`. Unknown fields are rejected and instances are immutable after validation.

| Field | Type/rules |
|---|---|
| `schema_version` | Required literal `"1"` |
| `source_type` | `normalized`, `zeek`, `suricata`, or `pcap` |
| `source_event_id` | Optional string, 1–128 characters |
| `event_time` | Required timezone-aware timestamp; normalized to UTC |
| `src_address`, `dst_address` | Required valid IPv4/IPv6; canonicalized |
| `src_port`, `dst_port` | Both absent or both integers 0–65535 |
| `protocol` | Lowercase alphanumeric string, 1–16 characters |
| `duration_ms` | Integer 0–604,800,000 |
| `packet_count`, `byte_count` | Non-negative signed 64-bit integers |
| `state` | Optional 0–32 character safe token |
| `metadata` | At most 12 safe-key scalar fields; strings at most 128 characters |

Payload bytes, filenames, MIME declarations, labels, detection results, and internal paths are excluded. The stable event key is SHA-256 over the sorted canonical JSON plus the authenticated sensor identity (or null for an authorized user upload). The key and schema version are unique in both the processed-event ledger and flow store, giving deterministic duplicate handling independent of arrival order.

### Source mappings

- Normalized JSONL maps field-for-field and forbids extras.
- Zeek TSV uses declared `#fields`/`#types`; Zeek JSON uses strict connection fields. `ts`, `id.orig_h/p`, `id.resp_h/p`, `proto`, `duration`, `orig_pkts`/`resp_pkts`, `orig_bytes`/`resp_bytes`, `conn_state`, and optional `uid` map to the canonical fields.
- Suricata EVE accepts only `event_type=flow`; it maps `timestamp`, endpoint IP/ports, `proto`, `flow.age`, packet/byte counters, `flow.state`, and optional `flow_id`. Other EVE event shapes are rejected, not coerced into flows.
- PCAP/PCAPNG is parsed offline and aggregated by directional packet tuple into bounded flow metadata. Packet payload content is never persisted.

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
- Canonical flow v1 is a major contract. Any required-field/type/meaning change creates v2; adapters must explicitly select a supported version.
