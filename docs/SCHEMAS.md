# Canonical Contract Schemas

**Status:** Canonical flow v1, Sprint 3 detection, and Sprint 4 feature/dataset manifest contracts implemented; later model, assessment, incident, and prevention contracts remain conceptual

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
- Suricata EVE handles event shapes explicitly. `event_type=flow` maps to canonical flow v1. `event_type=alert` maps to canonical signature event v1. Other event types are controlled rejections and are never coerced into a uniform record.
- PCAP/PCAPNG is parsed offline and aggregated by directional packet tuple into bounded flow metadata. Packet payload content is never persisted.

## Feature and dataset contracts v1

`FeatureSchemaV1` is immutable and strict. It fixes canonical input schema `1`, 39 ordered features, 60/300-second event-time windows, vocabularies, missing/unseen policy, leakage denylist, code version, and a canonical SHA-256 definition hash. Any semantic/order/window/vocabulary change requires a new schema version.

`FeatureVectorV1` contains schema hash, input event key as provenance, cutoff, source snapshot hash, ordered typed values, quality flags, vector hash, and creation provenance. Raw endpoint identities, timestamps, sensor/job IDs, labels, alerts, rule results, and dataset partition fields never enter `values`.

`DatasetManifestV1`, `SplitManifestV1`, `VocabularyManifestV1`, and `PreprocessorManifestV1` reject unknown fields and bind source terms, files/hashes, split/grouping strategy, train-only fitting evidence, and feature-schema compatibility. Sprint 4 has no accepted dataset, split, fitted production preprocessor, model, or prediction.

The authoritative feature order and semantics are in `docs/features/FEATURE_DICTIONARY_V1.json` and its analyst-readable Markdown companion.

## Canonical signature event v1

`CanonicalSignatureEventV1` is immutable and rejects extras. It requires schema `signature-event/v1`, source `suricata`, timezone-aware UTC event time, canonical IP addresses, paired optional ports, bounded lowercase protocol, signature ID, revision, 1–255 category, and severity 1–255. Optional sensor and source-event IDs are bounded. Payload bytes, arbitrary EVE metadata, filenames, paths, and exception text are prohibited. The stable event key hashes the sorted normalized contract.

## Behavioral rule v1

An immutable rule definition contains rule key, versioned schema/evaluator, strict evaluator parameters, fixed window, severity, optional MITRE mappings, evidence contract, false-positive/investigation guidance, prevention recommendation, and change rationale. SHA-256 covers every immutable definition field. Activation and review metadata are deliberately outside that hash.

## Detection signal v1

Sprint 3 fields are signal ID, source (`signature` or `behavioral_rule`), category, severity, immutable rule/signature reference, fixed window, normalized grouping, observed/threshold values where applicable, bounded evidence snapshot/hash, stable series key, stable semantic key, and run provenance. Risk, score, confidence, probability, uncertainty, model, and intelligence fields are intentionally absent until later versioned contracts.

## Decision assessment v1

Fields: assessment version, contributing signal IDs, asset context version, risk score 0–100, confidence 0–1, severity, category, uncertainty/reason codes, recommended analyst action, prevention recommendation, and `automation_eligible=false` for MVP.

## Alert v1

Sprint 3 fields are alert ID, `alert-fingerprint/v1`, source, category, severity, status=`new`, normalized grouping, optional rule/sensor reference, occurrence and evidence-overflow counts, first/last seen, and bounded evidence snapshots. Sensitive endpoint fields are presenter-redacted by permission. Risk/confidence, assignment, dispositions, incidents, intelligence, models, and prevention lifecycle are deferred.

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
