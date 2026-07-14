# PostgreSQL Data Design

**Status:** Logical design only; no database or migrations created

## Conventions

- UUID primary keys; UTC `timestamptz`; snake_case names.
- `created_at`, `updated_at`, and optimistic `version` where mutable.
- Enumerations enforced through validated text/check constraints or lookup tables with controlled migrations.
- Foreign keys default to restrict for evidence/audit lineage; business records are archived rather than cascade-deleted.
- Large raw files and model binaries are not stored in Git; database rows store controlled references, hashes, sizes, and metadata.
- Sensitive fields are minimized and classified; secrets are hashed/encrypted rather than stored as readable values.

## Identity and inventory

| Table | Key columns and constraints | Index/retention/sensitivity |
|---|---|---|
| users | id, email unique normalized, password_hash, status, failed_count, locked_until, last_login_at | email index; restricted; retain audit references |
| roles | id, name unique, description | controlled reference |
| permissions | id, action+resource unique | controlled reference |
| user_roles | user_id+role_id unique FK | authorization-critical |
| role_permissions | role_id+permission_id unique FK | authorization-critical |
| sessions | id, user_id, session_id_hash unique, csrf_secret_hash/derivation metadata, idle_expires_at, absolute_expires_at, revoked_at, rotated_from_id, safe client metadata | expiry/revocation index; restricted; opaque cookie value is never stored plaintext |
| sensors | id, name unique, type, credential_hash, status, schema_version, last_seen_at | restricted credential; status index |
| assets | id, canonical_address/name, zone, owner, criticality, internal flag, status | unique canonical identity; policy-critical |

## Ingestion and telemetry

| Table | Key columns and constraints | Notes |
|---|---|---|
| ingestion_jobs | id, source_type, status, object_ref, sha256, size, schema_version, submitted_by/sensor_id, correlation_id, error_code | one actor required; bounded safe error; lifecycle indexes |
| processed_events | source_id+event_key+schema_version unique, processed_at | idempotency ledger |
| flows | id, event_key, sensor_id, event_time, src/dst address/port, protocol, counters, state, metadata JSONB, schema_version, job_id | indexes on event_time, endpoints, sensor; partitioning reviewed later |
| raw_event_refs | id, flow_id/job_id, controlled_ref, sha256, expires_at | restricted; no arbitrary path; short retention |

## Detection and ML

| Table | Key columns and constraints | Notes |
|---|---|---|
| rule_versions | id, rule_key, version, type, definition_hash, enabled, created_by; unique key+version | immutable version records |
| detection_signals | id, flow/window ref, source_type, category, score, confidence, evidence JSONB, rule_version_id/model_version_id, event_time | exactly applicable version refs validated by service/check |
| feature_schema_versions | id, name+version unique, ordered_definition, hash, status | immutable |
| dataset_versions | id, name+version unique, source, license, sha256, manifest, split_manifest | controlled metadata, no raw data in DB/Git |
| model_versions | id, name+version unique, algorithm, artifact_ref, sha256, dataset_version_id, feature_schema_version_id, runtime, status, card_ref | activation permission/audit; one active per purpose via partial unique index |
| model_metrics | id, model_version_id, split, metric_name, class_label, value, context | unique metric identity where practical |
| predictions | id, flow_id, model_version_id, feature_schema_version_id, class, probabilities, latency_ms, created_at | traceable; retention configurable |
| anomaly_scores | id, flow/window ref, model_version_id, score, threshold_version, explanation | never sole prevention evidence |

## Intelligence, alerts, and incidents

| Table | Key columns and constraints | Notes |
|---|---|---|
| intelligence_sources | id, name unique, trust_level, terms, enabled | provenance |
| indicators | id, type, normalized_value_hash/value policy, source_id, confidence, first/last_seen, expires_at | normalized unique by type/value/source/time; expiry index |
| indicator_matches | id, indicator_id, flow/alert ref, matched_at, state | preserves provenance |
| alerts | id, fingerprint, first/last_seen, severity, confidence, risk_score check 0–100, category, status, assignee, assessment_version, created_at | fingerprint/suppression indexes; valid transition service/DB guard |
| alert_evidence | id, alert_id, signal_id/ref, evidence_type, payload, occurred_at | restrict deletion; no secret/raw payload by default |
| alert_notes | id, alert_id, author_id, body, created_at, edited_at | sanitize/display safely; audit edits |
| incidents | id, title, severity, status, owner_id, opened/closed timestamps, root_cause, containment, recovery, version | closure requirements; status index |
| incident_alerts | incident_id+alert_id unique | no orphan by restricted FK |
| incident_timeline | id, incident_id, event_type, actor_id, occurred_at, body/ref | append-oriented |

## Prevention simulation

| Table | Key columns and constraints | Safety invariant |
|---|---|---|
| prevention_policy_versions | id, name+version unique, definition, hash, status, created_by | immutable and audited |
| allowlist_entries | id, target_type/value, scope, reason, starts_at, expires_at nullable by policy, created_by | policy-critical and audited |
| prevention_requests | id, idempotency_key unique, alert/incident ref, action_type, target_type/value, reason, requested_by, policy_version_id, duration_seconds >0, expires_at not null, rollback_plan not null, status | permanent action type prohibited; expiry mandatory |
| policy_gate_results | request_id+gate_key unique, passed, reason_code, evidence_ref | complete deterministic decision evidence |
| prevention_previews | id, request_id unique, adapter=`simulation`, representation, validated_at | representation is data, never executable command |
| prevention_executions | id, request_id unique, mode check=`simulation`, started/completed, result | unique prevents duplicate; no real adapter |
| prevention_rollbacks | id, execution_id unique, requested_at, completed_at, result | simulated lifecycle evidence |

## Operations

| Table | Key columns and constraints | Notes |
|---|---|---|
| audit_events | id, occurred_at, actor_type/id, action, resource_type/id, outcome, correlation_id, before_hash/after_hash, safe_metadata | append-oriented; no update/delete application permission; long retention |
| configuration_versions | id, key, version, value/safe_ref, sensitivity, status, created_by | secrets stored as references, not values |
| notifications | id, user_id, type, resource_ref, read_at, created_at | bounded retention |
| report_jobs | id, type, status, requested_by, params, output_ref, expires_at, error_code | RBAC and export audit |
| retention_runs | id, policy_version, started/completed, counts, outcome | audit retention behavior |

## State constraints

- Alert transitions follow: New → Acknowledged/Investigating; Investigating → Confirmed malicious/False positive; confirmed → Contained/Resolved; resolved/false positive → Closed, with controlled reopen behavior.
- Prevention requests cannot reach `simulated` unless all mandatory gates pass and a preview exists.
- `duration_seconds` and `expires_at` are required; permanent actions are rejected.
- An execution has exactly one request; request idempotency key and execution request ID are unique.
- Alerts and predictions must reference immutable rule/model/feature versions when those sources contribute.
- Audit records are not cascade-deleted.

## Proposed migration order

1. Identity/reference tables.
2. Assets and sensors.
3. Ingestion jobs and telemetry.
4. Version registries and detection signals.
5. Intelligence.
6. Alerts/evidence/notes.
7. Incidents/timeline.
8. Prevention policies/allowlists/requests/gates/previews/simulation records.
9. Audit/configuration/notifications/reports/retention.
10. Performance indexes/partitioning only after measured query/load evidence.

Every migration requires forward/rollback review, existing-data compatibility, lock-risk analysis, and preservation of audit/model/prevention lineage.
