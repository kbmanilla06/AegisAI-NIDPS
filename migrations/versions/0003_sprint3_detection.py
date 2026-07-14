"""Create Sprint 3 deterministic detection, rule, signal, and alert tables."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0003_sprint3_detection"
down_revision: str | None = "0002_sprint2_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION_IDS = {
    "rules:read": "10000000-0000-0000-0000-000000000021",
    "rules:write": "10000000-0000-0000-0000-000000000022",
    "rules:review": "10000000-0000-0000-0000-000000000023",
    "rules:activate": "10000000-0000-0000-0000-000000000024",
    "alerts:read": "10000000-0000-0000-0000-000000000025",
    "alerts:read_sensitive": "10000000-0000-0000-0000-000000000026",
    "detections:read_metrics": "10000000-0000-0000-0000-000000000027",
}
ROLE_IDS = {
    "Viewer": "00000000-0000-0000-0000-000000000001",
    "SOC Analyst": "00000000-0000-0000-0000-000000000002",
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
ROLE_PERMISSIONS = {
    "Viewer": {"rules:read", "alerts:read"},
    "SOC Analyst": {
        "rules:read",
        "alerts:read",
        "alerts:read_sensitive",
        "detections:read_metrics",
    },
    "Senior Analyst": {
        "rules:read",
        "alerts:read",
        "alerts:read_sensitive",
        "detections:read_metrics",
    },
    "Security Administrator": set(PERMISSION_IDS),
    "System Administrator": set(PERMISSION_IDS),
    "Auditor": {
        "rules:read",
        "alerts:read",
        "alerts:read_sensitive",
        "detections:read_metrics",
    },
}

RULE_IDS = {
    "behavior.port_scan": "20000000-0000-0000-0000-000000000001",
    "behavior.repeated_failure": "20000000-0000-0000-0000-000000000002",
    "behavior.high_connection_rate": "20000000-0000-0000-0000-000000000003",
}

DEFAULT_RULES = (
    {
        "rule_key": "behavior.port_scan",
        "name": "Port scan indicator",
        "description": (
            "Source contacted many unique destination ports on one host in a fixed window."
        ),
        "category": "reconnaissance",
        "evaluator_key": "port_scan_v1",
        "parameters": {"threshold": 20, "excluded_asset_ids": []},
        "window_seconds": 60,
        "severity": "medium",
        "false_positive_guidance": (
            "Authorized vulnerability scanners and administrative discovery."
        ),
        "investigation_guidance": "Confirm source ownership and whether discovery was authorized.",
        "prevention_recommendation": (
            "Review only; no prevention action is authorized by this rule."
        ),
    },
    {
        "rule_key": "behavior.repeated_failure",
        "name": "Repeated connection failure indicator",
        "description": (
            "Zeek reported repeated recognized connection-failure states for one service."
        ),
        "category": "connection_failure",
        "evaluator_key": "repeated_failure_v1",
        "parameters": {
            "threshold": 10,
            "excluded_asset_ids": [],
            "failure_states": ["REJ", "S0", "RSTO", "RSTR", "SH", "SHR"],
        },
        "window_seconds": 300,
        "severity": "low",
        "false_positive_guidance": (
            "Misconfiguration, unavailable services, or expired client settings."
        ),
        "investigation_guidance": (
            "Review the destination service and source configuration before escalation."
        ),
        "prevention_recommendation": "Review only; connection failure is not proof of brute force.",
    },
    {
        "rule_key": "behavior.high_connection_rate",
        "name": "High connection-rate indicator",
        "description": "Source generated many distinct canonical flows in a fixed window.",
        "category": "traffic_rate",
        "evaluator_key": "high_connection_rate_v1",
        "parameters": {"threshold": 100, "excluded_asset_ids": []},
        "window_seconds": 60,
        "severity": "medium",
        "false_positive_guidance": (
            "Proxies, monitoring, load tests, NAT gateways, and busy application clients."
        ),
        "investigation_guidance": (
            "Validate source role and compare the observed rate with expected activity."
        ),
        "prevention_recommendation": (
            "Review only; no prevention action is authorized by this rule."
        ),
    },
)


def _definition(rule: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "behavioral-rule/v1",
        **rule,
        "mitre_mappings": [],
        "evidence_contract": {
            "version": "alert-evidence/v1",
            "fields": ["group", "window", "observed", "threshold", "event_keys"],
        },
        "change_rationale": "Approved Sprint 3 initial deterministic rule.",
    }


def _hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def upgrade() -> None:
    permissions = sa.table(
        "permissions", sa.column("id", sa.Uuid()), sa.column("key"), sa.column("description")
    )
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    op.bulk_insert(
        permissions,
        [
            {"id": UUID(identifier), "key": key, "description": f"Allows {key}"}
            for key, identifier in PERMISSION_IDS.items()
        ],
    )

    op.alter_column(
        "processed_events",
        "schema_version",
        existing_type=sa.String(16),
        type_=sa.String(32),
        existing_nullable=False,
    )
    op.bulk_insert(
        role_permissions,
        [
            {
                "role_id": UUID(ROLE_IDS[role]),
                "permission_id": UUID(PERMISSION_IDS[permission]),
            }
            for role, assigned in ROLE_PERMISSIONS.items()
            for permission in sorted(assigned)
        ],
    )

    op.create_table(
        "rule_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_key", sa.String(100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("evaluator_key", sa.String(64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("mitre_mappings", sa.JSON(), nullable=False),
        sa.Column("evidence_contract", sa.JSON(), nullable=False),
        sa.Column("false_positive_guidance", sa.String(1000), nullable=False),
        sa.Column("investigation_guidance", sa.String(1000), nullable=False),
        sa.Column("prevention_recommendation", sa.String(1000), nullable=False),
        sa.Column("change_rationale", sa.String(500), nullable=False),
        sa.Column("definition_hash", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("rule_key", "version", name="uq_rule_versions_key_version"),
        sa.UniqueConstraint("definition_hash", name="uq_rule_versions_definition_hash"),
        sa.CheckConstraint(
            "lifecycle_state IN ('draft','approved','retired')",
            name="ck_rule_versions_lifecycle",
        ),
        sa.CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_rule_versions_severity",
        ),
        sa.CheckConstraint("version > 0", name="ck_rule_versions_version"),
        sa.CheckConstraint("window_seconds BETWEEN 1 AND 86400", name="ck_rule_versions_window"),
    )
    op.create_index("ix_rule_versions_rule_key", "rule_versions", ["rule_key"])
    op.create_index("ix_rule_versions_category", "rule_versions", ["category"])
    op.create_index("ix_rule_versions_is_active", "rule_versions", ["is_active"])
    op.create_index("ix_rule_versions_created_at", "rule_versions", ["created_at"])
    op.create_index(
        "uq_rule_versions_one_active",
        "rule_versions",
        ["rule_key"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )
    op.execute(
        """
        CREATE FUNCTION protect_rule_version_definition() RETURNS trigger AS $$
        BEGIN
          IF OLD.rule_key IS DISTINCT FROM NEW.rule_key
             OR OLD.version IS DISTINCT FROM NEW.version
             OR OLD.schema_version IS DISTINCT FROM NEW.schema_version
             OR OLD.name IS DISTINCT FROM NEW.name
             OR OLD.description IS DISTINCT FROM NEW.description
             OR OLD.category IS DISTINCT FROM NEW.category
             OR OLD.evaluator_key IS DISTINCT FROM NEW.evaluator_key
             OR OLD.parameters::jsonb IS DISTINCT FROM NEW.parameters::jsonb
             OR OLD.window_seconds IS DISTINCT FROM NEW.window_seconds
             OR OLD.severity IS DISTINCT FROM NEW.severity
             OR OLD.mitre_mappings::jsonb IS DISTINCT FROM NEW.mitre_mappings::jsonb
             OR OLD.evidence_contract::jsonb IS DISTINCT FROM NEW.evidence_contract::jsonb
             OR OLD.false_positive_guidance IS DISTINCT FROM NEW.false_positive_guidance
             OR OLD.investigation_guidance IS DISTINCT FROM NEW.investigation_guidance
             OR OLD.prevention_recommendation IS DISTINCT FROM NEW.prevention_recommendation
             OR OLD.change_rationale IS DISTINCT FROM NEW.change_rationale
             OR OLD.definition_hash IS DISTINCT FROM NEW.definition_hash
             OR OLD.created_by IS DISTINCT FROM NEW.created_by
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'rule version definitions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_protect_rule_version_definition
        BEFORE UPDATE ON rule_versions
        FOR EACH ROW EXECUTE FUNCTION protect_rule_version_definition()
        """
    )

    op.create_table(
        "rule_activations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_key", sa.String(100), nullable=False),
        sa.Column(
            "rule_version_id",
            sa.Uuid(),
            sa.ForeignKey("rule_versions.id", ondelete="RESTRICT"),
        ),
        sa.Column(
            "previous_rule_version_id",
            sa.Uuid(),
            sa.ForeignKey("rule_versions.id", ondelete="RESTRICT"),
        ),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("regression_evidence", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "action IN ('activate','deactivate','rollback')",
            name="ck_rule_activations_action",
        ),
    )
    op.create_index("ix_rule_activations_rule_key", "rule_activations", ["rule_key"])
    op.create_index("ix_rule_activations_rule_version_id", "rule_activations", ["rule_version_id"])
    op.create_index("ix_rule_activations_created_at", "rule_activations", ["created_at"])

    op.create_table(
        "signature_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("event_key", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column(
            "job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sensor_id", sa.Uuid(), sa.ForeignKey("sensors.id", ondelete="RESTRICT")),
        sa.Column("source_event_id", sa.String(128)),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_address", sa.String(45), nullable=False),
        sa.Column("dst_address", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("signature_id", sa.Integer(), nullable=False),
        sa.Column("signature_revision", sa.Integer(), nullable=False),
        sa.Column("signature_name", sa.String(256), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("reported_severity", sa.Integer(), nullable=False),
        sa.Column("reported_action", sa.String(32)),
        sa.Column("flow_id", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("event_key", "schema_version", name="uq_signature_event_identity"),
        sa.CheckConstraint("reported_severity BETWEEN 1 AND 255", name="ck_signature_severity"),
    )
    for column in ("job_id", "sensor_id", "event_time", "created_at"):
        op.create_index(f"ix_signature_events_{column}", "signature_events", [column])

    op.create_table(
        "detection_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "ingestion_job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("rule_set_hash", sa.String(64)),
        sa.Column("signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suppressed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ingestion_job_id", name="uq_detection_runs_ingestion_job"),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_detection_runs_status",
        ),
        sa.CheckConstraint("signal_count >= 0", name="ck_detection_runs_signals"),
        sa.CheckConstraint("alert_count >= 0", name="ck_detection_runs_alerts"),
        sa.CheckConstraint("suppressed_count >= 0", name="ck_detection_runs_suppressed"),
    )
    for column in ("ingestion_job_id", "source_job_id", "status", "created_at"):
        op.create_index(f"ix_detection_runs_{column}", "detection_runs", [column])

    op.create_table(
        "detection_signals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("semantic_key", sa.String(64), nullable=False),
        sa.Column("series_key", sa.String(64), nullable=False),
        sa.Column(
            "detection_run_id",
            sa.Uuid(),
            sa.ForeignKey("detection_runs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column(
            "rule_version_id", sa.Uuid(), sa.ForeignKey("rule_versions.id", ondelete="RESTRICT")
        ),
        sa.Column(
            "signature_event_id",
            sa.Uuid(),
            sa.ForeignKey("signature_events.id", ondelete="SET NULL"),
        ),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("sensor_id", sa.Uuid(), sa.ForeignKey("sensors.id", ondelete="RESTRICT")),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("grouping", sa.JSON(), nullable=False),
        sa.Column("observed_value", sa.BigInteger(), nullable=False),
        sa.Column("threshold_value", sa.BigInteger(), nullable=False),
        sa.Column("evidence_event_keys", sa.JSON(), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("data_quality", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("semantic_key", name="uq_detection_signals_semantic_key"),
        sa.CheckConstraint(
            "source_type IN ('behavioral_rule','suricata_signature')",
            name="ck_detection_signals_source_type",
        ),
        sa.CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_detection_signals_severity",
        ),
        sa.CheckConstraint("observed_value >= 0", name="ck_detection_signals_observed"),
        sa.CheckConstraint("threshold_value >= 0", name="ck_detection_signals_threshold"),
    )
    for column in (
        "series_key",
        "detection_run_id",
        "rule_version_id",
        "signature_event_id",
        "category",
        "severity",
        "sensor_id",
        "bucket_start",
        "created_at",
    ):
        op.create_index(f"ix_detection_signals_{column}", "detection_signals", [column])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("fingerprint_schema", sa.String(32), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        sa.Column(
            "rule_version_id", sa.Uuid(), sa.ForeignKey("rule_versions.id", ondelete="RESTRICT")
        ),
        sa.Column("sensor_id", sa.Uuid(), sa.ForeignKey("sensors.id", ondelete="RESTRICT")),
        sa.Column("grouping", sa.JSON(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("evidence_overflow_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_overflow_hash", sa.String(64)),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("fingerprint", name="uq_alerts_fingerprint"),
        sa.CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_alerts_severity",
        ),
        sa.CheckConstraint("status = 'new'", name="ck_alerts_sprint3_status"),
        sa.CheckConstraint("occurrence_count > 0", name="ck_alerts_occurrence_count"),
    )
    for column in (
        "source_type",
        "category",
        "severity",
        "status",
        "rule_version_id",
        "sensor_id",
        "first_seen",
        "last_seen",
        "created_at",
    ):
        op.create_index(f"ix_alerts_{column}", "alerts", [column])

    op.create_table(
        "alert_evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "alert_id", sa.Uuid(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "signal_id", sa.Uuid(), sa.ForeignKey("detection_signals.id", ondelete="SET NULL")
        ),
        sa.Column("evidence_snapshot", sa.JSON(), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("alert_id", "signal_id", name="uq_alert_evidence_signal"),
    )
    for column in ("alert_id", "signal_id", "occurred_at", "created_at"):
        op.create_index(f"ix_alert_evidence_{column}", "alert_evidence", [column])

    rule_versions = sa.table(
        "rule_versions",
        sa.column("id", sa.Uuid()),
        sa.column("rule_key", sa.String()),
        sa.column("version", sa.Integer()),
        sa.column("schema_version", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("category", sa.String()),
        sa.column("evaluator_key", sa.String()),
        sa.column("parameters", sa.JSON()),
        sa.column("window_seconds", sa.Integer()),
        sa.column("severity", sa.String()),
        sa.column("mitre_mappings", sa.JSON()),
        sa.column("evidence_contract", sa.JSON()),
        sa.column("false_positive_guidance", sa.String()),
        sa.column("investigation_guidance", sa.String()),
        sa.column("prevention_recommendation", sa.String()),
        sa.column("change_rationale", sa.String()),
        sa.column("definition_hash", sa.String()),
        sa.column("lifecycle_state", sa.String()),
        sa.column("is_active", sa.Boolean()),
    )
    op.bulk_insert(
        rule_versions,
        [
            {
                "id": UUID(RULE_IDS[str(rule["rule_key"])]),
                **rule,
                "version": 1,
                "schema_version": "behavioral-rule/v1",
                "mitre_mappings": [],
                "evidence_contract": {
                    "version": "alert-evidence/v1",
                    "fields": ["group", "window", "observed", "threshold", "event_keys"],
                },
                "change_rationale": "Approved Sprint 3 initial deterministic rule.",
                "definition_hash": _hash(_definition(rule)),
                "lifecycle_state": "approved",
                "is_active": True,
            }
            for rule in DEFAULT_RULES
        ],
    )


def downgrade() -> None:
    op.drop_table("alert_evidence")
    op.drop_table("alerts")
    op.drop_table("detection_signals")
    op.drop_table("detection_runs")
    op.drop_table("signature_events")
    op.drop_table("rule_activations")
    op.drop_table("rule_versions")
    op.execute("DROP FUNCTION protect_rule_version_definition()")

    op.alter_column(
        "processed_events",
        "schema_version",
        existing_type=sa.String(32),
        type_=sa.String(16),
        existing_nullable=False,
    )

    connection = op.get_bind()
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    permission_ids = [UUID(identifier) for identifier in PERMISSION_IDS.values()]
    connection.execute(
        sa.delete(role_permissions).where(role_permissions.c.permission_id.in_(permission_ids))
    )
    connection.execute(sa.delete(permissions).where(permissions.c.id.in_(permission_ids)))
