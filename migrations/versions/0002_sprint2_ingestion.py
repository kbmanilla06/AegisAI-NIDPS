"""Create Sprint 2 telemetry ingestion and canonical flow tables."""

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0002_sprint2_ingestion"
down_revision: str | None = "0001_sprint1_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION_IDS = {
    "telemetry:read": "10000000-0000-0000-0000-000000000011",
    "ingestion:submit": "10000000-0000-0000-0000-000000000012",
    "ingestion:replay": "10000000-0000-0000-0000-000000000013",
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
    "SOC Analyst": {"telemetry:read"},
    "Senior Analyst": {"telemetry:read"},
    "Security Administrator": {
        "telemetry:read",
        "ingestion:submit",
        "ingestion:replay",
    },
    "System Administrator": set(PERMISSION_IDS),
    "Auditor": {"telemetry:read"},
}


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
        "ingestion_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("object_ref", sa.String(255)),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False, server_default="1"),
        sa.Column("submitted_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("sensor_id", sa.Uuid(), sa.ForeignKey("sensors.id", ondelete="RESTRICT")),
        sa.Column(
            "replay_of_id", sa.Uuid(), sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT")
        ),
        sa.Column("idempotency_key", sa.String(128)),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("accepted_records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("raw_expires_at", sa.DateTime(timezone=True)),
        sa.Column("raw_deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "source_type IN ('normalized','zeek','suricata','pcap')",
            name="ck_ingestion_jobs_source_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','rejected')",
            name="ck_ingestion_jobs_status",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_ingestion_jobs_size"),
        sa.CheckConstraint("accepted_records >= 0", name="ck_ingestion_jobs_accepted"),
        sa.CheckConstraint("rejected_records >= 0", name="ck_ingestion_jobs_rejected"),
        sa.CheckConstraint("duplicate_records >= 0", name="ck_ingestion_jobs_duplicate"),
        sa.CheckConstraint(
            "(submitted_by IS NOT NULL) <> (sensor_id IS NOT NULL)",
            name="ck_ingestion_jobs_one_actor",
        ),
        sa.UniqueConstraint(
            "submitted_by", "idempotency_key", name="uq_ingestion_jobs_actor_idempotency"
        ),
    )
    for column in (
        "source_type",
        "status",
        "submitted_by",
        "sensor_id",
        "replay_of_id",
        "correlation_id",
        "created_at",
        "raw_expires_at",
    ):
        op.create_index(f"ix_ingestion_jobs_{column}", "ingestion_jobs", [column])

    op.create_table(
        "processed_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("event_key", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column(
            "job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("processed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("event_key", "schema_version", name="uq_processed_event_identity"),
    )
    op.create_index("ix_processed_events_job_id", "processed_events", ["job_id"])
    op.create_index("ix_processed_events_processed_at", "processed_events", ["processed_at"])

    op.create_table(
        "flows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("event_key", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False, server_default="1"),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("source_event_id", sa.String(128)),
        sa.Column(
            "job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sensor_id", sa.Uuid(), sa.ForeignKey("sensors.id", ondelete="RESTRICT")),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_address", sa.String(45), nullable=False),
        sa.Column("dst_address", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("duration_ms", sa.BigInteger(), nullable=False),
        sa.Column("packet_count", sa.BigInteger(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(32)),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("event_key", "schema_version", name="uq_flows_event_identity"),
        sa.CheckConstraint(
            "src_port IS NULL OR src_port BETWEEN 0 AND 65535", name="ck_flows_src_port"
        ),
        sa.CheckConstraint(
            "dst_port IS NULL OR dst_port BETWEEN 0 AND 65535", name="ck_flows_dst_port"
        ),
        sa.CheckConstraint("duration_ms >= 0", name="ck_flows_duration"),
        sa.CheckConstraint("packet_count >= 0", name="ck_flows_packets"),
        sa.CheckConstraint("byte_count >= 0", name="ck_flows_bytes"),
    )
    for column in (
        "job_id",
        "sensor_id",
        "event_time",
        "created_at",
        "src_address",
        "dst_address",
        "protocol",
    ):
        op.create_index(f"ix_flows_{column}", "flows", [column])


def downgrade() -> None:
    op.drop_table("flows")
    op.drop_table("processed_events")
    op.drop_table("ingestion_jobs")

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
