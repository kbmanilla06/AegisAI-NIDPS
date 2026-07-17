"""Add bounded synthetic observability, aggregate reports, and recovery metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0014_post_mvp_observability"
down_revision: str | None = "0013_p1_monitoring"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "observability:read": "10000000-0000-0000-0000-000000000074",
    "observability:request": "10000000-0000-0000-0000-000000000075",
    "observability:finalize": "10000000-0000-0000-0000-000000000076",
    "observability:recovery": "10000000-0000-0000-0000-000000000077",
    "observability:cleanup": "10000000-0000-0000-0000-000000000078",
}
ROLES = {
    "SOC Analyst": "00000000-0000-0000-0000-000000000002",
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
GRANTS = {
    "SOC Analyst": ("observability:read", "observability:request"),
    "Senior Analyst": ("observability:read", "observability:request"),
    "Security Administrator": tuple(PERMISSIONS.keys()),
    "System Administrator": (
        "observability:read",
        "observability:request",
        "observability:recovery",
        "observability:cleanup",
    ),
    "Auditor": ("observability:read", "observability:recovery"),
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
            {"id": UUID(value), "key": key, "description": f"Allows {key}"}
            for key, value in PERMISSIONS.items()
        ],
    )
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": UUID(ROLES[role]), "permission_id": UUID(PERMISSIONS[key])}
            for role, keys in GRANTS.items()
            for key in keys
        ],
    )

    op.create_table(
        "synthetic_reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("report_type", sa.String(48), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("report_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("source_hashes", sa.JSON(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("false_capability_flags", sa.JSON(), nullable=False),
        sa.Column("finalized_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('complete','partial','failed','not_evaluable')",
            name="ck_synthetic_report_status",
        ),
    )
    op.create_index("ix_synthetic_reports_report_type", "synthetic_reports", ["report_type"])
    op.create_index("ix_synthetic_reports_status", "synthetic_reports", ["status"])
    op.create_index("ix_synthetic_reports_expires_at", "synthetic_reports", ["expires_at"])

    op.create_table(
        "synthetic_report_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("report_type", sa.String(48), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column(
            "report_id", sa.Uuid(), sa.ForeignKey("synthetic_reports.id", ondelete="RESTRICT")
        ),
        sa.Column("error_code", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_synthetic_report_actor_key"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','complete','partial','failed','not_evaluable')",
            name="ck_synthetic_report_job_status",
        ),
    )
    op.create_index("ix_synthetic_report_jobs_status", "synthetic_report_jobs", ["status"])
    op.create_index("ix_synthetic_report_jobs_expires_at", "synthetic_report_jobs", ["expires_at"])

    op.create_table(
        "synthetic_observability_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("component", sa.String(32), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("groups_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bytes_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("actor_role", sa.String(32), nullable=False, server_default="system"),
        sa.Column("safe_error_code", sa.String(64)),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("evidence_hashes", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("false_capability_flags", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('succeeded','failed','degraded','not_evaluable')",
            name="ck_observability_event_status",
        ),
        sa.CheckConstraint(
            "duration_ms BETWEEN 0 AND 300000", name="ck_observability_event_duration"
        ),
        sa.CheckConstraint("rows BETWEEN 0 AND 100000", name="ck_observability_event_rows"),
        sa.CheckConstraint(
            "groups_count BETWEEN 0 AND 10000", name="ck_observability_event_groups"
        ),
        sa.CheckConstraint(
            "bytes_count BETWEEN 0 AND 67108864", name="ck_observability_event_bytes"
        ),
    )
    op.create_index(
        "ix_synthetic_observability_events_correlation",
        "synthetic_observability_events",
        ["correlation_id"],
    )
    op.create_index(
        "ix_synthetic_observability_events_created_at",
        "synthetic_observability_events",
        ["created_at"],
    )
    op.create_index(
        "ix_synthetic_observability_events_expires_at",
        "synthetic_observability_events",
        ["expires_at"],
    )

    op.create_table(
        "synthetic_sli_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("dimensions", sa.JSON(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_hashes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="succeeded"),
        sa.Column("snapshot_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("false_capability_flags", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('succeeded','failed','degraded','not_evaluable')",
            name="ck_sli_snapshot_status",
        ),
        sa.CheckConstraint("sample_count BETWEEN 0 AND 100000", name="ck_sli_snapshot_samples"),
    )
    op.create_index(
        "ix_synthetic_sli_snapshots_window_start", "synthetic_sli_snapshots", ["window_start"]
    )
    op.create_index(
        "ix_synthetic_sli_snapshots_expires_at", "synthetic_sli_snapshots", ["expires_at"]
    )

    op.create_table(
        "synthetic_recovery_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("outcome", sa.JSON(), nullable=False),
        sa.Column("safe_error_code", sa.String(64)),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','not_evaluable')",
            name="ck_synthetic_recovery_status",
        ),
    )
    op.create_index("ix_synthetic_recovery_runs_status", "synthetic_recovery_runs", ["status"])
    op.create_index(
        "ix_synthetic_recovery_runs_expires_at", "synthetic_recovery_runs", ["expires_at"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    count_queries = (
        "SELECT COUNT(*) FROM synthetic_recovery_runs",
        "SELECT COUNT(*) FROM synthetic_sli_snapshots",
        "SELECT COUNT(*) FROM synthetic_observability_events",
        "SELECT COUNT(*) FROM synthetic_report_jobs",
        "SELECT COUNT(*) FROM synthetic_reports",
    )
    for query in count_queries:
        count = bind.execute(sa.text(query)).scalar_one()
        if count:
            raise RuntimeError("expire synthetic observability evidence before downgrade")
    for index, table in (
        ("ix_synthetic_recovery_runs_expires_at", "synthetic_recovery_runs"),
        ("ix_synthetic_recovery_runs_status", "synthetic_recovery_runs"),
        ("ix_synthetic_sli_snapshots_expires_at", "synthetic_sli_snapshots"),
        ("ix_synthetic_sli_snapshots_window_start", "synthetic_sli_snapshots"),
        ("ix_synthetic_observability_events_expires_at", "synthetic_observability_events"),
        ("ix_synthetic_observability_events_created_at", "synthetic_observability_events"),
        ("ix_synthetic_observability_events_correlation", "synthetic_observability_events"),
        ("ix_synthetic_report_jobs_expires_at", "synthetic_report_jobs"),
        ("ix_synthetic_report_jobs_status", "synthetic_report_jobs"),
        ("ix_synthetic_reports_expires_at", "synthetic_reports"),
        ("ix_synthetic_reports_status", "synthetic_reports"),
        ("ix_synthetic_reports_report_type", "synthetic_reports"),
    ):
        op.drop_index(index, table_name=table)
    for table in (
        "synthetic_recovery_runs",
        "synthetic_sli_snapshots",
        "synthetic_observability_events",
        "synthetic_report_jobs",
        "synthetic_reports",
    ):
        op.drop_table(table)
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
