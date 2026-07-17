"""Add synthetic-only monitoring and analyst feedback metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0013_p1_monitoring"
down_revision: str | None = "0012_sprint9_prevention_sim"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "synthetic_monitoring:read": "10000000-0000-0000-0000-000000000070",
    "synthetic_monitoring:run": "10000000-0000-0000-0000-000000000071",
    "synthetic_feedback:write": "10000000-0000-0000-0000-000000000072",
    "synthetic_feedback:review": "10000000-0000-0000-0000-000000000073",
}
ROLES = {
    "SOC Analyst": "00000000-0000-0000-0000-000000000002",
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
GRANTS = {
    "SOC Analyst": ("synthetic_monitoring:read", "synthetic_feedback:write"),
    "Senior Analyst": (
        "synthetic_monitoring:read",
        "synthetic_monitoring:run",
        "synthetic_feedback:write",
    ),
    "Security Administrator": (
        "synthetic_monitoring:read",
        "synthetic_monitoring:run",
        "synthetic_feedback:write",
        "synthetic_feedback:review",
    ),
    "System Administrator": ("synthetic_monitoring:read", "synthetic_monitoring:run"),
    "Auditor": ("synthetic_monitoring:read",),
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
        "synthetic_monitoring_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("baseline_snapshot", sa.JSON(), nullable=False),
        sa.Column("current_snapshot", sa.JSON(), nullable=False),
        sa.Column("baseline_snapshot_hash", sa.String(64)),
        sa.Column("current_snapshot_hash", sa.String(64)),
        sa.Column("policy_hash", sa.String(64)),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("group_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warning_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_monitoring_actor_idempotency"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','not_evaluable')",
            name="ck_monitoring_status",
        ),
        sa.CheckConstraint("sample_count BETWEEN 0 AND 10000", name="ck_monitoring_samples"),
        sa.CheckConstraint("group_count BETWEEN 0 AND 120", name="ck_monitoring_groups"),
        sa.CheckConstraint("warning_count >= 0", name="ck_monitoring_warnings"),
        sa.CheckConstraint("critical_count >= 0", name="ck_monitoring_criticals"),
    )
    op.create_index("ix_synthetic_monitoring_runs_status", "synthetic_monitoring_runs", ["status"])
    op.create_index(
        "ix_synthetic_monitoring_runs_expires_at", "synthetic_monitoring_runs", ["expires_at"]
    )

    op.create_table(
        "synthetic_monitoring_metrics",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "run_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_monitoring_runs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("metric_key", sa.String(64), nullable=False),
        sa.Column("baseline_value", sa.Float()),
        sa.Column("current_value", sa.Float()),
        sa.Column("delta", sa.Float()),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("run_id", "metric_key", name="uq_monitoring_run_metric"),
        sa.CheckConstraint(
            "status IN ('ok','warning','critical','not_evaluable')",
            name="ck_monitoring_metric_status",
        ),
    )
    op.create_index(
        "ix_synthetic_monitoring_metrics_run_id", "synthetic_monitoring_metrics", ["run_id"]
    )

    op.create_table(
        "synthetic_analyst_feedback",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "monitoring_run_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_monitoring_runs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("disposition", sa.String(48), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("note", sa.String(1000), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="submitted"),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("review_reason", sa.String(500)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "disposition IN ('confirmed_synthetic_intrusion_like',"
            "'confirmed_synthetic_benign_like',"
            "'false_positive_demo','false_negative_demo','insufficient_evidence','needs_review')",
            name="ck_synthetic_feedback_disposition",
        ),
        sa.CheckConstraint(
            "status IN ('submitted','reviewed','rejected')", name="ck_synthetic_feedback_status"
        ),
        sa.CheckConstraint(
            "reviewed_by IS NULL OR reviewed_by <> created_by",
            name="ck_synthetic_feedback_reviewer_distinct",
        ),
    )
    op.create_index(
        "ix_synthetic_analyst_feedback_status", "synthetic_analyst_feedback", ["status"]
    )
    op.create_index(
        "ix_synthetic_analyst_feedback_expires_at",
        "synthetic_analyst_feedback",
        ["expires_at"],
    )


def downgrade() -> None:
    # Never silently destroy evidence during a downgrade; an operator must clean up
    # expired rows explicitly and rerun the downgrade.
    bind = op.get_bind()
    feedback_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM synthetic_analyst_feedback")
    ).scalar_one()
    metric_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM synthetic_monitoring_metrics")
    ).scalar_one()
    run_count = bind.execute(sa.text("SELECT COUNT(*) FROM synthetic_monitoring_runs")).scalar_one()
    if feedback_count or metric_count or run_count:
        raise RuntimeError("expire synthetic monitoring evidence before downgrade")
    op.drop_index(
        "ix_synthetic_analyst_feedback_expires_at", table_name="synthetic_analyst_feedback"
    )
    op.drop_index("ix_synthetic_analyst_feedback_status", table_name="synthetic_analyst_feedback")
    op.drop_table("synthetic_analyst_feedback")
    op.drop_index(
        "ix_synthetic_monitoring_metrics_run_id", table_name="synthetic_monitoring_metrics"
    )
    op.drop_table("synthetic_monitoring_metrics")
    op.drop_index("ix_synthetic_monitoring_runs_expires_at", table_name="synthetic_monitoring_runs")
    op.drop_index("ix_synthetic_monitoring_runs_status", table_name="synthetic_monitoring_runs")
    op.drop_table("synthetic_monitoring_runs")
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
