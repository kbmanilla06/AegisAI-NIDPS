"""Unlock alert SOC workflow and add incident correlation metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0011_sprint8_alert_incident_soc"
down_revision: str | None = "0010_sprint7_explain_intel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "alerts:triage": "10000000-0000-0000-0000-00000000005c",
    "incidents:read": "10000000-0000-0000-0000-00000000005d",
    "incidents:correlate": "10000000-0000-0000-0000-00000000005e",
    "incidents:manage": "10000000-0000-0000-0000-00000000005f",
}
ROLES = {
    "SOC Analyst": "00000000-0000-0000-0000-000000000002",
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
GRANTS = {
    "SOC Analyst": ("alerts:triage", "incidents:read"),
    "Senior Analyst": ("alerts:triage", "incidents:read", "incidents:manage"),
    "Security Administrator": (
        "alerts:triage",
        "incidents:read",
        "incidents:correlate",
        "incidents:manage",
    ),
    "System Administrator": ("incidents:read", "incidents:correlate"),
    "Auditor": ("incidents:read",),
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

    # Unlock the alert workflow reserved by Sprint 3's status lock; projection is untouched.
    op.drop_constraint("ck_alerts_sprint3_status", "alerts", type_="check")
    op.add_column(
        "alerts",
        sa.Column("assignee_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
    )
    op.add_column("alerts", sa.Column("disposition", sa.String(32)))
    op.add_column(
        "alerts",
        sa.Column("closed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
    )
    op.add_column("alerts", sa.Column("closed_at", sa.DateTime(timezone=True)))
    op.add_column(
        "alerts",
        sa.Column("updated_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
    )
    op.create_check_constraint(
        "ck_alerts_status",
        "alerts",
        "status IN ('new','acknowledged','investigating','closed')",
    )
    op.create_check_constraint(
        "ck_alerts_disposition",
        "alerts",
        "disposition IS NULL OR disposition IN "
        "('false_positive','benign','synthetic_true_positive')",
    )
    op.create_check_constraint(
        "ck_alerts_disposition_on_close",
        "alerts",
        "(status = 'closed') = (disposition IS NOT NULL)",
    )
    op.create_index("ix_alerts_assignee_id", "alerts", ["assignee_id"])

    op.create_table(
        "alert_notes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "alert_id", sa.Uuid(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "author_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("body", sa.String(4096), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_alert_notes_alert_id", "alert_notes", ["alert_id"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("correlation_key", sa.String(64), nullable=False),
        sa.Column("correlation_version", sa.String(32), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("disposition", sa.String(32)),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("correlation_key", name="uq_incidents_correlation_key"),
        sa.CheckConstraint(
            "status IN ('open','investigating','resolved','closed')", name="ck_incidents_status"
        ),
        sa.CheckConstraint(
            "disposition IS NULL OR disposition IN "
            "('false_positive','benign','synthetic_true_positive')",
            name="ck_incidents_disposition",
        ),
        sa.CheckConstraint("alert_count >= 0", name="ck_incidents_alert_count"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_expires_at", "incidents", ["expires_at"])

    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "alert_id", sa.Uuid(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_member"),
    )
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])

    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_incident_timeline_incident_id", "incident_timeline", ["incident_id"])


def downgrade() -> None:
    # Refuse to re-lock the alert status while workflow/incident inventory remains.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM alerts WHERE status <> 'new')
               OR EXISTS (SELECT 1 FROM incidents) THEN
                RAISE EXCEPTION
                    'close open alert/incident workflow inventory before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("incident_timeline")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
    op.drop_index("ix_alert_notes_alert_id", table_name="alert_notes")
    op.drop_table("alert_notes")
    op.drop_index("ix_alerts_assignee_id", table_name="alerts")
    op.drop_constraint("ck_alerts_disposition_on_close", "alerts", type_="check")
    op.drop_constraint("ck_alerts_disposition", "alerts", type_="check")
    op.drop_constraint("ck_alerts_status", "alerts", type_="check")
    op.drop_column("alerts", "updated_by")
    op.drop_column("alerts", "closed_at")
    op.drop_column("alerts", "closed_by")
    op.drop_column("alerts", "disposition")
    op.drop_column("alerts", "assignee_id")
    op.create_check_constraint("ck_alerts_sprint3_status", "alerts", "status = 'new'")

    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
