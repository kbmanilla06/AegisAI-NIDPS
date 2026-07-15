"""Add reviewed synthetic registry metadata and offline scoring jobs."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0008_sprint5_synthetic_registry"
down_revision: str | None = "0007_sprint5_synthetic_training"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "models:review_synthetic": "10000000-0000-0000-0000-000000000040",
    "models:score_synthetic": "10000000-0000-0000-0000-000000000041",
    "predictions:read": "10000000-0000-0000-0000-000000000042",
}
ROLES = {
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
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
    grants = {
        "Senior Analyst": ("models:score_synthetic", "predictions:read"),
        "Security Administrator": (
            "models:review_synthetic",
            "models:score_synthetic",
            "predictions:read",
        ),
        "System Administrator": ("models:score_synthetic", "predictions:read"),
        "Auditor": ("predictions:read",),
    }
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": UUID(ROLES[role]), "permission_id": UUID(PERMISSIONS[key])}
            for role, keys in grants.items()
            for key in keys
        ],
    )
    op.create_table(
        "synthetic_registry_models",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "candidate_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_model_candidates.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column(
            "reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("review_reason", sa.String(512), nullable=False),
        sa.Column("evidence_reference", sa.String(128), nullable=False),
        sa.Column("candidate_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("candidate_id", name="uq_synthetic_registry_candidate"),
        sa.CheckConstraint(
            "lifecycle_state IN ('reviewed_synthetic','rejected','quarantined','retired')",
            name="ck_synthetic_registry_state",
        ),
    )
    op.create_table(
        "synthetic_scoring_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "registry_model_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_registry_models.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "dataset_version_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_dataset_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("predicted_counts", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_synthetic_scoring_actor_key"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_scoring_status",
        ),
        sa.CheckConstraint("row_count BETWEEN 0 AND 10000", name="ck_synthetic_scoring_rows"),
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM synthetic_scoring_jobs
                WHERE status IN ('pending', 'processing', 'succeeded')
            ) THEN
                RAISE EXCEPTION 'delete scoring jobs before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("synthetic_scoring_jobs")
    op.drop_table("synthetic_registry_models")
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
