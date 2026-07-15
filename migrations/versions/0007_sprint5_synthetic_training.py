"""Add Gate 5S-B synthetic training metadata only."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0007_sprint5_synthetic_training"
down_revision: str | None = "0006_sprint5_synthetic_gate"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "models:read": "10000000-0000-0000-0000-000000000038",
    "models:train_synthetic": "10000000-0000-0000-0000-000000000039",
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
        [{"id": UUID(v), "key": k, "description": f"Allows {k}"} for k, v in PERMISSIONS.items()],
    )
    read_roles = tuple(ROLES)
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": UUID(ROLES[role]), "permission_id": UUID(PERMISSIONS[permission])}
            for role in read_roles
            for permission in (
                ("models:read", "models:train_synthetic")
                if role == "System Administrator"
                else ("models:read",)
            )
        ],
    )
    op.create_table(
        "synthetic_training_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
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
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("selected_algorithm", sa.String(32)),
        sa.Column("selected_candidate_hash", sa.String(64)),
        sa.Column("test_opening_hash", sa.String(64)),
        sa.Column("test_opened_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_synthetic_training_actor_key"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_training_status",
        ),
        sa.CheckConstraint("threshold = 0.5", name="ck_synthetic_training_threshold"),
        sa.CheckConstraint("retention_days = 30", name="ck_synthetic_training_retention"),
    )
    op.create_table(
        "synthetic_model_candidates",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "training_run_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_training_runs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("model_object_ref", sa.String(64), nullable=False),
        sa.Column("model_sha256", sa.String(64), nullable=False),
        sa.Column("model_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("metadata_object_ref", sa.String(64), nullable=False),
        sa.Column("metadata_sha256", sa.String(64), nullable=False),
        sa.Column("metadata_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("preprocessor_hash", sa.String(64), nullable=False),
        sa.Column("evaluation_hash", sa.String(64), nullable=False),
        sa.Column("model_card_hash", sa.String(64), nullable=False),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("selected", sa.Boolean(), nullable=False),
        sa.Column("artifacts_deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "training_run_id", "algorithm", name="uq_synthetic_candidate_algorithm"
        ),
        sa.UniqueConstraint("model_sha256", name="uq_synthetic_candidate_model_hash"),
        sa.CheckConstraint(
            "algorithm IN ('logistic_regression','random_forest')",
            name="ck_synthetic_candidate_algorithm",
        ),
        sa.CheckConstraint(
            "lifecycle_state = 'unreviewed_candidate'", name="ck_synthetic_candidate_state"
        ),
        sa.CheckConstraint(
            "model_size_bytes BETWEEN 1 AND 16777216", name="ck_synthetic_candidate_size"
        ),
        sa.CheckConstraint(
            "metadata_size_bytes BETWEEN 1 AND 16777216",
            name="ck_synthetic_candidate_metadata_size",
        ),
    )
    for table, columns in {
        "synthetic_training_runs": (
            "dataset_version_id",
            "requested_by",
            "status",
            "expires_at",
            "created_at",
        ),
        "synthetic_model_candidates": ("training_run_id", "lifecycle_state", "created_at"),
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM synthetic_model_candidates
                WHERE artifacts_deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'inventory and delete model artifacts before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("synthetic_model_candidates")
    op.drop_table("synthetic_training_runs")
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for identifier in PERMISSIONS.values():
        op.execute(
            role_permissions.delete().where(role_permissions.c.permission_id == UUID(identifier))
        )
        op.execute(permissions.delete().where(permissions.c.id == UUID(identifier)))
