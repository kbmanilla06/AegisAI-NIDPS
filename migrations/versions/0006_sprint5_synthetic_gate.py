"""Create Sprint 5 Gate 5S-A synthetic dataset metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0006_sprint5_synthetic_gate"
down_revision: str | None = "0005_sprint5_preacquisition"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION_IDS = {
    "synthetic_datasets:read": "10000000-0000-0000-0000-000000000035",
    "synthetic_datasets:generate": "10000000-0000-0000-0000-000000000036",
    "synthetic_datasets:review": "10000000-0000-0000-0000-000000000037",
}
ROLE_IDS = {
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
ROLE_PERMISSIONS = {
    "Senior Analyst": {"synthetic_datasets:read"},
    "Security Administrator": {"synthetic_datasets:read", "synthetic_datasets:review"},
    "System Administrator": {"synthetic_datasets:read", "synthetic_datasets:generate"},
    "Auditor": {"synthetic_datasets:read"},
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
        "synthetic_generation_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "feature_schema_id",
            sa.Uuid(),
            sa.ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("scenario_catalog_hash", sa.String(64), nullable=False),
        sa.Column("global_seed", sa.BigInteger(), nullable=False),
        sa.Column("requested_flow_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("generated_flow_count", sa.Integer(), nullable=False),
        sa.Column("generated_group_count", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_synthetic_job_actor_idempotency"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_job_status",
        ),
        sa.CheckConstraint("requested_flow_count = 7200", name="ck_synthetic_job_flow_count"),
        sa.CheckConstraint(
            "generated_flow_count BETWEEN 0 AND 10000", name="ck_synthetic_generated"
        ),
        sa.CheckConstraint("generated_group_count BETWEEN 0 AND 120", name="ck_synthetic_groups"),
        sa.CheckConstraint("global_seed = 20260714", name="ck_synthetic_seed"),
    )
    for column in ("requested_by", "feature_schema_id", "status", "created_at"):
        op.create_index(
            f"ix_synthetic_generation_jobs_{column}", "synthetic_generation_jobs", [column]
        )

    op.create_table(
        "synthetic_dataset_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "generation_job_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_generation_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "feature_schema_id",
            sa.Uuid(),
            sa.ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("target_manifest_hash", sa.String(64), nullable=False),
        sa.Column("split_manifest", sa.JSON(), nullable=False),
        sa.Column("split_manifest_hash", sa.String(64), nullable=False),
        sa.Column("quality_report", sa.JSON(), nullable=False),
        sa.Column("quality_report_hash", sa.String(64), nullable=False),
        sa.Column("leakage_report", sa.JSON(), nullable=False),
        sa.Column("leakage_report_hash", sa.String(64), nullable=False),
        sa.Column("flow_object_ref", sa.String(36), nullable=False),
        sa.Column("flow_sha256", sa.String(64), nullable=False),
        sa.Column("flow_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("target_object_ref", sa.String(36), nullable=False),
        sa.Column("target_sha256", sa.String(64), nullable=False),
        sa.Column("target_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("feature_object_ref", sa.String(36), nullable=False),
        sa.Column("feature_sha256", sa.String(64), nullable=False),
        sa.Column("feature_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("feature_column_count", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("group_count", sa.Integer(), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("review_reason", sa.String(500)),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifacts_deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("generation_job_id", name="uq_synthetic_dataset_generation_job"),
        sa.UniqueConstraint("manifest_hash", name="uq_synthetic_dataset_manifest_hash"),
        sa.UniqueConstraint("split_manifest_hash", name="uq_synthetic_split_manifest_hash"),
        sa.CheckConstraint(
            "lifecycle_state IN ('generated','accepted_synthetic','rejected','retired')",
            name="ck_synthetic_dataset_lifecycle",
        ),
        sa.CheckConstraint("flow_count = 7200", name="ck_synthetic_dataset_flow_count"),
        sa.CheckConstraint("group_count = 120", name="ck_synthetic_dataset_group_count"),
        sa.CheckConstraint("feature_column_count = 46", name="ck_synthetic_feature_columns"),
        sa.CheckConstraint("retention_days = 30", name="ck_synthetic_dataset_retention"),
        sa.CheckConstraint(
            "reviewed_by IS NULL OR reviewed_by <> created_by",
            name="ck_synthetic_dataset_reviewer_separation",
        ),
    )
    for column in (
        "generation_job_id",
        "created_by",
        "feature_schema_id",
        "lifecycle_state",
        "reviewed_by",
        "expires_at",
        "created_at",
    ):
        op.create_index(
            f"ix_synthetic_dataset_versions_{column}", "synthetic_dataset_versions", [column]
        )

    op.execute(
        """
        CREATE FUNCTION aegis_synthetic_dataset_definition_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF ROW(
                NEW.generation_job_id, NEW.created_by, NEW.feature_schema_id, NEW.name,
                NEW.version, NEW.manifest, NEW.manifest_hash, NEW.target_manifest_hash,
                NEW.split_manifest, NEW.split_manifest_hash, NEW.quality_report,
                NEW.quality_report_hash, NEW.leakage_report, NEW.leakage_report_hash,
                NEW.flow_object_ref, NEW.flow_sha256, NEW.flow_size_bytes,
                NEW.target_object_ref, NEW.target_sha256, NEW.target_size_bytes,
                NEW.feature_object_ref, NEW.feature_sha256, NEW.feature_size_bytes,
                NEW.feature_column_count, NEW.flow_count, NEW.group_count,
                NEW.retention_days, NEW.expires_at, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.generation_job_id, OLD.created_by, OLD.feature_schema_id, OLD.name,
                OLD.version, OLD.manifest, OLD.manifest_hash, OLD.target_manifest_hash,
                OLD.split_manifest, OLD.split_manifest_hash, OLD.quality_report,
                OLD.quality_report_hash, OLD.leakage_report, OLD.leakage_report_hash,
                OLD.flow_object_ref, OLD.flow_sha256, OLD.flow_size_bytes,
                OLD.target_object_ref, OLD.target_sha256, OLD.target_size_bytes,
                OLD.feature_object_ref, OLD.feature_sha256, OLD.feature_size_bytes,
                OLD.feature_column_count, OLD.flow_count, OLD.group_count,
                OLD.retention_days, OLD.expires_at, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'synthetic dataset definitions are immutable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_synthetic_dataset_definition_immutable
        BEFORE UPDATE ON synthetic_dataset_versions
        FOR EACH ROW EXECUTE FUNCTION aegis_synthetic_dataset_definition_immutable();
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM synthetic_dataset_versions WHERE artifacts_deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'inventory and delete synthetic artifacts before downgrade';
            END IF;
        END $$;
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_synthetic_dataset_definition_immutable "
        "ON synthetic_dataset_versions"
    )
    op.execute("DROP FUNCTION IF EXISTS aegis_synthetic_dataset_definition_immutable()")
    op.drop_table("synthetic_dataset_versions")
    op.drop_table("synthetic_generation_jobs")
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    for role, assigned in ROLE_PERMISSIONS.items():
        for permission in assigned:
            op.execute(
                role_permissions.delete().where(
                    role_permissions.c.role_id == UUID(ROLE_IDS[role]),
                    role_permissions.c.permission_id == UUID(PERMISSION_IDS[permission]),
                )
            )
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for identifier in PERMISSION_IDS.values():
        op.execute(permissions.delete().where(permissions.c.id == UUID(identifier)))
