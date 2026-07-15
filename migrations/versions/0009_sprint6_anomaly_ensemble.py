"""Add synthetic-only anomaly and transparent fusion metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0009_sprint6_anomaly_ensemble"
down_revision: str | None = "0008_sprint5_synthetic_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "anomaly:fit": "10000000-0000-0000-0000-000000000050",
    "anomaly:evaluate": "10000000-0000-0000-0000-000000000051",
    "ensemble:review": "10000000-0000-0000-0000-000000000052",
    "ensemble:evaluate": "10000000-0000-0000-0000-000000000053",
}
ROLES = {
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
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
        "Senior Analyst": ("anomaly:evaluate", "ensemble:evaluate"),
        "Security Administrator": ("anomaly:evaluate", "ensemble:evaluate", "ensemble:review"),
        "System Administrator": ("anomaly:fit", "anomaly:evaluate", "ensemble:evaluate"),
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
        "anomaly_detector_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("feature_schema_hash", sa.String(64), nullable=False),
        sa.Column("preprocessor_hash", sa.String(64), nullable=False),
        sa.Column("dataset_content_hash", sa.String(64), nullable=False),
        sa.Column("split_manifest_hash", sa.String(64), nullable=False),
        sa.Column("training_identity_hash", sa.String(64), nullable=False),
        sa.Column("normal_identity_hash", sa.String(64), nullable=False),
        sa.Column("manifest_hash", sa.String(64), unique=True),
        sa.Column("model_object_ref", sa.String(64)),
        sa.Column("model_sha256", sa.String(64)),
        sa.Column("model_size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("metadata_object_ref", sa.String(64)),
        sa.Column("metadata_sha256", sa.String(64)),
        sa.Column("metadata_size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("threshold_hash", sa.String(64)),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("review_reason", sa.String(512)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("artifacts_deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("manifest_hash", name="uq_anomaly_detector_manifest"),
        sa.CheckConstraint(
            "lifecycle_state IN ("
            "'unreviewed_candidate','reviewed_synthetic','rejected','quarantined','retired')",
            name="ck_anomaly_detector_state",
        ),
        sa.CheckConstraint(
            "model_size_bytes BETWEEN 0 AND 16777216", name="ck_anomaly_detector_size"
        ),
    )
    op.create_index("ix_anomaly_detector_status", "anomaly_detector_versions", ["status"])
    op.create_table(
        "anomaly_threshold_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "detector_id",
            sa.Uuid(),
            sa.ForeignKey("anomaly_detector_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "reviewed_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
        ),
        sa.Column("review_reason", sa.String(512)),
        sa.Column("detector_manifest_hash", sa.String(64), nullable=False),
        sa.Column("threshold_hash", sa.String(64), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("validation_identity_hash", sa.String(64), nullable=False),
        sa.Column("validation_reference_count", sa.Integer(), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column("test_opened_once", sa.Boolean(), nullable=False),
        sa.Column("limitations", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("threshold_hash", name="uq_anomaly_threshold_hash"),
    )
    op.create_index(
        "ix_anomaly_threshold_detector_id", "anomaly_threshold_versions", ["detector_id"]
    )
    op.create_table(
        "ensemble_policy_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("review_reason", sa.String(512)),
        sa.Column("limitations", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("policy_hash", name="uq_ensemble_policy_hash"),
    )
    op.create_table(
        "assessment_batches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("dataset_content_hash", sa.String(64), nullable=False),
        sa.Column("feature_artifact_hash", sa.String(64), nullable=False),
        sa.Column("anomaly_detector_hash", sa.String(64), nullable=False),
        sa.Column("threshold_hash", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aggregate", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("limitations", sa.String(512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("requested_by", "idempotency_key", name="uq_assessment_actor_key"),
        sa.CheckConstraint("row_count BETWEEN 0 AND 10000", name="ck_assessment_rows"),
    )
    op.create_index("ix_assessment_batches_status", "assessment_batches", ["status"])
    op.create_table(
        "decision_assessments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Uuid(),
            sa.ForeignKey("assessment_batches.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_identity_hash", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("anomaly_detector_hash", sa.String(64), nullable=False),
        sa.Column("source_scores", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("uncertainty_codes", sa.JSON(), nullable=False),
        sa.Column("evidence_complete", sa.Boolean(), nullable=False),
        sa.Column("limitations", sa.String(512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("batch_id", "source_identity_hash", name="uq_decision_batch_source"),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_decision_risk"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_decision_confidence"),
    )
    op.create_index("ix_decision_assessments_batch_id", "decision_assessments", ["batch_id"])


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM assessment_batches
                WHERE status IN ('pending', 'processing', 'succeeded')
            ) THEN
                RAISE EXCEPTION 'delete active assessment batches before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("decision_assessments")
    op.drop_table("assessment_batches")
    op.drop_table("ensemble_policy_versions")
    op.drop_table("anomaly_threshold_versions")
    op.drop_table("anomaly_detector_versions")
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
