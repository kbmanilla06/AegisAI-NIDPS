"""Add synthetic-only explainability, threat-intelligence, and MITRE metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0010_sprint7_explain_intel"
down_revision: str | None = "0009_sprint6_anomaly_ensemble"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "explanations:read": "10000000-0000-0000-0000-000000000054",
    "explanations:generate": "10000000-0000-0000-0000-000000000055",
    "explanations:review": "10000000-0000-0000-0000-000000000056",
    "intelligence:read": "10000000-0000-0000-0000-000000000057",
    "intelligence:import": "10000000-0000-0000-0000-000000000058",
    "intelligence:review": "10000000-0000-0000-0000-000000000059",
    "intelligence:match": "10000000-0000-0000-0000-00000000005a",
    "mitre:read": "10000000-0000-0000-0000-00000000005b",
}
ROLES = {
    "SOC Analyst": "00000000-0000-0000-0000-000000000002",
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
    "Auditor": "00000000-0000-0000-0000-000000000006",
}
GRANTS = {
    "SOC Analyst": ("intelligence:read", "mitre:read"),
    "Senior Analyst": (
        "explanations:read",
        "intelligence:read",
        "intelligence:match",
        "mitre:read",
    ),
    "Security Administrator": (
        "explanations:read",
        "explanations:review",
        "intelligence:read",
        "intelligence:import",
        "intelligence:review",
        "intelligence:match",
        "mitre:read",
    ),
    "System Administrator": (
        "explanations:read",
        "explanations:generate",
        "intelligence:read",
        "intelligence:match",
        "mitre:read",
    ),
    "Auditor": ("explanations:read", "intelligence:read", "mitre:read"),
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
        "explanation_method_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("target_algorithm", sa.String(32), nullable=False),
        sa.Column("feature_schema_hash", sa.String(64), nullable=False),
        sa.Column("top_k", sa.Integer(), nullable=False),
        sa.Column("method_hash", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("review_reason", sa.String(512)),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("method_hash", name="uq_explanation_method_hash"),
        sa.CheckConstraint("top_k BETWEEN 1 AND 39", name="ck_explanation_method_top_k"),
        sa.CheckConstraint(
            "lifecycle_state IN ('draft','reviewed','retired')", name="ck_explanation_method_state"
        ),
    )
    op.create_table(
        "explanation_batches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("method_hash", sa.String(64), nullable=False),
        sa.Column("target_model_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aggregate", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("requested_by", "idempotency_key", name="uq_explanation_actor_key"),
        sa.CheckConstraint("row_count BETWEEN 0 AND 10000", name="ck_explanation_batch_rows"),
    )
    op.create_index("ix_explanation_batches_status", "explanation_batches", ["status"])
    op.create_table(
        "explanations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Uuid(),
            sa.ForeignKey("explanation_batches.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "method_id",
            sa.Uuid(),
            sa.ForeignKey("explanation_method_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("explanation_hash", sa.String(64), nullable=False),
        sa.Column("method_hash", sa.String(64), nullable=False),
        sa.Column("target_model_hash", sa.String(64), nullable=False),
        sa.Column("source_identity_hash", sa.String(64), nullable=False),
        sa.Column("subject_score", sa.Float(), nullable=False),
        sa.Column("baseline_score", sa.Float(), nullable=False),
        sa.Column("attributions", sa.JSON(), nullable=False),
        sa.Column("analyst_summary", sa.String(512), nullable=False),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("batch_id", "source_identity_hash", name="uq_explanation_batch_source"),
        sa.CheckConstraint("subject_score BETWEEN 0 AND 1", name="ck_explanation_subject"),
        sa.CheckConstraint("baseline_score BETWEEN 0 AND 1", name="ck_explanation_baseline"),
    )
    op.create_index("ix_explanations_batch_id", "explanations", ["batch_id"])
    op.create_table(
        "intelligence_sources",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("trust_level", sa.String(16), nullable=False),
        sa.Column("terms_reference_hash", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("review_reason", sa.String(512)),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("name", name="uq_intelligence_source_name"),
        sa.UniqueConstraint("source_hash", name="uq_intelligence_source_hash"),
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "source_id",
            sa.Uuid(),
            sa.ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("indicator_type", sa.String(16), nullable=False),
        sa.Column("value_hash", sa.String(64), nullable=False),
        sa.Column("indicator_hash", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("indicator_hash", name="uq_indicator_hash"),
        sa.UniqueConstraint(
            "indicator_type", "value_hash", "source_id", name="uq_indicator_type_value_source"
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_indicator_confidence"),
    )
    op.create_index("ix_indicators_expires_at", "indicators", ["expires_at"])
    op.create_table(
        "intelligence_match_batches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aggregate", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("requested_by", "idempotency_key", name="uq_intel_match_actor_key"),
        sa.CheckConstraint("match_count BETWEEN 0 AND 10000", name="ck_intel_match_count"),
    )
    op.create_index("ix_intel_match_batches_status", "intelligence_match_batches", ["status"])
    op.create_table(
        "indicator_matches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Uuid(),
            sa.ForeignKey("intelligence_match_batches.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "indicator_id",
            sa.Uuid(),
            sa.ForeignKey("indicators.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("match_id", sa.String(64), nullable=False),
        sa.Column("indicator_hash", sa.String(64), nullable=False),
        sa.Column("source_name", sa.String(64), nullable=False),
        sa.Column("provenance_hash", sa.String(64), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("batch_id", "match_id", name="uq_indicator_match_batch_match"),
        sa.CheckConstraint(
            "state IN ('active','expired','allowlist_conflict')", name="ck_indicator_match_state"
        ),
    )
    op.create_index("ix_indicator_matches_batch_id", "indicator_matches", ["batch_id"])
    op.create_table(
        "mitre_technique_catalog",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("catalog_version", sa.String(16), nullable=False),
        sa.Column("catalog_hash", sa.String(64), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("catalog_hash", name="uq_mitre_catalog_hash"),
    )
    op.create_table(
        "mitre_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "catalog_id",
            sa.Uuid(),
            sa.ForeignKey("mitre_technique_catalog.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("evidence_class", sa.String(64), nullable=False),
        sa.Column("catalog_hash", sa.String(64), nullable=False),
        sa.Column("rationale", sa.String(256), nullable=False),
        sa.Column("mapping_version", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("limitations", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "catalog_id", "technique_id", "evidence_class", name="uq_mitre_mapping_identity"
        ),
    )
    op.create_index("ix_mitre_mappings_catalog_id", "mitre_mappings", ["catalog_id"])


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM explanation_batches
                WHERE status IN ('pending', 'processing', 'succeeded')
            ) OR EXISTS (
                SELECT 1 FROM intelligence_match_batches
                WHERE status IN ('pending', 'processing', 'succeeded')
            ) OR EXISTS (SELECT 1 FROM indicators) THEN
                RAISE EXCEPTION
                    'retire Sprint 7 explanation/intelligence inventory before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("mitre_mappings")
    op.drop_table("mitre_technique_catalog")
    op.drop_table("indicator_matches")
    op.drop_table("intelligence_match_batches")
    op.drop_table("indicators")
    op.drop_table("intelligence_sources")
    op.drop_table("explanations")
    op.drop_table("explanation_batches")
    op.drop_table("explanation_method_versions")
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    for value in PERMISSIONS.values():
        op.execute(role_permissions.delete().where(role_permissions.c.permission_id == UUID(value)))
        op.execute(permissions.delete().where(permissions.c.id == UUID(value)))
