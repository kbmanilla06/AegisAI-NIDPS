"""Create Sprint 4 feature, dataset, materialization, and artifact metadata."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

from aegis_services.features import canonical_hash, feature_schema

revision: str = "0004_sprint4_features"
down_revision: str | None = "0003_sprint3_detection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INITIAL_SCHEMA_ID = "30000000-0000-0000-0000-000000000001"
UNSW_DATASET_ID = "30000000-0000-0000-0000-000000000002"
PERMISSION_IDS = {
    "features:read": "10000000-0000-0000-0000-000000000028",
    "features:materialize": "10000000-0000-0000-0000-000000000029",
    "features:review": "10000000-0000-0000-0000-000000000030",
    "datasets:read": "10000000-0000-0000-0000-000000000031",
    "datasets:manage": "10000000-0000-0000-0000-000000000032",
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
    "Viewer": set(),
    "SOC Analyst": {"features:read"},
    "Senior Analyst": {"features:read", "datasets:read"},
    "Security Administrator": set(PERMISSION_IDS),
    "System Administrator": {"features:read", "features:materialize", "datasets:read"},
    "Auditor": {"features:read", "datasets:read"},
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
        "feature_schema_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("input_schema", sa.String(32), nullable=False),
        sa.Column("ordered_definition", sa.JSON(), nullable=False),
        sa.Column("preprocessing_config", sa.JSON(), nullable=False),
        sa.Column("banned_fields", sa.JSON(), nullable=False),
        sa.Column("definition_hash", sa.String(64), nullable=False),
        sa.Column("code_version", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(16), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("review_reason", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("name", "version", name="uq_feature_schema_name_version"),
        sa.UniqueConstraint("definition_hash", name="uq_feature_schema_definition_hash"),
        sa.CheckConstraint(
            "lifecycle_state IN ('draft','approved','retired')",
            name="ck_feature_schema_lifecycle",
        ),
    )
    op.create_index(
        "ix_feature_schema_versions_lifecycle_state",
        "feature_schema_versions",
        ["lifecycle_state"],
    )
    op.create_index(
        "ix_feature_schema_versions_created_at", "feature_schema_versions", ["created_at"]
    )

    op.create_table(
        "dataset_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("official_source_url", sa.String(512), nullable=False),
        sa.Column("publisher", sa.String(128), nullable=False),
        sa.Column("intended_use", sa.String(64), nullable=False),
        sa.Column("terms_reference_hash", sa.String(64), nullable=False),
        sa.Column("citation_required", sa.Boolean(), nullable=False),
        sa.Column("commercial_approval_required", sa.Boolean(), nullable=False),
        sa.Column("acquisition_authorized", sa.Boolean(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("name", "version", name="uq_dataset_name_version"),
        sa.UniqueConstraint("manifest_hash", name="uq_dataset_manifest_hash"),
        sa.CheckConstraint("status IN ('proposed','accepted','retired')", name="ck_dataset_status"),
    )
    op.create_index("ix_dataset_versions_status", "dataset_versions", ["status"])
    op.create_index("ix_dataset_versions_created_at", "dataset_versions", ["created_at"])

    op.create_table(
        "dataset_split_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "dataset_version_id",
            sa.Uuid(),
            sa.ForeignKey("dataset_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("strategy", sa.String(32), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("train_count", sa.BigInteger(), nullable=False),
        sa.Column("validation_count", sa.BigInteger(), nullable=False),
        sa.Column("test_count", sa.BigInteger(), nullable=False),
        sa.Column(
            "reviewed_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("manifest_hash", name="uq_dataset_split_manifest_hash"),
        sa.CheckConstraint("train_count > 0", name="ck_dataset_split_train"),
        sa.CheckConstraint("validation_count > 0", name="ck_dataset_split_validation"),
        sa.CheckConstraint("test_count > 0", name="ck_dataset_split_test"),
    )
    op.create_index(
        "ix_dataset_split_versions_dataset_version_id",
        "dataset_split_versions",
        ["dataset_version_id"],
    )
    op.create_index(
        "ix_dataset_split_versions_created_at", "dataset_split_versions", ["created_at"]
    )

    op.create_table(
        "feature_materialization_jobs",
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
        sa.Column(
            "ingestion_job_id",
            sa.Uuid(),
            sa.ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("requested_limit", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("input_count", sa.Integer(), nullable=False),
        sa.Column("output_count", sa.Integer(), nullable=False),
        sa.Column("source_snapshot_hash", sa.String(64)),
        sa.Column("quality_summary", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_feature_job_actor_idempotency"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_feature_job_status",
        ),
        sa.CheckConstraint("requested_limit BETWEEN 1 AND 10000", name="ck_feature_job_limit"),
        sa.CheckConstraint("input_count >= 0", name="ck_feature_job_input_count"),
        sa.CheckConstraint("output_count >= 0", name="ck_feature_job_output_count"),
    )
    for column in (
        "requested_by",
        "feature_schema_id",
        "ingestion_job_id",
        "status",
        "created_at",
    ):
        op.create_index(
            f"ix_feature_materialization_jobs_{column}",
            "feature_materialization_jobs",
            [column],
        )

    op.create_table(
        "feature_artifacts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "materialization_job_id",
            sa.Uuid(),
            sa.ForeignKey("feature_materialization_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "feature_schema_id",
            sa.Uuid(),
            sa.ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("object_ref", sa.String(36), nullable=False),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("row_count", sa.BigInteger(), nullable=False),
        sa.Column("column_count", sa.Integer(), nullable=False),
        sa.Column("source_snapshot_hash", sa.String(64), nullable=False),
        sa.Column("code_version", sa.String(64), nullable=False),
        sa.Column("retention_class", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("materialization_job_id", name="uq_feature_artifact_job"),
        sa.UniqueConstraint("object_ref", name="uq_feature_artifact_ref"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_feature_artifact_size"),
        sa.CheckConstraint("row_count > 0", name="ck_feature_artifact_rows"),
        sa.CheckConstraint("column_count BETWEEN 1 AND 128", name="ck_feature_artifact_columns"),
        sa.CheckConstraint("status IN ('available','deleted')", name="ck_feature_artifact_status"),
    )
    for column in (
        "materialization_job_id",
        "feature_schema_id",
        "expires_at",
        "status",
        "created_at",
    ):
        op.create_index(f"ix_feature_artifacts_{column}", "feature_artifacts", [column])

    op.execute(
        """
        CREATE FUNCTION protect_feature_schema_definition() RETURNS trigger AS $$
        BEGIN
          IF OLD.name IS DISTINCT FROM NEW.name
             OR OLD.version IS DISTINCT FROM NEW.version
             OR OLD.input_schema IS DISTINCT FROM NEW.input_schema
             OR OLD.ordered_definition::jsonb IS DISTINCT FROM NEW.ordered_definition::jsonb
             OR OLD.preprocessing_config::jsonb IS DISTINCT FROM NEW.preprocessing_config::jsonb
             OR OLD.banned_fields::jsonb IS DISTINCT FROM NEW.banned_fields::jsonb
             OR OLD.definition_hash IS DISTINCT FROM NEW.definition_hash
             OR OLD.code_version IS DISTINCT FROM NEW.code_version
             OR OLD.created_by IS DISTINCT FROM NEW.created_by
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'feature schema definitions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_protect_feature_schema_definition
        BEFORE UPDATE ON feature_schema_versions
        FOR EACH ROW EXECUTE FUNCTION protect_feature_schema_definition()
        """
    )
    op.execute(
        """
        CREATE FUNCTION protect_dataset_definition() RETURNS trigger AS $$
        BEGIN
          IF OLD.name IS DISTINCT FROM NEW.name
             OR OLD.version IS DISTINCT FROM NEW.version
             OR OLD.official_source_url IS DISTINCT FROM NEW.official_source_url
             OR OLD.publisher IS DISTINCT FROM NEW.publisher
             OR OLD.intended_use IS DISTINCT FROM NEW.intended_use
             OR OLD.terms_reference_hash IS DISTINCT FROM NEW.terms_reference_hash
             OR OLD.citation_required IS DISTINCT FROM NEW.citation_required
             OR OLD.commercial_approval_required IS DISTINCT FROM NEW.commercial_approval_required
             OR OLD.acquisition_authorized IS DISTINCT FROM NEW.acquisition_authorized
             OR OLD.manifest::jsonb IS DISTINCT FROM NEW.manifest::jsonb
             OR OLD.manifest_hash IS DISTINCT FROM NEW.manifest_hash
             OR OLD.created_by IS DISTINCT FROM NEW.created_by
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'dataset definitions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_protect_dataset_definition
        BEFORE UPDATE ON dataset_versions
        FOR EACH ROW EXECUTE FUNCTION protect_dataset_definition()
        """
    )
    op.execute(
        """
        CREATE FUNCTION reject_dataset_split_update() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'dataset split versions are immutable';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_reject_dataset_split_update
        BEFORE UPDATE ON dataset_split_versions
        FOR EACH ROW EXECUTE FUNCTION reject_dataset_split_update()
        """
    )
    op.execute(
        """
        CREATE FUNCTION protect_feature_artifact_definition() RETURNS trigger AS $$
        BEGIN
          IF OLD.materialization_job_id IS DISTINCT FROM NEW.materialization_job_id
             OR OLD.feature_schema_id IS DISTINCT FROM NEW.feature_schema_id
             OR OLD.object_ref IS DISTINCT FROM NEW.object_ref
             OR OLD.media_type IS DISTINCT FROM NEW.media_type
             OR OLD.sha256 IS DISTINCT FROM NEW.sha256
             OR OLD.size_bytes IS DISTINCT FROM NEW.size_bytes
             OR OLD.row_count IS DISTINCT FROM NEW.row_count
             OR OLD.column_count IS DISTINCT FROM NEW.column_count
             OR OLD.source_snapshot_hash IS DISTINCT FROM NEW.source_snapshot_hash
             OR OLD.code_version IS DISTINCT FROM NEW.code_version
             OR OLD.retention_class IS DISTINCT FROM NEW.retention_class
             OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'feature artifact definitions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_protect_feature_artifact_definition
        BEFORE UPDATE ON feature_artifacts
        FOR EACH ROW EXECUTE FUNCTION protect_feature_artifact_definition()
        """
    )

    schema = feature_schema(code_version="sprint4")
    schema_table = sa.table(
        "feature_schema_versions",
        sa.column("id", sa.Uuid()),
        sa.column("name"),
        sa.column("version"),
        sa.column("input_schema"),
        sa.column("ordered_definition", sa.JSON()),
        sa.column("preprocessing_config", sa.JSON()),
        sa.column("banned_fields", sa.JSON()),
        sa.column("definition_hash"),
        sa.column("code_version"),
        sa.column("lifecycle_state"),
        sa.column("review_reason"),
    )
    op.bulk_insert(
        schema_table,
        [
            {
                "id": UUID(INITIAL_SCHEMA_ID),
                "name": schema.name,
                "version": schema.version,
                "input_schema": schema.input_schema,
                "ordered_definition": schema.model_dump(mode="json"),
                "preprocessing_config": {
                    "missing_token": schema.missing_token,
                    "unknown_token": schema.unknown_token,
                    "numeric_dtype": schema.numeric_dtype,
                    "fit_partition": "training_only",
                },
                "banned_fields": list(schema.banned_fields),
                "definition_hash": schema.definition_hash,
                "code_version": schema.code_version,
                "lifecycle_state": "draft",
                "review_reason": None,
            }
        ],
    )
    terms_summary = (
        "UNSW grants free academic research use in perpetuity, requires citation of the "
        "listed works, and requires author agreement for commercial use."
    )
    terms_hash = canonical_hash(terms_summary)
    dataset_manifest = {
        "contract": "dataset-manifest/v1",
        "dataset_name": "UNSW-NB15",
        "dataset_version": "official-source-review-2026-07-14",
        "official_source_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "publisher": "UNSW Canberra at ADFA",
        "reviewed_at": "2026-07-14T00:00:00Z",
        "acquisition_authorized": False,
        "intended_use": "academic_portfolio",
        "terms_reference_hash": terms_hash,
        "citation_required": True,
        "commercial_use_requires_author_agreement": True,
        "redistribution_authorized": False,
        "files": [],
        "adapter_version": None,
        "limitations": [
            "Official page last-updated date is 2021-06-02.",
            "Prepared tabular files require semantic mapping to canonical flow v1.",
            "Raw approximately 100 GB PCAP is explicitly excluded.",
            "No dataset file or download link was opened during Sprint 4 investigation.",
        ],
    }
    dataset_table = sa.table(
        "dataset_versions",
        sa.column("id", sa.Uuid()),
        sa.column("name"),
        sa.column("version"),
        sa.column("official_source_url"),
        sa.column("publisher"),
        sa.column("intended_use"),
        sa.column("terms_reference_hash"),
        sa.column("citation_required", sa.Boolean()),
        sa.column("commercial_approval_required", sa.Boolean()),
        sa.column("acquisition_authorized", sa.Boolean()),
        sa.column("manifest", sa.JSON()),
        sa.column("manifest_hash"),
        sa.column("status"),
    )
    op.bulk_insert(
        dataset_table,
        [
            {
                "id": UUID(UNSW_DATASET_ID),
                "name": "UNSW-NB15",
                "version": "official-source-review-2026-07-14",
                "official_source_url": dataset_manifest["official_source_url"],
                "publisher": dataset_manifest["publisher"],
                "intended_use": "academic_portfolio",
                "terms_reference_hash": terms_hash,
                "citation_required": True,
                "commercial_approval_required": True,
                "acquisition_authorized": False,
                "manifest": dataset_manifest,
                "manifest_hash": canonical_hash(dataset_manifest),
                "status": "proposed",
            }
        ],
    )


def downgrade() -> None:
    connection = op.get_bind()
    artifact_count = connection.scalar(sa.text("SELECT count(*) FROM feature_artifacts"))
    if artifact_count:
        raise RuntimeError(
            "inventory and delete/export Sprint 4 artifacts before downgrading metadata"
        )
    op.drop_table("feature_artifacts")
    op.drop_table("feature_materialization_jobs")
    op.drop_table("dataset_split_versions")
    op.drop_table("dataset_versions")
    op.drop_table("feature_schema_versions")
    op.execute("DROP FUNCTION protect_feature_artifact_definition()")
    op.execute("DROP FUNCTION reject_dataset_split_update()")
    op.execute("DROP FUNCTION protect_dataset_definition()")
    op.execute("DROP FUNCTION protect_feature_schema_definition()")

    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    permission_ids = [UUID(identifier) for identifier in PERMISSION_IDS.values()]
    connection.execute(
        sa.delete(role_permissions).where(role_permissions.c.permission_id.in_(permission_ids))
    )
    connection.execute(sa.delete(permissions).where(permissions.c.id.in_(permission_ids)))
