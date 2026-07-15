"""Create Sprint 5 pre-acquisition governance foundations."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "0005_sprint5_preacquisition"
down_revision: str | None = "0004_sprint4_features"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION_IDS = {
    "datasets:acquire": "10000000-0000-0000-0000-000000000033",
    "datasets:accept": "10000000-0000-0000-0000-000000000034",
}
ROLE_IDS = {
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
}
ROLE_PERMISSIONS = {
    "Security Administrator": {"datasets:accept"},
    "System Administrator": {"datasets:acquire"},
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
        "dataset_acquisition_plans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("dataset_name", sa.String(128), nullable=False),
        sa.Column("dataset_version", sa.String(64), nullable=False),
        sa.Column("official_page_url", sa.String(512), nullable=False),
        sa.Column("source_review_hash", sa.String(64), nullable=False),
        sa.Column("terms_reference_hash", sa.String(64), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("combined_byte_limit", sa.BigInteger(), nullable=False),
        sa.Column("file_byte_limit", sa.BigInteger(), nullable=False),
        sa.Column("file_count_limit", sa.Integer(), nullable=False),
        sa.Column("raw_retention_days", sa.Integer(), nullable=False),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("manifest_hash", name="uq_dataset_acquisition_manifest_hash"),
        sa.CheckConstraint("state = 'proposed'", name="ck_dataset_acquisition_preapproval_state"),
        sa.CheckConstraint(
            "combined_byte_limit BETWEEN 1 AND 5368709120",
            name="ck_dataset_acquisition_combined_limit",
        ),
        sa.CheckConstraint(
            "file_byte_limit BETWEEN 1 AND 2147483648",
            name="ck_dataset_acquisition_file_limit",
        ),
        sa.CheckConstraint(
            "file_count_limit BETWEEN 1 AND 10", name="ck_dataset_acquisition_file_count"
        ),
        sa.CheckConstraint(
            "raw_retention_days BETWEEN 1 AND 90", name="ck_dataset_acquisition_retention"
        ),
    )
    for column in ("state", "created_by", "created_at"):
        op.create_index(
            f"ix_dataset_acquisition_plans_{column}", "dataset_acquisition_plans", [column]
        )

    op.execute(
        """
        CREATE FUNCTION aegis_dataset_acquisition_plan_immutable()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'dataset acquisition proposals are immutable';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_dataset_acquisition_plan_immutable
        BEFORE UPDATE OR DELETE ON dataset_acquisition_plans
        FOR EACH ROW EXECUTE FUNCTION aegis_dataset_acquisition_plan_immutable();
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_dataset_acquisition_plan_immutable ON dataset_acquisition_plans"
    )
    op.execute("DROP FUNCTION IF EXISTS aegis_dataset_acquisition_plan_immutable()")
    op.drop_table("dataset_acquisition_plans")
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
