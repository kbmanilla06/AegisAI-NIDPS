"""Sprint 9 prevention *simulation* tables, permission, and baseline policy.

Additive and reversible. There is no real adapter, enforcement column, or network
target anywhere here: `prevention_executions.mode` and `prevention_previews.adapter`
are check-constrained to the single literal 'simulation' (PREV-001/007/008).
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

from aegis_services.prevention import (
    DEFAULT_MAX_DURATION_SECONDS,
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_VERSION,
    PREVENTION_LIMITATIONS,
    default_policy_definition,
    default_policy_hash,
)

revision: str = "0012_sprint9_prevention_sim"
down_revision: str | None = "0011_sprint8_alert_incident_soc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION_KEY = "prevention:simulate"
PERMISSION_ID = "10000000-0000-0000-0000-000000000060"
# Requester needs an explicit simulation permission (Authorization gate). Read/manage
# are reused from Sprint 1; only the request/preview/simulate/rollback verb is new.
GRANT_ROLES = {
    "Senior Analyst": "00000000-0000-0000-0000-000000000003",
    "Security Administrator": "00000000-0000-0000-0000-000000000004",
    "System Administrator": "00000000-0000-0000-0000-000000000005",
}
POLICY_ID = "20000000-0000-0000-0000-000000000901"


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
            {
                "id": UUID(PERMISSION_ID),
                "key": PERMISSION_KEY,
                "description": f"Allows {PERMISSION_KEY}",
            }
        ],
    )
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": UUID(role_id), "permission_id": UUID(PERMISSION_ID)}
            for role_id in GRANT_ROLES.values()
        ],
    )

    op.create_table(
        "prevention_policy_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("definition_hash", sa.String(64), nullable=False),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("lifecycle", sa.String(16), nullable=False, server_default="reviewed"),
        sa.Column("limitations", sa.String(2048), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("reviewed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("name", "version", name="uq_prevention_policy_name_version"),
        sa.CheckConstraint(
            "lifecycle IN ('draft','reviewed','retired')", name="ck_prevention_policy_lifecycle"
        ),
        sa.CheckConstraint("max_duration_seconds > 0", name="ck_prevention_policy_max_duration"),
        sa.CheckConstraint(
            "reviewed_by IS NULL OR reviewed_by <> created_by",
            name="ck_prevention_policy_reviewer_distinct",
        ),
    )
    op.create_index("ix_prevention_policy_versions_name", "prevention_policy_versions", ["name"])

    op.create_table(
        "allowlist_entries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_value", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_allowlist_entries_target_value", "allowlist_entries", ["target_value"])

    op.create_table(
        "prevention_requests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id", ondelete="RESTRICT")),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="RESTRICT")),
        sa.Column("indicator_id", sa.Uuid(), sa.ForeignKey("indicators.id", ondelete="RESTRICT")),
        sa.Column(
            "policy_version_id",
            sa.Uuid(),
            sa.ForeignKey("prevention_policy_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(48), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_value", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rollback_plan", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("limitations", sa.String(2048), nullable=False),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("idempotency_key", name="uq_prevention_requests_idempotency"),
        sa.CheckConstraint("duration_seconds > 0", name="ck_prevention_requests_duration"),
        sa.CheckConstraint(
            "status IN ('draft','evaluated','rejected','previewed','simulated',"
            "'expired','rolled_back')",
            name="ck_prevention_requests_status",
        ),
        sa.CheckConstraint(
            "alert_id IS NOT NULL OR incident_id IS NOT NULL",
            name="ck_prevention_requests_evidence_ref",
        ),
    )
    op.create_index("ix_prevention_requests_status", "prevention_requests", ["status"])

    op.create_table(
        "policy_gate_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "request_id",
            sa.Uuid(),
            sa.ForeignKey("prevention_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("gate_key", sa.String(48), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("evidence_ref", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("request_id", "gate_key", name="uq_policy_gate_results_gate"),
    )
    op.create_index("ix_policy_gate_results_request_id", "policy_gate_results", ["request_id"])

    op.create_table(
        "prevention_previews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "request_id",
            sa.Uuid(),
            sa.ForeignKey("prevention_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("adapter", sa.String(32), nullable=False, server_default="simulation"),
        sa.Column("representation", sa.JSON(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("request_id", name="uq_prevention_previews_request"),
        sa.CheckConstraint("adapter = 'simulation'", name="ck_prevention_previews_adapter"),
    )

    op.create_table(
        "prevention_executions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "request_id",
            sa.Uuid(),
            sa.ForeignKey("prevention_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("mode", sa.String(16), nullable=False, server_default="simulation"),
        sa.Column("result", sa.String(32), nullable=False, server_default="simulated"),
        sa.Column("verify", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("request_id", name="uq_prevention_executions_request"),
        sa.CheckConstraint("mode = 'simulation'", name="ck_prevention_executions_mode"),
    )

    op.create_table(
        "prevention_rollbacks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "execution_id",
            sa.Uuid(),
            sa.ForeignKey("prevention_executions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("result", sa.String(32), nullable=False, server_default="rolled_back"),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("execution_id", name="uq_prevention_rollbacks_execution"),
    )

    # Seed the single reviewed baseline policy. Its definition is immutable; a change
    # is a new version, never an in-place edit.
    policy_versions = sa.table(
        "prevention_policy_versions",
        sa.column("id", sa.Uuid()),
        sa.column("name"),
        sa.column("version"),
        sa.column("definition", sa.JSON()),
        sa.column("definition_hash"),
        sa.column("max_duration_seconds"),
        sa.column("lifecycle"),
        sa.column("limitations"),
    )
    op.bulk_insert(
        policy_versions,
        [
            {
                "id": UUID(POLICY_ID),
                "name": DEFAULT_POLICY_NAME,
                "version": DEFAULT_POLICY_VERSION,
                "definition": default_policy_definition(),
                "definition_hash": default_policy_hash(),
                "max_duration_seconds": DEFAULT_MAX_DURATION_SECONDS,
                "lifecycle": "reviewed",
                "limitations": PREVENTION_LIMITATIONS,
            }
        ],
    )


def downgrade() -> None:
    # Refuse to drop the simulation lifecycle while any live (non-terminal) request or
    # any execution/rollback inventory remains; Sprints 0–8 objects are untouched.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM prevention_requests
                WHERE status NOT IN ('rejected','expired','rolled_back')
            )
            OR EXISTS (SELECT 1 FROM prevention_executions) THEN
                RAISE EXCEPTION
                    'resolve open prevention simulation inventory before downgrade';
            END IF;
        END $$;
        """
    )
    op.drop_table("prevention_rollbacks")
    op.drop_table("prevention_executions")
    op.drop_table("prevention_previews")
    op.drop_index("ix_policy_gate_results_request_id", table_name="policy_gate_results")
    op.drop_table("policy_gate_results")
    op.drop_index("ix_prevention_requests_status", table_name="prevention_requests")
    op.drop_table("prevention_requests")
    op.drop_index("ix_allowlist_entries_target_value", table_name="allowlist_entries")
    op.drop_table("allowlist_entries")
    op.drop_index("ix_prevention_policy_versions_name", table_name="prevention_policy_versions")
    op.drop_table("prevention_policy_versions")

    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    op.execute(
        role_permissions.delete().where(role_permissions.c.permission_id == UUID(PERMISSION_ID))
    )
    op.execute(permissions.delete().where(permissions.c.id == UUID(PERMISSION_ID)))
