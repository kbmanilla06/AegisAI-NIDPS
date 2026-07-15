from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="RESTRICT"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, lazy="selectin")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255))
    permissions: Mapped[list[Permission]] = relationship(
        secondary=role_permissions, lazy="selectin"
    )


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(96), unique=True)
    description: Mapped[str] = mapped_column(String(255))


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    rotated_from_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user: Mapped[User] = relationship(lazy="selectin")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    address: Mapped[str | None] = mapped_column(String(255))
    network_zone: Mapped[str] = mapped_column(String(64))
    criticality: Mapped[str] = mapped_column(String(16))
    is_internal: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Sensor(Base):
    __tablename__ = "sensors"
    __table_args__ = (UniqueConstraint("name", name="uq_sensors_name"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128))
    sensor_type: Mapped[str] = mapped_column(String(32))
    credential_hash: Mapped[str] = mapped_column(String(64))
    credential_version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="active")
    schema_version: Mapped[str] = mapped_column(String(32), default="1")
    asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('normalized','zeek','suricata','pcap')",
            name="ck_ingestion_jobs_source_type",
        ),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','rejected')",
            name="ck_ingestion_jobs_status",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_ingestion_jobs_size"),
        CheckConstraint("accepted_records >= 0", name="ck_ingestion_jobs_accepted"),
        CheckConstraint("rejected_records >= 0", name="ck_ingestion_jobs_rejected"),
        CheckConstraint("duplicate_records >= 0", name="ck_ingestion_jobs_duplicate"),
        CheckConstraint(
            "(submitted_by IS NOT NULL) <> (sensor_id IS NOT NULL)",
            name="ck_ingestion_jobs_one_actor",
        ),
        UniqueConstraint(
            "submitted_by", "idempotency_key", name="uq_ingestion_jobs_actor_idempotency"
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    source_type: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    object_ref: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(16), default="1")
    submitted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="RESTRICT"), index=True
    )
    replay_of_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    error_code: Mapped[str | None] = mapped_column(String(64))
    accepted_records: Mapped[int] = mapped_column(Integer, default=0)
    rejected_records: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_records: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    raw_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProcessedEvent(Base):
    __tablename__ = "processed_events"
    __table_args__ = (
        UniqueConstraint("event_key", "schema_version", name="uq_processed_event_identity"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_key: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(32))
    job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        UniqueConstraint("event_key", "schema_version", name="uq_flows_event_identity"),
        CheckConstraint(
            "src_port IS NULL OR src_port BETWEEN 0 AND 65535", name="ck_flows_src_port"
        ),
        CheckConstraint(
            "dst_port IS NULL OR dst_port BETWEEN 0 AND 65535", name="ck_flows_dst_port"
        ),
        CheckConstraint("duration_ms >= 0", name="ck_flows_duration"),
        CheckConstraint("packet_count >= 0", name="ck_flows_packets"),
        CheckConstraint("byte_count >= 0", name="ck_flows_bytes"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_key: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(16), default="1")
    source_type: Mapped[str] = mapped_column(String(16))
    source_event_id: Mapped[str | None] = mapped_column(String(128))
    job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="RESTRICT"), index=True
    )
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    src_address: Mapped[str] = mapped_column(String(45), index=True)
    dst_address: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    duration_ms: Mapped[int] = mapped_column(BigInteger)
    packet_count: Mapped[int] = mapped_column(BigInteger)
    byte_count: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str | None] = mapped_column(String(32))
    flow_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_key", "version", name="uq_rule_versions_key_version"),
        UniqueConstraint("definition_hash", name="uq_rule_versions_definition_hash"),
        CheckConstraint(
            "lifecycle_state IN ('draft','approved','retired')",
            name="ck_rule_versions_lifecycle",
        ),
        CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_rule_versions_severity",
        ),
        CheckConstraint("version > 0", name="ck_rule_versions_version"),
        CheckConstraint("window_seconds BETWEEN 1 AND 86400", name="ck_rule_versions_window"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    rule_key: Mapped[str] = mapped_column(String(100), index=True)
    version: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[str] = mapped_column(String(32), default="behavioral-rule/v1")
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(1000))
    category: Mapped[str] = mapped_column(String(64), index=True)
    evaluator_key: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON)
    window_seconds: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    mitre_mappings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence_contract: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    false_positive_guidance: Mapped[str] = mapped_column(String(1000))
    investigation_guidance: Mapped[str] = mapped_column(String(1000))
    prevention_recommendation: Mapped[str] = mapped_column(String(1000))
    change_rationale: Mapped[str] = mapped_column(String(500))
    definition_hash: Mapped[str] = mapped_column(String(64))
    lifecycle_state: Mapped[str] = mapped_column(String(16), default="draft")
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RuleActivation(Base):
    __tablename__ = "rule_activations"
    __table_args__ = (
        CheckConstraint(
            "action IN ('activate','deactivate','rollback')",
            name="ck_rule_activations_action",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    rule_key: Mapped[str] = mapped_column(String(100), index=True)
    rule_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rule_versions.id", ondelete="RESTRICT"), index=True
    )
    previous_rule_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rule_versions.id", ondelete="RESTRICT")
    )
    action: Mapped[str] = mapped_column(String(16))
    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reason: Mapped[str] = mapped_column(String(500))
    regression_evidence: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SignatureEvent(Base):
    __tablename__ = "signature_events"
    __table_args__ = (
        UniqueConstraint("event_key", "schema_version", name="uq_signature_event_identity"),
        CheckConstraint("reported_severity BETWEEN 1 AND 255", name="ck_signature_severity"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_key: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(32))
    job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="RESTRICT"), index=True
    )
    source_event_id: Mapped[str | None] = mapped_column(String(128))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    src_address: Mapped[str] = mapped_column(String(45))
    dst_address: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))
    signature_id: Mapped[int] = mapped_column(Integer)
    signature_revision: Mapped[int] = mapped_column(Integer)
    signature_name: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(128))
    reported_severity: Mapped[int] = mapped_column(Integer)
    reported_action: Mapped[str | None] = mapped_column(String(32))
    flow_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        UniqueConstraint("ingestion_job_id", name="uq_detection_runs_ingestion_job"),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_detection_runs_status",
        ),
        CheckConstraint("signal_count >= 0", name="ck_detection_runs_signals"),
        CheckConstraint("alert_count >= 0", name="ck_detection_runs_alerts"),
        CheckConstraint("suppressed_count >= 0", name="ck_detection_runs_suppressed"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    ingestion_job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    source_job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    rule_set_hash: Mapped[str | None] = mapped_column(String(64))
    signal_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionSignal(Base):
    __tablename__ = "detection_signals"
    __table_args__ = (
        UniqueConstraint("semantic_key", name="uq_detection_signals_semantic_key"),
        CheckConstraint(
            "source_type IN ('behavioral_rule','suricata_signature')",
            name="ck_detection_signals_source_type",
        ),
        CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_detection_signals_severity",
        ),
        CheckConstraint("observed_value >= 0", name="ck_detection_signals_observed"),
        CheckConstraint("threshold_value >= 0", name="ck_detection_signals_threshold"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    semantic_key: Mapped[str] = mapped_column(String(64))
    series_key: Mapped[str] = mapped_column(String(64), index=True)
    detection_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="RESTRICT"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(32))
    rule_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rule_versions.id", ondelete="RESTRICT"), index=True
    )
    signature_event_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("signature_events.id", ondelete="SET NULL"), index=True
    )
    category: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="RESTRICT"), index=True
    )
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    bucket_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    grouping: Mapped[dict[str, Any]] = mapped_column(JSON)
    observed_value: Mapped[int] = mapped_column(BigInteger)
    threshold_value: Mapped[int] = mapped_column(BigInteger)
    evidence_event_keys: Mapped[list[str]] = mapped_column(JSON)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    data_quality: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_alerts_fingerprint"),
        CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')",
            name="ck_alerts_severity",
        ),
        CheckConstraint("status = 'new'", name="ck_alerts_sprint3_status"),
        CheckConstraint("occurrence_count > 0", name="ck_alerts_occurrence_count"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64))
    fingerprint_schema: Mapped[str] = mapped_column(String(32), default="alert-fingerprint/v1")
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    rule_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rule_versions.id", ondelete="RESTRICT"), index=True
    )
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="RESTRICT"), index=True
    )
    grouping: Mapped[dict[str, Any]] = mapped_column(JSON)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    evidence_overflow_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_overflow_hash: Mapped[str | None] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    __table_args__ = (UniqueConstraint("alert_id", "signal_id", name="uq_alert_evidence_signal"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), index=True)
    signal_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("detection_signals.id", ondelete="SET NULL"), index=True
    )
    evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class FeatureSchemaVersion(Base):
    __tablename__ = "feature_schema_versions"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_feature_schema_name_version"),
        UniqueConstraint("definition_hash", name="uq_feature_schema_definition_hash"),
        CheckConstraint(
            "lifecycle_state IN ('draft','approved','retired')",
            name="ck_feature_schema_lifecycle",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(32))
    input_schema: Mapped[str] = mapped_column(String(32))
    ordered_definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    preprocessing_config: Mapped[dict[str, Any]] = mapped_column(JSON)
    banned_fields: Mapped[list[str]] = mapped_column(JSON)
    definition_hash: Mapped[str] = mapped_column(String(64))
    code_version: Mapped[str] = mapped_column(String(64))
    lifecycle_state: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_reason: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_dataset_name_version"),
        UniqueConstraint("manifest_hash", name="uq_dataset_manifest_hash"),
        CheckConstraint("status IN ('proposed','accepted','retired')", name="ck_dataset_status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    official_source_url: Mapped[str] = mapped_column(String(512))
    publisher: Mapped[str] = mapped_column(String(128))
    intended_use: Mapped[str] = mapped_column(String(64))
    terms_reference_hash: Mapped[str] = mapped_column(String(64))
    citation_required: Mapped[bool] = mapped_column(Boolean, default=True)
    commercial_approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    acquisition_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DatasetSplitVersion(Base):
    __tablename__ = "dataset_split_versions"
    __table_args__ = (
        UniqueConstraint("manifest_hash", name="uq_dataset_split_manifest_hash"),
        CheckConstraint("train_count > 0", name="ck_dataset_split_train"),
        CheckConstraint("validation_count > 0", name="ck_dataset_split_validation"),
        CheckConstraint("test_count > 0", name="ck_dataset_split_test"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dataset_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="RESTRICT"), index=True
    )
    strategy: Mapped[str] = mapped_column(String(32))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest_hash: Mapped[str] = mapped_column(String(64))
    train_count: Mapped[int] = mapped_column(BigInteger)
    validation_count: Mapped[int] = mapped_column(BigInteger)
    test_count: Mapped[int] = mapped_column(BigInteger)
    reviewed_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DatasetAcquisitionPlan(Base):
    __tablename__ = "dataset_acquisition_plans"
    __table_args__ = (
        UniqueConstraint("manifest_hash", name="uq_dataset_acquisition_manifest_hash"),
        CheckConstraint("state = 'proposed'", name="ck_dataset_acquisition_preapproval_state"),
        CheckConstraint(
            "combined_byte_limit BETWEEN 1 AND 5368709120",
            name="ck_dataset_acquisition_combined_limit",
        ),
        CheckConstraint(
            "file_byte_limit BETWEEN 1 AND 2147483648", name="ck_dataset_acquisition_file_limit"
        ),
        CheckConstraint(
            "file_count_limit BETWEEN 1 AND 10", name="ck_dataset_acquisition_file_count"
        ),
        CheckConstraint(
            "raw_retention_days BETWEEN 1 AND 90", name="ck_dataset_acquisition_retention"
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dataset_name: Mapped[str] = mapped_column(String(128))
    dataset_version: Mapped[str] = mapped_column(String(64))
    official_page_url: Mapped[str] = mapped_column(String(512))
    source_review_hash: Mapped[str] = mapped_column(String(64))
    terms_reference_hash: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(24), default="proposed", index=True)
    combined_byte_limit: Mapped[int] = mapped_column(BigInteger)
    file_byte_limit: Mapped[int] = mapped_column(BigInteger)
    file_count_limit: Mapped[int] = mapped_column(Integer)
    raw_retention_days: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SyntheticGenerationJob(Base):
    __tablename__ = "synthetic_generation_jobs"
    __table_args__ = (
        UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_synthetic_job_actor_idempotency"
        ),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_job_status",
        ),
        CheckConstraint("requested_flow_count = 7200", name="ck_synthetic_job_flow_count"),
        CheckConstraint("generated_flow_count BETWEEN 0 AND 10000", name="ck_synthetic_generated"),
        CheckConstraint("generated_group_count BETWEEN 0 AND 120", name="ck_synthetic_groups"),
        CheckConstraint("global_seed = 20260714", name="ck_synthetic_seed"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    feature_schema_id: Mapped[UUID] = mapped_column(
        ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    scenario_catalog_hash: Mapped[str] = mapped_column(String(64))
    global_seed: Mapped[int] = mapped_column(BigInteger, default=20260714)
    requested_flow_count: Mapped[int] = mapped_column(Integer, default=7200)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    generated_flow_count: Mapped[int] = mapped_column(Integer, default=0)
    generated_group_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyntheticDatasetVersion(Base):
    __tablename__ = "synthetic_dataset_versions"
    __table_args__ = (
        UniqueConstraint("generation_job_id", name="uq_synthetic_dataset_generation_job"),
        UniqueConstraint("manifest_hash", name="uq_synthetic_dataset_manifest_hash"),
        UniqueConstraint("split_manifest_hash", name="uq_synthetic_split_manifest_hash"),
        CheckConstraint(
            "lifecycle_state IN ('generated','accepted_synthetic','rejected','retired')",
            name="ck_synthetic_dataset_lifecycle",
        ),
        CheckConstraint("flow_count = 7200", name="ck_synthetic_dataset_flow_count"),
        CheckConstraint("group_count = 120", name="ck_synthetic_dataset_group_count"),
        CheckConstraint("feature_column_count = 46", name="ck_synthetic_feature_columns"),
        CheckConstraint("retention_days = 30", name="ck_synthetic_dataset_retention"),
        CheckConstraint(
            "reviewed_by IS NULL OR reviewed_by <> created_by",
            name="ck_synthetic_distinct_reviewer",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    generation_job_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_generation_jobs.id", ondelete="RESTRICT"), index=True
    )
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    feature_schema_id: Mapped[UUID] = mapped_column(
        ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(32))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest_hash: Mapped[str] = mapped_column(String(64))
    target_manifest_hash: Mapped[str] = mapped_column(String(64))
    split_manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    split_manifest_hash: Mapped[str] = mapped_column(String(64))
    quality_report: Mapped[dict[str, Any]] = mapped_column(JSON)
    quality_report_hash: Mapped[str] = mapped_column(String(64))
    leakage_report: Mapped[dict[str, Any]] = mapped_column(JSON)
    leakage_report_hash: Mapped[str] = mapped_column(String(64))
    flow_object_ref: Mapped[str] = mapped_column(String(36))
    flow_sha256: Mapped[str] = mapped_column(String(64))
    flow_size_bytes: Mapped[int] = mapped_column(BigInteger)
    target_object_ref: Mapped[str] = mapped_column(String(36))
    target_sha256: Mapped[str] = mapped_column(String(64))
    target_size_bytes: Mapped[int] = mapped_column(BigInteger)
    feature_object_ref: Mapped[str] = mapped_column(String(36))
    feature_sha256: Mapped[str] = mapped_column(String(64))
    feature_size_bytes: Mapped[int] = mapped_column(BigInteger)
    feature_column_count: Mapped[int] = mapped_column(Integer, default=46)
    flow_count: Mapped[int] = mapped_column(Integer)
    group_count: Mapped[int] = mapped_column(Integer)
    lifecycle_state: Mapped[str] = mapped_column(String(24), default="generated", index=True)
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_reason: Mapped[str | None] = mapped_column(String(500))
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    artifacts_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SyntheticTrainingRun(Base):
    __tablename__ = "synthetic_training_runs"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key", name="uq_synthetic_training_actor_key"),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_training_status",
        ),
        CheckConstraint("threshold = 0.5", name="ck_synthetic_training_threshold"),
        CheckConstraint("retention_days = 30", name="ck_synthetic_training_retention"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dataset_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_dataset_versions.id", ondelete="RESTRICT"), index=True
    )
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    threshold: Mapped[float] = mapped_column(default=0.5)
    selected_algorithm: Mapped[str | None] = mapped_column(String(32))
    selected_candidate_hash: Mapped[str | None] = mapped_column(String(64))
    test_opening_hash: Mapped[str | None] = mapped_column(String(64))
    test_opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyntheticModelCandidate(Base):
    __tablename__ = "synthetic_model_candidates"
    __table_args__ = (
        UniqueConstraint("training_run_id", "algorithm", name="uq_synthetic_candidate_algorithm"),
        UniqueConstraint("model_sha256", name="uq_synthetic_candidate_model_hash"),
        CheckConstraint(
            "algorithm IN ('logistic_regression','random_forest')",
            name="ck_synthetic_candidate_algorithm",
        ),
        CheckConstraint(
            "lifecycle_state = 'unreviewed_candidate'", name="ck_synthetic_candidate_state"
        ),
        CheckConstraint(
            "model_size_bytes BETWEEN 1 AND 16777216", name="ck_synthetic_candidate_size"
        ),
        CheckConstraint(
            "metadata_size_bytes BETWEEN 1 AND 16777216",
            name="ck_synthetic_candidate_metadata_size",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    training_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_training_runs.id", ondelete="RESTRICT"), index=True
    )
    algorithm: Mapped[str] = mapped_column(String(32))
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), default="unreviewed_candidate", index=True
    )
    model_object_ref: Mapped[str] = mapped_column(String(64))
    model_sha256: Mapped[str] = mapped_column(String(64))
    model_size_bytes: Mapped[int] = mapped_column(BigInteger)
    metadata_object_ref: Mapped[str] = mapped_column(String(64))
    metadata_sha256: Mapped[str] = mapped_column(String(64))
    metadata_size_bytes: Mapped[int] = mapped_column(BigInteger)
    preprocessor_hash: Mapped[str] = mapped_column(String(64))
    evaluation_hash: Mapped[str] = mapped_column(String(64))
    model_card_hash: Mapped[str] = mapped_column(String(64))
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON)
    selected: Mapped[bool] = mapped_column(default=False)
    artifacts_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SyntheticRegistryModel(Base):
    __tablename__ = "synthetic_registry_models"
    __table_args__ = (
        UniqueConstraint("candidate_id", name="uq_synthetic_registry_candidate"),
        CheckConstraint(
            "lifecycle_state IN ('reviewed_synthetic','rejected','quarantined','retired')",
            name="ck_synthetic_registry_state",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    candidate_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_model_candidates.id", ondelete="RESTRICT"), index=True
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(24), default="reviewed_synthetic", index=True
    )
    purpose: Mapped[str] = mapped_column(String(64), default="synthetic_demo_offline")
    reviewed_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    review_reason: Mapped[str] = mapped_column(String(512))
    evidence_reference: Mapped[str] = mapped_column(String(128))
    candidate_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SyntheticScoringJob(Base):
    __tablename__ = "synthetic_scoring_jobs"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key", name="uq_synthetic_scoring_actor_key"),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_synthetic_scoring_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    registry_model_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_registry_models.id", ondelete="RESTRICT"), index=True
    )
    dataset_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("synthetic_dataset_versions.id", ondelete="RESTRICT"), index=True
    )
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    predicted_counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeatureMaterializationJob(Base):
    __tablename__ = "feature_materialization_jobs"
    __table_args__ = (
        UniqueConstraint(
            "requested_by", "idempotency_key", name="uq_feature_job_actor_idempotency"
        ),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="ck_feature_job_status",
        ),
        CheckConstraint("requested_limit BETWEEN 1 AND 10000", name="ck_feature_job_limit"),
        CheckConstraint("input_count >= 0", name="ck_feature_job_input_count"),
        CheckConstraint("output_count >= 0", name="ck_feature_job_output_count"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    feature_schema_id: Mapped[UUID] = mapped_column(
        ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_job_id: Mapped[UUID] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    requested_limit: Mapped[int] = mapped_column(Integer, default=10_000)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    input_count: Mapped[int] = mapped_column(Integer, default=0)
    output_count: Mapped[int] = mapped_column(Integer, default=0)
    source_snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    quality_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeatureArtifact(Base):
    __tablename__ = "feature_artifacts"
    __table_args__ = (
        UniqueConstraint("materialization_job_id", name="uq_feature_artifact_job"),
        UniqueConstraint("object_ref", name="uq_feature_artifact_ref"),
        CheckConstraint("size_bytes >= 0", name="ck_feature_artifact_size"),
        CheckConstraint("row_count > 0", name="ck_feature_artifact_rows"),
        CheckConstraint("column_count BETWEEN 1 AND 128", name="ck_feature_artifact_columns"),
        CheckConstraint("status IN ('available','deleted')", name="ck_feature_artifact_status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    materialization_job_id: Mapped[UUID] = mapped_column(
        ForeignKey("feature_materialization_jobs.id", ondelete="RESTRICT"), index=True
    )
    feature_schema_id: Mapped[UUID] = mapped_column(
        ForeignKey("feature_schema_versions.id", ondelete="RESTRICT"), index=True
    )
    object_ref: Mapped[str] = mapped_column(String(36))
    media_type: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    row_count: Mapped[int] = mapped_column(BigInteger)
    column_count: Mapped[int] = mapped_column(Integer)
    source_snapshot_hash: Mapped[str] = mapped_column(String(64))
    code_version: Mapped[str] = mapped_column(String(64))
    retention_class: Mapped[str] = mapped_column(String(32), default="feature_30d")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(16), default="available", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AnomalyDetectorVersion(Base):
    """Immutable, synthetic-only Isolation Forest candidate metadata."""

    __tablename__ = "anomaly_detector_versions"
    __table_args__ = (
        UniqueConstraint("manifest_hash", name="uq_anomaly_detector_manifest"),
        CheckConstraint(
            "lifecycle_state IN ("
            "'unreviewed_candidate','reviewed_synthetic','rejected','quarantined','retired')",
            name="ck_anomaly_detector_state",
        ),
        CheckConstraint("model_size_bytes BETWEEN 0 AND 16777216", name="ck_anomaly_detector_size"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), default="unreviewed_candidate", index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    algorithm: Mapped[str] = mapped_column(String(32), default="isolation_forest")
    feature_schema_hash: Mapped[str] = mapped_column(String(64))
    preprocessor_hash: Mapped[str] = mapped_column(String(64))
    dataset_content_hash: Mapped[str] = mapped_column(String(64))
    split_manifest_hash: Mapped[str] = mapped_column(String(64))
    training_identity_hash: Mapped[str] = mapped_column(String(64))
    normal_identity_hash: Mapped[str] = mapped_column(String(64))
    manifest_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    model_object_ref: Mapped[str | None] = mapped_column(String(64))
    model_sha256: Mapped[str | None] = mapped_column(String(64))
    model_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    metadata_object_ref: Mapped[str | None] = mapped_column(String(64))
    metadata_sha256: Mapped[str | None] = mapped_column(String(64))
    metadata_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    threshold_hash: Mapped[str | None] = mapped_column(String(64))
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    review_reason: Mapped[str | None] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    error_code: Mapped[str | None] = mapped_column(String(64))
    artifacts_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AnomalyThresholdVersion(Base):
    __tablename__ = "anomaly_threshold_versions"
    __table_args__ = (UniqueConstraint("threshold_hash", name="uq_anomaly_threshold_hash"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    detector_id: Mapped[UUID] = mapped_column(
        ForeignKey("anomaly_detector_versions.id", ondelete="RESTRICT"), index=True
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    review_reason: Mapped[str | None] = mapped_column(String(512))
    detector_manifest_hash: Mapped[str] = mapped_column(String(64))
    threshold_hash: Mapped[str] = mapped_column(String(64))
    threshold: Mapped[float] = mapped_column()
    validation_identity_hash: Mapped[str] = mapped_column(String(64))
    validation_reference_count: Mapped[int] = mapped_column(Integer)
    lifecycle_state: Mapped[str] = mapped_column(String(24), default="candidate", index=True)
    test_opened_once: Mapped[bool] = mapped_column(Boolean, default=True)
    limitations: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EnsemblePolicyVersion(Base):
    __tablename__ = "ensemble_policy_versions"
    __table_args__ = (UniqueConstraint("policy_hash", name="uq_ensemble_policy_hash"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    version: Mapped[str] = mapped_column(String(32))
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    policy_hash: Mapped[str] = mapped_column(String(64))
    lifecycle_state: Mapped[str] = mapped_column(String(24), default="draft", index=True)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    reviewed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    review_reason: Mapped[str | None] = mapped_column(String(512))
    limitations: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssessmentBatch(Base):
    __tablename__ = "assessment_batches"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key", name="uq_assessment_actor_key"),
        CheckConstraint("row_count BETWEEN 0 AND 10000", name="ck_assessment_rows"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    requested_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    dataset_content_hash: Mapped[str] = mapped_column(String(64))
    feature_artifact_hash: Mapped[str] = mapped_column(String(64))
    anomaly_detector_hash: Mapped[str] = mapped_column(String(64))
    threshold_hash: Mapped[str] = mapped_column(String(64))
    policy_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    aggregate: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64))
    limitations: Mapped[str] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DecisionAssessment(Base):
    __tablename__ = "decision_assessments"
    __table_args__ = (
        UniqueConstraint("batch_id", "source_identity_hash", name="uq_decision_batch_source"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_decision_risk"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_decision_confidence"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    batch_id: Mapped[UUID] = mapped_column(
        ForeignKey("assessment_batches.id", ondelete="RESTRICT"), index=True
    )
    source_identity_hash: Mapped[str] = mapped_column(String(64))
    policy_hash: Mapped[str] = mapped_column(String(64))
    anomaly_detector_hash: Mapped[str] = mapped_column(String(64))
    source_scores: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column()
    severity: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(64))
    uncertainty_codes: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    limitations: Mapped[str] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    action: Mapped[str] = mapped_column(String(96), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
