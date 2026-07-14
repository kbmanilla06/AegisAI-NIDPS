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
    schema_version: Mapped[str] = mapped_column(String(16))
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
