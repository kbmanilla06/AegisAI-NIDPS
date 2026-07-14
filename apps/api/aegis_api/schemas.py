from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    description: str
    permissions: list[str]


class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    roles: list[str]
    version: int
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    roles: list[str] = Field(min_length=1, max_length=6)

    @field_validator("roles")
    @classmethod
    def unique_roles(cls, roles: list[str]) -> list[str]:
        if len(roles) != len(set(roles)):
            raise ValueError("roles must be unique")
        return roles


class UserStatusUpdate(BaseModel):
    is_active: bool
    expected_version: int = Field(ge=1)


class UserRolesUpdate(BaseModel):
    roles: list[str] = Field(min_length=1, max_length=6)
    expected_version: int = Field(ge=1)

    @field_validator("roles")
    @classmethod
    def unique_roles(cls, roles: list[str]) -> list[str]:
        if len(roles) != len(set(roles)):
            raise ValueError("roles must be unique")
        return roles


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class AuthResponse(BaseModel):
    user: UserOut
    permissions: list[str]
    csrf_token: str


class CurrentUserResponse(BaseModel):
    user: UserOut
    permissions: list[str]


class CsrfResponse(BaseModel):
    csrf_token: str


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str | None = Field(default=None, max_length=255)
    network_zone: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    criticality: Criticality
    is_internal: bool = True


class AssetUpdate(BaseModel):
    address: str | None = Field(default=None, max_length=255)
    network_zone: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    criticality: Criticality
    is_internal: bool
    is_active: bool
    expected_version: int = Field(ge=1)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    address: str | None
    network_zone: str
    criticality: str
    is_internal: bool
    is_active: bool
    version: int
    created_at: datetime


class SensorType(StrEnum):
    ZEEK = "zeek"
    SURICATA = "suricata"
    FLOW = "flow"


class SensorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    sensor_type: SensorType
    asset_id: UUID | None = None


class SensorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    sensor_type: str
    credential_version: int
    status: str
    schema_version: str
    asset_id: UUID | None
    last_seen_at: datetime | None
    version: int
    created_at: datetime


class SensorCredentialResponse(BaseModel):
    sensor: SensorOut
    credential: str


class SensorStatusUpdate(BaseModel):
    active: bool
    expected_version: int = Field(ge=1)


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    occurred_at: datetime
    actor_user_id: UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    correlation_id: str
    safe_metadata: dict[str, object]


class IngestionSource(StrEnum):
    NORMALIZED = "normalized"
    ZEEK = "zeek"
    SURICATA = "suricata"
    PCAP = "pcap"


class IngestionJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_type: str
    status: str
    sha256: str
    size_bytes: int
    media_type: str
    schema_version: str
    submitted_by: UUID | None
    sensor_id: UUID | None
    replay_of_id: UUID | None
    error_code: str | None
    accepted_records: int
    rejected_records: int
    duplicate_records: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    raw_expires_at: datetime | None
    raw_deleted_at: datetime | None


class FlowOut(BaseModel):
    id: UUID
    event_key: str
    schema_version: str
    source_type: str
    source_event_id: str | None
    job_id: UUID
    sensor_id: UUID | None
    event_time: datetime
    src_address: str
    dst_address: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    duration_ms: int
    packet_count: int
    byte_count: int
    state: str | None
    metadata: dict[str, object]


class IngestionMetricsOut(BaseModel):
    jobs_by_status: dict[str, int]
    accepted_records: int
    rejected_records: int
    duplicate_records: int
    delayed_jobs: int
    failed_jobs: int
