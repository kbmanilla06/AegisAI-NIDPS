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


class FeatureSchemaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    version: str
    input_schema: str
    ordered_definition: dict[str, object]
    preprocessing_config: dict[str, object]
    banned_fields: list[str]
    definition_hash: str
    code_version: str
    lifecycle_state: str
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_reason: str | None
    created_at: datetime


class FeatureSchemaReviewRequest(BaseModel):
    approved: bool
    reason: str = Field(min_length=10, max_length=500)
    regression_evidence: str = Field(min_length=3, max_length=255)


class FeatureJobCreate(BaseModel):
    feature_schema_id: UUID
    ingestion_job_id: UUID
    requested_limit: int = Field(default=10_000, ge=1, le=10_000)


class FeatureArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    media_type: str
    sha256: str
    size_bytes: int
    row_count: int
    column_count: int
    source_snapshot_hash: str
    retention_class: str
    expires_at: datetime
    status: str


class FeatureJobOut(BaseModel):
    id: UUID
    feature_schema_id: UUID
    ingestion_job_id: UUID
    requested_limit: int
    status: str
    input_count: int
    output_count: int
    source_snapshot_hash: str | None
    quality_summary: dict[str, object]
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    artifact: FeatureArtifactOut | None = None


class DatasetVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    version: str
    official_source_url: str
    publisher: str
    intended_use: str
    terms_reference_hash: str
    citation_required: bool
    commercial_approval_required: bool
    acquisition_authorized: bool
    manifest_hash: str
    status: str
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    created_at: datetime


class DatasetReviewRequest(BaseModel):
    accepted: bool
    reason: str = Field(min_length=10, max_length=500)


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleVersionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1000)
    category: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    evaluator_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    parameters: dict[str, object]
    window_seconds: int = Field(ge=1, le=86_400)
    severity: Severity
    mitre_mappings: list[dict[str, object]] = Field(default_factory=list, max_length=10)
    false_positive_guidance: str = Field(min_length=1, max_length=1000)
    investigation_guidance: str = Field(min_length=1, max_length=1000)
    prevention_recommendation: str = Field(min_length=1, max_length=1000)
    change_rationale: str = Field(min_length=8, max_length=500)


class RuleReviewRequest(BaseModel):
    approved: bool
    reason: str = Field(min_length=8, max_length=500)
    regression_evidence: str = Field(min_length=3, max_length=255)


class RuleActivationRequest(BaseModel):
    reason: str = Field(min_length=8, max_length=500)
    regression_evidence: str = Field(min_length=3, max_length=255)
    expected_active_version_id: UUID | None = None


class RuleRollbackRequest(RuleActivationRequest):
    target_version_id: UUID


class RuleVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_key: str
    version: int
    schema_version: str
    name: str
    description: str
    category: str
    evaluator_key: str
    parameters: dict[str, object]
    window_seconds: int
    severity: str
    mitre_mappings: list[dict[str, object]]
    false_positive_guidance: str
    investigation_guidance: str
    prevention_recommendation: str
    change_rationale: str
    definition_hash: str
    lifecycle_state: str
    is_active: bool
    created_by: UUID | None
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    created_at: datetime


class AlertSummaryOut(BaseModel):
    id: UUID
    source_type: str
    category: str
    severity: str
    status: str
    grouping: dict[str, object]
    occurrence_count: int
    evidence_overflow_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    rule_version_id: UUID | None


class AlertEvidenceOut(BaseModel):
    id: UUID
    evidence_snapshot: dict[str, object]
    evidence_hash: str
    occurred_at: datetime


class AlertDetailOut(AlertSummaryOut):
    fingerprint: str
    fingerprint_schema: str
    evidence: list[AlertEvidenceOut]


class DetectionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    ingestion_job_id: UUID
    source_job_id: UUID
    status: str
    rule_set_hash: str | None
    signal_count: int
    alert_count: int
    suppressed_count: int
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class DetectionMetricsOut(BaseModel):
    runs_by_status: dict[str, int]
    signals: int
    alerts: int
    occurrences: int
    suppressed: int
