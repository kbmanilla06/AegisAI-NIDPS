from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from aegis_services.monitoring import (
    FALSE_CAPABILITY_FLAGS as MONITORING_FALSE_CAPABILITY_FLAGS,
)
from aegis_services.monitoring import (
    MONITORING_LIMITATIONS,
    DriftPolicyV1,
    SyntheticMonitoringSnapshotV1,
)
from aegis_services.observability import (
    FALSE_CAPABILITY_FLAGS as OBSERVABILITY_FALSE_CAPABILITY_FLAGS,
)
from aegis_services.observability import (
    OBSERVABILITY_LIMITATIONS,
    REPORT_TYPES,
)
from aegis_services.prevention import (
    FALSE_CAPABILITY_FLAGS,
    PREVENTION_LIMITATIONS,
    PreventionActionType,
    PreventionTargetType,
)
from aegis_services.soc import (
    SOC_LIMITATIONS,
    AlertDisposition,
    AlertStatus,
    IncidentStatus,
)
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS


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


class DatasetAcquisitionPlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    dataset_name: str
    dataset_version: str
    official_page_url: str
    source_review_hash: str
    terms_reference_hash: str
    manifest_hash: str
    state: str
    combined_byte_limit: int
    file_byte_limit: int
    file_count_limit: int
    raw_retention_days: int
    created_by: UUID
    created_at: datetime


class SyntheticGenerationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_schema_id: UUID


class SyntheticGenerationJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    feature_schema_id: UUID
    scenario_catalog_hash: str
    global_seed: int
    requested_flow_count: int
    status: str
    generated_flow_count: int
    generated_group_count: int
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_acquired: bool = False
    unsw_nb15_evaluated: bool = False
    network_traffic_generated: bool = False
    online_inference_allowed: bool = False
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False


class SyntheticDatasetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    generation_job_id: UUID
    feature_schema_id: UUID
    name: str
    version: str
    manifest_hash: str
    target_manifest_hash: str
    split_manifest_hash: str
    quality_report_hash: str
    leakage_report_hash: str
    flow_count: int
    group_count: int
    feature_column_count: int
    lifecycle_state: str
    quality_report: dict[str, object]
    leakage_report: dict[str, object]
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_reason: str | None
    expires_at: datetime
    artifacts_deleted_at: datetime | None
    created_at: datetime
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_acquired: bool = False
    unsw_nb15_evaluated: bool = False
    network_traffic_generated: bool = False
    online_inference_allowed: bool = False
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False


class SyntheticDatasetReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool
    reason: str = Field(min_length=10, max_length=500)
    evidence_reference: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


class SyntheticTrainingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_version_id: UUID


class SyntheticTrainingRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    dataset_version_id: UUID
    status: str
    threshold: float
    selected_algorithm: str | None
    selected_candidate_hash: str | None
    test_opening_hash: str | None
    test_opened_at: datetime | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_evaluated: bool = False
    online_inference_allowed: bool = False
    scoring_allowed: bool = False
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False


class SyntheticCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    training_run_id: UUID
    algorithm: str
    lifecycle_state: str
    model_sha256: str
    model_size_bytes: int
    preprocessor_hash: str
    evaluation_hash: str
    model_card_hash: str
    selected: bool
    created_at: datetime
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_acquired: bool = False
    unsw_nb15_evaluated: bool = False
    network_traffic_generated: bool = False
    online_inference_allowed: bool = False
    scoring_allowed: bool = False
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False


class SyntheticRegistryReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accepted: bool
    reason: str = Field(min_length=8, max_length=512)
    evidence_reference: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


class SyntheticRegistryModelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    candidate_id: UUID
    lifecycle_state: str
    purpose: str
    reviewed_by: UUID
    candidate_hash: str
    expires_at: datetime
    created_at: datetime
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_acquired: bool = False
    unsw_nb15_evaluated: bool = False
    online_inference_allowed: bool = False
    scoring_allowed: bool = True
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False

    @model_validator(mode="after")
    def enforce_lifecycle_capabilities(self) -> "SyntheticRegistryModelOut":
        if self.lifecycle_state != "reviewed_synthetic":
            self.scoring_allowed = False
        return self


class SyntheticScoringCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registry_model_id: UUID
    dataset_version_id: UUID


class SyntheticScoringJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    registry_model_id: UUID
    dataset_version_id: UUID
    status: str
    row_count: int
    predicted_counts: dict[str, object]
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    limitations: str = SYNTHETIC_LIMITATIONS
    synthetic_demo_only: bool = True
    real_dataset_used: bool = False
    unsw_nb15_acquired: bool = False
    unsw_nb15_evaluated: bool = False
    online_inference_allowed: bool = False
    scoring_allowed: bool = True
    alert_side_effects_allowed: bool = False
    prevention_allowed: bool = False


class MonitoringRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: str = Field(pattern=r"^[a-z_]+$")
    baseline: SyntheticMonitoringSnapshotV1
    current: SyntheticMonitoringSnapshotV1
    policy: DriftPolicyV1 = Field(default_factory=DriftPolicyV1)

    @model_validator(mode="after")
    def validate_source(self) -> "MonitoringRunCreate":
        if (
            self.source_kind != self.baseline.source_kind
            or self.source_kind != self.current.source_kind
        ):
            raise ValueError("source_kind must match both snapshots")
        return self


class MonitoringRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    requested_by: UUID
    source_kind: str
    schema_version: str
    baseline_snapshot_hash: str | None
    current_snapshot_hash: str | None
    policy_hash: str | None
    result: dict[str, object]
    status: str
    sample_count: int
    group_count: int
    warning_count: int
    critical_count: int
    error_code: str | None
    limitations: str = MONITORING_LIMITATIONS
    false_capability_flags: dict[str, bool] = MONITORING_FALSE_CAPABILITY_FLAGS
    synthetic_demo_only: bool = True
    created_at: datetime
    completed_at: datetime | None


class MonitoringMetricOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    metric_key: str
    baseline_value: float | None
    current_value: float | None
    delta: float | None
    sample_count: int
    status: str


class FeedbackDisposition(StrEnum):
    CONFIRMED_SYNTHETIC_INTRUSION = "confirmed_synthetic_intrusion_like"
    CONFIRMED_SYNTHETIC_BENIGN = "confirmed_synthetic_benign_like"
    FALSE_POSITIVE = "false_positive_demo"
    FALSE_NEGATIVE = "false_negative_demo"
    INSUFFICIENT = "insufficient_evidence"
    NEEDS_REVIEW = "needs_review"


class AnalystFeedbackCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    monitoring_run_id: UUID
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: FeedbackDisposition
    reason_code: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    note: str = Field(min_length=1, max_length=1000)


class AnalystFeedbackReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool
    reason: str = Field(min_length=8, max_length=500)


class AnalystFeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    monitoring_run_id: UUID
    evidence_hash: str
    disposition: str
    reason_code: str
    note: str
    status: str
    created_by: UUID
    reviewed_by: UUID | None
    review_reason: str | None
    expires_at: datetime
    created_at: datetime
    reviewed_at: datetime | None
    limitations: str = MONITORING_LIMITATIONS
    false_capability_flags: dict[str, bool] = MONITORING_FALSE_CAPABILITY_FLAGS
    synthetic_demo_only: bool = True


class ObservabilityReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: str = Field(pattern=r"^[a-z_]{1,48}$")
    window_start: datetime
    window_end: datetime

    @field_validator("report_type")
    @classmethod
    def report_type_allowed(cls, value: str) -> str:
        if value not in REPORT_TYPES:
            raise ValueError("unsupported observability report type")
        return value

    @model_validator(mode="after")
    def window_valid(self) -> "ObservabilityReportRequest":
        if self.window_end < self.window_start:
            raise ValueError("report window is invalid")
        if (self.window_end - self.window_start).days > 31:
            raise ValueError("report window is too large")
        return self


class ObservabilityFinalizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=8, max_length=500)


class ObservabilityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    correlation_id: str
    component: str
    operation: str
    status: str
    duration_ms: float
    rows: int
    groups_count: int
    tasks: int
    bytes_count: int
    actor_role: str
    safe_error_code: str | None
    policy_version: str
    evidence_hashes: list[str]
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = OBSERVABILITY_FALSE_CAPABILITY_FLAGS
    expires_at: datetime
    created_at: datetime


class ObservabilitySnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    window_start: datetime
    window_end: datetime
    policy_version: str
    metrics: dict[str, float]
    dimensions: dict[str, str]
    sample_count: int
    source_hashes: list[str]
    status: str
    snapshot_hash: str
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = OBSERVABILITY_FALSE_CAPABILITY_FLAGS
    expires_at: datetime
    created_at: datetime


class ObservabilityReportJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    report_type: str
    status: str
    report_id: UUID | None
    error_code: str | None
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = OBSERVABILITY_FALSE_CAPABILITY_FLAGS
    created_at: datetime
    completed_at: datetime | None


class ObservabilityReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    report_type: str
    status: str
    payload: dict[str, object]
    report_hash: str
    source_hashes: list[str]
    policy_version: str
    finalized_by: UUID | None
    finalized_at: datetime | None
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = OBSERVABILITY_FALSE_CAPABILITY_FLAGS
    expires_at: datetime
    created_at: datetime


class ObservabilityRecoveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    outcome: dict[str, object]
    safe_error_code: str | None
    correlation_id: str
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = OBSERVABILITY_FALSE_CAPABILITY_FLAGS
    created_at: datetime
    completed_at: datetime | None


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
    # Sprint 8 SOC workflow band.
    assignee_id: UUID | None = None
    disposition: str | None = None
    closed_at: datetime | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def limitations(self) -> str:
        return SOC_LIMITATIONS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def prevention_allowed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def enforcement_authority(self) -> bool:
        return False


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


class AnomalyDetectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    lifecycle_state: str
    status: str
    algorithm: str
    feature_schema_hash: str
    dataset_content_hash: str
    split_manifest_hash: str
    training_identity_hash: str
    normal_identity_hash: str
    manifest_hash: str | None
    model_sha256: str | None
    model_size_bytes: int
    threshold_hash: str | None
    safe_metadata: dict[str, object]
    error_code: str | None
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None


class AnomalyFitCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preprocessor_hash: str = Field(default="0" * 64, pattern=r"^[a-f0-9]{64}$")


class AnomalyReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
    reason: str = Field(min_length=8, max_length=512)


class EnsemblePolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: str
    definition: dict[str, object]
    policy_hash: str
    lifecycle_state: str
    reviewed_by: UUID | None
    review_reason: str | None
    limitations: str
    created_at: datetime


class AssessmentBatchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_artifact_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    anomaly_detector_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    threshold_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class AssessmentBatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    dataset_content_hash: str
    feature_artifact_hash: str
    anomaly_detector_hash: str
    threshold_hash: str
    policy_hash: str
    row_count: int
    aggregate: dict[str, object]
    error_code: str | None
    limitations: str
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None


# --- Sprint 7: explainability and threat-intelligence API contracts ---


class ExplanationMethodOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    method: str
    target_algorithm: str
    feature_schema_hash: str
    top_k: int
    method_hash: str
    lifecycle_state: str
    reviewed_by: UUID | None
    review_reason: str | None
    limitations: str
    created_at: datetime


class ExplanationMethodCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top_k: int = Field(default=10, ge=1, le=39)


class SprintSevenReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
    reason: str = Field(min_length=8, max_length=512)


class ExplanationBatchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ExplanationBatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    method_hash: str
    target_model_hash: str
    row_count: int
    aggregate: dict[str, object]
    error_code: str | None
    limitations: str
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None


class ExplanationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    batch_id: UUID
    source_identity_hash: str
    subject_score: float
    baseline_score: float
    attributions: list[dict[str, object]]
    analyst_summary: str
    limitations: str
    created_at: datetime


class IntelligenceSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    trust_level: str
    terms_reference_hash: str
    enabled: bool
    source_hash: str
    lifecycle_state: str
    reviewed_by: UUID | None
    limitations: str
    created_at: datetime


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: UUID
    indicator_type: str
    value_hash: str
    indicator_hash: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime
    lifecycle_state: str
    limitations: str
    created_at: datetime


class MatchBatchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class MatchBatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    source_hash: str
    match_count: int
    aggregate: dict[str, object]
    error_code: str | None
    limitations: str
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None


class MitreTechniqueCatalogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    catalog_version: str
    catalog_hash: str
    techniques: list[dict[str, object]]
    lifecycle_state: str
    created_at: datetime


class MitreMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    catalog_id: UUID
    technique_id: str
    evidence_class: str
    catalog_hash: str
    rationale: str
    mapping_version: str
    confidence: str
    lifecycle_state: str
    limitations: str


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    fingerprint: str
    source_type: str
    category: str
    severity: str
    status: str
    occurrence_count: int
    assignee_id: UUID | None
    disposition: str | None
    closed_at: datetime | None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def limitations(self) -> str:
        return SOC_LIMITATIONS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def prevention_allowed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def enforcement_authority(self) -> bool:
        return False


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Optimistic lock: the caller states the status it believes it is transitioning from.
    expected_status: AlertStatus
    status: AlertStatus
    disposition: AlertDisposition | None = None


class AlertAssign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee_id: UUID


class AlertNoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=4096)


class AlertNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: UUID
    author_id: UUID
    body: str
    created_at: datetime


class IncidentCorrelateResponse(BaseModel):
    created: int
    updated: int
    incident_ids: list[UUID]
    synthetic_demo_only: bool = True
    prevention_allowed: bool = False


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    correlation_key: str
    correlation_version: str
    category: str
    status: str
    owner_id: UUID | None
    disposition: str | None
    alert_count: int
    expires_at: datetime
    created_at: datetime
    updated_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def limitations(self) -> str:
        return SOC_LIMITATIONS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def prevention_allowed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def enforcement_authority(self) -> bool:
        return False


class IncidentTimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_type: str
    detail: dict[str, object]
    actor_id: UUID | None
    created_at: datetime


class IncidentDetailOut(IncidentOut):
    member_alert_ids: list[UUID]
    timeline: list[IncidentTimelineOut]


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_status: IncidentStatus
    status: IncidentStatus
    disposition: AlertDisposition | None = None


class IncidentAssign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_id: UUID


# ---------------------------------------------------------------------------
# Sprint 9 prevention simulation (simulation-only; no enforcement).
# ---------------------------------------------------------------------------

_REDACTED_TARGET = "[redacted-target]"


class PreventionPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    version: str
    definition_hash: str
    lifecycle: str
    max_duration_seconds: int
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def limitations(self) -> str:
        return PREVENTION_LIMITATIONS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def false_capability_flags(self) -> dict[str, bool]:
        return dict(FALSE_CAPABILITY_FLAGS)


class PreventionRollbackPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=512)
    steps: list[str] = Field(default_factory=list, max_length=32)


class PreventionRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: UUID | None = None
    incident_id: UUID | None = None
    # Optional supplementary threat-intelligence indicator (never sole proof).
    indicator_id: UUID | None = None
    action_type: PreventionActionType
    target_type: PreventionTargetType
    target_value: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=1024)
    # Positive-bounded; the policy maximum is enforced by the Duration gate.
    duration_seconds: int = Field(gt=0, le=2_592_000)
    rollback_plan: PreventionRollbackPlan

    @model_validator(mode="after")
    def _require_evidence_ref(self) -> "PreventionRequestCreate":
        if self.alert_id is None and self.incident_id is None:
            raise ValueError("prevention_request_requires_alert_or_incident")
        return self


class GateResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    gate_key: str
    passed: bool
    reason_code: str
    evidence_ref: str | None


class PreventionPreviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    adapter: str
    representation: dict[str, object]
    validated_at: datetime


class PreventionExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    mode: str
    result: str
    verify: dict[str, object]
    started_at: datetime
    completed_at: datetime


class PreventionRollbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_id: UUID
    result: str
    requested_at: datetime
    completed_at: datetime


class PreventionRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    action_type: str
    target_type: str
    target_value: str
    reason: str
    duration_seconds: int
    expires_at: datetime
    policy_version_id: UUID
    alert_id: UUID | None
    incident_id: UUID | None
    indicator_id: UUID | None
    created_at: datetime
    updated_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def mode(self) -> str:
        return "simulation"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def limitations(self) -> str:
        return PREVENTION_LIMITATIONS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def prevention_allowed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def enforcement_authority(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def false_capability_flags(self) -> dict[str, bool]:
        return dict(FALSE_CAPABILITY_FLAGS)

    def redacted(self, *, allowed: bool) -> "PreventionRequestOut":
        """Return a copy with the target hidden when the viewer lacks sensitive read."""
        if allowed:
            return self
        return self.model_copy(update={"target_value": _REDACTED_TARGET})


class PreventionRequestDetailOut(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    request: PreventionRequestOut
    gate_results: list[GateResultOut]
    preview: PreventionPreviewOut | None
    execution: PreventionExecutionOut | None
    rollback: PreventionRollbackOut | None
