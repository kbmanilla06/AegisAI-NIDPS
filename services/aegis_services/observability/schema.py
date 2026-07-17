from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_services.monitoring import (
    ACCEPTED_SYNTHETIC_ARTIFACT_HASHES,
    MONITORING_LIMITATIONS,
)

OBSERVABILITY_LIMITATIONS = MONITORING_LIMITATIONS
FALSE_CAPABILITY_FLAGS = {
    "real_dataset_used": False,
    "unsw_nb15_acquired": False,
    "live_capture_enabled": False,
    "online_inference_allowed": False,
    "model_activation_allowed": False,
    "alert_side_effects_allowed": False,
    "prevention_allowed": False,
}
REPORT_TYPES = frozenset(
    {
        "synthetic_quality_drift",
        "synthetic_feedback_summary",
        "synthetic_operations",
        "synthetic_retention_recovery",
        "synthetic_gate_evidence",
    }
)
SLI_METRICS = frozenset(
    {
        "api_request_count",
        "api_latency_ms_p50",
        "api_latency_ms_p95",
        "api_error_count",
        "queue_depth",
        "queue_age_seconds_p95",
        "task_success_count",
        "task_failure_count",
        "task_not_evaluable_count",
        "monitoring_stale_count",
        "monitoring_hash_mismatch_count",
        "feedback_unresolved_count",
        "artifact_integrity_failure_count",
        "retention_cleanup_success_count",
        "retention_cleanup_failure_count",
        "backup_restore_success_count",
        "backup_restore_failure_count",
        "readiness_failure_count",
    }
)
ALLOWED_DIMENSIONS = frozenset(
    {"component", "operation", "status", "source_kind", "report_type", "task_name", "role_class"}
)
ALLOWED_STATUSES = frozenset({"succeeded", "failed", "degraded", "not_evaluable"})


class ReportStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_EVALUABLE = "not_evaluable"


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _finite(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError("numeric value must be finite")
    return value


class SyntheticObservabilityEventV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: str = Field(default="synthetic-observability-event", pattern=r"^[a-z0-9-]+$")
    version: str = Field(default="1.0.0", pattern=r"^1\.0\.0$")
    event_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    correlation_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    occurred_at: datetime
    component: str = Field(pattern=r"^[a-z0-9_.-]{1,32}$")
    operation: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")
    status: str
    duration_ms: float = Field(ge=0, le=300_000)
    rows: int = Field(default=0, ge=0, le=100_000)
    groups: int = Field(default=0, ge=0, le=10_000)
    tasks: int = Field(default=0, ge=0, le=10_000)
    bytes: int = Field(default=0, ge=0, le=67_108_864)
    actor_role: str = Field(default="system", pattern=r"^[a-z0-9_. -]{1,32}$")
    safe_error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_.-]{1,64}$")
    policy_version: str = Field(default="synthetic-observability/1.0.0", max_length=64)
    evidence_hashes: list[str] = Field(default_factory=list, max_length=12)
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = FALSE_CAPABILITY_FLAGS

    @field_validator("limitations")
    @classmethod
    def limitation_is_exact(cls, value: str) -> str:
        if value != OBSERVABILITY_LIMITATIONS:
            raise ValueError("synthetic limitation text is immutable")
        return value

    @field_validator("false_capability_flags")
    @classmethod
    def flags_are_exact(cls, value: dict[str, bool]) -> dict[str, bool]:
        if value != FALSE_CAPABILITY_FLAGS:
            raise ValueError("false capability flags are immutable")
        return dict(value)

    @field_validator("status")
    @classmethod
    def status_allowed(cls, value: str) -> str:
        if value not in ALLOWED_STATUSES:
            raise ValueError("unsupported observability status")
        return value

    @field_validator("duration_ms")
    @classmethod
    def duration_finite(cls, value: float) -> float:
        return _finite(value)

    @field_validator("evidence_hashes")
    @classmethod
    def hashes_allowed(cls, value: list[str]) -> list[str]:
        if any(
            len(item) != 64 or any(char not in "0123456789abcdef" for char in item)
            for item in value
        ):
            raise ValueError("evidence hashes must be lowercase SHA-256 values")
        if any(item not in ACCEPTED_SYNTHETIC_ARTIFACT_HASHES for item in value):
            raise ValueError("evidence hash is not an accepted synthetic artifact")
        return sorted(set(value))

    @model_validator(mode="after")
    def safe_error_consistency(self) -> SyntheticObservabilityEventV1:
        if self.status == "failed" and not self.safe_error_code:
            raise ValueError("failed event requires a safe error code")
        if self.status != "failed" and self.safe_error_code:
            raise ValueError("safe error code is only valid for failed events")
        return self


class SyntheticSLISnapshotV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: str = Field(default="synthetic-sli-snapshot", pattern=r"^[a-z0-9-]+$")
    version: str = Field(default="1.0.0", pattern=r"^1\.0\.0$")
    window_start: datetime
    window_end: datetime
    policy_version: str = Field(default="synthetic-observability/1.0.0", max_length=64)
    metrics: dict[str, float] = Field(min_length=1, max_length=64)
    dimensions: dict[str, str] = Field(default_factory=dict, max_length=8)
    sample_count: int = Field(ge=0, le=100_000)
    source_hashes: list[str] = Field(default_factory=list, max_length=12)
    status: str = "succeeded"
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = FALSE_CAPABILITY_FLAGS

    @field_validator("limitations")
    @classmethod
    def limitation_is_exact(cls, value: str) -> str:
        if value != OBSERVABILITY_LIMITATIONS:
            raise ValueError("synthetic limitation text is immutable")
        return value

    @field_validator("false_capability_flags")
    @classmethod
    def flags_are_exact(cls, value: dict[str, bool]) -> dict[str, bool]:
        if value != FALSE_CAPABILITY_FLAGS:
            raise ValueError("false capability flags are immutable")
        return dict(value)

    @field_validator("metrics")
    @classmethod
    def metric_allowlist(cls, value: dict[str, float]) -> dict[str, float]:
        if not set(value).issubset(SLI_METRICS):
            raise ValueError("unsupported SLI metric")
        return {key: _finite(number) for key, number in sorted(value.items())}

    @field_validator("dimensions")
    @classmethod
    def dimensions_allowlist(cls, value: dict[str, str]) -> dict[str, str]:
        if not set(value).issubset(ALLOWED_DIMENSIONS):
            raise ValueError("unsupported SLI dimension")
        if any(
            not isinstance(item, str) or len(item) > 32 or "\n" in item for item in value.values()
        ):
            raise ValueError("dimension values are bounded")
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def valid_window(self) -> SyntheticSLISnapshotV1:
        if self.window_end < self.window_start:
            raise ValueError("window end must not precede start")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError("unsupported snapshot status")
        return self


class SyntheticAggregateReportV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: str = Field(default="synthetic-aggregate-report", pattern=r"^[a-z0-9-]+$")
    version: str = Field(default="1.0.0", pattern=r"^1\.0\.0$")
    report_type: str
    generated_at: datetime
    window_start: datetime
    window_end: datetime
    policy_version: str
    source_hashes: list[str] = Field(max_length=12)
    sections: dict[str, dict[str, Any]] = Field(min_length=1, max_length=8)
    status: ReportStatus
    limitations: str = OBSERVABILITY_LIMITATIONS
    false_capability_flags: dict[str, bool] = FALSE_CAPABILITY_FLAGS

    @field_validator("limitations")
    @classmethod
    def limitation_is_exact(cls, value: str) -> str:
        if value != OBSERVABILITY_LIMITATIONS:
            raise ValueError("synthetic limitation text is immutable")
        return value

    @field_validator("false_capability_flags")
    @classmethod
    def flags_are_exact(cls, value: dict[str, bool]) -> dict[str, bool]:
        if value != FALSE_CAPABILITY_FLAGS:
            raise ValueError("false capability flags are immutable")
        return dict(value)

    @field_validator("report_type")
    @classmethod
    def report_type_allowed(cls, value: str) -> str:
        if value not in REPORT_TYPES:
            raise ValueError("unsupported report type")
        return value

    @field_validator("source_hashes")
    @classmethod
    def source_hashes_allowed(cls, value: list[str]) -> list[str]:
        if any(item not in ACCEPTED_SYNTHETIC_ARTIFACT_HASHES for item in value):
            raise ValueError("report source is not an accepted synthetic artifact")
        return sorted(set(value))

    @model_validator(mode="after")
    def valid_window(self) -> SyntheticAggregateReportV1:
        if self.window_end < self.window_start:
            raise ValueError("report window is invalid")
        return self

    def content_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))
