from __future__ import annotations

import hashlib
import json
import math
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MONITORING_LIMITATIONS = (
    "SYNTHETIC DEMO ONLY. Monitoring evidence is derived from project-generated synthetic "
    "metadata and offline artifacts. It does not measure real-network drift, UNSW-NB15 "
    "performance, production readiness, or prevention suitability. Monitoring cannot activate "
    "models or create or modify alerts, detections, incidents, or prevention actions."
)
FALSE_CAPABILITY_FLAGS: dict[str, bool] = {
    "real_dataset_used": False,
    "unsw_nb15_acquired": False,
    "live_capture_enabled": False,
    "online_inference_allowed": False,
    "model_activation_allowed": False,
    "alert_side_effects_allowed": False,
    "prevention_allowed": False,
}
ACCEPTED_SYNTHETIC_ARTIFACT_HASHES = frozenset(
    {
        "72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87",
        "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114",
        "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a",
        "96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac",
        "90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70",
        "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9",
        "d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895",
        "c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4",
        "2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d",
        "25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7",
        "96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f",
        "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4",
    }
)
ALLOWED_SOURCE_KINDS = frozenset(
    {"synthetic_flow", "synthetic_feature", "synthetic_score", "synthetic_anomaly"}
)
ALLOWED_METRIC_KEYS = frozenset(
    {
        "row_count",
        "group_count",
        "missing_rate",
        "unseen_rate",
        "range_failure_rate",
        "duplicate_rate",
        "score_mean",
        "score_stddev",
        "positive_rate",
        "latency_ms_p50",
        "latency_ms_p95",
    }
)


class MonitoringStatus(StrEnum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    NOT_EVALUABLE = "not_evaluable"


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


class MetricSnapshotV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: float = Field(ge=0, le=1_000_000_000)
    sample_count: int = Field(ge=0, le=10_000)

    @field_validator("value")
    @classmethod
    def finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("metric value must be finite")
        return value


class SyntheticMonitoringSnapshotV1(BaseModel):
    """Aggregate-only snapshot; raw rows, addresses, payloads, and paths are prohibited."""

    model_config = ConfigDict(extra="forbid")

    contract: str = Field(default="synthetic-monitoring-snapshot", pattern=r"^[a-z0-9-]+$")
    version: str = Field(default="1.0.0", pattern=r"^1\.0\.0$")
    source_kind: str = Field(pattern=r"^[a-z_]+$")
    artifact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sample_count: int = Field(ge=0, le=10_000)
    group_count: int = Field(ge=0, le=120)
    window_start: str = Field(min_length=20, max_length=40)
    window_end: str = Field(min_length=20, max_length=40)
    metrics: dict[str, MetricSnapshotV1] = Field(min_length=1, max_length=32)

    @field_validator("source_kind")
    @classmethod
    def source_kind_allowed(cls, value: str) -> str:
        if value not in ALLOWED_SOURCE_KINDS:
            raise ValueError("unsupported synthetic source kind")
        return value

    @field_validator("metrics")
    @classmethod
    def metric_keys_allowed(cls, value: dict[str, MetricSnapshotV1]) -> dict[str, MetricSnapshotV1]:
        if not set(value).issubset(ALLOWED_METRIC_KEYS):
            raise ValueError("unsupported monitoring metric")
        return value

    @model_validator(mode="after")
    def counts_are_consistent(self) -> SyntheticMonitoringSnapshotV1:
        if self.sample_count == 0 and any(metric.sample_count for metric in self.metrics.values()):
            raise ValueError("zero-row snapshot cannot contain sampled metrics")
        if self.group_count > self.sample_count and self.sample_count > 0:
            raise ValueError("group count cannot exceed sample count")
        if self.window_end < self.window_start:
            raise ValueError("window end must not precede start")
        return self


class DriftPolicyV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_key: str = Field(default="synthetic-drift-default", pattern=r"^[a-z0-9-]+$")
    version: str = Field(default="1.0.0", pattern=r"^1\.0\.0$")
    minimum_samples: int = Field(default=30, ge=1, le=10_000)
    warning_delta: float = Field(default=0.20, gt=0, le=1_000_000_000)
    critical_delta: float = Field(default=0.50, gt=0, le=1_000_000_000)

    @model_validator(mode="after")
    def ordered_thresholds(self) -> DriftPolicyV1:
        if self.critical_delta < self.warning_delta:
            raise ValueError("critical threshold must be at least warning threshold")
        return self


class MetricResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric_key: str
    baseline_value: float | None
    current_value: float | None
    delta: float | None
    status: MonitoringStatus
    sample_count: int


class MonitoringResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: str = "synthetic-monitoring-result"
    version: str = "1.0.0"
    status: MonitoringStatus
    policy_hash: str
    baseline_snapshot_hash: str
    current_snapshot_hash: str
    metrics: list[MetricResultV1]
    warning_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    limitations: str = MONITORING_LIMITATIONS
    false_capability_flags: dict[str, bool] = FALSE_CAPABILITY_FLAGS


def evaluate_drift(
    baseline: SyntheticMonitoringSnapshotV1,
    current: SyntheticMonitoringSnapshotV1,
    policy: DriftPolicyV1 | None = None,
) -> MonitoringResultV1:
    policy = policy or DriftPolicyV1()
    if baseline.source_kind != current.source_kind or baseline.schema_hash != current.schema_hash:
        raise ValueError("monitoring snapshots must use the same source and schema")
    baseline_hash = canonical_hash(baseline.model_dump(mode="json"))
    current_hash = canonical_hash(current.model_dump(mode="json"))
    policy_hash = canonical_hash(policy.model_dump(mode="json"))
    metric_keys = sorted(set(baseline.metrics) | set(current.metrics))
    results: list[MetricResultV1] = []
    warnings = 0
    criticals = 0
    not_evaluable = (
        baseline.sample_count < policy.minimum_samples
        or current.sample_count < policy.minimum_samples
    )
    for key in metric_keys:
        left = baseline.metrics.get(key)
        right = current.metrics.get(key)
        samples = min(left.sample_count if left else 0, right.sample_count if right else 0)
        if left is None or right is None or not_evaluable or samples < policy.minimum_samples:
            status = MonitoringStatus.NOT_EVALUABLE
            delta = None
        else:
            delta = abs(right.value - left.value)
            if delta >= policy.critical_delta:
                status = MonitoringStatus.CRITICAL
                criticals += 1
            elif delta >= policy.warning_delta:
                status = MonitoringStatus.WARNING
                warnings += 1
            else:
                status = MonitoringStatus.OK
        results.append(
            MetricResultV1(
                metric_key=key,
                baseline_value=left.value if left else None,
                current_value=right.value if right else None,
                delta=delta,
                status=status,
                sample_count=samples,
            )
        )
    status = (
        MonitoringStatus.NOT_EVALUABLE
        if not_evaluable or any(item.status == MonitoringStatus.NOT_EVALUABLE for item in results)
        else MonitoringStatus.CRITICAL
        if criticals
        else MonitoringStatus.WARNING
        if warnings
        else MonitoringStatus.OK
    )
    return MonitoringResultV1(
        status=status,
        policy_hash=policy_hash,
        baseline_snapshot_hash=baseline_hash,
        current_snapshot_hash=current_hash,
        metrics=results,
        warning_count=warnings,
        critical_count=criticals,
    )
