import pytest

from aegis_services.monitoring import (
    MonitoringStatus,
    SyntheticMonitoringSnapshotV1,
    canonical_hash,
    evaluate_drift,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
SCHEMA = "c" * 64


def snapshot(artifact_hash: str, value: float, samples: int = 50) -> SyntheticMonitoringSnapshotV1:
    return SyntheticMonitoringSnapshotV1(
        source_kind="synthetic_feature",
        artifact_hash=artifact_hash,
        schema_hash=SCHEMA,
        sample_count=samples,
        group_count=min(10, samples),
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-01T00:05:00Z",
        metrics={"missing_rate": {"value": value, "sample_count": samples}},
    )


def test_monitoring_is_deterministic_and_warns() -> None:
    result = evaluate_drift(snapshot(HASH_A, 0.10), snapshot(HASH_B, 0.35))
    assert result.status == MonitoringStatus.WARNING
    assert result.warning_count == 1
    assert result.critical_count == 0
    expected = evaluate_drift(snapshot(HASH_A, 0.10), snapshot(HASH_B, 0.35))
    assert result.model_dump() == expected.model_dump()
    assert canonical_hash(result.model_dump(mode="json")) == canonical_hash(
        result.model_dump(mode="json")
    )


def test_monitoring_marks_low_sample_not_evaluable() -> None:
    result = evaluate_drift(snapshot(HASH_A, 0.1, samples=2), snapshot(HASH_B, 0.9, samples=2))
    assert result.status == MonitoringStatus.NOT_EVALUABLE
    assert result.metrics[0].delta is None


def test_monitoring_rejects_unsupported_metric_and_mismatched_schema() -> None:
    with pytest.raises(ValueError):
        SyntheticMonitoringSnapshotV1(
            source_kind="synthetic_feature",
            artifact_hash=HASH_A,
            schema_hash=SCHEMA,
            sample_count=50,
            group_count=10,
            window_start="2026-01-01T00:00:00Z",
            window_end="2026-01-01T00:05:00Z",
            metrics={"raw_endpoint": {"value": 1, "sample_count": 50}},
        )
    with pytest.raises(ValueError):
        evaluate_drift(
            snapshot(HASH_A, 0.1),
            SyntheticMonitoringSnapshotV1(
                source_kind="synthetic_feature",
                artifact_hash=HASH_B,
                schema_hash="d" * 64,
                sample_count=50,
                group_count=10,
                window_start="2026-01-01T00:00:00Z",
                window_end="2026-01-01T00:05:00Z",
                metrics={"missing_rate": {"value": 0.2, "sample_count": 50}},
            ),
        )
