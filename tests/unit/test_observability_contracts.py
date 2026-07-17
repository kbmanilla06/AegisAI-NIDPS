from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegis_services.observability import (
    OBSERVABILITY_LIMITATIONS,
    SyntheticAggregateReportV1,
    SyntheticObservabilityEventV1,
    SyntheticSLISnapshotV1,
)

FEATURE_HASH = "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9"


def test_observability_contracts_are_closed_and_synthetic_only() -> None:
    event = SyntheticObservabilityEventV1(
        event_id=str(uuid4()),
        correlation_id=str(uuid4()),
        occurred_at=datetime.now(UTC),
        component="reporting",
        operation="report.generate",
        status="succeeded",
        duration_ms=10,
        evidence_hashes=[FEATURE_HASH],
    )
    assert event.limitations == OBSERVABILITY_LIMITATIONS
    assert event.false_capability_flags["prevention_allowed"] is False

    snapshot = SyntheticSLISnapshotV1(
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        metrics={"task_success_count": 3},
        sample_count=30,
        source_hashes=[FEATURE_HASH],
    )
    assert snapshot.metrics == {"task_success_count": 3.0}

    report = SyntheticAggregateReportV1(
        report_type="synthetic_operations",
        generated_at=snapshot.window_end,
        window_start=snapshot.window_start,
        window_end=snapshot.window_end,
        policy_version="synthetic-observability/1.0.0",
        source_hashes=[FEATURE_HASH],
        sections={"synthetic_operations": {"status": "complete", "event_count": 1}},
        status="complete",
    )
    assert len(report.content_hash()) == 64


def test_observability_contract_rejects_sensitive_or_unaccepted_inputs() -> None:
    with pytest.raises(ValidationError):
        SyntheticObservabilityEventV1(
            event_id=str(uuid4()),
            correlation_id=str(uuid4()),
            occurred_at=datetime.now(UTC),
            component="reporting",
            operation="report.generate",
            status="succeeded",
            duration_ms=1,
            evidence_hashes=["f" * 64],
        )
    with pytest.raises(ValidationError):
        SyntheticSLISnapshotV1(
            window_start=datetime(2026, 1, 1, tzinfo=UTC),
            window_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            metrics={"raw_endpoint": 1},
            sample_count=30,
        )
