from pathlib import Path

import numpy as np
import pytest

from aegis_services.anomaly import (
    AnomalyAssessmentV1,
    FusionInputV1,
    SignalSource,
    build_anomaly_candidate,
    default_fusion_policy,
    fuse_assessment,
)
from aegis_services.features import feature_schema
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS, build_synthetic_dataset


@pytest.fixture(scope="module")
def anomaly_evidence(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    schema = feature_schema("sprint4")
    return build_anomaly_candidate(
        build_synthetic_dataset(schema), schema, tmp_path_factory.mktemp("anomaly")
    )


def _signal(source: SignalSource, score: float, number: int) -> FusionInputV1:
    return FusionInputV1(
        source=source,
        signal_id=f"00000000-0000-0000-0000-{number:012d}",
        source_version_hash="a" * 64,
        score=score,
        category="reconnaissance" if source != SignalSource.ANOMALY else "unusual_behavior",
        evidence_hash="b" * 64,
    )


def test_anomaly_candidate_is_bounded_and_synthetic_only(anomaly_evidence) -> None:  # type: ignore[no-untyped-def]
    assert anomaly_evidence.detector.algorithm == "isolation_forest"
    assert anomaly_evidence.detector.training_row_count > 0
    assert len(anomaly_evidence.test_scores) == 1080
    assert all(0.0 <= value <= 1.0 for value in anomaly_evidence.test_scores)
    assert anomaly_evidence.detector.online_inference_allowed is False
    assert anomaly_evidence.detector.alert_side_effects_allowed is False
    assert anomaly_evidence.detector.prevention_allowed is False
    assert anomaly_evidence.detector.limitations == SYNTHETIC_LIMITATIONS


def test_anomaly_candidate_is_deterministic(anomaly_evidence, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    schema = feature_schema("sprint4")
    repeated = build_anomaly_candidate(build_synthetic_dataset(schema), schema, tmp_path)
    assert repeated.detector.model_sha256 == anomaly_evidence.detector.model_sha256
    assert repeated.threshold.threshold == anomaly_evidence.threshold.threshold
    assert repeated.detector.manifest_hash == anomaly_evidence.detector.manifest_hash


def test_fusion_truth_table_and_confidence_cap() -> None:
    result = fuse_assessment(
        assessment_id="a" * 16,
        source_identity_hash="c" * 64,
        anomaly_detector_hash="d" * 64,
        signals=[_signal(SignalSource.ANOMALY, 0.99, 1)],
        policy=default_fusion_policy(),
    )
    assert isinstance(result, AnomalyAssessmentV1)
    assert result.risk_score == 99
    assert result.confidence == 0.166667
    assert "SINGLE_SOURCE" in result.uncertainty_codes
    assert result.automation_eligible is False


def test_fusion_missing_and_conflicting_sources_are_explicit() -> None:
    missing = FusionInputV1(
        source=SignalSource.SUPERVISED,
        signal_id="00000000-0000-0000-0000-000000000099",
        source_version_hash="e" * 64,
        score=0.0,
        quality="absent",
        reason_codes=("MODEL_UNAVAILABLE",),
    )
    result = fuse_assessment(
        assessment_id="b" * 16,
        source_identity_hash="c" * 64,
        anomaly_detector_hash="d" * 64,
        signals=[
            _signal(SignalSource.SIGNATURE, 0.99, 2),
            _signal(SignalSource.ANOMALY, 0.01, 3),
            missing,
        ],
        policy=default_fusion_policy(),
    )
    assert result.risk_score == 79
    assert "SIGNAL_DISAGREEMENT" in result.uncertainty_codes
    assert "SOURCE_SUPERVISED_ABSENT" in result.uncertainty_codes


def test_anomaly_input_guards(anomaly_evidence) -> None:  # type: ignore[no-untyped-def]
    from aegis_services.anomaly import evaluate_anomaly_scores

    with pytest.raises(ValueError, match="resource_limit"):
        evaluate_anomaly_scores(anomaly_evidence, np.zeros((10_001, 39), dtype=np.float32))
    with pytest.raises(ValueError, match="non_finite"):
        values = np.zeros((1, 39), dtype=np.float32)
        values[0, 0] = np.nan
        evaluate_anomaly_scores(anomaly_evidence, values)
