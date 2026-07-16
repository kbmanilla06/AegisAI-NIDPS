import numpy as np
import pytest

from aegis_services.anomaly import build_anomaly_candidate
from aegis_services.explainability import (
    ExplanationV1,
    explain_anomaly_batch,
    explanation_method,
)
from aegis_services.explainability.attribution import explain_anomaly_example
from aegis_services.features import feature_schema
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS, build_synthetic_dataset


@pytest.fixture(scope="module")
def candidate(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    schema = feature_schema("sprint4")
    result = build_synthetic_dataset(schema)
    built = build_anomaly_candidate(result, schema, tmp_path_factory.mktemp("explain"))
    return schema, result, built


def test_explanations_are_bounded_and_synthetic_only(candidate) -> None:  # type: ignore[no-untyped-def]
    schema, result, built = candidate
    explanations = explain_anomaly_batch(built, result, schema, top_k=10, max_instances=6)
    assert len(explanations) == 6
    for explanation in explanations:
        assert isinstance(explanation, ExplanationV1)
        assert 1 <= len(explanation.attributions) <= 10
        assert 0.0 <= explanation.subject_score <= 1.0
        assert 0.0 <= explanation.baseline_score <= 1.0
        assert explanation.association_only is True
        assert explanation.online_inference_allowed is False
        assert explanation.prevention_allowed is False
        assert SYNTHETIC_LIMITATIONS in explanation.limitations
        magnitudes = [item.magnitude for item in explanation.attributions]
        assert magnitudes == sorted(magnitudes, reverse=True)
        assert all(0.0 <= item.magnitude <= 1.0 for item in explanation.attributions)


def test_explanations_are_deterministic(candidate) -> None:  # type: ignore[no-untyped-def]
    schema, result, built = candidate
    first = explain_anomaly_batch(built, result, schema, top_k=8, max_instances=4)
    second = explain_anomaly_batch(built, result, schema, top_k=8, max_instances=4)
    assert [e.explanation_hash for e in first] == [e.explanation_hash for e in second]


def test_top_k_is_respected(candidate) -> None:  # type: ignore[no-untyped-def]
    schema, result, built = candidate
    explanations = explain_anomaly_batch(built, result, schema, top_k=3, max_instances=3)
    assert all(len(e.attributions) == 3 for e in explanations)


def test_method_binds_feature_schema(candidate) -> None:  # type: ignore[no-untyped-def]
    schema, _result, _built = candidate
    method = explanation_method(schema, top_k=10)
    assert method.feature_schema_hash == schema.definition_hash
    assert method.method_hash == explanation_method(schema, top_k=10).method_hash


def test_instance_shape_and_finiteness_are_guarded(candidate) -> None:  # type: ignore[no-untyped-def]
    schema, _result, built = candidate
    method = explanation_method(schema)
    good = np.zeros(39, dtype=np.float32)
    with pytest.raises(ValueError, match="shape"):
        explain_anomaly_example(
            built, schema, np.zeros(38, dtype=np.float32), good, "a" * 64, method
        )
    bad = np.zeros(39, dtype=np.float32)
    bad[0] = np.nan
    with pytest.raises(ValueError, match="non_finite"):
        explain_anomaly_example(built, schema, bad, good, "a" * 64, method)
