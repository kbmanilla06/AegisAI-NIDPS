import pytest

from aegis_services.explainability import (
    EXPLANATION_LIMITATIONS,
    AttributionDirection,
    ExplanationMethod,
    ExplanationMethodV1,
    ExplanationV1,
    FeatureAttributionV1,
)
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS


def _method() -> ExplanationMethodV1:
    return ExplanationMethodV1(
        method=ExplanationMethod.PERMUTATION_OCCLUSION,
        target_algorithm="isolation_forest",
        feature_schema_hash="a" * 64,
        top_k=10,
    )


def _attr(feature: str, magnitude: float) -> FeatureAttributionV1:
    return FeatureAttributionV1(
        feature_key=feature,
        raw_value=1.0,
        transformed_meaning="bounded flow count",
        direction=AttributionDirection.INCREASE,
        magnitude=magnitude,
        uncertainty=0.1,
    )


def _explanation(attributions: tuple[FeatureAttributionV1, ...], summary: str) -> ExplanationV1:
    return ExplanationV1(
        explanation_id="0" * 32,
        method_hash="b" * 64,
        target_model_hash="c" * 64,
        source_identity_hash="d" * 64,
        subject_score=0.8,
        baseline_score=0.2,
        attributions=attributions,
        analyst_summary=summary,
    )


def test_method_is_hash_bound_and_synthetic_only() -> None:
    method = _method()
    assert method.method_hash == _method().method_hash
    assert method.online_inference_allowed is False
    assert method.model_activation_used is False
    assert method.external_lookup_used is False
    assert method.limitations == EXPLANATION_LIMITATIONS
    assert SYNTHETIC_LIMITATIONS in method.limitations


def test_method_top_k_is_bounded() -> None:
    with pytest.raises(ValueError):
        ExplanationMethodV1(
            method=ExplanationMethod.NATIVE_IMPORTANCE,
            target_algorithm="random_forest",
            feature_schema_hash="a" * 64,
            top_k=40,
        )


def test_explanation_requires_descending_magnitudes() -> None:
    with pytest.raises(ValueError, match="unordered"):
        _explanation(
            (_attr("flow_count", 0.2), _attr("byte_count", 0.9)),
            "Higher flow count is associated with a higher anomaly score.",
        )


def test_explanation_rejects_duplicate_feature() -> None:
    with pytest.raises(ValueError, match="duplicate_feature"):
        _explanation(
            (_attr("flow_count", 0.9), _attr("flow_count", 0.2)),
            "Flow count is associated with the anomaly score.",
        )


def test_explanation_rejects_causal_language() -> None:
    for summary in (
        "This flow is malicious.",
        "High byte count causes the anomaly.",
        "The score proves an attacker is present.",
    ):
        with pytest.raises(ValueError, match="causal_language"):
            _explanation((_attr("byte_count", 0.9),), summary)


def test_explanation_accepts_association_language_and_is_hash_bound() -> None:
    explanation = _explanation(
        (_attr("byte_count", 0.9), _attr("flow_count", 0.4)),
        "A higher byte count is associated with a higher synthetic anomaly score.",
    )
    assert explanation.association_only is True
    assert explanation.prevention_allowed is False
    assert (
        explanation.explanation_hash
        == _explanation(
            (_attr("byte_count", 0.9), _attr("flow_count", 0.4)),
            "A higher byte count is associated with a higher synthetic anomaly score.",
        ).explanation_hash
    )


def test_attribution_rejects_non_finite() -> None:
    with pytest.raises(ValueError):
        FeatureAttributionV1(
            feature_key="flow_count",
            raw_value=float("nan"),
            transformed_meaning="bounded flow count",
            direction=AttributionDirection.NEUTRAL,
            magnitude=0.5,
            uncertainty=0.1,
        )
