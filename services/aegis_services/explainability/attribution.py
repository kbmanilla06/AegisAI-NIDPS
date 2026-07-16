from __future__ import annotations

import hashlib

import numpy as np

from aegis_services.anomaly import (
    AnomalyBuildResult,
    encode_feature_matrix,
    evaluate_anomaly_scores,
)
from aegis_services.features import FeatureSchemaV1
from aegis_services.synthetic import SyntheticBuildResult, SyntheticLabel

from .schema import (
    AttributionDirection,
    ExplanationMethod,
    ExplanationMethodV1,
    ExplanationV1,
    FeatureAttributionV1,
)

# Deltas below this magnitude are treated as no contribution; keeps the
# attribution deterministic and avoids presenting numerical noise as evidence.
_EPSILON = 1e-9


def _training_normal_matrix(result: SyntheticBuildResult, schema: FeatureSchemaV1) -> np.ndarray:
    rows = [
        vector
        for vector, example in zip(result.vectors, result.examples, strict=True)
        if example.target.partition.value == "training"
        and example.target.label == SyntheticLabel.BENIGN_LIKE
    ]
    if len(rows) < 10:
        raise ValueError("explanation_reference_population_too_small")
    return encode_feature_matrix(rows, schema)


def explanation_method(schema: FeatureSchemaV1, *, top_k: int = 10) -> ExplanationMethodV1:
    return ExplanationMethodV1(
        method=ExplanationMethod.PERMUTATION_OCCLUSION,
        target_algorithm="isolation_forest",
        feature_schema_hash=schema.definition_hash,
        top_k=top_k,
    )


def _direction(delta: float) -> AttributionDirection:
    if delta > _EPSILON:
        return AttributionDirection.INCREASE
    if delta < -_EPSILON:
        return AttributionDirection.DECREASE
    return AttributionDirection.NEUTRAL


def _summary(feature_key: str, direction: AttributionDirection) -> str:
    verb = {
        AttributionDirection.INCREASE: "a higher",
        AttributionDirection.DECREASE: "a lower",
        AttributionDirection.NEUTRAL: "the observed",
    }[direction]
    return (
        f"Within synthetic scenario data, {verb} {feature_key} is associated with this "
        "example's anomaly score. This is an association, not a verdict."
    )


def explain_anomaly_example(
    candidate: AnomalyBuildResult,
    schema: FeatureSchemaV1,
    instance_row: np.ndarray,
    baseline_row: np.ndarray,
    source_identity_hash: str,
    method: ExplanationMethodV1,
) -> ExplanationV1:
    if instance_row.shape != (39,) or baseline_row.shape != (39,):
        raise ValueError("explanation_instance_shape_invalid")
    if not np.isfinite(instance_row).all() or not np.isfinite(baseline_row).all():
        raise ValueError("explanation_instance_non_finite")
    feature_names = [item.name for item in schema.features]

    # One bounded ONNX batch: row 0 is the instance, rows 1..39 replace feature i
    # with the training-median baseline (occlusion). No estimator object is loaded.
    variants = np.repeat(instance_row.reshape(1, -1), 40, axis=0).astype(np.float32)
    for index in range(39):
        variants[index + 1, index] = baseline_row[index]
    scores = evaluate_anomaly_scores(candidate, variants)
    subject_score = float(scores[0])
    deltas = subject_score - scores[1:]

    magnitudes = np.abs(deltas)
    scale = float(magnitudes.max()) if magnitudes.max() > _EPSILON else 1.0
    order = sorted(range(39), key=lambda i: (-magnitudes[i], feature_names[i]))
    top = order[: method.top_k]

    attributions: list[FeatureAttributionV1] = []
    for index in top:
        magnitude = round(float(magnitudes[index]) / scale, 6)
        attributions.append(
            FeatureAttributionV1(
                feature_key=feature_names[index],
                raw_value=round(float(instance_row[index]), 6),
                transformed_meaning=f"encoded value of {feature_names[index]}",
                direction=_direction(float(deltas[index])),
                magnitude=magnitude,
                uncertainty=round(1.0 - magnitude, 6),
            )
        )

    lead = attributions[0]
    explanation_id = hashlib.sha256(
        f"{method.method_hash}:{source_identity_hash}".encode()
    ).hexdigest()
    baseline_score = float(evaluate_anomaly_scores(candidate, baseline_row.reshape(1, -1))[0])
    return ExplanationV1(
        explanation_id=explanation_id,
        method_hash=method.method_hash,
        target_model_hash=candidate.detector.manifest_hash,
        source_identity_hash=source_identity_hash,
        subject_score=round(subject_score, 6),
        baseline_score=round(baseline_score, 6),
        attributions=tuple(attributions),
        analyst_summary=_summary(lead.feature_key, lead.direction),
    )


def explain_anomaly_batch(
    candidate: AnomalyBuildResult,
    result: SyntheticBuildResult,
    schema: FeatureSchemaV1,
    *,
    top_k: int = 10,
    max_instances: int = 64,
    partition: str = "validation",
) -> tuple[ExplanationV1, ...]:
    """Deterministically explain up to ``max_instances`` synthetic examples.

    Uses the previously-locked partitions only; the Sprint 6 sealed test is not
    reopened for tuning here, and no model object is loaded or activated.
    """
    if not 1 <= max_instances <= 10_000:
        raise ValueError("explanation_resource_limit")
    method = explanation_method(schema, top_k=top_k)
    baseline = np.median(_training_normal_matrix(result, schema), axis=0).astype(np.float32)
    selected = [
        (vector, example)
        for vector, example in zip(result.vectors, result.examples, strict=True)
        if example.target.partition.value == partition
    ][:max_instances]
    matrix = encode_feature_matrix([vector for vector, _ in selected], schema)
    return tuple(
        explain_anomaly_example(
            candidate,
            schema,
            matrix[position],
            baseline,
            example.target.example_identity_hash,
            method,
        )
        for position, (_, example) in enumerate(selected)
    )
