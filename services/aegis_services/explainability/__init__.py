"""Synthetic-only, offline explainability contracts and deterministic attribution."""

from .attribution import (
    explain_anomaly_batch,
    explain_anomaly_example,
    explanation_method,
)
from .schema import (
    EXPLANATION_LIMITATIONS,
    AttributionDirection,
    ExplanationMethod,
    ExplanationMethodV1,
    ExplanationV1,
    FeatureAttributionV1,
)

__all__ = [
    "EXPLANATION_LIMITATIONS",
    "AttributionDirection",
    "ExplanationMethod",
    "ExplanationMethodV1",
    "ExplanationV1",
    "FeatureAttributionV1",
    "explain_anomaly_batch",
    "explain_anomaly_example",
    "explanation_method",
]
