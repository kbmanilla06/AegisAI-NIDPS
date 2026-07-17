"""Synthetic-only anomaly evidence contracts and deterministic scoring.

The API imports contracts and hash metadata without importing native ML runtimes.
Detector functions are lazy exports and load only in the ML-enabled worker.
"""

from typing import Any

from .fusion import default_fusion_policy, fuse_assessment
from .schema import (
    ANOMALY_LIMITATIONS,
    GATE_5SA_HASHES,
    AnomalyAssessmentV1,
    AnomalyDetectorManifestV1,
    AnomalyThresholdV1,
    FusionInputV1,
    FusionPolicyV1,
    SignalSource,
)

_DETECTOR_EXPORTS = {
    "AnomalyBuildResult",
    "build_anomaly_candidate",
    "encode_feature_matrix",
    "evaluate_anomaly_scores",
    "validate_anomaly_onnx",
}


def __getattr__(name: str) -> Any:
    if name in _DETECTOR_EXPORTS:
        from . import detector

        return getattr(detector, name)
    raise AttributeError(name)


__all__ = [
    "ANOMALY_LIMITATIONS",
    "GATE_5SA_HASHES",
    "AnomalyAssessmentV1",
    "AnomalyDetectorManifestV1",
    "AnomalyThresholdV1",
    "FusionInputV1",
    "FusionPolicyV1",
    "SignalSource",
    "default_fusion_policy",
    "fuse_assessment",
    *_DETECTOR_EXPORTS,
]
