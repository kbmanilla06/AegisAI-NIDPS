"""Synthetic-only anomaly evidence contracts and deterministic scoring."""

from .detector import (
    GATE_5SA_HASHES,
    AnomalyBuildResult,
    build_anomaly_candidate,
    evaluate_anomaly_scores,
    validate_anomaly_onnx,
)
from .fusion import default_fusion_policy, fuse_assessment
from .schema import (
    ANOMALY_LIMITATIONS,
    AnomalyAssessmentV1,
    AnomalyDetectorManifestV1,
    AnomalyThresholdV1,
    FusionInputV1,
    FusionPolicyV1,
    SignalSource,
)

__all__ = [
    "ANOMALY_LIMITATIONS",
    "GATE_5SA_HASHES",
    "AnomalyAssessmentV1",
    "AnomalyBuildResult",
    "AnomalyDetectorManifestV1",
    "AnomalyThresholdV1",
    "FusionInputV1",
    "FusionPolicyV1",
    "SignalSource",
    "build_anomaly_candidate",
    "default_fusion_policy",
    "evaluate_anomaly_scores",
    "fuse_assessment",
    "validate_anomaly_onnx",
]
