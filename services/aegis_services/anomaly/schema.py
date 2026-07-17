from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis_services.features import canonical_hash
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

ANOMALY_LIMITATIONS = SYNTHETIC_LIMITATIONS

# Accepted Gate 5S-A identities are lightweight metadata. Keeping them in the
# schema module lets the API validate hash bindings without importing NumPy,
# ONNX, or scikit-learn; those native runtimes remain worker-only dependencies.
GATE_5SA_HASHES = {
    "scenario_catalog": "72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87",
    "feature_schema": "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114",
    "dataset_content": "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a",
    "feature_artifact": "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9",
    "split_manifest": "d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895",
    "training_identity": "25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7",
    "validation_identity": "96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f",
    "test_identity": "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4",
}


class SignalSource(StrEnum):
    SIGNATURE = "signature"
    BEHAVIORAL_RULE = "behavioral_rule"
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    INTELLIGENCE = "intelligence"
    ASSET_CRITICALITY = "asset_criticality"
    HISTORICAL_BEHAVIOR = "historical_behavior"


class AnomalyDetectorManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["anomaly-detector-manifest/v1"] = "anomaly-detector-manifest/v1"
    algorithm: Literal["isolation_forest"] = "isolation_forest"
    feature_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    preprocessor_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    split_manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    training_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    normal_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    normal_population: Literal["synthetic_benign_like_training_only"] = (
        "synthetic_benign_like_training_only"
    )
    seed: Literal[20260714] = 20260714
    estimators: Literal[100] = 100
    max_samples: int = Field(ge=1, le=256)
    max_features: float = Field(ge=0.01, le=1.0)
    bootstrap: Literal[False] = False
    threads: Literal[1] = 1
    training_row_count: int = Field(ge=1, le=10_000)
    model_object_ref: str = Field(pattern=r"^[a-f0-9]{32}$")
    model_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    model_size_bytes: int = Field(ge=1, le=16_777_216)
    score_lower_anchor: float = Field(ge=0.0, le=1.0)
    score_upper_anchor: float = Field(ge=0.0, le=1.0)
    threshold_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    limitations: str = ANOMALY_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    unsw_nb15_acquired: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_anchors(self) -> AnomalyDetectorManifestV1:
        if self.score_lower_anchor >= self.score_upper_anchor:
            raise ValueError("anomaly_score_anchors_invalid")
        return self

    @property
    def manifest_hash(self) -> str:
        return canonical_hash(self)


class AnomalyThresholdV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["anomaly-threshold/v1"] = "anomaly-threshold/v1"
    detector_manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy: Literal["validation_normal_quantile"] = "validation_normal_quantile"
    quantile: float = Field(default=0.95, ge=0.95, le=0.95)
    threshold: float = Field(ge=0.0, le=1.0)
    validation_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    validation_reference_count: int = Field(ge=1, le=10_000)
    test_opened_once: Literal[True] = True
    limitations: str = ANOMALY_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @property
    def threshold_hash(self) -> str:
        return canonical_hash(self)


class FusionInputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["fusion-input/v1"] = "fusion-input/v1"
    source: SignalSource
    signal_id: str = Field(pattern=r"^[a-f0-9-]{1,64}$")
    source_version_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    score: float = Field(ge=0.0, le=1.0)
    quality: Literal["valid", "absent", "stale", "incompatible"] = "valid"
    category: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    severity: str | None = Field(default=None, max_length=16, pattern=r"^[a-z]+$")
    evidence_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    reason_codes: tuple[str, ...] = Field(default=(), max_length=12)

    @model_validator(mode="after")
    def require_valid_provenance(self) -> FusionInputV1:
        if self.quality == "valid" and (self.evidence_hash is None or self.category is None):
            raise ValueError("fusion_valid_signal_requires_evidence_and_category")
        return self


class FusionPolicyV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["ensemble-policy/v1"] = "ensemble-policy/v1"
    version: Literal["1.0.0"] = "1.0.0"
    weights: dict[SignalSource, float] = {
        SignalSource.SIGNATURE: 0.40,
        SignalSource.BEHAVIORAL_RULE: 0.30,
        SignalSource.SUPERVISED: 0.20,
        SignalSource.ANOMALY: 0.10,
    }
    severity_bands: tuple[tuple[str, int, int], ...] = (
        ("informational", 0, 24),
        ("low", 25, 49),
        ("medium", 50, 74),
        ("high", 75, 89),
        ("critical", 90, 100),
    )
    category_precedence: tuple[SignalSource, ...] = (
        SignalSource.SIGNATURE,
        SignalSource.BEHAVIORAL_RULE,
        SignalSource.SUPERVISED,
        SignalSource.ANOMALY,
    )
    missing_signal_policy: Literal["explicit_absent_renormalize"] = "explicit_absent_renormalize"
    confidence_denominator: Literal[3] = 3
    automation_eligible: Literal[False] = False
    prevention_mode: Literal["simulation"] = "simulation"
    limitations: str = ANOMALY_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    unsw_nb15_acquired: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_weights(self) -> FusionPolicyV1:
        if set(self.weights) != set(self.category_precedence):
            raise ValueError("fusion_policy_sources_mismatch")
        if abs(sum(self.weights.values()) - 1.0) > 1e-9 or any(
            value <= 0.0 or value > 1.0 for value in self.weights.values()
        ):
            raise ValueError("fusion_policy_weights_invalid")
        return self

    @property
    def policy_hash(self) -> str:
        return canonical_hash(self)


class AnomalyAssessmentV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["decision-assessment/v1"] = "decision-assessment/v1"
    assessment_id: str = Field(pattern=r"^[a-f0-9-]{1,64}$")
    source_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    anomaly_detector_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    contributing_signal_ids: tuple[str, ...] = Field(max_length=8)
    source_scores: dict[str, float] = Field(max_length=8)
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    category: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    uncertainty_codes: tuple[str, ...] = Field(max_length=16)
    evidence_complete: bool
    automation_eligible: Literal[False] = False
    prevention_mode: Literal["simulation"] = "simulation"
    limitations: str = ANOMALY_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    unsw_nb15_acquired: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False
