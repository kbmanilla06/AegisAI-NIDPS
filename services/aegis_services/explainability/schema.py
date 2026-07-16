from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_services.features import canonical_hash
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

# Sprint 7 explanations extend the mandatory synthetic limitation with the
# explicit association-not-causation clause required by the plan and DET-005.
EXPLANATION_LIMITATIONS = (
    SYNTHETIC_LIMITATIONS
    + " Explanations describe association within synthetic data, not causation "
    "or real-world maliciousness."
)

# Causal / verdict words are forbidden in analyst summaries so an explanation can
# never be read as proof of intent or malice (ML-007, AC-10).
_BANNED_SUMMARY_TOKENS = (
    "cause",
    "causes",
    "caused",
    "proves",
    "proof",
    "malicious",
    "attacker",
    "guarantee",
    "guaranteed",
)


class ExplanationMethod(StrEnum):
    LINEAR_COEFFICIENT = "linear_coefficient"
    NATIVE_IMPORTANCE = "native_importance"
    PERMUTATION_OCCLUSION = "permutation_occlusion"


class AttributionDirection(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"
    NEUTRAL = "neutral"


class ExplanationMethodV1(BaseModel):
    """Immutable, hash-bound description of a faithful offline explanation method."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["explanation-method/v1"] = "explanation-method/v1"
    method: ExplanationMethod
    target_algorithm: Literal["isolation_forest", "logistic_regression", "random_forest"]
    feature_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    top_k: int = Field(ge=1, le=39)
    # Deterministic settings; permutation/occlusion uses a fixed reference and seed.
    seed: Literal[20260714] = 20260714
    reference: Literal["training_median"] = "training_median"
    online_inference_used: Literal[False] = False
    model_activation_used: Literal[False] = False
    external_lookup_used: Literal[False] = False
    limitations: str = EXPLANATION_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    unsw_nb15_acquired: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @property
    def method_hash(self) -> str:
        return canonical_hash(self)


class FeatureAttributionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["feature-attribution/v1"] = "feature-attribution/v1"
    feature_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.]+$")
    raw_value: float
    transformed_meaning: str = Field(min_length=1, max_length=128)
    direction: AttributionDirection
    magnitude: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)

    @field_validator("raw_value", "magnitude", "uncertainty")
    @classmethod
    def reject_non_finite(cls, value: float) -> float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("attribution_non_finite")
        return value


class ExplanationV1(BaseModel):
    """Bounded per-result explanation sidecar bound to method and model versions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["explanation/v1"] = "explanation/v1"
    explanation_id: str = Field(pattern=r"^[a-f0-9-]{1,64}$")
    method_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    # Restricted provenance only: a synthetic example identity, never endpoints or labels.
    source_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    subject_score: float = Field(ge=0.0, le=1.0)
    baseline_score: float = Field(ge=0.0, le=1.0)
    attributions: tuple[FeatureAttributionV1, ...] = Field(min_length=1, max_length=39)
    analyst_summary: str = Field(min_length=1, max_length=512)
    association_only: Literal[True] = True
    limitations: str = EXPLANATION_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_dataset_used: Literal[False] = False
    unsw_nb15_acquired: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @field_validator("analyst_summary")
    @classmethod
    def reject_causal_language(cls, value: str) -> str:
        lowered = value.lower()
        if any(token in lowered for token in _BANNED_SUMMARY_TOKENS):
            raise ValueError("explanation_summary_causal_language")
        return value

    @model_validator(mode="after")
    def validate_ordering(self) -> ExplanationV1:
        magnitudes = [item.magnitude for item in self.attributions]
        if magnitudes != sorted(magnitudes, reverse=True):
            raise ValueError("explanation_attributions_unordered")
        keys = [item.feature_key for item in self.attributions]
        if len(keys) != len(set(keys)):
            raise ValueError("explanation_attributions_duplicate_feature")
        return self

    @property
    def explanation_hash(self) -> str:
        return canonical_hash(self)
