from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

MISSING_TOKEN = "__MISSING__"  # noqa: S105  # nosec B105
UNKNOWN_TOKEN = "__UNKNOWN__"  # noqa: S105  # nosec B105
MAX_FEATURES = 128
MAX_WINDOWS = 4


def canonical_hash(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


class FeatureDefinitionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    dtype: Literal["int64", "float64", "bool", "category"]
    unit: str = Field(min_length=1, max_length=32)
    source: str = Field(min_length=1, max_length=128)
    security_meaning: str = Field(min_length=1, max_length=256)
    missing_policy: str = Field(min_length=1, max_length=128)
    minimum: float | None = None
    maximum: float | None = None
    categories: tuple[str, ...] = ()
    inference_available: bool = True

    @model_validator(mode="after")
    def validate_range_and_categories(self) -> FeatureDefinitionV1:
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("feature minimum cannot exceed maximum")
        if self.dtype == "category" and not self.categories:
            raise ValueError("categorical features require an ordered vocabulary")
        if self.dtype != "category" and self.categories:
            raise ValueError("only categorical features may define categories")
        return self


class WindowDefinitionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seconds: int = Field(ge=1, le=86_400)
    order: Literal["event_time,event_key"] = "event_time,event_key"
    lower_bound: Literal["inclusive"] = "inclusive"
    upper_bound: Literal["inclusive_as_of_tuple"] = "inclusive_as_of_tuple"
    grouping: Literal["sensor,source_address"] = "sensor,source_address"


class FeatureSchemaV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["feature-schema/v1"] = "feature-schema/v1"
    name: Literal["flow_features"] = "flow_features"
    version: Literal["1.0.0"] = "1.0.0"
    input_schema: Literal["1"] = "1"
    features: tuple[FeatureDefinitionV1, ...]
    windows: tuple[WindowDefinitionV1, ...]
    banned_fields: tuple[str, ...] = Field(max_length=128)
    missing_token: Literal["__MISSING__"] = "__MISSING__"  # noqa: S105 - vocabulary token
    unknown_token: Literal["__UNKNOWN__"] = "__UNKNOWN__"  # noqa: S105 - vocabulary token
    numeric_dtype: Literal["float64"] = "float64"
    code_version: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_definition(self) -> FeatureSchemaV1:
        names = [feature.name for feature in self.features]
        if not names or len(names) > MAX_FEATURES or len(names) != len(set(names)):
            raise ValueError("feature names must be unique and bounded")
        if len(self.windows) > MAX_WINDOWS or len({item.seconds for item in self.windows}) != len(
            self.windows
        ):
            raise ValueError("windows must be unique and bounded")
        return self

    @property
    def definition_hash(self) -> str:
        return canonical_hash(self)


FeatureValue = Annotated[
    StrictBool | StrictInt | StrictFloat | StrictStr, Field(union_mode="left_to_right")
]


class FeatureVectorV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["feature-vector/v1"] = "feature-vector/v1"
    feature_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    feature_schema_version: Literal["1.0.0"] = "1.0.0"
    input_schema: Literal["1"] = "1"
    source_event_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    cutoff_time: datetime
    source_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    ordered_names: tuple[str, ...]
    ordered_values: tuple[FeatureValue, ...]
    quality_flags: tuple[str, ...] = ()
    vector_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("cutoff_time")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("cutoff_time must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_shape(self) -> FeatureVectorV1:
        if len(self.ordered_names) != len(self.ordered_values):
            raise ValueError("feature names and values must have equal length")
        if len(self.ordered_names) > MAX_FEATURES:
            raise ValueError("feature vector is too wide")
        return self


class DatasetFileV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    logical_name: str = Field(min_length=1, max_length=128)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: str = Field(min_length=1, max_length=64)
    artifact_ref: str = Field(pattern=r"^[a-f0-9-]{36}$")


class DatasetManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["dataset-manifest/v1"] = "dataset-manifest/v1"
    dataset_name: str = Field(min_length=1, max_length=128)
    dataset_version: str = Field(min_length=1, max_length=64)
    official_source_url: str = Field(max_length=512, pattern=r"^https://")
    publisher: str = Field(min_length=1, max_length=128)
    reviewed_at: datetime
    acquisition_authorized: bool = False
    intended_use: Literal["academic_portfolio"] = "academic_portfolio"
    terms_reference_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    citation_required: bool = True
    commercial_use_requires_author_agreement: bool = True
    redistribution_authorized: bool = False
    files: tuple[DatasetFileV1, ...] = Field(default=(), max_length=100)
    adapter_version: str | None = Field(default=None, max_length=64)
    limitations: tuple[str, ...] = Field(default=(), max_length=50)

    @field_validator("limitations")
    @classmethod
    def bound_limitations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 500 for value in values):
            raise ValueError("dataset limitations must be non-empty and bounded")
        return values

    @model_validator(mode="after")
    def reject_unauthorized_files(self) -> DatasetManifestV1:
        if self.files and not self.acquisition_authorized:
            raise ValueError("unauthorized dataset manifests cannot contain files")
        return self

    @property
    def manifest_hash(self) -> str:
        return canonical_hash(self)


class SplitManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["split-manifest/v1"] = "split-manifest/v1"
    dataset_manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    strategy: Literal["time", "host", "capture", "group_time"]
    grouping_keys: tuple[str, ...] = Field(min_length=1, max_length=8)
    train_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    validation_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    test_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    train_count: int = Field(ge=1)
    validation_count: int = Field(ge=1)
    test_count: int = Field(ge=1)
    cross_partition_duplicates: Literal[0] = 0
    reviewed_by: UUID

    @model_validator(mode="after")
    def require_distinct_partitions(self) -> SplitManifestV1:
        identities = {
            self.train_identity_hash,
            self.validation_identity_hash,
            self.test_identity_hash,
        }
        if len(identities) != 3:
            raise ValueError("split partitions must be distinct")
        return self


class VocabularyManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    ordered_tokens: tuple[str, ...] = Field(min_length=2, max_length=512)
    training_split_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    minimum_frequency: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_tokens(self) -> VocabularyManifestV1:
        if self.ordered_tokens[:2] != (MISSING_TOKEN, UNKNOWN_TOKEN):
            raise ValueError("reserved tokens must be first")
        if len(self.ordered_tokens) != len(set(self.ordered_tokens)):
            raise ValueError("vocabulary tokens must be unique")
        if any(not token or len(token) > 128 for token in self.ordered_tokens):
            raise ValueError("vocabulary tokens must be non-empty and bounded")
        return self


class PreprocessorManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["preprocessor-manifest/v1"] = "preprocessor-manifest/v1"
    feature_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    training_split_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    vocabularies: tuple[VocabularyManifestV1, ...]
    fitted_numeric_statistics: dict[str, float] = Field(default_factory=dict)

    @field_validator("fitted_numeric_statistics")
    @classmethod
    def validate_statistics(cls, values: dict[str, float]) -> dict[str, float]:
        if len(values) > MAX_FEATURES:
            raise ValueError("too many fitted statistics")
        for name, value in values.items():
            if (
                not name
                or len(name) > 64
                or not value == value
                or value in {float("inf"), float("-inf")}
            ):
                raise ValueError("fitted statistics must be named, finite, and bounded")
        return values

    @property
    def manifest_hash(self) -> str:
        return canonical_hash(self)
