from __future__ import annotations

from collections import Counter

from aegis_services.features.schema import (
    MISSING_TOKEN,
    UNKNOWN_TOKEN,
    PreprocessorManifestV1,
    VocabularyManifestV1,
)


def fit_vocabulary(
    *,
    name: str,
    training_values: tuple[str | None, ...],
    training_split_hash: str,
    partition: str,
    minimum_frequency: int = 1,
) -> VocabularyManifestV1:
    if partition != "training":
        raise ValueError("preprocessing_fit_requires_training_partition")
    counts = Counter(value for value in training_values if value is not None)
    tokens = tuple(
        token
        for token, count in sorted(counts.items())
        if count >= minimum_frequency and token not in {MISSING_TOKEN, UNKNOWN_TOKEN}
    )
    return VocabularyManifestV1(
        name=name,
        ordered_tokens=(MISSING_TOKEN, UNKNOWN_TOKEN, *tokens),
        training_split_hash=training_split_hash,
        minimum_frequency=minimum_frequency,
    )


def encode_category(value: str | None, vocabulary: VocabularyManifestV1) -> int:
    token = MISSING_TOKEN if value is None else value
    if token not in vocabulary.ordered_tokens:
        token = UNKNOWN_TOKEN
    return vocabulary.ordered_tokens.index(token)


def build_preprocessor_manifest(
    *,
    feature_schema_hash: str,
    training_split_hash: str,
    vocabularies: tuple[VocabularyManifestV1, ...],
    fitted_numeric_statistics: dict[str, float] | None = None,
    partition: str,
) -> PreprocessorManifestV1:
    if partition != "training":
        raise ValueError("preprocessing_fit_requires_training_partition")
    if any(item.training_split_hash != training_split_hash for item in vocabularies):
        raise ValueError("preprocessing_split_mismatch")
    return PreprocessorManifestV1(
        feature_schema_hash=feature_schema_hash,
        training_split_hash=training_split_hash,
        vocabularies=vocabularies,
        fitted_numeric_statistics=fitted_numeric_statistics or {},
    )
