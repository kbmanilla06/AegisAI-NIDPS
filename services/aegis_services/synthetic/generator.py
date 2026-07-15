from __future__ import annotations

import hashlib
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis_services.features import (
    FeatureInput,
    FeaturePipeline,
    FeatureSchemaV1,
    FeatureVectorV1,
    canonical_hash,
)
from aegis_services.ingestion import CanonicalFlowV1, event_key

from .schema import (
    SYNTHETIC_LIMITATIONS,
    ScenarioFamily,
    SyntheticLabel,
    SyntheticLeakageReportV1,
    SyntheticPartition,
    SyntheticQualityReportV1,
    SyntheticScenarioCatalogV1,
    SyntheticSplitManifestV1,
    SyntheticTargetV1,
)


@dataclass(frozen=True)
class GeneratedExample:
    flow: CanonicalFlowV1
    feature_input: FeatureInput
    target: SyntheticTargetV1


@dataclass(frozen=True)
class SyntheticBuildResult:
    catalog: SyntheticScenarioCatalogV1
    examples: tuple[GeneratedExample, ...]
    vectors: tuple[FeatureVectorV1, ...]
    split_manifest: SyntheticSplitManifestV1
    quality_report: SyntheticQualityReportV1
    leakage_report: SyntheticLeakageReportV1
    target_manifest_hash: str
    dataset_content_hash: str


_PARTITION_LAYOUT = {
    SyntheticPartition.TRAINING: (9, 70, datetime(2025, 1, 1, tzinfo=UTC)),
    SyntheticPartition.VALIDATION: (3, 45, datetime(2025, 7, 1, tzinfo=UTC)),
    SyntheticPartition.TEST: (3, 45, datetime(2025, 10, 1, tzinfo=UTC)),
}


def _digest(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()


def _label(
    family: ScenarioFamily, partition: SyntheticPartition, group_index: int
) -> SyntheticLabel:
    if family in {
        ScenarioFamily.BACKGROUND_MIXED_SERVICES,
        ScenarioFamily.BACKGROUND_SPARSE_IDLE,
        ScenarioFamily.BACKGROUND_BURSTY,
    }:
        return SyntheticLabel.BENIGN_LIKE
    if family in {
        ScenarioFamily.SCAN_LIKE_FANOUT,
        ScenarioFamily.FAILURE_LIKE_SEQUENCE,
        ScenarioFamily.CONNECTION_RATE_LIKE,
    }:
        return SyntheticLabel.INTRUSION_LIKE
    offset = {
        SyntheticPartition.TRAINING: 0,
        SyntheticPartition.VALIDATION: 1,
        SyntheticPartition.TEST: 0,
    }[partition]
    return tuple(SyntheticLabel)[(group_index + offset) % 2]


def _flow_for(
    family: ScenarioFamily,
    *,
    group_index: int,
    record_index: int,
    group_start: datetime,
    group_seed: int,
) -> CanonicalFlowV1:
    # This is a reproducible fixture generator, never a security or token source.
    rng = random.Random(group_seed + record_index)  # noqa: S311  # nosec B311
    src_octet = 1 + (group_index % 250)
    dst_octet = 1 + ((group_index * 17 + record_index * 7) % 250)
    src_address = f"192.0.2.{src_octet}"
    dst_address = f"198.51.100.{dst_octet}"
    protocol = "tcp" if record_index % 4 else "udp"
    src_port: int | None = 40_000 + ((group_index * 101 + record_index) % 20_000)
    dst_port: int | None = (22, 53, 80, 123, 443, 8080)[record_index % 6]
    state: str | None = "SF"
    spacing_seconds = 7
    duration_ms = 20 + rng.randrange(2_000)
    packet_count = 2 + rng.randrange(50)
    byte_count = packet_count * (64 + rng.randrange(900)) + record_index + group_index
    source_type = "normalized"

    if family == ScenarioFamily.BACKGROUND_SPARSE_IDLE:
        spacing_seconds = 90
        packet_count = 1 + rng.randrange(10)
    elif family == ScenarioFamily.BACKGROUND_BURSTY:
        spacing_seconds = 2
        packet_count = 5 + rng.randrange(80)
    elif family == ScenarioFamily.SCAN_LIKE_FANOUT:
        spacing_seconds = 1
        dst_port = 1 + ((group_index * 977 + record_index * 37) % 65_534)
        dst_address = f"203.0.113.{dst_octet}"
        state = "S0"
        packet_count = 1 + (record_index % 3)
    elif family == ScenarioFamily.FAILURE_LIKE_SEQUENCE:
        spacing_seconds = 4
        source_type = "zeek"
        state = ("REJ", "S0", "RSTO", "RSTR")[record_index % 4]
        packet_count = 1 + (record_index % 5)
    elif family == ScenarioFamily.CONNECTION_RATE_LIKE:
        spacing_seconds = 0
        duration_ms = 1 + (record_index % 10)
        packet_count = 1 + (record_index % 4)
    elif family == ScenarioFamily.AMBIGUOUS_OVERLAP:
        spacing_seconds = 3 + (record_index % 6)
        state = ("SF", "S0", "REJ")[record_index % 3]
        dst_port = (22, 53, 80, 443, 8080, 8443)[record_index % 6]
    elif family == ScenarioFamily.MISSING_UNKNOWN_BOUNDARY:
        spacing_seconds = 11
        if record_index % 5 == 0:
            src_port = None
            dst_port = None
            protocol = "gre"
            state = None
        elif record_index % 5 == 1:
            protocol = "esp"
            state = "OTH"
        if record_index % 13 == 0:
            duration_ms = 0
            packet_count = 0
            byte_count = group_index

    event_time = group_start + timedelta(
        seconds=(record_index * spacing_seconds), microseconds=record_index + group_index
    )
    source_event_id = f"syn-{_digest(group_seed, record_index)[:24]}"
    return CanonicalFlowV1(
        schema_version="1",
        source_type=source_type,
        source_event_id=source_event_id,
        event_time=event_time,
        src_address=src_address,
        dst_address=dst_address,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        duration_ms=duration_ms,
        packet_count=packet_count,
        byte_count=byte_count,
        state=state,
        metadata={},
    )


def _near_projection(vector: FeatureVectorV1) -> str:
    normalized: list[Any] = []
    for value in vector.ordered_values:
        normalized.append(round(value, 6) if isinstance(value, float) else value)
    return canonical_hash({"names": vector.ordered_names, "values": normalized})


def build_synthetic_dataset(
    schema: FeatureSchemaV1,
    *,
    catalog: SyntheticScenarioCatalogV1 | None = None,
) -> SyntheticBuildResult:
    approved_catalog = catalog or SyntheticScenarioCatalogV1()
    examples: list[GeneratedExample] = []
    group_sequence = 0
    partition_sequences = {partition: 0 for partition in SyntheticPartition}
    for family in approved_catalog.families:
        for partition, (group_count, row_count, band_start) in _PARTITION_LAYOUT.items():
            for partition_group_index in range(group_count):
                group_sequence += 1
                partition_sequences[partition] += 1
                group_hash = _digest(
                    approved_catalog.catalog_hash,
                    family.value,
                    partition.value,
                    partition_group_index,
                )
                group_seed = int(_digest(approved_catalog.global_seed, group_hash)[:16], 16)
                label = _label(family, partition, partition_group_index)
                group_start = band_start + timedelta(
                    days=partition_sequences[partition], seconds=partition_group_index
                )
                for record_index in range(row_count):
                    flow = _flow_for(
                        family,
                        group_index=group_sequence,
                        record_index=record_index,
                        group_start=group_start,
                        group_seed=group_seed,
                    )
                    key = event_key(flow, group_hash)
                    identity_hash = _digest("synthetic-example/v1", key, group_hash)
                    examples.append(
                        GeneratedExample(
                            flow=flow,
                            feature_input=FeatureInput(
                                event_key=key, sensor_id=group_hash, flow=flow
                            ),
                            target=SyntheticTargetV1(
                                example_identity_hash=identity_hash,
                                label=label,
                                scenario_family=family,
                                group_identity_hash=group_hash,
                                partition=partition,
                            ),
                        )
                    )
    if len(examples) > approved_catalog.maximum_flows:
        raise ValueError("synthetic_flow_limit")
    groups = {item.target.group_identity_hash for item in examples}
    if len(groups) > approved_catalog.maximum_groups:
        raise ValueError("synthetic_group_limit")

    ordered = tuple(
        sorted(examples, key=lambda item: (item.flow.event_time, item.feature_input.event_key))
    )
    vectors = FeaturePipeline(schema).transform_batch(tuple(item.feature_input for item in ordered))
    vector_by_key = {vector.source_event_key: vector for vector in vectors}
    if len(vector_by_key) != len(ordered):
        raise ValueError("synthetic_duplicate_event_key")

    partition_examples: dict[SyntheticPartition, list[GeneratedExample]] = defaultdict(list)
    partition_vectors: dict[SyntheticPartition, list[FeatureVectorV1]] = defaultdict(list)
    for example in ordered:
        partition_examples[example.target.partition].append(example)
        partition_vectors[example.target.partition].append(
            vector_by_key[example.feature_input.event_key]
        )

    event_sets = {
        partition: {item.feature_input.event_key for item in items}
        for partition, items in partition_examples.items()
    }
    vector_sets = {
        partition: {item.vector_hash for item in items}
        for partition, items in partition_vectors.items()
    }
    group_sets = {
        partition: {item.target.group_identity_hash for item in items}
        for partition, items in partition_examples.items()
    }
    near_sets = {
        partition: {_near_projection(item) for item in items}
        for partition, items in partition_vectors.items()
    }
    partitions = tuple(SyntheticPartition)
    for index, left in enumerate(partitions):
        for right in partitions[index + 1 :]:
            if event_sets[left] & event_sets[right]:
                raise ValueError("synthetic_cross_partition_event_duplicate")
            if vector_sets[left] & vector_sets[right]:
                raise ValueError("synthetic_cross_partition_vector_duplicate")
            if group_sets[left] & group_sets[right]:
                raise ValueError("synthetic_cross_partition_group_duplicate")
            if near_sets[left] & near_sets[right]:
                raise ValueError("synthetic_cross_partition_near_duplicate")

    identity_hashes = {
        partition: canonical_hash(sorted(item.target.example_identity_hash for item in items))
        for partition, items in partition_examples.items()
    }
    dataset_content_hash = canonical_hash(
        [
            {
                "flow": item.flow.model_dump(mode="json"),
                "target": item.target.model_dump(mode="json"),
            }
            for item in ordered
        ]
    )
    split = SyntheticSplitManifestV1(
        dataset_content_hash=dataset_content_hash,
        train_identity_hash=identity_hashes[SyntheticPartition.TRAINING],
        validation_identity_hash=identity_hashes[SyntheticPartition.VALIDATION],
        test_identity_hash=identity_hashes[SyntheticPartition.TEST],
        train_count=len(partition_examples[SyntheticPartition.TRAINING]),
        validation_count=len(partition_examples[SyntheticPartition.VALIDATION]),
        test_count=len(partition_examples[SyntheticPartition.TEST]),
        train_group_count=len(group_sets[SyntheticPartition.TRAINING]),
        validation_group_count=len(group_sets[SyntheticPartition.VALIDATION]),
        test_group_count=len(group_sets[SyntheticPartition.TEST]),
        train_time_end=max(
            item.flow.event_time for item in partition_examples[SyntheticPartition.TRAINING]
        ),
        validation_time_start=min(
            item.flow.event_time for item in partition_examples[SyntheticPartition.VALIDATION]
        ),
        validation_time_end=max(
            item.flow.event_time for item in partition_examples[SyntheticPartition.VALIDATION]
        ),
        test_time_start=min(
            item.flow.event_time for item in partition_examples[SyntheticPartition.TEST]
        ),
    )

    labels = Counter(item.target.label.value for item in ordered)
    families = Counter(item.target.scenario_family.value for item in ordered)
    partition_counts = Counter(item.target.partition.value for item in ordered)
    quality_flags: Counter[str] = Counter()
    for vector in vectors:
        quality_flags.update(vector.quality_flags)
    quality = SyntheticQualityReportV1(
        total_flows=len(ordered),
        total_groups=len(groups),
        label_counts=dict(sorted(labels.items())),
        family_counts=dict(sorted(families.items())),
        partition_counts=dict(sorted(partition_counts.items())),
        quality_flag_counts=dict(sorted(quality_flags.items())),
    )

    values_by_label: dict[str, dict[str, set[object]]] = defaultdict(lambda: defaultdict(set))
    for example in ordered:
        vector = vector_by_key[example.feature_input.event_key]
        for name, value in zip(vector.ordered_names, vector.ordered_values, strict=True):
            values_by_label[example.target.label.value][name].add(value)
    perfect: list[str] = []
    label_left, label_right = (item.value for item in SyntheticLabel)
    for name in vectors[0].ordered_names:
        if values_by_label[label_left][name].isdisjoint(values_by_label[label_right][name]):
            perfect.append(name)
    leakage = SyntheticLeakageReportV1(
        perfect_single_feature_separators=tuple(perfect),
        limitations=(SYNTHETIC_LIMITATIONS,),
    )
    target_manifest_hash = canonical_hash([item.target.model_dump(mode="json") for item in ordered])
    return SyntheticBuildResult(
        catalog=approved_catalog,
        examples=ordered,
        vectors=vectors,
        split_manifest=split,
        quality_report=quality,
        leakage_report=leakage,
        target_manifest_hash=target_manifest_hash,
        dataset_content_hash=dataset_content_hash,
    )
