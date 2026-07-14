import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from pydantic import ValidationError

from aegis_services.features import (
    PROVENANCE_COLUMNS,
    DatasetManifestV1,
    FeatureInput,
    FeaturePipeline,
    build_preprocessor_manifest,
    encode_category,
    feature_schema,
    fit_vocabulary,
    verify_artifact,
    write_parquet,
)
from aegis_services.features.schema import DatasetFileV1
from aegis_services.ingestion import CanonicalFlowV1


def _key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _input(
    name: str,
    offset: int = 0,
    *,
    sensor: str = "sensor-a",
    destination: str = "198.51.100.20",
    state: str | None = "SF",
    duration_ms: int = 1_000,
    packets: int = 10,
    bytes_: int = 1_000,
) -> FeatureInput:
    return FeatureInput(
        event_key=_key(name),
        sensor_id=sensor,
        flow=CanonicalFlowV1(
            source_type="zeek",
            source_event_id=name,
            event_time=datetime(2026, 7, 14, tzinfo=UTC) + timedelta(seconds=offset),
            src_address="192.0.2.10",
            dst_address=destination,
            src_port=49152,
            dst_port=443,
            protocol="tcp",
            duration_ms=duration_ms,
            packet_count=packets,
            byte_count=bytes_,
            state=state,
        ),
    )


def _values(vector) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return dict(zip(vector.ordered_names, vector.ordered_values, strict=True))


def test_direct_features_are_ordered_finite_and_deterministic() -> None:
    item = _input("golden")
    pipeline = FeaturePipeline()
    first = pipeline.transform_batch((item,))[0]
    second = pipeline.transform_batch((item,))[0]
    assert first == second
    values = _values(first)
    assert values["duration_ms"] == 1_000
    assert values["bytes_per_packet"] == 100.0
    assert values["packets_per_second"] == 10.0
    assert values["src_port_class"] == "dynamic"
    assert values["dst_port_class"] == "well_known"
    assert first.vector_hash == second.vector_hash
    assert tuple(values) == tuple(item.name for item in feature_schema().features)


def test_zero_denominators_and_unseen_categories_are_explicit() -> None:
    item = _input("zero", duration_ms=0, packets=0, bytes_=100, state="NEW_STATE")
    vector = FeaturePipeline().transform_batch((item,))[0]
    values = _values(vector)
    assert values["bytes_per_packet"] == 0.0
    assert values["packets_per_second"] == 0.0
    assert values["bytes_per_second"] == 0.0
    assert values["zero_duration"] is True
    assert values["zero_packets"] is True
    assert values["connection_state"] == "__UNKNOWN__"


def test_window_boundaries_order_duplicates_and_sensor_scope() -> None:
    target = _input("target", 60)
    lower = _input("lower", 0)
    excluded = _input("excluded", -1)
    other_sensor = _input("other-sensor", 30, sensor="sensor-b")
    duplicate = _input("lower", 0)
    vectors = FeaturePipeline().transform_batch(
        (target, other_sensor, excluded, lower, duplicate, lower)
    )
    target_vector = next(item for item in vectors if item.source_event_key == target.event_key)
    values = _values(target_vector)
    assert values["w60_flow_count"] == 2
    assert values["w60_byte_total"] == 2_000
    assert values["w300_flow_count"] == 3


def test_batch_order_is_stable_and_training_inference_entry_points_match() -> None:
    first = _input("first", 0)
    second = _input("second", 10)
    pipeline = FeaturePipeline()
    training = pipeline.transform_batch((second, first))
    inference = pipeline.transform_batch((first, second))
    assert [item.vector_hash for item in training] == [item.vector_hash for item in inference]
    snapshot_hash = training[0].source_snapshot_hash
    reference = pipeline.transform_one(first, (second, first), snapshot_hash)
    assert reference.vector_hash == training[0].vector_hash


def test_incompatible_schema_fails_closed() -> None:
    payload = _input("bad-schema").flow.model_dump()
    payload["schema_version"] = "2"
    with pytest.raises(ValidationError):
        CanonicalFlowV1.model_validate(payload)


def test_banned_leakage_fields_are_not_features() -> None:
    schema = feature_schema()
    feature_names = {item.name for item in schema.features}
    assert not feature_names.intersection(schema.banned_fields)
    fixture = json.loads(Path("tests/fixtures/features/leakage_cases.json").read_text())
    assert set(fixture["banned"]).issubset(set(schema.banned_fields))


def test_vocabulary_can_only_fit_training_and_unseen_is_unknown() -> None:
    split_hash = _key("training-split")
    vocabulary = fit_vocabulary(
        name="protocol",
        training_values=("tcp", "udp", "tcp", None),
        training_split_hash=split_hash,
        partition="training",
    )
    assert vocabulary.ordered_tokens == ("__MISSING__", "__UNKNOWN__", "tcp", "udp")
    assert encode_category("gre", vocabulary) == 1
    assert encode_category(None, vocabulary) == 0
    manifest = build_preprocessor_manifest(
        feature_schema_hash=feature_schema().definition_hash,
        training_split_hash=split_hash,
        vocabularies=(vocabulary,),
        partition="training",
    )
    assert manifest.training_split_hash == split_hash
    with pytest.raises(ValueError, match="training_partition"):
        fit_vocabulary(
            name="protocol",
            training_values=("gre",),
            training_split_hash=_key("test"),
            partition="test",
        )


def test_dataset_manifest_cannot_smuggle_unauthorized_files() -> None:
    payload = {
        "dataset_name": "synthetic",
        "dataset_version": "1",
        "official_source_url": "https://example.invalid/dataset",
        "publisher": "Synthetic fixture",
        "reviewed_at": datetime(2026, 7, 14, tzinfo=UTC),
        "terms_reference_hash": _key("terms"),
    }
    manifest = DatasetManifestV1(**payload)
    assert not manifest.acquisition_authorized
    with pytest.raises(ValidationError, match="unauthorized"):
        DatasetManifestV1(
            **payload,
            files=(
                DatasetFileV1(
                    logical_name="data.csv",
                    size_bytes=10,
                    sha256=_key("file"),
                    media_type="text/csv",
                    artifact_ref="00000000-0000-0000-0000-000000000001",
                ),
            ),
        )


def test_parquet_artifact_is_atomic_hashed_and_integrity_checked(tmp_path: Path) -> None:
    vectors = FeaturePipeline().transform_batch((_input("artifact"),))
    artifact = write_parquet(vectors, tmp_path, max_output_bytes=2_000_000)
    path = verify_artifact(tmp_path, artifact.object_ref, artifact.sha256)
    assert path.stat().st_size == artifact.size_bytes
    table = pq.read_table(path)
    assert table.column_names[: len(PROVENANCE_COLUMNS)] == list(PROVENANCE_COLUMNS)
    assert artifact.column_count == len(vectors[0].ordered_names) + len(PROVENANCE_COLUMNS)
    assert table["__aegis_source_event_key"][0].as_py() == vectors[0].source_event_key
    assert table["__aegis_vector_hash"][0].as_py() == vectors[0].vector_hash
    assert "src_address" not in table.column_names
    assert "dst_address" not in table.column_names
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        verify_artifact(tmp_path, artifact.object_ref, artifact.sha256)


def test_feature_fixture_contract_is_valid() -> None:
    fixture = json.loads(Path("tests/fixtures/features/canonical_flow_cases.json").read_text())
    records = tuple(CanonicalFlowV1.model_validate(item) for item in fixture["valid"])
    assert len(records) == 3


def test_machine_readable_dictionary_matches_runtime_schema() -> None:
    dictionary = json.loads(
        Path("docs/features/FEATURE_DICTIONARY_V1.json").read_text(encoding="utf-8")
    )
    schema = feature_schema()
    assert dictionary["order"] == [item.name for item in schema.features]
    assert dictionary["banned_fields"] == list(schema.banned_fields)
    assert [item["seconds"] for item in dictionary["windows"]] == [
        item.seconds for item in schema.windows
    ]
