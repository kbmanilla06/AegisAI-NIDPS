from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_services.features import PROVENANCE_COLUMNS, feature_schema
from aegis_services.synthetic import (
    SYNTHETIC_LIMITATIONS,
    ScenarioFamily,
    SyntheticLabel,
    SyntheticScenarioCatalogV1,
    build_synthetic_dataset,
    select_model_matrix,
    synthetic_artifact_path,
    write_synthetic_artifacts,
)


@pytest.fixture(scope="module")
def built():  # type: ignore[no-untyped-def]
    return build_synthetic_dataset(feature_schema("sprint4"))


def test_fixtures_freeze_closed_catalog_before_generator() -> None:
    fixture = json.loads(
        Path("tests/fixtures/synthetic/scenario_cases.json").read_text(encoding="utf-8")
    )
    catalog = SyntheticScenarioCatalogV1.model_validate(fixture["valid"])
    assert catalog.families == tuple(ScenarioFamily)
    assert catalog.labels == tuple(SyntheticLabel)
    assert catalog.maximum_flows == 10_000
    assert catalog.maximum_groups == 120
    with pytest.raises(ValidationError):
        SyntheticScenarioCatalogV1.model_validate({**fixture["valid"], "global_seed": -1})
    with pytest.raises(ValidationError):
        SyntheticScenarioCatalogV1.model_validate({**fixture["valid"], "source_url": "x"})


def test_generation_is_bounded_group_time_split_and_explicitly_synthetic(built) -> None:  # type: ignore[no-untyped-def]
    assert len(built.examples) == 7_200
    assert len(built.vectors) == 7_200
    assert built.quality_report.total_groups == 120
    assert built.quality_report.partition_counts == {
        "test": 1_080,
        "training": 5_040,
        "validation": 1_080,
    }
    assert built.quality_report.label_counts == {
        "synthetic_benign_like": 3_670,
        "synthetic_intrusion_like": 3_530,
    }
    assert built.split_manifest.train_group_count == 72
    assert built.split_manifest.validation_group_count == 24
    assert built.split_manifest.test_group_count == 24
    assert built.split_manifest.test_sealed is True
    assert built.leakage_report.banned_model_columns_found == ()
    assert built.leakage_report.cross_partition_near_duplicates == 0
    assert built.leakage_report.limitations == (SYNTHETIC_LIMITATIONS,)


def test_generation_uses_canonical_documentation_flows_without_label_metadata(built) -> None:  # type: ignore[no-untyped-def]
    for example in built.examples:
        assert example.flow.schema_version == "1"
        assert example.flow.src_address.startswith("192.0.2.")
        assert example.flow.dst_address.startswith(("198.51.100.", "203.0.113."))
        assert example.flow.metadata == {}
        assert "label" not in example.flow.model_dump()
        assert "scenario" not in example.flow.model_dump()
        assert example.target.label in tuple(SyntheticLabel)
        assert example.target.scenario_family in tuple(ScenarioFamily)


def test_generation_repeats_exact_manifest_hashes(built) -> None:  # type: ignore[no-untyped-def]
    assert SyntheticScenarioCatalogV1().catalog_hash == (
        "72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87"
    )
    assert feature_schema("sprint4").definition_hash == (
        "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114"
    )
    assert built.dataset_content_hash == (
        "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a"
    )
    assert built.target_manifest_hash == (
        "90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70"
    )
    assert built.split_manifest.manifest_hash == (
        "d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895"
    )
    assert built.quality_report.report_hash == (
        "c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4"
    )
    assert built.leakage_report.report_hash == (
        "2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d"
    )
    assert built.split_manifest.train_identity_hash == (
        "25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7"
    )
    assert built.split_manifest.validation_identity_hash == (
        "96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f"
    )
    assert built.split_manifest.test_identity_hash == (
        "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4"
    )
    repeated = build_synthetic_dataset(feature_schema("sprint4"))
    assert repeated.dataset_content_hash == built.dataset_content_hash
    assert repeated.target_manifest_hash == built.target_manifest_hash
    assert repeated.split_manifest.manifest_hash == built.split_manifest.manifest_hash
    assert repeated.quality_report.report_hash == built.quality_report.report_hash
    assert repeated.leakage_report.report_hash == built.leakage_report.report_hash
    assert tuple(item.vector_hash for item in repeated.vectors) == tuple(
        item.vector_hash for item in built.vectors
    )


def test_artifacts_are_label_separated_and_selector_returns_exact_39(
    built,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    flow, target, feature = write_synthetic_artifacts(built, tmp_path, max_feature_bytes=67_108_864)
    assert flow.row_count == target.row_count == feature.row_count == 7_200
    assert feature.column_count == 46
    assert flow.sha256 == "96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac"
    assert target.sha256 == "90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70"
    assert feature.sha256 == "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9"
    flow_path = synthetic_artifact_path(tmp_path, flow.object_ref, "jsonl")
    target_path = synthetic_artifact_path(tmp_path, target.object_ref, "targets.json")
    feature_path = synthetic_artifact_path(tmp_path, feature.object_ref, "parquet")
    assert flow_path.stat().st_mode & 0o777 == 0o600
    assert target_path.stat().st_mode & 0o777 == 0o600
    first_flow = json.loads(flow_path.read_text().splitlines()[0])
    assert "label" not in first_flow and "partition" not in first_flow
    assert "synthetic_benign_like" in target_path.read_text()
    names = built.vectors[0].ordered_names
    matrix = select_model_matrix(feature_path, names)
    assert tuple(matrix.column_names) == names
    assert matrix.num_columns == 39
    assert not set(PROVENANCE_COLUMNS) & set(matrix.column_names)


def test_selector_rejects_reordered_or_incomplete_contract(built, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _, _, feature = write_synthetic_artifacts(built, tmp_path, max_feature_bytes=67_108_864)
    path = synthetic_artifact_path(tmp_path, feature.object_ref, "parquet")
    names = built.vectors[0].ordered_names
    with pytest.raises(ValueError, match="contract"):
        select_model_matrix(path, names[:-1])
    with pytest.raises(ValueError, match="columns"):
        select_model_matrix(path, tuple(reversed(names)))
