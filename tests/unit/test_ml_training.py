from __future__ import annotations

from pathlib import Path

import onnx
import pytest

from aegis_services.features import feature_schema
from aegis_services.ml import (
    GATE_5SA_HASHES,
    delete_candidate_artifacts,
    open_sealed_test_once,
    train_gate_5sb,
    validate_onnx_closed_policy,
)
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS, build_synthetic_dataset

# Vendored dependency directories ship their own pickle fixtures; they are not
# produced by the training pipeline and must not fail the safe-format guard.
_VENDOR_DIRS = frozenset({".venv", "venv", "env", "site-packages", "node_modules", ".git"})


def _stray_pickles(pattern: str) -> list[Path]:
    return [path for path in Path(".").glob(pattern) if _VENDOR_DIRS.isdisjoint(path.parts)]


@pytest.fixture(scope="module")
def trained(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    schema = feature_schema("sprint4")
    result = build_synthetic_dataset(schema)
    return train_gate_5sb(result, schema, tmp_path_factory.mktemp("gate5sb"))


def test_gate_5sa_boundary_is_exact() -> None:
    assert (
        GATE_5SA_HASHES["dataset_content"]
        == "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a"
    )
    assert (
        GATE_5SA_HASHES["test_identity"]
        == "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4"
    )


def test_training_produces_only_two_unreviewed_onnx_candidates(trained) -> None:  # type: ignore[no-untyped-def]
    assert {item.algorithm for item in trained.candidates} == {
        "logistic_regression",
        "random_forest",
    }
    assert trained.selected_algorithm in {"logistic_regression", "random_forest"}
    assert len(trained.selected_candidate_hash) == 64
    assert len(trained.test_opening_hash) == 64
    assert sum(item.test_metrics is not None for item in trained.candidates) == 1
    for candidate in trained.candidates:
        assert candidate.model_size_bytes <= 16 * 1024 * 1024
        assert candidate.metadata_size_bytes <= 16 * 1024 * 1024
        assert len(candidate.metadata_sha256) == 64
        assert candidate.metadata["state"] == "unreviewed_candidate"
        assert candidate.metadata["scoring_allowed"] is False
        assert candidate.metadata["loadable_by_api"] is False
        assert candidate.metadata["limitations"] == SYNTHETIC_LIMITATIONS
        # Safe-format guard: the pipeline must emit no pickled estimator anywhere in
        # the repo. Vendored dependency dirs (a local .venv, node_modules) ship their
        # own .pkl/.joblib fixtures and are not produced by us, so they are excluded.
        assert not _stray_pickles("**/*.pkl")
        assert not _stray_pickles("**/*.joblib")


def test_onnx_is_fixed_float32_closed_policy_and_probability_parity(trained) -> None:  # type: ignore[no-untyped-def]
    for candidate in trained.candidates:
        model = validate_onnx_closed_policy(candidate.onnx_bytes, 39)
        assert model.graph.input[0].type.tensor_type.shape.dim[0].dim_value == 1
        assert not any(initializer.external_data for initializer in model.graph.initializer)


def test_training_and_onnx_hashes_are_deterministic(
    trained,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    schema = feature_schema("sprint4")
    repeated = train_gate_5sb(build_synthetic_dataset(schema), schema, tmp_path)
    assert repeated.selected_candidate_hash == trained.selected_candidate_hash
    assert repeated.test_opening_hash == trained.test_opening_hash
    assert [(item.algorithm, item.model_sha256) for item in repeated.candidates] == [
        (item.algorithm, item.model_sha256) for item in trained.candidates
    ]


def test_candidate_cleanup_removes_onnx_and_canonical_json(tmp_path: Path) -> None:
    schema = feature_schema("sprint4")
    result = train_gate_5sb(build_synthetic_dataset(schema), schema, tmp_path)
    assert len(list(tmp_path.iterdir())) == 4
    delete_candidate_artifacts(result, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_sealed_test_can_open_only_once() -> None:
    state: dict[str, object] = {}
    opening = open_sealed_test_once(state, "a" * 64)
    assert len(opening) == 64
    with pytest.raises(ValueError, match="already_opened"):
        open_sealed_test_once(state, "a" * 64)


def test_onnx_policy_rejects_dynamic_shape() -> None:
    model = onnx.helper.make_model(
        onnx.helper.make_graph(
            [],
            "x",
            [onnx.helper.make_tensor_value_info("features", onnx.TensorProto.FLOAT, [None, 39])],
            [],
        )
    )
    with pytest.raises(ValueError, match="shape_forbidden"):
        validate_onnx_closed_policy(model.SerializeToString(), 39)
