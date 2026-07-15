from pathlib import Path

import numpy as np
import pytest

from aegis_api.schemas import SyntheticRegistryModelOut, SyntheticScoringJobOut
from aegis_api.scoring_processor import _safe_path, score_matrix
from aegis_services.features import feature_schema
from aegis_services.ml import train_gate_5sb
from aegis_services.synthetic import build_synthetic_dataset


def test_scoring_path_is_opaque_and_rejects_traversal(tmp_path: Path) -> None:
    assert _safe_path(tmp_path, "a" * 32, "onnx") == tmp_path / ("a" * 32 + ".onnx")
    with pytest.raises(ValueError, match="path_invalid"):
        _safe_path(tmp_path, "../escape", "onnx")


def test_gate5c_lifecycle_has_no_activation_state() -> None:
    assert "active" not in {"reviewed_synthetic", "rejected", "quarantined", "retired"}
    assert SyntheticRegistryModelOut.model_fields["scoring_allowed"].default is True
    assert SyntheticRegistryModelOut.model_fields["online_inference_allowed"].default is False
    assert SyntheticScoringJobOut.model_fields["alert_side_effects_allowed"].default is False
    assert SyntheticScoringJobOut.model_fields["prevention_allowed"].default is False


def test_offline_score_matrix_is_bounded_and_aggregate_only(tmp_path: Path) -> None:
    schema = feature_schema("sprint4")
    evidence = train_gate_5sb(build_synthetic_dataset(schema), schema, tmp_path)
    candidate = next(
        item for item in evidence.candidates if item.algorithm == "logistic_regression"
    )
    result = score_matrix(
        candidate.onnx_bytes,
        np.zeros((3, 39), dtype="float32"),
        candidate.algorithm,
        candidate.metadata["preprocessor"],
    )
    assert result["row_count"] == 3
    assert set(result["predicted_counts"]) == {"synthetic_benign_like", "synthetic_intrusion_like"}
    with pytest.raises(ValueError, match="resource_limit"):
        score_matrix(
            candidate.onnx_bytes,
            np.zeros((10_001, 39), dtype="float32"),
            candidate.algorithm,
            candidate.metadata["preprocessor"],
        )
