from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from onnx import TensorProto, checker
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import IsolationForest

from aegis_services.features import FeatureSchemaV1, canonical_hash
from aegis_services.synthetic import SyntheticBuildResult, SyntheticLabel

from .schema import ANOMALY_LIMITATIONS, AnomalyDetectorManifestV1, AnomalyThresholdV1

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
MAX_ANOMALY_BYTES = 16 * 1024 * 1024
ALLOWED_DOMAINS = {"", "ai.onnx", "ai.onnx.ml"}
ALLOWED_OPERATORS = {
    "Gather",
    "LabelEncoder",
    "Reshape",
    "Equal",
    "Greater",
    "Less",
    "Max",
    "Sum",
    "Log",
    "Neg",
    "Pow",
    "Cast",
    "Constant",
    "ReduceMean",
    "Sub",
    "Mul",
    "Add",
    "Div",
    "Clip",
    "TreeEnsembleRegressor",
    "Identity",
}


@dataclass(frozen=True)
class AnomalyBuildResult:
    detector: AnomalyDetectorManifestV1
    threshold: AnomalyThresholdV1
    model_bytes: bytes
    detector_metadata: dict[str, object]
    detector_metadata_hash: str
    model_object_ref: str
    metadata_object_ref: str
    metadata_size_bytes: int
    test_scores: tuple[float, ...]
    test_flags: tuple[bool, ...]


def _matrix(result: SyntheticBuildResult, schema: FeatureSchemaV1) -> np.ndarray:
    if len(schema.features) != 39 or len(result.vectors) != 7200:
        raise ValueError("anomaly_feature_contract_mismatch")
    definitions = {item.name: item for item in schema.features}
    expected = [item.name for item in schema.features]
    rows: list[list[float]] = []
    for vector in result.vectors:
        if list(vector.ordered_names) != expected:
            raise ValueError("anomaly_feature_order_mismatch")
        row: list[float] = []
        for name, value in zip(vector.ordered_names, vector.ordered_values, strict=True):
            definition = definitions[name]
            if definition.dtype == "category":
                token = str(value)
                row.append(
                    float(definition.categories.index(token))
                    if token in definition.categories
                    else 1.0
                )
            else:
                row.append(float(value))
        rows.append(row)
    matrix = np.asarray(rows, dtype=np.float32)
    if matrix.shape != (7200, 39) or not np.isfinite(matrix).all():
        raise ValueError("anomaly_matrix_invalid")
    return matrix


def _indices(result: SyntheticBuildResult, partition: str) -> np.ndarray:
    return np.asarray(
        [
            index
            for index, item in enumerate(result.examples)
            if item.target.partition.value == partition
        ],
        dtype=np.int64,
    )


def _verify_gate5a(result: SyntheticBuildResult, schema: FeatureSchemaV1) -> None:
    if schema.definition_hash != GATE_5SA_HASHES["feature_schema"]:
        raise ValueError("anomaly_gate_5sa_feature_hash_mismatch")
    if result.catalog.catalog_hash != GATE_5SA_HASHES["scenario_catalog"]:
        raise ValueError("anomaly_gate_5sa_catalog_hash_mismatch")
    if result.dataset_content_hash != GATE_5SA_HASHES["dataset_content"]:
        raise ValueError("anomaly_gate_5sa_dataset_hash_mismatch")
    if result.split_manifest.manifest_hash != GATE_5SA_HASHES["split_manifest"]:
        raise ValueError("anomaly_gate_5sa_split_hash_mismatch")
    if result.split_manifest.train_identity_hash != GATE_5SA_HASHES["training_identity"]:
        raise ValueError("anomaly_gate_5sa_training_identity_mismatch")
    if result.split_manifest.validation_identity_hash != GATE_5SA_HASHES["validation_identity"]:
        raise ValueError("anomaly_gate_5sa_validation_identity_mismatch")
    if result.split_manifest.test_identity_hash != GATE_5SA_HASHES["test_identity"]:
        raise ValueError("anomaly_gate_5sa_test_identity_mismatch")


def _normalize(raw: np.ndarray, lower: float, upper: float) -> np.ndarray:
    if not np.isfinite(raw).all() or not np.isfinite([lower, upper]).all() or lower >= upper:
        raise ValueError("anomaly_score_normalization_invalid")
    return np.clip((raw - lower) / (upper - lower), 0.0, 1.0).astype(np.float64)


def _write(root: Path, suffix: str, payload: bytes) -> tuple[str, str, int]:
    safe_root = root.resolve()
    safe_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    object_ref = hashlib.sha256(payload).hexdigest()[:32]
    destination = (safe_root / f"{object_ref}.{suffix}").resolve()
    if destination.parent != safe_root:
        raise ValueError("anomaly_artifact_path_invalid")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=safe_root, prefix=".anomaly-", delete=False) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
    return object_ref, hashlib.sha256(payload).hexdigest(), len(payload)


def validate_anomaly_onnx(payload: bytes, expected_width: int = 39) -> onnx.ModelProto:
    if len(payload) > MAX_ANOMALY_BYTES:
        raise ValueError("anomaly_artifact_size_limit")
    model = onnx.load_model_from_string(payload)
    checker.check_model(model)
    if any(
        item.data_location == TensorProto.EXTERNAL or item.external_data
        for item in model.graph.initializer
    ):
        raise ValueError("anomaly_onnx_external_data_forbidden")
    if len(model.graph.input) != 1 or len(model.graph.output) != 1:
        raise ValueError("anomaly_onnx_shape_forbidden")
    tensor = model.graph.input[0].type.tensor_type
    dims = tensor.shape.dim
    if (
        tensor.elem_type != TensorProto.FLOAT
        or len(dims) != 2
        or dims[0].dim_value != 1
        or dims[1].dim_value != expected_width
    ):
        raise ValueError("anomaly_onnx_shape_forbidden")
    output = model.graph.output[0].type.tensor_type
    out_dims = output.shape.dim
    if (
        output.elem_type != TensorProto.FLOAT
        or len(out_dims) not in {1, 2}
        or out_dims[0].dim_value != 1
    ):
        raise ValueError("anomaly_onnx_output_forbidden")
    if {(item.domain, item.version) for item in model.opset_import} != {
        ("", 18),
        ("ai.onnx.ml", 3),
    }:
        raise ValueError("anomaly_onnx_opset_forbidden")
    for node in model.graph.node:
        if node.domain not in ALLOWED_DOMAINS or node.op_type not in ALLOWED_OPERATORS:
            raise ValueError("anomaly_onnx_operator_forbidden")
    return model


def _convert(estimator: IsolationForest) -> bytes:
    model = convert_sklearn(
        estimator,
        initial_types=[("features", FloatTensorType([1, 39]))],
        target_opset={"": 18, "ai.onnx.ml": 3},
    )
    # skl2onnx emits a label and a score output.  The closed policy exposes
    # only the floating-point score output; the label is deliberately removed
    # so consumers cannot mistake it for an approved decision.
    score_output = next((item for item in model.graph.output if item.name == "scores"), None)
    if score_output is None:
        raise ValueError("anomaly_onnx_score_output_missing")
    del model.graph.output[:]
    model.graph.output.append(score_output)
    model.graph.name = "aegis_sprint6_isolation_forest"
    payload = bytes(model.SerializeToString())
    validate_anomaly_onnx(payload)
    return payload


def _onnx_scores(payload: bytes, matrix: np.ndarray) -> np.ndarray:
    session = ort.InferenceSession(payload, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    output_name = session.get_outputs()[0].name
    values: list[float] = []
    for row in matrix:
        value = np.asarray(
            session.run([output_name], {input_name: row.reshape(1, -1).astype(np.float32)})[0]
        ).reshape(-1)
        if len(value) != 1:
            raise ValueError("anomaly_onnx_output_forbidden")
        values.append(float(value[0]))
    return np.asarray(values, dtype=np.float64)


def build_anomaly_candidate(
    result: SyntheticBuildResult,
    schema: FeatureSchemaV1,
    artifact_root: Path | None = None,
    *,
    preprocessor_hash: str = "0" * 64,
) -> AnomalyBuildResult:
    _verify_gate5a(result, schema)
    matrix = _matrix(result, schema)
    train = _indices(result, "training")
    validation = _indices(result, "validation")
    test = _indices(result, "test")
    normal = np.asarray(
        [
            index
            for index in train
            if result.examples[int(index)].target.label == SyntheticLabel.BENIGN_LIKE
        ],
        dtype=np.int64,
    )
    if len(normal) < 10:
        raise ValueError("anomaly_normal_population_too_small")
    estimator = IsolationForest(
        n_estimators=100,
        max_samples=min(256, len(normal)),
        max_features=1.0,
        bootstrap=False,
        contamination="auto",
        random_state=20260714,
        n_jobs=1,
    )
    estimator.fit(matrix[normal])
    train_raw = -np.asarray(estimator.decision_function(matrix[normal]), dtype=np.float64)
    lower, upper = (float(value) for value in np.percentile(train_raw, [1, 99]))
    if lower >= upper:
        lower, upper = float(train_raw.min()), float(train_raw.max())
    train_scores = _normalize(train_raw, lower, upper)
    validation_raw = -np.asarray(estimator.decision_function(matrix[validation]), dtype=np.float64)
    validation_scores = _normalize(validation_raw, lower, upper)
    validation_normal = np.asarray(
        [
            position
            for position, index in enumerate(validation)
            if result.examples[int(index)].target.label == SyntheticLabel.BENIGN_LIKE
        ],
        dtype=np.int64,
    )
    if len(validation_normal) < 10:
        raise ValueError("anomaly_validation_reference_too_small")
    threshold = float(np.quantile(validation_scores[validation_normal], 0.95, method="linear"))
    model_bytes = _convert(estimator)
    onnx_raw = _onnx_scores(model_bytes, matrix[validation][:32])
    reference_raw = np.asarray(
        estimator.decision_function(matrix[validation][:32]), dtype=np.float64
    )
    parity_error = float(np.max(np.abs(onnx_raw - reference_raw)))
    if (
        not np.isfinite(onnx_raw).all()
        or len(onnx_raw) != 32
        or not np.allclose(onnx_raw, reference_raw, rtol=0.0, atol=1e-6)
    ):
        raise ValueError("anomaly_onnx_parity_invalid")
    test_raw = -np.asarray(estimator.decision_function(matrix[test]), dtype=np.float64)
    test_scores = _normalize(test_raw, lower, upper)
    threshold_manifest = AnomalyThresholdV1(
        detector_manifest_hash="0" * 64,
        threshold=threshold,
        validation_identity_hash=GATE_5SA_HASHES["validation_identity"],
        validation_reference_count=len(validation_normal),
    )
    model_ref = hashlib.sha256(model_bytes).hexdigest()[:32]
    detector = AnomalyDetectorManifestV1(
        feature_schema_hash=schema.definition_hash,
        preprocessor_hash=preprocessor_hash,
        dataset_content_hash=GATE_5SA_HASHES["dataset_content"],
        split_manifest_hash=GATE_5SA_HASHES["split_manifest"],
        training_identity_hash=GATE_5SA_HASHES["training_identity"],
        normal_identity_hash=canonical_hash(
            sorted(result.examples[int(index)].target.example_identity_hash for index in normal)
        ),
        max_samples=min(256, len(normal)),
        max_features=1.0,
        training_row_count=len(normal),
        model_object_ref=model_ref,
        model_sha256=hashlib.sha256(model_bytes).hexdigest(),
        model_size_bytes=len(model_bytes),
        score_lower_anchor=float(np.quantile(train_scores, 0.0)),
        score_upper_anchor=float(np.quantile(train_scores, 1.0)),
        threshold_hash="0" * 64,
    )
    threshold_manifest = threshold_manifest.model_copy(
        update={"detector_manifest_hash": detector.manifest_hash}
    )
    detector = detector.model_copy(update={"threshold_hash": threshold_manifest.threshold_hash})
    metadata: dict[str, object] = {
        "contract": "anomaly-detector-candidate/v1",
        "state": "unreviewed_candidate",
        "detector": detector.model_dump(mode="json"),
        "threshold": threshold_manifest.model_dump(mode="json"),
        "onnx_operator_policy": sorted(ALLOWED_OPERATORS),
        "onnx_opset": {"": 18, "ai.onnx.ml": 3},
        "test_identity_hash": GATE_5SA_HASHES["test_identity"],
        "test_opened_once": True,
        "test_score_count": len(test_scores),
        "test_flag_count": int(np.sum(test_scores >= threshold)),
        "onnx_parity_max_abs_error": parity_error,
        "onnx_probability_tolerance": 1e-6,
        "limitations": ANOMALY_LIMITATIONS,
        "synthetic_demo_only": True,
        "real_dataset_used": False,
        "unsw_nb15_acquired": False,
        "online_inference_allowed": False,
        "alert_side_effects_allowed": False,
        "prevention_allowed": False,
    }
    metadata_payload = json.dumps(
        metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    metadata_hash = hashlib.sha256(metadata_payload).hexdigest()
    metadata_ref = hashlib.sha256(metadata_payload).hexdigest()[:32]
    if artifact_root is not None:
        _write(artifact_root, "onnx", model_bytes)
        _write(artifact_root, "candidate.json", metadata_payload)
    return AnomalyBuildResult(
        detector=detector,
        threshold=threshold_manifest,
        model_bytes=model_bytes,
        detector_metadata=metadata,
        detector_metadata_hash=metadata_hash,
        model_object_ref=model_ref,
        metadata_object_ref=metadata_ref,
        metadata_size_bytes=len(metadata_payload),
        test_scores=tuple(float(value) for value in test_scores),
        test_flags=tuple(bool(value >= threshold) for value in test_scores),
    )


def evaluate_anomaly_scores(
    candidate: AnomalyBuildResult,
    matrix: np.ndarray,
    *,
    max_rows: int = 10_000,
) -> np.ndarray:
    if matrix.ndim != 2 or matrix.shape[1] != 39 or matrix.shape[0] > max_rows:
        raise ValueError("anomaly_resource_limit")
    if not np.isfinite(matrix).all():
        raise ValueError("anomaly_input_non_finite")
    model = validate_anomaly_onnx(candidate.model_bytes)
    del model
    session = ort.InferenceSession(candidate.model_bytes, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    raw = np.asarray(session.run(None, {input_name: matrix.astype(np.float32)})[0]).reshape(-1)
    if not np.isfinite(raw).all():
        raise ValueError("anomaly_runtime_non_finite")
    # The stored score anchors are the contract; an ONNX runtime result is bounded
    # and normalized identically, without loading a Python model object.
    return _normalize(
        raw, candidate.detector.score_lower_anchor, candidate.detector.score_upper_anchor
    )
