from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import numpy as np
import onnx
import onnxruntime as ort
from onnx import TensorProto, checker
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

from aegis_services.features import FeatureSchemaV1, canonical_hash
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS, SyntheticBuildResult

GATE_5SA_HASHES = {
    "scenario_catalog": "72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87",
    "feature_schema": "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114",
    "dataset_content": "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a",
    "canonical_flow_artifact": "96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac",
    "target_manifest": "90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70",
    "feature_artifact": "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9",
    "split_manifest": "d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895",
    "quality_report": "c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4",
    "leakage_report": "2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d",
    "training_identity": "25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7",
    "validation_identity": "96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f",
    "test_identity": "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4",
}
CLASS_ORDER = ("synthetic_benign_like", "synthetic_intrusion_like")
MAX_MODEL_BYTES = 16 * 1024 * 1024
ALLOWED_DOMAINS = {"", "ai.onnx", "ai.onnx.ml"}
ALLOWED_OPERATORS = {
    "ArrayFeatureExtractor",
    "Cast",
    "Concat",
    "Div",
    "Gemm",
    "Identity",
    "LabelEncoder",
    "LinearClassifier",
    "MatMul",
    "Mul",
    "Reshape",
    "Sigmoid",
    "Softmax",
    "Sub",
    "TreeEnsembleClassifier",
    "ZipMap",
}


@dataclass(frozen=True)
class CandidateArtifact:
    algorithm: str
    validation_metrics: dict[str, object]
    test_metrics: dict[str, object] | None
    model_sha256: str
    model_size_bytes: int
    metadata_object_ref: str
    metadata_sha256: str
    metadata_size_bytes: int
    preprocessor_hash: str
    evaluation_hash: str
    model_card_hash: str
    onnx_bytes: bytes
    metadata: dict[str, object]


@dataclass(frozen=True)
class Gate5SBResult:
    selected_algorithm: str
    selected_candidate_hash: str
    test_opening_hash: str
    candidates: tuple[CandidateArtifact, ...]


def _verify_boundary(result: SyntheticBuildResult, schema: FeatureSchemaV1) -> None:
    actual = {
        "scenario_catalog": result.catalog.catalog_hash,
        "feature_schema": schema.definition_hash,
        "dataset_content": result.dataset_content_hash,
        "target_manifest": result.target_manifest_hash,
        "split_manifest": result.split_manifest.manifest_hash,
        "quality_report": result.quality_report.report_hash,
        "leakage_report": result.leakage_report.report_hash,
        "training_identity": result.split_manifest.train_identity_hash,
        "validation_identity": result.split_manifest.validation_identity_hash,
        "test_identity": result.split_manifest.test_identity_hash,
    }
    if any(GATE_5SA_HASHES[key] != value for key, value in actual.items()):
        raise ValueError("ml_gate_5sa_hash_mismatch")


def _encode(
    result: SyntheticBuildResult, schema: FeatureSchemaV1
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    definitions = {item.name: item for item in schema.features}
    names = list(result.vectors[0].ordered_names)
    if names != [item.name for item in schema.features] or len(names) != 39:
        raise ValueError("ml_feature_contract_mismatch")
    rows: list[list[float]] = []
    for vector in result.vectors:
        encoded: list[float] = []
        for name, value in zip(names, vector.ordered_values, strict=True):
            definition = definitions[name]
            if definition.dtype == "category":
                token = str(value)
                try:
                    encoded.append(float(definition.categories.index(token)))
                except ValueError:
                    encoded.append(float(definition.categories.index("__UNKNOWN__")))
            else:
                encoded.append(float(value))
        rows.append(encoded)
    labels_by_identity = {
        item.target.example_identity_hash: item.target.label.value for item in result.examples
    }
    ordered_labels = [
        labels_by_identity[item.target.example_identity_hash] for item in result.examples
    ]
    return (
        np.asarray(rows, dtype=np.float32),
        np.asarray([CLASS_ORDER.index(v) for v in ordered_labels]),
        names,
    )


def _partition_indices(result: SyntheticBuildResult, partition: str) -> np.ndarray:
    return np.asarray(
        [i for i, item in enumerate(result.examples) if item.target.partition.value == partition]
    )


def _fit_scaler(x_train: np.ndarray, schema: FeatureSchemaV1) -> tuple[np.ndarray, np.ndarray]:
    numeric = np.asarray([item.dtype != "category" for item in schema.features])
    center = np.zeros(x_train.shape[1], dtype=np.float32)
    scale = np.ones(x_train.shape[1], dtype=np.float32)
    center[numeric] = np.median(x_train[:, numeric], axis=0)
    q75, q25 = np.percentile(x_train[:, numeric], [75, 25], axis=0)
    iqr = (q75 - q25).astype(np.float32)
    scale[numeric] = np.where(iqr == 0, 1.0, iqr)
    return center, scale


def _metrics(y: np.ndarray, probability: np.ndarray) -> dict[str, object]:
    prediction = (probability >= 0.50).astype(np.int64)
    precision, recall, f1, support = precision_recall_fscore_support(
        y, prediction, labels=[0, 1], zero_division=0
    )
    matrix = confusion_matrix(y, prediction, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "threshold": 0.5,
        "class_order": list(CLASS_ORDER),
        "per_class": [
            {
                "label": CLASS_ORDER[i],
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i in range(2)
        ],
        "macro_f1": float(f1_score(y, prediction, average="macro")),
        "weighted_f1": float(f1_score(y, prediction, average="weighted")),
        "roc_auc": float(roc_auc_score(y, probability)),
        "pr_auc": float(average_precision_score(y, probability)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "brier": float(brier_score_loss(y, probability)),
        "confusion_matrix": matrix.tolist(),
        "limitations": SYNTHETIC_LIMITATIONS,
        "synthetic_demo_only": True,
        "real_dataset_used": False,
        "unsw_nb15_acquired": False,
        "unsw_nb15_evaluated": False,
        "network_traffic_generated": False,
        "online_inference_allowed": False,
        "alert_side_effects_allowed": False,
        "prevention_allowed": False,
    }


def validate_onnx_closed_policy(payload: bytes, expected_width: int) -> onnx.ModelProto:
    if len(payload) > MAX_MODEL_BYTES:
        raise ValueError("ml_artifact_size_limit")
    model = onnx.load_model_from_string(payload)
    checker.check_model(model)
    if any(
        item.data_location == TensorProto.EXTERNAL or item.external_data
        for item in model.graph.initializer
    ):
        raise ValueError("ml_onnx_external_data_forbidden")
    if len(model.graph.input) != 1:
        raise ValueError("ml_onnx_shape_forbidden")
    tensor = model.graph.input[0].type.tensor_type
    dimensions = tensor.shape.dim
    if tensor.elem_type != TensorProto.FLOAT or len(dimensions) != 2:
        raise ValueError("ml_onnx_shape_forbidden")
    if dimensions[0].dim_value != 1 or dimensions[1].dim_value != expected_width:
        raise ValueError("ml_onnx_shape_forbidden")
    if {(item.domain, item.version) for item in model.opset_import} != {
        ("", 18),
        ("ai.onnx.ml", 1),
    }:
        raise ValueError("ml_onnx_opset_forbidden")
    if len(model.graph.output) != 2:
        raise ValueError("ml_onnx_output_forbidden")
    label_output = model.graph.output[0].type.tensor_type
    probability_output = model.graph.output[1].type.tensor_type
    label_dims = label_output.shape.dim
    probability_dims = probability_output.shape.dim
    if (
        label_output.elem_type != TensorProto.INT64
        or len(label_dims) != 1
        or label_dims[0].dim_value != 1
        or probability_output.elem_type != TensorProto.FLOAT
        or len(probability_dims) != 2
        or probability_dims[0].dim_value != 1
        or probability_dims[1].dim_value != 2
    ):
        raise ValueError("ml_onnx_output_forbidden")
    for node in model.graph.node:
        if node.domain not in ALLOWED_DOMAINS:
            raise ValueError("ml_onnx_domain_forbidden")
        if node.op_type not in ALLOWED_OPERATORS:
            raise ValueError("ml_onnx_operator_forbidden")
    return model


def _convert(estimator: object, width: int) -> bytes:
    model = convert_sklearn(
        estimator,
        initial_types=[("features", FloatTensorType([1, width]))],
        target_opset={"": 18, "ai.onnx.ml": 3},
        options={id(estimator): {"zipmap": False}},
    )
    model.graph.name = f"aegis_gate5sb_{type(estimator).__name__.lower()}"
    payload = bytes(model.SerializeToString())
    validate_onnx_closed_policy(payload, width)
    return payload


def _onnx_probabilities(payload: bytes, matrix: np.ndarray) -> np.ndarray:
    session = ort.InferenceSession(payload, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    values = [
        session.run(None, {input_name: row.reshape(1, -1).astype(np.float32)})[1][0, 1]
        for row in matrix
    ]
    return np.asarray(values, dtype=np.float64)


def open_sealed_test_once(state: dict[str, object], locked_hash: str) -> str:
    if state.get("opened"):
        raise ValueError("ml_test_already_opened")
    state["opened"] = True
    state["locked_candidate_hash"] = locked_hash
    return canonical_hash(
        {
            "event": "synthetic_test_opened_once",
            "candidate": locked_hash,
            "test_identity": GATE_5SA_HASHES["test_identity"],
        }
    )


def _write_artifact(root: Path, suffix: str, payload: bytes) -> tuple[str, str, int]:
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    object_ref = hashlib.sha256(payload).hexdigest()[:32]
    destination = root / f"{object_ref}.{suffix}"
    if destination.parent != root:
        raise ValueError("ml_artifact_path_invalid")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=root, prefix=".ml-", delete=False) as handle:
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


def delete_candidate_artifacts(result: Gate5SBResult, artifact_root: Path) -> None:
    root = artifact_root.resolve()
    for candidate in result.candidates:
        for object_ref, suffix in (
            (str(candidate.metadata["model_object_ref"]), "onnx"),
            (candidate.metadata_object_ref, "candidate.json"),
        ):
            path = (root / f"{object_ref}.{suffix}").resolve()
            if path.parent != root:
                raise ValueError("ml_artifact_path_invalid")
            path.unlink(missing_ok=True)


def train_gate_5sb(
    result: SyntheticBuildResult, schema: FeatureSchemaV1, artifact_root: Path
) -> Gate5SBResult:
    _verify_boundary(result, schema)
    x, y, names = _encode(result, schema)
    train = _partition_indices(result, "training")
    validation = _partition_indices(result, "validation")
    test = _partition_indices(result, "test")
    center, scale = _fit_scaler(x[train], schema)
    x_scaled = ((x - center) / scale).astype(np.float32)
    preprocessors = {
        "logistic_regression": {
            "scaling": "training_only_robust",
            "center": center.tolist(),
            "scale": scale.tolist(),
        },
        "random_forest": {
            "scaling": "none",
            "center": [0.0] * len(names),
            "scale": [1.0] * len(names),
        },
    }
    estimators: list[tuple[str, Any, np.ndarray]] = [
        (
            "logistic_regression",
            LogisticRegression(
                C=1.0,
                class_weight="balanced",
                max_iter=500,
                random_state=20260714,
                solver="liblinear",
            ),
            x_scaled,
        ),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=20,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                random_state=20260714,
                n_jobs=2,
            ),
            x,
        ),
    ]
    fitted: list[tuple[str, Any, np.ndarray, dict[str, object], bytes]] = []
    majority_probability = np.full(len(validation), float(np.mean(y[train])), dtype=np.float64)
    reference = _metrics(y[validation], majority_probability)
    for algorithm, estimator, matrix in estimators:
        estimator.fit(matrix[train], y[train])
        validation_probability = estimator.predict_proba(matrix[validation])[:, 1]
        metrics = _metrics(y[validation], validation_probability)
        metrics["majority_reference"] = reference
        onnx_bytes = _convert(estimator, matrix.shape[1])
        runtime_probability = _onnx_probabilities(onnx_bytes, matrix[validation])
        if np.max(np.abs(runtime_probability - validation_probability)) > 1e-5:
            raise ValueError("ml_onnx_full_matrix_parity")
        if np.max(np.abs(runtime_probability[:32] - validation_probability[:32])) > 1e-6:
            raise ValueError("ml_onnx_golden_parity")
        if not np.array_equal(runtime_probability >= 0.5, validation_probability >= 0.5):
            raise ValueError("ml_onnx_decision_parity")
        fitted.append((algorithm, estimator, matrix, metrics, onnx_bytes))
    selected = max(
        fitted,
        key=lambda item: (
            cast(float, item[3]["macro_f1"]),
            item[0] == "logistic_regression",
        ),
    )
    selected_preprocessor = {
        "contract": "synthetic-preprocessor-manifest/v1",
        "fit_partition": "training",
        "training_identity_hash": GATE_5SA_HASHES["training_identity"],
        "feature_names": names,
        "category_encoding": "schema_fixed_ordinal",
        "output_dtype": "float32",
        **preprocessors[selected[0]],
        "limitations": SYNTHETIC_LIMITATIONS,
    }
    locked_hash = canonical_hash(
        {
            "algorithm": selected[0],
            "validation": selected[3],
            "preprocessor_hash": canonical_hash(selected_preprocessor),
            "feature_schema_hash": schema.definition_hash,
            "threshold": 0.5,
        }
    )
    opening_hash = open_sealed_test_once({}, locked_hash)
    candidates: list[CandidateArtifact] = []
    written: list[tuple[str, str]] = []
    try:
        for algorithm, estimator, matrix, validation_metrics, onnx_bytes in fitted:
            preprocessor = {
                "contract": "synthetic-preprocessor-manifest/v1",
                "fit_partition": "training",
                "training_identity_hash": GATE_5SA_HASHES["training_identity"],
                "feature_names": names,
                "category_encoding": "schema_fixed_ordinal",
                "output_dtype": "float32",
                **preprocessors[algorithm],
                "limitations": SYNTHETIC_LIMITATIONS,
            }
            preprocessor_hash = canonical_hash(preprocessor)
            test_metrics = None
            if algorithm == selected[0]:
                test_probability = estimator.predict_proba(matrix[test])[:, 1]
                runtime_test = _onnx_probabilities(onnx_bytes, matrix[test])
                if np.max(np.abs(runtime_test - test_probability)) > 1e-5 or not np.array_equal(
                    runtime_test >= 0.5, test_probability >= 0.5
                ):
                    raise ValueError("ml_onnx_test_parity")
                test_metrics = _metrics(y[test], test_probability)
            evaluation = {
                "validation": validation_metrics,
                "test": test_metrics,
                "test_opening_hash": opening_hash if test_metrics else None,
                "no_retuning_after_test": True,
                "limitations": SYNTHETIC_LIMITATIONS,
            }
            card = {
                "contract": "synthetic-model-card/v1",
                "algorithm": algorithm,
                "intended_use": "offline synthetic software-contract demonstration only",
                "prohibited_use": [
                    "real-network inference",
                    "alerts",
                    "prevention",
                    "UNSW-NB15 claims",
                ],
                "limitations": SYNTHETIC_LIMITATIONS,
                "synthetic_demo_only": True,
                "real_dataset_used": False,
                "unsw_nb15_acquired": False,
                "unsw_nb15_evaluated": False,
                "network_traffic_generated": False,
                "online_inference_allowed": False,
                "alert_side_effects_allowed": False,
                "prevention_allowed": False,
            }
            model_ref, model_hash, model_size = _write_artifact(artifact_root, "onnx", onnx_bytes)
            written.append((model_ref, "onnx"))
            metadata = {
                "contract": "synthetic-model-candidate/v1",
                "state": "unreviewed_candidate",
                "algorithm": algorithm,
                "model_object_ref": model_ref,
                "model_sha256": model_hash,
                "preprocessor": preprocessor,
                "evaluation": evaluation,
                "model_card": card,
                "retention_days": 30,
                "loadable_by_api": False,
                "scoring_allowed": False,
                "limitations": SYNTHETIC_LIMITATIONS,
            }
            metadata_payload = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
            metadata_ref, metadata_hash, metadata_size = _write_artifact(
                artifact_root, "candidate.json", metadata_payload
            )
            written.append((metadata_ref, "candidate.json"))
            candidates.append(
                CandidateArtifact(
                    algorithm,
                    validation_metrics,
                    test_metrics,
                    model_hash,
                    model_size,
                    metadata_ref,
                    metadata_hash,
                    metadata_size,
                    preprocessor_hash,
                    canonical_hash(evaluation),
                    canonical_hash(card),
                    onnx_bytes,
                    metadata,
                )
            )
    except Exception:
        root = artifact_root.resolve()
        for object_ref, suffix in written:
            path = (root / f"{object_ref}.{suffix}").resolve()
            if path.parent == root:
                path.unlink(missing_ok=True)
        raise
    return Gate5SBResult(selected[0], locked_hash, opening_hash, tuple(candidates))
