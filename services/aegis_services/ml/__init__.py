"""Lazy ML exports so the API image does not import native ML runtimes at startup."""

from typing import Any

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

_TRAINING_EXPORTS = {
    "Gate5SBResult",
    "delete_candidate_artifacts",
    "open_sealed_test_once",
    "train_gate_5sb",
    "validate_onnx_closed_policy",
}


def __getattr__(name: str) -> Any:
    if name in _TRAINING_EXPORTS:
        from . import training

        return getattr(training, name)
    raise AttributeError(name)


__all__ = ["GATE_5SA_HASHES", *_TRAINING_EXPORTS]
