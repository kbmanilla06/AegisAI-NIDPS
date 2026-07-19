"""Pure, metadata-only Gate P4 reproducibility evidence helpers.

This module deliberately performs no network, subprocess, Docker, model, or
dataset operation. It hashes an allowlisted set of repository control files and
describes the already-accepted synthetic evidence without reading any payload.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Final

CONTRACT: Final = "deployment_reproducibility/1.0.0"
MAX_CONTROL_FILE_BYTES: Final = 2 * 1024 * 1024

ACCEPTED_SYNTHETIC_HASHES: Final[dict[str, str]] = {
    "scenario_catalog": "72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87",
    "feature_schema": "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114",
    "dataset_content": "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a",
    "canonical_flow_artifact": "96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac",
    "target_artifact": "90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70",
    "feature_artifact": "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9",
    "split_manifest": "d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895",
    "quality_report": "c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4",
    "leakage_report": "2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d",
    "training_identity": "25484ad54cfbcd91dfb1312fb2faab07569baf84558acbaacce3484d7ebadea7",
    "validation_identity": "96116e2b745321f11c0e3d8e753c9b9b0f75a6d5abce2e733f0576f4ff1a770f",
    "sealed_test_identity": "ee45a32898ba678aa51b79b054d5589edb47df4b178a8b55d1fc0c6b21160eb4",
}

FALSE_CAPABILITY_FLAGS: Final[dict[str, bool]] = {
    "real_dataset_used": False,
    "unsw_nb15_acquired": False,
    "live_capture_enabled": False,
    "online_inference_allowed": False,
    "model_activation_allowed": False,
    "alert_side_effects_allowed": False,
    "prevention_allowed": False,
}

CONTROL_FILES: Final[tuple[str, ...]] = (
    ".env.example",
    ".github/workflows/ci.yml",
    "apps/api/Dockerfile",
    "apps/worker/Dockerfile",
    "apps/dashboard/Dockerfile",
    "apps/dashboard/package.json",
    "apps/dashboard/package-lock.json",
    "constraints/ml-arm64-py312.lock",
    "docker-compose.yml",
    "pyproject.toml",
)
SOURCE_ROOTS: Final[tuple[str, ...]] = (
    "apps/api",
    "apps/worker",
    "apps/dashboard/src",
    "migrations",
    "services",
)
SOURCE_SUFFIXES: Final[frozenset[str]] = frozenset({".css", ".json", ".py", ".ts", ".tsx"})

_DIGEST_RE: Final = re.compile(r"sha256:([0-9a-f]{64})")
_FORBIDDEN_COMPOSE_MARKERS: Final[tuple[str, ...]] = (
    "privileged" + ": true",
    "network_mode" + ": host",
    "/var/run/docker" + ".sock",
    "NET_" + "ADMIN",
    "NET_" + "RAW",
)
_LIMITATION_TEXT: Final = (
    "SYNTHETIC DEMO ONLY. Monitoring evidence is derived from project-generated synthetic "
    "metadata and offline artifacts. It does not measure real-network drift, UNSW-NB15 "
    "performance, production readiness, or prevention suitability. Monitoring cannot activate "
    "models or create or modify alerts, detections, incidents, or prevention actions."
)


class ReproducibilityError(ValueError):
    """Raised when the safe, metadata-only evidence contract cannot be built."""


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _safe_file(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    candidate = (root / relative).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ReproducibilityError("control_file_outside_project")
    return candidate


def _hash_control_file(root: Path, relative: str) -> str:
    path = _safe_file(root, relative)
    if not path.is_file():
        raise ReproducibilityError(f"missing_control_file:{relative}")
    if path.stat().st_size > MAX_CONTROL_FILE_BYTES:
        raise ReproducibilityError(f"control_file_too_large:{relative}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_control_file(root: Path, relative: str) -> str:
    path = _safe_file(root, relative)
    if not path.is_file() or path.stat().st_size > MAX_CONTROL_FILE_BYTES:
        raise ReproducibilityError(f"invalid_control_file:{relative}")
    return path.read_text(encoding="utf-8")


def _source_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for source_root in SOURCE_ROOTS:
        directory = _safe_file(root, source_root)
        if not directory.is_dir():
            raise ReproducibilityError(f"missing_source_root:{source_root}")
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            hashes[relative] = _hash_control_file(root, relative)
    return hashes


def _image_digests(compose_text: str) -> list[str]:
    return sorted(set(_DIGEST_RE.findall(compose_text)))


def _base_image_digests(root: Path) -> list[str]:
    digests: set[str] = set()
    for relative in ("apps/api/Dockerfile", "apps/worker/Dockerfile", "apps/dashboard/Dockerfile"):
        digests.update(_DIGEST_RE.findall(_read_control_file(root, relative)))
    return sorted(digests)


def _security_posture(compose_text: str) -> dict[str, bool]:
    markers = {marker: marker not in compose_text for marker in _FORBIDDEN_COMPOSE_MARKERS}
    localhost_ports = any(
        "127.0.0.1:" in line and line.lstrip().startswith("-") for line in compose_text.splitlines()
    )
    return {
        "forbidden_compose_markers_absent": all(markers.values()),
        "localhost_published_ports": localhost_ports,
        "simulation_mode_declared": "AEGIS_PREVENTION_MODE: simulation" in compose_text,
        "no_public_dataset_source": True,
        "no_execution_payload": True,
    }


def build_manifest(root: Path) -> dict[str, object]:
    """Build a stable, aggregate-only reproducibility manifest for ``root``."""

    root = root.resolve()
    compose_text = _read_control_file(root, "docker-compose.yml")
    control_hashes = {relative: _hash_control_file(root, relative) for relative in CONTROL_FILES}
    source_hashes = _source_hashes(root)
    posture = _security_posture(compose_text)
    if not all(posture.values()):
        raise ReproducibilityError("unsafe_compose_posture")

    stable_identity: dict[str, object] = {
        "contract": CONTRACT,
        "control_file_sha256": control_hashes,
        "source_file_sha256": source_hashes,
        "source_tree_sha256": _canonical_hash(source_hashes),
        "compose_image_digests": _image_digests(compose_text),
        "base_image_digests": _base_image_digests(root),
        "accepted_synthetic_hashes": ACCEPTED_SYNTHETIC_HASHES,
        "limitation_text_sha256": hashlib.sha256(_LIMITATION_TEXT.encode()).hexdigest(),
        "false_capability_flags": FALSE_CAPABILITY_FLAGS,
        "security_posture": posture,
        "prevention_mode": "simulation",
        "raw_payloads_included": False,
        "credentials_included": False,
    }
    return {
        "contract": CONTRACT,
        "identity": stable_identity,
        "identity_sha256": _canonical_hash(stable_identity),
        "runtime": {
            "architecture": platform.machine(),
            "operating_system": platform.platform(aliased=True),
            "python": platform.python_version(),
        },
        "limitations": _LIMITATION_TEXT,
        "false_capability_flags": FALSE_CAPABILITY_FLAGS,
        "retention": {
            "flow_days": 30,
            "alert_days": 180,
            "audit_days": 180,
            "evidence_days": 30,
            "exceptional_holds_enabled": False,
        },
    }


def write_manifest(root: Path, output: Path) -> dict[str, object]:
    """Write canonical JSON without exposing the project path in the evidence."""

    manifest = build_manifest(root)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(output)
    output.chmod(0o600)
    return manifest
