from pathlib import Path

import pytest

from aegis_services.reproducibility import (
    ACCEPTED_SYNTHETIC_HASHES,
    CONTRACT,
    FALSE_CAPABILITY_FLAGS,
    ReproducibilityError,
    build_manifest,
    write_manifest,
)

ROOT = Path(__file__).parents[2]


def test_manifest_is_aggregate_only_and_binds_accepted_synthetic_hashes() -> None:
    manifest = build_manifest(ROOT)
    identity = manifest["identity"]
    assert manifest["contract"] == CONTRACT
    assert isinstance(identity, dict)
    assert identity["accepted_synthetic_hashes"] == ACCEPTED_SYNTHETIC_HASHES
    assert manifest["false_capability_flags"] == FALSE_CAPABILITY_FLAGS
    assert manifest["retention"] == {
        "flow_days": 30,
        "alert_days": 180,
        "audit_days": 180,
        "evidence_days": 30,
        "exceptional_holds_enabled": False,
    }
    assert identity["raw_payloads_included"] is False
    assert identity["credentials_included"] is False


def test_manifest_is_deterministic_for_stable_identity() -> None:
    first = build_manifest(ROOT)
    second = build_manifest(ROOT)
    assert first["identity"] == second["identity"]
    assert first["identity_sha256"] == second["identity_sha256"]


def test_manifest_rejects_unsafe_compose_posture(tmp_path: Path) -> None:
    for relative in (
        ".env.example",
        ".github/workflows/ci.yml",
        "apps/api/Dockerfile",
        "apps/worker/Dockerfile",
        "apps/dashboard/Dockerfile",
        "apps/dashboard/package.json",
        "apps/dashboard/package-lock.json",
        "constraints/ml-arm64-py312.lock",
        "pyproject.toml",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("control", encoding="utf-8")
    for relative in (
        "apps/dashboard/src/main.tsx",
        "migrations/000.py",
        "services/a.py",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("control", encoding="utf-8")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("privileged: true\n", encoding="utf-8")
    with pytest.raises(ReproducibilityError, match="unsafe_compose_posture"):
        build_manifest(tmp_path)


def test_write_manifest_uses_restrictive_file_mode(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    write_manifest(ROOT, output)
    assert output.stat().st_mode & 0o777 == 0o600
    assert "identity_sha256" in output.read_text(encoding="utf-8")
