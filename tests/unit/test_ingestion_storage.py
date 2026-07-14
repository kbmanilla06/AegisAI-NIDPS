from pathlib import Path

import pytest

from aegis_api.ingestion_storage import prepare_upload_root, resolve_object_ref


@pytest.mark.parametrize(
    "reference",
    ["../secret", "uploads/../../secret", "/etc/passwd", "uploads/name.pcap", "uploads/xyz.bin"],
)
def test_object_reference_rejects_paths_and_user_names(tmp_path: Path, reference: str) -> None:
    with pytest.raises(ValueError, match="invalid object reference"):
        resolve_object_ref(tmp_path, reference)


def test_upload_root_rejects_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "uploads").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError, match="must not be a symlink"):
        prepare_upload_root(artifact_root)


def test_object_reference_rejects_symlink_substitution(tmp_path: Path) -> None:
    upload_root = prepare_upload_root(tmp_path)
    target = upload_root / ("a" * 32 + ".bin")
    target.write_bytes(b"first")
    substituted = upload_root / ("b" * 32 + ".bin")
    substituted.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic object reference"):
        resolve_object_ref(tmp_path, f"uploads/{substituted.name}")
