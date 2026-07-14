from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from aegis_services.features.schema import FeatureVectorV1

PROVENANCE_COLUMNS = (
    "__aegis_source_event_key",
    "__aegis_cutoff_time",
    "__aegis_feature_schema_hash",
    "__aegis_feature_schema_version",
    "__aegis_source_snapshot_hash",
    "__aegis_vector_hash",
    "__aegis_quality_flags",
)


@dataclass(frozen=True)
class WrittenArtifact:
    artifact_id: UUID
    object_ref: str
    sha256: str
    size_bytes: int
    row_count: int
    column_count: int
    media_type: str = "application/vnd.apache.parquet"


def _safe_root(root: Path) -> Path:
    resolved = root.resolve()
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    return resolved


def write_parquet(
    vectors: tuple[FeatureVectorV1, ...], root: Path, *, max_output_bytes: int
) -> WrittenArtifact:
    if not vectors:
        raise ValueError("feature_artifact_empty")
    names = vectors[0].ordered_names
    if any(vector.ordered_names != names for vector in vectors):
        raise ValueError("feature_artifact_schema_mismatch")
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as error:  # pragma: no cover - dependency gate exercises container build
        raise RuntimeError("parquet_dependency_unavailable") from error

    artifact_id = uuid4()
    safe_root = _safe_root(root)
    final_path = safe_root / f"{artifact_id}.parquet"
    rows = [
        {
            "__aegis_source_event_key": vector.source_event_key,
            "__aegis_cutoff_time": vector.cutoff_time,
            "__aegis_feature_schema_hash": vector.feature_schema_hash,
            "__aegis_feature_schema_version": vector.feature_schema_version,
            "__aegis_source_snapshot_hash": vector.source_snapshot_hash,
            "__aegis_vector_hash": vector.vector_hash,
            "__aegis_quality_flags": list(vector.quality_flags),
            **dict(zip(names, vector.ordered_values, strict=True)),
        }
        for vector in vectors
    ]
    table = pa.Table.from_pylist(rows)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=safe_root, prefix=".feature-", suffix=".tmp", delete=False
        ) as temporary:
            temporary_name = temporary.name
        os.chmod(temporary_name, 0o600)
        pq.write_table(table, temporary_name, compression="zstd")
        size = os.path.getsize(temporary_name)
        if size > max_output_bytes:
            raise ValueError("feature_artifact_size_limit")
        digest = hashlib.sha256()
        with open(temporary_name, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        os.replace(temporary_name, final_path)
        temporary_name = None
        return WrittenArtifact(
            artifact_id=artifact_id,
            object_ref=str(artifact_id),
            sha256=digest.hexdigest(),
            size_bytes=size,
            row_count=len(rows),
            column_count=len(names) + len(PROVENANCE_COLUMNS),
        )
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def verify_artifact(root: Path, object_ref: str, expected_sha256: str) -> Path:
    try:
        artifact_id = UUID(object_ref)
    except ValueError as error:
        raise ValueError("feature_artifact_ref_invalid") from error
    path = (_safe_root(root) / f"{artifact_id}.parquet").resolve()
    if path.parent != _safe_root(root) or not path.is_file():
        raise ValueError("feature_artifact_missing")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != expected_sha256:
        raise ValueError("feature_artifact_integrity_failure")
    return path
