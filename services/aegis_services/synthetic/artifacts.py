from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from aegis_services.features import PROVENANCE_COLUMNS, WrittenArtifact, write_parquet

from .generator import SyntheticBuildResult


@dataclass(frozen=True)
class WrittenJsonArtifact:
    object_ref: str
    sha256: str
    size_bytes: int
    row_count: int
    media_type: str


def _root(root: Path) -> Path:
    value = root.resolve()
    value.mkdir(mode=0o700, parents=True, exist_ok=True)
    return value


def _write_bytes(
    root: Path, payload: bytes, suffix: str, media_type: str, rows: int
) -> WrittenJsonArtifact:
    safe_root = _root(root)
    object_ref = str(uuid4())
    destination = safe_root / f"{object_ref}.{suffix}"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=safe_root, prefix=".synthetic-", delete=False) as tmp:
            temporary_name = tmp.name
            os.chmod(temporary_name, 0o600)
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
        return WrittenJsonArtifact(
            object_ref=object_ref,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            row_count=rows,
            media_type=media_type,
        )
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def write_synthetic_artifacts(
    result: SyntheticBuildResult, root: Path, *, max_feature_bytes: int
) -> tuple[WrittenJsonArtifact, WrittenJsonArtifact, WrittenArtifact]:
    flow_payload = b"".join(
        json.dumps(
            item.flow.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        + b"\n"
        for item in result.examples
    )
    target_payload = json.dumps(
        [item.target.model_dump(mode="json") for item in result.examples],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    flow_artifact = _write_bytes(
        root, flow_payload, "jsonl", "application/x-ndjson", len(result.examples)
    )
    target_artifact = _write_bytes(
        root, target_payload, "targets.json", "application/json", len(result.examples)
    )
    feature_artifact = write_parquet(result.vectors, root, max_output_bytes=max_feature_bytes)
    return flow_artifact, target_artifact, feature_artifact


def select_model_matrix(
    path: Path, expected_names: tuple[str, ...], *, max_rows: int = 10_000
) -> object:
    try:
        import pyarrow.parquet as pq
    except ImportError as error:  # pragma: no cover
        raise RuntimeError("parquet_dependency_unavailable") from error
    if len(expected_names) != 39 or len(set(expected_names)) != 39:
        raise ValueError("synthetic_model_feature_contract_invalid")
    expected_columns = (*PROVENANCE_COLUMNS, *expected_names)
    parquet = pq.ParquetFile(path)
    metadata = parquet.metadata
    if metadata is None or metadata.num_rows > max_rows or metadata.num_columns != 46:
        raise ValueError("synthetic_scoring_resource_limit")
    if tuple(parquet.schema_arrow.names) != expected_columns:
        raise ValueError("synthetic_feature_columns_invalid")
    return pq.read_table(path, columns=list(expected_names))


def synthetic_artifact_path(root: Path, object_ref: str, suffix: str) -> Path:
    try:
        parsed = UUID(object_ref)
    except ValueError as error:
        raise ValueError("synthetic_artifact_ref_invalid") from error
    path = (_root(root) / f"{parsed}.{suffix}").resolve()
    if path.parent != _root(root) or not path.is_file():
        raise ValueError("synthetic_artifact_missing")
    return path


def verify_synthetic_artifact(
    root: Path,
    object_ref: str,
    suffix: str,
    *,
    expected_sha256: str,
    expected_size: int,
    maximum_size: int,
) -> None:
    path = synthetic_artifact_path(root, object_ref, suffix)
    actual_size = path.stat().st_size
    if actual_size != expected_size or actual_size > maximum_size:
        raise ValueError("synthetic_artifact_size_mismatch")
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > maximum_size:
                raise ValueError("synthetic_artifact_size_limit")
            digest.update(chunk)
    if consumed != expected_size or digest.hexdigest() != expected_sha256:
        raise ValueError("synthetic_artifact_integrity")
