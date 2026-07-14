from __future__ import annotations

import hashlib
import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from starlette.datastructures import UploadFile

OBJECT_REF = re.compile(r"^uploads/[0-9a-f]{32}\.bin$")
CHUNK_SIZE = 64 * 1024


class UploadTooLarge(Exception):
    pass


@dataclass(frozen=True)
class StoredUpload:
    object_ref: str
    sha256: str
    size_bytes: int
    prefix: bytes


def prepare_upload_root(artifact_root: Path) -> Path:
    base = artifact_root.resolve()
    upload_root = artifact_root / "uploads"
    if upload_root.is_symlink():
        raise OSError("upload root must not be a symlink")
    upload_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = upload_root.resolve()
    if resolved != base / "uploads":
        raise OSError("upload root escapes controlled storage")
    return resolved


async def store_upload(upload: UploadFile, artifact_root: Path, max_bytes: int) -> StoredUpload:
    async def chunks() -> AsyncIterator[bytes]:
        while chunk := await upload.read(CHUNK_SIZE):
            yield chunk

    try:
        return await store_chunks(chunks(), artifact_root, max_bytes)
    finally:
        await upload.close()


async def store_chunks(
    chunks: AsyncIterator[bytes], artifact_root: Path, max_bytes: int
) -> StoredUpload:
    root = prepare_upload_root(artifact_root)
    opaque_name = f"{uuid4().hex}.bin"
    destination = root / opaque_name
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    digest = hashlib.sha256()
    total = 0
    prefix = b""
    try:
        with os.fdopen(descriptor, "wb") as handle:
            async for chunk in chunks:
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLarge
                if len(prefix) < 4096:
                    prefix += chunk[: 4096 - len(prefix)]
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return StoredUpload(
        object_ref=f"uploads/{opaque_name}",
        sha256=digest.hexdigest(),
        size_bytes=total,
        prefix=prefix,
    )


def resolve_object_ref(artifact_root: Path, object_ref: str) -> Path:
    if not OBJECT_REF.fullmatch(object_ref):
        raise ValueError("invalid object reference")
    root = artifact_root.resolve()
    upload_root = root / "uploads"
    candidate = root / object_ref
    if upload_root.is_symlink() or candidate.is_symlink():
        raise ValueError("symbolic object reference is prohibited")
    candidate = candidate.resolve()
    if candidate.parent != upload_root:
        raise ValueError("object reference escapes controlled storage")
    return candidate


def delete_object(artifact_root: Path, object_ref: str | None) -> bool:
    if object_ref is None:
        return False
    path = resolve_object_ref(artifact_root, object_ref)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed
