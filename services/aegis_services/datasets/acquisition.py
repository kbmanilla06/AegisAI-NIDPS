from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import socket
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

GIB = 1024**3


class AcquisitionState(StrEnum):
    PROPOSED = "proposed"
    OWNER_APPROVED = "owner_approved"
    TRANSFERRING = "transferring"
    ACQUIRED = "acquired"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TRANSITIONS: Mapping[AcquisitionState, frozenset[AcquisitionState]] = {
    AcquisitionState.PROPOSED: frozenset(
        {AcquisitionState.OWNER_APPROVED, AcquisitionState.CANCELLED}
    ),
    AcquisitionState.OWNER_APPROVED: frozenset(
        {AcquisitionState.TRANSFERRING, AcquisitionState.CANCELLED}
    ),
    AcquisitionState.TRANSFERRING: frozenset({AcquisitionState.ACQUIRED, AcquisitionState.FAILED}),
    AcquisitionState.ACQUIRED: frozenset(),
    AcquisitionState.FAILED: frozenset(),
    AcquisitionState.CANCELLED: frozenset(),
}


def transition_acquisition(current: AcquisitionState, target: AcquisitionState) -> AcquisitionState:
    if target not in _TRANSITIONS[current]:
        raise ValueError("invalid acquisition state transition")
    return target


class AcquisitionLimitsV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    combined_bytes: int = Field(default=5 * GIB, ge=1, le=5 * GIB)
    file_bytes: int = Field(default=2 * GIB, ge=1, le=2 * GIB)
    file_count: int = Field(default=10, ge=1, le=10)
    redirect_count: int = Field(default=5, ge=0, le=5)
    connect_timeout_seconds: int = Field(default=30, ge=1, le=30)
    idle_timeout_seconds: int = Field(default=120, ge=1, le=120)
    file_deadline_seconds: int = Field(default=1_800, ge=1, le=1_800)
    retry_count: int = Field(default=2, ge=0, le=2)
    protected_free_bytes: int = Field(default=50 * GIB, ge=50 * GIB)
    archive_allowed: bool = False


class AcquisitionFileV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    logical_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    source_url: str = Field(min_length=1, max_length=1024)
    advertised_size_bytes: int = Field(ge=1, le=2 * GIB)
    media_type: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    upstream_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    archive: bool = False

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("source URL must be credential-free query-free HTTPS")
        return value


class AcquisitionManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = Field(
        default="dataset-acquisition-manifest/v1", pattern=r"^dataset-acquisition-manifest/v1$"
    )
    dataset_name: str = Field(min_length=1, max_length=128)
    dataset_version: str = Field(min_length=1, max_length=64)
    official_page_url: str = Field(max_length=512, pattern=r"^https://")
    source_review_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    terms_reference_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    intended_use: str = Field(default="academic_portfolio", pattern=r"^academic_portfolio$")
    state: AcquisitionState = AcquisitionState.PROPOSED
    owner_approval_reference: str | None = Field(default=None, min_length=8, max_length=128)
    allowed_hosts: tuple[str, ...] = Field(min_length=1, max_length=8)
    files: tuple[AcquisitionFileV1, ...] = Field(min_length=1, max_length=10)
    limits: AcquisitionLimitsV1 = Field(default_factory=AcquisitionLimitsV1)
    raw_retention_days: int = Field(default=90, ge=1, le=90)
    raw_pcap_excluded: bool = True
    redistribution_authorized: bool = False

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.lower().rstrip(".") for value in values)
        if any(not value or "/" in value or ":" in value for value in normalized):
            raise ValueError("allowed hosts must be bare DNS names")
        if len(normalized) != len(set(normalized)):
            raise ValueError("allowed hosts must be unique")
        return normalized

    @model_validator(mode="after")
    def enforce_authority_and_limits(self) -> AcquisitionManifestV1:
        if self.state != AcquisitionState.PROPOSED and not self.owner_approval_reference:
            raise ValueError("non-proposed manifests require an owner approval reference")
        if self.state == AcquisitionState.PROPOSED and self.owner_approval_reference:
            raise ValueError("proposed manifests cannot claim owner approval")
        if not self.raw_pcap_excluded or self.redistribution_authorized:
            raise ValueError("raw PCAP and redistribution must remain prohibited")
        if len(self.files) > self.limits.file_count:
            raise ValueError("file count exceeds acquisition limit")
        if sum(item.advertised_size_bytes for item in self.files) > self.limits.combined_bytes:
            raise ValueError("combined advertised size exceeds acquisition limit")
        if any(item.advertised_size_bytes > self.limits.file_bytes for item in self.files):
            raise ValueError("advertised file size exceeds acquisition limit")
        if any(item.archive for item in self.files) or self.limits.archive_allowed:
            raise ValueError("archives are prohibited at the pre-acquisition gate")
        allowed = set(self.allowed_hosts)
        if any(
            (urlsplit(item.source_url).hostname or "").lower() not in allowed for item in self.files
        ):
            raise ValueError("every source URL host must be explicitly allowlisted")
        if len({item.logical_name for item in self.files}) != len(self.files):
            raise ValueError("logical filenames must be unique")
        return self

    @property
    def manifest_hash(self) -> str:
        import json

        value = self.model_dump(mode="json", exclude_none=False)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


class TransferResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]
    final_url: str
    redirect_urls: tuple[str, ...]

    def iter_bytes(self, chunk_size: int) -> Iterable[bytes]: ...


class TransferTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        connect_timeout_seconds: int,
        idle_timeout_seconds: int,
        file_deadline_seconds: int,
    ) -> TransferResponse: ...


@dataclass(frozen=True)
class TransferResult:
    object_ref: str
    sha256: str
    size_bytes: int
    media_type: str


class BoundedTransferClient:
    """Transfer one exact authorized file into opaque controlled storage.

    Network behavior is injected so ordinary tests and CI never contact a dataset host.
    """

    def __init__(self, root: Path, transport: TransferTransport) -> None:
        self._root = root.resolve()
        self._transport = transport

    def transfer(self, manifest: AcquisitionManifestV1, logical_name: str) -> TransferResult:
        if manifest.state != AcquisitionState.OWNER_APPROVED:
            raise PermissionError("dataset acquisition has not been owner approved")
        candidate = next(
            (item for item in manifest.files if item.logical_name == logical_name), None
        )
        if candidate is None:
            raise ValueError("requested file is not in the approved manifest")
        self._preflight(candidate, manifest.limits)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        object_ref = str(uuid4())
        staging = self._root / f".{object_ref}.part"
        destination = self._root / object_ref
        digest = hashlib.sha256()
        size = 0
        started = time.monotonic()
        try:
            response = self._request_with_retries(candidate, manifest.limits)
            _validate_response_chain(
                candidate.source_url,
                response.final_url,
                response.redirect_urls,
                manifest.allowed_hosts,
                manifest.limits.redirect_count,
            )
            if response.status_code != 200:
                raise ValueError("dataset transfer returned an unexpected status")
            declared = response.headers.get("content-length")
            if declared is None or not declared.isdigit():
                raise ValueError("dataset transfer requires a valid content length")
            if int(declared) != candidate.advertised_size_bytes:
                raise ValueError("dataset content length differs from the approved manifest")
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != candidate.media_type.lower():
                raise ValueError("dataset media type differs from the approved manifest")
            descriptor = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                for chunk in response.iter_bytes(1024 * 1024):
                    if time.monotonic() - started > manifest.limits.file_deadline_seconds:
                        raise TimeoutError("dataset transfer exceeded its deadline")
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > candidate.advertised_size_bytes or size > manifest.limits.file_bytes:
                        raise ValueError("dataset transfer exceeded its byte limit")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if size != candidate.advertised_size_bytes:
                raise ValueError("dataset transfer ended before the approved byte count")
            sha256 = digest.hexdigest()
            if candidate.upstream_sha256 and sha256 != candidate.upstream_sha256:
                raise ValueError("dataset transfer checksum mismatch")
            os.replace(staging, destination)
            os.chmod(destination, 0o600)
            return TransferResult(object_ref, sha256, size, candidate.media_type)
        except Exception:
            staging.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            raise

    def _request_with_retries(
        self, candidate: AcquisitionFileV1, limits: AcquisitionLimitsV1
    ) -> TransferResponse:
        last_error: OSError | TimeoutError | None = None
        for _attempt in range(limits.retry_count + 1):
            try:
                return self._transport.get(
                    candidate.source_url,
                    connect_timeout_seconds=limits.connect_timeout_seconds,
                    idle_timeout_seconds=limits.idle_timeout_seconds,
                    file_deadline_seconds=limits.file_deadline_seconds,
                )
            except (OSError, TimeoutError) as error:
                last_error = error
        assert last_error is not None
        raise last_error

    def _preflight(self, candidate: AcquisitionFileV1, limits: AcquisitionLimitsV1) -> None:
        parsed = urlsplit(candidate.source_url)
        assert parsed.hostname is not None
        _require_public_dns(parsed.hostname)
        nearest = self._root if self._root.exists() else self._root.parent
        while not nearest.exists() and nearest != nearest.parent:
            nearest = nearest.parent
        free = shutil.disk_usage(nearest).free
        required = limits.protected_free_bytes + 3 * candidate.advertised_size_bytes
        if free < required:
            raise OSError("insufficient protected free space for dataset acquisition")


def _require_public_dns(hostname: str) -> None:
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        }
    except OSError as error:
        raise ValueError("dataset host could not be resolved safely") from error
    if not addresses:
        raise ValueError("dataset host did not resolve")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError("dataset host resolved to a non-public address")


def _validate_response_chain(
    requested_url: str,
    final_url: str,
    redirect_urls: tuple[str, ...],
    allowed_hosts: tuple[str, ...],
    redirect_limit: int,
) -> None:
    if len(redirect_urls) > redirect_limit:
        raise ValueError("dataset transfer exceeded its redirect limit")
    chain = (requested_url, *redirect_urls, final_url)
    allowed = set(allowed_hosts)
    for url in chain:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or not host
            or host not in allowed
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("dataset transfer redirect chain is not authorized")
        _require_public_dns(host)
