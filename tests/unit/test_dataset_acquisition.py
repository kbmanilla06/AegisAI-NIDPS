from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_services.datasets import (
    AcquisitionFileV1,
    AcquisitionLimitsV1,
    AcquisitionManifestV1,
    AcquisitionState,
    BoundedTransferClient,
    transition_acquisition,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _file(**overrides: object) -> AcquisitionFileV1:
    values: dict[str, object] = {
        "logical_name": "UNSW-NB15_1.csv",
        "source_url": "https://dataset.example.invalid/UNSW-NB15_1.csv",
        "advertised_size_bytes": 4,
        "media_type": "text/csv",
        "role": "principal_data_part",
    }
    values.update(overrides)
    return AcquisitionFileV1.model_validate(values)


def _manifest(*, state: AcquisitionState = AcquisitionState.PROPOSED) -> AcquisitionManifestV1:
    return AcquisitionManifestV1(
        dataset_name="UNSW-NB15",
        dataset_version="publisher-review-2026-07-14",
        official_page_url="https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        source_review_hash=_hash("review"),
        terms_reference_hash=_hash("terms"),
        state=state,
        owner_approval_reference="OWNER-S5-DATASET-001"
        if state != AcquisitionState.PROPOSED
        else None,
        allowed_hosts=("dataset.example.invalid",),
        files=(_file(),),
        limits=AcquisitionLimitsV1(protected_free_bytes=50 * 1024**3),
    )


def test_manifest_rejects_urls_credentials_archives_and_unapproved_authority() -> None:
    for url in (
        "http://dataset.example.invalid/file.csv",
        "https://user@dataset.example.invalid/file.csv",
        "https://dataset.example.invalid/file.csv?token=secret",
        "https://dataset.example.invalid/file.csv#fragment",
    ):
        with pytest.raises(ValidationError):
            _file(source_url=url)
    with pytest.raises(ValidationError, match="archives"):
        AcquisitionManifestV1(
            **_manifest().model_dump(exclude={"files"}), files=(_file(archive=True),)
        )
    with pytest.raises(ValidationError, match="approval"):
        AcquisitionManifestV1(
            **_manifest().model_dump(exclude={"state"}), state=AcquisitionState.OWNER_APPROVED
        )


def test_state_machine_rejects_skips_and_terminal_reentry() -> None:
    assert (
        transition_acquisition(AcquisitionState.PROPOSED, AcquisitionState.OWNER_APPROVED)
        == AcquisitionState.OWNER_APPROVED
    )
    with pytest.raises(ValueError, match="state transition"):
        transition_acquisition(AcquisitionState.PROPOSED, AcquisitionState.ACQUIRED)
    with pytest.raises(ValueError, match="state transition"):
        transition_acquisition(AcquisitionState.FAILED, AcquisitionState.TRANSFERRING)


@dataclass
class FakeResponse:
    body: bytes
    headers: Mapping[str, str]
    status_code: int = 200
    final_url: str = "https://dataset.example.invalid/UNSW-NB15_1.csv"
    redirect_urls: tuple[str, ...] = ()

    def iter_bytes(self, chunk_size: int) -> Iterable[bytes]:
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset : offset + chunk_size]


class FakeTransport:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        connect_timeout_seconds: int,
        idle_timeout_seconds: int,
        file_deadline_seconds: int,
    ) -> FakeResponse:
        assert connect_timeout_seconds == 30
        assert idle_timeout_seconds == 120
        assert file_deadline_seconds == 1_800
        self.calls.append(url)
        return self.response


def test_transfer_requires_owner_approval_before_network_or_storage(tmp_path: Path) -> None:
    transport = FakeTransport(
        FakeResponse(b"data", {"content-length": "4", "content-type": "text/csv"})
    )
    client = BoundedTransferClient(tmp_path / "datasets", transport)
    with pytest.raises(PermissionError, match="owner approved"):
        client.transfer(_manifest(), "UNSW-NB15_1.csv")
    assert not transport.calls
    assert not (tmp_path / "datasets").exists()


def test_transfer_is_atomic_mode_0600_hashed_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aegis_services.datasets.acquisition._require_public_dns", lambda _host: None
    )
    transport = FakeTransport(
        FakeResponse(b"data", {"content-length": "4", "content-type": "text/csv"})
    )
    root = tmp_path / "datasets"
    result = BoundedTransferClient(root, transport).transfer(
        _manifest(state=AcquisitionState.OWNER_APPROVED), "UNSW-NB15_1.csv"
    )
    path = root / result.object_ref
    assert path.read_bytes() == b"data"
    assert result.sha256 == hashlib.sha256(b"data").hexdigest()
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(root.glob("*.part"))


def test_transfer_deletes_partial_on_size_or_integrity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aegis_services.datasets.acquisition._require_public_dns", lambda _host: None
    )
    response = FakeResponse(b"toolong", {"content-length": "4", "content-type": "text/csv"})
    root = tmp_path / "datasets"
    with pytest.raises(ValueError, match="byte limit"):
        BoundedTransferClient(root, FakeTransport(response)).transfer(
            _manifest(state=AcquisitionState.OWNER_APPROVED), "UNSW-NB15_1.csv"
        )
    assert list(root.iterdir()) == []


def test_transfer_rejects_unapproved_redirect_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aegis_services.datasets.acquisition._require_public_dns", lambda _host: None
    )
    response = FakeResponse(
        b"data",
        {"content-length": "4", "content-type": "text/csv"},
        final_url="https://evil.invalid/UNSW-NB15_1.csv",
        redirect_urls=("https://evil.invalid/redirect",),
    )
    root = tmp_path / "datasets"
    with pytest.raises(ValueError, match="redirect chain"):
        BoundedTransferClient(root, FakeTransport(response)).transfer(
            _manifest(state=AcquisitionState.OWNER_APPROVED), "UNSW-NB15_1.csv"
        )
    assert list(root.iterdir()) == []
