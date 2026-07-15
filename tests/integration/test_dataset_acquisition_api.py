from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from aegis_api.models import AuditEvent, DatasetAcquisitionPlan
from conftest import ORIGIN, AppHarness


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _proposal() -> dict[str, object]:
    return {
        "dataset_name": "UNSW-NB15",
        "dataset_version": "publisher-review-2026-07-14",
        "official_page_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "source_review_hash": _hash("source-review"),
        "terms_reference_hash": _hash("terms-review"),
        "state": "proposed",
        "allowed_hosts": ["dataset.example.invalid"],
        "files": [
            {
                "logical_name": "UNSW-NB15_1.csv",
                "source_url": "https://dataset.example.invalid/UNSW-NB15_1.csv",
                "advertised_size_bytes": 4,
                "media_type": "text/csv",
                "role": "principal_data_part",
                "archive": False,
            }
        ],
    }


def test_only_system_administrator_can_record_preapproval_proposal(
    app_harness: AppHarness,
) -> None:
    for role in (
        "Viewer",
        "SOC Analyst",
        "Senior Analyst",
        "Security Administrator",
        "Auditor",
    ):
        _, csrf = app_harness.login(role)
        response = app_harness.client.post(
            "/api/v1/dataset-acquisition-plans",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json=_proposal(),
        )
        assert response.status_code == 403, role

    _, csrf = app_harness.login("System Administrator")
    response = app_harness.client.post(
        "/api/v1/dataset-acquisition-plans",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json=_proposal(),
    )
    assert response.status_code == 201, response.text
    assert response.json()["state"] == "proposed"
    assert "manifest" not in response.json()

    async def verify(db):  # type: ignore[no-untyped-def]
        plan = await db.scalar(select(DatasetAcquisitionPlan))
        event = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "dataset.acquisition.proposal.create")
        )
        assert plan is not None and plan.state == "proposed"
        assert event is not None
        assert event.safe_metadata["raw_pcap_excluded"] is True
        assert "source_url" not in event.safe_metadata

    app_harness.run(verify)


def test_csrf_origin_duplicates_and_claimed_approval_fail_closed(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("System Administrator")
    endpoint = "/api/v1/dataset-acquisition-plans"
    assert app_harness.client.post(endpoint, json=_proposal()).status_code == 403
    assert (
        app_harness.client.post(
            endpoint,
            headers={"Origin": "https://evil.invalid", "X-CSRF-Token": csrf},
            json=_proposal(),
        ).status_code
        == 403
    )
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    first = app_harness.client.post(endpoint, headers=headers, json=_proposal())
    assert first.status_code == 201
    assert app_harness.client.post(endpoint, headers=headers, json=_proposal()).status_code == 409

    approved = _proposal()
    approved["state"] = "owner_approved"
    approved["owner_approval_reference"] = "OWNER-S5-DATASET-001"
    assert app_harness.client.post(endpoint, headers=headers, json=approved).status_code == 403


@pytest.mark.parametrize(
    "role", ["Senior Analyst", "Security Administrator", "System Administrator", "Auditor"]
)
def test_dataset_read_roles_can_list_safe_proposal_metadata(
    app_harness: AppHarness, role: str
) -> None:
    app_harness.login(role)
    response = app_harness.client.get("/api/v1/dataset-acquisition-plans")
    assert response.status_code == 200
