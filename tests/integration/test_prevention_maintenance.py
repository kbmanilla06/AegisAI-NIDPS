from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from test_sprint9_api import (
    _create_request,
    _hdr,
    _seed_alert,
    _seed_policy,
)

from aegis_api.models import PreventionRequest
from aegis_api.prevention_maintenance import expire_due_simulations


def _simulate_one(app_harness, csrf) -> str:  # type: ignore[no-untyped-def]
    alert_id = _seed_alert(app_harness)
    request_id = _create_request(app_harness, csrf, alert_id).json()["id"]
    app_harness.client.post(f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf))
    app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/simulate", headers=_hdr(csrf, "sim")
    )
    return request_id


def test_expire_due_simulations_transitions_only_past_due(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    request_id = _simulate_one(app_harness, csrf)

    # Not yet due: maintenance is a no-op.
    def run_maintenance(db):  # type: ignore[no-untyped-def]
        return expire_due_simulations(db)

    assert app_harness.run(run_maintenance) == 0

    # Backdate the expiry, then a maintenance pass expires exactly this request.
    def backdate(db):  # type: ignore[no-untyped-def]
        async def _inner():  # type: ignore[no-untyped-def]
            row = await db.get(PreventionRequest, UUID(request_id))
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()

        return _inner()

    app_harness.run(backdate)

    assert app_harness.run(run_maintenance) == 1
    # Idempotent: a second pass finds nothing (already terminal).
    assert app_harness.run(run_maintenance) == 0

    detail = app_harness.client.get(
        f"/api/v1/prevention/requests/{request_id}", headers={"Origin": "http://localhost:5173"}
    )
    assert detail.json()["request"]["status"] == "expired"


def test_rollback_of_expired_request_is_clean_conflict(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    request_id = _simulate_one(app_harness, csrf)
    detail = app_harness.client.get(
        f"/api/v1/prevention/requests/{request_id}", headers={"Origin": "http://localhost:5173"}
    ).json()
    execution_id = detail["execution"]["id"]

    # Backdate + expire the simulated request.
    def backdate(db):  # type: ignore[no-untyped-def]
        async def _inner():  # type: ignore[no-untyped-def]
            row = await db.get(PreventionRequest, UUID(request_id))
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()

        return _inner()

    app_harness.run(backdate)
    assert app_harness.run(lambda db: expire_due_simulations(db)) == 1

    # Rolling back an expired request is a clean 409, never a 500.
    resp = app_harness.client.post(
        f"/api/v1/prevention/executions/{execution_id}/rollback",
        headers=_hdr(csrf),
    )
    assert resp.status_code == 409
    assert resp.json()["code"] == "prevention_not_simulated"
