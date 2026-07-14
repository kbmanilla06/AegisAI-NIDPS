from uuid import UUID

from sqlalchemy import select

from aegis_api.models import AuditEvent, Sensor
from aegis_api.security.tokens import hash_secret
from conftest import ORIGIN, AppHarness


def test_sensor_secret_is_shown_once_hashed_and_rotatable(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    created = app_harness.client.post(
        "/api/v1/sensors",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={"name": "sensor-one", "sensor_type": "flow"},
    )
    assert created.status_code == 201
    first_credential = created.json()["credential"]
    sensor_id = created.json()["sensor"]["id"]
    listed = app_harness.client.get("/api/v1/sensors")
    assert "credential" not in listed.json()[0]
    assert "credential_hash" not in listed.json()[0]

    async def stored_sensor(db):  # type: ignore[no-untyped-def]
        return (await db.execute(select(Sensor).where(Sensor.id == UUID(sensor_id)))).scalar_one()

    stored = app_harness.run(stored_sensor)
    assert stored.credential_hash == hash_secret(first_credential)
    assert first_credential not in stored.credential_hash

    rotated = app_harness.client.post(
        f"/api/v1/sensors/{sensor_id}/rotate",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert rotated.status_code == 200
    assert rotated.json()["credential"] != first_credential
    assert rotated.json()["sensor"]["credential_version"] == 2


def test_asset_and_sensor_changes_create_safe_audit_events(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/assets",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "name": "database",
            "network_zone": "data",
            "criticality": "high",
            "is_internal": True,
        },
    )
    assert response.status_code == 201

    async def events(db):  # type: ignore[no-untyped-def]
        return list(
            (
                await db.execute(select(AuditEvent).where(AuditEvent.action == "asset.create"))
            ).scalars()
        )

    audit_events = app_harness.run(events)
    assert len(audit_events) == 1
    serialized = str(audit_events[0].safe_metadata)
    assert "password" not in serialized.lower()
    assert "credential" not in serialized.lower()
