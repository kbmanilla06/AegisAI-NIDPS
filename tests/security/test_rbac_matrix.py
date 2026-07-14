import pytest

from conftest import ORIGIN, PASSWORD, AppHarness

READ_MATRIX = {
    "Viewer": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 403,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
    },
    "SOC Analyst": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
    },
    "Senior Analyst": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
    },
    "Security Administrator": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
    },
    "System Administrator": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 200,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
    },
    "Auditor": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
    },
}


@pytest.mark.parametrize(("role", "expectations"), READ_MATRIX.items())
def test_every_role_against_every_protected_read_route(
    app_harness: AppHarness, role: str, expectations: dict[str, int]
) -> None:
    app_harness.login(role)
    for path, expected_status in expectations.items():
        assert app_harness.client.get(path).status_code == expected_status, (role, path)


@pytest.mark.parametrize("role", READ_MATRIX)
def test_every_role_against_protected_create_routes(app_harness: AppHarness, role: str) -> None:
    _, csrf = app_harness.login(role)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    slug = role.lower().replace(" ", "-")
    asset = app_harness.client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": f"{slug}-asset",
            "network_zone": "test",
            "criticality": "low",
            "is_internal": True,
        },
    )
    sensor = app_harness.client.post(
        "/api/v1/sensors",
        headers=headers,
        json={"name": f"{slug}-sensor", "sensor_type": "flow"},
    )
    user = app_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": f"created-by-{slug}@example.com",
            "password": PASSWORD,
            "roles": ["Viewer"],
        },
    )
    inventory_status = 201 if role in {"Security Administrator", "System Administrator"} else 403
    assert asset.status_code == inventory_status, (role, "assets")
    assert sensor.status_code == inventory_status, (role, "sensors")
    assert user.status_code == (201 if role == "System Administrator" else 403), (role, "users")
