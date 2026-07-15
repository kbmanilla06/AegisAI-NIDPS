import pytest

from conftest import ORIGIN, PASSWORD, AppHarness

READ_MATRIX = {
    "Viewer": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 403,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
        "/api/v1/ingestion/jobs": 403,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 403,
        "/api/v1/detection/runs": 403,
        "/api/v1/feature-schemas": 403,
        "/api/v1/feature-jobs": 403,
        "/api/v1/datasets": 403,
        "/api/v1/dataset-acquisition-plans": 403,
        "/api/v1/synthetic/datasets": 403,
    },
    "SOC Analyst": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
        "/api/v1/ingestion/jobs": 200,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 200,
        "/api/v1/detection/runs": 200,
        "/api/v1/feature-schemas": 200,
        "/api/v1/feature-jobs": 200,
        "/api/v1/datasets": 403,
        "/api/v1/dataset-acquisition-plans": 403,
        "/api/v1/synthetic/datasets": 403,
    },
    "Senior Analyst": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 403,
        "/api/v1/audit/events": 403,
        "/api/v1/ingestion/jobs": 200,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 200,
        "/api/v1/detection/runs": 200,
        "/api/v1/feature-schemas": 200,
        "/api/v1/feature-jobs": 200,
        "/api/v1/datasets": 200,
        "/api/v1/dataset-acquisition-plans": 200,
        "/api/v1/synthetic/datasets": 200,
    },
    "Security Administrator": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
        "/api/v1/ingestion/jobs": 200,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 200,
        "/api/v1/detection/runs": 200,
        "/api/v1/feature-schemas": 200,
        "/api/v1/feature-jobs": 200,
        "/api/v1/datasets": 200,
        "/api/v1/dataset-acquisition-plans": 200,
        "/api/v1/synthetic/datasets": 200,
    },
    "System Administrator": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 200,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
        "/api/v1/ingestion/jobs": 200,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 200,
        "/api/v1/detection/runs": 200,
        "/api/v1/feature-schemas": 200,
        "/api/v1/feature-jobs": 200,
        "/api/v1/datasets": 200,
        "/api/v1/dataset-acquisition-plans": 200,
        "/api/v1/synthetic/datasets": 200,
    },
    "Auditor": {
        "/api/v1/assets": 200,
        "/api/v1/sensors": 200,
        "/api/v1/users": 403,
        "/api/v1/roles": 200,
        "/api/v1/audit/events": 200,
        "/api/v1/ingestion/jobs": 200,
        "/api/v1/rules": 200,
        "/api/v1/alerts": 200,
        "/api/v1/detection/metrics": 200,
        "/api/v1/detection/runs": 200,
        "/api/v1/feature-schemas": 200,
        "/api/v1/feature-jobs": 200,
        "/api/v1/datasets": 200,
        "/api/v1/dataset-acquisition-plans": 200,
        "/api/v1/synthetic/datasets": 200,
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
    ingestion = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=headers,
        data={"source_type": "normalized"},
        files={
            "file": (
                "flow.jsonl",
                b'{"schema_version":"1","event_time":"2026-07-14T00:00:00Z"}\n',
                "application/json",
            )
        },
    )
    rule = app_harness.client.post(
        "/api/v1/rules/behavior.rbac_test/versions",
        headers=headers,
        json={
            "name": "RBAC test rule",
            "description": "Synthetic rule used only to verify server-side authorization.",
            "category": "test",
            "evaluator_key": "port_scan_v1",
            "parameters": {"threshold": 30, "excluded_asset_ids": []},
            "window_seconds": 60,
            "severity": "low",
            "mitre_mappings": [],
            "false_positive_guidance": "Synthetic test only.",
            "investigation_guidance": "No investigation required.",
            "prevention_recommendation": "No action.",
            "change_rationale": "Verify the complete role denial matrix.",
        },
    )
    inventory_status = 201 if role in {"Security Administrator", "System Administrator"} else 403
    assert asset.status_code == inventory_status, (role, "assets")
    assert sensor.status_code == inventory_status, (role, "sensors")
    assert user.status_code == (201 if role == "System Administrator" else 403), (role, "users")
    ingestion_status = 202 if role in {"Security Administrator", "System Administrator"} else 403
    assert ingestion.status_code == ingestion_status, (role, "ingestion")
    assert rule.status_code == inventory_status, (role, "rule version")
