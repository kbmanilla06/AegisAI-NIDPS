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


# Sprint 9: prevention:read holders can view policies; others are denied.
_PREVENTION_READ_EXPECTED = {
    "Viewer": 403,
    "SOC Analyst": 403,
    "Senior Analyst": 200,
    "Security Administrator": 200,
    "System Administrator": 200,
    "Auditor": 200,
}


@pytest.mark.parametrize(("role", "expected"), _PREVENTION_READ_EXPECTED.items())
def test_prevention_policies_read_authorization(
    app_harness: AppHarness, role: str, expected: int
) -> None:
    app_harness.login(role)
    assert app_harness.client.get("/api/v1/prevention/policies").status_code == expected, (
        role,
        "prevention policies",
    )


# Only prevention:simulate holders may create a simulation request (no enforcement).
_PREVENTION_SIMULATE_EXPECTED = {
    "Viewer": 403,
    "SOC Analyst": 403,
    "Senior Analyst": 201,
    "Security Administrator": 201,
    "System Administrator": 201,
    "Auditor": 403,
}


@pytest.mark.parametrize(("role", "expected"), _PREVENTION_SIMULATE_EXPECTED.items())
def test_prevention_request_create_authorization(
    app_harness: AppHarness, role: str, expected: int
) -> None:
    from datetime import UTC, datetime

    from aegis_api.models import Alert, PreventionPolicyVersion
    from aegis_services.prevention import (
        DEFAULT_MAX_DURATION_SECONDS,
        DEFAULT_POLICY_NAME,
        DEFAULT_POLICY_VERSION,
        PREVENTION_LIMITATIONS,
        default_policy_definition,
        default_policy_hash,
    )

    async def seed(db):  # type: ignore[no-untyped-def]
        now = datetime.now(UTC)
        alert = Alert(
            fingerprint="f" * 64,
            source_type="behavioral_rule",
            category="port_scan",
            severity="medium",
            grouping={"series_key": "s"},
            first_seen=now,
            last_seen=now,
        )
        db.add(alert)
        db.add(
            PreventionPolicyVersion(
                name=DEFAULT_POLICY_NAME,
                version=DEFAULT_POLICY_VERSION,
                definition=default_policy_definition(),
                definition_hash=default_policy_hash(),
                max_duration_seconds=DEFAULT_MAX_DURATION_SECONDS,
                lifecycle="reviewed",
                limitations=PREVENTION_LIMITATIONS,
            )
        )
        await db.commit()
        await db.refresh(alert)
        return str(alert.id)

    alert_id = app_harness.run(seed)
    _, csrf = app_harness.login(role)
    resp = app_harness.client.post(
        "/api/v1/prevention/requests",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": f"rbac-{role}"},
        json={
            "alert_id": alert_id,
            "action_type": "temporary_block",
            "target_type": "external_ip",
            "target_value": "203.0.113.10",
            "reason": "RBAC synthetic proposal",
            "duration_seconds": 300,
            "rollback_plan": {"summary": "undo"},
        },
    )
    assert resp.status_code == expected, (role, resp.text)
