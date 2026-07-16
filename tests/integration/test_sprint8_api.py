from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from aegis_api.models import Alert, User

ORIGIN = "http://localhost:5173"


def _hdr(csrf: str) -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def _seed_alert(  # type: ignore[no-untyped-def]
    app_harness, fingerprint: str = "a" * 64, category: str = "port_scan"
) -> str:
    async def op(db):  # type: ignore[no-untyped-def]
        now = datetime.now(UTC)
        alert = Alert(
            fingerprint=fingerprint,
            source_type="behavioral_rule",
            category=category,
            severity="medium",
            grouping={"series_key": "series-1"},
            first_seen=now,
            last_seen=now,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        return str(alert.id)

    return app_harness.run(op)


def _user_id(app_harness, email: str) -> str:  # type: ignore[no-untyped-def]
    async def op(db):  # type: ignore[no-untyped-def]
        user = await db.scalar(select(User).where(User.email == email))
        assert user is not None
        return str(user.id)

    return app_harness.run(op)


def test_alert_workflow_lifecycle_and_disposition(app_harness) -> None:  # type: ignore[no-untyped-def]
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("SOC Analyst")

    listed = app_harness.client.get("/api/v1/alerts", headers={"Origin": ORIGIN})
    assert listed.status_code == 200
    assert any(item["id"] == alert_id for item in listed.json())
    assert listed.json()[0]["limitations"]
    assert listed.json()[0]["prevention_allowed"] is False

    # new -> acknowledged
    ack = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers=_hdr(csrf),
        json={"expected_status": "new", "status": "acknowledged"},
    )
    assert ack.status_code == 200, ack.text
    assert ack.json()["status"] == "acknowledged"

    # acknowledged -> closed requires a disposition
    closed = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers=_hdr(csrf),
        json={
            "expected_status": "acknowledged",
            "status": "closed",
            "disposition": "false_positive",
        },
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    assert closed.json()["disposition"] == "false_positive"


def test_alert_status_requires_csrf_and_rejects_bad_transitions(app_harness) -> None:  # type: ignore[no-untyped-def]
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("SOC Analyst")

    # CSRF mandatory
    missing = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers={"Origin": ORIGIN},
        json={"expected_status": "new", "status": "acknowledged"},
    )
    assert missing.status_code == 403

    # Invalid transition new -> closed
    bad = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers=_hdr(csrf),
        json={"expected_status": "new", "status": "closed", "disposition": "benign"},
    )
    assert bad.status_code == 422
    assert bad.json()["code"] == "alert_invalid_transition"

    # Optimistic conflict: wrong expected_status
    conflict = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers=_hdr(csrf),
        json={"expected_status": "investigating", "status": "closed", "disposition": "benign"},
    )
    assert conflict.status_code == 409


def test_alert_notes_are_sanitized_and_assignment_validates(app_harness) -> None:  # type: ignore[no-untyped-def]
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("SOC Analyst")

    note = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        headers=_hdr(csrf),
        json={"body": "Investigated beacon from 192.0.2.10 in synthetic scenario"},
    )
    assert note.status_code == 201, note.text
    assert "192.0.2.10" not in note.json()["body"]
    assert "[redacted-endpoint]" in note.json()["body"]

    assignee = _user_id(app_harness, "senior.analyst@example.com")
    assigned = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/assign",
        headers=_hdr(csrf),
        json={"assignee_id": assignee},
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["assignee_id"] == assignee

    invalid = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/assign",
        headers=_hdr(csrf),
        json={"assignee_id": str(UUID(int=0))},
    )
    assert invalid.status_code == 409


def test_alert_triage_denied_without_permission(app_harness) -> None:  # type: ignore[no-untyped-def]
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Viewer")
    denied = app_harness.client.post(
        f"/api/v1/alerts/{alert_id}/status",
        headers=_hdr(csrf),
        json={"expected_status": "new", "status": "acknowledged"},
    )
    assert denied.status_code == 403


def test_incident_correlation_and_workflow(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_alert(app_harness, fingerprint="b" * 64, category="port_scan")
    _seed_alert(app_harness, fingerprint="c" * 64, category="port_scan")
    _seed_alert(app_harness, fingerprint="d" * 64, category="brute_force")
    _, csrf = app_harness.login("Security Administrator")

    result = app_harness.client.post("/api/v1/incidents/correlate", headers=_hdr(csrf))
    assert result.status_code == 200, result.text
    assert result.json()["created"] == 2  # two categories -> two incidents
    assert result.json()["prevention_allowed"] is False

    # Re-running is idempotent: no new incidents.
    again = app_harness.client.post("/api/v1/incidents/correlate", headers=_hdr(csrf))
    assert again.json()["created"] == 0

    listed = app_harness.client.get("/api/v1/incidents", headers={"Origin": ORIGIN})
    assert listed.status_code == 200
    assert len(listed.json()) == 2
    incident = next(item for item in listed.json() if item["category"] == "port_scan")
    assert incident["alert_count"] == 2
    assert incident["limitations"]

    detail = app_harness.client.get(
        f"/api/v1/incidents/{incident['id']}", headers={"Origin": ORIGIN}
    )
    assert detail.status_code == 200
    assert len(detail.json()["member_alert_ids"]) == 2
    assert any(item["event_type"] == "created" for item in detail.json()["timeline"])

    # open -> investigating
    moved = app_harness.client.post(
        f"/api/v1/incidents/{incident['id']}/status",
        headers=_hdr(csrf),
        json={"expected_status": "open", "status": "investigating"},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["status"] == "investigating"

    # invalid: open -> closed rejected (already investigating now anyway)
    bad = app_harness.client.post(
        f"/api/v1/incidents/{incident['id']}/status",
        headers=_hdr(csrf),
        json={"expected_status": "investigating", "status": "closed", "disposition": "benign"},
    )
    assert bad.status_code == 422


def test_incident_correlate_denied_without_permission(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_alert(app_harness, fingerprint="e" * 64)
    _, csrf = app_harness.login("SOC Analyst")  # has incidents:read but not correlate
    denied = app_harness.client.post("/api/v1/incidents/correlate", headers=_hdr(csrf))
    assert denied.status_code == 403
