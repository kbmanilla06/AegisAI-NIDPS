from uuid import UUID

from sqlalchemy import select

from aegis_api.config import Settings
from aegis_api.models import AuditEvent, SyntheticMonitoringRun
from aegis_api.monitoring_processor import process_monitoring_run

ORIGIN = "http://localhost:5173"


def _snapshot(artifact_hash: str, value: float) -> dict[str, object]:
    return {
        "source_kind": "synthetic_feature",
        "artifact_hash": artifact_hash,
        "schema_hash": "17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114",
        "sample_count": 50,
        "group_count": 10,
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:05:00Z",
        "metrics": {"missing_rate": {"value": value, "sample_count": 50}},
    }


def test_monitoring_run_feedback_review_is_separated(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("System Administrator")
    created = app_harness.client.post(
        "/api/v1/monitoring/runs",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "monitoring-run-1"},
        json={
            "source_kind": "synthetic_feature",
            "baseline": _snapshot(
                "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9", 0.10
            ),
            "current": _snapshot(
                "b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a", 0.35
            ),
        },
    )
    assert created.status_code == 202, created.text
    run_id = created.json()["id"]
    app_harness.run(
        lambda _db: process_monitoring_run(
            UUID(run_id),
            Settings(environment="test", artifact_root=app_harness.artifact_root),
            app_harness.session_factory,
        )
    )
    runs = app_harness.client.get("/api/v1/monitoring/runs")
    assert runs.status_code == 200
    run = runs.json()[0]
    assert run["status"] == "succeeded"
    assert run["warning_count"] == 1
    _, analyst_csrf = app_harness.login("SOC Analyst")
    feedback = app_harness.client.post(
        "/api/v1/monitoring/feedback",
        headers={"Origin": ORIGIN, "X-CSRF-Token": analyst_csrf},
        json={
            "monitoring_run_id": run_id,
            "evidence_hash": run["current_snapshot_hash"],
            "disposition": "false_positive_demo",
            "reason_code": "synthetic_threshold_review",
            "note": "Synthetic-only warning requires analyst review.",
        },
    )
    assert feedback.status_code == 201, feedback.text
    feedback_id = feedback.json()["id"]
    own_review = app_harness.client.post(
        f"/api/v1/monitoring/feedback/{feedback_id}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": analyst_csrf},
        json={"accepted": True, "reason": "Independent evidence review complete."},
    )
    assert own_review.status_code == 403
    _, security_csrf = app_harness.login("Security Administrator")
    reviewed = app_harness.client.post(
        f"/api/v1/monitoring/feedback/{feedback_id}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": security_csrf},
        json={"accepted": True, "reason": "Independent evidence review complete."},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["status"] == "reviewed"

    async def evidence(db):  # type: ignore[no-untyped-def]
        row = await db.get(SyntheticMonitoringRun, UUID(run_id))
        audits = list((await db.scalars(select(AuditEvent))).all())
        return row, audits

    row, audits = app_harness.run(evidence)
    assert row is not None
    assert row.result["false_capability_flags"]["prevention_allowed"] is False
    assert any(item.action == "synthetic.feedback.review" for item in audits)


def test_monitoring_rejects_unknown_artifact_and_origin(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("System Administrator")
    response = app_harness.client.post(
        "/api/v1/monitoring/runs",
        headers={
            "Origin": "https://evil.invalid",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "monitoring-run-2",
        },
        json={
            "source_kind": "synthetic_feature",
            "baseline": _snapshot("f" * 64, 0.10),
            "current": _snapshot(
                "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9", 0.20
            ),
        },
    )
    assert response.status_code == 403
