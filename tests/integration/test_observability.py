from uuid import UUID

from aegis_api.config import Settings
from aegis_api.observability_processor import process_report_job

ORIGIN = "http://localhost:5173"


def test_report_is_aggregate_only_idempotent_and_reviewer_separated(app_harness) -> None:  # type: ignore[no-untyped-def]
    requester, csrf = app_harness.login("SOC Analyst")
    response = app_harness.client.post(
        "/api/v1/observability/reports",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "p2-report-1"},
        json={
            "report_type": "synthetic_operations",
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-02T00:00:00Z",
        },
    )
    assert response.status_code == 202, response.text
    job_id = UUID(response.json()["id"])
    replay = app_harness.client.post(
        "/api/v1/observability/reports",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "p2-report-1"},
        json={
            "report_type": "synthetic_operations",
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-02T00:00:00Z",
        },
    )
    assert replay.status_code == 202
    assert replay.json()["id"] == str(job_id)
    app_harness.run(
        lambda _db: process_report_job(
            job_id,
            Settings(environment="test", artifact_root=app_harness.artifact_root),
            app_harness.session_factory,
        )
    )
    reports = app_harness.client.get("/api/v1/observability/reports")
    assert reports.status_code == 200, reports.text
    report = reports.json()[0]
    assert report["status"] == "complete"
    assert report["limitations"].startswith("SYNTHETIC DEMO ONLY")
    assert report["false_capability_flags"]["prevention_allowed"] is False
    assert "raw_endpoint" not in str(report)

    _, security_csrf = app_harness.login("Security Administrator")
    finalized = app_harness.client.post(
        f"/api/v1/observability/reports/{report['id']}/finalize",
        headers={"Origin": ORIGIN, "X-CSRF-Token": security_csrf},
        json={"reason": "Independent Security Administrator review"},
    )
    assert finalized.status_code == 200, finalized.text
    assert finalized.json()["finalized_by"] != requester["user"]["id"]


def test_report_request_rejects_bad_origin_and_unknown_type(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("SOC Analyst")
    bad_origin = app_harness.client.post(
        "/api/v1/observability/reports",
        headers={
            "Origin": "https://evil.invalid",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "p2-report-2",
        },
        json={
            "report_type": "synthetic_operations",
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-01T01:00:00Z",
        },
    )
    assert bad_origin.status_code == 403
    unknown = app_harness.client.post(
        "/api/v1/observability/reports",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "p2-report-3"},
        json={
            "report_type": "raw_packets",
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-01T01:00:00Z",
        },
    )
    assert unknown.status_code == 422
