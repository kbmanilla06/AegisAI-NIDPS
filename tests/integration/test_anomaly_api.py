from __future__ import annotations

from uuid import UUID

ORIGIN = "http://localhost:5173"


def test_anomaly_fit_requires_csrf_and_is_json_uuid_only(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("System Administrator")
    payload = {"preprocessor_hash": "0" * 64}
    missing = app_harness.client.post(
        "/api/v1/anomaly/detectors/fit",
        headers={"Origin": ORIGIN, "Idempotency-Key": "anomaly-fit-1"},
        json=payload,
    )
    assert missing.status_code == 403
    response = app_harness.client.post(
        "/api/v1/anomaly/detectors/fit",
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "anomaly-fit-1",
        },
        json=payload,
    )
    assert response.status_code == 202, response.text
    assert UUID(response.json()["id"])
    assert app_harness.dispatched_anomaly_fits == [response.json()["id"]]
    assert response.json()["safe_metadata"]["synthetic_demo_only"] is True


def test_fusion_policy_is_review_separated_and_assessment_is_metadata_only(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/anomaly/policies",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    assert response.json()["lifecycle_state"] == "draft"
    assert response.json()["limitations"]
    policy_hash = response.json()["policy_hash"]
    assessment = app_harness.client.post(
        "/api/v1/anomaly/assessments",
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "assessment-1",
        },
        json={
            "feature_artifact_hash": (
                "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9"
            ),
            "anomaly_detector_hash": "a" * 64,
            "threshold_hash": "b" * 64,
            "policy_hash": policy_hash,
        },
    )
    assert assessment.status_code == 202, assessment.text
    assert app_harness.dispatched_assessments == [assessment.json()["id"]]
    assert assessment.json()["limitations"]
