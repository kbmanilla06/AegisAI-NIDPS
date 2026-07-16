from __future__ import annotations

from uuid import UUID

ORIGIN = "http://localhost:5173"
TARGET_MODEL_HASH = "a" * 64


def _hdr(csrf: str, idem: str | None = None) -> dict[str, str]:
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    if idem is not None:
        headers["Idempotency-Key"] = idem
    return headers


def test_explanation_method_requires_csrf_and_rbac(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, csrf = app_harness.login("System Administrator")
    # CSRF is mandatory for the unsafe method-create route.
    missing = app_harness.client.post(
        "/api/v1/explainability/methods", headers={"Origin": ORIGIN}, json={"top_k": 10}
    )
    assert missing.status_code == 403
    created = app_harness.client.post(
        "/api/v1/explainability/methods", headers=_hdr(csrf), json={"top_k": 10}
    )
    assert created.status_code == 201, created.text
    assert created.json()["lifecycle_state"] == "draft"
    assert created.json()["limitations"]

    # A SOC Analyst lacks explanations:generate.
    _, soc_csrf = app_harness.login("SOC Analyst")
    denied = app_harness.client.post(
        "/api/v1/explainability/methods", headers=_hdr(soc_csrf), json={"top_k": 10}
    )
    assert denied.status_code == 403


def test_explanation_review_separation_and_batch_flow(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, admin_csrf = app_harness.login("System Administrator")
    method = app_harness.client.post(
        "/api/v1/explainability/methods", headers=_hdr(admin_csrf), json={"top_k": 10}
    )
    method_id = method.json()["id"]
    method_hash = method.json()["method_hash"]

    # A distinct Security Administrator reviews (creator separation enforced).
    _, sec_csrf = app_harness.login("Security Administrator")
    reviewed = app_harness.client.post(
        f"/api/v1/explainability/methods/{method_id}/review",
        headers=_hdr(sec_csrf),
        json={"approved": True, "reason": "synthetic review ok"},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["lifecycle_state"] == "reviewed"

    # Re-login restores the System Administrator session (login rotates the cookie).
    _, admin_csrf = app_harness.login("System Administrator")
    # Batch requires the reviewed method; dispatch is JSON-UUID only and idempotent.
    first = app_harness.client.post(
        "/api/v1/explainability/batches",
        headers=_hdr(admin_csrf, "explain-batch-1"),
        json={"method_hash": method_hash, "target_model_hash": TARGET_MODEL_HASH},
    )
    assert first.status_code == 202, first.text
    assert UUID(first.json()["id"])
    assert first.json()["limitations"]
    assert app_harness.dispatched_explanation_batches == [first.json()["id"]]
    # Replayed idempotency key returns the same batch, no duplicate dispatch.
    repeat = app_harness.client.post(
        "/api/v1/explainability/batches",
        headers=_hdr(admin_csrf, "explain-batch-1"),
        json={"method_hash": method_hash, "target_model_hash": TARGET_MODEL_HASH},
    )
    assert repeat.json()["id"] == first.json()["id"]
    assert app_harness.dispatched_explanation_batches == [first.json()["id"]]


def test_explanation_batch_requires_reviewed_method(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, admin_csrf = app_harness.login("System Administrator")
    # An unreviewed (never-created) method hash is rejected.
    response = app_harness.client.post(
        "/api/v1/explainability/batches",
        headers=_hdr(admin_csrf, "explain-batch-2"),
        json={"method_hash": "f" * 64, "target_model_hash": TARGET_MODEL_HASH},
    )
    assert response.status_code == 409


def test_intelligence_import_match_and_mitre_are_offline(app_harness) -> None:  # type: ignore[no-untyped-def]
    _, sec_csrf = app_harness.login("Security Administrator")
    imported = app_harness.client.post("/api/v1/intelligence/imports", headers=_hdr(sec_csrf))
    assert imported.status_code == 201, imported.text
    source_hash = imported.json()["source_hash"]
    assert imported.json()["limitations"]

    indicators = app_harness.client.get(
        "/api/v1/intelligence/indicators", headers={"Origin": ORIGIN}
    )
    assert indicators.status_code == 200
    assert indicators.json(), "bundled indicators should be present"
    for item in indicators.json():
        # Only a normalized hash is ever exposed, never a raw value.
        assert len(item["value_hash"]) == 64
        assert "value" not in item

    match = app_harness.client.post(
        "/api/v1/intelligence/match-batches",
        headers=_hdr(sec_csrf, "match-batch-1"),
        json={"source_hash": source_hash},
    )
    assert match.status_code == 202, match.text
    assert app_harness.dispatched_match_batches == [match.json()["id"]]

    techniques = app_harness.client.get(
        "/api/v1/intelligence/mitre/techniques", headers={"Origin": ORIGIN}
    )
    assert techniques.status_code == 200
    assert techniques.json()[0]["catalog_hash"]


def test_intelligence_read_denied_for_viewer(app_harness) -> None:  # type: ignore[no-untyped-def]
    app_harness.login("Viewer")
    response = app_harness.client.get("/api/v1/intelligence/sources", headers={"Origin": ORIGIN})
    assert response.status_code == 403
