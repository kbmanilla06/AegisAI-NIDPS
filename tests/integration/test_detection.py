from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from aegis_api.config import Settings
from aegis_api.detection_processor import cleanup_detection_data, process_detection_run
from aegis_api.ingestion_processor import cleanup_expired_flows, process_ingestion_job
from aegis_api.models import (
    Alert,
    AlertEvidence,
    AuditEvent,
    DetectionRun,
    DetectionSignal,
    Flow,
    Session,
    SignatureEvent,
)
from conftest import ORIGIN, AppHarness

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"


def _headers(csrf: str) -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def _settings(harness: AppHarness) -> Settings:
    return Settings(
        environment="test",
        artifact_root=harness.artifact_root,
        ingestion_max_records=100,
        ingestion_max_unique_flows=50,
        ingestion_max_processing_seconds=10,
        detection_max_groups=100,
        detection_max_alerts=100,
        detection_max_signals=100,
    )


def test_suricata_signature_ingestion_creates_one_idempotent_evidence_alert(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "suricata"},
        files={
            "file": (
                "hostile-name.json",
                (FIXTURES / "suricata_alert_valid.jsonl").read_bytes(),
                "text/plain",
            )
        },
    )
    assert response.status_code == 202, response.text
    run_id = app_harness.run(
        lambda _db: process_ingestion_job(
            UUID(response.json()["id"]), _settings(app_harness), app_harness.session_factory
        )
    )
    assert run_id is not None
    changed = app_harness.run(
        lambda _db: process_detection_run(
            run_id, _settings(app_harness), app_harness.session_factory
        )
    )
    assert len(changed) == 1
    runs = app_harness.client.get(f"/api/v1/detection/runs?source_job_id={response.json()['id']}")
    assert runs.status_code == 200
    assert [item["id"] for item in runs.json()] == [str(run_id)]
    assert (
        app_harness.run(
            lambda _db: process_detection_run(
                run_id, _settings(app_harness), app_harness.session_factory
            )
        )
        == []
    )

    admin_view = app_harness.client.get(f"/api/v1/alerts/{changed[0]}")
    assert admin_view.status_code == 200
    assert admin_view.json()["grouping"]["src_address"] == "192.0.2.41"
    assert admin_view.json()["occurrence_count"] == 1
    assert "risk_score" not in admin_view.json()

    app_harness.login("Viewer")
    viewer_view = app_harness.client.get(f"/api/v1/alerts/{changed[0]}")
    assert viewer_view.status_code == 200
    assert "src_address" not in viewer_view.json()["grouping"]
    assert "src_address" not in viewer_view.json()["evidence"][0]["evidence_snapshot"]["group"]


def test_rule_version_review_activation_and_rollback_are_authorized_and_audited(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    active = app_harness.client.get("/api/v1/rules?active_only=true").json()
    current = next(item for item in active if item["rule_key"] == "behavior.port_scan")
    created = app_harness.client.post(
        "/api/v1/rules/behavior.port_scan/versions",
        headers=_headers(csrf),
        json={
            "name": "Port scan indicator",
            "description": "Reviewed threshold variation for the deterministic port scan rule.",
            "category": "reconnaissance",
            "evaluator_key": "port_scan_v1",
            "parameters": {"threshold": 25, "excluded_asset_ids": []},
            "window_seconds": 60,
            "severity": "medium",
            "mitre_mappings": [],
            "false_positive_guidance": "Authorized scanners and administration.",
            "investigation_guidance": "Confirm activity was authorized.",
            "prevention_recommendation": "Review only; no automatic action.",
            "change_rationale": "Increase the development threshold for regression verification.",
        },
    )
    assert created.status_code == 201, created.text
    version_id = created.json()["id"]
    reviewed = app_harness.client.post(
        f"/api/v1/rule-versions/{version_id}/review",
        headers=_headers(csrf),
        json={
            "approved": True,
            "reason": "Synthetic positive and negative regression cases passed.",
            "regression_evidence": "pytest:test_detection_rules",
        },
    )
    assert reviewed.status_code == 200
    activated = app_harness.client.post(
        f"/api/v1/rule-versions/{version_id}/activate",
        headers=_headers(csrf),
        json={
            "reason": "Activate the reviewed threshold version.",
            "regression_evidence": "pytest:test_detection_rules",
            "expected_active_version_id": current["id"],
        },
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["is_active"] is True

    app_harness.login("SOC Analyst")
    denied = app_harness.client.post(
        f"/api/v1/rule-versions/{current['id']}/activate",
        headers={"Origin": ORIGIN, "X-CSRF-Token": "invalid"},
        json={
            "reason": "Unauthorized activation must not work.",
            "regression_evidence": "none",
            "expected_active_version_id": version_id,
        },
    )
    assert denied.status_code == 403

    async def audit_evidence(db):  # type: ignore[no-untyped-def]
        return list(
            (
                await db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.action.in_(
                            ["rule.version.create", "rule.version.review", "rule.activate"]
                        )
                    )
                )
            ).all()
        )

    assert len(app_harness.run(audit_evidence)) == 3


def test_live_alert_channel_requires_origin_session_and_alert_permission(
    app_harness: AppHarness,
) -> None:
    with pytest.raises(WebSocketDisconnect):
        with app_harness.client.websocket_connect("/ws/v1/alerts", headers={"Origin": ORIGIN}):
            pass

    app_harness.login("Viewer")
    session_cookie = app_harness.client.cookies.get("__Host-aegis_session")
    assert session_cookie is not None
    with app_harness.client.websocket_connect(
        "/ws/v1/alerts",
        headers={"Origin": ORIGIN, "Cookie": f"__Host-aegis_session={session_cookie}"},
    ) as websocket:
        assert websocket.receive_json() == {"event": "connected"}

    with pytest.raises(WebSocketDisconnect):
        with app_harness.client.websocket_connect(
            "/ws/v1/alerts", headers={"Origin": "https://evil.example"}
        ):
            pass


def test_live_alert_channel_rechecks_revoked_session(
    app_harness: AppHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aegis_api.routers.detection as detection_router

    class QuietPubSub:
        async def subscribe(self, _channel: str) -> None:
            return None

        async def get_message(self, **_kwargs):  # type: ignore[no-untyped-def]
            await detection_router.asyncio.sleep(0.01)
            return None

        async def aclose(self) -> None:
            return None

    class QuietRedis:
        def __init__(self) -> None:
            self._pubsub = QuietPubSub()

        def pubsub(self) -> QuietPubSub:
            return self._pubsub

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(detection_router, "WEBSOCKET_AUTH_RECHECK_SECONDS", 0.01)
    monkeypatch.setattr(detection_router.Redis, "from_url", lambda *_args, **_kwargs: QuietRedis())

    app_harness.login("Viewer")
    session_cookie = app_harness.client.cookies.get("__Host-aegis_session")
    assert session_cookie is not None

    async def revoke(db):  # type: ignore[no-untyped-def]
        session = await db.scalar(select(Session))
        assert session is not None
        session.revoked_at = datetime.now(UTC)
        await db.commit()

    with pytest.raises(WebSocketDisconnect) as disconnected:
        with app_harness.client.websocket_connect(
            "/ws/v1/alerts",
            headers={"Origin": ORIGIN, "Cookie": f"__Host-aegis_session={session_cookie}"},
        ) as websocket:
            assert websocket.receive_json() == {"event": "connected"}
            app_harness.run(revoke)
            websocket.receive_json()
    assert disconnected.value.code == 4403


def test_alert_evidence_survives_flow_retention(app_harness: AppHarness) -> None:
    async def prepare(db):  # type: ignore[no-untyped-def]
        expired = datetime.now(UTC) - timedelta(days=31)
        flow = Flow(
            event_key="f" * 64,
            schema_version="1",
            source_type="normalized",
            job_id=(await db.scalar(select(DetectionRun.source_job_id).limit(1))),
            event_time=datetime.now(UTC),
            src_address="192.0.2.50",
            dst_address="198.51.100.50",
            src_port=50000,
            dst_port=443,
            protocol="tcp",
            duration_ms=10,
            packet_count=1,
            byte_count=1,
            flow_metadata={},
            created_at=expired,
        )
        db.add(flow)
        for model in (SignatureEvent, DetectionSignal, DetectionRun):
            rows = list((await db.scalars(select(model))).all())
            for row in rows:
                row.created_at = expired
        await db.commit()

    # Create an alert/evidence first so this test verifies different retention clocks.
    test_suricata_signature_ingestion_creates_one_idempotent_evidence_alert(app_harness)
    app_harness.run(prepare)
    removed = app_harness.run(
        lambda _db: cleanup_expired_flows(_settings(app_harness), app_harness.session_factory)
    )
    assert removed == 1
    detection_removed = app_harness.run(
        lambda _db: cleanup_detection_data(_settings(app_harness), app_harness.session_factory)
    )
    assert detection_removed == {
        "alerts": 0,
        "evidence": 0,
        "signals": 1,
        "signature_events": 1,
        "runs": 1,
    }

    async def remaining(db):  # type: ignore[no-untyped-def]
        return (
            int(
                await db.scalar(select(__import__("sqlalchemy").func.count()).select_from(Alert))
                or 0
            ),
            int(
                await db.scalar(
                    select(__import__("sqlalchemy").func.count()).select_from(AlertEvidence)
                )
                or 0
            ),
            int(
                await db.scalar(
                    select(__import__("sqlalchemy").func.count()).select_from(DetectionSignal)
                )
                or 0
            ),
            int(
                await db.scalar(
                    select(__import__("sqlalchemy").func.count()).select_from(SignatureEvent)
                )
                or 0
            ),
            int(
                await db.scalar(
                    select(__import__("sqlalchemy").func.count()).select_from(DetectionRun)
                )
                or 0
            ),
            await db.scalar(select(AlertEvidence.signal_id)),
        )

    assert app_harness.run(remaining) == (1, 1, 0, 0, 0, None)
