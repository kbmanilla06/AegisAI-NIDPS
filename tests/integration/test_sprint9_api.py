from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegis_api.models import (
    Alert,
    AllowlistEntry,
    Asset,
    Indicator,
    IntelligenceSource,
    PreventionPolicyVersion,
)
from aegis_services.prevention import (
    DEFAULT_MAX_DURATION_SECONDS,
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_VERSION,
    PREVENTION_LIMITATIONS,
    default_policy_definition,
    default_policy_hash,
)

ORIGIN = "http://localhost:5173"


def _hdr(csrf: str, idem: str | None = None) -> dict[str, str]:
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    if idem is not None:
        headers["Idempotency-Key"] = idem
    return headers


def _seed_policy(app_harness) -> None:  # type: ignore[no-untyped-def]
    async def op(db):  # type: ignore[no-untyped-def]
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

    app_harness.run(op)


def _seed_alert(  # type: ignore[no-untyped-def]
    app_harness, fingerprint: str = "a" * 64, source_type: str = "behavioral_rule"
) -> str:
    async def op(db):  # type: ignore[no-untyped-def]
        now = datetime.now(UTC)
        alert = Alert(
            fingerprint=fingerprint,
            source_type=source_type,
            category="port_scan",
            severity="medium",
            grouping={"series_key": "s1"},
            first_seen=now,
            last_seen=now,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        return str(alert.id)

    return app_harness.run(op)


def _seed_allowlist(app_harness, target_value: str) -> None:  # type: ignore[no-untyped-def]
    async def op(db):  # type: ignore[no-untyped-def]
        db.add(
            AllowlistEntry(
                target_type="external_ip",
                target_value=target_value,
                scope="global",
                reason="protected synthetic target",
            )
        )
        await db.commit()

    app_harness.run(op)


def _seed_critical_asset(app_harness, address: str) -> None:  # type: ignore[no-untyped-def]
    async def op(db):  # type: ignore[no-untyped-def]
        from sqlalchemy import select

        from aegis_api.models import User

        admin = await db.scalar(select(User).where(User.email.like("system%")))
        db.add(
            Asset(
                name=f"crit-{address}",
                address=address,
                network_zone="dmz",
                criticality="critical",
                is_internal=False,
                created_by=admin.id,
            )
        )
        await db.commit()

    app_harness.run(op)


def _seed_indicator(app_harness, *, fresh: bool) -> str:  # type: ignore[no-untyped-def]
    async def op(db):  # type: ignore[no-untyped-def]
        from sqlalchemy import select

        from aegis_api.models import User

        admin = await db.scalar(select(User).where(User.email.like("system%")))
        now = datetime.now(UTC)
        source = IntelligenceSource(
            name="synthetic-feed",
            trust_level="community",
            terms_reference_hash="t" * 64,
            source_hash="s" * 64,
            created_by=admin.id,
            limitations="synthetic",
        )
        db.add(source)
        await db.flush()
        indicator = Indicator(
            source_id=source.id,
            indicator_type="ipv4",
            value_hash="v" * 64,
            indicator_hash="i" * 64,
            confidence=0.9,
            first_seen=now - timedelta(days=10),
            last_seen=now - timedelta(days=1),
            expires_at=now + timedelta(days=5) if fresh else now - timedelta(days=1),
            created_by=admin.id,
            limitations="synthetic",
        )
        db.add(indicator)
        await db.commit()
        await db.refresh(indicator)
        return str(indicator.id)

    return app_harness.run(op)


def _create_request(  # type: ignore[no-untyped-def]
    app_harness,
    csrf,
    alert_id,
    target="203.0.113.10",
    idem="idem-1",
    duration=300,
    indicator_id=None,
):
    body = {
        "alert_id": alert_id,
        "action_type": "temporary_block",
        "target_type": "external_ip",
        "target_value": target,
        "reason": "Synthetic scenario proposal",
        "duration_seconds": duration,
        "rollback_plan": {"summary": "Remove the simulated temporary rule"},
    }
    if indicator_id is not None:
        body["indicator_id"] = indicator_id
    return app_harness.client.post(
        "/api/v1/prevention/requests", headers=_hdr(csrf, idem), json=body
    )


def test_full_simulation_lifecycle(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")

    # Policies are visible and carry the mandatory limitation + false flags.
    policies = app_harness.client.get("/api/v1/prevention/policies", headers={"Origin": ORIGIN})
    assert policies.status_code == 200, policies.text
    assert policies.json()[0]["limitations"] == PREVENTION_LIMITATIONS
    assert policies.json()[0]["false_capability_flags"]["real_prevention"] is False

    created = _create_request(app_harness, csrf, alert_id)
    assert created.status_code == 201, created.text
    body = created.json()
    request_id = body["id"]
    assert body["status"] == "draft"
    assert body["mode"] == "simulation"
    assert body["prevention_allowed"] is False
    assert body["enforcement_authority"] is False

    preview = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    )
    assert preview.status_code == 200, preview.text
    detail = preview.json()
    assert detail["request"]["status"] == "previewed"
    assert all(g["passed"] for g in detail["gate_results"])
    assert len(detail["gate_results"]) == 13
    representation = detail["preview"]["representation"]
    assert detail["preview"]["adapter"] == "simulation"
    # The representation is data, never an executable command.
    assert representation["executable_command"] is None
    assert representation["network_call"] is None

    simulate = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/simulate", headers=_hdr(csrf, "sim-1")
    )
    assert simulate.status_code == 200, simulate.text
    sim = simulate.json()
    assert sim["request"]["status"] == "simulated"
    assert sim["execution"]["mode"] == "simulation"
    assert sim["execution"]["result"] == "simulated"
    # The execution proves no real side effect path was invoked (PREV-008).
    assert sim["execution"]["verify"]["real_side_effect_invoked"] is False
    assert sim["execution"]["verify"]["firewall_state_changed"] is False
    execution_id = sim["execution"]["id"]

    rollback = app_harness.client.post(
        f"/api/v1/prevention/executions/{execution_id}/rollback", headers=_hdr(csrf)
    )
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["request"]["status"] == "rolled_back"
    assert rollback.json()["rollback"]["result"] == "rolled_back"


def test_idempotent_request_and_execution(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")

    first = _create_request(app_harness, csrf, alert_id, idem="dup")
    second = _create_request(app_harness, csrf, alert_id, idem="dup")
    assert first.json()["id"] == second.json()["id"]  # no second request (PREV-005)

    request_id = first.json()["id"]
    app_harness.client.post(f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf))
    sim1 = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/simulate", headers=_hdr(csrf, "s")
    )
    sim2 = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/simulate", headers=_hdr(csrf, "s")
    )
    assert sim1.json()["execution"]["id"] == sim2.json()["execution"]["id"]


def test_allowlisted_target_is_rejected(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _seed_allowlist(app_harness, "203.0.113.10")
    _, csrf = app_harness.login("Senior Analyst")

    request_id = _create_request(app_harness, csrf, alert_id).json()["id"]
    preview = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    )
    detail = preview.json()
    assert detail["request"]["status"] == "rejected"
    allowlist_gate = next(g for g in detail["gate_results"] if g["gate_key"] == "allowlist")
    assert allowlist_gate["passed"] is False
    assert allowlist_gate["reason_code"] == "target_allowlisted"
    # A rejected request cannot be simulated.
    blocked = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/simulate", headers=_hdr(csrf, "x")
    )
    assert blocked.status_code == 409


def test_model_only_evidence_is_ineligible(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    # An alert from a non-deterministic source models model/anomaly-only evidence.
    alert_id = _seed_alert(app_harness, fingerprint="b" * 64, source_type="anomaly_model")
    _, csrf = app_harness.login("Senior Analyst")

    request_id = _create_request(app_harness, csrf, alert_id).json()["id"]
    detail = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    ).json()
    assert detail["request"]["status"] == "rejected"
    gate = next(g for g in detail["gate_results"] if g["gate_key"] == "model_anomaly_only")
    assert gate["passed"] is False


def test_internal_target_is_rejected(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")

    resp = app_harness.client.post(
        "/api/v1/prevention/requests",
        headers=_hdr(csrf, "internal"),
        json={
            "alert_id": alert_id,
            "action_type": "temporary_block",
            "target_type": "internal_ip",
            "target_value": "10.0.0.5",
            "reason": "Synthetic internal proposal",
            "duration_seconds": 300,
            "rollback_plan": {"summary": "undo"},
        },
    )
    request_id = resp.json()["id"]
    detail = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    ).json()
    assert detail["request"]["status"] == "rejected"
    gate = next(g for g in detail["gate_results"] if g["gate_key"] == "internal_external")
    assert gate["passed"] is False


def test_critical_target_is_rejected(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _seed_critical_asset(app_harness, "203.0.113.99")
    _, csrf = app_harness.login("Senior Analyst")

    request_id = _create_request(app_harness, csrf, alert_id, target="203.0.113.99").json()["id"]
    detail = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    ).json()
    assert detail["request"]["status"] == "rejected"
    gate = next(g for g in detail["gate_results"] if g["gate_key"] == "critical_asset")
    assert gate["passed"] is False


def test_rbac_and_csrf(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)

    # SOC Analyst has no prevention:simulate.
    _, soc_csrf = app_harness.login("SOC Analyst")
    denied = _create_request(app_harness, soc_csrf, alert_id, idem="soc")
    assert denied.status_code == 403

    # Senior Analyst without CSRF is rejected.
    _, csrf = app_harness.login("Senior Analyst")
    no_csrf = app_harness.client.post(
        "/api/v1/prevention/requests",
        headers={"Origin": ORIGIN, "Idempotency-Key": "nocsrf"},
        json={
            "alert_id": alert_id,
            "action_type": "temporary_block",
            "target_type": "external_ip",
            "target_value": "203.0.113.10",
            "reason": "x",
            "duration_seconds": 300,
            "rollback_plan": {"summary": "undo"},
        },
    )
    assert no_csrf.status_code == 403


def test_target_redacted_for_read_only_auditor(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    request_id = _create_request(app_harness, csrf, alert_id).json()["id"]

    # Auditor has prevention:read but not simulate/manage -> target is redacted.
    app_harness.login("Auditor")
    detail = app_harness.client.get(
        f"/api/v1/prevention/requests/{request_id}", headers={"Origin": ORIGIN}
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["request"]["target_value"] == "[redacted-target]"


def test_missing_idempotency_key_rejected(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    resp = app_harness.client.post(
        "/api/v1/prevention/requests",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "alert_id": alert_id,
            "action_type": "temporary_block",
            "target_type": "external_ip",
            "target_value": "203.0.113.10",
            "reason": "x",
            "duration_seconds": 300,
            "rollback_plan": {"summary": "undo"},
        },
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "idempotency_key_required"


def test_fresh_indicator_passes_freshness_gate(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    indicator_id = _seed_indicator(app_harness, fresh=True)
    _, csrf = app_harness.login("Senior Analyst")

    request_id = _create_request(app_harness, csrf, alert_id, indicator_id=indicator_id).json()[
        "id"
    ]
    detail = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    ).json()
    assert detail["request"]["status"] == "previewed"
    assert detail["request"]["indicator_id"] == indicator_id
    gate = next(g for g in detail["gate_results"] if g["gate_key"] == "intelligence_freshness")
    assert gate["passed"] is True
    assert gate["reason_code"] == "ok"


def test_stale_indicator_is_ignored_not_fatal(app_harness) -> None:  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    indicator_id = _seed_indicator(app_harness, fresh=False)
    _, csrf = app_harness.login("Senior Analyst")

    request_id = _create_request(app_harness, csrf, alert_id, indicator_id=indicator_id).json()[
        "id"
    ]
    detail = app_harness.client.post(
        f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf)
    ).json()
    # Deterministic corroboration still carries the request; stale intel is ignored.
    assert detail["request"]["status"] == "previewed"
    gate = next(g for g in detail["gate_results"] if g["gate_key"] == "intelligence_freshness")
    assert gate["passed"] is True
    assert gate["reason_code"] == "intelligence_stale_ignored"


def test_unknown_indicator_is_rejected(app_harness) -> None:  # type: ignore[no-untyped-def]
    from uuid import UUID

    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    resp = _create_request(
        app_harness, csrf, alert_id, indicator_id=str(UUID(int=0)), idem="bad-indi"
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "prevention_indicator_not_found"


def test_preview_representation_target_is_redacted_for_readers(app_harness):  # type: ignore[no-untyped-def]
    _seed_policy(app_harness)
    alert_id = _seed_alert(app_harness)
    _, csrf = app_harness.login("Senior Analyst")
    request_id = _create_request(app_harness, csrf, alert_id).json()["id"]
    app_harness.client.post(f"/api/v1/prevention/requests/{request_id}/preview", headers=_hdr(csrf))

    # Auditor (read-only): both the request field AND the preview representation redact.
    app_harness.login("Auditor")
    detail = app_harness.client.get(
        f"/api/v1/prevention/requests/{request_id}", headers={"Origin": ORIGIN}
    ).json()
    assert detail["request"]["target_value"] == "[redacted-target]"
    assert detail["preview"]["representation"]["target"]["display"] == "[redacted-target]"

    # Author still sees the raw target through the representation.
    app_harness.login("Senior Analyst")
    author_view = app_harness.client.get(
        f"/api/v1/prevention/requests/{request_id}", headers={"Origin": ORIGIN}
    ).json()
    assert author_view["preview"]["representation"]["target"]["display"] == "203.0.113.10"
