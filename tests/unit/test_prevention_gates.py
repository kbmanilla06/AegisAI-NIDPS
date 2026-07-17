from __future__ import annotations

from dataclasses import replace

import pytest

from aegis_services.prevention import (
    GATE_ORDER,
    GateContext,
    GateKey,
    all_passed,
    evaluate_gates,
    first_failure,
    is_valid_target,
    target_scope,
)
from aegis_services.prevention.schema import TargetScope


def _passing_context() -> GateContext:
    return GateContext(
        environment="simulation",
        has_simulate_permission=True,
        action_type="temporary_block",
        target_type="external_ip",
        target_value="203.0.113.10",
        allowlist_match=False,
        target_is_critical=False,
        evidence_present=True,
        evidence_has_deterministic_corroboration=True,
        evidence_is_model_or_anomaly_only=False,
        intelligence_used=False,
        intelligence_is_sole_proof=False,
        intelligence_is_fresh=True,
        duration_seconds=300,
        policy_max_duration_seconds=86_400,
        has_expiry=True,
        has_rollback_plan=True,
        duplicate_detected=False,
        cooldown_active=False,
    )


def test_all_thirteen_gates_evaluated_in_order() -> None:
    results = evaluate_gates(_passing_context())
    assert len(results) == 13
    assert tuple(result.key for result in results) == GATE_ORDER
    assert all_passed(results)
    assert first_failure(results) is None


def test_evaluation_is_deterministic() -> None:
    context = _passing_context()
    assert evaluate_gates(context) == evaluate_gates(context)


@pytest.mark.parametrize(
    ("mutation", "failing_gate", "reason"),
    [
        ({"environment": "production"}, GateKey.ENVIRONMENT, "environment_not_simulation"),
        (
            {"has_simulate_permission": False},
            GateKey.AUTHORIZATION,
            "missing_simulation_permission",
        ),
        ({"target_value": "not-an-ip"}, GateKey.TARGET_VALIDITY, "target_not_canonical"),
        (
            {"target_type": "external_ip", "target_value": "10.0.0.1"},
            GateKey.TARGET_VALIDITY,
            "target_not_canonical",
        ),
        ({"allowlist_match": True}, GateKey.ALLOWLIST, "target_allowlisted"),
        ({"target_is_critical": True}, GateKey.CRITICAL_ASSET, "critical_asset_denied"),
        ({"evidence_present": False}, GateKey.EVIDENCE, "evidence_missing"),
        (
            {"evidence_has_deterministic_corroboration": False},
            GateKey.EVIDENCE,
            "evidence_not_corroborated",
        ),
        (
            {"evidence_is_model_or_anomaly_only": True},
            GateKey.MODEL_ANOMALY_ONLY,
            "model_or_anomaly_only",
        ),
        ({"duration_seconds": 0}, GateKey.DURATION, "duration_not_positive"),
        ({"duration_seconds": 999_999}, GateKey.DURATION, "duration_exceeds_policy_max"),
        ({"has_expiry": False}, GateKey.DURATION, "expiry_missing"),
        ({"has_rollback_plan": False}, GateKey.ROLLBACK, "rollback_plan_missing"),
        ({"duplicate_detected": True}, GateKey.DUPLICATE_REPLAY, "duplicate_request"),
        ({"cooldown_active": True}, GateKey.RATE_COOLDOWN, "cooldown_active"),
    ],
)
def test_single_failure_fails_closed(mutation: dict, failing_gate: GateKey, reason: str) -> None:
    results = evaluate_gates(replace(_passing_context(), **mutation))
    assert not all_passed(results)
    failed = {result.key: result for result in results if not result.passed}
    assert failing_gate in failed
    assert failed[failing_gate].reason_code == reason


def test_internal_target_receives_stricter_denial() -> None:
    context = replace(_passing_context(), target_type="internal_ip", target_value="10.0.0.5")
    results = {result.key: result for result in evaluate_gates(context)}
    assert results[GateKey.INTERNAL_EXTERNAL].passed is False
    assert results[GateKey.INTERNAL_EXTERNAL].reason_code == "internal_stricter_denial"


def test_intelligence_can_never_be_sole_proof() -> None:
    context = replace(
        _passing_context(),
        intelligence_used=True,
        intelligence_is_sole_proof=True,
        intelligence_is_fresh=True,
    )
    results = {result.key: result for result in evaluate_gates(context)}
    assert results[GateKey.INTELLIGENCE_FRESHNESS].passed is False
    assert results[GateKey.INTELLIGENCE_FRESHNESS].reason_code == "intelligence_sole_proof"


def test_stale_intelligence_is_ignored_not_fatal() -> None:
    context = replace(
        _passing_context(),
        intelligence_used=True,
        intelligence_is_sole_proof=False,
        intelligence_is_fresh=False,
    )
    results = {result.key: result for result in evaluate_gates(context)}
    assert results[GateKey.INTELLIGENCE_FRESHNESS].passed is True
    assert results[GateKey.INTELLIGENCE_FRESHNESS].reason_code == "intelligence_stale_ignored"


def test_scope_and_target_helpers() -> None:
    assert target_scope("external_ip") is TargetScope.EXTERNAL
    assert target_scope("internal_ip") is TargetScope.INTERNAL
    assert target_scope("nonsense") is TargetScope.UNKNOWN
    assert is_valid_target("external_ip", "203.0.113.10") is True
    assert is_valid_target("external_ip", "10.0.0.1") is False
    assert is_valid_target("internal_ip", "10.0.0.1") is True
    assert is_valid_target("external_domain", "malware.example.com") is True
    assert is_valid_target("external_domain", "bad domain; rm -rf") is False
    assert is_valid_target("external_ip", "203.0.113.10; iptables -A") is False
