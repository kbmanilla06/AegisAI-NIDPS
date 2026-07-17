from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from .schema import (
    SIMULATION_MODE,
    TargetScope,
    is_valid_target,
    target_scope,
)

# Versioned so a change to gate logic produces a new, auditable evaluation identity
# rather than silently re-deciding stored requests.
GATE_SET_VERSION = "prevention-gates/v1"


class GateKey(StrEnum):
    """The 13 mandatory gates from docs/PREVENTION_SAFETY.md, in evaluation order."""

    ENVIRONMENT = "environment"
    AUTHORIZATION = "authorization"
    TARGET_VALIDITY = "target_validity"
    INTERNAL_EXTERNAL = "internal_external"
    ALLOWLIST = "allowlist"
    CRITICAL_ASSET = "critical_asset"
    EVIDENCE = "evidence"
    MODEL_ANOMALY_ONLY = "model_anomaly_only"
    INTELLIGENCE_FRESHNESS = "intelligence_freshness"
    DURATION = "duration"
    ROLLBACK = "rollback"
    DUPLICATE_REPLAY = "duplicate_replay"
    RATE_COOLDOWN = "rate_cooldown"


# Canonical order used for both evaluation and storage/redisplay.
GATE_ORDER: tuple[GateKey, ...] = tuple(GateKey)


@dataclass(frozen=True)
class GateContext:
    """Fully resolved, side-effect-free inputs to gate evaluation.

    The router resolves every DB-backed fact (allowlist match, critical asset,
    evidence corroboration, intelligence freshness, duplicate detection) *before*
    calling ``evaluate_gates`` so gate logic stays pure and deterministic.
    """

    environment: str
    has_simulate_permission: bool
    action_type: str
    target_type: str
    target_value: str
    allowlist_match: bool
    target_is_critical: bool
    evidence_present: bool
    evidence_has_deterministic_corroboration: bool
    evidence_is_model_or_anomaly_only: bool
    intelligence_used: bool
    intelligence_is_sole_proof: bool
    intelligence_is_fresh: bool
    duration_seconds: int
    policy_max_duration_seconds: int
    has_expiry: bool
    has_rollback_plan: bool
    duplicate_detected: bool
    cooldown_active: bool


@dataclass(frozen=True)
class GateResult:
    key: GateKey
    passed: bool
    reason_code: str
    evidence_ref: str | None = None


def _environment(ctx: GateContext) -> GateResult:
    ok = ctx.environment == SIMULATION_MODE
    return GateResult(GateKey.ENVIRONMENT, ok, "ok" if ok else "environment_not_simulation")


def _authorization(ctx: GateContext) -> GateResult:
    ok = ctx.has_simulate_permission
    return GateResult(GateKey.AUTHORIZATION, ok, "ok" if ok else "missing_simulation_permission")


def _target_validity(ctx: GateContext) -> GateResult:
    ok = is_valid_target(ctx.target_type, ctx.target_value)
    return GateResult(GateKey.TARGET_VALIDITY, ok, "ok" if ok else "target_not_canonical")


def _internal_external(ctx: GateContext) -> GateResult:
    scope = target_scope(ctx.target_type)
    if scope is TargetScope.UNKNOWN:
        return GateResult(GateKey.INTERNAL_EXTERNAL, False, "scope_unknown")
    if scope is TargetScope.INTERNAL:
        # Internal targets receive the stricter default denial in the MVP; a future
        # high-impact workflow (Sprint 10) is the only path that could change this.
        return GateResult(GateKey.INTERNAL_EXTERNAL, False, "internal_stricter_denial")
    return GateResult(GateKey.INTERNAL_EXTERNAL, True, "ok")


def _allowlist(ctx: GateContext) -> GateResult:
    # A match *denies* the proposal (the target is explicitly protected from action).
    ok = not ctx.allowlist_match
    return GateResult(GateKey.ALLOWLIST, ok, "ok" if ok else "target_allowlisted")


def _critical_asset(ctx: GateContext) -> GateResult:
    ok = not ctx.target_is_critical
    return GateResult(GateKey.CRITICAL_ASSET, ok, "ok" if ok else "critical_asset_denied")


def _evidence(ctx: GateContext) -> GateResult:
    ok = ctx.evidence_present and ctx.evidence_has_deterministic_corroboration
    reason = "ok"
    if not ctx.evidence_present:
        reason = "evidence_missing"
    elif not ctx.evidence_has_deterministic_corroboration:
        reason = "evidence_not_corroborated"
    return GateResult(GateKey.EVIDENCE, ok, reason)


def _model_anomaly_only(ctx: GateContext) -> GateResult:
    # PREV-006: model-only or anomaly-only evidence is never sufficient.
    ok = not ctx.evidence_is_model_or_anomaly_only
    return GateResult(GateKey.MODEL_ANOMALY_ONLY, ok, "ok" if ok else "model_or_anomaly_only")


def _intelligence_freshness(ctx: GateContext) -> GateResult:
    if not ctx.intelligence_used:
        return GateResult(GateKey.INTELLIGENCE_FRESHNESS, True, "ok")
    if ctx.intelligence_is_sole_proof:
        # Intelligence may never be the sole proof, fresh or not (TM-13).
        return GateResult(GateKey.INTELLIGENCE_FRESHNESS, False, "intelligence_sole_proof")
    if not ctx.intelligence_is_fresh:
        # Expired intelligence is ignored; it cannot contribute, but with deterministic
        # corroboration already required, staleness alone does not fail the request.
        return GateResult(GateKey.INTELLIGENCE_FRESHNESS, True, "intelligence_stale_ignored")
    return GateResult(GateKey.INTELLIGENCE_FRESHNESS, True, "ok")


def _duration(ctx: GateContext) -> GateResult:
    ok = 0 < ctx.duration_seconds <= ctx.policy_max_duration_seconds and ctx.has_expiry
    reason = "ok"
    if ctx.duration_seconds <= 0:
        reason = "duration_not_positive"
    elif ctx.duration_seconds > ctx.policy_max_duration_seconds:
        reason = "duration_exceeds_policy_max"
    elif not ctx.has_expiry:
        reason = "expiry_missing"
    return GateResult(GateKey.DURATION, ok, reason)


def _rollback(ctx: GateContext) -> GateResult:
    ok = ctx.has_rollback_plan
    return GateResult(GateKey.ROLLBACK, ok, "ok" if ok else "rollback_plan_missing")


def _duplicate_replay(ctx: GateContext) -> GateResult:
    ok = not ctx.duplicate_detected
    return GateResult(GateKey.DUPLICATE_REPLAY, ok, "ok" if ok else "duplicate_request")


def _rate_cooldown(ctx: GateContext) -> GateResult:
    ok = not ctx.cooldown_active
    return GateResult(GateKey.RATE_COOLDOWN, ok, "ok" if ok else "cooldown_active")


_EVALUATORS = {
    GateKey.ENVIRONMENT: _environment,
    GateKey.AUTHORIZATION: _authorization,
    GateKey.TARGET_VALIDITY: _target_validity,
    GateKey.INTERNAL_EXTERNAL: _internal_external,
    GateKey.ALLOWLIST: _allowlist,
    GateKey.CRITICAL_ASSET: _critical_asset,
    GateKey.EVIDENCE: _evidence,
    GateKey.MODEL_ANOMALY_ONLY: _model_anomaly_only,
    GateKey.INTELLIGENCE_FRESHNESS: _intelligence_freshness,
    GateKey.DURATION: _duration,
    GateKey.ROLLBACK: _rollback,
    GateKey.DUPLICATE_REPLAY: _duplicate_replay,
    GateKey.RATE_COOLDOWN: _rate_cooldown,
}


def evaluate_gates(ctx: GateContext) -> tuple[GateResult, ...]:
    """Evaluate all 13 gates deterministically, in canonical order.

    Every gate is always evaluated (no short-circuit) so the stored decision carries
    a complete per-gate reason set. The request is eligible only if all gates pass.
    """
    return tuple(_EVALUATORS[key](ctx) for key in GATE_ORDER)


def all_passed(results: Sequence[GateResult]) -> bool:
    return all(result.passed for result in results)


def first_failure(results: Sequence[GateResult]) -> GateResult | None:
    return next((result for result in results if not result.passed), None)
