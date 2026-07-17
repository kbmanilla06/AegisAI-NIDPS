from __future__ import annotations

from .gates import GATE_ORDER, GATE_SET_VERSION
from .schema import (
    PreventionActionType,
    PreventionTargetType,
    canonical_policy_hash,
)

# The MVP ships one reviewed policy version. Its definition is immutable; a change
# creates a new version + review event (never an in-place edit).
DEFAULT_POLICY_NAME = "baseline-simulation"
DEFAULT_POLICY_VERSION = "1"

# Duration ceiling for any simulated action. Positive-bounded, well below any notion
# of a permanent action (permanent actions do not exist — PREV-007).
DEFAULT_MAX_DURATION_SECONDS = 86_400  # 24 hours


def default_policy_definition() -> dict[str, object]:
    """Canonical, immutable definition of the baseline simulation policy."""
    return {
        "name": DEFAULT_POLICY_NAME,
        "version": DEFAULT_POLICY_VERSION,
        "mode": "simulation",
        "gate_set_version": GATE_SET_VERSION,
        "gates": [gate.value for gate in GATE_ORDER],
        "max_duration_seconds": DEFAULT_MAX_DURATION_SECONDS,
        "supported_action_types": sorted(action.value for action in PreventionActionType),
        "supported_target_types": sorted(target.value for target in PreventionTargetType),
        "requires_deterministic_corroboration": True,
        "model_or_anomaly_only_eligible": False,
        "permanent_action_allowed": False,
        "automatic_action_allowed": False,
    }


def default_policy_hash() -> str:
    return canonical_policy_hash(default_policy_definition())
