"""Sprint 9 prevention *simulation* service.

Level 1 simulation only (docs/PREVENTION_SAFETY.md, PREV-001): policy-gated
evaluation, a safe structured preview that is never an executable command, and
`simulated` execution/rollback records. There is no real adapter, no firewall /
network / host-state change, and no outbound socket anywhere in this package.
"""

from __future__ import annotations

from .adapter import (
    ADAPTER_REGISTRY,
    ExecutableRepresentationError,
    NoEnforcementEvidence,
    PreventionPreview,
    SimulationAdapter,
    SimulationPreventionAdapter,
    contains_executable_string,
    get_adapter,
)
from .gates import (
    GATE_ORDER,
    GATE_SET_VERSION,
    GateContext,
    GateKey,
    GateResult,
    all_passed,
    evaluate_gates,
    first_failure,
)
from .policy import (
    DEFAULT_MAX_DURATION_SECONDS,
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_VERSION,
    default_policy_definition,
    default_policy_hash,
)
from .schema import (
    FALSE_CAPABILITY_FLAGS,
    PREVENTION_LIMITATIONS,
    SIMULATION_ADAPTER,
    SIMULATION_MODE,
    PolicyLifecycle,
    PreventionActionType,
    PreventionRequestStatus,
    PreventionTargetType,
    TargetScope,
    canonical_policy_hash,
    is_valid_target,
    target_scope,
)
from .state_machine import (
    REQUEST_TRANSITIONS,
    TERMINAL_STATES,
    is_terminal,
    validate_request_transition,
)

__all__ = [
    "ADAPTER_REGISTRY",
    "DEFAULT_MAX_DURATION_SECONDS",
    "DEFAULT_POLICY_NAME",
    "DEFAULT_POLICY_VERSION",
    "FALSE_CAPABILITY_FLAGS",
    "GATE_ORDER",
    "GATE_SET_VERSION",
    "PREVENTION_LIMITATIONS",
    "REQUEST_TRANSITIONS",
    "SIMULATION_ADAPTER",
    "SIMULATION_MODE",
    "TERMINAL_STATES",
    "ExecutableRepresentationError",
    "GateContext",
    "GateKey",
    "GateResult",
    "NoEnforcementEvidence",
    "PolicyLifecycle",
    "PreventionActionType",
    "PreventionPreview",
    "PreventionRequestStatus",
    "PreventionTargetType",
    "SimulationAdapter",
    "SimulationPreventionAdapter",
    "TargetScope",
    "all_passed",
    "canonical_policy_hash",
    "contains_executable_string",
    "default_policy_definition",
    "default_policy_hash",
    "evaluate_gates",
    "first_failure",
    "get_adapter",
    "is_terminal",
    "is_valid_target",
    "target_scope",
    "validate_request_transition",
]
