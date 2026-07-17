from __future__ import annotations

from .schema import PreventionRequestStatus as S

# Deterministic, forward-biased request lifecycle. Invalid or skipped transitions
# fail closed. A request can never reach ``simulated`` without passing through
# ``previewed`` (all gates passed + preview persisted), and terminal states never
# transition again — a replay returns the existing record, never a new execution.
REQUEST_TRANSITIONS: dict[S, frozenset[S]] = {
    S.DRAFT: frozenset({S.EVALUATED}),
    S.EVALUATED: frozenset({S.REJECTED, S.PREVIEWED}),
    S.REJECTED: frozenset(),
    S.PREVIEWED: frozenset({S.SIMULATED}),
    S.SIMULATED: frozenset({S.EXPIRED, S.ROLLED_BACK}),
    S.EXPIRED: frozenset(),
    S.ROLLED_BACK: frozenset(),
}

TERMINAL_STATES: frozenset[S] = frozenset({S.REJECTED, S.EXPIRED, S.ROLLED_BACK})


def validate_request_transition(current: S, target: S) -> None:
    """Fail closed (ValueError) on any transition not in the state machine."""
    if target not in REQUEST_TRANSITIONS[current]:
        raise ValueError("prevention_invalid_transition")


def is_terminal(status: S) -> bool:
    return status in TERMINAL_STATES
