from __future__ import annotations

import pytest

from aegis_services.prevention import (
    REQUEST_TRANSITIONS,
    is_terminal,
    validate_request_transition,
)
from aegis_services.prevention import (
    PreventionRequestStatus as S,
)


def test_happy_path_transitions_are_valid() -> None:
    validate_request_transition(S.DRAFT, S.EVALUATED)
    validate_request_transition(S.EVALUATED, S.PREVIEWED)
    validate_request_transition(S.PREVIEWED, S.SIMULATED)
    validate_request_transition(S.SIMULATED, S.ROLLED_BACK)
    validate_request_transition(S.SIMULATED, S.EXPIRED)
    validate_request_transition(S.EVALUATED, S.REJECTED)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (S.DRAFT, S.SIMULATED),  # cannot skip preview
        (S.DRAFT, S.PREVIEWED),
        (S.EVALUATED, S.SIMULATED),
        (S.PREVIEWED, S.ROLLED_BACK),
        (S.REJECTED, S.PREVIEWED),  # terminal
        (S.EXPIRED, S.SIMULATED),  # terminal
        (S.ROLLED_BACK, S.SIMULATED),  # terminal
    ],
)
def test_invalid_transitions_fail_closed(current: S, target: S) -> None:
    with pytest.raises(ValueError, match="prevention_invalid_transition"):
        validate_request_transition(current, target)


def test_terminal_states_have_no_successors() -> None:
    for terminal in (S.REJECTED, S.EXPIRED, S.ROLLED_BACK):
        assert is_terminal(terminal)
        assert REQUEST_TRANSITIONS[terminal] == frozenset()


def test_no_state_reaches_a_real_execution_mode() -> None:
    # There is no "enforced"/"blocked"/"contained" state anywhere in the machine.
    all_states = set(REQUEST_TRANSITIONS) | {
        target for targets in REQUEST_TRANSITIONS.values() for target in targets
    }
    assert all_states == set(S)
    forbidden = {"enforced", "blocked", "contained", "quarantined", "applied"}
    assert forbidden.isdisjoint({state.value for state in all_states})
