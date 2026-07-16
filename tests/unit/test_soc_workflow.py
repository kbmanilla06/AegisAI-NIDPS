from __future__ import annotations

import pytest

from aegis_services.soc import (
    SOC_LIMITATIONS,
    AlertDisposition,
    AlertStatus,
    IncidentStatus,
    sanitize_note,
    validate_alert_transition,
    validate_incident_transition,
)


def test_alert_transitions_follow_the_state_machine() -> None:
    validate_alert_transition(AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, None)
    validate_alert_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, None)
    validate_alert_transition(
        AlertStatus.INVESTIGATING, AlertStatus.CLOSED, AlertDisposition.SYNTHETIC_TRUE_POSITIVE
    )
    # Reopen is an explicit, allowed transition.
    validate_alert_transition(AlertStatus.CLOSED, AlertStatus.INVESTIGATING, None)


def test_alert_invalid_transitions_fail_closed() -> None:
    with pytest.raises(ValueError, match="alert_invalid_transition"):
        validate_alert_transition(AlertStatus.NEW, AlertStatus.CLOSED, AlertDisposition.BENIGN)
    with pytest.raises(ValueError, match="alert_invalid_transition"):
        validate_alert_transition(AlertStatus.NEW, AlertStatus.INVESTIGATING, None)
    with pytest.raises(ValueError, match="alert_invalid_transition"):
        validate_alert_transition(AlertStatus.CLOSED, AlertStatus.NEW, None)


def test_alert_close_requires_disposition_and_others_forbid_it() -> None:
    with pytest.raises(ValueError, match="alert_close_requires_disposition"):
        validate_alert_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.CLOSED, None)
    with pytest.raises(ValueError, match="alert_disposition_only_on_close"):
        validate_alert_transition(
            AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertDisposition.BENIGN
        )


def test_incident_transitions_and_disposition_rules() -> None:
    validate_incident_transition(IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, None)
    validate_incident_transition(IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, None)
    validate_incident_transition(
        IncidentStatus.RESOLVED, IncidentStatus.CLOSED, AlertDisposition.BENIGN
    )
    with pytest.raises(ValueError, match="incident_invalid_transition"):
        validate_incident_transition(IncidentStatus.OPEN, IncidentStatus.CLOSED, None)
    with pytest.raises(ValueError, match="incident_close_requires_disposition"):
        validate_incident_transition(IncidentStatus.RESOLVED, IncidentStatus.CLOSED, None)


def test_sanitize_note_redacts_endpoints_and_strips_control() -> None:
    cleaned = sanitize_note("Observed beacon from 192.0.2.10\x00 and 2001:db8::1 today")
    assert "192.0.2.10" not in cleaned
    assert "2001:db8::1" not in cleaned
    assert "[redacted-endpoint]" in cleaned
    assert "\x00" not in cleaned


def test_sanitize_note_bounds_and_rejects_empty() -> None:
    with pytest.raises(ValueError, match="note_empty"):
        sanitize_note("   \x00  ")
    with pytest.raises(ValueError, match="note_too_large"):
        sanitize_note("a" * 4097)


def test_soc_limitation_is_present_and_denies_authority() -> None:
    assert "SYNTHETIC DEMO ONLY" in SOC_LIMITATIONS
    assert "confer no authority" in SOC_LIMITATIONS
