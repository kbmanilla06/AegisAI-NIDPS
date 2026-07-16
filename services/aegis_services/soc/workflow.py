from __future__ import annotations

import re
import unicodedata

from .schema import AlertDisposition, AlertStatus, IncidentStatus

# Deterministic, forward-biased state machines. Closure requires a disposition;
# a reopen is an explicit audited transition, never an in-place rewrite. There is
# no contained/blocked/prevented state — SOC workflow is investigative only.
ALERT_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset({AlertStatus.ACKNOWLEDGED}),
    AlertStatus.ACKNOWLEDGED: frozenset({AlertStatus.INVESTIGATING, AlertStatus.CLOSED}),
    AlertStatus.INVESTIGATING: frozenset({AlertStatus.CLOSED}),
    AlertStatus.CLOSED: frozenset({AlertStatus.INVESTIGATING}),
}

INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.RESOLVED}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING}),
    IncidentStatus.CLOSED: frozenset({IncidentStatus.INVESTIGATING}),
}

_MAX_NOTE_BYTES = 4096
# Endpoint-like tokens are redacted so a note can never carry an address; this is a
# privacy guard (PRIV-004), not a claim that synthetic values are real endpoints.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Matches full and ``::``-compressed IPv6 (>= two colon groups); intentionally
# aggressive, since over-redaction is safe for a privacy guard.
_IPV6 = re.compile(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
_REDACTED = "[redacted-endpoint]"


def validate_alert_transition(
    current: AlertStatus, target: AlertStatus, disposition: AlertDisposition | None
) -> None:
    """Fail closed on an invalid alert transition or a missing/extra disposition."""
    if target not in ALERT_TRANSITIONS[current]:
        raise ValueError("alert_invalid_transition")
    if target is AlertStatus.CLOSED and disposition is None:
        raise ValueError("alert_close_requires_disposition")
    if target is not AlertStatus.CLOSED and disposition is not None:
        raise ValueError("alert_disposition_only_on_close")


def validate_incident_transition(
    current: IncidentStatus, target: IncidentStatus, disposition: AlertDisposition | None
) -> None:
    """Fail closed on an invalid incident transition or a missing/extra disposition."""
    if target not in INCIDENT_TRANSITIONS[current]:
        raise ValueError("incident_invalid_transition")
    if target is IncidentStatus.CLOSED and disposition is None:
        raise ValueError("incident_close_requires_disposition")
    if target is not IncidentStatus.CLOSED and disposition is not None:
        raise ValueError("incident_disposition_only_on_close")


def sanitize_note(raw: str) -> str:
    """Normalize and bound an analyst note; redact endpoint-like tokens.

    Rejects empty/oversized input and strips control characters so a note can
    never carry raw endpoints, vectors, payloads, or control sequences.
    """
    normalized = unicodedata.normalize("NFC", raw)
    stripped = "".join(
        character
        for character in normalized
        if character in "\t\n" or unicodedata.category(character)[0] != "C"
    ).strip()
    if not stripped:
        raise ValueError("note_empty")
    if len(stripped.encode("utf-8")) > _MAX_NOTE_BYTES:
        raise ValueError("note_too_large")
    redacted = _IPV6.sub(_REDACTED, _IPV4.sub(_REDACTED, stripped))
    return redacted
