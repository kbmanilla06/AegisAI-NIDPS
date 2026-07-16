from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

# Versioned so a change to the correlation rule creates new incident versions
# rather than silently re-grouping existing ones.
CORRELATION_VERSION = "incident-correlation/v1"

_MAX_ALERTS = 10_000


@dataclass(frozen=True)
class AlertRef:
    """Minimal, metadata-only view of an alert used for offline correlation."""

    alert_id: str
    category: str


@dataclass(frozen=True)
class IncidentGroup:
    correlation_key: str
    category: str
    alert_ids: tuple[str, ...]


def correlation_key(category: str) -> str:
    """Deterministic correlation key; alerts of one category cluster into one incident."""
    return hashlib.sha256(f"{CORRELATION_VERSION}:{category}".encode()).hexdigest()


def correlate_alerts(alerts: Sequence[AlertRef]) -> tuple[IncidentGroup, ...]:
    """Deterministically group alerts into incidents by category.

    Pure and offline: no ML, no real-risk inference, no live-traffic input. Groups
    and their member ordering are stable for a given input.
    """
    if len(alerts) > _MAX_ALERTS:
        raise ValueError("incident_resource_limit")
    buckets: dict[str, list[str]] = {}
    categories: dict[str, str] = {}
    for alert in alerts:
        key = correlation_key(alert.category)
        buckets.setdefault(key, []).append(alert.alert_id)
        categories[key] = alert.category
    return tuple(
        IncidentGroup(
            correlation_key=key,
            category=categories[key],
            alert_ids=tuple(sorted(alert_ids)),
        )
        for key, alert_ids in sorted(buckets.items())
    )
