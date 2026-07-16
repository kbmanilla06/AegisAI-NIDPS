from __future__ import annotations

from enum import StrEnum

from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

# Sprint 8 SOC workflow operates over synthetic evidence; extend the mandatory
# synthetic limitation with the alert/incident no-authority clause (PREV-006).
SOC_LIMITATIONS = (
    SYNTHETIC_LIMITATIONS
    + " Alerts and incidents are workflow state over synthetic evidence, not real "
    "detections or real incidents, and confer no authority to prevent, block, contain, "
    "or act."
)


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class AlertDisposition(StrEnum):
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    SYNTHETIC_TRUE_POSITIVE = "synthetic_true_positive"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
