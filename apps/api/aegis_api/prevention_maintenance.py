from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.models import PreventionRequest
from aegis_services.prevention import (
    PreventionRequestStatus,
    validate_request_transition,
)

# Bounded so a single maintenance pass can never fan out unboundedly.
_MAX_PER_RUN = 1000


async def expire_due_simulations(db: AsyncSession, *, correlation_id: str = "maintenance") -> int:
    """Transition `simulated` requests past their expiry to `expired` (audited).

    Deterministic and side-effect-free beyond the audited status update: expiry is a
    simulated lifecycle event, never a real un-block. Returns the number expired.
    """
    now = datetime.now(UTC)
    rows = (
        await db.scalars(
            select(PreventionRequest)
            .where(PreventionRequest.status == PreventionRequestStatus.SIMULATED.value)
            .order_by(PreventionRequest.expires_at.asc())
            .limit(_MAX_PER_RUN)
        )
    ).all()
    expired = 0
    for row in rows:
        due = row.expires_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=UTC)
        if due > now:
            continue
        validate_request_transition(
            PreventionRequestStatus(row.status), PreventionRequestStatus.EXPIRED
        )
        row.status = PreventionRequestStatus.EXPIRED.value
        record_audit(
            db,
            actor_user_id=None,
            action="prevention.request.expire",
            resource_type="prevention_request",
            resource_id=str(row.id),
            outcome="success",
            correlation_id=correlation_id,
            metadata={"mode": "simulation", "prevention_allowed": False},
        )
        expired += 1
    if expired:
        await db.commit()
    return expired
