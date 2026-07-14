from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.models import AuditEvent


def record_audit(
    db: AsyncSession,
    *,
    actor_user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    correlation_id: str,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        correlation_id=correlation_id,
        safe_metadata=metadata or {},
    )
    db.add(event)
    return event
