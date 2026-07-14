from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.database import get_db
from aegis_api.models import AuditEvent
from aegis_api.schemas import AuditEventOut
from aegis_api.security.authentication import Principal, require_permission
from aegis_api.security.permissions import PermissionKey

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/events", response_model=list[AuditEventOut])
async def list_audit_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.AUDIT_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[AuditEvent]:
    events = (
        await db.execute(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(limit))
    ).scalars()
    return list(events)
