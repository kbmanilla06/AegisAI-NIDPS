from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.alert_notifier import AlertNotifier, get_alert_notifier
from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Alert, AlertNote, User
from aegis_api.schemas import (
    AlertAssign,
    AlertNoteCreate,
    AlertNoteOut,
    AlertOut,
    AlertStatusUpdate,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.soc import AlertStatus, sanitize_note, validate_alert_transition

# Alert reads live in the detection router (Sprint 3); this router adds only the
# Sprint 8 SOC workflow mutations and notes on those existing alerts.
router = APIRouter(prefix="/api/v1/alerts")


@router.post("/{alert_id}/status", response_model=AlertOut)
async def update_alert_status(
    alert_id: UUID,
    payload: AlertStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ALERTS_TRIAGE))],
    notifier: Annotated[AlertNotifier, Depends(get_alert_notifier)],
) -> AlertOut:
    row = await db.get(Alert, alert_id)
    if row is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    if row.status != payload.expected_status.value:
        raise ApiError(409, "alert_state_conflict", "Alert is not in the expected state")
    try:
        validate_alert_transition(AlertStatus(row.status), payload.status, payload.disposition)
    except ValueError as error:
        raise ApiError(422, str(error), "Invalid alert workflow transition") from error
    now = datetime.now(UTC)
    row.status = payload.status.value
    row.updated_by = principal.user_id
    if payload.status is AlertStatus.CLOSED:
        assert payload.disposition is not None
        row.disposition = payload.disposition.value
        row.closed_by = principal.user_id
        row.closed_at = now
    else:
        # Reopening clears the prior closure so disposition never lingers as authority.
        row.disposition = None
        row.closed_by = None
        row.closed_at = None
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="alert.status",
        resource_type="alert",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "from": payload.expected_status.value,
            "to": payload.status.value,
            "disposition": row.disposition,
            "synthetic_demo_only": True,
            "prevention_allowed": False,
        },
    )
    await db.commit()
    await db.refresh(row)
    # FR-012: best-effort metadata-only notification; never blocks the transition.
    with contextlib.suppress(Exception):
        await notifier(row.id)
    return AlertOut.model_validate(row)


@router.post("/{alert_id}/assign", response_model=AlertOut)
async def assign_alert(
    alert_id: UUID,
    payload: AlertAssign,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ALERTS_TRIAGE))],
    notifier: Annotated[AlertNotifier, Depends(get_alert_notifier)],
) -> AlertOut:
    row = await db.get(Alert, alert_id)
    if row is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    assignee = await db.get(User, payload.assignee_id)
    if assignee is None or not assignee.is_active:
        raise ApiError(409, "alert_assignee_invalid", "Assignee is not a valid active user")
    row.assignee_id = assignee.id
    row.updated_by = principal.user_id
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="alert.assign",
        resource_type="alert",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"assignee_id": str(assignee.id), "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(row)
    with contextlib.suppress(Exception):
        await notifier(row.id)
    return AlertOut.model_validate(row)


@router.get("/{alert_id}/notes", response_model=list[AlertNoteOut])
async def list_alert_notes(
    alert_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.ALERTS_READ))],
) -> list[AlertNoteOut]:
    rows = (
        await db.scalars(
            select(AlertNote)
            .where(AlertNote.alert_id == alert_id)
            .order_by(AlertNote.created_at.asc())
        )
    ).all()
    return [AlertNoteOut.model_validate(row) for row in rows]


@router.post("/{alert_id}/notes", response_model=AlertNoteOut, status_code=201)
async def add_alert_note(
    alert_id: UUID,
    payload: AlertNoteCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ALERTS_TRIAGE))],
) -> AlertNoteOut:
    row = await db.get(Alert, alert_id)
    if row is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    try:
        body = sanitize_note(payload.body)
    except ValueError as error:
        raise ApiError(422, str(error), "Note failed sanitization") from error
    note = AlertNote(alert_id=row.id, author_id=principal.user_id, body=body)
    db.add(note)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="alert.note",
        resource_type="alert",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"note_id": str(note.id), "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(note)
    return AlertNoteOut.model_validate(note)
