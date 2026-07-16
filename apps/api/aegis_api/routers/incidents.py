from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Alert, Incident, IncidentAlert, IncidentTimeline, User
from aegis_api.schemas import (
    IncidentAssign,
    IncidentCorrelateResponse,
    IncidentDetailOut,
    IncidentOut,
    IncidentStatusUpdate,
    IncidentTimelineOut,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.soc import (
    CORRELATION_VERSION,
    SOC_LIMITATIONS,
    AlertRef,
    IncidentStatus,
    correlate_alerts,
    validate_incident_transition,
)

router = APIRouter(prefix="/api/v1/incidents")

_CORRELATION_WINDOW_DAYS = 30
_MAX_ALERTS = 10_000


@router.post("/correlate", response_model=IncidentCorrelateResponse)
async def correlate(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INCIDENTS_CORRELATE))
    ],
) -> IncidentCorrelateResponse:
    now = datetime.now(UTC)
    window_start = now - timedelta(days=_CORRELATION_WINDOW_DAYS)
    alerts = (
        await db.scalars(
            select(Alert)
            .where(Alert.last_seen >= window_start)
            .order_by(Alert.last_seen.asc())
            .limit(_MAX_ALERTS)
        )
    ).all()
    refs = [AlertRef(alert_id=str(alert.id), category=alert.category) for alert in alerts]
    groups = correlate_alerts(refs)

    created = 0
    updated = 0
    touched: list[UUID] = []
    for group in groups:
        incident = await db.scalar(
            select(Incident).where(Incident.correlation_key == group.correlation_key)
        )
        member_ids = [UUID(alert_id) for alert_id in group.alert_ids]
        if incident is None:
            incident = Incident(
                correlation_key=group.correlation_key,
                correlation_version=CORRELATION_VERSION,
                category=group.category,
                status=IncidentStatus.OPEN.value,
                alert_count=0,
                limitations=SOC_LIMITATIONS,
                expires_at=now + timedelta(days=_CORRELATION_WINDOW_DAYS),
            )
            db.add(incident)
            await db.flush()
            db.add(
                IncidentTimeline(
                    incident_id=incident.id,
                    event_type="created",
                    detail={"category": group.category, "synthetic_demo_only": True},
                    actor_id=principal.user_id,
                )
            )
            created += 1
        else:
            updated += 1
        existing_members = set(
            (
                await db.scalars(
                    select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)
                )
            ).all()
        )
        added = 0
        for alert_id in member_ids:
            if alert_id in existing_members:
                continue
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert_id))
            added += 1
        if added:
            incident.alert_count = len(existing_members) + added
            db.add(
                IncidentTimeline(
                    incident_id=incident.id,
                    event_type="members_added",
                    detail={"added": added, "synthetic_demo_only": True},
                    actor_id=principal.user_id,
                )
            )
        touched.append(incident.id)

    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="incident.correlate",
        resource_type="incident",
        resource_id=None,
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "created": created,
            "updated": updated,
            "correlation_version": CORRELATION_VERSION,
            "synthetic_demo_only": True,
            "prevention_allowed": False,
        },
    )
    await db.commit()
    return IncidentCorrelateResponse(created=created, updated=updated, incident_ids=touched)


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INCIDENTS_READ))],
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[IncidentOut]:
    query = select(Incident).order_by(Incident.created_at.desc()).limit(limit)
    if status is not None:
        query = query.where(Incident.status == status)
    rows = (await db.scalars(query)).all()
    return [IncidentOut.model_validate(row) for row in rows]


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INCIDENTS_READ))],
) -> IncidentDetailOut:
    row = await db.get(Incident, incident_id)
    if row is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    member_ids = (
        await db.scalars(
            select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident_id)
        )
    ).all()
    timeline_rows = (
        await db.scalars(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident_id)
            .order_by(IncidentTimeline.created_at.asc())
        )
    ).all()
    return IncidentDetailOut(
        **IncidentOut.model_validate(row).model_dump(),
        member_alert_ids=list(member_ids),
        timeline=[IncidentTimelineOut.model_validate(item) for item in timeline_rows],
    )


@router.post("/{incident_id}/status", response_model=IncidentOut)
async def update_incident_status(
    incident_id: UUID,
    payload: IncidentStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INCIDENTS_MANAGE))
    ],
) -> IncidentOut:
    row = await db.get(Incident, incident_id)
    if row is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    if row.status != payload.expected_status.value:
        raise ApiError(409, "incident_state_conflict", "Incident is not in the expected state")
    try:
        validate_incident_transition(
            IncidentStatus(row.status), payload.status, payload.disposition
        )
    except ValueError as error:
        raise ApiError(422, str(error), "Invalid incident workflow transition") from error
    row.status = payload.status.value
    row.updated_by = principal.user_id
    if payload.status is IncidentStatus.CLOSED:
        assert payload.disposition is not None
        row.disposition = payload.disposition.value
    else:
        row.disposition = None
    db.add(
        IncidentTimeline(
            incident_id=row.id,
            event_type="status",
            detail={
                "from": payload.expected_status.value,
                "to": payload.status.value,
                "disposition": row.disposition,
            },
            actor_id=principal.user_id,
        )
    )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="incident.status",
        resource_type="incident",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "to": payload.status.value,
            "disposition": row.disposition,
            "synthetic_demo_only": True,
            "prevention_allowed": False,
        },
    )
    await db.commit()
    await db.refresh(row)
    return IncidentOut.model_validate(row)


@router.post("/{incident_id}/assign", response_model=IncidentOut)
async def assign_incident(
    incident_id: UUID,
    payload: IncidentAssign,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INCIDENTS_MANAGE))
    ],
) -> IncidentOut:
    row = await db.get(Incident, incident_id)
    if row is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    owner = await db.get(User, payload.owner_id)
    if owner is None or not owner.is_active:
        raise ApiError(409, "incident_owner_invalid", "Owner is not a valid active user")
    row.owner_id = owner.id
    row.updated_by = principal.user_id
    db.add(
        IncidentTimeline(
            incident_id=row.id,
            event_type="assigned",
            detail={"owner_id": str(owner.id)},
            actor_id=principal.user_id,
        )
    )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="incident.assign",
        resource_type="incident",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"owner_id": str(owner.id), "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(row)
    return IncidentOut.model_validate(row)
