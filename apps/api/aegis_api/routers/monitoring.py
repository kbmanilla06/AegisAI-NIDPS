from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    SyntheticAnalystFeedback,
    SyntheticMonitoringMetric,
    SyntheticMonitoringRun,
)
from aegis_api.monitoring_dispatch import get_monitoring_dispatcher
from aegis_api.schemas import (
    AnalystFeedbackCreate,
    AnalystFeedbackOut,
    AnalystFeedbackReview,
    MonitoringMetricOut,
    MonitoringRunCreate,
    MonitoringRunOut,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.monitoring import (
    ACCEPTED_SYNTHETIC_ARTIFACT_HASHES,
    MONITORING_LIMITATIONS,
)

router = APIRouter(prefix="/api/v1/monitoring")
_ALLOWED_HASHES = ACCEPTED_SYNTHETIC_ARTIFACT_HASHES


def _validate_snapshot_hashes(payload: MonitoringRunCreate) -> None:
    for snapshot in (payload.baseline, payload.current):
        if snapshot.artifact_hash not in _ALLOWED_HASHES:
            raise ApiError(
                409,
                "synthetic_artifact_not_accepted",
                "Monitoring input is not an accepted synthetic artifact",
            )


@router.get("/runs", response_model=list[MonitoringRunOut])
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_MONITORING_READ))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[MonitoringRunOut]:
    rows = (
        await db.scalars(
            select(SyntheticMonitoringRun)
            .order_by(SyntheticMonitoringRun.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [MonitoringRunOut.model_validate(row) for row in rows]


@router.get("/runs/{run_id}/metrics", response_model=list[MonitoringMetricOut])
async def get_run_metrics(
    run_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_MONITORING_READ))
    ],
) -> list[MonitoringMetricOut]:
    if await db.get(SyntheticMonitoringRun, run_id) is None:
        raise ApiError(404, "monitoring_run_not_found", "Monitoring run not found")
    rows = (
        await db.scalars(
            select(SyntheticMonitoringMetric)
            .where(SyntheticMonitoringMetric.run_id == run_id)
            .order_by(SyntheticMonitoringMetric.metric_key.asc())
        )
    ).all()
    return [MonitoringMetricOut.model_validate(row) for row in rows]


@router.post("/runs", response_model=MonitoringRunOut, status_code=202)
async def create_run(
    payload: MonitoringRunCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.SYNTHETIC_MONITORING_RUN))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_monitoring_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> MonitoringRunOut:
    _validate_snapshot_hashes(payload)
    existing = await db.scalar(
        select(SyntheticMonitoringRun).where(
            SyntheticMonitoringRun.requested_by == principal.user_id,
            SyntheticMonitoringRun.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.source_kind != payload.source_kind:
            raise ApiError(409, "monitoring_idempotency_conflict", "Idempotency key conflicts")
        return MonitoringRunOut.model_validate(existing)
    now = datetime.now(UTC)
    run = SyntheticMonitoringRun(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        source_kind=payload.source_kind,
        schema_version="synthetic-monitoring/1.0.0",
        baseline_snapshot=payload.baseline.model_dump(mode="json"),
        current_snapshot=payload.current.model_dump(mode="json"),
        result={"status": "pending", "synthetic_demo_only": True},
        limitations=MONITORING_LIMITATIONS,
        expires_at=now + timedelta(days=30),
    )
    db.add(run)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(
            409, "monitoring_idempotency_conflict", "Monitoring run already exists"
        ) from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.monitoring.evaluate.request",
        resource_type="synthetic_monitoring_run",
        resource_id=str(run.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "source_kind": payload.source_kind,
            "baseline_artifact_hash": payload.baseline.artifact_hash,
            "current_artifact_hash": payload.current.artifact_hash,
            "synthetic_demo_only": True,
        },
    )
    await db.commit()
    await db.refresh(run)
    try:
        dispatcher(str(run.id))
    except Exception as error:
        run.status = "failed"
        run.error_code = "monitoring_dispatch_failed"
        run.completed_at = datetime.now(UTC)
        await db.commit()
        raise ApiError(
            503, "monitoring_dispatch_failed", "Monitoring worker unavailable"
        ) from error
    return MonitoringRunOut.model_validate(run)


@router.get("/feedback", response_model=list[AnalystFeedbackOut])
async def list_feedback(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_MONITORING_READ))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[AnalystFeedbackOut]:
    rows = (
        await db.scalars(
            select(SyntheticAnalystFeedback)
            .order_by(SyntheticAnalystFeedback.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [AnalystFeedbackOut.model_validate(row) for row in rows]


@router.post("/feedback", response_model=AnalystFeedbackOut, status_code=201)
async def create_feedback(
    payload: AnalystFeedbackCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.SYNTHETIC_FEEDBACK_WRITE))
    ],
) -> AnalystFeedbackOut:
    run = await db.get(SyntheticMonitoringRun, payload.monitoring_run_id)
    if run is None or run.status not in {"succeeded", "not_evaluable"}:
        raise ApiError(
            409, "monitoring_evidence_unavailable", "Monitoring evidence is not reviewable"
        )
    if payload.evidence_hash not in {
        run.baseline_snapshot_hash,
        run.current_snapshot_hash,
        run.policy_hash,
    }:
        raise ApiError(
            409, "feedback_evidence_mismatch", "Feedback evidence does not match the run"
        )
    row = SyntheticAnalystFeedback(
        monitoring_run_id=run.id,
        evidence_hash=payload.evidence_hash,
        disposition=payload.disposition.value,
        reason_code=payload.reason_code,
        note=payload.note,
        created_by=principal.user_id,
        expires_at=datetime.now(UTC) + timedelta(days=180),
    )
    db.add(row)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.feedback.submit",
        resource_type="synthetic_analyst_feedback",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"monitoring_run_id": str(run.id), "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(row)
    return AnalystFeedbackOut.model_validate(row)


@router.post("/feedback/{feedback_id}/review", response_model=AnalystFeedbackOut)
async def review_feedback(
    feedback_id: UUID,
    payload: AnalystFeedbackReview,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.SYNTHETIC_FEEDBACK_REVIEW))
    ],
) -> AnalystFeedbackOut:
    row = await db.get(SyntheticAnalystFeedback, feedback_id)
    if row is None:
        raise ApiError(404, "feedback_not_found", "Feedback not found")
    if row.created_by == principal.user_id:
        raise ApiError(
            409,
            "feedback_reviewer_not_distinct",
            "Feedback requires an independent reviewer",
        )
    if row.status != "submitted":
        raise ApiError(409, "feedback_already_reviewed", "Feedback has already been reviewed")
    row.status = "reviewed" if payload.accepted else "rejected"
    row.reviewed_by = principal.user_id
    row.review_reason = payload.reason
    row.reviewed_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.feedback.review",
        resource_type="synthetic_analyst_feedback",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"accepted": payload.accepted, "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(row)
    return AnalystFeedbackOut.model_validate(row)
