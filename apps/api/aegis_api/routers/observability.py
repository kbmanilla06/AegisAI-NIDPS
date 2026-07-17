from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    SyntheticAnalystFeedback,
    SyntheticMonitoringRun,
    SyntheticRecoveryRun,
    SyntheticReport,
    SyntheticReportJob,
)
from aegis_api.observability_dispatch import get_recovery_dispatcher, get_report_dispatcher
from aegis_api.schemas import (
    ObservabilityFinalizeRequest,
    ObservabilityRecoveryOut,
    ObservabilityReportJobOut,
    ObservabilityReportOut,
    ObservabilityReportRequest,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.observability import FALSE_CAPABILITY_FLAGS, OBSERVABILITY_LIMITATIONS

router = APIRouter(prefix="/api/v1/observability")


def _envelope(payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "limitations": OBSERVABILITY_LIMITATIONS,
        "false_capability_flags": FALSE_CAPABILITY_FLAGS,
        "synthetic_only": True,
    }


@router.get("/summary")
async def summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_READ))],
) -> dict[str, object]:
    run_count = int(await db.scalar(select(func.count()).select_from(SyntheticMonitoringRun)) or 0)
    report_count = int(await db.scalar(select(func.count()).select_from(SyntheticReport)) or 0)
    feedback_count = int(
        await db.scalar(select(func.count()).select_from(SyntheticAnalystFeedback)) or 0
    )
    return _envelope(
        {
            "contract": "synthetic-dashboard-view",
            "version": "1.0.0",
            "monitoring_run_count": run_count,
            "report_count": report_count,
            "feedback_count": feedback_count,
            "status": "complete" if run_count or report_count else "not_evaluable",
        }
    )


@router.get("/series")
async def series(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> dict[str, object]:
    from aegis_api.models import SyntheticObservabilityEvent

    rows = (
        await db.scalars(
            select(SyntheticObservabilityEvent)
            .order_by(SyntheticObservabilityEvent.created_at.desc())
            .limit(limit)
        )
    ).all()
    values = [
        {
            "component": row.component,
            "operation": row.operation,
            "status": row.status,
            "duration_ms": row.duration_ms,
            "rows": row.rows,
            "tasks": row.tasks,
            "created_at": row.created_at,
        }
        for row in rows
    ]
    return _envelope({"contract": "synthetic-sli-snapshot", "version": "1.0.0", "series": values})


@router.get("/reports", response_model=list[ObservabilityReportOut])
async def list_reports(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[ObservabilityReportOut]:
    rows = (
        await db.scalars(
            select(SyntheticReport).order_by(SyntheticReport.created_at.desc()).limit(limit)
        )
    ).all()
    return [ObservabilityReportOut.model_validate(row) for row in rows]


@router.get("/reports/{report_id}", response_model=ObservabilityReportOut)
async def get_report(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_READ))],
) -> ObservabilityReportOut:
    row = await db.get(SyntheticReport, report_id)
    if row is None:
        raise ApiError(404, "report_not_found", "Report not found")
    return ObservabilityReportOut.model_validate(row)


@router.post("/reports", response_model=ObservabilityReportJobOut, status_code=202)
async def create_report(
    payload: ObservabilityReportRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.OBSERVABILITY_REQUEST))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_report_dispatcher)],
    settings: Annotated[Settings, Depends(get_settings)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> ObservabilityReportJobOut:
    existing = await db.scalar(
        select(SyntheticReportJob).where(
            SyntheticReportJob.requested_by == principal.user_id,
            SyntheticReportJob.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.report_type != payload.report_type:
            raise ApiError(409, "report_idempotency_conflict", "Idempotency key conflicts")
        return ObservabilityReportJobOut.model_validate(existing)
    expires_at = datetime.now(UTC) + timedelta(days=settings.report_retention_days)
    job = SyntheticReportJob(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        report_type=payload.report_type,
        window_start=payload.window_start,
        window_end=payload.window_end,
        expires_at=expires_at,
    )
    db.add(job)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.report.generate.request",
        resource_type="synthetic_report_job",
        resource_id=str(job.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"report_type": payload.report_type, "synthetic_demo_only": True},
    )
    await db.commit()
    await db.refresh(job)
    try:
        dispatcher(str(job.id))
    except Exception as error:
        job.status = "failed"
        job.error_code = "report_dispatch_failed"
        await db.commit()
        raise ApiError(503, "report_dispatch_failed", "Reporting worker unavailable") from error
    return ObservabilityReportJobOut.model_validate(job)


@router.post("/reports/{report_id}/finalize", response_model=ObservabilityReportOut)
async def finalize_report(
    report_id: UUID,
    payload: ObservabilityFinalizeRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.OBSERVABILITY_FINALIZE))
    ],
) -> ObservabilityReportOut:
    row = await db.get(SyntheticReport, report_id)
    if row is None:
        raise ApiError(404, "report_not_found", "Report not found")
    if row.finalized_by is not None:
        raise ApiError(409, "report_already_finalized", "Report is already finalized")
    if row.status not in {"complete", "not_evaluable"}:
        raise ApiError(409, "report_not_finalizable", "Report is not ready for finalization")
    job = await db.scalar(select(SyntheticReportJob).where(SyntheticReportJob.report_id == row.id))
    if job is not None and job.requested_by == principal.user_id:
        raise ApiError(
            409,
            "report_reviewer_not_distinct",
            "Report finalization requires an independent reviewer",
        )
    row.finalized_by = principal.user_id
    row.finalized_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.report.finalize",
        resource_type="synthetic_report",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "report_hash": row.report_hash,
            "reason_length": len(payload.reason),
            "synthetic_demo_only": True,
        },
    )
    await db.commit()
    await db.refresh(row)
    return ObservabilityReportOut.model_validate(row)


@router.get("/feedback-summary")
async def feedback_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_READ))],
) -> dict[str, object]:
    rows = (
        await db.execute(
            select(SyntheticAnalystFeedback.disposition, func.count()).group_by(
                SyntheticAnalystFeedback.disposition
            )
        )
    ).all()
    return _envelope({"dispositions": {str(key): int(value) for key, value in rows}})


@router.get("/recovery", response_model=list[ObservabilityRecoveryOut])
async def list_recovery(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.OBSERVABILITY_RECOVERY))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[ObservabilityRecoveryOut]:
    rows = (
        await db.scalars(
            select(SyntheticRecoveryRun)
            .order_by(SyntheticRecoveryRun.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [ObservabilityRecoveryOut.model_validate(row) for row in rows]


@router.post("/recovery", response_model=ObservabilityRecoveryOut, status_code=202)
async def create_recovery(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.OBSERVABILITY_RECOVERY))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_recovery_dispatcher)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ObservabilityRecoveryOut:
    run = SyntheticRecoveryRun(
        requested_by=principal.user_id,
        correlation_id=request.state.correlation_id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.report_retention_days),
    )
    db.add(run)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.recovery.verify.request",
        resource_type="synthetic_recovery_run",
        resource_id=str(run.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"synthetic_demo_only": True, "metadata_only": True},
    )
    await db.commit()
    await db.refresh(run)
    try:
        dispatcher(str(run.id))
    except Exception as error:
        run.status = "failed"
        run.safe_error_code = "recovery_dispatch_failed"
        await db.commit()
        raise ApiError(503, "recovery_dispatch_failed", "Recovery worker unavailable") from error
    return ObservabilityRecoveryOut.model_validate(run)
