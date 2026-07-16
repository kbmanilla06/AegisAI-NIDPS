from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.explainability_dispatch import get_explanation_dispatcher
from aegis_api.models import Explanation, ExplanationBatch, ExplanationMethodVersion
from aegis_api.schemas import (
    ExplanationBatchCreate,
    ExplanationBatchOut,
    ExplanationMethodCreate,
    ExplanationMethodOut,
    ExplanationOut,
    SprintSevenReview,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.explainability import explanation_method
from aegis_services.features import feature_schema

router = APIRouter(prefix="/api/v1/explainability")


@router.get("/methods", response_model=list[ExplanationMethodOut])
async def list_methods(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.EXPLANATIONS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[ExplanationMethodOut]:
    rows = (
        await db.scalars(
            select(ExplanationMethodVersion)
            .order_by(ExplanationMethodVersion.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [ExplanationMethodOut.model_validate(row) for row in rows]


@router.post("/methods", response_model=ExplanationMethodOut, status_code=201)
async def create_method(
    payload: ExplanationMethodCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.EXPLANATIONS_GENERATE))
    ],
) -> ExplanationMethodOut:
    method = explanation_method(feature_schema("sprint4"), top_k=payload.top_k)
    existing = await db.scalar(
        select(ExplanationMethodVersion).where(
            ExplanationMethodVersion.method_hash == method.method_hash
        )
    )
    if existing is not None:
        return ExplanationMethodOut.model_validate(existing)
    row = ExplanationMethodVersion(
        method=method.method.value,
        target_algorithm=method.target_algorithm,
        feature_schema_hash=method.feature_schema_hash,
        top_k=method.top_k,
        method_hash=method.method_hash,
        lifecycle_state="draft",
        created_by=principal.user_id,
        limitations=method.limitations,
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="explanation.method.create",
        resource_type="explanation_method",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"method_hash": row.method_hash, "synthetic_demo_only": True},
    )
    await db.commit()
    return ExplanationMethodOut.model_validate(row)


@router.post("/methods/{method_id}/review", response_model=ExplanationMethodOut)
async def review_method(
    method_id: UUID,
    payload: SprintSevenReview,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.EXPLANATIONS_REVIEW))
    ],
) -> ExplanationMethodOut:
    row = await db.get(ExplanationMethodVersion, method_id)
    if row is None:
        raise ApiError(404, "explanation_method_not_found", "Method not found")
    if row.created_by == principal.user_id:
        raise ApiError(
            409, "explanation_reviewer_separation", "Creator cannot review the same method"
        )
    row.lifecycle_state = "reviewed" if payload.approved else "retired"
    row.reviewed_by = principal.user_id
    row.review_reason = payload.reason
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="explanation.method.review",
        resource_type="explanation_method",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"approved": payload.approved, "synthetic_demo_only": True},
    )
    await db.commit()
    return ExplanationMethodOut.model_validate(row)


@router.get("/batches", response_model=list[ExplanationBatchOut])
async def list_batches(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.EXPLANATIONS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[ExplanationBatchOut]:
    rows = (
        await db.scalars(
            select(ExplanationBatch).order_by(ExplanationBatch.created_at.desc()).limit(limit)
        )
    ).all()
    return [ExplanationBatchOut.model_validate(row) for row in rows]


@router.post("/batches", response_model=ExplanationBatchOut, status_code=202)
async def create_batch(
    payload: ExplanationBatchCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.EXPLANATIONS_GENERATE))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_explanation_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> ExplanationBatchOut:
    existing = await db.scalar(
        select(ExplanationBatch).where(
            ExplanationBatch.requested_by == principal.user_id,
            ExplanationBatch.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return ExplanationBatchOut.model_validate(existing)
    active = await db.scalar(
        select(func.count(ExplanationBatch.id)).where(
            ExplanationBatch.requested_by == principal.user_id,
            ExplanationBatch.status.in_(("pending", "processing")),
        )
    )
    if int(active or 0) >= 3:
        raise ApiError(
            429, "explanation_resource_limit", "Too many explanation batches in progress"
        )
    method = await db.scalar(
        select(ExplanationMethodVersion).where(
            ExplanationMethodVersion.method_hash == payload.method_hash,
            ExplanationMethodVersion.lifecycle_state == "reviewed",
        )
    )
    if method is None:
        raise ApiError(409, "explanation_method_not_reviewed", "A reviewed method is required")
    now = datetime.now(UTC)
    row = ExplanationBatch(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        method_hash=payload.method_hash,
        target_model_hash=payload.target_model_hash,
        status="pending",
        aggregate={},
        limitations=method.limitations,
        expires_at=now + timedelta(days=30),
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="explanation.batch.request",
        resource_type="explanation_batch",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"synthetic_demo_only": True, "online_inference_allowed": False},
    )
    await db.commit()
    dispatcher(str(row.id))
    return ExplanationBatchOut.model_validate(row)


@router.get("/batches/{batch_id}", response_model=ExplanationBatchOut)
async def get_batch(
    batch_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.EXPLANATIONS_READ))],
) -> ExplanationBatchOut:
    row = await db.get(ExplanationBatch, batch_id)
    if row is None:
        raise ApiError(404, "explanation_batch_not_found", "Batch not found")
    return ExplanationBatchOut.model_validate(row)


@router.get("/batches/{batch_id}/explanations", response_model=list[ExplanationOut])
async def list_explanations(
    batch_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.EXPLANATIONS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[ExplanationOut]:
    rows = (
        await db.scalars(
            select(Explanation)
            .where(Explanation.batch_id == batch_id)
            .order_by(Explanation.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [ExplanationOut.model_validate(row) for row in rows]
