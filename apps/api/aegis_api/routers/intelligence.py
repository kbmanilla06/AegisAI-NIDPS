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
from aegis_api.intelligence_dispatch import get_match_dispatcher
from aegis_api.intelligence_processor import import_bundled_fixtures
from aegis_api.models import (
    Indicator,
    IntelligenceMatchBatch,
    IntelligenceSource,
    MitreMapping,
    MitreTechniqueCatalog,
)
from aegis_api.schemas import (
    IndicatorOut,
    IntelligenceSourceOut,
    MatchBatchCreate,
    MatchBatchOut,
    MitreMappingOut,
    MitreTechniqueCatalogOut,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey

router = APIRouter(prefix="/api/v1/intelligence")


@router.get("/sources", response_model=list[IntelligenceSourceOut])
async def list_sources(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INTELLIGENCE_READ))],
) -> list[IntelligenceSourceOut]:
    rows = (
        await db.scalars(select(IntelligenceSource).order_by(IntelligenceSource.created_at.desc()))
    ).all()
    return [IntelligenceSourceOut.model_validate(row) for row in rows]


@router.post("/imports", response_model=IntelligenceSourceOut, status_code=201)
async def import_fixtures(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INTELLIGENCE_IMPORT))
    ],
) -> IntelligenceSourceOut:
    source = await import_bundled_fixtures(principal.user_id, db)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="intelligence.import",
        resource_type="intelligence_source",
        resource_id=str(source.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "source_hash": source.source_hash,
            "external_lookup": False,
            "synthetic_demo_only": True,
        },
    )
    await db.commit()
    return IntelligenceSourceOut.model_validate(source)


@router.get("/indicators", response_model=list[IndicatorOut])
async def list_indicators(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INTELLIGENCE_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[IndicatorOut]:
    rows = (
        await db.scalars(select(Indicator).order_by(Indicator.created_at.desc()).limit(limit))
    ).all()
    return [IndicatorOut.model_validate(row) for row in rows]


@router.get("/match-batches", response_model=list[MatchBatchOut])
async def list_match_batches(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INTELLIGENCE_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[MatchBatchOut]:
    rows = (
        await db.scalars(
            select(IntelligenceMatchBatch)
            .order_by(IntelligenceMatchBatch.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [MatchBatchOut.model_validate(row) for row in rows]


@router.post("/match-batches", response_model=MatchBatchOut, status_code=202)
async def create_match_batch(
    payload: MatchBatchCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INTELLIGENCE_MATCH))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_match_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> MatchBatchOut:
    existing = await db.scalar(
        select(IntelligenceMatchBatch).where(
            IntelligenceMatchBatch.requested_by == principal.user_id,
            IntelligenceMatchBatch.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return MatchBatchOut.model_validate(existing)
    active = await db.scalar(
        select(func.count(IntelligenceMatchBatch.id)).where(
            IntelligenceMatchBatch.requested_by == principal.user_id,
            IntelligenceMatchBatch.status.in_(("pending", "processing")),
        )
    )
    if int(active or 0) >= 3:
        raise ApiError(429, "intelligence_resource_limit", "Too many match batches in progress")
    source = await db.scalar(
        select(IntelligenceSource).where(IntelligenceSource.source_hash == payload.source_hash)
    )
    if source is None:
        raise ApiError(409, "intelligence_source_not_found", "Import the bundled source first")
    now = datetime.now(UTC)
    row = IntelligenceMatchBatch(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        source_hash=payload.source_hash,
        status="pending",
        aggregate={},
        limitations=source.limitations,
        expires_at=now + timedelta(days=30),
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="intelligence.match.request",
        resource_type="intelligence_match_batch",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"synthetic_demo_only": True, "external_lookup": False},
    )
    await db.commit()
    dispatcher(str(row.id))
    return MatchBatchOut.model_validate(row)


@router.get("/match-batches/{batch_id}", response_model=MatchBatchOut)
async def get_match_batch(
    batch_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.INTELLIGENCE_READ))],
) -> MatchBatchOut:
    row = await db.get(IntelligenceMatchBatch, batch_id)
    if row is None:
        raise ApiError(404, "intelligence_match_batch_not_found", "Batch not found")
    return MatchBatchOut.model_validate(row)


@router.get("/mitre/techniques", response_model=list[MitreTechniqueCatalogOut])
async def list_mitre_techniques(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MITRE_READ))],
) -> list[MitreTechniqueCatalogOut]:
    rows = (
        await db.scalars(
            select(MitreTechniqueCatalog).order_by(MitreTechniqueCatalog.created_at.desc())
        )
    ).all()
    return [MitreTechniqueCatalogOut.model_validate(row) for row in rows]


@router.get("/mitre/mappings", response_model=list[MitreMappingOut])
async def list_mitre_mappings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MITRE_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[MitreMappingOut]:
    rows = (
        await db.scalars(select(MitreMapping).order_by(MitreMapping.created_at.desc()).limit(limit))
    ).all()
    return [MitreMappingOut.model_validate(row) for row in rows]
