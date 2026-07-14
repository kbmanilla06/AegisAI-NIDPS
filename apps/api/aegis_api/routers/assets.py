from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Asset
from aegis_api.schemas import AssetCreate, AssetOut, AssetUpdate
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
async def list_assets(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.ASSETS_READ))],
) -> list[Asset]:
    return list((await db.execute(select(Asset).order_by(Asset.name).limit(100))).scalars())


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    payload: AssetCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ASSETS_MANAGE))],
) -> Asset:
    if (await db.execute(select(Asset.id).where(Asset.name == payload.name))).scalar_one_or_none():
        raise ApiError(409, "asset_exists", "An asset with that name already exists")
    asset = Asset(
        **payload.model_dump(exclude={"criticality"}),
        criticality=payload.criticality.value,
        created_by=principal.user_id,
    )
    db.add(asset)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="asset.create",
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"criticality": asset.criticality, "network_zone": asset.network_zone},
    )
    await db.commit()
    return asset


@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ASSETS_MANAGE))],
) -> Asset:
    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id).with_for_update())
    ).scalar_one_or_none()
    if asset is None:
        raise ApiError(404, "asset_not_found", "Asset not found")
    if asset.version != payload.expected_version:
        raise ApiError(409, "version_conflict", "The asset was modified by another request")
    for field, value in payload.model_dump(exclude={"expected_version"}).items():
        setattr(asset, field, value.value if field == "criticality" else value)
    asset.version += 1
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="asset.update",
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"version": asset.version},
    )
    await db.commit()
    return asset
