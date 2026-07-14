from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Asset, Sensor
from aegis_api.schemas import (
    SensorCreate,
    SensorCredentialResponse,
    SensorOut,
    SensorStatusUpdate,
)
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey
from aegis_api.security.tokens import issue_sensor_credential

router = APIRouter(prefix="/api/v1/sensors", tags=["sensors"])


@router.get("", response_model=list[SensorOut])
async def list_sensors(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.SENSORS_READ))],
) -> list[Sensor]:
    return list((await db.execute(select(Sensor).order_by(Sensor.name).limit(100))).scalars())


@router.post("", response_model=SensorCredentialResponse, status_code=201)
async def create_sensor(
    payload: SensorCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.SENSORS_MANAGE))],
) -> SensorCredentialResponse:
    if (
        await db.execute(select(Sensor.id).where(Sensor.name == payload.name))
    ).scalar_one_or_none():
        raise ApiError(409, "sensor_exists", "A sensor with that name already exists")
    if (
        payload.asset_id
        and not (
            await db.execute(select(Asset.id).where(Asset.id == payload.asset_id))
        ).scalar_one_or_none()
    ):
        raise ApiError(422, "invalid_asset", "The selected asset does not exist")
    sensor_id = uuid4()
    credential, credential_hash = issue_sensor_credential(str(sensor_id))
    sensor = Sensor(
        id=sensor_id,
        name=payload.name,
        sensor_type=payload.sensor_type.value,
        credential_hash=credential_hash,
        asset_id=payload.asset_id,
        created_by=principal.user_id,
    )
    db.add(sensor)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="sensor.create",
        resource_type="sensor",
        resource_id=str(sensor.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"sensor_type": sensor.sensor_type, "credential_version": 1},
    )
    await db.commit()
    return SensorCredentialResponse(sensor=SensorOut.model_validate(sensor), credential=credential)


@router.post("/{sensor_id}/rotate", response_model=SensorCredentialResponse)
async def rotate_sensor_credential(
    sensor_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.SENSORS_MANAGE))],
) -> SensorCredentialResponse:
    sensor = (
        await db.execute(select(Sensor).where(Sensor.id == sensor_id).with_for_update())
    ).scalar_one_or_none()
    if sensor is None:
        raise ApiError(404, "sensor_not_found", "Sensor not found")
    credential, credential_hash = issue_sensor_credential(str(sensor.id))
    sensor.credential_hash = credential_hash
    sensor.credential_version += 1
    sensor.version += 1
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="sensor.credential_rotate",
        resource_type="sensor",
        resource_id=str(sensor.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"credential_version": sensor.credential_version},
    )
    await db.commit()
    return SensorCredentialResponse(sensor=SensorOut.model_validate(sensor), credential=credential)


@router.patch("/{sensor_id}", response_model=SensorOut)
async def update_sensor_status(
    sensor_id: UUID,
    payload: SensorStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.SENSORS_MANAGE))],
) -> Sensor:
    sensor = (
        await db.execute(select(Sensor).where(Sensor.id == sensor_id).with_for_update())
    ).scalar_one_or_none()
    if sensor is None:
        raise ApiError(404, "sensor_not_found", "Sensor not found")
    if sensor.version != payload.expected_version:
        raise ApiError(409, "version_conflict", "The sensor was modified by another request")
    sensor.status = "active" if payload.active else "inactive"
    sensor.version += 1
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="sensor.status_update",
        resource_type="sensor",
        resource_id=str(sensor.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"status": sensor.status},
    )
    await db.commit()
    return sensor
