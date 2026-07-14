import hmac
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.ingestion_throttle import IngestionThrottle, get_ingestion_throttle
from aegis_api.models import Sensor
from aegis_api.security.tokens import hash_secret


@dataclass(frozen=True)
class SensorPrincipal:
    sensor: Sensor


async def get_sensor_principal(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    throttle: Annotated[IngestionThrottle, Depends(get_ingestion_throttle)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> SensorPrincipal:
    client_address = request.client.host if request.client else "unknown"
    await throttle.check(f"sensor-auth:{client_address}")
    sensor: Sensor | None = None
    credential = ""
    if authorization and authorization.startswith("Sensor "):
        credential = authorization.removeprefix("Sensor ").strip()
        sensor_id_value = credential.partition(".")[0]
        try:
            sensor = await db.get(Sensor, UUID(sensor_id_value))
        except ValueError:
            sensor = None
    if (
        sensor is None
        or sensor.status != "active"
        or not hmac.compare_digest(sensor.credential_hash, hash_secret(credential))
    ):
        record_audit(
            db,
            actor_user_id=None,
            action="sensor.authentication",
            resource_type="sensor",
            resource_id=str(sensor.id) if sensor is not None else None,
            outcome="denied",
            correlation_id=request.state.correlation_id,
            metadata={"reason": "invalid_sensor_credential"},
        )
        await db.commit()
        raise ApiError(401, "invalid_sensor_credential", "Sensor authentication failed")
    return SensorPrincipal(sensor=sensor)
