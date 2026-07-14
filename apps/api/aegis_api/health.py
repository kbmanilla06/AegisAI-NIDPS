from dataclasses import dataclass

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from aegis_api.dependencies import Check


class LivenessResponse(BaseModel):
    status: str
    prevention_mode: str


class ReadinessResponse(BaseModel):
    status: str
    dependencies: dict[str, str]


@dataclass(frozen=True)
class HealthChecks:
    postgres: Check
    redis: Check


def create_health_router(checks: HealthChecks) -> APIRouter:
    router = APIRouter(prefix="/api/v1/health", tags=["health"])

    @router.get("/live", response_model=LivenessResponse)
    async def live() -> LivenessResponse:
        return LivenessResponse(status="ok", prevention_mode="simulation")

    @router.get("/ready", response_model=ReadinessResponse)
    async def ready(response: Response) -> ReadinessResponse:
        results = {
            "postgres": "ok" if await checks.postgres() else "unavailable",
            "redis": "ok" if await checks.redis() else "unavailable",
        }
        ready_status = "ok" if all(value == "ok" for value in results.values()) else "degraded"
        if ready_status != "ok":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(status=ready_status, dependencies=results)

    return router
