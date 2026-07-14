from collections.abc import Awaitable, Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis_api.health import HealthChecks, create_health_router


def check(result: bool) -> Callable[[], Awaitable[bool]]:
    async def run() -> bool:
        return result

    return run


def client(postgres: bool, redis: bool) -> TestClient:
    app = FastAPI()
    app.include_router(create_health_router(HealthChecks(check(postgres), check(redis))))
    return TestClient(app)


def test_liveness_discloses_simulation_mode() -> None:
    response = client(True, True).get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "prevention_mode": "simulation"}


def test_readiness_passes_when_dependencies_are_available() -> None:
    response = client(True, True).get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_fails_closed_when_dependency_is_unavailable() -> None:
    response = client(True, False).get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json()["dependencies"]["redis"] == "unavailable"
