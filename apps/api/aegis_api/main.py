from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_api.config import get_settings
from aegis_api.dependencies import postgres_check, redis_check
from aegis_api.health import HealthChecks, create_health_router


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AegisAI NIDPS API",
        version="0.1.0",
        description="Sprint 0 foundation. Prevention is simulation-only.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Correlation-ID", "Idempotency-Key"],
    )
    checks = HealthChecks(postgres=postgres_check(settings), redis=redis_check(settings))
    app.include_router(create_health_router(checks))
    return app


app = create_app()
