from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_api.body_limits import IngestionBodyLimitMiddleware
from aegis_api.config import Settings, get_settings
from aegis_api.database import SessionFactory, engine
from aegis_api.dependencies import postgres_check, redis_check
from aegis_api.errors import install_error_handlers
from aegis_api.health import HealthChecks, create_health_router
from aegis_api.middleware import install_correlation_middleware
from aegis_api.routers import (
    anomaly,
    assets,
    audit,
    auth,
    detection,
    explainability,
    features,
    incidents,
    ingestion,
    intelligence,
    ml,
    prevention,
    sensors,
    soc,
    synthetic,
    users,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
    yield
    await engine.dispose()


def create_app(settings_override: Settings | None = None) -> FastAPI:
    settings = settings_override or get_settings()
    app = FastAPI(
        title="AegisAI NIDPS API",
        version="0.7.0",
        description=(
            "Sprint 6 synthetic-only anomaly and transparent offline fusion evidence. "
            "Prevention is simulation-only."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.session_factory = SessionFactory
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Correlation-ID", "Idempotency-Key"],
    )
    app.add_middleware(
        IngestionBodyLimitMiddleware,
        max_bytes=settings.ingestion_max_upload_bytes + settings.ingestion_request_overhead_bytes,
    )
    install_correlation_middleware(app)
    install_error_handlers(app)
    checks = HealthChecks(postgres=postgres_check(settings), redis=redis_check(settings))
    app.include_router(create_health_router(checks))
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(assets.router)
    app.include_router(anomaly.router)
    app.include_router(sensors.router)
    app.include_router(audit.router)
    app.include_router(ingestion.router)
    app.include_router(detection.router)
    app.include_router(features.router)
    app.include_router(synthetic.router)
    app.include_router(ml.router)
    app.include_router(explainability.router)
    app.include_router(intelligence.router)
    app.include_router(soc.router)
    app.include_router(incidents.router)
    app.include_router(prevention.router)
    app.include_router(detection.ws_router)
    return app


app = create_app()
