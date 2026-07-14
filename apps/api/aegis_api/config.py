from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime configuration with simulation as the only accepted mode."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", case_sensitive=False)

    environment: Literal["development", "test", "demo"] = "development"
    prevention_mode: Literal["simulation"] = "simulation"
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    database_url: str = "postgresql+asyncpg://aegis:unset@postgres:5432/aegis"
    redis_url: str = "redis://redis:6379/0"
    artifact_root: Path = Path("/var/lib/aegis/artifacts")
    upload_retention_hours: int = Field(default=24, ge=1, le=24)
    flow_retention_days: int = Field(default=30, ge=1)
    alert_retention_days: int = Field(default=180, ge=1)
    audit_retention_days: int = Field(default=180, ge=1)
    incident_retention_days: int = Field(default=180, ge=1)
    report_retention_days: int = Field(default=30, ge=1)
    prediction_retention_days: int = Field(default=30, ge=1)
    exceptional_holds_enabled: Literal[False] = False
    session_idle_minutes: int = Field(default=30, ge=5, le=120)
    session_absolute_hours: int = Field(default=8, ge=1, le=24)
    session_cookie_secure: Literal[True] = True
    login_ip_limit: int = Field(default=10, ge=3, le=100)
    login_ip_window_seconds: int = Field(default=300, ge=60, le=3600)
    login_failure_limit: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=120)
    password_min_length: int = Field(default=12, ge=12, le=64)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
