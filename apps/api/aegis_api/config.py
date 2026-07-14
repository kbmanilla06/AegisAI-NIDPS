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

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
