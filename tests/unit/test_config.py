import pytest
from pydantic import ValidationError

from aegis_api.config import Settings


def test_prevention_defaults_to_simulation() -> None:
    settings = Settings(_env_file=None)
    assert settings.prevention_mode == "simulation"
    assert settings.exceptional_holds_enabled is False


def test_real_prevention_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, prevention_mode="enforcement")  # type: ignore[arg-type]


def test_upload_retention_cannot_exceed_24_hours() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, upload_retention_hours=25)


def test_comma_separated_origins_are_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_ALLOWED_ORIGINS", "http://localhost:5173, http://127.0.0.1:5173")
    settings = Settings(_env_file=None)
    assert settings.allowed_origins == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
