from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SIGNATURE_SCHEMA_VERSION = "signature-event/v1"


class CanonicalSignatureEventV1(BaseModel):
    """Strict metadata-only representation of a reported Suricata alert."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=SIGNATURE_SCHEMA_VERSION, pattern=r"^signature-event/v1$")
    source_type: str = Field(default="suricata", pattern=r"^suricata$")
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_time: datetime
    src_address: str = Field(min_length=2, max_length=45)
    dst_address: str = Field(min_length=2, max_length=45)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(min_length=1, max_length=16, pattern=r"^[a-z0-9]+$")
    signature_id: int = Field(ge=1, le=2_147_483_647)
    signature_revision: int = Field(ge=0, le=2_147_483_647)
    signature_name: str = Field(min_length=1, max_length=256)
    category: str = Field(min_length=1, max_length=128)
    reported_severity: int = Field(ge=1, le=255)
    reported_action: str | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    flow_id: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("event_time")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("event_time must include a timezone")
        return value.astimezone(UTC)

    @field_validator("src_address", "dst_address")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        return value.lower()

    @field_validator("signature_name", "category")
    @classmethod
    def reject_control_text(cls, value: str) -> str:
        if any(ord(character) < 32 and character not in {"\t"} for character in value):
            raise ValueError("control characters are not permitted")
        return value

    @model_validator(mode="after")
    def validate_port_pair(self) -> CanonicalSignatureEventV1:
        if (self.src_port is None) != (self.dst_port is None):
            raise ValueError("source and destination ports must both be present or absent")
        return self


def signature_event_key(event: CanonicalSignatureEventV1, sensor_id: str | None) -> str:
    identity: dict[str, Any] = event.model_dump(mode="json")
    identity["sensor_id"] = sensor_id
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
