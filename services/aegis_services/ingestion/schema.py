from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1"


class CanonicalFlowV1(BaseModel):
    """Version 1 normalized flow contract; payload content is intentionally absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^1$")
    source_type: str = Field(pattern=r"^(normalized|zeek|suricata|pcap)$")
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_time: datetime
    src_address: str = Field(min_length=2, max_length=45)
    dst_address: str = Field(min_length=2, max_length=45)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(min_length=1, max_length=16, pattern=r"^[a-z0-9]+$")
    duration_ms: int = Field(ge=0, le=604_800_000)
    packet_count: int = Field(ge=0, le=9_223_372_036_854_775_807)
    byte_count: int = Field(ge=0, le=9_223_372_036_854_775_807)
    state: str | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)

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

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, str | int | bool]) -> dict[str, str | int | bool]:
        if len(value) > 12:
            raise ValueError("metadata contains too many fields")
        for key, item in value.items():
            if not key or len(key) > 32 or not key.replace("_", "").isalnum():
                raise ValueError("metadata key is invalid")
            if isinstance(item, str) and len(item) > 128:
                raise ValueError("metadata value is too long")
        return value

    @model_validator(mode="after")
    def validate_port_pair(self) -> CanonicalFlowV1:
        if (self.src_port is None) != (self.dst_port is None):
            raise ValueError("source and destination ports must both be present or absent")
        return self


@dataclass(frozen=True)
class ParsedRecord:
    flow: CanonicalFlowV1 | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if (self.flow is None) == (self.error_code is None):
            raise ValueError("parsed record must contain exactly one result")


def event_key(flow: CanonicalFlowV1, sensor_id: str | None) -> str:
    identity: dict[str, Any] = flow.model_dump(mode="json")
    identity["sensor_id"] = sensor_id
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
