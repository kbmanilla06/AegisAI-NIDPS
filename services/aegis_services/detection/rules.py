from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class FlowRecord:
    event_key: str
    source_type: str
    sensor_id: str | None
    event_time: datetime
    src_address: str
    dst_address: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    byte_count: int
    state: str | None


@dataclass(frozen=True)
class RuleDefinition:
    rule_key: str
    name: str
    description: str
    category: str
    evaluator_key: str
    parameters: dict[str, Any]
    window_seconds: int
    severity: str
    false_positive_guidance: str
    investigation_guidance: str
    prevention_recommendation: str
    mitre_mappings: tuple[dict[str, Any], ...] = ()
    evidence_contract: dict[str, Any] = field(
        default_factory=lambda: {
            "version": "alert-evidence/v1",
            "fields": ["group", "window", "observed", "threshold", "event_keys"],
        }
    )
    change_rationale: str = "Approved Sprint 3 initial deterministic rule."
    active: bool = True

    def canonical_definition(self) -> dict[str, Any]:
        return {
            "schema_version": "behavioral-rule/v1",
            "rule_key": self.rule_key,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "evaluator_key": self.evaluator_key,
            "parameters": self.parameters,
            "window_seconds": self.window_seconds,
            "severity": self.severity,
            "mitre_mappings": list(self.mitre_mappings),
            "evidence_contract": self.evidence_contract,
            "false_positive_guidance": self.false_positive_guidance,
            "investigation_guidance": self.investigation_guidance,
            "prevention_recommendation": self.prevention_recommendation,
            "change_rationale": self.change_rationale,
        }


@dataclass(frozen=True)
class RuleMatch:
    bucket_start: datetime
    bucket_end: datetime
    group: dict[str, str | int]
    observed_value: int
    threshold_value: int
    evidence_event_keys: tuple[str, ...]
    data_quality: tuple[str, ...] = ()


class _BaseParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold: int = Field(ge=2, le=100_000)
    excluded_asset_ids: list[str] = Field(default_factory=list, max_length=100)


class PortScanParameters(_BaseParameters):
    threshold: int = Field(default=20, ge=2, le=65_536)


class FailureParameters(_BaseParameters):
    threshold: int = Field(default=10, ge=2, le=10_000)
    failure_states: list[str] = Field(min_length=1, max_length=32)


class RateParameters(_BaseParameters):
    threshold: int = Field(default=100, ge=2, le=100_000)


PARAMETER_MODELS: dict[str, type[_BaseParameters]] = {
    "port_scan_v1": PortScanParameters,
    "repeated_failure_v1": FailureParameters,
    "high_connection_rate_v1": RateParameters,
}


DEFAULT_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_key="behavior.port_scan",
        name="Port scan indicator",
        description="Source contacted many unique destination ports on one host in a fixed window.",
        category="reconnaissance",
        evaluator_key="port_scan_v1",
        parameters={"threshold": 20, "excluded_asset_ids": []},
        window_seconds=60,
        severity="medium",
        false_positive_guidance="Authorized vulnerability scanners and administrative discovery.",
        investigation_guidance="Confirm source ownership and whether discovery was authorized.",
        prevention_recommendation="Review only; no prevention action is authorized by this rule.",
    ),
    RuleDefinition(
        rule_key="behavior.repeated_failure",
        name="Repeated connection failure indicator",
        description="Zeek reported repeated recognized connection-failure states for one service.",
        category="connection_failure",
        evaluator_key="repeated_failure_v1",
        parameters={
            "threshold": 10,
            "excluded_asset_ids": [],
            "failure_states": ["REJ", "S0", "RSTO", "RSTR", "SH", "SHR"],
        },
        window_seconds=300,
        severity="low",
        false_positive_guidance=(
            "Misconfiguration, unavailable services, or expired client settings."
        ),
        investigation_guidance=(
            "Review the destination service and source configuration before escalation."
        ),
        prevention_recommendation="Review only; connection failure is not proof of brute force.",
    ),
    RuleDefinition(
        rule_key="behavior.high_connection_rate",
        name="High connection-rate indicator",
        description="Source generated many distinct canonical flows in a fixed window.",
        category="traffic_rate",
        evaluator_key="high_connection_rate_v1",
        parameters={"threshold": 100, "excluded_asset_ids": []},
        window_seconds=60,
        severity="medium",
        false_positive_guidance=(
            "Proxies, monitoring, load tests, NAT gateways, and busy application clients."
        ),
        investigation_guidance=(
            "Validate source role and compare the observed rate with expected activity."
        ),
        prevention_recommendation="Review only; no prevention action is authorized by this rule.",
    ),
)


def validate_rule_parameters(evaluator_key: str, parameters: dict[str, Any]) -> dict[str, Any]:
    model = PARAMETER_MODELS.get(evaluator_key)
    if model is None:
        raise ValueError("unknown evaluator")
    try:
        validated = model.model_validate(parameters).model_dump(mode="json")
        return dict(validated)
    except ValidationError as error:
        raise ValueError("invalid rule parameters") from error


def bucket_start(event_time: datetime, window_seconds: int) -> datetime:
    normalized = (
        event_time.replace(tzinfo=UTC) if event_time.tzinfo is None else event_time.astimezone(UTC)
    )
    epoch_seconds = int(normalized.timestamp())
    return datetime.fromtimestamp(epoch_seconds - epoch_seconds % window_seconds, tz=UTC)


def evaluate_rule(
    definition: RuleDefinition,
    flows: list[FlowRecord],
    *,
    excluded_sources: frozenset[str] = frozenset(),
) -> list[RuleMatch]:
    parameters = validate_rule_parameters(definition.evaluator_key, definition.parameters)
    filtered = [flow for flow in flows if flow.src_address not in excluded_sources]
    if definition.evaluator_key == "port_scan_v1":
        return _port_scan(definition, filtered, int(parameters["threshold"]))
    if definition.evaluator_key == "repeated_failure_v1":
        return _repeated_failures(
            definition,
            filtered,
            int(parameters["threshold"]),
            frozenset(str(state) for state in parameters["failure_states"]),
        )
    if definition.evaluator_key == "high_connection_rate_v1":
        return _high_rate(definition, filtered, int(parameters["threshold"]))
    raise ValueError("unknown evaluator")


def _port_scan(
    definition: RuleDefinition, flows: list[FlowRecord], threshold: int
) -> list[RuleMatch]:
    groups: dict[tuple[datetime, str | None, str, str], list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        if flow.dst_port is None:
            continue
        groups[
            (
                bucket_start(flow.event_time, definition.window_seconds),
                flow.sensor_id,
                flow.src_address,
                flow.dst_address,
            )
        ].append(flow)
    matches: list[RuleMatch] = []
    for (start, sensor_id, source, destination), items in sorted(groups.items(), key=str):
        unique_ports = {item.dst_port for item in items}
        if len(unique_ports) < threshold:
            continue
        evidence = tuple(sorted({item.event_key for item in items}))
        matches.append(
            RuleMatch(
                start,
                start + timedelta(seconds=definition.window_seconds),
                {
                    "sensor_id": sensor_id or "unspecified",
                    "src_address": source,
                    "dst_address": destination,
                },
                len(unique_ports),
                threshold,
                evidence,
            )
        )
    return matches


def _repeated_failures(
    definition: RuleDefinition,
    flows: list[FlowRecord],
    threshold: int,
    failure_states: frozenset[str],
) -> list[RuleMatch]:
    groups: dict[tuple[datetime, str | None, str, str, int, str], list[FlowRecord]] = defaultdict(
        list
    )
    for flow in flows:
        if flow.source_type != "zeek" or flow.state not in failure_states or flow.dst_port is None:
            continue
        groups[
            (
                bucket_start(flow.event_time, definition.window_seconds),
                flow.sensor_id,
                flow.src_address,
                flow.dst_address,
                flow.dst_port,
                flow.protocol,
            )
        ].append(flow)
    matches: list[RuleMatch] = []
    for (start, sensor_id, source, destination, port, protocol), items in sorted(
        groups.items(), key=str
    ):
        evidence = tuple(sorted({item.event_key for item in items}))
        if len(evidence) < threshold:
            continue
        matches.append(
            RuleMatch(
                start,
                start + timedelta(seconds=definition.window_seconds),
                {
                    "sensor_id": sensor_id or "unspecified",
                    "src_address": source,
                    "dst_address": destination,
                    "dst_port": port,
                    "protocol": protocol,
                },
                len(evidence),
                threshold,
                evidence,
            )
        )
    return matches


def _high_rate(
    definition: RuleDefinition, flows: list[FlowRecord], threshold: int
) -> list[RuleMatch]:
    groups: dict[tuple[datetime, str | None, str], list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        groups[
            (
                bucket_start(flow.event_time, definition.window_seconds),
                flow.sensor_id,
                flow.src_address,
            )
        ].append(flow)
    matches: list[RuleMatch] = []
    for (start, sensor_id, source), items in sorted(groups.items(), key=str):
        evidence = tuple(sorted({item.event_key for item in items}))
        if len(evidence) < threshold:
            continue
        matches.append(
            RuleMatch(
                start,
                start + timedelta(seconds=definition.window_seconds),
                {"sensor_id": sensor_id or "unspecified", "src_address": source},
                len(evidence),
                threshold,
                evidence,
            )
        )
    return matches
