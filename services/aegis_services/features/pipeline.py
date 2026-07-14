from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from statistics import fmean

from aegis_services.features.schema import (
    MISSING_TOKEN,
    UNKNOWN_TOKEN,
    FeatureDefinitionV1,
    FeatureSchemaV1,
    FeatureVectorV1,
    WindowDefinitionV1,
    canonical_hash,
)
from aegis_services.ingestion.schema import CanonicalFlowV1

RATE_CAP = 1_000_000_000_000.0
MAX_INT64 = 9_223_372_036_854_775_807
FAILURE_STATES = frozenset({"REJ", "S0", "RSTO", "RSTR", "SH", "SHR"})
BANNED_FIELDS = (
    "label",
    "attack_cat",
    "row_id",
    "event_key",
    "source_event_id",
    "job_id",
    "sensor_id",
    "src_address",
    "dst_address",
    "event_time",
    "alert",
    "rule_match",
    "severity",
    "risk",
    "confidence",
    "incident",
    "prevention",
    "split",
    "source_filename",
)


@dataclass(frozen=True)
class FeatureInput:
    event_key: str
    sensor_id: str | None
    flow: CanonicalFlowV1


def _definition(
    name: str,
    dtype: str,
    unit: str,
    source: str,
    meaning: str,
    missing: str,
    minimum: float | None = None,
    maximum: float | None = None,
    categories: tuple[str, ...] = (),
) -> FeatureDefinitionV1:
    return FeatureDefinitionV1(
        name=name,
        dtype=dtype,  # type: ignore[arg-type]
        unit=unit,
        source=source,
        security_meaning=meaning,
        missing_policy=missing,
        minimum=minimum,
        maximum=maximum,
        categories=categories,
    )


DIRECT_FEATURES = (
    _definition(
        "duration_ms",
        "int64",
        "milliseconds",
        "flow.duration_ms",
        "Flow duration",
        "required",
        0,
        604_800_000,
    ),
    _definition(
        "packet_count",
        "int64",
        "packets",
        "flow.packet_count",
        "Reported packet total",
        "required",
        0,
    ),
    _definition(
        "byte_count", "int64", "bytes", "flow.byte_count", "Reported byte total", "required", 0
    ),
    _definition(
        "src_port_present",
        "bool",
        "boolean",
        "flow.src_port",
        "Source port availability",
        "never missing",
    ),
    _definition(
        "dst_port_present",
        "bool",
        "boolean",
        "flow.dst_port",
        "Destination port availability",
        "never missing",
    ),
    _definition(
        "src_port",
        "int64",
        "port",
        "flow.src_port",
        "Source transport port",
        "zero sentinel plus presence",
        0,
        65535,
    ),
    _definition(
        "dst_port",
        "int64",
        "port",
        "flow.dst_port",
        "Destination transport port",
        "zero sentinel plus presence",
        0,
        65535,
    ),
    _definition(
        "src_port_class",
        "category",
        "category",
        "derived.src_port",
        "IANA source port band",
        "none",
        categories=("none", "well_known", "registered", "dynamic"),
    ),
    _definition(
        "dst_port_class",
        "category",
        "category",
        "derived.dst_port",
        "IANA destination port band",
        "none",
        categories=("none", "well_known", "registered", "dynamic"),
    ),
    _definition(
        "protocol",
        "category",
        "category",
        "flow.protocol",
        "Canonical protocol token",
        UNKNOWN_TOKEN,
        categories=(MISSING_TOKEN, UNKNOWN_TOKEN, "tcp", "udp", "icmp", "icmpv6", "gre", "esp"),
    ),
    _definition(
        "connection_state",
        "category",
        "category",
        "flow.state",
        "Source-aware connection state",
        f"{MISSING_TOKEN}/{UNKNOWN_TOKEN}",
        categories=(
            MISSING_TOKEN,
            UNKNOWN_TOKEN,
            "REJ",
            "S0",
            "S1",
            "SF",
            "RSTO",
            "RSTR",
            "SH",
            "SHR",
            "OTH",
        ),
    ),
    _definition(
        "bytes_per_packet",
        "float64",
        "bytes_per_packet",
        "derived.counters",
        "Traffic density",
        "zero plus denominator flag",
        0,
        RATE_CAP,
    ),
    _definition(
        "packets_per_second",
        "float64",
        "packets_per_second",
        "derived.duration",
        "Packet rate",
        "zero plus denominator flag",
        0,
        RATE_CAP,
    ),
    _definition(
        "bytes_per_second",
        "float64",
        "bytes_per_second",
        "derived.duration",
        "Byte rate",
        "zero plus denominator flag",
        0,
        RATE_CAP,
    ),
    _definition(
        "zero_duration",
        "bool",
        "boolean",
        "derived.duration",
        "Zero-duration indicator",
        "never missing",
    ),
    _definition(
        "zero_packets",
        "bool",
        "boolean",
        "derived.packet_count",
        "Zero-packet indicator",
        "never missing",
    ),
    _definition(
        "rate_clipped",
        "bool",
        "boolean",
        "derived.rate",
        "Rate exceeded v1 safety cap",
        "never missing",
    ),
)

WINDOW_BASES = (
    ("flow_count", "int64", "flows", "Distinct flows in the as-of window"),
    ("unique_dst_address_count", "int64", "addresses", "Distinct destination addresses"),
    ("unique_dst_port_count", "int64", "ports", "Distinct destination ports"),
    ("packet_total", "int64", "packets", "Window packet total"),
    ("byte_total", "int64", "bytes", "Window byte total"),
    ("failure_count", "int64", "flows", "Recognized Zeek failure-state total"),
    ("mean_duration_ms", "float64", "milliseconds", "Mean flow duration"),
    ("max_duration_ms", "int64", "milliseconds", "Maximum flow duration"),
    ("mean_bytes_per_flow", "float64", "bytes_per_flow", "Mean bytes per flow"),
    (
        "seconds_since_prior_service",
        "float64",
        "seconds",
        "Time since prior same destination/service flow",
    ),
    ("prior_service_missing", "bool", "boolean", "No prior same destination/service flow"),
)


def feature_schema(code_version: str = "sprint4") -> FeatureSchemaV1:
    window_features = tuple(
        _definition(
            f"w{seconds}_{name}",
            dtype,
            unit,
            f"window.{seconds}",
            meaning,
            "zero" if name != "seconds_since_prior_service" else "zero plus missing indicator",
            0,
        )
        for seconds in (60, 300)
        for name, dtype, unit, meaning in WINDOW_BASES
    )
    return FeatureSchemaV1(
        features=DIRECT_FEATURES + window_features,
        windows=(WindowDefinitionV1(seconds=60), WindowDefinitionV1(seconds=300)),
        banned_fields=BANNED_FIELDS,
        code_version=code_version,
    )


def _port_class(port: int | None) -> str:
    if port is None:
        return "none"
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "dynamic"


def _category(value: str | None, vocabulary: tuple[str, ...]) -> str:
    if value is None:
        return MISSING_TOKEN
    return value if value in vocabulary else UNKNOWN_TOKEN


def _bounded_rate(numerator: int, denominator_seconds: float, flags: set[str], name: str) -> float:
    if denominator_seconds == 0:
        return 0.0
    value = numerator / denominator_seconds
    if not math.isfinite(value):
        raise ValueError("feature_non_finite")
    if value > RATE_CAP:
        flags.add(f"{name}_clipped")
        return RATE_CAP
    return value


def _window_values(
    target: FeatureInput, context: tuple[FeatureInput, ...], seconds: int
) -> list[int | float | bool]:
    cutoff = (target.flow.event_time, target.event_key)
    lower = target.flow.event_time - timedelta(seconds=seconds)
    unique: dict[str, FeatureInput] = {}
    for item in context:
        if item.sensor_id != target.sensor_id or item.flow.src_address != target.flow.src_address:
            continue
        item_order = (item.flow.event_time, item.event_key)
        if item.flow.event_time >= lower and item_order <= cutoff:
            unique[item.event_key] = item
    rows = sorted(unique.values(), key=lambda item: (item.flow.event_time, item.event_key))
    durations = [item.flow.duration_ms for item in rows]
    bytes_ = [item.flow.byte_count for item in rows]
    prior = [
        item
        for item in rows
        if (item.flow.event_time, item.event_key) < cutoff
        and item.flow.dst_address == target.flow.dst_address
        and item.flow.dst_port == target.flow.dst_port
        and item.flow.protocol == target.flow.protocol
    ]
    since_prior = 0.0
    if prior:
        since_prior = (target.flow.event_time - prior[-1].flow.event_time).total_seconds()
    return [
        len(rows),
        len({item.flow.dst_address for item in rows}),
        len({item.flow.dst_port for item in rows if item.flow.dst_port is not None}),
        sum(item.flow.packet_count for item in rows),
        sum(bytes_),
        sum(item.flow.source_type == "zeek" and item.flow.state in FAILURE_STATES for item in rows),
        fmean(durations) if durations else 0.0,
        max(durations, default=0),
        fmean(bytes_) if bytes_ else 0.0,
        since_prior,
        not prior,
    ]


class _WindowAccumulator:
    def __init__(self, seconds: int) -> None:
        self.seconds = seconds
        self.rows: deque[FeatureInput] = deque()
        self.destination_addresses: Counter[str] = Counter()
        self.destination_ports: Counter[int] = Counter()
        self.packet_total = 0
        self.byte_total = 0
        self.failure_count = 0
        self.duration_total = 0
        self.duration_max: deque[tuple[int, str]] = deque()
        self.services: dict[tuple[str, int | None, str], deque[FeatureInput]] = defaultdict(deque)

    @staticmethod
    def _service(item: FeatureInput) -> tuple[str, int | None, str]:
        return (item.flow.dst_address, item.flow.dst_port, item.flow.protocol)

    def _remove(self, item: FeatureInput) -> None:
        self.destination_addresses[item.flow.dst_address] -= 1
        if self.destination_addresses[item.flow.dst_address] == 0:
            del self.destination_addresses[item.flow.dst_address]
        if item.flow.dst_port is not None:
            self.destination_ports[item.flow.dst_port] -= 1
            if self.destination_ports[item.flow.dst_port] == 0:
                del self.destination_ports[item.flow.dst_port]
        self.packet_total -= item.flow.packet_count
        self.byte_total -= item.flow.byte_count
        self.failure_count -= int(
            item.flow.source_type == "zeek" and item.flow.state in FAILURE_STATES
        )
        self.duration_total -= item.flow.duration_ms
        if self.duration_max and self.duration_max[0][1] == item.event_key:
            self.duration_max.popleft()
        service = self._service(item)
        service_rows = self.services[service]
        if service_rows and service_rows[0].event_key == item.event_key:
            service_rows.popleft()
        if not service_rows:
            del self.services[service]

    def _add(self, item: FeatureInput) -> None:
        self.rows.append(item)
        self.destination_addresses[item.flow.dst_address] += 1
        if item.flow.dst_port is not None:
            self.destination_ports[item.flow.dst_port] += 1
        self.packet_total += item.flow.packet_count
        self.byte_total += item.flow.byte_count
        if self.packet_total > MAX_INT64 or self.byte_total > MAX_INT64:
            raise ValueError("feature_numeric_overflow")
        self.failure_count += int(
            item.flow.source_type == "zeek" and item.flow.state in FAILURE_STATES
        )
        self.duration_total += item.flow.duration_ms
        while self.duration_max and self.duration_max[-1][0] <= item.flow.duration_ms:
            self.duration_max.pop()
        self.duration_max.append((item.flow.duration_ms, item.event_key))
        self.services[self._service(item)].append(item)

    def append(self, target: FeatureInput) -> list[int | float | bool]:
        lower = target.flow.event_time - timedelta(seconds=self.seconds)
        while self.rows and self.rows[0].flow.event_time < lower:
            self._remove(self.rows.popleft())
        service_rows = self.services.get(self._service(target))
        prior = service_rows[-1] if service_rows else None
        self._add(target)
        count = len(self.rows)
        since_prior = (
            (target.flow.event_time - prior.flow.event_time).total_seconds()
            if prior is not None
            else 0.0
        )
        return [
            count,
            len(self.destination_addresses),
            len(self.destination_ports),
            self.packet_total,
            self.byte_total,
            self.failure_count,
            self.duration_total / count,
            self.duration_max[0][0],
            self.byte_total / count,
            since_prior,
            prior is None,
        ]


class FeaturePipeline:
    def __init__(self, schema: FeatureSchemaV1 | None = None) -> None:
        self.schema = schema or feature_schema()

    def validate_input(self, item: FeatureInput) -> FeatureInput:
        if item.flow.schema_version != self.schema.input_schema:
            raise ValueError("feature_schema_incompatible")
        if len(item.event_key) != 64 or any(
            character not in "0123456789abcdef" for character in item.event_key
        ):
            raise ValueError("feature_event_key_invalid")
        return item

    def transform_one(
        self,
        item: FeatureInput,
        context: tuple[FeatureInput, ...],
        source_snapshot_hash: str,
    ) -> FeatureVectorV1:
        target = self.validate_input(item)
        validated = tuple(self.validate_input(entry) for entry in context)
        window_values: list[int | float | bool] = []
        for window in self.schema.windows:
            window_values.extend(_window_values(target, validated, window.seconds))
        return self._build_vector(target, window_values, source_snapshot_hash)

    def _build_vector(
        self,
        target: FeatureInput,
        window_values: list[int | float | bool],
        source_snapshot_hash: str,
    ) -> FeatureVectorV1:
        flags: set[str] = set()
        duration_seconds = target.flow.duration_ms / 1000.0
        protocol_vocab = DIRECT_FEATURES[9].categories
        state_vocab = DIRECT_FEATURES[10].categories
        values: list[int | float | bool | str] = [
            target.flow.duration_ms,
            target.flow.packet_count,
            target.flow.byte_count,
            target.flow.src_port is not None,
            target.flow.dst_port is not None,
            target.flow.src_port or 0,
            target.flow.dst_port or 0,
            _port_class(target.flow.src_port),
            _port_class(target.flow.dst_port),
            _category(target.flow.protocol, protocol_vocab),
            _category(target.flow.state, state_vocab),
            _bounded_rate(
                target.flow.byte_count, float(target.flow.packet_count), flags, "bytes_per_packet"
            ),
            _bounded_rate(target.flow.packet_count, duration_seconds, flags, "packets_per_second"),
            _bounded_rate(target.flow.byte_count, duration_seconds, flags, "bytes_per_second"),
            target.flow.duration_ms == 0,
            target.flow.packet_count == 0,
            bool(flags),
        ]
        values.extend(window_values)
        names = tuple(definition.name for definition in self.schema.features)
        hash_input = {
            "contract": "feature-vector/v1",
            "feature_schema_hash": self.schema.definition_hash,
            "feature_schema_version": self.schema.version,
            "input_schema": self.schema.input_schema,
            "cutoff_time": target.flow.event_time.isoformat(),
            "source_snapshot_hash": source_snapshot_hash,
            "ordered_names": names,
            "ordered_values": values,
            "quality_flags": sorted(flags),
        }
        return FeatureVectorV1(
            feature_schema_hash=self.schema.definition_hash,
            source_event_key=target.event_key,
            cutoff_time=target.flow.event_time,
            source_snapshot_hash=source_snapshot_hash,
            ordered_names=names,
            ordered_values=tuple(values),
            quality_flags=tuple(sorted(flags)),
            vector_hash=canonical_hash(hash_input),
        )

    def transform_batch(self, items: tuple[FeatureInput, ...]) -> tuple[FeatureVectorV1, ...]:
        if len(items) > 10_000:
            raise ValueError("feature_record_limit")
        unique: dict[str, FeatureInput] = {}
        for item in items:
            validated = self.validate_input(item)
            existing = unique.get(validated.event_key)
            if existing is not None and existing != validated:
                raise ValueError("feature_duplicate_conflict")
            unique[validated.event_key] = validated
        ordered = tuple(
            sorted(unique.values(), key=lambda item: (item.flow.event_time, item.event_key))
        )
        snapshot_hash = canonical_hash(
            [{"event_key": item.event_key, "sensor_id": item.sensor_id} for item in ordered]
        )
        grouped: dict[tuple[str | None, str], list[FeatureInput]] = defaultdict(list)
        for item in ordered:
            grouped[(item.sensor_id, item.flow.src_address)].append(item)
        window_values: dict[str, list[int | float | bool]] = {
            item.event_key: [] for item in ordered
        }
        for group in grouped.values():
            accumulators = [_WindowAccumulator(window.seconds) for window in self.schema.windows]
            for item in group:
                for accumulator in accumulators:
                    window_values[item.event_key].extend(accumulator.append(item))
        return tuple(
            self._build_vector(item, window_values[item.event_key], snapshot_hash)
            for item in ordered
        )
