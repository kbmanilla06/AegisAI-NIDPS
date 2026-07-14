from __future__ import annotations

import json
import math
import socket
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import dpkt
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aegis_services.ingestion.schema import CanonicalFlowV1, ParsedRecord

MAX_LINE_BYTES = 65_536
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
}


class FatalIngestionError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ParseLimits:
    max_records: int
    max_unique_flows: int
    max_seconds: int


class NormalizedInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^1$")
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_time: datetime
    src_address: str
    dst_address: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    duration_ms: int
    packet_count: int
    byte_count: int
    state: str | None = None

    @field_validator("event_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timezone required")
        return value


def content_matches(source_type: str, prefix: bytes) -> bool:
    stripped = prefix.lstrip()
    if source_type == "pcap":
        return prefix[:4] in PCAP_MAGICS
    if source_type == "zeek":
        return stripped.startswith((b"#separator", b"#fields", b"{"))
    if source_type in {"normalized", "suricata"}:
        return stripped.startswith(b"{")
    return False


def parse_file(path: Path, source_type: str, limits: ParseLimits) -> Iterator[ParsedRecord]:
    started = time.monotonic()
    if source_type == "normalized":
        yield from _parse_json_lines(path, limits, started, _normalize_flow)
    elif source_type == "zeek":
        yield from _parse_zeek(path, limits, started)
    elif source_type == "suricata":
        yield from _parse_json_lines(path, limits, started, _normalize_suricata)
    elif source_type == "pcap":
        yield from _parse_pcap(path, limits, started)
    else:
        raise FatalIngestionError("unsupported_source")


def _check_limits(index: int, limits: ParseLimits, started: float) -> None:
    if index > limits.max_records:
        raise FatalIngestionError("record_limit_exceeded")
    if time.monotonic() - started > limits.max_seconds:
        raise FatalIngestionError("processing_time_exceeded")


def _bounded_lines(handle: BinaryIO) -> Iterator[tuple[bytes, bool]]:
    while True:
        line = handle.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            while line and not line.endswith(b"\n"):
                line = handle.readline(MAX_LINE_BYTES + 1)
            yield b"", True
        else:
            yield line, False


def _parse_json_lines(
    path: Path,
    limits: ParseLimits,
    started: float,
    normalizer: Any,
) -> Iterator[ParsedRecord]:
    with path.open("rb") as handle:
        for index, (raw_line, too_long) in enumerate(_bounded_lines(handle), start=1):
            _check_limits(index, limits, started)
            if too_long:
                yield ParsedRecord(error_code="line_too_long")
                continue
            if not raw_line.strip():
                yield ParsedRecord(error_code="empty_record")
                continue
            try:
                value = json.loads(raw_line.decode("utf-8"))
                if not isinstance(value, dict):
                    raise ValueError
                yield ParsedRecord(flow=normalizer(value))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValidationError,
                ValueError,
                TypeError,
                OverflowError,
                OSError,
            ):
                yield ParsedRecord(error_code="invalid_record")


def _normalize_flow(value: dict[str, Any]) -> CanonicalFlowV1:
    item = NormalizedInput.model_validate(value)
    return CanonicalFlowV1(source_type="normalized", **item.model_dump())


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, int | float):
        if isinstance(value, bool) or not math.isfinite(float(value)):
            raise ValueError("timestamp must be finite")
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (ValueError, OSError, OverflowError):
            pass
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(UTC)
    raise ValueError("invalid timestamp")


def _integer(value: object, default: int = 0) -> int:
    if value in {None, "-", ""}:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("invalid integer")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError("fractional integer")
    return int(value)


def _float(value: object, default: float = 0.0) -> float:
    if value in {None, "-", ""}:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("invalid number")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("number must be finite")
    return parsed


def _normalize_zeek(value: dict[str, Any]) -> CanonicalFlowV1:
    return CanonicalFlowV1(
        source_type="zeek",
        source_event_id=str(value["uid"]),
        event_time=_parse_timestamp(value["ts"]),
        src_address=str(value["id.orig_h"]),
        dst_address=str(value["id.resp_h"]),
        src_port=_integer(value.get("id.orig_p")),
        dst_port=_integer(value.get("id.resp_p")),
        protocol=str(value["proto"]).lower(),
        duration_ms=max(0, round(_float(value.get("duration")) * 1000)),
        packet_count=_integer(value.get("orig_pkts")) + _integer(value.get("resp_pkts")),
        byte_count=_integer(value.get("orig_bytes")) + _integer(value.get("resp_bytes")),
        state=None if value.get("conn_state") in {None, "-"} else str(value["conn_state"]),
        metadata={"service": str(value["service"])}
        if value.get("service") not in {None, "-", ""}
        else {},
    )


def _parse_zeek(path: Path, limits: ParseLimits, started: float) -> Iterator[ParsedRecord]:
    fields: list[str] | None = None
    record_index = 0
    with path.open("rb") as handle:
        for raw_line, too_long in _bounded_lines(handle):
            if too_long:
                record_index += 1
                _check_limits(record_index, limits, started)
                yield ParsedRecord(error_code="line_too_long")
                continue
            try:
                line = raw_line.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                record_index += 1
                _check_limits(record_index, limits, started)
                yield ParsedRecord(error_code="invalid_record")
                continue
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            record_index += 1
            _check_limits(record_index, limits, started)
            try:
                if line.startswith("{"):
                    value = json.loads(line)
                else:
                    if fields is None:
                        raise ValueError("missing fields")
                    values = line.split("\t")
                    if len(values) != len(fields):
                        raise ValueError("field mismatch")
                    value = dict(zip(fields, values, strict=True))
                if not isinstance(value, dict):
                    raise ValueError
                yield ParsedRecord(flow=_normalize_zeek(value))
            except (
                json.JSONDecodeError,
                KeyError,
                ValidationError,
                ValueError,
                TypeError,
                OverflowError,
                OSError,
            ):
                yield ParsedRecord(error_code="invalid_record")


def _normalize_suricata(value: dict[str, Any]) -> CanonicalFlowV1:
    if value.get("event_type") != "flow" or not isinstance(value.get("flow"), dict):
        raise ValueError("unsupported event type")
    flow = value["flow"]
    packet_count = _integer(flow.get("pkts_toserver")) + _integer(flow.get("pkts_toclient"))
    byte_count = _integer(flow.get("bytes_toserver")) + _integer(flow.get("bytes_toclient"))
    start = _parse_timestamp(flow.get("start", value["timestamp"]))
    end = _parse_timestamp(flow.get("end", value["timestamp"]))
    return CanonicalFlowV1(
        source_type="suricata",
        source_event_id=str(value["flow_id"]),
        event_time=_parse_timestamp(value["timestamp"]),
        src_address=str(value["src_ip"]),
        dst_address=str(value["dest_ip"]),
        src_port=_integer(value.get("src_port")),
        dst_port=_integer(value.get("dest_port")),
        protocol=str(value["proto"]).lower(),
        duration_ms=max(0, round((end - start).total_seconds() * 1000)),
        packet_count=packet_count,
        byte_count=byte_count,
        state=str(flow["state"]) if flow.get("state") else None,
        metadata={"app_proto": str(value["app_proto"])} if value.get("app_proto") else {},
    )


@dataclass
class _PcapAggregate:
    first: float
    last: float
    packets: int
    octets: int


def _pcap_reader(handle: BinaryIO) -> Any:
    magic = handle.read(4)
    handle.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(handle)
    return dpkt.pcap.Reader(handle)


def _packet_tuple(packet: bytes) -> tuple[str, str, int | None, int | None, str] | None:
    ethernet = dpkt.ethernet.Ethernet(packet)
    network = ethernet.data
    if isinstance(network, dpkt.ip.IP):
        src = socket.inet_ntop(socket.AF_INET, network.src)
        dst = socket.inet_ntop(socket.AF_INET, network.dst)
    elif isinstance(network, dpkt.ip6.IP6):
        src = socket.inet_ntop(socket.AF_INET6, network.src)
        dst = socket.inet_ntop(socket.AF_INET6, network.dst)
    else:
        return None
    transport = network.data
    if isinstance(transport, dpkt.tcp.TCP):
        return src, dst, transport.sport, transport.dport, "tcp"
    if isinstance(transport, dpkt.udp.UDP):
        return src, dst, transport.sport, transport.dport, "udp"
    if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        return src, dst, None, None, "icmp"
    return src, dst, None, None, "other"


def _parse_pcap(path: Path, limits: ParseLimits, started: float) -> Iterator[ParsedRecord]:
    aggregates: dict[tuple[str, str, int | None, int | None, str], _PcapAggregate] = {}
    rejected = 0
    try:
        with path.open("rb") as handle:
            reader = _pcap_reader(handle)
            for index, (timestamp, packet) in enumerate(reader, start=1):
                _check_limits(index, limits, started)
                if not math.isfinite(float(timestamp)):
                    rejected += 1
                    continue
                try:
                    key = _packet_tuple(packet)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
                    rejected += 1
                    continue
                if key is None:
                    rejected += 1
                    continue
                item = aggregates.get(key)
                if item is None:
                    if len(aggregates) >= limits.max_unique_flows:
                        raise FatalIngestionError("unique_flow_limit_exceeded")
                    aggregates[key] = _PcapAggregate(timestamp, timestamp, 1, len(packet))
                else:
                    item.first = min(item.first, timestamp)
                    item.last = max(item.last, timestamp)
                    item.packets += 1
                    item.octets += len(packet)
    except FatalIngestionError:
        raise
    except (OSError, ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as error:
        raise FatalIngestionError("invalid_pcap") from error

    for _ in range(rejected):
        yield ParsedRecord(error_code="unsupported_packet")
    for key in sorted(
        aggregates, key=lambda item: tuple("" if value is None else str(value) for value in item)
    ):
        src, dst, src_port, dst_port, protocol = key
        item = aggregates[key]
        yield ParsedRecord(
            flow=CanonicalFlowV1(
                source_type="pcap",
                event_time=datetime.fromtimestamp(item.first, tz=UTC),
                src_address=src,
                dst_address=dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                duration_ms=max(0, round((item.last - item.first) * 1000)),
                packet_count=item.packets,
                byte_count=item.octets,
            )
        )
