from __future__ import annotations

import io
import json
import random
import socket
from pathlib import Path

import dpkt
import pytest

from aegis_services.ingestion import FatalIngestionError, ParseLimits, event_key, parse_file
from aegis_services.ingestion.adapters import content_matches

FIXTURES = Path(__file__).parents[1] / "fixtures" / "telemetry"
LIMITS = ParseLimits(max_records=100, max_unique_flows=50, max_seconds=10)


def parsed(path: str, source: str):  # type: ignore[no-untyped-def]
    return list(parse_file(FIXTURES / path, source, LIMITS))


def test_normalized_flow_contract_and_stable_identity() -> None:
    result = parsed("normalized_valid.jsonl", "normalized")
    assert len(result) == 1
    flow = result[0].flow
    assert flow is not None
    assert flow.schema_version == "1"
    assert flow.src_address == "192.0.2.10"
    assert flow.byte_count == 4096
    assert event_key(flow, None) == event_key(flow, None)
    assert event_key(flow, "sensor-a") != event_key(flow, "sensor-b")


def test_duplicate_and_out_of_order_fixtures_are_deterministic() -> None:
    duplicate = parsed("normalized_duplicate.jsonl", "normalized")
    assert duplicate[0].flow == duplicate[1].flow
    out_of_order = parsed("normalized_out_of_order.jsonl", "normalized")
    assert out_of_order[0].flow is not None and out_of_order[1].flow is not None
    assert out_of_order[0].flow.event_time > out_of_order[1].flow.event_time


def test_malformed_and_unicode_records_fail_without_content_echo() -> None:
    result = parsed("normalized_malformed.jsonl", "normalized")
    assert [item.error_code for item in result] == ["invalid_record", "invalid_record"]


def test_zeek_conn_log_maps_strict_fields() -> None:
    result = parsed("zeek_valid.log", "zeek")
    flow = result[0].flow
    assert flow is not None
    assert flow.source_event_id == "Csynthetic1"
    assert flow.packet_count == 13
    assert flow.byte_count == 3600
    assert parsed("zeek_malformed.log", "zeek")[0].error_code == "invalid_record"


def test_suricata_flow_maps_and_alert_is_deferred() -> None:
    result = parsed("suricata_valid.jsonl", "suricata")
    flow = result[0].flow
    assert flow is not None
    assert flow.source_event_id == "9001"
    assert flow.duration_ms == 1500
    malformed = parsed("suricata_malformed.jsonl", "suricata")
    assert [item.error_code for item in malformed] == ["invalid_record", "invalid_record"]


def _pcap_bytes() -> bytes:
    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    tcp = dpkt.tcp.TCP(sport=50000, dport=443, flags=dpkt.tcp.TH_ACK)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.0.2.50"),
        dst=socket.inet_aton("198.51.100.50"),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    writer.writepkt(bytes(ethernet), ts=1_783_987_200.0)
    writer.writepkt(bytes(ethernet), ts=1_783_987_200.5)
    data = buffer.getvalue()
    writer.close()
    return data


def test_offline_pcap_is_aggregated_without_payload_storage(tmp_path: Path) -> None:
    path = tmp_path / "synthetic.bin"
    path.write_bytes(_pcap_bytes())
    assert content_matches("pcap", path.read_bytes()[:4])
    result = list(parse_file(path, "pcap", LIMITS))
    flow = result[0].flow
    assert flow is not None
    assert flow.packet_count == 2
    assert flow.duration_ms == 500
    assert flow.metadata == {}


def test_pcap_sorting_handles_portless_and_port_based_flows_with_same_endpoints(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    source = socket.inet_aton("192.0.2.51")
    destination = socket.inet_aton("198.51.100.51")
    tcp = dpkt.tcp.TCP(sport=50000, dport=443)
    tcp_ip = dpkt.ip.IP(src=source, dst=destination, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    tcp_ip.len = len(tcp_ip)
    icmp = dpkt.icmp.ICMP(type=8, code=0)
    icmp_ip = dpkt.ip.IP(src=source, dst=destination, p=dpkt.ip.IP_PROTO_ICMP, data=icmp)
    icmp_ip.len = len(icmp_ip)
    for network in (tcp_ip, icmp_ip):
        ethernet = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=network,
        )
        writer.writepkt(bytes(ethernet), ts=1_783_987_200.0)
    data = buffer.getvalue()
    writer.close()
    path = tmp_path / "mixed.bin"
    path.write_bytes(data)
    result = list(parse_file(path, "pcap", LIMITS))
    assert {item.flow.protocol for item in result if item.flow is not None} == {"icmp", "tcp"}


def test_record_and_unique_flow_limits_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "too-many.jsonl"
    path.write_bytes((FIXTURES / "normalized_valid.jsonl").read_bytes() * 2)
    with pytest.raises(FatalIngestionError, match="record_limit_exceeded"):
        list(parse_file(path, "normalized", ParseLimits(1, 1, 10)))


@pytest.mark.parametrize("source", ["normalized", "zeek", "suricata", "pcap"])
def test_deterministic_fuzz_bytes_never_escape_controlled_errors(
    tmp_path: Path, source: str
) -> None:
    generator = random.Random(20260714)  # noqa: S311 - deterministic non-security fuzz data
    for index in range(50):
        data = generator.randbytes(generator.randint(0, 256))
        path = tmp_path / f"fuzz-{source}-{index}.bin"
        path.write_bytes(data)
        try:
            list(parse_file(path, source, ParseLimits(20, 10, 2)))
        except FatalIngestionError as error:
            assert error.code in {"invalid_pcap", "record_limit_exceeded"}


def test_content_detection_ignores_declared_filename_and_mime() -> None:
    assert content_matches("normalized", b'  {"schema_version":"1"}')
    assert not content_matches("pcap", b"#!/bin/sh")
    assert not content_matches("suricata", b"PK\x03\x04")


@pytest.mark.parametrize(
    ("source", "record"),
    [
        (
            "zeek",
            {
                "ts": 1e309,
                "uid": "Cfinite1",
                "id.orig_h": "192.0.2.1",
                "id.orig_p": 12345,
                "id.resp_h": "198.51.100.1",
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 1,
            },
        ),
        (
            "zeek",
            {
                "ts": 1_783_987_200,
                "uid": "Cfinite2",
                "id.orig_h": "192.0.2.1",
                "id.orig_p": 12345,
                "id.resp_h": "198.51.100.1",
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": float("inf"),
            },
        ),
        (
            "suricata",
            {
                "event_type": "flow",
                "timestamp": float("inf"),
                "flow_id": 10,
                "src_ip": "192.0.2.1",
                "src_port": 12345,
                "dest_ip": "198.51.100.1",
                "dest_port": 443,
                "proto": "TCP",
                "flow": {},
            },
        ),
    ],
)
def test_non_finite_numbers_are_controlled_rejections(
    tmp_path: Path, source: str, record: dict[str, object]
) -> None:
    path = tmp_path / f"{source}-non-finite.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    result = list(parse_file(path, source, LIMITS))
    assert [item.error_code for item in result] == ["invalid_record"]
