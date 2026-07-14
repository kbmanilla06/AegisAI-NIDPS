from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegis_services.detection import DEFAULT_RULES, FlowRecord, canonical_hash, evaluate_rule
from aegis_services.detection.rules import bucket_start
from aegis_services.ingestion import ParseLimits, parse_file

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"


def _flow(
    index: int,
    *,
    port: int = 443,
    state: str | None = None,
    source_type: str = "normalized",
    second: int = 1,
) -> FlowRecord:
    return FlowRecord(
        event_key=f"{index:064x}",
        source_type=source_type,
        sensor_id=None,
        event_time=datetime(2026, 7, 14, 0, 0, second, tzinfo=UTC),
        src_address="192.0.2.10",
        dst_address="198.51.100.10",
        src_port=50_000 + index,
        dst_port=port,
        protocol="tcp",
        byte_count=100,
        state=state,
    )


def test_port_scan_is_deterministic_at_threshold_and_deduplicates_evidence() -> None:
    rule = replace(DEFAULT_RULES[0], parameters={"threshold": 3, "excluded_asset_ids": []})
    flows = [_flow(1, port=20), _flow(2, port=21), _flow(3, port=22), _flow(3, port=22)]
    matches = evaluate_rule(rule, flows)
    assert len(matches) == 1
    assert matches[0].observed_value == 3
    assert len(matches[0].evidence_event_keys) == 3
    assert evaluate_rule(rule, flows) == matches
    assert evaluate_rule(rule, flows[:2]) == []


def test_repeated_failure_counts_only_recognized_zeek_states() -> None:
    rule = replace(
        DEFAULT_RULES[1],
        parameters={
            "threshold": 3,
            "excluded_asset_ids": [],
            "failure_states": ["REJ", "S0"],
        },
    )
    flows = [
        _flow(1, state="REJ", source_type="zeek"),
        _flow(2, state="S0", source_type="zeek"),
        _flow(3, state="REJ", source_type="zeek"),
        _flow(4, state="REJ", source_type="normalized"),
        _flow(5, state="UNKNOWN", source_type="zeek"),
    ]
    matches = evaluate_rule(rule, flows)
    assert len(matches) == 1
    assert matches[0].observed_value == 3


def test_high_rate_honors_excluded_source_and_bucket_boundaries() -> None:
    rule = replace(DEFAULT_RULES[2], parameters={"threshold": 3, "excluded_asset_ids": []})
    flows = [_flow(1), _flow(2), _flow(3)]
    assert len(evaluate_rule(rule, flows)) == 1
    assert evaluate_rule(rule, flows, excluded_sources=frozenset({"192.0.2.10"})) == []
    boundary = replace(flows[2], event_time=flows[2].event_time + timedelta(seconds=60))
    assert evaluate_rule(rule, [flows[0], flows[1], boundary]) == []
    assert bucket_start(boundary.event_time, 60) != bucket_start(flows[0].event_time, 60)


def test_suricata_alert_contract_accepts_bounded_metadata_and_rejects_malformed() -> None:
    limits = ParseLimits(100, 50, 10)
    valid = list(parse_file(FIXTURES / "suricata_alert_valid.jsonl", "suricata", limits))
    assert valid[0].signature is not None
    assert valid[0].signature.signature_id == 2_100_001
    assert valid[0].flow is None
    malformed = list(parse_file(FIXTURES / "suricata_alert_malformed.jsonl", "suricata", limits))
    assert [item.error_code for item in malformed] == ["invalid_record", "invalid_record"]


def test_canonical_hash_is_order_independent_and_version_inputs_change_it() -> None:
    assert canonical_hash({"b": 2, "a": 1}) == canonical_hash({"a": 1, "b": 2})
    assert canonical_hash({"version": 1}) != canonical_hash({"version": 2})
