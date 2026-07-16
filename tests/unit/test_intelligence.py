from datetime import UTC, datetime

import pytest

from aegis_services.intelligence import (
    INTELLIGENCE_LIMITATIONS,
    IndicatorType,
    MatchState,
    bundled_indicators,
    bundled_intelligence_source,
    bundled_mitre_catalog,
    bundled_mitre_mappings,
    bundled_observations,
    hash_value,
    match_indicators,
    normalize_value,
)
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

_NOW = datetime(2026, 7, 15, tzinfo=UTC)


def test_source_and_indicators_are_synthetic_only() -> None:
    source = bundled_intelligence_source()
    assert source.external_lookup_used is False
    assert source.real_feed_used is False
    assert SYNTHETIC_LIMITATIONS in source.limitations
    assert source.limitations == INTELLIGENCE_LIMITATIONS
    for indicator in bundled_indicators():
        assert indicator.enforcement_authority is False
        assert indicator.prevention_allowed is False
        # Only a normalized hash is stored, never a raw value.
        assert len(indicator.value_hash) == 64


def test_normalization_canonicalizes_and_rejects_bad_values() -> None:
    assert normalize_value(IndicatorType.IPV4, " 192.0.2.10 ") == "192.0.2.10"
    assert normalize_value(IndicatorType.DOMAIN, "Malicious.Example.INVALID.") == (
        "malicious.example.invalid"
    )
    assert normalize_value(IndicatorType.IPV6, "2001:DB8::1") == "2001:db8::1"
    for bad in ("", "not-an-ip", "999.999.999.999"):
        with pytest.raises(ValueError, match="invalid"):
            normalize_value(IndicatorType.IPV4, bad)
    with pytest.raises(ValueError, match="invalid"):
        normalize_value(IndicatorType.SHA256, "xyz")


def test_matching_marks_active_expired_and_no_authority() -> None:
    matches = match_indicators(bundled_indicators(), bundled_observations(), now=_NOW)
    by_state = {match.state for match in matches}
    assert MatchState.ACTIVE in by_state
    assert MatchState.EXPIRED in by_state  # the stale 203.0.113.7 indicator
    assert all(match.confers_authority is False for match in matches)
    assert all(match.prevention_allowed is False for match in matches)
    # The non-intersecting observation (192.0.2.200) produces no match.
    assert len(matches) == 3


def test_expired_indicator_never_active() -> None:
    matches = match_indicators(bundled_indicators(), bundled_observations(), now=_NOW)
    stale = [m for m in matches if m.state is MatchState.EXPIRED]
    assert stale, "expected the stale indicator to match as expired"
    assert all(m.confers_authority is False for m in stale)


def test_allowlist_conflict_overrides_active() -> None:
    allowlisted = frozenset({hash_value(IndicatorType.IPV4, "192.0.2.10")})
    matches = match_indicators(
        bundled_indicators(),
        bundled_observations(),
        now=_NOW,
        allowlist_value_hashes=allowlisted,
    )
    conflicts = [m for m in matches if m.state is MatchState.ALLOWLIST_CONFLICT]
    assert len(conflicts) == 1
    assert conflicts[0].confers_authority is False


def test_indicator_timeline_is_validated() -> None:
    from aegis_services.intelligence import IndicatorV1

    with pytest.raises(ValueError, match="expiry_not_after"):
        IndicatorV1(
            indicator_type=IndicatorType.IPV4,
            value_hash="a" * 64,
            source_name="aegis-synthetic-intel",
            confidence=0.5,
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2025, 1, 1, tzinfo=UTC),
        )


def test_mitre_catalog_and_mappings_are_qualified() -> None:
    catalog = bundled_mitre_catalog()
    assert catalog.catalog_hash == bundled_mitre_catalog().catalog_hash
    mappings = bundled_mitre_mappings(catalog)
    assert mappings
    for mapping in mappings:
        assert mapping.qualified is True
        assert mapping.catalog_hash == catalog.catalog_hash
        assert mapping.prevention_allowed is False


def test_match_now_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="aware"):
        match_indicators(bundled_indicators(), bundled_observations(), now=datetime(2026, 7, 15))
