from __future__ import annotations

from datetime import UTC, datetime

from aegis_services.features import canonical_hash

from .matching import SyntheticObservation, hash_value
from .schema import (
    IndicatorType,
    IndicatorV1,
    IntelligenceSourceV1,
    MitreMappingV1,
    MitreTechniqueCatalogV1,
    MitreTechniqueV1,
)

_SOURCE_NAME = "aegis-synthetic-intel"
_FIRST_SEEN = datetime(2026, 1, 1, tzinfo=UTC)
_LAST_SEEN = datetime(2026, 6, 1, tzinfo=UTC)
_ACTIVE_EXPIRY = datetime(2026, 12, 31, tzinfo=UTC)
_STALE_EXPIRY = datetime(2026, 2, 1, tzinfo=UTC)

# Documentation / TEST-NET ranges only (RFC 5737 / RFC 3849 / .invalid).
_RAW_INDICATORS: tuple[tuple[IndicatorType, str, bool], ...] = (
    (IndicatorType.IPV4, "192.0.2.10", True),
    (IndicatorType.IPV4, "198.51.100.23", True),
    (IndicatorType.IPV4, "203.0.113.7", False),  # intentionally stale
    (IndicatorType.IPV6, "2001:db8::1", True),
    (IndicatorType.DOMAIN, "malicious.example.invalid", True),
    (IndicatorType.URL, "http://beacon.example.invalid/c2", True),
    (IndicatorType.SHA256, "a" * 64, True),
)


def bundled_intelligence_source() -> IntelligenceSourceV1:
    return IntelligenceSourceV1(
        name=_SOURCE_NAME,
        trust_level="medium",
        terms_reference_hash=canonical_hash("aegis-synthetic-intelligence-terms/v1"),
    )


def bundled_indicators() -> tuple[IndicatorV1, ...]:
    indicators: list[IndicatorV1] = []
    for indicator_type, raw, active in _RAW_INDICATORS:
        indicators.append(
            IndicatorV1(
                indicator_type=indicator_type,
                value_hash=hash_value(indicator_type, raw),
                source_name=_SOURCE_NAME,
                confidence=0.7,
                first_seen=_FIRST_SEEN,
                last_seen=_LAST_SEEN,
                expires_at=_ACTIVE_EXPIRY if active else _STALE_EXPIRY,
            )
        )
    return tuple(indicators)


def bundled_observations() -> tuple[SyntheticObservation, ...]:
    """Synthetic observations; some intersect indicators, some do not."""
    return (
        SyntheticObservation(IndicatorType.IPV4, "192.0.2.10", canonical_hash("obs-1")),
        SyntheticObservation(IndicatorType.IPV4, "203.0.113.7", canonical_hash("obs-2")),
        SyntheticObservation(
            IndicatorType.DOMAIN, "malicious.example.invalid", canonical_hash("obs-3")
        ),
        SyntheticObservation(
            IndicatorType.IPV4, "192.0.2.200", canonical_hash("obs-4")
        ),  # no match
    )


def bundled_mitre_catalog() -> MitreTechniqueCatalogV1:
    return MitreTechniqueCatalogV1(
        catalog_version="2026-01-01",
        techniques=(
            MitreTechniqueV1(
                technique_id="T1046", name="Network Service Discovery", tactic="discovery"
            ),
            MitreTechniqueV1(technique_id="T1110", name="Brute Force", tactic="credential-access"),
            MitreTechniqueV1(technique_id="T1595", name="Active Scanning", tactic="reconnaissance"),
        ),
    )


def bundled_mitre_mappings(catalog: MitreTechniqueCatalogV1) -> tuple[MitreMappingV1, ...]:
    catalog_hash = catalog.catalog_hash
    return (
        MitreMappingV1(
            technique_id="T1046",
            evidence_class="port_scan",
            catalog_hash=catalog_hash,
            rationale="Many distinct destination ports from one source is associated with "
            "service discovery.",
            mapping_version="2026-01-01",
            confidence="medium",
        ),
        MitreMappingV1(
            technique_id="T1110",
            evidence_class="repeated_failures",
            catalog_hash=catalog_hash,
            rationale="Repeated connection failures to one service are associated with "
            "brute-force behavior.",
            mapping_version="2026-01-01",
            confidence="low",
        ),
    )
