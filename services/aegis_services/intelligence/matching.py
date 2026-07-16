from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from .schema import IndicatorMatchV1, IndicatorType, IndicatorV1, MatchState

_MAX_OBSERVATIONS = 10_000


@dataclass(frozen=True)
class SyntheticObservation:
    """A synthetic, documentation-range observation matched offline.

    ``provenance_hash`` is an opaque synthetic identity hash, never an endpoint.
    """

    indicator_type: IndicatorType
    raw_value: str
    provenance_hash: str


def normalize_value(indicator_type: IndicatorType, raw: str) -> str:
    value = raw.strip()
    if not value or len(value) > 2048:
        raise ValueError("indicator_value_invalid")
    if indicator_type in {IndicatorType.IPV4, IndicatorType.IPV6}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("indicator_value_invalid") from error
        expected = 4 if indicator_type is IndicatorType.IPV4 else 6
        if address.version != expected:
            raise ValueError("indicator_value_invalid")
        return address.compressed
    if indicator_type is IndicatorType.DOMAIN:
        domain = value.lower().rstrip(".")
        if not domain or any(character.isspace() for character in domain) or "/" in domain:
            raise ValueError("indicator_value_invalid")
        return domain
    if indicator_type is IndicatorType.URL:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("indicator_value_invalid")
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{parsed.path}"
    digest = value.lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("indicator_value_invalid")
    return digest


def hash_value(indicator_type: IndicatorType, raw: str) -> str:
    normalized = normalize_value(indicator_type, raw)
    return hashlib.sha256(f"{indicator_type.value}:{normalized}".encode()).hexdigest()


def match_indicators(
    indicators: Sequence[IndicatorV1],
    observations: Sequence[SyntheticObservation],
    *,
    now: datetime,
    allowlist_value_hashes: frozenset[str] = frozenset(),
) -> tuple[IndicatorMatchV1, ...]:
    """Deterministically match indicators against synthetic observations.

    Expired indicators produce ``expired`` matches that confer no authority;
    allowlisted values produce ``allowlist_conflict`` matches (TM-13, TM-16).
    No alert, incident, or prevention record is created.
    """
    if now.tzinfo is None:
        raise ValueError("match_now_must_be_aware")
    if len(observations) > _MAX_OBSERVATIONS:
        raise ValueError("intelligence_resource_limit")
    index: dict[tuple[IndicatorType, str], list[IndicatorV1]] = {}
    for indicator in indicators:
        index.setdefault((indicator.indicator_type, indicator.value_hash), []).append(indicator)

    matches: list[IndicatorMatchV1] = []
    for observation in observations:
        observed_hash = hash_value(observation.indicator_type, observation.raw_value)
        candidates = index.get((observation.indicator_type, observed_hash), [])
        for indicator in candidates:
            if observed_hash in allowlist_value_hashes:
                state = MatchState.ALLOWLIST_CONFLICT
            elif indicator.is_expired(now):
                state = MatchState.EXPIRED
            else:
                state = MatchState.ACTIVE
            match_id = hashlib.sha256(
                f"{indicator.indicator_hash}:{observation.provenance_hash}".encode()
            ).hexdigest()
            matches.append(
                IndicatorMatchV1(
                    match_id=match_id,
                    indicator_hash=indicator.indicator_hash,
                    source_name=indicator.source_name,
                    provenance_hash=observation.provenance_hash,
                    matched_at=now,
                    state=state,
                )
            )
    return tuple(matches)
