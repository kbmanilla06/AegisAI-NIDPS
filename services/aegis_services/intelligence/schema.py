from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis_services.features import canonical_hash
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

# Sprint 7 threat intelligence is bundled/synthetic and offline; extend the
# mandatory synthetic limitation with the no-real-feed / no-lookup clause (PRIV-004).
INTELLIGENCE_LIMITATIONS = (
    SYNTHETIC_LIMITATIONS
    + " Threat-intelligence indicators and MITRE mappings are synthetic or bundled "
    "fixtures, not real feeds or live lookups. No external lookup is performed."
)


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class MatchState(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    ALLOWLIST_CONFLICT = "allowlist_conflict"


class IntelligenceSourceV1(BaseModel):
    """Immutable description of a bundled/synthetic indicator source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["intelligence-source/v1"] = "intelligence-source/v1"
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    trust_level: Literal["low", "medium", "high"]
    terms_reference_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    enabled: bool = True
    bundled_fixture: Literal[True] = True
    external_lookup_used: Literal[False] = False
    limitations: str = INTELLIGENCE_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_feed_used: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @property
    def source_hash(self) -> str:
        return canonical_hash(self)


class IndicatorV1(BaseModel):
    """Immutable indicator; sensitive values are stored only as normalized hashes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["indicator/v1"] = "indicator/v1"
    indicator_type: IndicatorType
    # PRIV-004: the raw value is never stored; only a normalized SHA-256 hash.
    value_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime
    # Intelligence is never enforcement authority (TM-13, PREV-006).
    enforcement_authority: Literal[False] = False
    limitations: str = INTELLIGENCE_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_feed_used: Literal[False] = False
    online_inference_allowed: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_timeline(self) -> IndicatorV1:
        if not (
            self.first_seen.tzinfo is not None
            and self.last_seen.tzinfo is not None
            and self.expires_at.tzinfo is not None
        ):
            raise ValueError("indicator_timestamps_must_be_aware")
        if self.last_seen < self.first_seen:
            raise ValueError("indicator_last_seen_before_first_seen")
        if self.expires_at <= self.first_seen:
            raise ValueError("indicator_expiry_not_after_first_seen")
        return self

    @property
    def indicator_hash(self) -> str:
        return canonical_hash(self)

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class IndicatorMatchV1(BaseModel):
    """Metadata-only offline match; never creates or mutates an alert."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["indicator-match/v1"] = "indicator-match/v1"
    match_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    indicator_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    # Restricted provenance only: a synthetic observation hash, never an endpoint.
    provenance_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    matched_at: datetime
    state: MatchState
    confers_authority: Literal[False] = False
    limitations: str = INTELLIGENCE_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    real_feed_used: Literal[False] = False
    alert_side_effects_allowed: Literal[False] = False
    prevention_allowed: Literal[False] = False


class MitreTechniqueV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["mitre-technique/v1"] = "mitre-technique/v1"
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1, max_length=128)
    tactic: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")


class MitreTechniqueCatalogV1(BaseModel):
    """Bundled, immutable ATT&CK technique catalog; no live ATT&CK fetch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["mitre-technique-catalog/v1"] = "mitre-technique-catalog/v1"
    catalog_version: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    techniques: tuple[MitreTechniqueV1, ...] = Field(min_length=1, max_length=256)
    bundled_fixture: Literal[True] = True
    external_lookup_used: Literal[False] = False

    @model_validator(mode="after")
    def validate_unique(self) -> MitreTechniqueCatalogV1:
        ids = [item.technique_id for item in self.techniques]
        if len(ids) != len(set(ids)):
            raise ValueError("mitre_catalog_duplicate_technique")
        return self

    @property
    def catalog_hash(self) -> str:
        return canonical_hash(self)


class MitreMappingV1(BaseModel):
    """Qualified mapping from a deterministic evidence class to a technique."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["mitre-mapping/v1"] = "mitre-mapping/v1"
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    evidence_class: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    catalog_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    rationale: str = Field(min_length=1, max_length=256)
    mapping_version: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    confidence: Literal["low", "medium", "high"]
    # A mapping indicates a technique; it never proves adversary intent (DET-006).
    qualified: Literal[True] = True
    limitations: str = INTELLIGENCE_LIMITATIONS
    synthetic_demo_only: Literal[True] = True
    prevention_allowed: Literal[False] = False

    @property
    def mapping_hash(self) -> str:
        return canonical_hash(self)
