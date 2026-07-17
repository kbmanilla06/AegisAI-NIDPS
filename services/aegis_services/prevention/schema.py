from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from enum import StrEnum
from typing import Literal

from aegis_services.soc import SOC_LIMITATIONS

# Sprint 9 prevention is a policy-gated *simulation* over synthetic evidence. This
# limitation extends the SOC/synthetic chain with the explicit no-enforcement clause
# and MUST be carried, verbatim, on every prevention surface (PREV-001/007/008).
PREVENTION_LIMITATIONS = (
    "SIMULATION ONLY. Prevention in this system is a policy-gated simulation over "
    "synthetic evidence. It previews and records what a defensive action WOULD be, "
    "never performs one: no firewall, network, host, or traffic change occurs, and OS "
    "firewall state is unchanged. Alerts, incidents, models, and intelligence are "
    "evidence, never enforcement authority. Real or lab enforcement is a separately "
    "authorized later sprint and is not present. "
) + SOC_LIMITATIONS

# The prevention simulation runs in exactly one mode. There is no real adapter, no
# approval mode, and no execution mode; the literal is pinned so a check constraint,
# a schema, and a test can all assert the same single value.
SIMULATION_MODE: Literal["simulation"] = "simulation"
SIMULATION_ADAPTER = "simulation"

# Machine-readable false-capability flags emitted alongside the limitation text so a
# consumer never has to parse prose to learn the system cannot enforce.
FALSE_CAPABILITY_FLAGS: dict[str, bool] = {
    "real_prevention": False,
    "firewall_change": False,
    "network_change": False,
    "host_state_change": False,
    "packet_block": False,
    "enforcement_authority": False,
    "automatic_action": False,
    "permanent_action": False,
}


class PreventionActionType(StrEnum):
    """Canonical, temporary-only simulated actions. No permanent action exists."""

    TEMPORARY_BLOCK = "temporary_block"
    TEMPORARY_RATE_LIMIT = "temporary_rate_limit"
    TEMPORARY_QUARANTINE_TAG = "temporary_quarantine_tag"


class PreventionTargetType(StrEnum):
    """Canonical supported target kinds; arbitrary command/path input is not one."""

    EXTERNAL_IP = "external_ip"
    INTERNAL_IP = "internal_ip"
    EXTERNAL_DOMAIN = "external_domain"


class TargetScope(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class PreventionRequestStatus(StrEnum):
    DRAFT = "draft"
    EVALUATED = "evaluated"
    REJECTED = "rejected"
    PREVIEWED = "previewed"
    SIMULATED = "simulated"
    EXPIRED = "expired"
    ROLLED_BACK = "rolled_back"


class PolicyLifecycle(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    RETIRED = "retired"


# Deterministic scope classification. Anything outside the canonical target kinds is
# UNKNOWN, which the internal/external gate fails closed (PREV target validity).
_SCOPE_BY_TARGET_TYPE: dict[str, TargetScope] = {
    PreventionTargetType.EXTERNAL_IP: TargetScope.EXTERNAL,
    PreventionTargetType.EXTERNAL_DOMAIN: TargetScope.EXTERNAL,
    PreventionTargetType.INTERNAL_IP: TargetScope.INTERNAL,
}

# Conservative hostname grammar: labels of unreserved DNS characters only. Anything
# with whitespace, shell metacharacters, slashes, or control bytes is rejected, so a
# target value can never smuggle an executable string past target validation.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})+$")

# Explicit internal (non-routable) blocks. We classify internal directly rather than
# via ``is_private``, whose meaning shifted across Python versions to include
# documentation ranges — exactly the synthetic examples a demo should treat as
# external. Loopback/link-local/RFC1918/ULA are internal; everything else external.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(block)
    for block in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _is_internal_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in _INTERNAL_NETWORKS)


def target_scope(target_type: str) -> TargetScope:
    return _SCOPE_BY_TARGET_TYPE.get(target_type, TargetScope.UNKNOWN)


def is_valid_target(target_type: str, value: str) -> bool:
    """True only for a canonical, well-formed target value (no arbitrary input).

    Pure and total: rejects unknown target kinds, malformed literals, and any value
    whose address class contradicts its declared internal/external kind.
    """
    if not value or len(value) > 253 or value != value.strip():
        return False
    try:
        kind = PreventionTargetType(target_type)
    except ValueError:
        return False
    if kind is PreventionTargetType.EXTERNAL_DOMAIN:
        return bool(_HOSTNAME.match(value))
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified:
        return False
    internal = _is_internal_address(address)
    if kind is PreventionTargetType.INTERNAL_IP:
        return internal
    return not internal  # EXTERNAL_IP must be outside the non-routable blocks.


def canonical_policy_hash(definition: dict[str, object]) -> str:
    """SHA-256 over the canonical JSON of an immutable policy definition."""
    payload = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
