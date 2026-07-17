from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

from .schema import (
    FALSE_CAPABILITY_FLAGS,
    PREVENTION_LIMITATIONS,
    SIMULATION_ADAPTER,
    SIMULATION_MODE,
)

# Tokens that would indicate an executable string leaked into a "preview". The
# representation is data only; if any of these ever appears, the preview builder and
# its tests fail closed (a Critical defect per the safety model).
_EXECUTABLE_MARKERS = re.compile(
    r"(iptables|nftables|\bnft\b|\bpfctl\b|/bin/|/sbin/|subprocess|os\.system|"
    r"\bsudo\b|\bsh -c\b|\bcurl\b|\bnc\b|;|\||&&|`|\$\()",
    re.IGNORECASE,
)


class ExecutableRepresentationError(RuntimeError):
    """Raised if a preview representation contains an executable-looking string."""


def contains_executable_string(value: Any) -> bool:
    """Recursively scan a JSON-like structure for executable-command markers."""
    if isinstance(value, str):
        return bool(_EXECUTABLE_MARKERS.search(value))
    if isinstance(value, dict):
        return any(contains_executable_string(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_executable_string(item) for item in value)
    return False


@dataclass(frozen=True)
class PreventionPreview:
    """Typed proposal previewed by the simulation adapter (data only)."""

    request_id: UUID
    mode: Literal["simulation"]
    action_type: str
    target_type: str
    target_display: str
    duration_seconds: int
    rollback_summary: str

    def representation(self) -> dict[str, Any]:
        """A safe, structured description of what WOULD occur — never a command.

        The ``executable_command`` field is explicitly ``None`` to make the contract
        legible: there is no command, ever. The result is validated before return.
        """
        representation: dict[str, Any] = {
            "kind": "prevention_simulation_preview",
            "adapter": SIMULATION_ADAPTER,
            "mode": self.mode,
            "action_type": self.action_type,
            "target": {"type": self.target_type, "display": self.target_display},
            "duration_seconds": self.duration_seconds,
            "would_perform": (
                "A temporary, reversible action WOULD be simulated for the stated "
                "duration. No firewall, packet, routing, host, or network change occurs."
            ),
            "rollback": {"summary": self.rollback_summary, "automatic_on_expiry": True},
            "executable_command": None,
            "network_call": None,
            "limitations": PREVENTION_LIMITATIONS,
            "false_capability_flags": dict(FALSE_CAPABILITY_FLAGS),
        }
        if contains_executable_string(
            {key: value for key, value in representation.items() if key != "limitations"}
        ):
            raise ExecutableRepresentationError("preview_representation_not_data_only")
        return representation


@dataclass(frozen=True)
class NoEnforcementEvidence:
    """Per-execution proof that no real side-effect path was reachable."""

    adapter: str
    real_side_effect_invoked: bool
    outbound_socket_opened: bool
    firewall_state_changed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "real_side_effect_invoked": self.real_side_effect_invoked,
            "outbound_socket_opened": self.outbound_socket_opened,
            "firewall_state_changed": self.firewall_state_changed,
        }


class SimulationAdapter(Protocol):
    """Data-only contract. Implementations MUST NOT perform OS or network actions."""

    name: str

    def validate(self, preview: PreventionPreview) -> bool: ...

    def preview(self, preview: PreventionPreview) -> dict[str, Any]: ...

    def execute(self, preview: PreventionPreview) -> dict[str, Any]: ...

    def verify(self, request_id: UUID) -> NoEnforcementEvidence: ...

    def rollback(self, execution_id: UUID) -> dict[str, Any]: ...


class SimulationPreventionAdapter:
    """The one and only adapter. It records data; it never touches OS or network.

    Every method is pure with respect to the outside world: no sockets are opened,
    no subprocess is spawned, no firewall/host state is read or written. ``verify``
    reports that fact as structured evidence.
    """

    name = SIMULATION_ADAPTER

    def validate(self, preview: PreventionPreview) -> bool:
        return preview.mode == SIMULATION_MODE

    def preview(self, preview: PreventionPreview) -> dict[str, Any]:
        if not self.validate(preview):
            raise ValueError("prevention_mode_not_simulation")
        return preview.representation()

    def execute(self, preview: PreventionPreview) -> dict[str, Any]:
        if not self.validate(preview):
            raise ValueError("prevention_mode_not_simulation")
        # "Execution" persists a simulated record only. There is no real effect.
        return {
            "mode": SIMULATION_MODE,
            "adapter": self.name,
            "result": "simulated",
            "verify": self.verify(preview.request_id).as_dict(),
        }

    def verify(self, request_id: UUID) -> NoEnforcementEvidence:
        # This adapter has no real side-effect path; the evidence is constant by
        # construction. The dependency/capability/firewall-state proofs live in the
        # test suite and the static guard (docs/PREVENTION_SAFETY.md §Sprint 9).
        return NoEnforcementEvidence(
            adapter=self.name,
            real_side_effect_invoked=False,
            outbound_socket_opened=False,
            firewall_state_changed=False,
        )

    def rollback(self, execution_id: UUID) -> dict[str, Any]:
        return {"mode": SIMULATION_MODE, "adapter": self.name, "result": "rolled_back"}


# The registry holds exactly one adapter. A test asserts this is the only registered
# adapter and that its mode is immutably ``simulation``.
ADAPTER_REGISTRY: dict[str, SimulationPreventionAdapter] = {
    SIMULATION_ADAPTER: SimulationPreventionAdapter()
}


def get_adapter() -> SimulationPreventionAdapter:
    return ADAPTER_REGISTRY[SIMULATION_ADAPTER]
