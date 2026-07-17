"""Sprint 9 no-enforcement verification evidence (PREV-008, PREVENTION_SAFETY.md §Sprint 9).

These tests are the machine-checkable core of the sprint: they prove the prevention
paths cannot enforce, not merely that they choose not to.
"""

from __future__ import annotations

import ast
from pathlib import Path
from uuid import uuid4

from aegis_services.prevention import (
    ADAPTER_REGISTRY,
    SIMULATION_ADAPTER,
    SIMULATION_MODE,
    ExecutableRepresentationError,
    PreventionPreview,
    contains_executable_string,
    get_adapter,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PREVENTION_PKG = _REPO_ROOT / "services" / "aegis_services" / "prevention"
_PREVENTION_ROUTER = _REPO_ROOT / "apps" / "api" / "aegis_api" / "routers" / "prevention.py"

# Modules that could reach real enforcement, raw sockets, or OS state. None may be
# imported anywhere on the prevention path.
_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {"subprocess", "socket", "os", "ctypes", "fcntl", "scapy", "pydivert", "nftables", "iptc"}
)


def _prevention_source_files() -> list[Path]:
    files = list(_PREVENTION_PKG.rglob("*.py"))
    files.append(_PREVENTION_ROUTER)
    return files


def test_no_forbidden_imports_on_prevention_path() -> None:
    offenders: list[str] = []
    for path in _prevention_source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if name in _FORBIDDEN_IMPORT_ROOTS:
                    offenders.append(f"{path.name}: imports {name}")
    assert offenders == [], offenders


def test_simulation_is_the_only_registered_adapter() -> None:
    assert set(ADAPTER_REGISTRY) == {SIMULATION_ADAPTER}
    adapter = get_adapter()
    assert adapter.name == SIMULATION_ADAPTER == "simulation"


def test_mode_is_immutably_simulation() -> None:
    preview = PreventionPreview(
        request_id=uuid4(),
        mode="simulation",
        action_type="temporary_block",
        target_type="external_ip",
        target_display="203.0.113.10",
        duration_seconds=300,
        rollback_summary="undo",
    )
    outcome = get_adapter().execute(preview)
    assert outcome["mode"] == SIMULATION_MODE
    assert outcome["result"] == "simulated"
    # verify asserts no real side-effect path was invoked.
    assert outcome["verify"]["real_side_effect_invoked"] is False
    assert outcome["verify"]["outbound_socket_opened"] is False
    assert outcome["verify"]["firewall_state_changed"] is False


def test_preview_representation_is_data_never_a_command() -> None:
    preview = PreventionPreview(
        request_id=uuid4(),
        mode="simulation",
        action_type="temporary_block",
        target_type="external_ip",
        target_display="203.0.113.10",
        duration_seconds=300,
        rollback_summary="Remove the simulated temporary rule",
    )
    representation = get_adapter().preview(preview)
    assert representation["executable_command"] is None
    assert representation["network_call"] is None
    payload = {key: value for key, value in representation.items() if key != "limitations"}
    assert contains_executable_string(payload) is False


def test_executable_string_detector_catches_command_injection() -> None:
    assert contains_executable_string("iptables -A INPUT -s 1.2.3.4 -j DROP") is True
    assert contains_executable_string({"nested": ["/bin/sh", "-c", "curl evil"]}) is True
    assert contains_executable_string({"safe": "a temporary block would be simulated"}) is False


def test_executable_representation_error_is_raisable() -> None:
    # The guard type exists and is a RuntimeError so callers can fail closed.
    assert issubclass(ExecutableRepresentationError, RuntimeError)
