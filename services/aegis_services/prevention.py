from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID


@dataclass(frozen=True)
class PreventionPreview:
    request_id: UUID
    mode: Literal["simulation"]
    action_type: str
    target_type: str
    target_display: str
    duration_seconds: int
    rollback_summary: str


class SimulationAdapter(Protocol):
    """Data-only contract. Implementations must not perform OS or network actions."""

    async def validate(self, preview: PreventionPreview) -> bool: ...

    async def preview(self, request_id: UUID) -> PreventionPreview: ...

    async def simulate(self, preview: PreventionPreview) -> str: ...

    async def verify(self, request_id: UUID) -> bool: ...

    async def rollback(self, request_id: UUID) -> str: ...

    async def status(self, request_id: UUID) -> str: ...
