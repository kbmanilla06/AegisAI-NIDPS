from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class SessionRecord:
    id: UUID
    user_id: UUID
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None = None


class SessionStore(Protocol):
    """Server-side opaque session contract for Sprint 1 implementations."""

    async def get_by_opaque_id(self, opaque_id: str) -> SessionRecord | None: ...

    async def rotate(self, session: SessionRecord) -> tuple[SessionRecord, str]: ...

    async def revoke(self, session_id: UUID) -> None: ...


@dataclass(frozen=True)
class SessionCookiePolicy:
    name: str = "__Host-aegis_session"
    secure: bool = True
    http_only: bool = True
    same_site: str = "lax"
    path: str = "/"
