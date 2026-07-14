import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import Cookie, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Role, Session, User
from aegis_api.security.permissions import PermissionKey
from aegis_api.security.tokens import hash_secret

SESSION_COOKIE_NAME = "__Host-aegis_session"


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    email: str
    roles: frozenset[str]
    permissions: frozenset[str]
    session: Session


async def get_principal(
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> Principal:
    if not session_token:
        raise ApiError(401, "authentication_required", "Authentication required")
    statement = (
        select(Session)
        .where(Session.token_hash == hash_secret(session_token))
        .options(selectinload(Session.user).selectinload(User.roles).selectinload(Role.permissions))
    )
    session = (await db.execute(statement)).scalar_one_or_none()
    now = datetime.now(UTC)
    if session is None or session.revoked_at is not None:
        raise ApiError(401, "invalid_session", "Authentication required")
    idle_expires_at = as_utc(session.idle_expires_at)
    absolute_expires_at = as_utc(session.absolute_expires_at)
    if idle_expires_at <= now or absolute_expires_at <= now:
        session.revoked_at = now
        await db.commit()
        raise ApiError(401, "expired_session", "Authentication required")
    user = session.user
    if not user.is_active:
        session.revoked_at = now
        await db.commit()
        raise ApiError(401, "invalid_session", "Authentication required")
    session.last_seen_at = now
    session.idle_expires_at = min(
        now + timedelta(minutes=settings.session_idle_minutes), absolute_expires_at
    )
    await db.commit()
    roles = frozenset(role.name for role in user.roles)
    permissions = frozenset(
        permission.key for role in user.roles for permission in role.permissions
    )
    return Principal(user.id, user.email, roles, permissions, session)


def require_permission(permission: PermissionKey):  # type: ignore[no-untyped-def]
    async def dependency(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        ensure_permission(principal, permission)
        return principal

    return dependency


def ensure_permission(principal: Principal, permission: PermissionKey) -> None:
    if permission not in principal.permissions:
        raise ApiError(403, "permission_denied", "Permission denied")


def require_allowed_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("Origin")
    if origin not in settings.allowed_origins:
        raise ApiError(403, "invalid_origin", "Request origin is not allowed")


async def require_csrf(
    request: Request,
    principal: Annotated[Principal, Depends(get_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Principal:
    require_allowed_origin(request, settings)
    if not csrf_token or not hmac.compare_digest(
        hash_secret(csrf_token), principal.session.csrf_hash
    ):
        raise ApiError(403, "invalid_csrf", "CSRF validation failed")
    return principal


def require_csrf_permission(permission: PermissionKey):  # type: ignore[no-untyped-def]
    async def dependency(principal: Annotated[Principal, Depends(require_csrf)]) -> Principal:
        ensure_permission(principal, permission)
        return principal

    return dependency
