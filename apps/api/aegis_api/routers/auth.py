import asyncio
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aegis_api.audit import record_audit
from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Role, Session, User
from aegis_api.presenters import user_out
from aegis_api.schemas import (
    AuthResponse,
    CsrfResponse,
    CurrentUserResponse,
    LoginRequest,
)
from aegis_api.security.authentication import (
    SESSION_COOKIE_NAME,
    Principal,
    as_utc,
    get_principal,
    require_allowed_origin,
    require_csrf,
)
from aegis_api.security.passwords import password_service
from aegis_api.security.throttle import LoginThrottle, get_login_throttle
from aegis_api.security.tokens import hash_secret, issue_secret

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


@router.post("/login", response_model=AuthResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    throttle: Annotated[LoginThrottle, Depends(get_login_throttle)],
    current_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> AuthResponse:
    require_allowed_origin(request, settings)
    await throttle.check(request.client.host if request.client else "unknown")
    email = payload.email.lower()
    statement = (
        select(User)
        .where(User.email == email)
        .with_for_update()
        .options(selectinload(User.roles).selectinload(Role.permissions))
    )
    user = (await db.execute(statement)).scalar_one_or_none()
    now = datetime.now(UTC)
    password_valid = await asyncio.to_thread(
        password_service.verify, user.password_hash if user else None, payload.password
    )
    locked = bool(user and user.locked_until and as_utc(user.locked_until) > now)
    if user is None or not password_valid or not user.is_active or locked:
        if user is not None and user.is_active and not locked:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.login_failure_limit:
                user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
        record_audit(
            db,
            actor_user_id=user.id if user else None,
            action="auth.login",
            resource_type="session",
            resource_id=None,
            outcome="denied",
            correlation_id=request.state.correlation_id,
            metadata={"reason": "invalid_credentials"},
        )
        await db.commit()
        raise ApiError(401, "invalid_credentials", "Invalid email or password")

    rotated_from_id = None
    if current_token:
        existing = (
            await db.execute(
                select(Session).where(Session.token_hash == hash_secret(current_token))
            )
        ).scalar_one_or_none()
        if existing and existing.revoked_at is None:
            existing.revoked_at = now
            rotated_from_id = existing.id
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if password_service.needs_rehash(user.password_hash):
        user.password_hash = await asyncio.to_thread(password_service.hash, payload.password)
    session_token = issue_secret()
    csrf_token = issue_secret()
    absolute_expiry = now + timedelta(hours=settings.session_absolute_hours)
    session = Session(
        user_id=user.id,
        token_hash=hash_secret(session_token),
        csrf_hash=hash_secret(csrf_token),
        idle_expires_at=now + timedelta(minutes=settings.session_idle_minutes),
        absolute_expires_at=absolute_expiry,
        last_seen_at=now,
        rotated_from_id=rotated_from_id,
    )
    db.add(session)
    await db.flush()
    record_audit(
        db,
        actor_user_id=user.id,
        action="auth.login",
        resource_type="session",
        resource_id=str(session.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
    )
    await db.commit()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )
    permissions = sorted({permission.key for role in user.roles for permission in role.permissions})
    return AuthResponse(user=user_out(user), permissions=permissions, csrf_token=csrf_token)


@router.get("/me", response_model=CurrentUserResponse)
async def me(principal: Annotated[Principal, Depends(get_principal)]) -> CurrentUserResponse:
    return CurrentUserResponse(
        user=user_out(principal.session.user), permissions=sorted(principal.permissions)
    )


@router.get("/csrf", response_model=CsrfResponse)
async def rotate_csrf(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(get_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CsrfResponse:
    require_allowed_origin(request, settings)
    token = issue_secret()
    principal.session.csrf_hash = hash_secret(token)
    await db.commit()
    response.headers["Cache-Control"] = "no-store"
    return CsrfResponse(csrf_token=token)


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    principal.session.revoked_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="auth.logout",
        resource_type="session",
        resource_id=str(principal.session.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
    )
    await db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=True, httponly=True)
