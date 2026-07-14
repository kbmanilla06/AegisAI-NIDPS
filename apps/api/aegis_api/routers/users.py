import asyncio
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import Role, Session, User, user_roles
from aegis_api.presenters import user_out
from aegis_api.schemas import RoleOut, UserCreate, UserOut, UserRolesUpdate, UserStatusUpdate
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.passwords import password_service
from aegis_api.security.permissions import PermissionKey

router = APIRouter(prefix="/api/v1", tags=["identity"])


async def _load_user(db: AsyncSession, user_id: UUID, *, lock: bool = False) -> User:
    statement = (
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.roles).selectinload(Role.permissions))
    )
    if lock:
        statement = statement.with_for_update()
    user = (await db.execute(statement)).scalar_one_or_none()
    if user is None:
        raise ApiError(404, "user_not_found", "User not found")
    return user


async def _ensure_another_active_system_admin(db: AsyncSession) -> None:
    """Serialize demotions/deactivations and preserve one active system administrator."""
    system_role_id = (
        await db.execute(
            select(Role.id).where(Role.name == "System Administrator").with_for_update()
        )
    ).scalar_one()
    admin_count = (
        await db.execute(
            select(func.count())
            .select_from(user_roles.join(User, user_roles.c.user_id == User.id))
            .where(user_roles.c.role_id == system_role_id, User.is_active.is_(True))
        )
    ).scalar_one()
    if admin_count <= 1:
        raise ApiError(409, "last_system_admin", "The last active system administrator is required")


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.USERS_READ))],
) -> list[UserOut]:
    users = (
        (
            await db.execute(
                select(User)
                .options(selectinload(User.roles).selectinload(Role.permissions))
                .order_by(User.email)
                .limit(100)
            )
        )
        .scalars()
        .all()
    )
    return [user_out(user) for user in users]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.USERS_MANAGE))],
) -> UserOut:
    email = payload.email.lower()
    if (await db.execute(select(User.id).where(User.email == email))).scalar_one_or_none():
        raise ApiError(409, "user_exists", "A user with that email already exists")
    roles = (await db.execute(select(Role).where(Role.name.in_(payload.roles)))).scalars().all()
    if {role.name for role in roles} != set(payload.roles):
        raise ApiError(422, "invalid_roles", "One or more roles are invalid")
    password_hash = await asyncio.to_thread(password_service.hash, payload.password)
    user = User(email=email, password_hash=password_hash, roles=list(roles))
    db.add(user)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="user.create",
        resource_type="user",
        resource_id=str(user.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"roles": sorted(payload.roles)},
    )
    await db.commit()
    await db.refresh(user, attribute_names=["roles"])
    return user_out(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user_status(
    user_id: UUID,
    payload: UserStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.USERS_MANAGE))],
) -> UserOut:
    user = await _load_user(db, user_id, lock=True)
    if user.version != payload.expected_version:
        raise ApiError(409, "version_conflict", "The user was modified by another request")
    if user.id == principal.user_id and not payload.is_active:
        raise ApiError(409, "self_deactivation", "You cannot deactivate your own account")
    if (
        user.is_active
        and not payload.is_active
        and any(role.name == "System Administrator" for role in user.roles)
    ):
        await _ensure_another_active_system_admin(db)
    user.is_active = payload.is_active
    user.version += 1
    if not payload.is_active:
        await db.execute(
            update(Session)
            .where(Session.user_id == user.id, Session.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="user.status_update",
        resource_type="user",
        resource_id=str(user.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"is_active": payload.is_active},
    )
    await db.commit()
    return user_out(user)


@router.put("/users/{user_id}/roles", response_model=UserOut)
async def replace_user_roles(
    user_id: UUID,
    payload: UserRolesUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.USERS_MANAGE))],
) -> UserOut:
    user = await _load_user(db, user_id, lock=True)
    if user.version != payload.expected_version:
        raise ApiError(409, "version_conflict", "The user was modified by another request")
    roles = (await db.execute(select(Role).where(Role.name.in_(payload.roles)))).scalars().all()
    if {role.name for role in roles} != set(payload.roles):
        raise ApiError(422, "invalid_roles", "One or more roles are invalid")
    existing_names = {role.name for role in user.roles}
    removing_system_admin = (
        "System Administrator" in existing_names and "System Administrator" not in payload.roles
    )
    if removing_system_admin:
        await _ensure_another_active_system_admin(db)
    user.roles = list(roles)
    user.version += 1
    await db.execute(
        update(Session)
        .where(Session.user_id == user.id, Session.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="user.roles_update",
        resource_type="user",
        resource_id=str(user.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"roles": sorted(payload.roles)},
    )
    await db.commit()
    return user_out(user)


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.ROLES_READ))],
) -> list[RoleOut]:
    roles = (
        (await db.execute(select(Role).options(selectinload(Role.permissions)).order_by(Role.name)))
        .scalars()
        .all()
    )
    return [
        RoleOut(
            name=role.name,
            description=role.description,
            permissions=sorted(permission.key for permission in role.permissions),
        )
        for role in roles
    ]
