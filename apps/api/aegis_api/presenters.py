from aegis_api.models import User
from aegis_api.schemas import UserOut


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        roles=sorted(role.name for role in user.roles),
        version=user.version,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )
