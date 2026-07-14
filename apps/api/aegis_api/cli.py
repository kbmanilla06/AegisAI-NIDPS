import argparse
import asyncio
import getpass

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from aegis_api.audit import record_audit
from aegis_api.config import get_settings
from aegis_api.database import SessionFactory, engine
from aegis_api.models import Role, User
from aegis_api.security.passwords import password_service


async def bootstrap_admin(email: str, password: str) -> None:
    async with SessionFactory() as db:
        existing = (
            await db.execute(select(User.id).where(User.email == email))
        ).scalar_one_or_none()
        if existing:
            raise RuntimeError("A user with that email already exists")
        role = (
            await db.execute(
                select(Role)
                .where(Role.name == "System Administrator")
                .options(selectinload(Role.permissions))
            )
        ).scalar_one_or_none()
        if role is None:
            raise RuntimeError("Run the database migration before bootstrapping an administrator")
        user = User(email=email, password_hash=password_service.hash(password), roles=[role])
        db.add(user)
        await db.flush()
        record_audit(
            db,
            actor_user_id=user.id,
            action="user.bootstrap",
            resource_type="user",
            resource_id=str(user.id),
            outcome="success",
            correlation_id="bootstrap-cli",
            metadata={"roles": ["System Administrator"]},
        )
        await db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisAI administrative commands")
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap = subparsers.add_parser("bootstrap-admin")
    bootstrap.add_argument("--email", required=True)
    args = parser.parse_args()
    if args.command != "bootstrap-admin":
        return 2
    try:
        email = str(TypeAdapter(EmailStr).validate_python(args.email)).lower()
    except ValidationError:
        parser.error("--email must be a valid email address")
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        parser.error("passwords do not match")
    if len(password) < get_settings().password_min_length or len(password) > 128:
        parser.error("password does not meet the configured length policy")

    async def run() -> None:
        try:
            await bootstrap_admin(email, password)
        finally:
            await engine.dispose()

    asyncio.run(run())
    print("System administrator created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
