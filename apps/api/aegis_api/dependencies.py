from collections.abc import Awaitable, Callable

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from aegis_api.config import Settings

Check = Callable[[], Awaitable[bool]]


def postgres_check(settings: Settings) -> Check:
    async def check() -> bool:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except Exception:  # Health boundary converts dependency errors to status only.
            return False
        finally:
            await engine.dispose()

    return check


def redis_check(settings: Settings) -> Check:
    async def check() -> bool:
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        try:
            return bool(await client.ping())
        except Exception:  # Health boundary converts dependency errors to status only.
            return False
        finally:
            await client.aclose()

    return check
