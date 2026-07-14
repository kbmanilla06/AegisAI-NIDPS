import hashlib
from typing import Protocol

from redis.asyncio import Redis

from aegis_api.config import Settings
from aegis_api.errors import ApiError


class LoginThrottle(Protocol):
    async def check(self, client_address: str) -> None: ...


class RedisLoginThrottle:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def check(self, client_address: str) -> None:
        client_key = hashlib.sha256(client_address.encode("utf-8")).hexdigest()
        key = f"aegis:login:{client_key}"
        client = Redis.from_url(self._settings.redis_url, decode_responses=True)
        try:
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, self._settings.login_ip_window_seconds)
            if count > self._settings.login_ip_limit:
                raise ApiError(429, "rate_limited", "Too many authentication attempts")
        except ApiError:
            raise
        except Exception as error:
            raise ApiError(
                503, "authentication_unavailable", "Authentication is unavailable"
            ) from error
        finally:
            await client.aclose()


def get_login_throttle() -> LoginThrottle:
    from aegis_api.config import get_settings

    return RedisLoginThrottle(get_settings())
