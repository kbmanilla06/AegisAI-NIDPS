from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from redis.exceptions import RedisError

from aegis_api.config import Settings, get_settings
from aegis_api.errors import ApiError


class IngestionThrottle:
    def __init__(self, settings: Settings) -> None:
        self._redis = Redis.from_url(settings.redis_url, decode_responses=True)
        self._limit = settings.ingestion_upload_limit
        self._window = settings.ingestion_upload_window_seconds

    async def check(self, actor_key: str) -> None:
        key = f"aegis:ingestion-rate:{actor_key}"
        try:
            async with self._redis.pipeline(transaction=True) as pipeline:
                results = await pipeline.incr(key).expire(key, self._window, nx=True).execute()
            count = int(results[0])
        except RedisError as error:
            raise ApiError(
                503, "ingestion_unavailable", "Ingestion is temporarily unavailable"
            ) from error
        if count > self._limit:
            raise ApiError(429, "ingestion_rate_limited", "Ingestion rate limit exceeded")

    async def close(self) -> None:
        await self._redis.aclose()


async def get_ingestion_throttle(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AsyncIterator[IngestionThrottle]:
    throttle = IngestionThrottle(settings)
    try:
        yield throttle
    finally:
        await throttle.close()
