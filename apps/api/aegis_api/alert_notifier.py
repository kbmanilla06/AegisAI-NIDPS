from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends
from redis.asyncio import Redis

from aegis_api.config import Settings, get_settings

# FR-012: a metadata-only "alert changed" notifier over the existing authenticated
# bounded channel. It carries only {event, alert_id, sequence} — never endpoints,
# vectors, notes, or evidence — and can never trigger prevention.
AlertNotifier = Callable[[UUID], Awaitable[None]]


def get_alert_notifier(settings: Annotated[Settings, Depends(get_settings)]) -> AlertNotifier:
    async def notify(alert_id: UUID) -> None:
        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        try:
            await redis.publish(
                "aegis.alerts",
                json.dumps(
                    {
                        "event": "alert_changed",
                        "alert_id": str(alert_id),
                        "sequence": str(uuid4()),
                    },
                    separators=(",", ":"),
                ),
            )
        finally:
            await redis.aclose()

    return notify
