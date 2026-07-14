from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLarge(Exception):
    pass


class IngestionBodyLimitMiddleware:
    """Cap the raw multipart body before Starlette can spool an unbounded upload."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") in {"/api/v1/ingestion/jobs", "/api/v1/ingestion/sensor/jobs"}
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(scope, send)
                    return
            except ValueError:
                await self._reject(scope, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(scope, send)

    @staticmethod
    async def _reject(scope: Scope, send: Send) -> None:
        state: dict[str, Any] = scope.get("state", {})
        response = JSONResponse(
            status_code=413,
            content={
                "code": "upload_too_large",
                "message": "Upload exceeds the configured limit",
                "correlation_id": state.get("correlation_id", "unavailable"),
            },
        )

        async def disconnected() -> Message:
            return {"type": "http.disconnect"}

        await response(scope, disconnected, send)
