import re
from uuid import uuid4

from fastapi import FastAPI, Request

CORRELATION_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def install_correlation_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def correlation_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        supplied = request.headers.get("X-Correlation-ID", "")
        request.state.correlation_id = (
            supplied if CORRELATION_ID.fullmatch(supplied) else uuid4().hex
        )
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        return response
