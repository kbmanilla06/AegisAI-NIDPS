from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
        payload: dict[str, Any] = {
            "code": error.code,
            "message": error.message,
            "correlation_id": request.state.correlation_id,
        }
        if error.details:
            payload["details"] = error.details
        return JSONResponse(status_code=error.status_code, content=payload)
