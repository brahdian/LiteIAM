from __future__ import annotations

"""X-Request-ID correlation middleware.

Every request gets a unique request ID. If the client sends `X-Request-ID`
it is reused; otherwise a new UUID4 is generated. The ID is:

  - Echoed back in the `X-Request-ID` response header so callers can correlate
    their logs with server-side logs.
  - Bound into every structlog log record emitted during the request via
    structlog.contextvars.bind_contextvars so all log lines share the same
    request_id without manual threading.

Production integrations: pass `X-Request-ID` from your API gateway and it
propagates end-to-end through auth-engine logs.
"""

import uuid

import structlog.contextvars
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Bind to structlog context — cleared automatically between requests
        # because BaseHTTPMiddleware resets contextvars per-call.
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
