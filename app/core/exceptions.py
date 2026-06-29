from __future__ import annotations

"""RFC 7807 Problem Details error handler.

Replaces FastAPI's default `{"detail": "..."}` error format with the
standard `application/problem+json` shape from RFC 7807.

Shape:
    {
        "type": "https://example.dev/problems/unauthorized",
        "title": "Unauthorized",
        "status": 401,
        "detail": "Invalid or expired token",
        "instance": "/auth/login"
    }

Benefits:
  - Clients can programmatically distinguish error classes by "type" URI
  - Consistent across all endpoints — no per-endpoint error schema needed
  - "instance" allows easy log correlation (path + X-Request-ID)
  - Interoperable with API gateways that understand RFC 7807

Wiring: add_problem_details_handler(app) in main.py after app is created.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

_PROBLEM_BASE = "https://example.dev/problems"

_STATUS_SLUGS: dict[int, str] = {
    400: "bad-request",
    401: "unauthorized",
    403: "forbidden",
    404: "not-found",
    409: "conflict",
    422: "validation-error",
    429: "too-many-requests",
    500: "internal-server-error",
    503: "service-unavailable",
}

_STATUS_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def _problem(
    request: Request,
    status: int,
    detail: str,
    extra_headers: dict | None = None,
) -> JSONResponse:
    slug = _STATUS_SLUGS.get(status, "error")
    body = {
        "type": f"{_PROBLEM_BASE}/{slug}",
        "title": _STATUS_TITLES.get(status, "Error"),
        "status": status,
        "detail": detail,
        "instance": str(request.url.path),
    }
    headers = {"Content-Type": "application/problem+json"}
    if extra_headers:
        headers.update(extra_headers)
    return JSONResponse(body, status_code=status, headers=headers)


async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return _problem(request, exc.status_code, detail, extra_headers=dict(exc.headers or {}))


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Flatten Pydantic validation errors into a human-readable message
    errors = exc.errors()
    if errors:
        first = errors[0]
        loc = " → ".join(str(p) for p in first.get("loc", []))
        msg = first.get("msg", "Validation error")
        detail = f"{loc}: {msg}" if loc else msg
    else:
        detail = "Request validation failed"
    return _problem(request, 422, detail)


def add_problem_details_handler(app: FastAPI) -> None:
    """Register RFC 7807 Problem Details handlers on the FastAPI app."""
    app.add_exception_handler(HTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
