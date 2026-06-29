from __future__ import annotations

"""Registration rate-limiter middleware.

/auth/register is managed by fastapi-users so @limiter.limit() decorators
can't reach it. This middleware intercepts POST requests to that path before
routing and enforces a per-IP, per-hour cap.

Default: 5 registrations per IP per hour.
Multi-worker note: the counter is in-process memory. For horizontally-scaled
deployments, replace _RegCounter with a Redis-backed equivalent and set
REGISTRATION_RATE_LIMIT_REDIS_URL in config.
"""

import time
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings

_WINDOW_SECONDS = 3600  # 1 hour sliding window
_MAX_REGISTRATIONS = 5  # per IP per window


class _RegCounter:
    """Thread-safe, in-process sliding-window counter."""

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check_and_record(self, ip: str) -> bool:
        """Return True if the request should be allowed, False if rate-limited."""
        now = time.monotonic()
        cutoff = now - _WINDOW_SECONDS
        with self._lock:
            # Prune stale entries
            self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
            if len(self._hits[ip]) >= _MAX_REGISTRATIONS:
                return False
            self._hits[ip].append(now)
            return True


_counter = _RegCounter()


def _client_ip(request: Request) -> str:
    if settings.TRUST_X_FORWARDED_FOR:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


_REGISTER_PATH = "/auth/register"


class RegistrationRateLimitMiddleware(BaseHTTPMiddleware):
    """Limits POST /auth/register to 5 attempts per IP per hour."""

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)
        # Strip trailing slash so /auth/register and /auth/register/ both match
        if request.url.path.rstrip("/") != _REGISTER_PATH:
            return await call_next(request)

        ip = _client_ip(request)
        if not _counter.check_and_record(ip):
            return JSONResponse(
                {"detail": "Too many registration attempts. Please try again later."},
                status_code=429,
                headers={"Retry-After": str(_WINDOW_SECONDS)},
            )

        return await call_next(request)
