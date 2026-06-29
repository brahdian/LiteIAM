from __future__ import annotations

"""
Rate limiting for auth endpoints.

Uses slowapi (a FastAPI-compatible Limits wrapper). Limits are applied at
the endpoint level via the @limiter.limit() decorator.

Limits:
  - /auth/login              : 10 requests/minute per IP (brute-force prevention)
  - /auth/totp/verify        : 5 requests/minute per IP (TOTP brute-force)
  - /auth/google/callback    : 20 requests/minute per IP
  - /oauth/token             : 30 requests/minute per IP
  - All other auth endpoints : 60 requests/minute per IP (reasonable default)

The IP is extracted from the real client IP, not X-Forwarded-For, unless
TRUST_X_FORWARDED_FOR is True (configured in Settings).
"""

from app.core.config import settings


def _get_client_ip(request) -> str:
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    # Direct connection IP — not spoofable without access to network layer
    if request.client:
        return request.client.host
    return "unknown"


try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=_get_client_ip, headers_enabled=True)
except ImportError:
    # slowapi not installed — create a no-op limiter for local dev
    class _NoOpLimiter:
        def limit(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator
    limiter = _NoOpLimiter()
