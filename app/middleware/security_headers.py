from __future__ import annotations

"""
Security headers middleware for the auth engine.

Auth endpoints are high-value targets. These headers prevent a class of client-side
attacks that are irrelevant for non-browser API clients but mandatory for any
endpoint that issues tokens consumed by browser-hosted apps.

Headers applied to every response:
  X-Content-Type-Options: nosniff         — prevents MIME-type sniffing attacks
  X-Frame-Options: DENY                   — prevents clickjacking
  Referrer-Policy: no-referrer            — prevents token leakage via Referrer header
  Permissions-Policy: …                  — disables dangerous browser features
  Cache-Control: no-store                 — auth responses must never be cached by proxies

HSTS is only applied in production (DEBUG=False) because browsers enforce HSTS
strictly and it would break local HTTP dev flows if set during development.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings

_CACHE_CONTROL_NO_STORE = "no-store, no-cache, must-revalidate, private"
_AUTH_PATHS = {
    "/auth/",
    "/oauth/",
    "/users/",
    "/.well-known/",
}

# CSP for the Jinja2-rendered UI pages.
# Tailwind CDN and Google Fonts require relaxed src-* directives.
# 'unsafe-inline' is needed because our templates use <script> blocks.
# Nonce-based CSP would be stricter but requires per-request context injection.
_CSP_UI = (
    "default-src 'self'; "
    "script-src 'self' cdn.tailwindcss.com 'unsafe-inline'; "
    "style-src 'self' fonts.googleapis.com cdn.tailwindcss.com 'unsafe-inline'; "
    "font-src fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    # Tailwind CDN Play mode fetches CSS/WASM chunks at runtime from the same CDN host
    "connect-src 'self' cdn.tailwindcss.com; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none';"
)

# Strict CSP for JSON API responses — no document rendering, nothing to permit.
_CSP_API = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'; "
    "base-uri 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Applied unconditionally to every response
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "accelerometer=(), gyroscope=(), magnetometer=(), clipboard-read=(), "
            "clipboard-write=(), display-capture=(), interest-cohort=()"
        )
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Cross-Origin isolation headers — prevent cross-site info leaks via
        # SharedArrayBuffer, Spectre-style attacks, and cross-origin window access.
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # Auth-engine is now API-only (Jinja2 /ui/* removed; Next.js auth-ui serves the frontend).
        # Apply the strict API CSP on all paths — no document rendering here.
        path = request.url.path
        response.headers["Content-Security-Policy"] = _CSP_API

        # Auth responses must never be cached — tokens in a proxy cache are a serious leak
        if any(path.startswith(p) for p in _AUTH_PATHS) or path in ("/health", "/metrics"):
            response.headers["Cache-Control"] = _CACHE_CONTROL_NO_STORE
            response.headers["Pragma"] = "no-cache"

        # HSTS: only emit over an actual HTTPS connection. Sending it over plain
        # HTTP poisons the browser's HSTS cache for the whole *.lvh.me dev domain
        # (includeSubDomains), which then force-upgrades every sibling app
        # (app.lvh.me, etc.) to HTTPS and makes the HTTP dev stack unreachable.
        # Behind the TLS-terminating proxy the request arrives as https (or with
        # X-Forwarded-Proto: https), which is exactly when HSTS belongs.
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        if is_https and not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response
