from __future__ import annotations

"""
TenantBindMiddleware — extracts tenant_id from a Bearer JWT and sets
the ContextVar before the endpoint handler runs.

This means any endpoint that opens a get_tenant_session() after this
middleware runs will automatically have the correct search_path applied,
giving schema-level defense-in-depth on top of row-level tenant_id filters.

Endpoints that do NOT require authentication (login, register, JWKS) run
without a tenant ContextVar — get_tenant_session() is still safe (it checks
for None and skips the SET LOCAL in that case).

Failures are silent: a missing/invalid token leaves the ContextVar unset.
Auth endpoints enforce token validity themselves; this middleware is
defense-in-depth only.
"""

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.tenant.router import clear_tenant, set_tenant

logger = structlog.get_logger(__name__)


class TenantBindMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        clear_tenant()
        _try_bind_tenant(request)
        response = await call_next(request)
        clear_tenant()
        return response


def _try_bind_tenant(request: Request) -> None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return
    token = auth_header[7:]
    try:
        import jwt as pyjwt
        # Decode without verification to read tenant_id — signature is verified
        # by the endpoint's own auth dependency. This is read-only context binding.
        payload = pyjwt.decode(token, options={"verify_signature": False})
        tenant_id_str = payload.get("tenant_id")
        if tenant_id_str:
            set_tenant(uuid.UUID(tenant_id_str))
    except Exception:
        pass
