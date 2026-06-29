from __future__ import annotations

"""Unified authentication + scope-enforcement dependencies.

current_user_or_pat — accepts RS256 JWT bearer tokens AND aai_* PAT tokens.
require_scopes(*scopes) — dependency factory that gates PAT requests by scope.

How it works:
- PATAuthMiddleware (app/middleware/pat_auth.py) runs first for every request.
  If it finds a valid aai_* token it stores the resolved User in
  request.state.pat_user and the granted scopes in request.state.pat_scopes.
- current_user_or_pat checks that state first; for JWT requests it validates
  inline via TenantAwareJWTStrategy so callers need one dependency for both.
- require_scopes() wraps current_user_or_pat and enforces scope membership.
  JWT-authenticated requests are never scope-limited (they have full access).

Usage:
    # Accepts JWT or any valid PAT
    user: User = Depends(current_user_or_pat)

    # Only PATs with api:write scope (or JWT tokens) may reach this endpoint
    user: User = Depends(require_scopes("api:write"))
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from fastapi_users.exceptions import UserNotExists

from app.identity.password import get_user_manager
from app.models.user import User
from app.tokens.strategy import get_jwt_strategy


async def current_user_or_pat(
    request: Request,
    user_manager=Depends(get_user_manager),
) -> User:
    """Authenticate via JWT bearer token OR aai_* Personal Access Token."""
    # PAT path: PATAuthMiddleware pre-validated the token
    if hasattr(request.state, "pat_user"):
        return request.state.pat_user

    # JWT path: validate inline via TenantAwareJWTStrategy
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth[7:]
    strategy = get_jwt_strategy()

    try:
        user = await strategy.read_token(token, user_manager)
    except (UserNotExists, Exception):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user


def require_scopes(*scopes: str) -> Callable:
    """Return a FastAPI dependency that requires the PAT to carry all listed scopes.

    When the request is authenticated via JWT the check is skipped entirely —
    JWT holders always have full access (scopes are a PAT-only restriction).
    When authenticated via PAT, ALL listed scopes must be present in
    request.state.pat_scopes or the request is rejected with 403.

    Example:
        @router.post("/api/write-thing")
        async def write_thing(user: User = Depends(require_scopes("api:write"))):
            ...
    """
    async def _check(
        request: Request,
        user: User = Depends(current_user_or_pat),
    ) -> User:
        if not hasattr(request.state, "pat_scopes"):
            # JWT auth — no scope restriction
            return user
        granted = set(request.state.pat_scopes)
        required = set(scopes)
        missing = required - granted
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"API token missing required scopes: {sorted(missing)}",
            )
        return user

    return _check
