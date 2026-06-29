from __future__ import annotations

"""PAT authentication middleware.

Intercepts `Authorization: Bearer aai_*` before FastAPI's endpoint routing.
Validates the token against personal_access_tokens, stores the resolved User
in request.state.pat_user, and fires a lazy last_used_at update.

All other requests pass through untouched — JWT auth still works normally.
"""

import asyncio
import hashlib
from datetime import UTC, datetime, timezone

import structlog
from sqlalchemy import or_, select, update
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.database import AsyncSessionLocal
from app.models.pat import PersonalAccessToken
from app.models.user import User

logger = structlog.get_logger(__name__)

_PREFIX = "aai_"

# Strong-reference set — prevents the GC from collecting in-flight update tasks.
_bg_tasks: set[asyncio.Task] = set()


def _hash(raw: str) -> str:
    value = raw[len(_PREFIX):] if raw.startswith(_PREFIX) else raw
    return hashlib.sha256(value.encode()).hexdigest()


async def _update_last_used(pat_id) -> None:
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(PersonalAccessToken)
                .where(PersonalAccessToken.id == pat_id)
                .values(last_used_at=datetime.now(UTC))
            )
            await db.commit()
    except Exception as exc:
        logger.warning("pat_last_used_update_failed", pat_id=str(pat_id), exc=str(exc))


def _spawn(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return t


class PATAuthMiddleware(BaseHTTPMiddleware):
    """Validates `aai_*` bearer tokens before the request reaches any endpoint.

    On success: sets request.state.pat_user (User) and request.state.pat_scopes (list[str]).
    On failure: returns 401 immediately — never passes bad PAT tokens downstream.
    On non-PAT requests: no-op, passes to the next handler unchanged.
    """

    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and auth[7:].startswith(_PREFIX)):
            return await call_next(request)

        raw = auth[7:]
        token_hash = _hash(raw)
        now = datetime.now(UTC)

        try:
            async with AsyncSessionLocal() as db:
                pat = await db.scalar(
                    select(PersonalAccessToken).where(
                        PersonalAccessToken.token_hash == token_hash,
                        PersonalAccessToken.is_active,
                        or_(
                            PersonalAccessToken.expires_at is None,
                            PersonalAccessToken.expires_at > now,
                        ),
                    )
                )
                if pat is None:
                    logger.warning("pat_invalid_token", token_prefix=raw[:12])
                    return JSONResponse({"detail": "Invalid or expired API token"}, status_code=401)

                user = await db.scalar(
                    select(User).where(
                        User.id == pat.user_id,
                        User.is_active,
                    )
                )
                if user is None:
                    return JSONResponse({"detail": "Token owner inactive or not found"}, status_code=401)

                # Detach so the object is accessible after the session closes
                db.expunge(user)
                pat_id = pat.id
                pat_scopes = list(pat.scopes or [])

        except Exception as exc:
            logger.error("pat_middleware_error", exc=str(exc))
            return JSONResponse({"detail": "Authentication error"}, status_code=500)

        request.state.pat_user = user
        request.state.pat_scopes = pat_scopes

        # Non-blocking housekeeping — doesn't block the request
        _spawn(_update_last_used(pat_id))

        return await call_next(request)
