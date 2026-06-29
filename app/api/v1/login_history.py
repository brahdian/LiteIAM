
"""Login history API — tracks per-login IP, user agent, and timestamp.

Unlike /auth/sessions (which tracks OAuth tokens), this records every
successful login event including password, magic-link, and social logins,
so users can see where and when they have signed in.

Session cap: 10 per user (oldest evicted). Matches Auth0 / WorkOS behaviour.
"""

import uuid
from datetime import UTC, datetime, timezone
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.login_session import LoginSession
from app.models.user import User

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth/login-events", tags=["Login History"])

_MAX_SESSIONS_PER_USER = 10


class LoginEventRead(BaseModel):
    id: str
    ip_address: str | None
    user_agent: str | None
    created_at: str
    last_seen_at: str
    is_current: bool


async def record_login(
    *,
    user: User,
    request: Request,
) -> None:
    """Record a successful login. Evicts oldest when per-user cap is exceeded.

    Opens its own session (and commits) so it is safe to launch as a detached
    `asyncio.create_task` — the request-scoped session is closed by the dependency
    once the login response is sent, so borrowing it here would do DB work on a
    returned/concurrently-reused connection.
    """
    from app.core.database import AsyncSessionLocal

    # Capture request-derived primitives now; the Request object outlives the
    # handler but reading these eagerly keeps the background body pure data.
    ip_address = request.client.host if request.client else None
    user_agent = (request.headers.get("User-Agent") or "")[:512] or None

    async with AsyncSessionLocal() as db:
        db.add(
            LoginSession(
                id=uuid.uuid4(),
                user_id=user.id,
                tenant_id=user.tenant_id,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
                is_active=True,
            )
        )

        # Evict oldest sessions beyond the cap
        existing = (
            await db.scalars(
                select(LoginSession)
                .where(
                    LoginSession.user_id == user.id,
                    LoginSession.is_active,
                )
                .order_by(LoginSession.created_at.asc())
            )
        ).all()

        overflow = len(existing) - (_MAX_SESSIONS_PER_USER - 1)
        if overflow > 0:
            evict_ids = [s.id for s in existing[:overflow]]
            await db.execute(
                update(LoginSession)
                .where(LoginSession.id.in_(evict_ids))
                .values(is_active=False)
            )
            logger.info("session_evicted", user_id=str(user.id), evicted_count=overflow)

        await db.commit()


@router.get("", response_model=list[LoginEventRead])
async def list_login_events(
    request: Request,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """List the authenticated user's recent login events (most recent first)."""
    rows = (
        await db.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user.id,
                LoginSession.is_active,
            )
            .order_by(LoginSession.created_at.desc())
        )
    ).all()

    current_ip = request.client.host if request.client else None
    current_ua = request.headers.get("User-Agent") or ""

    return [
        LoginEventRead(
            id=str(s.id),
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at.isoformat(),
            last_seen_at=s.last_seen_at.isoformat(),
            is_current=(s.ip_address == current_ip and (s.user_agent or "") == current_ua),
        )
        for s in rows
    ]


@router.delete("/{event_id}", status_code=204)
async def revoke_login_event(
    event_id: uuid.UUID,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
    request: Request = None,
):
    """Revoke a specific login event (marks it inactive + emits audit event)."""
    row = await db.scalar(
        select(LoginSession).where(
            LoginSession.id == event_id,
            LoginSession.user_id == user.id,
        )
    )
    if row is None:
        raise HTTPException(404, "Login event not found")

    await db.execute(
        update(LoginSession)
        .where(LoginSession.id == event_id)
        .values(is_active=False)
    )
    await emit(
        db,
        AuthEvent.SESSION_REVOKED,
        tenant_id=user.tenant_id,
        subject_id=user.id,
        ip_address=request.client.host if request and request.client else None,
        metadata={"revoked_login_event_id": str(event_id)},
    )
    await db.commit()
    logger.info("login_event_revoked", user_id=str(user.id), event_id=str(event_id))


@router.delete("", status_code=204)
async def revoke_all_login_events(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
    request: Request = None,
):
    """Revoke all login events for the user (global sign-out marker)."""
    await db.execute(
        update(LoginSession)
        .where(LoginSession.user_id == user.id, LoginSession.is_active)
        .values(is_active=False)
    )
    await emit(
        db,
        AuthEvent.SESSION_REVOKED,
        tenant_id=user.tenant_id,
        subject_id=user.id,
        ip_address=request.client.host if request and request.client else None,
        metadata={"action": "global_sign_out"},
    )
    await db.commit()
    logger.info("all_login_events_revoked", user_id=str(user.id))
