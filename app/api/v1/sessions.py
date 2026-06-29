
"""
Session management API.

Allows authenticated users to list their active sessions (issued token pairs)
and revoke individual sessions or all sessions at once (remote logout).

The "session" concept maps onto OAuthToken rows — each row represents one
active access/refresh token pair issued to a specific client.
"""

import uuid
from datetime import UTC, datetime, timezone
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.token import OAuthToken
from app.models.user import User
from app.tokens.revocation import revoke_token

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth/sessions", tags=["Sessions"])


class SessionInfo(BaseModel):
    session_id: str
    client_id: str
    scope: str
    issued_at: datetime
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime | None
    token_family_id: str | None


class RevokeSessionRequest(BaseModel):
    session_id: str


@router.get("", response_model=list[SessionInfo])
async def list_sessions(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Return all active (non-revoked, non-expired) sessions for the current user."""
    now = datetime.now(UTC)
    rows = await db.execute(
        select(OAuthToken).where(
            OAuthToken.user_id == user.id,
            not OAuthToken.revoked,
            OAuthToken.access_token_expires_at > now,
        )
    )
    sessions = rows.scalars().all()
    return [
        SessionInfo(
            session_id=str(row.id),
            client_id=row.client_id,
            scope=row.scope,
            issued_at=row.issued_at,
            access_token_expires_at=row.access_token_expires_at,
            refresh_token_expires_at=row.refresh_token_expires_at,
            token_family_id=str(row.token_family_id) if row.token_family_id else None,
        )
        for row in sessions
    ]


@router.delete("/{session_id}", status_code=204)
async def revoke_session(
    session_id: str,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Revoke a specific session by its ID. Only the owning user can revoke."""
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session_id")

    row = await db.scalar(
        select(OAuthToken).where(
            OAuthToken.id == session_uuid,
            OAuthToken.user_id == user.id,
        )
    )
    if row is None:
        raise HTTPException(404, "Session not found")
    if row.revoked:
        return  # already revoked — idempotent

    # Revoke the OAuthToken row
    await db.execute(
        update(OAuthToken).where(OAuthToken.id == session_uuid).values(revoked=True)
    )

    # Also blacklist the JWT jti so it's rejected on the hot path immediately
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from app.tokens.keys import key_manager

    try:
        header = pyjwt.get_unverified_header(row.access_token)
        kid = header.get("kid")
        pem = key_manager.get_public_pem_by_kid(kid) if kid else None
        if pem:
            pub = load_pem_public_key(pem)
            payload = pyjwt.decode(
                row.access_token, pub, algorithms=["RS256"], audience=["open-auth:auth"],
                options={"verify_exp": False},
            )
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                exp_dt = datetime.fromtimestamp(exp, tz=UTC)
                await revoke_token(jti=jti, expires_at=exp_dt, db=db)
    except Exception:
        pass  # JWT decode failure is non-fatal — DB revocation already applied

    await emit(db, AuthEvent.TOKEN_REVOKED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()


@router.delete("", status_code=204)
async def revoke_all_sessions(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Revoke ALL active sessions for the current user (global sign-out)."""
    rows_result = await db.execute(
        select(OAuthToken).where(
            OAuthToken.user_id == user.id,
            not OAuthToken.revoked,
        )
    )
    rows = rows_result.scalars().all()

    if not rows:
        return

    # Bulk revoke in DB
    await db.execute(
        update(OAuthToken)
        .where(OAuthToken.user_id == user.id, not OAuthToken.revoked)
        .values(revoked=True)
    )

    # Blacklist each JWT jti
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from app.tokens.keys import key_manager

    for row in rows:
        try:
            header = pyjwt.get_unverified_header(row.access_token)
            kid = header.get("kid")
            pem = key_manager.get_public_pem_by_kid(kid) if kid else None
            if pem:
                pub = load_pem_public_key(pem)
                payload = pyjwt.decode(
                    row.access_token, pub, algorithms=["RS256"], audience=["open-auth:auth"],
                    options={"verify_exp": False},
                )
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp:
                    exp_dt = datetime.fromtimestamp(exp, tz=UTC)
                    await revoke_token(jti=jti, expires_at=exp_dt, db=db)
        except Exception:
            pass

    await emit(db, AuthEvent.TOKEN_REVOKED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()
    logger.info("all_sessions_revoked", user_id=str(user.id), count=len(rows))
