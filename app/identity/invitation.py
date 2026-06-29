from __future__ import annotations

"""
User invitation service.

Admins create invitations for specific email addresses. The recipient gets a
signed link containing a raw token. The raw token is never stored — only its
SHA-256 hash. On acceptance the user provides a password and the account is
created with the role specified in the invitation.

Security properties:
- Token is 32 bytes of OS entropy → 256 bits, unguessable
- Only the hash is stored (same as trusted-device pattern)
- Invitations are single-use: accepted_at set on first use, rejected thereafter
- Invitations expire after INVITATION_TTL_HOURS (default 72)
- Email address in invitation must match registration email exactly
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.invitation import UserInvitation

logger = structlog.get_logger(__name__)

INVITATION_TTL_HOURS = 72
_TOKEN_BYTES = 32


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def create_invitation(
    *,
    tenant_id: uuid.UUID,
    email: str,
    role: str = "member",
    invited_by_id: uuid.UUID | None = None,
    db: AsyncSession,
) -> str:
    """
    Create an invitation and return the raw token (send it in the link).

    The token is never stored; only its hash is persisted.
    """
    raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    # Invalidate any existing pending invitation for this email+tenant
    existing = await db.scalar(
        select(UserInvitation).where(
            UserInvitation.tenant_id == tenant_id,
            UserInvitation.email == email.lower(),
            UserInvitation.accepted_at == None,  # noqa: E711
        )
    )
    if existing:
        await db.delete(existing)

    inv = UserInvitation(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        email=email.lower(),
        token_hash=token_hash,
        role=role,
        invited_by_id=invited_by_id,
        created_at=now,
        expires_at=now + timedelta(hours=INVITATION_TTL_HOURS),
    )
    db.add(inv)
    await db.commit()

    logger.info("invitation_created", tenant_id=str(tenant_id), email=email, role=role)
    return raw_token


async def verify_invitation(
    raw_token: str,
    email: str,
    db: AsyncSession,
) -> UserInvitation | None:
    """
    Verify an invitation token.

    Returns the UserInvitation if valid and not yet used, None otherwise.
    The invitation is NOT consumed here — call accept_invitation() after
    creating the user.
    """
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    inv = await db.scalar(
        select(UserInvitation).where(
            UserInvitation.token_hash == token_hash,
            UserInvitation.email == email.lower(),
            UserInvitation.accepted_at == None,  # noqa: E711
            UserInvitation.expires_at > now,
        )
    )
    return inv


async def accept_invitation(invitation: UserInvitation, db: AsyncSession) -> None:
    """Mark an invitation as used. Call after the user account is created."""
    invitation.accepted_at = datetime.now(UTC)
    db.add(invitation)
    await db.commit()
    logger.info("invitation_accepted", invitation_id=str(invitation.id))


async def list_invitations(tenant_id: uuid.UUID, db: AsyncSession) -> list[dict]:
    """Return pending + recently accepted invitations for a tenant."""
    rows = await db.scalars(
        select(UserInvitation)
        .where(UserInvitation.tenant_id == tenant_id)
        .order_by(UserInvitation.created_at.desc())
        .limit(100)
    )
    return [
        {
            "id": str(inv.id),
            "email": inv.email,
            "role": inv.role,
            "status": "accepted" if inv.accepted_at else "pending",
            "expires_at": inv.expires_at.isoformat(),
            "accepted_at": inv.accepted_at.isoformat() if inv.accepted_at else None,
        }
        for inv in rows
    ]


async def revoke_invitation(invitation_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> bool:
    """Delete a pending invitation. Returns False if not found or already accepted."""
    inv = await db.scalar(
        select(UserInvitation).where(
            UserInvitation.id == invitation_id,
            UserInvitation.tenant_id == tenant_id,
            UserInvitation.accepted_at == None,  # noqa: E711
        )
    )
    if inv is None:
        return False
    await db.delete(inv)
    await db.commit()
    logger.info("invitation_revoked", invitation_id=str(invitation_id))
    return True
