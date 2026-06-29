
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.core.rate_limit import limiter
from app.identity.password import UserManager, get_user_manager
from app.mfa.orchestrator import requires_mfa
from app.models.magic_link import MagicLinkToken
from app.models.tenant import Tenant
from app.models.user import User
from app.tokens.strategy import get_jwt_strategy

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth/magic-link", tags=["Auth"])

_TTL_MINUTES = 15


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class MagicLinkSendRequest(BaseModel):
    email: EmailStr


class MagicLinkVerifyRequest(BaseModel):
    token: str


@router.post("/send", status_code=202)
@limiter.limit("3/5minutes")
async def send_magic_link(
    request: Request,
    response: Response,
    body: MagicLinkSendRequest,
    db: AsyncSession = Depends(get_session),
):
    """Send a one-time login link to the provided email address.

    Always returns 202 — callers cannot distinguish "email found" from "email not found"
    to prevent user-enumeration.
    """
    from app.notifications.email import send_email

    # Look up user; proceed silently if not found (anti-enumeration)
    user = await db.scalar(select(User).where(User.email == body.email, User.is_active))

    if user:
        raw_token = secrets.token_urlsafe(32)
        db.add(
            MagicLinkToken(
                id=uuid.uuid4(),
                token_hash=_hash(raw_token),
                email=body.email,
                tenant_id=user.tenant_id,
                expires_at=datetime.now(UTC) + timedelta(minutes=_TTL_MINUTES),
                ip_address=request.client.host if request.client else None,
            )
        )
        await emit(db, AuthEvent.MAGIC_LINK_SENT, tenant_id=user.tenant_id, subject_id=user.id)
        await db.commit()

        magic_url = f"{settings.ui_base}/magic-link?token={raw_token}"
        await send_email(
            to=body.email,
            subject="Your sign-in link",
            text_body=(
                f"Click the link below to sign in to the platform. "
                f"This link expires in {_TTL_MINUTES} minutes and can only be used once.\n\n"
                f"{magic_url}\n\n"
                f"If you did not request this, you can safely ignore this email."
            ),
            html_body=(
                f'<p>Click the link below to sign in to the platform.</p>'
                f'<p>This link expires in <strong>{_TTL_MINUTES} minutes</strong> and can only be used once.</p>'
                f'<p><a href="{magic_url}" style="background:#5D5FEF;color:#fff;padding:12px 24px;'
                f'border-radius:8px;text-decoration:none;font-weight:700;display:inline-block">'
                f'Sign in</a></p>'
                f'<p style="color:#6b7280;font-size:12px">If you did not request this, you can safely ignore this email.</p>'
            ),
        )

    return {"message": "If that email is registered, a sign-in link has been sent."}


@router.post("/verify")
async def verify_magic_link(
    body: MagicLinkVerifyRequest,
    db: AsyncSession = Depends(get_session),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Validate a magic-link token and return an access token."""
    now = datetime.now(UTC)
    token_hash = _hash(body.token)

    row = await db.scalar(
        select(MagicLinkToken).where(
            MagicLinkToken.token_hash == token_hash,
            MagicLinkToken.used_at is None,
            MagicLinkToken.expires_at > now,
        )
    )
    if row is None:
        raise HTTPException(400, "Magic link is invalid, expired, or already used.")

    # Mark as used immediately (single-use guarantee)
    await db.execute(
        update(MagicLinkToken)
        .where(MagicLinkToken.id == row.id)
        .values(used_at=now)
    )

    user = await db.scalar(select(User).where(User.email == row.email, User.is_active))
    if user is None:
        await db.rollback()
        # Same generic message as every other failure path — never reveal account state
        raise HTTPException(400, "Magic link is invalid, expired, or already used.")

    # Mark email as verified if not already
    if not user.is_verified:
        user.is_verified = True
        db.add(user)

    # Tenant-level MFA enforcement: if the organisation mandates MFA and the
    # user has no TOTP enrolled, block here rather than issuing any token.
    tenant = await db.get(Tenant, user.tenant_id)
    if tenant and tenant.require_mfa and not user.is_totp_enabled:
        await db.rollback()
        raise HTTPException(
            status_code=403,
            detail=(
                "Multi-factor authentication is required for this organisation. "
                "Please enrol TOTP before signing in."
            ),
            headers={"X-MFA-Enroll-URL": f"{settings.BASE_URL}/ui/totp/enroll"},
        )

    await emit(db, AuthEvent.MAGIC_LINK_USED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()

    strategy = get_jwt_strategy()

    # MFA step-up: if the user has TOTP enrolled, issue a pending token —
    # the client must pass the TOTP challenge before receiving a full token.
    if requires_mfa(user):
        pending_token = await strategy.write_mfa_pending_token(user)
        logger.info("magic_link_mfa_pending", user_id=str(user.id))
        return {"access_token": pending_token, "token_type": "bearer", "auth_stage": "mfa_pending"}

    token = await strategy.write_token(user)
    logger.info("magic_link_login", user_id=str(user.id))
    return {"access_token": token, "token_type": "bearer", "auth_stage": "complete"}
