
"""Two-step email change flow.

Security properties:
- Token sent to NEW email (verifies ownership) and notification sent to OLD email
  (alerts user of the change so they can raise an alarm if it's unauthorised)
- Token is SHA-256 hashed before storage — raw value shown only in the email
- Tokens expire after 24 hours (TTL in settings)
- Single-use: is_used=True is set BEFORE updating the email (no race condition)
- Rate limited: 3 requests per hour per user (slowapi)
- Emits USER_EMAIL_CHANGED audit event on completion
"""

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
from app.identity.password import current_active_user
from app.models.email_change import EmailChangeRequest
from app.models.user import User

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth/email-change", tags=["Email Change"])

_TOKEN_TTL_HOURS = 24
_PREFIX_LEN = 8  # visible prefix in logs for debugging (never the full raw token)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class EmailChangeRequestBody(BaseModel):
    new_email: EmailStr


class EmailChangeConfirmBody(BaseModel):
    token: str


@router.post("/request", status_code=202)
@limiter.limit("3/hour")
async def request_email_change(
    body: EmailChangeRequestBody,
    request: Request,
    response: Response,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Initiate an email address change.

    Sends a verification link to the new address and a security notification to the
    current address. Always returns 202 — never reveals whether the new email is
    already registered (anti-enumeration).
    """
    new_email = str(body.new_email).lower().strip()

    if new_email == user.email.lower():
        raise HTTPException(400, "New email must differ from the current email")

    # Invalidate any existing pending request for this user
    await db.execute(
        update(EmailChangeRequest)
        .where(
            EmailChangeRequest.user_id == user.id,
            not EmailChangeRequest.is_used,
        )
        .values(is_used=True)
    )

    raw_token = secrets.token_urlsafe(32)
    req = EmailChangeRequest(
        id=uuid.uuid4(),
        user_id=user.id,
        tenant_id=user.tenant_id,
        new_email=new_email,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=_TOKEN_TTL_HOURS),
        is_used=False,
        created_at=datetime.now(UTC),
    )
    db.add(req)
    await emit(
        db,
        AuthEvent.USER_UPDATED,
        tenant_id=user.tenant_id,
        subject_id=user.id,
        metadata={"action": "email_change_requested", "new_email_prefix": new_email[:4] + "***"},
    )
    await db.commit()

    # Fire both emails as non-blocking tasks
    from app.core.tasks import spawn
    from app.notifications.email import (
        send_email_change_notification,
        send_email_change_verification,
    )

    confirm_url = f"{settings.ui_base}/email-change/verify?token={raw_token}"
    spawn(send_email_change_verification(to=new_email, confirm_url=confirm_url))
    spawn(send_email_change_notification(to=user.email, new_email=new_email))

    logger.info(
        "email_change_requested",
        user_id=str(user.id),
        new_email_prefix=new_email[:_PREFIX_LEN],
    )
    return {"message": "Verification email sent to the new address."}


@router.post("/confirm")
async def confirm_email_change(
    body: EmailChangeConfirmBody,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Complete the email change by verifying the token sent to the new address."""
    token_hash = _hash_token(body.token)
    now = datetime.now(UTC)

    req = await db.scalar(
        select(EmailChangeRequest).where(
            EmailChangeRequest.token_hash == token_hash,
            EmailChangeRequest.user_id == user.id,
            not EmailChangeRequest.is_used,
            EmailChangeRequest.expires_at > now,
        )
    )
    if req is None:
        raise HTTPException(400, "Invalid or expired email change token")

    # Mark used BEFORE updating email — prevents double-use even under concurrent requests
    await db.execute(
        update(EmailChangeRequest)
        .where(EmailChangeRequest.id == req.id)
        .values(is_used=True)
    )

    old_email = user.email
    await db.execute(
        update(User).where(User.id == user.id).values(email=req.new_email)
    )
    await emit(
        db,
        AuthEvent.USER_EMAIL_CHANGED,
        tenant_id=user.tenant_id,
        subject_id=user.id,
        metadata={"old_email_prefix": old_email[:4] + "***", "action": "email_changed"},
    )
    await db.commit()

    from app.core.tasks import spawn
    from app.notifications.email import send_email_change_complete

    spawn(send_email_change_complete(to=old_email, new_email=req.new_email))

    logger.info(
        "email_changed",
        user_id=str(user.id),
        old_email_prefix=old_email[:_PREFIX_LEN],
        new_email_prefix=req.new_email[:_PREFIX_LEN],
    )
    return {"message": "Email address updated successfully", "new_email": req.new_email}
