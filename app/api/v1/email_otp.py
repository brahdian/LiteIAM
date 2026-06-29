
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.core.rate_limit import limiter
from app.identity.password import UserManager, get_user_manager
from app.mfa.orchestrator import requires_mfa
from app.models.email_otp import EmailOTP
from app.models.tenant import Tenant
from app.models.user import User
from app.tokens.strategy import get_jwt_strategy

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth/email-otp", tags=["Auth"])

_TTL_MINUTES = 10
_MAX_ATTEMPTS = 5  # cap brute-force against the 6-digit (1e6) code space


def _hash(email: str, code: str) -> str:
    # Bind the code to the email so a leaked hash can't be matched against codes
    # issued for a different address.
    return hashlib.sha256(f"{email}:{code}".encode()).hexdigest()


class EmailOTPSendRequest(BaseModel):
    email: EmailStr


class EmailOTPVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/send", status_code=202)
@limiter.limit("3/5minutes")
async def send_email_otp_endpoint(
    request: Request,
    response: Response,
    body: EmailOTPSendRequest,
    db: AsyncSession = Depends(get_session),
):
    """Email a one-time 6-digit sign-in code.

    Always returns 202 — callers cannot distinguish "email found" from "not found"
    (anti-enumeration), matching the magic-link flow.
    """
    from app.notifications.email import resolve_tenant_sender, send_email_otp

    user = await db.scalar(select(User).where(User.email == body.email, User.is_active))

    if user:
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.add(
            EmailOTP(
                id=uuid.uuid4(),
                code_hash=_hash(body.email, code),
                email=body.email,
                tenant_id=user.tenant_id,
                expires_at=datetime.now(UTC) + timedelta(minutes=_TTL_MINUTES),
                ip_address=request.client.host if request.client else None,
            )
        )
        await emit(db, AuthEvent.EMAIL_OTP_SENT, tenant_id=user.tenant_id, subject_id=user.id)
        await db.commit()

        from_address, from_name = await resolve_tenant_sender(db, user.tenant_id)
        await send_email_otp(
            to=body.email, code=code, ttl_minutes=_TTL_MINUTES,
            from_address=from_address, from_name=from_name,
        )

    return {"message": "If that email is registered, a sign-in code has been sent."}


@router.post("/verify")
async def verify_email_otp_endpoint(
    request: Request,
    body: EmailOTPVerifyRequest,
    db: AsyncSession = Depends(get_session),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Validate a 6-digit code and return an access token."""
    now = datetime.now(UTC)

    # Most recent active code for this email. We fetch the row (not match by hash)
    # so a wrong code can still increment the attempts counter on the live OTP.
    row = await db.scalar(
        select(EmailOTP)
        .where(EmailOTP.email == body.email, EmailOTP.used_at is None, EmailOTP.expires_at > now)
        .order_by(EmailOTP.created_at.desc())
    )
    if row is None:
        raise HTTPException(400, "Code is invalid, expired, or already used.")

    if row.attempts >= _MAX_ATTEMPTS:
        # Burn the code so further guesses are pointless.
        await db.execute(update(EmailOTP).where(EmailOTP.id == row.id).values(used_at=now))
        await emit(db, AuthEvent.EMAIL_OTP_FAILED, tenant_id=row.tenant_id,
                   metadata={"reason": "too_many_attempts"})
        await db.commit()
        raise HTTPException(400, "Too many incorrect attempts. Request a new code.")

    if not secrets.compare_digest(row.code_hash, _hash(body.email, body.code)):
        await db.execute(update(EmailOTP).where(EmailOTP.id == row.id).values(attempts=row.attempts + 1))
        await emit(db, AuthEvent.EMAIL_OTP_FAILED, tenant_id=row.tenant_id, metadata={"reason": "wrong_code"})
        await db.commit()
        raise HTTPException(400, "Code is invalid, expired, or already used.")

    # Correct — single-use: atomically claim the code. The `used_at IS NULL` guard
    # makes two concurrent verifies with the same code race-safe — only one UPDATE
    # matches the row; the loser sees rowcount 0 and is rejected, so a valid code
    # can never mint two access tokens.
    claim = await db.execute(
        update(EmailOTP)
        .where(EmailOTP.id == row.id, EmailOTP.used_at is None)
        .values(used_at=now)
    )
    if claim.rowcount != 1:
        await db.rollback()
        raise HTTPException(400, "Code is invalid, expired, or already used.")

    user = await db.scalar(select(User).where(User.email == body.email, User.is_active))
    if user is None:
        # Same generic message as every other failure path — never reveal whether
        # the account exists or was deactivated between code issuance and verify.
        await db.rollback()
        raise HTTPException(400, "Code is invalid, expired, or already used.")

    if not user.is_verified:
        user.is_verified = True
        db.add(user)

    # Tenant-level MFA enforcement: same gate as the password login flow.
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

    await emit(db, AuthEvent.EMAIL_OTP_USED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()

    strategy = get_jwt_strategy()

    # MFA step-up: user has TOTP enrolled — issue a pending token.
    if requires_mfa(user):
        pending_token = await strategy.write_mfa_pending_token(user)
        logger.info("email_otp_mfa_pending", user_id=str(user.id))
        return {"access_token": pending_token, "token_type": "bearer", "auth_stage": "mfa_pending"}

    token = await strategy.write_token(user)
    logger.info("email_otp_login", user_id=str(user.id))
    return {"access_token": token, "token_type": "bearer", "auth_stage": "complete"}
