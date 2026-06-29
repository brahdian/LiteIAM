from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timezone
from typing import Optional

import pyotp
import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.events import AuthEvent, emit
from app.models.user import User

_LOCKOUT_WINDOW_SECONDS = 60

logger = structlog.get_logger(__name__)


def generate_backup_codes(n: int = 8) -> tuple[list[str], list[str]]:
    """Returns (plaintext_codes, sha256_hashed_codes). Show plaintext ONCE; store only hashes."""
    plaintext = [secrets.token_hex(4).upper() for _ in range(n)]
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in plaintext]
    return plaintext, hashed


def _fernet() -> Fernet:
    return Fernet(settings.fernet_key())


def _encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def _decrypt_secret(enc: str) -> str:
    try:
        return _fernet().decrypt(enc.encode()).decode()
    except InvalidToken:
        raise HTTPException(500, "TOTP secret decryption failed — key rotation issue")


async def enroll_totp(user_id: uuid.UUID, db: AsyncSession) -> dict:
    """
    Generate a new TOTP secret for the user and store it encrypted.
    Returns the OTP Auth URI for QR code display.
    The enrollment is NOT active until the user verifies their first code.
    """
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.is_totp_enabled:
        raise HTTPException(409, "TOTP already enrolled for this user")

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="LiteIAM")

    # Store encrypted — NOT active yet (is_totp_enabled stays False until verify)
    await db.execute(
        update(User)
        .where(User.id == user_id)
        .values(totp_secret_enc=_encrypt_secret(secret))
    )
    await db.commit()

    return {"uri": uri, "secret": secret}


async def verify_and_activate_totp(
    user_id: uuid.UUID, code: str, db: AsyncSession, *, ip_address: str | None = None
) -> list[str]:
    """
    Verify a TOTP code against the stored (but not yet active) secret.
    On success, activates TOTP, generates 8 backup codes, and returns them plaintext.
    Backup code hashes are stored in user.totp_backup_codes — show plaintext ONCE.
    """
    user = await db.get(User, user_id)
    if user is None or not user.totp_secret_enc:
        raise HTTPException(400, "TOTP not enrolled")
    if user.is_totp_enabled:
        raise HTTPException(409, "TOTP already active — use verify_totp instead")

    secret = _decrypt_secret(user.totp_secret_enc)
    totp = pyotp.TOTP(secret)

    if not totp.verify(code, valid_window=1):
        raise HTTPException(400, "Invalid TOTP code")

    plaintext_codes, hashed_codes = generate_backup_codes()
    await db.execute(
        update(User)
        .where(User.id == user_id)
        .values(is_totp_enabled=True, totp_failure_count=0, totp_backup_codes=hashed_codes)
    )
    await emit(db, AuthEvent.MFA_ENROLLED, tenant_id=user.tenant_id, subject_id=user.id, ip_address=ip_address)
    await db.commit()
    return plaintext_codes


async def verify_totp(
    user_id: uuid.UUID, code: str, db: AsyncSession, *, ip_address: str | None = None
) -> bool:
    """
    Verify a TOTP code for an already-enrolled user (login MFA challenge).
    Enforces failure lockout: settings.TOTP_MAX_FAILURES consecutive failures
    trigger a 60-second cooldown.
    """
    user = await db.get(User, user_id)
    if user is None or not user.is_totp_enabled or not user.totp_secret_enc:
        raise HTTPException(400, "TOTP not configured for this user")

    now = datetime.now(UTC)

    # Lockout check with time-based reset: if the last failure was more than
    # _LOCKOUT_WINDOW_SECONDS ago, the counter is stale and we reset it.
    if user.totp_failure_count >= settings.TOTP_MAX_FAILURES:
        if user.totp_last_failure_at is None:
            # Shouldn't happen, but treat as permanent lockout
            raise HTTPException(429, "Too many failed TOTP attempts. Try again later.")
        last_failure = user.totp_last_failure_at
        if last_failure.tzinfo is None:
            last_failure = last_failure.replace(tzinfo=UTC)
        age = (now - last_failure).total_seconds()
        if age < _LOCKOUT_WINDOW_SECONDS:
            await emit(db, AuthEvent.MFA_FAILED, tenant_id=user.tenant_id, subject_id=user.id)
            wait = int(_LOCKOUT_WINDOW_SECONDS - age)
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed TOTP attempts. Wait {wait}s.",
                headers={"Retry-After": str(wait)},
            )
        # Cooldown has passed — reset the counter before verifying
        await db.execute(
            update(User).where(User.id == user_id).values(totp_failure_count=0, totp_last_failure_at=None)
        )
        await db.commit()
        await db.refresh(user)

    secret = _decrypt_secret(user.totp_secret_enc)
    totp = pyotp.TOTP(secret)
    valid = totp.verify(code, valid_window=1)

    if not valid:
        await db.execute(
            update(User)
            .where(User.id == user_id)
            .values(totp_failure_count=User.totp_failure_count + 1, totp_last_failure_at=now)
        )
        await db.commit()
        await emit(db, AuthEvent.MFA_FAILED, tenant_id=user.tenant_id, subject_id=user.id,
                   ip_address=ip_address)
        raise HTTPException(400, "Invalid TOTP code")

    # Replay prevention: reject a code that was already accepted in this window
    if user.totp_last_used_code == code:
        raise HTTPException(400, "TOTP code already used. Wait for the next code.")

    # Success — reset failure counter and record the used code
    await db.execute(
        update(User).where(User.id == user_id).values(
            totp_failure_count=0,
            totp_last_failure_at=None,
            totp_last_used_code=code,
        )
    )
    await db.commit()
    await emit(db, AuthEvent.MFA_CHALLENGED, tenant_id=user.tenant_id, subject_id=user.id,
               ip_address=ip_address)
    return True


async def verify_backup_code(
    user_id: uuid.UUID, code: str, db: AsyncSession, *, ip_address: str | None = None
) -> bool:
    """Single-use backup code redemption. Removes the used code from stored hashes."""
    user = await db.get(User, user_id)
    if not user or not user.is_totp_enabled:
        raise HTTPException(400, "TOTP not configured for this user")
    if not user.totp_backup_codes:
        raise HTTPException(400, "No backup codes available — contact support")

    hashed = hashlib.sha256(code.strip().upper().encode()).hexdigest()
    codes = list(user.totp_backup_codes)
    if hashed not in codes:
        raise HTTPException(400, "Invalid backup code")

    codes.remove(hashed)
    await db.execute(
        update(User).where(User.id == user_id)
        .values(totp_backup_codes=codes if codes else None)
    )
    await db.commit()
    await emit(db, AuthEvent.MFA_CHALLENGED, tenant_id=user.tenant_id, subject_id=user.id, ip_address=ip_address)
    return True
