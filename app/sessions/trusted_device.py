"""Trusted device management — "remember this device" 30-day MFA bypass."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.trusted_device import TrustedDevice

COOKIE_NAME = "auth_device"
DEVICE_TTL_DAYS = 30


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _secure_cookie_kwargs() -> dict:
    return dict(
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
        max_age=DEVICE_TTL_DAYS * 86400,
        path="/",
    )


async def is_trusted_device(
    user_id: uuid.UUID, cookie_value: str, db: AsyncSession
) -> bool:
    """Return True if cookie_value corresponds to a valid, unexpired trusted device."""
    token_hash = _hash_token(cookie_value)
    now = datetime.now(UTC)
    row = await db.scalar(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_token_hash == token_hash,
            TrustedDevice.expires_at > now,
        )
    )
    return row is not None


async def create_trusted_device(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    *,
    request: Request | None = None,
) -> str:
    """Persist a new trusted-device record and return the raw token for the cookie."""
    token = secrets.token_hex(32)
    now = datetime.now(UTC)
    device = TrustedDevice(
        id=uuid.uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        device_token_hash=_hash_token(token),
        expires_at=now + timedelta(days=DEVICE_TTL_DAYS),
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=_get_ip(request) if request else None,
        created_at=now,
    )
    db.add(device)
    await db.commit()
    return token


async def revoke_all_trusted_devices(user_id: uuid.UUID, db: AsyncSession) -> int:
    """Delete all trusted devices for a user. Returns count deleted."""
    result = await db.execute(
        delete(TrustedDevice).where(TrustedDevice.user_id == user_id)
    )
    await db.commit()
    return result.rowcount


async def list_trusted_devices(user_id: uuid.UUID, db: AsyncSession) -> list[dict]:
    rows = await db.scalars(
        select(TrustedDevice)
        .where(TrustedDevice.user_id == user_id)
        .order_by(TrustedDevice.created_at.desc())
    )
    now = datetime.now(UTC)
    return [
        {
            "id": str(r.id),
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "created_at": r.created_at.isoformat(),
            "expires_at": r.expires_at.isoformat(),
            "is_active": r.expires_at > now,
        }
        for r in rows.all()
    ]


async def revoke_device_by_id(
    device_id: uuid.UUID, user_id: uuid.UUID, db: AsyncSession
) -> bool:
    result = await db.execute(
        delete(TrustedDevice).where(
            TrustedDevice.id == device_id,
            TrustedDevice.user_id == user_id,
        )
    )
    await db.commit()
    return result.rowcount > 0


def _get_ip(request: Request | None) -> str | None:
    if not request:
        return None
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
