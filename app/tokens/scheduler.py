from __future__ import annotations

"""
Automated signing key rotation scheduler.

Runs as a background asyncio task. Checks daily whether the current signing
key is approaching expiry (within ROTATION_THRESHOLD_DAYS). If so, rotates
to a new key. The old key remains in _valid_jwks so existing tokens can still
be verified until their TTL expires.

Zero-downtime guarantee:
- New key is created and added to JWKS BEFORE the old key is deactivated
- All workers reload JWKS within one poll interval (30s) via PG NOTIFY
- Old tokens (up to 1h TTL) continue to verify against the old kid
"""

import asyncio
from datetime import UTC, datetime, timezone

import structlog

from app.core.database import AsyncSessionLocal
from app.tokens.keys import key_manager

logger = structlog.get_logger(__name__)

_ROTATION_CHECK_INTERVAL = 86400  # check once per day
_ROTATION_THRESHOLD_DAYS = 7      # rotate when ≤7 days from expiry
_scheduler_task: asyncio.Task | None = None


async def _rotation_loop() -> None:
    while True:
        try:
            await _maybe_rotate()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Key rotation check failed", error=str(exc))
        await asyncio.sleep(_ROTATION_CHECK_INTERVAL)


async def _maybe_rotate() -> None:
    from sqlalchemy import select

    from app.models.signing_key import SigningKey

    async with AsyncSessionLocal() as db:
        current_row = await db.scalar(
            select(SigningKey).where(SigningKey.is_current)
        )
        if current_row is None:
            logger.warning("No current signing key found during rotation check")
            return

        exp = current_row.expires_at
        if exp.tzinfo is None:
            from datetime import timezone as tz
            exp = exp.replace(tzinfo=UTC)

        days_remaining = (exp - datetime.now(UTC)).days
        if days_remaining <= _ROTATION_THRESHOLD_DAYS:
            logger.info(
                "Signing key rotation triggered",
                days_remaining=days_remaining,
                old_kid=current_row.kid,
            )
            new_kid = await key_manager.rotate(db)
            logger.info("Signing key rotated", new_kid=new_kid)
        else:
            logger.debug("Signing key OK", days_remaining=days_remaining)


async def start_key_rotation_scheduler() -> None:
    global _scheduler_task
    _scheduler_task = asyncio.create_task(_rotation_loop())
    logger.info("Key rotation scheduler started", check_interval_s=_ROTATION_CHECK_INTERVAL)


async def stop_key_rotation_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
    _scheduler_task = None
