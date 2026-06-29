from __future__ import annotations

"""
PG NOTIFY token revocation blacklist.

Why PG instead of Redis:
- auth-engine already requires PostgreSQL; no extra dependency
- NOTIFY is transactional — the revocation message is only delivered if the
  DB write commits, so workers never act on a revocation that was rolled back
- The in-memory set is the fast path; the DB is the source of truth on restart

Lifecycle:
  1. `revoke_token(jti, exp, db)` — writes to revoked_tokens table + NOTIFY
  2. All workers listening on 'token_revoked' add the jti to their local set
  3. `is_revoked(jti)` — O(1) set lookup, never hits the DB on the hot path

On worker restart, the set is rebuilt from revoked_tokens WHERE expires_at > now.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timezone
from typing import Optional, Set

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

REVOKE_CHANNEL = "token_revoked"

# In-memory revocation set — O(1) lookup on the auth hot path
_revoked_jtis: set[str] = set()
_watcher_task: asyncio.Task | None = None


def is_revoked(jti: str) -> bool:
    return jti in _revoked_jtis


async def revoke_token(jti: str, expires_at: datetime, db: AsyncSession) -> None:
    """
    Persist the revocation and broadcast to all workers via PG NOTIFY.
    Call AFTER emitting any audit event so the audit row and revocation
    row land in the same transaction.
    """
    from app.models.revoked_token import RevokedToken

    row = RevokedToken(
        id=uuid.uuid4(),
        jti=jti,
        expires_at=expires_at,
        revoked_at=datetime.now(UTC),
    )
    db.add(row)
    await db.flush()
    # NOTIFY is sent when this transaction commits
    await db.execute(text(f"NOTIFY {REVOKE_CHANNEL}, '{jti}'"))
    _revoked_jtis.add(jti)


async def _load_active_revocations(database_url: str) -> None:
    """Rebuild in-memory set from DB on startup."""
    try:
        import asyncpg

        conn = await asyncpg.connect(database_url.replace("+asyncpg", ""))
        rows = await conn.fetch(
            "SELECT jti FROM revoked_tokens WHERE expires_at > NOW()"
        )
        for row in rows:
            _revoked_jtis.add(row["jti"])
        await conn.close()
        logger.info("revocation_set_loaded", count=len(_revoked_jtis))
    except Exception as exc:
        logger.error("Failed to load revocations on startup", error=str(exc))


async def _listen_loop(database_url: str) -> None:
    try:
        import asyncpg

        conn = await asyncpg.connect(database_url.replace("+asyncpg", ""))

        def _on_revoke(connection, pid, channel, payload):
            if payload:
                _revoked_jtis.add(payload)
                logger.info("token_revoked_via_notify", jti=payload[:8] + "...")

        await conn.add_listener(REVOKE_CHANNEL, _on_revoke)
        logger.info("Token revocation watcher listening", channel=REVOKE_CHANNEL)

        # Periodic cleanup: prune expired JTIs from the in-memory set every hour.
        # Without this, the set grows unbounded — every revoked token stays in memory
        # forever even after its exp has passed and it can never be used again.
        tick = 0
        while True:
            await asyncio.sleep(30)
            tick += 1
            if tick % 120 == 0:  # every 3600s (120 × 30s)
                await _prune_expired_jtis(conn)
    except asyncio.CancelledError:
        logger.info("Token revocation watcher shutting down")
        raise
    except Exception as exc:
        logger.error("Revocation watcher error", error=str(exc))


async def _prune_expired_jtis(conn) -> None:
    """Remove expired JTIs from the in-memory set and DB table."""
    try:
        rows = await conn.fetch(
            "SELECT jti FROM revoked_tokens WHERE expires_at <= NOW()"
        )
        expired = {r["jti"] for r in rows}
        if expired:
            _revoked_jtis.difference_update(expired)
            await conn.execute("DELETE FROM revoked_tokens WHERE expires_at <= NOW()")
            logger.info("revocation_set_pruned", removed=len(expired), remaining=len(_revoked_jtis))
    except Exception as exc:
        logger.warning("Failed to prune expired JTIs", error=str(exc))


async def start_revocation_watcher(database_url: str) -> None:
    await _load_active_revocations(database_url)
    global _watcher_task
    _watcher_task = asyncio.create_task(_listen_loop(database_url))


async def stop_revocation_watcher() -> None:
    global _watcher_task
    if _watcher_task and not _watcher_task.done():
        _watcher_task.cancel()
        try:
            await _watcher_task
        except asyncio.CancelledError:
            pass
    _watcher_task = None
