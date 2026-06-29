from __future__ import annotations

"""
PG LISTEN/NOTIFY watcher for cross-worker Casbin policy sync.

When an admin mutates a Casbin policy (add/remove role, policy row), the
mutating worker broadcasts `NOTIFY casbin_policy_update` on the PostgreSQL
channel. All workers (including the mutating one) listen on this channel and
call `safe_reload_policy()` on receipt, keeping their in-memory Casbin models
consistent without Redis or any external message broker.

Why PG NOTIFY instead of Redis:
- auth-engine already requires PostgreSQL; no extra dependency
- NOTIFY is transactional — the message is only delivered if the mutating
  transaction commits, so listeners never reload stale policies from a
  rolled-back write

Lifecycle:
    Start: await start_policy_watcher(database_url)
    Stop:  await stop_policy_watcher()   (called in lifespan shutdown)
"""

import asyncio
from typing import Optional

import structlog

from app.authz.enforcer import casbin_enforcer

logger = structlog.get_logger(__name__)

POLICY_CHANNEL = "casbin_policy_update"

_watcher_task: asyncio.Task | None = None


async def _listen_loop(database_url: str) -> None:
    try:
        import asyncpg

        conn = await asyncpg.connect(database_url.replace("+asyncpg", ""))
        await conn.add_listener(
            POLICY_CHANNEL,
            lambda *_: asyncio.ensure_future(casbin_enforcer.safe_reload_policy()),
        )
        logger.info("PG policy watcher listening", channel=POLICY_CHANNEL)
        # Keep the connection alive until cancelled
        while True:
            await asyncio.sleep(30)
    except asyncio.CancelledError:
        logger.info("PG policy watcher shutting down")
        raise
    except Exception as exc:
        logger.error("PG policy watcher error — will not retry", error=str(exc))


async def start_policy_watcher(database_url: str) -> None:
    global _watcher_task
    _watcher_task = asyncio.create_task(_listen_loop(database_url))


async def stop_policy_watcher() -> None:
    global _watcher_task
    if _watcher_task and not _watcher_task.done():
        _watcher_task.cancel()
        try:
            await _watcher_task
        except asyncio.CancelledError:
            pass
    _watcher_task = None


async def notify_policy_updated(database_url: str) -> None:
    """
    Call this after any Casbin policy mutation to broadcast to all workers.
    Should be called AFTER the DB transaction that changed the policy commits,
    so listeners reload the committed state.
    """
    try:
        import asyncpg

        conn = await asyncpg.connect(database_url.replace("+asyncpg", ""))
        await conn.execute(f"NOTIFY {POLICY_CHANNEL}")
        await conn.close()
    except Exception as exc:
        logger.error("Failed to notify policy update", error=str(exc))
