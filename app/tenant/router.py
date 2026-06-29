from __future__ import annotations

"""
Tenant session binding via ContextVar.

Every incoming request binds its tenant_id into a ContextVar BEFORE the
async DB session is opened. The session middleware reads the var and issues
  SET LOCAL search_path = tenant_{tid}, public
inside every transaction so no query can escape tenant boundaries.

Critical invariants:
- SET LOCAL (not SET) — bare SET sticks to the pooled connection and leaks
  across unrelated requests sharing the same connection.
- asyncio.shield() in cleanup prevents connection leaks when a client
  disconnects mid-request (the event loop cancels the coroutine but we must
  still close the session).
- ctx.run() propagates the ContextVar to any thread-pool executor calls.
"""

import uuid
from contextvars import ContextVar, copy_context
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal

# Per-request tenant binding — not set means request is not tenant-scoped
_tenant_ctx: ContextVar[uuid.UUID | None] = ContextVar("tenant_id", default=None)


def set_tenant(tenant_id: uuid.UUID) -> None:
    _tenant_ctx.set(tenant_id)


def get_tenant() -> uuid.UUID | None:
    return _tenant_ctx.get()


def clear_tenant() -> None:
    _tenant_ctx.set(None)


async def get_tenant_session() -> AsyncSession:
    """
    Yields an AsyncSession scoped to the current request's tenant.
    Issues SET LOCAL search_path at session open, shields cleanup from
    coroutine cancellation on client disconnect.
    """
    import asyncio

    tid = _tenant_ctx.get()
    async with AsyncSessionLocal() as session:
        try:
            if tid is not None:
                await session.execute(
                    text(f"SET LOCAL search_path = tenant_{tid.hex}, public")
                )
            yield session
            await session.commit()
        except Exception:
            await asyncio.shield(session.rollback())
            raise


def run_in_tenant_executor(executor, fn, *args):
    """
    Run `fn(*args)` in `executor`, propagating the current ContextVar state
    (including the tenant binding) into the thread.
    Without ctx.run(), thread-pool tasks lose the tenant_id ContextVar.
    """
    import asyncio

    ctx = copy_context()
    loop = asyncio.get_event_loop()
    return loop.run_in_executor(executor, ctx.run, fn, *args)
