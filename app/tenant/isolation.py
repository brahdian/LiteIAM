from __future__ import annotations

"""
Tenant schema isolation helpers.

The canonical pattern throughout auth-engine:
    await enforce_tenant_schema(session, tenant_id)

This issues SET LOCAL search_path inside the current transaction. The word
LOCAL is non-negotiable: a bare SET would pollute the connection back in the
pool and expose one tenant's data to another tenant's later request.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def enforce_tenant_schema(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """
    Scope all subsequent queries in this transaction to the tenant's schema.

    Uses SET LOCAL so the change is transaction-scoped and automatically
    reverted on COMMIT or ROLLBACK. Never use bare SET here.
    """
    schema = f"tenant_{tenant_id.hex}"
    await session.execute(text(f"SET LOCAL search_path = {schema}, public"))


async def reset_search_path(session: AsyncSession) -> None:
    """Restore to the public schema — use in cleanup after admin operations."""
    await session.execute(text("SET LOCAL search_path = public"))
