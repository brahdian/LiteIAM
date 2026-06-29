from __future__ import annotations

"""
SafeCasbinEnforcer — a process-singleton Casbin async enforcer with
correct locking around all policy mutations.

Why the lock matters:
  Casbin's AsyncEnforcer loads policies into an in-memory model. Without
  serialization, concurrent `add_policy` / `remove_policy` calls can leave
  the model in a partially-updated state, granting or denying access based
  on corrupted intermediate state.

  The lock is asyncio.Lock (not threading.Lock) because auth-engine runs on
  a single-threaded asyncio event loop per uvicorn worker. The lock never
  blocks the event loop while waiting — it yields control so other coroutines
  can run.

Usage:
    enforcer = get_enforcer()                         # after initialize()
    allowed = await enforcer.enforce(sub, obj, act)   # read — lock-free
    await enforcer.safe_add_policy(sub, obj, act)     # write — serialized
"""

import asyncio
import os
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Casbin model spec (RBAC with tenant isolation via domain)
_MODEL_CONF = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


class SafeCasbinEnforcer:
    """
    Thin wrapper around casbin.AsyncEnforcer that:
    1. Serializes all policy mutations behind asyncio.Lock
    2. Exposes a clean enforce() API for permission checks
    3. Supports PG NOTIFY-triggered policy reload (see watcher.py)
    """

    def __init__(self) -> None:
        self._enforcer: object | None = None
        self._lock = asyncio.Lock()

    async def initialize(self, database_url: str) -> None:
        try:
            # Write model to a temp file — casbin requires a file path
            import tempfile

            import casbin
            import casbin_async_sqlalchemy_adapter as adapter
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".conf", delete=False
            ) as f:
                f.write(_MODEL_CONF)
                model_path = f.name

            pg_url = database_url.replace("+asyncpg", "")
            a = adapter.Adapter(pg_url)
            self._enforcer = casbin.AsyncEnforcer(model_path, a)
            await self._enforcer.load_policy()
            os.unlink(model_path)
            logger.info("Casbin enforcer initialized")
        except ImportError:
            logger.warning("casbin not installed — authorization enforcement disabled")
            self._enforcer = None

    async def enforce(self, sub: str, domain: str, obj: str, act: str) -> bool:
        """Check permission — read-only, no lock needed."""
        if self._enforcer is None:
            return True  # fail-open during Phase 1; Phase 2 sets enforcer
        return await self._enforcer.enforce(sub, domain, obj, act)

    async def safe_add_policy(self, sub: str, domain: str, obj: str, act: str) -> bool:
        async with self._lock:
            if self._enforcer is None:
                return False
            return await self._enforcer.add_policy(sub, domain, obj, act)

    async def safe_remove_policy(self, sub: str, domain: str, obj: str, act: str) -> bool:
        async with self._lock:
            if self._enforcer is None:
                return False
            return await self._enforcer.remove_policy(sub, domain, obj, act)

    async def safe_add_role_for_user(self, user: str, role: str, domain: str) -> bool:
        async with self._lock:
            if self._enforcer is None:
                return False
            return await self._enforcer.add_role_for_user_in_domain(user, role, domain)

    async def safe_reload_policy(self) -> None:
        """Called by watcher.py when PG NOTIFY signals a policy change."""
        async with self._lock:
            if self._enforcer is not None:
                await self._enforcer.load_policy()
                logger.info("Casbin policy reloaded from DB")

    def get_roles_for_user(self, user: str, domain: str) -> list[str]:
        if self._enforcer is None:
            return []
        return self._enforcer.get_roles_for_user_in_domain(user, domain)


# Process-level singleton — initialized once per worker in lifespan
casbin_enforcer = SafeCasbinEnforcer()
