from __future__ import annotations

"""
GC-safe fire-and-forget task spawning.

`asyncio.create_task` only returns the task — if the caller keeps no reference,
CPython may garbage-collect the task before it finishes, silently dropping the
work (a transactional email never sent, a session never recorded). Holding a
strong reference until completion is the documented fix:
https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task

Use `spawn(coro)` for any fire-and-forget coroutine (security alert emails,
login-history writes) so the reference is held until the task is done.
"""

import asyncio
from typing import Set

_bg_tasks: set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    """Schedule `coro` as a background task, keeping a strong reference until it
    completes so it cannot be garbage-collected mid-flight."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task
