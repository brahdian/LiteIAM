"""
Unit tests for the GC-safe fire-and-forget helper, app.core.tasks.spawn.

The whole point of spawn() is that the scheduled task is kept alive by a strong
reference until it completes (so it cannot be garbage-collected mid-flight) and
that the reference is released afterwards (so the set does not leak).
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.tasks import _bg_tasks, spawn


@pytest.mark.asyncio
async def test_spawn_runs_the_coro_to_completion():
    ran = asyncio.Event()

    async def work():
        ran.set()

    task = spawn(work())
    await asyncio.wait_for(ran.wait(), timeout=1)
    await task
    assert task.done()


@pytest.mark.asyncio
async def test_spawn_holds_ref_while_pending_then_releases():
    gate = asyncio.Event()

    async def work():
        await gate.wait()

    task = spawn(work())
    # While pending, the helper must keep a strong reference.
    assert task in _bg_tasks

    gate.set()
    await task
    # add_done_callback runs on the next loop tick — yield so it fires.
    await asyncio.sleep(0)
    assert task not in _bg_tasks


@pytest.mark.asyncio
async def test_spawn_returns_the_task():
    async def work():
        return 42

    task = spawn(work())
    assert isinstance(task, asyncio.Task)
    assert await task == 42
