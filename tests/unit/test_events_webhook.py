"""Unit tests for events.py — _spawn task reference retention and webhook retry."""
from __future__ import annotations

import asyncio
import gc
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.events import _inflight_tasks, _spawn


@pytest.mark.asyncio
async def test_spawn_holds_task_reference():
    """Tasks created via _spawn must not be GC'd while running."""
    completed = []

    async def slow_coro():
        await asyncio.sleep(0)
        completed.append(1)

    _spawn(slow_coro())
    # Wait for task to complete
    await asyncio.sleep(0.1)
    assert completed == [1], "Task was GC'd before completion"


@pytest.mark.asyncio
async def test_spawn_removes_task_on_done():
    """Task is removed from _inflight_tasks once done."""
    async def instant():
        pass

    before = len(_inflight_tasks)
    t = _spawn(instant())
    await t
    await asyncio.sleep(0)
    assert len(_inflight_tasks) == before


@pytest.mark.asyncio
async def test_deliver_with_retry_succeeds_first_attempt():
    """Successful delivery on attempt 1 — no retries."""
    from app.core.events import _deliver_with_retry

    wh = MagicMock()
    wh.id = "wh-1"
    wh.secret_enc = None
    wh.url = "https://example.com/hook"

    async def fake_deliver(w, p):
        return 200

    with (
        patch("app.core.events._deliver", side_effect=fake_deliver),
        patch("app.core.database.AsyncSessionLocal") as mock_session,
    ):
        mock_db = AsyncMock()
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session.return_value.__aexit__ = AsyncMock(return_value=None)
        await _deliver_with_retry(wh, {"event": "test"})

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_deliver_with_retry_replays_on_500():
    """Retry on 5xx — first 2 attempts (index 0, 1) fail, 3rd succeeds."""
    from app.core.events import _deliver_with_retry

    wh = MagicMock()
    wh.id = "wh-2"
    wh.secret_enc = None
    wh.url = "https://example.com/hook"

    calls = []

    async def flaky_deliver(w, p):
        calls.append(1)
        if len(calls) < 2:
            return 500
        return 200

    with (
        patch("app.core.events._deliver", side_effect=flaky_deliver),
        patch("app.core.database.AsyncSessionLocal") as mock_session,
        patch("asyncio.sleep", return_value=None),
    ):
        mock_db = AsyncMock()
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session.return_value.__aexit__ = AsyncMock(return_value=None)
        await _deliver_with_retry(wh, {"event": "test"})

        assert len(calls) == 2  # 2 attempts before success
