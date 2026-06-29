"""Tests for password-history enforcement in UserManager.validate_password."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from argon2 import PasswordHasher
from fastapi_users.exceptions import InvalidPasswordException

from app.identity.password import UserManager

# Patch HIBP for all tests in this module — these tests cover complexity and
# history logic, not breach detection; a real HIBP call would make the suite
# network-dependent and would reject common test passwords.
pytestmark = pytest.mark.usefixtures("_no_hibp")


@pytest.fixture(autouse=True)
def _no_hibp(monkeypatch):
    async def _noop(password):
        pass
    monkeypatch.setattr("app.identity.password._check_hibp", _noop)


def _make_manager():
    user_db = MagicMock()
    user_db.session = AsyncMock()
    m = UserManager.__new__(UserManager)
    m.user_db = user_db
    return m


def _hashed(password: str) -> str:
    return PasswordHasher().hash(password)


def _make_user(current_password: str, history: list | None = None):
    user = MagicMock()
    user.hashed_password = _hashed(current_password)
    user.password_history = [_hashed(p) for p in history] if history else None
    return user


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _expect_rejection(manager, password, user, fragment):
    with pytest.raises(InvalidPasswordException) as exc_info:
        await manager.validate_password(password, user=user)
    assert fragment.lower() in (exc_info.value.reason or "").lower(), (
        f"Expected '{fragment}' in reason: {exc_info.value.reason!r}"
    )


# ---------------------------------------------------------------------------
# Complexity checks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_validate_password_rejects_short():
    m = _make_manager()
    await _expect_rejection(m, "Ab1!", None, "8")


@pytest.mark.asyncio
async def test_validate_password_rejects_no_uppercase():
    m = _make_manager()
    await _expect_rejection(m, "abcdef1!", None, "uppercase")


@pytest.mark.asyncio
async def test_validate_password_rejects_no_special():
    m = _make_manager()
    await _expect_rejection(m, "Abcdef12", None, "special")


@pytest.mark.asyncio
async def test_validate_password_accepts_strong_new_password():
    m = _make_manager()
    await m.validate_password("StrongP@ss1", user=None)  # must not raise


# ---------------------------------------------------------------------------
# History enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_validate_password_rejects_current_password_reuse():
    m = _make_manager()
    user = _make_user("CurrentPass1!")
    await _expect_rejection(m, "CurrentPass1!", user, "reuse")


@pytest.mark.asyncio
async def test_validate_password_rejects_password_in_history():
    m = _make_manager()
    user = _make_user("CurrentPass1!", history=["OldPass1!", "OlderPass2@"])
    await _expect_rejection(m, "OldPass1!", user, "reuse")


@pytest.mark.asyncio
async def test_validate_password_accepts_fresh_password():
    m = _make_manager()
    user = _make_user("CurrentPass1!", history=["OldPass1!", "OlderPass2@"])
    await m.validate_password("BrandNew3#", user=user)


@pytest.mark.asyncio
async def test_validate_password_no_history_allows_new_password():
    m = _make_manager()
    user = _make_user("CurrentPass1!")
    user.password_history = None
    await m.validate_password("NewPass2@", user=user)


@pytest.mark.asyncio
async def test_validate_password_skips_history_for_new_user():
    """On registration user=None — history check is skipped."""
    m = _make_manager()
    await m.validate_password("StrongN3w!", user=None)


@pytest.mark.asyncio
async def test_validate_password_depth_zero_disables_check():
    """PASSWORD_HISTORY_DEPTH=0 means no reuse enforcement at all."""
    m = _make_manager()
    user = _make_user("CurrentPass1!")
    # Patch the settings object that password.py already imported
    with patch("app.identity.password.settings") as mock_settings:
        mock_settings.PASSWORD_HISTORY_DEPTH = 0
        mock_settings.REQUIRE_EMAIL_VERIFICATION = False
        # Should NOT raise — depth 0 disables the check
        await m.validate_password("CurrentPass1!", user=user)


# ---------------------------------------------------------------------------
# _push_password_history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_push_password_history_appends_and_commits():
    m = _make_manager()
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()

    user = MagicMock()
    user.id = "uid"
    user.hashed_password = _hashed("NewPass1!")
    user.password_history = [_hashed("OldPass1!"), _hashed("OldPass2@")]

    await m._push_password_history(user, db)

    db.execute.assert_called_once()
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_push_password_history_noop_when_depth_zero():
    m = _make_manager()
    db = AsyncMock()

    user = MagicMock()
    user.id = "uid"
    user.hashed_password = _hashed("Pass1!")
    user.password_history = []

    with patch("app.identity.password.settings") as mock_settings:
        mock_settings.PASSWORD_HISTORY_DEPTH = 0
        await m._push_password_history(user, db)

    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_push_password_history_noop_when_no_hash():
    m = _make_manager()
    db = AsyncMock()

    user = MagicMock()
    user.id = "uid"
    user.hashed_password = None
    user.password_history = []

    await m._push_password_history(user, db)
    db.execute.assert_not_called()
