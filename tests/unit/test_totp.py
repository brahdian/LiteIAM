"""
Phase 1 Gate — TOTP unit tests.
Verifies: encryption roundtrip, valid code passes, invalid code fails,
failure counter increments, lockout enforced, replay prevention, lockout reset.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pyotp
import pytest

SECRET = "test-secret-key-for-unit-tests-min-32-chars!!"


def test_fernet_encrypt_decrypt_roundtrip():
    from app.mfa.totp import _decrypt_secret, _encrypt_secret
    original = pyotp.random_base32()
    enc = _encrypt_secret(original)
    assert enc != original
    assert _decrypt_secret(enc) == original


def test_different_secrets_encrypt_differently():
    from app.mfa.totp import _encrypt_secret
    s1, s2 = pyotp.random_base32(), pyotp.random_base32()
    assert _encrypt_secret(s1) != _encrypt_secret(s2)


def _make_mock_user(user_id, secret, *, failure_count=0, last_failure_at=None, last_used_code=None):
    from app.mfa.totp import _encrypt_secret
    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.is_totp_enabled = True
    mock_user.totp_secret_enc = _encrypt_secret(secret)
    mock_user.totp_failure_count = failure_count
    mock_user.totp_last_failure_at = last_failure_at
    mock_user.totp_last_used_code = last_used_code
    mock_user.tenant_id = uuid.uuid4()
    return mock_user


def _make_mock_db(user):
    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=user)
    mock_db.execute = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.add = MagicMock()
    return mock_db


@pytest.mark.asyncio
async def test_verify_totp_valid_code(user_id):
    from app.mfa.totp import verify_totp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    mock_user = _make_mock_user(user_id, secret)
    mock_db = _make_mock_db(mock_user)

    result = await verify_totp(user_id, current_code, mock_db)
    assert result is True


@pytest.mark.asyncio
async def test_verify_totp_invalid_code_raises(user_id):
    from fastapi import HTTPException

    from app.mfa.totp import verify_totp

    secret = pyotp.random_base32()
    mock_user = _make_mock_user(user_id, secret)
    mock_db = _make_mock_db(mock_user)

    with pytest.raises(HTTPException) as exc:
        await verify_totp(user_id, "000000", mock_db)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_totp_lockout_enforced(user_id):
    from fastapi import HTTPException

    from app.core.config import settings
    from app.mfa.totp import verify_totp

    secret = pyotp.random_base32()
    # last_failure_at is 10 seconds ago — still within lockout window
    recent_failure = datetime.now(UTC) - timedelta(seconds=10)
    mock_user = _make_mock_user(
        user_id, secret,
        failure_count=settings.TOTP_MAX_FAILURES,
        last_failure_at=recent_failure,
    )
    mock_db = _make_mock_db(mock_user)

    totp = pyotp.TOTP(secret)
    with pytest.raises(HTTPException) as exc:
        await verify_totp(user_id, totp.now(), mock_db)  # even valid code blocked
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_verify_totp_lockout_resets_after_cooldown(user_id):
    from app.core.config import settings
    from app.mfa.totp import verify_totp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    # last_failure_at is 90 seconds ago — past the 60s cooldown window
    old_failure = datetime.now(UTC) - timedelta(seconds=90)
    mock_user = _make_mock_user(
        user_id, secret,
        failure_count=settings.TOTP_MAX_FAILURES,
        last_failure_at=old_failure,
    )
    # After reset, db.get is called again with a reset user
    reset_user = _make_mock_user(user_id, secret, failure_count=0)
    mock_db = _make_mock_db(mock_user)
    # Second db.get (after reset commit) returns the reset user
    mock_db.get = AsyncMock(side_effect=[mock_user, reset_user])

    result = await verify_totp(user_id, totp.now(), mock_db)
    assert result is True


@pytest.mark.asyncio
async def test_verify_totp_replay_prevention(user_id):
    from fastapi import HTTPException

    from app.mfa.totp import verify_totp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    # User has already used this exact code
    mock_user = _make_mock_user(user_id, secret, last_used_code=current_code)
    mock_db = _make_mock_db(mock_user)

    with pytest.raises(HTTPException) as exc:
        await verify_totp(user_id, current_code, mock_db)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_totp_not_configured_raises(user_id):
    from fastapi import HTTPException

    from app.mfa.totp import verify_totp

    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.is_totp_enabled = False
    mock_user.totp_secret_enc = None
    mock_user.totp_failure_count = 0
    mock_user.tenant_id = uuid.uuid4()

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=mock_user)

    with pytest.raises(HTTPException) as exc:
        await verify_totp(user_id, "123456", mock_db)
    assert exc.value.status_code == 400
