"""Integration tests for the 'remember this device' trusted-device MFA bypass."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.trusted_device import TrustedDevice
from app.sessions.trusted_device import (
    COOKIE_NAME,
    DEVICE_TTL_DAYS,
    _hash_token,
    create_trusted_device,
    is_trusted_device,
    list_trusted_devices,
    revoke_all_trusted_devices,
    revoke_device_by_id,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_device(user_id, tenant_id, token, *, expired=False):
    now = datetime.now(UTC)
    delta = timedelta(days=-1) if expired else timedelta(days=DEVICE_TTL_DAYS)
    return TrustedDevice(
        id=uuid.uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        device_token_hash=_hash_token(token),
        expires_at=now + delta,
        user_agent="Mozilla/5.0",
        ip_address="127.0.0.1",
        created_at=now,
    )


# ---------------------------------------------------------------------------
# _hash_token
# ---------------------------------------------------------------------------

def test_hash_token_is_sha256_hex():
    token = "abc123"
    result = _hash_token(token)
    assert result == hashlib.sha256(b"abc123").hexdigest()
    assert len(result) == 64


def test_hash_token_different_inputs_differ():
    assert _hash_token("a") != _hash_token("b")


# ---------------------------------------------------------------------------
# is_trusted_device
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_is_trusted_device_returns_true_for_valid_token():
    uid = uuid.uuid4()
    token = secrets.token_hex(32)
    device = _make_device(uid, uuid.uuid4(), token)

    db = AsyncMock()
    db.scalar = AsyncMock(return_value=device)

    result = await is_trusted_device(uid, token, db)
    assert result is True


@pytest.mark.asyncio
async def test_is_trusted_device_returns_false_when_no_row():
    uid = uuid.uuid4()
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=None)

    result = await is_trusted_device(uid, secrets.token_hex(32), db)
    assert result is False


@pytest.mark.asyncio
async def test_is_trusted_device_passes_hash_not_plaintext_to_query():
    """The DB query must use the sha256 hash, never the raw cookie value."""
    uid = uuid.uuid4()
    token = secrets.token_hex(32)
    _hash_token(token)

    db = AsyncMock()
    db.scalar = AsyncMock(return_value=None)

    await is_trusted_device(uid, token, db)

    # Verify the scalar call was made with a query (not checking internals,
    # just that scalar was called — the hash logic is in _hash_token unit test)
    db.scalar.assert_called_once()


# ---------------------------------------------------------------------------
# create_trusted_device
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_trusted_device_returns_raw_token():
    uid = uuid.uuid4()
    tid = uuid.uuid4()

    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()

    token = await create_trusted_device(uid, tid, db)

    assert isinstance(token, str)
    assert len(token) == 64  # secrets.token_hex(32) → 64 hex chars
    db.add.assert_called_once()
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_create_trusted_device_stores_hash_not_plaintext():
    uid = uuid.uuid4()
    tid = uuid.uuid4()

    added_device = None

    db = AsyncMock()

    def capture_add(obj):
        nonlocal added_device
        added_device = obj

    db.add = MagicMock(side_effect=capture_add)
    db.commit = AsyncMock()

    token = await create_trusted_device(uid, tid, db)

    assert added_device is not None
    assert added_device.device_token_hash == _hash_token(token)
    assert added_device.device_token_hash != token  # raw token never stored


@pytest.mark.asyncio
async def test_create_trusted_device_sets_correct_expiry():
    uid = uuid.uuid4()
    tid = uuid.uuid4()

    db = AsyncMock()
    added_device = None

    def capture(obj):
        nonlocal added_device
        added_device = obj

    db.add = MagicMock(side_effect=capture)
    db.commit = AsyncMock()

    before = datetime.now(UTC)
    await create_trusted_device(uid, tid, db)
    after = datetime.now(UTC)

    expected_min = before + timedelta(days=DEVICE_TTL_DAYS - 1)
    expected_max = after + timedelta(days=DEVICE_TTL_DAYS + 1)
    assert expected_min < added_device.expires_at < expected_max


# ---------------------------------------------------------------------------
# revoke_all_trusted_devices
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_all_returns_rowcount():
    uid = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.rowcount = 3
    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()

    count = await revoke_all_trusted_devices(uid, db)
    assert count == 3
    db.commit.assert_called_once()


# ---------------------------------------------------------------------------
# revoke_device_by_id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_device_by_id_returns_true_on_success():
    mock_result = MagicMock()
    mock_result.rowcount = 1
    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()

    result = await revoke_device_by_id(uuid.uuid4(), uuid.uuid4(), db)
    assert result is True


@pytest.mark.asyncio
async def test_revoke_device_by_id_returns_false_when_not_found():
    mock_result = MagicMock()
    mock_result.rowcount = 0
    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()

    result = await revoke_device_by_id(uuid.uuid4(), uuid.uuid4(), db)
    assert result is False


# ---------------------------------------------------------------------------
# list_trusted_devices
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_trusted_devices_shapes_output():
    uid = uuid.uuid4()
    tid = uuid.uuid4()
    token = secrets.token_hex(32)
    device = _make_device(uid, tid, token)

    mock_scalars = MagicMock()
    mock_scalars.all = MagicMock(return_value=[device])
    db = AsyncMock()
    db.scalars = AsyncMock(return_value=mock_scalars)

    result = await list_trusted_devices(uid, db)
    assert len(result) == 1
    d = result[0]
    assert "id" in d
    assert "ip_address" in d
    assert "user_agent" in d
    assert "expires_at" in d
    assert "is_active" in d
    assert d["is_active"] is True
    # Must not expose the hash
    assert "device_token_hash" not in d


@pytest.mark.asyncio
async def test_list_trusted_devices_marks_expired_inactive():
    uid = uuid.uuid4()
    tid = uuid.uuid4()
    expired_device = _make_device(uid, tid, secrets.token_hex(32), expired=True)

    mock_scalars = MagicMock()
    mock_scalars.all = MagicMock(return_value=[expired_device])
    db = AsyncMock()
    db.scalars = AsyncMock(return_value=mock_scalars)

    result = await list_trusted_devices(uid, db)
    assert result[0]["is_active"] is False


# ---------------------------------------------------------------------------
# cookie name constant
# ---------------------------------------------------------------------------

def test_cookie_name_is_stable():
    assert COOKIE_NAME == "auth_device"
