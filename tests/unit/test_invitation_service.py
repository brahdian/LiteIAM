"""Unit tests for app.identity.invitation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.identity.invitation import (
    _hash_token,
    accept_invitation,
    create_invitation,
    list_invitations,
    revoke_invitation,
    verify_invitation,
)
from app.models.invitation import UserInvitation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inv(
    email="user@example.com",
    token_hash="abc123",
    accepted_at=None,
    expires_delta=timedelta(hours=24),
    tenant_id=None,
    role="member",
):
    """Build a mock UserInvitation."""
    i = MagicMock(spec=UserInvitation)
    i.id = uuid.uuid4()
    i.tenant_id = tenant_id or uuid.uuid4()
    i.email = email
    i.token_hash = token_hash
    i.role = role
    i.accepted_at = accepted_at
    i.expires_at = datetime.now(UTC) + expires_delta
    i.created_at = datetime.now(UTC)
    return i


def _db_that_returns(result=None):
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=result)
    db.scalars = AsyncMock()
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# _hash_token
# ---------------------------------------------------------------------------

def test_hash_token_is_deterministic():
    assert _hash_token("abc") == _hash_token("abc")


def test_hash_token_different_inputs_differ():
    assert _hash_token("abc") != _hash_token("xyz")


def test_hash_token_length():
    assert len(_hash_token("token")) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# create_invitation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_invitation_returns_raw_token():
    db = _db_that_returns(result=None)  # no existing invitation
    token = await create_invitation(
        tenant_id=uuid.uuid4(),
        email="new@example.com",
        db=db,
    )
    assert isinstance(token, str)
    assert len(token) > 20


@pytest.mark.asyncio
async def test_create_invitation_adds_to_db():
    db = _db_that_returns(result=None)
    await create_invitation(
        tenant_id=uuid.uuid4(),
        email="user@example.com",
        db=db,
    )
    db.add.assert_called_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_invitation_deletes_existing_pending():
    existing = _inv()
    db = _db_that_returns(result=existing)
    await create_invitation(
        tenant_id=uuid.uuid4(),
        email="user@example.com",
        db=db,
    )
    db.delete.assert_awaited_once_with(existing)


@pytest.mark.asyncio
async def test_create_invitation_lowercases_email():
    db = _db_that_returns(result=None)
    await create_invitation(
        tenant_id=uuid.uuid4(),
        email="USER@EXAMPLE.COM",
        db=db,
    )
    added_inv = db.add.call_args[0][0]
    assert added_inv.email == "user@example.com"


# ---------------------------------------------------------------------------
# verify_invitation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_returns_invitation_when_valid():
    raw = "good-token"
    inv = _inv(email="u@example.com", token_hash=_hash_token(raw))
    db = _db_that_returns(result=inv)
    result = await verify_invitation(raw, "u@example.com", db)
    assert result is inv


@pytest.mark.asyncio
async def test_verify_returns_none_when_not_found():
    db = _db_that_returns(result=None)
    result = await verify_invitation("bad-token", "u@example.com", db)
    assert result is None


# ---------------------------------------------------------------------------
# accept_invitation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_accept_sets_accepted_at():
    inv = _inv()
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()

    await accept_invitation(inv, db)

    assert inv.accepted_at is not None
    db.add.assert_called_once_with(inv)
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# revoke_invitation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_returns_true_when_found():
    inv = _inv()
    db = _db_that_returns(result=inv)
    result = await revoke_invitation(inv.id, inv.tenant_id, db)
    assert result is True
    db.delete.assert_awaited_once_with(inv)


@pytest.mark.asyncio
async def test_revoke_returns_false_when_not_found():
    db = _db_that_returns(result=None)
    result = await revoke_invitation(uuid.uuid4(), uuid.uuid4(), db)
    assert result is False


# ---------------------------------------------------------------------------
# list_invitations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_returns_formatted_dicts():
    pending = _inv(email="p@example.com", role="member")
    accepted = _inv(email="a@example.com", role="admin",
                    accepted_at=datetime.now(UTC))

    db = AsyncMock()
    db.scalars = AsyncMock(return_value=AsyncMock(__iter__=lambda self: iter([pending, accepted])))
    # Make scalars return an iterable
    mock_result = MagicMock()
    mock_result.__iter__ = MagicMock(return_value=iter([pending, accepted]))
    db.scalars = AsyncMock(return_value=mock_result)

    results = await list_invitations(uuid.uuid4(), db)
    assert len(results) == 2

    statuses = {r["email"]: r["status"] for r in results}
    assert statuses["p@example.com"] == "pending"
    assert statuses["a@example.com"] == "accepted"
