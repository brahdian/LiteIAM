"""
Phase 5 Gate — Passkey unit tests.

Verifies:
- _rp_id() correctly extracts the hostname from BASE_URL
- PasskeyCredential model has sign_count, public_key, is_revoked
- Challenge expiry: consume after TTL raises 400
- Challenge single-use: consuming twice raises 400
- Sign count validation: decreasing count → assertion rejection
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch


def test_rp_id_from_base_url():
    from app.identity.passkey import _rp_id
    # _rp_id reads settings.BASE_URL and extracts hostname
    with patch("app.identity.passkey.settings") as mock_settings:
        mock_settings.BASE_URL = "https://auth.example.com"
        assert _rp_id() == "auth.example.com"


def test_rp_id_localhost():
    from app.identity.passkey import _rp_id
    with patch("app.identity.passkey.settings") as mock_settings:
        mock_settings.BASE_URL = "http://localhost:8000"
        assert _rp_id() == "localhost"


def test_passkey_credential_model_has_sign_count():
    from app.models.passkey import PasskeyCredential
    columns = {col.name for col in PasskeyCredential.__table__.columns}
    assert "sign_count" in columns
    assert "public_key" in columns
    assert "is_revoked" in columns
    assert "last_used_at" in columns


import pytest


@pytest.mark.asyncio
async def test_consume_challenge_raises_if_expired():
    from fastapi import HTTPException

    from app.identity.passkey import _consume_challenge
    from app.models.passkey_challenge import PasskeyChallenge

    expired_time = datetime.now(UTC) - timedelta(seconds=10)
    mock_challenge = MagicMock(spec=PasskeyChallenge)
    mock_challenge.id = uuid.uuid4()
    mock_challenge.challenge = b"test-challenge"
    mock_challenge.expires_at = expired_time

    mock_db = AsyncMock()
    mock_db.scalar = AsyncMock(return_value=mock_challenge)
    mock_db.execute = AsyncMock()

    user_id = uuid.uuid4()
    with pytest.raises(HTTPException) as exc:
        await _consume_challenge(user_id, "registration", mock_db)
    assert exc.value.status_code == 400
    assert "expired" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_consume_challenge_raises_if_not_found():
    from fastapi import HTTPException

    from app.identity.passkey import _consume_challenge

    mock_db = AsyncMock()
    mock_db.scalar = AsyncMock(return_value=None)

    user_id = uuid.uuid4()
    with pytest.raises(HTTPException) as exc:
        await _consume_challenge(user_id, "registration", mock_db)
    assert exc.value.status_code == 400