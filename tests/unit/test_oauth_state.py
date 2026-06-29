"""
Phase 1 Gate — OAuth state tests.
Verifies: HMAC generation, tenant extraction, replay prevention, freshness.
"""
from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from app.identity.social import generate_oauth_state, verify_oauth_state

SECRET = "test-secret-key-for-unit-tests-min-32-chars!!"
TENANT_ID = str(uuid.uuid4())


def _mock_not_revoked(jti: str) -> bool:
    return False


def test_generate_and_verify_roundtrip():
    state = generate_oauth_state(TENANT_ID, SECRET)
    with patch("app.identity.social.is_revoked", _mock_not_revoked):
        tenant_id, nonce = verify_oauth_state(state, SECRET)
    assert tenant_id == TENANT_ID
    assert nonce  # non-empty


def test_wrong_secret_rejected():
    from fastapi import HTTPException
    state = generate_oauth_state(TENANT_ID, SECRET)
    with patch("app.identity.social.is_revoked", _mock_not_revoked):
        with pytest.raises(HTTPException) as exc:
            verify_oauth_state(state, "wrong-secret-completely-different!!")
    assert exc.value.status_code == 400
    assert "signature" in exc.value.detail.lower()


def test_tampered_tenant_rejected():
    from fastapi import HTTPException
    other_tenant = str(uuid.uuid4())
    tampered = generate_oauth_state(other_tenant, SECRET + "x")  # wrong secret too
    with patch("app.identity.social.is_revoked", _mock_not_revoked):
        with pytest.raises(HTTPException):
            verify_oauth_state(tampered, SECRET)


def test_expired_state_rejected():
    from fastapi import HTTPException
    with patch("app.identity.social.time") as mock_time:
        mock_time.time.return_value = 1_000_000
        state = generate_oauth_state(TENANT_ID, SECRET)
    with patch("app.identity.social.time") as mock_time:
        mock_time.time.return_value = 1_000_600
        with patch("app.identity.social.is_revoked", _mock_not_revoked):
            with pytest.raises(HTTPException) as exc:
                verify_oauth_state(state, SECRET, max_age_seconds=300)
    assert exc.value.status_code == 400
    assert "expired" in exc.value.detail.lower()


def test_fresh_state_within_window():
    with patch("app.identity.social.time") as mock_time:
        mock_time.time.return_value = 1_000_000
        state = generate_oauth_state(TENANT_ID, SECRET)
    with patch("app.identity.social.time") as mock_time:
        mock_time.time.return_value = 1_000_200  # 200s later, within 300s window
        with patch("app.identity.social.is_revoked", _mock_not_revoked):
            tenant_id, nonce = verify_oauth_state(state, SECRET, max_age_seconds=300)
    assert tenant_id == TENANT_ID


def test_malformed_state_rejected():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        verify_oauth_state("not-valid-base64!!!!", SECRET)
    assert exc.value.status_code == 400


def test_different_tenants_produce_different_states():
    state_a = generate_oauth_state("tenant-a", SECRET)
    state_b = generate_oauth_state("tenant-b", SECRET)
    assert state_a != state_b


def test_replay_produces_different_nonce():
    """Each call generates a fresh nonce — states are not deterministic."""
    state1 = generate_oauth_state(TENANT_ID, SECRET)
    state2 = generate_oauth_state(TENANT_ID, SECRET)
    assert state1 != state2
    # But both should be valid (when not revoked)
    with patch("app.identity.social.is_revoked", _mock_not_revoked):
        tid1, _ = verify_oauth_state(state1, SECRET)
        tid2, _ = verify_oauth_state(state2, SECRET)
    assert tid1 == TENANT_ID
    assert tid2 == TENANT_ID


def test_replay_attack_rejected():
    """Phase 6 gate: a consumed nonce must be rejected on replay."""
    from fastapi import HTTPException
    state = generate_oauth_state(TENANT_ID, SECRET)
    # Simulate the nonce already being consumed (in-memory revocation set)
    def _mock_revoked(jti: str) -> bool:
        return True  # pretend every nonce is already consumed

    with patch("app.identity.social.is_revoked", _mock_revoked):
        with pytest.raises(HTTPException) as exc:
            verify_oauth_state(state, SECRET)
    assert exc.value.status_code == 400
    assert "already used" in exc.value.detail.lower()
