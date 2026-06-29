"""
Phase 4 Gate — Enterprise BYOIDP unit tests.

Verifies:
- HMAC state generation/verification for enterprise flow
- Client secret Fernet encrypt/decrypt roundtrip
- Role mapping: IDP groups → Casbin roles
- State replay / expiry prevention
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

SECRET = "test-secret-key-for-unit-tests-min-32-chars!!"


def test_enterprise_state_roundtrip():
    from app.identity.enterprise import _make_enterprise_state, _verify_enterprise_state
    tid = uuid.uuid4()
    state = _make_enterprise_state(tid, SECRET)
    returned_tid = _verify_enterprise_state(state, SECRET)
    assert returned_tid == str(tid)


def test_enterprise_state_wrong_secret():
    from fastapi import HTTPException

    from app.identity.enterprise import _make_enterprise_state, _verify_enterprise_state
    tid = uuid.uuid4()
    state = _make_enterprise_state(tid, SECRET)
    with pytest.raises(HTTPException) as exc:
        _verify_enterprise_state(state, "wrong-secret-key-at-least-32-chars!!!")
    assert exc.value.status_code == 400


def test_enterprise_state_expired():
    from fastapi import HTTPException

    from app.identity.enterprise import _make_enterprise_state, _verify_enterprise_state
    tid = uuid.uuid4()
    state = _make_enterprise_state(tid, SECRET)
    # Simulate expiry by calling with max_age=-1 (any non-zero age exceeds -1)
    with pytest.raises(HTTPException) as exc:
        _verify_enterprise_state(state, SECRET, max_age=-1)
    assert exc.value.status_code == 400


def test_enterprise_state_tampered():
    import base64

    from fastapi import HTTPException

    from app.identity.enterprise import _make_enterprise_state, _verify_enterprise_state
    tid = uuid.uuid4()
    state = _make_enterprise_state(tid, SECRET)
    # Tamper with the state
    decoded = base64.urlsafe_b64decode(state.encode()).decode()
    parts = decoded.rsplit(":", 3)
    tampered_tid = str(uuid.uuid4())
    tampered = f"{tampered_tid}:{parts[1]}:{parts[2]}:{parts[3]}"
    tampered_state = base64.urlsafe_b64encode(tampered.encode()).decode()
    with pytest.raises(HTTPException) as exc:
        _verify_enterprise_state(tampered_state, SECRET)
    assert exc.value.status_code == 400


def test_client_secret_encrypt_decrypt():
    from app.identity.enterprise import _decrypt_client_secret, _encrypt_client_secret
    original = "super-secret-idp-client-secret"
    enc = _encrypt_client_secret(original)
    assert enc != original
    assert _decrypt_client_secret(enc) == original


import pytest


@pytest.mark.asyncio
async def test_role_mapping_applied():
    from app.identity.enterprise import _apply_role_mapping

    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()

    mock_config = MagicMock()
    mock_config.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    mock_config.role_mapping = {"Admins": "admin", "Engineers": "member"}

    userinfo = {"groups": ["Admins", "Engineers", "Unknown"]}

    mock_db = AsyncMock()

    # Patch the enforcer at its actual location in the authz module
    with patch("app.identity.enterprise.casbin_enforcer") as mock_enforcer:
        mock_enforcer.safe_add_role_for_user = AsyncMock(return_value=True)
        await _apply_role_mapping(mock_user, userinfo, mock_config, mock_db)
        # "Admins" → "admin", "Engineers" → "member", "Unknown" is unmapped → skipped
        assert mock_enforcer.safe_add_role_for_user.call_count == 2


@pytest.mark.asyncio
async def test_role_mapping_skips_unmapped_groups():
    from app.identity.enterprise import _apply_role_mapping

    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()

    mock_config = MagicMock()
    mock_config.tenant_id = uuid.uuid4()
    mock_config.role_mapping = {}  # no mappings configured

    userinfo = {"groups": ["Admins", "SomeGroup"]}
    mock_db = AsyncMock()

    with patch("app.identity.enterprise.casbin_enforcer") as mock_enforcer:
        mock_enforcer.safe_add_role_for_user = AsyncMock(return_value=True)
        await _apply_role_mapping(mock_user, userinfo, mock_config, mock_db)
        mock_enforcer.safe_add_role_for_user.assert_not_called()
