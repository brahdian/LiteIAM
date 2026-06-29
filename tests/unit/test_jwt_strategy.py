"""
Phase 1 Gate — JWT strategy tests.
Verifies: RSA signing, tenant_id claim injection, mfa_pending rejection,
auth_stage enforcement, kid in header.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _make_rsa_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _make_key_manager(private_pem, public_pem, kid="test-kid"):
    from app.tokens.keys import KeyManager
    km = KeyManager()
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._valid_jwks = [{"kid": kid, "kty": "RSA"}]
    # Override get_public_pem_by_kid to return the test public key
    km.get_public_pem_by_kid = lambda k: public_pem if k == kid else None
    return km


@pytest.mark.asyncio
async def test_write_token_contains_tenant_id():
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem)
    strategy = TenantAwareJWTStrategy(km)

    tenant_id = uuid.uuid4()
    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "user@example.com"
    user.tenant_id = tenant_id

    token = await strategy.write_token(user)
    public_key = serialization.load_pem_public_key(public_pem)
    payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=["open-auth:auth"])

    assert payload["tenant_id"] == str(tenant_id)
    assert payload["auth_stage"] == "complete"
    assert payload["email"] == "user@example.com"
    assert payload["sub"] == str(user.id)


@pytest.mark.asyncio
async def test_write_token_uses_rs256():
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem, kid="rotation-kid-1")
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "u@x.com"
    user.tenant_id = uuid.uuid4()

    token = await strategy.write_token(user)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"] == "rotation-kid-1"


@pytest.mark.asyncio
async def test_mfa_pending_token_auth_stage():
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem)
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "u@x.com"
    user.tenant_id = uuid.uuid4()

    pending = await strategy.write_mfa_pending_token(user)
    public_key = serialization.load_pem_public_key(public_pem)
    payload = jwt.decode(pending, public_key, algorithms=["RS256"], audience=["open-auth:auth"])

    assert payload["auth_stage"] == "mfa_pending"
    assert "email" not in payload  # pending token has minimal claims


@pytest.mark.asyncio
async def test_read_token_rejects_mfa_pending():
    """read_token must return None for mfa_pending tokens — they cannot access resources."""
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem)
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "u@x.com"
    user.tenant_id = uuid.uuid4()

    pending = await strategy.write_mfa_pending_token(user)
    user_manager = MagicMock()
    result = await strategy.read_token(pending, user_manager)
    assert result is None


@pytest.mark.asyncio
async def test_read_mfa_pending_token_roundtrip():
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem)
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "u@x.com"
    user.tenant_id = uuid.uuid4()

    pending = await strategy.write_mfa_pending_token(user)
    payload = await strategy.read_mfa_pending_token(pending)
    assert payload is not None
    assert payload["sub"] == str(user.id)
    assert payload["auth_stage"] == "mfa_pending"


@pytest.mark.asyncio
async def test_read_token_rejects_expired():
    from datetime import timedelta

    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    km = _make_key_manager(private_pem, public_pem)
    strategy = TenantAwareJWTStrategy(km)

    # Create token with -1s lifetime (already expired)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    now = datetime.now(UTC)
    payload = {
        "sub": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "auth_stage": "complete",
        "aud": ["open-auth:auth"],
        "iat": now,
        "exp": now - timedelta(seconds=1),
    }
    private_key = load_pem_private_key(private_pem, password=None)
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-kid"})

    result = await strategy.read_token(token, MagicMock())
    assert result is None
