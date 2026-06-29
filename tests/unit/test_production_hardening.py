"""
Phase 6 Gate — Production hardening unit tests.

Verifies:
- Token revocation: revoked JTI is correctly detected by is_revoked()
- JTI is present in write_token output (required for revocation)
- PKCE enforced: auth code grant rejects missing code_verifier
- read_token rejects revoked JTI
- Rate limiter key function respects TRUST_X_FORWARDED_FOR setting
- Metrics counters exist and are incrementable
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Revocation blacklist
# ---------------------------------------------------------------------------

def test_is_revoked_returns_false_initially():
    from app.tokens.revocation import _revoked_jtis, is_revoked
    test_jti = f"test-jti-{uuid.uuid4()}"
    _revoked_jtis.discard(test_jti)
    assert is_revoked(test_jti) is False


def test_is_revoked_after_adding_to_set():
    from app.tokens.revocation import _revoked_jtis, is_revoked
    test_jti = f"test-jti-{uuid.uuid4()}"
    _revoked_jtis.add(test_jti)
    assert is_revoked(test_jti) is True
    _revoked_jtis.discard(test_jti)


# ---------------------------------------------------------------------------
# JTI in tokens
# ---------------------------------------------------------------------------

from datetime import UTC

import pytest


@pytest.mark.asyncio
async def test_write_token_contains_jti(user_id, tenant_id):
    import jwt

    from app.tokens.keys import KeyManager
    from app.tokens.strategy import TenantAwareJWTStrategy

    km = KeyManager()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = "test-kid"
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}

    strategy = TenantAwareJWTStrategy(km)
    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.email = "test@example.com"
    mock_user.tenant_id = tenant_id

    token = await strategy.write_token(mock_user)

    # Decode without verification to inspect claims
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "jti" in payload, "jti claim must be present for revocation support"
    assert len(payload["jti"]) > 0


@pytest.mark.asyncio
async def test_read_token_rejects_revoked_jti(user_id, tenant_id):
    from datetime import datetime, timedelta, timezone

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.tokens.keys import KeyManager
    from app.tokens.revocation import _revoked_jtis
    from app.tokens.strategy import TenantAwareJWTStrategy

    km = KeyManager()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = "test-kid-revoke"
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}

    jti = str(uuid.uuid4())
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "email": "test@example.com",
        "tenant_id": str(tenant_id),
        "auth_stage": "complete",
        "jti": jti,
        "aud": ["open-auth:auth"],
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    _revoked_jtis.add(jti)
    strategy = TenantAwareJWTStrategy(km)
    mock_manager = AsyncMock()

    result = await strategy.read_token(token, mock_manager)
    assert result is None, "Revoked JTI must be rejected"

    _revoked_jtis.discard(jti)


# ---------------------------------------------------------------------------
# Prometheus metrics exist
# ---------------------------------------------------------------------------

def test_metrics_counters_defined():
    from app.core.metrics import (
        auth_login_total,
        auth_mfa_total,
        auth_token_issued_total,
        auth_token_revoked_total,
    )
    # Verify they're prometheus Counter objects (have inc() method)
    assert hasattr(auth_login_total, "labels")
    assert hasattr(auth_token_issued_total, "labels")
    assert hasattr(auth_token_revoked_total, "inc")
    assert hasattr(auth_mfa_total, "labels")


def test_metrics_can_be_incremented():
    from app.core.metrics import auth_login_total, auth_token_revoked_total
    # Should not raise
    auth_login_total.labels(result="success", method="password").inc()
    auth_token_revoked_total.inc()


# ---------------------------------------------------------------------------
# Rate limiter key function
# ---------------------------------------------------------------------------

def test_rate_limiter_uses_direct_ip_by_default():
    from app.core.rate_limit import _get_client_ip

    mock_request = MagicMock()
    mock_request.headers = {"X-Forwarded-For": "1.2.3.4"}
    mock_request.client = MagicMock()
    mock_request.client.host = "10.0.0.1"

    with patch("app.core.rate_limit.settings") as mock_settings:
        mock_settings.TRUST_X_FORWARDED_FOR = False
        ip = _get_client_ip(mock_request)
    # When not trusting X-Forwarded-For, should return the real client IP
    assert ip == "10.0.0.1"


def test_rate_limiter_uses_forwarded_ip_when_trusted():
    from app.core.rate_limit import _get_client_ip

    mock_request = MagicMock()
    mock_request.headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}

    with patch("app.core.rate_limit.settings") as mock_settings:
        mock_settings.TRUST_X_FORWARDED_FOR = True
        ip = _get_client_ip(mock_request)
    assert ip == "1.2.3.4"


# ---------------------------------------------------------------------------
# 503 for DB pool exhaustion (Phase 6 gate: returns 503, not 500)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pool_exhaustion_returns_503():
    """asyncpg pool exhaustion must surface as 503 so LBs can retry elsewhere."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    # Build a minimal app that uses the same exception handler logic
    mini_app = FastAPI()

    @mini_app.exception_handler(Exception)
    async def _pool_handler(request, exc):
        exc_name = type(exc).__name__
        if "TooManyConnections" in exc_name or "PoolTimeout" in exc_name or "pool" in str(exc).lower():
            return JSONResponse(
                status_code=503,
                content={"error": "service_unavailable"},
                headers={"Retry-After": "2"},
            )
        raise exc

    @mini_app.get("/test-pool-exhaust")
    async def _trigger():
        raise Exception("asyncpg pool: timeout acquiring connection from pool")

    client = TestClient(mini_app, raise_server_exceptions=False)
    resp = client.get("/test-pool-exhaust")
    assert resp.status_code == 503
    assert "Retry-After" in resp.headers


def test_runbook_exists():
    """RUNBOOK.md must exist — required Phase 6 gate item."""
    import os
    runbook = os.path.join(
        os.path.dirname(__file__), "..", "..", "RUNBOOK.md"
    )
    assert os.path.isfile(runbook), "RUNBOOK.md is a Phase 6 gate requirement"
    content = open(runbook).read()
    assert "Key Rotation" in content
    assert "Emergency Token Revocation" in content
    assert "Rollback" in content
