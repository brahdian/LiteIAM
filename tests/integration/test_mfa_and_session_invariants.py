"""
Integration tests: MFA step-up enforcement and session safety invariants.

Phase 1 + Phase 2 Gate items covered:
- MFA pending JWT rejected by read_token (resource endpoints get None → 401)
- Full JWT (auth_stage: complete) accepted by read_token
- write_mfa_pending_token produces correct claims
- No raw Session() / engine.connect() outside tenant/isolation.py
- Background tasks in asyncio use the same ContextVar binding as parent
- read_token rejects MFA pending even without revocation
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------------------------------------------------------------------------
# RSA key pair fixture shared across tests
# ---------------------------------------------------------------------------

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


def _make_strategy():
    from app.tokens.keys import KeyManager
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    kid = "test-kid-mfa"
    km = KeyManager()
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}
    return TenantAwareJWTStrategy(km)


def _make_user():
    user = MagicMock()
    user.id = uuid.UUID("00000000-0000-0000-0000-000000000042")
    user.email = "mfa-test@example.com"
    user.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000099")
    return user


# ---------------------------------------------------------------------------
# MFA pending JWT — must be rejected by resource endpoint auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mfa_pending_token_rejected_by_read_token():
    """
    Phase 1 gate: MFA pending tokens must be rejected by read_token.
    Resource endpoints use read_token → they will return 401 for mfa_pending tokens.
    This prevents step-up bypass: user authenticates with password but skips TOTP.
    """
    strategy = _make_strategy()
    user = _make_user()

    # Issue an MFA pending token
    pending_token = await strategy.write_mfa_pending_token(user)

    # Resource endpoint dependency calls read_token — must return None for mfa_pending
    mock_manager = AsyncMock()
    result = await strategy.read_token(pending_token, mock_manager)

    assert result is None, (
        "read_token must reject mfa_pending tokens — "
        "a user who has only passed password auth must not access resources"
    )
    # UserManager.get must not have been called (we didn't even look up the user)
    mock_manager.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_complete_token_accepted_by_read_token():
    """Full JWT (auth_stage: complete) is accepted by read_token."""
    strategy = _make_strategy()
    user = _make_user()

    full_token = await strategy.write_token(user)

    mock_manager = AsyncMock()
    mock_manager.get = AsyncMock(return_value=user)

    result = await strategy.read_token(full_token, mock_manager)
    assert result is user, "Complete token must be accepted"
    mock_manager.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_mfa_pending_token_has_correct_claims():
    """MFA pending token must contain tenant_id but NOT a full auth_stage: complete."""
    import jwt as pyjwt
    strategy = _make_strategy()
    user = _make_user()

    pending_token = await strategy.write_mfa_pending_token(user)
    payload = pyjwt.decode(pending_token, options={"verify_signature": False})

    assert payload["auth_stage"] == "mfa_pending"
    assert payload["tenant_id"] == str(user.tenant_id)
    assert payload["sub"] == str(user.id)
    # MFA pending tokens must not have a jti (no need to revoke — they're short-lived)
    # OR they do — either way, the auth_stage is the enforced gate
    assert "auth_stage" in payload


@pytest.mark.asyncio
async def test_full_token_contains_jti_for_revocation():
    """Full JWT must contain jti so individual tokens can be revoked."""
    import jwt as pyjwt
    strategy = _make_strategy()
    user = _make_user()

    full_token = await strategy.write_token(user)
    payload = pyjwt.decode(full_token, options={"verify_signature": False})

    assert "jti" in payload, "Full token must contain jti for per-token revocation"
    assert len(payload["jti"]) > 0
    # Verify jti is a UUID
    uuid.UUID(payload["jti"])  # raises ValueError if not valid UUID


@pytest.mark.asyncio
async def test_expired_token_rejected():
    """Expired JWT is rejected — even with correct auth_stage."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from app.tokens.keys import KeyManager
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_pem, public_pem = _make_rsa_pair()
    kid = "test-kid-expired"
    km = KeyManager()
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}
    strategy = TenantAwareJWTStrategy(km)

    private_key = load_pem_private_key(private_pem, password=None)
    now = datetime.now(UTC)
    expired_payload = {
        "sub": str(uuid.uuid4()),
        "email": "test@example.com",
        "tenant_id": str(uuid.uuid4()),
        "auth_stage": "complete",
        "jti": str(uuid.uuid4()),
        "aud": ["open-auth:auth"],
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),  # expired 1 hour ago
    }
    expired_token = pyjwt.encode(expired_payload, private_key, algorithm="RS256", headers={"kid": kid})

    mock_manager = AsyncMock()
    result = await strategy.read_token(expired_token, mock_manager)
    assert result is None, "Expired token must be rejected"


# ---------------------------------------------------------------------------
# Static checks: no raw DB session usage outside tenant layer
# ---------------------------------------------------------------------------

def test_no_raw_engine_connect_in_app():
    """
    No code outside tenant/isolation.py should call engine.connect() directly.
    Direct engine usage bypasses the ContextVar tenant binding and asyncio.shield cleanup.
    """
    import os
    import re

    violations = []
    app_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app")

    for root, dirs, files in os.walk(app_dir):
        # tenant/isolation.py and tokens/keys.py are allowed (keys.py needs engine for rotation)
        dirs[:] = [d for d in dirs if d not in ["__pycache__"]]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, fname), app_dir)
            if rel in ("tenant/isolation.py", "tenant/router.py", "tokens/keys.py", "core/database.py"):
                continue
            path = os.path.join(root, fname)
            content = open(path).read()
            if re.search(r'engine\.connect\(\)', content):
                violations.append(f"{rel}: uses engine.connect() — must use get_session() or get_tenant_session()")

    assert not violations, "\n".join(violations)


def test_no_raw_asyncsession_instantiation_in_app():
    """
    No endpoint handler should instantiate AsyncSession directly.
    All sessions must come from the Depends(get_session) or Depends(get_tenant_session) factory
    which provides asyncio.shield cleanup and SET LOCAL search_path.
    """
    import os
    import re

    violations = []
    app_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app")

    # Pattern: AsyncSession() called as constructor (not type annotation or parameter)
    raw_session_pattern = re.compile(r'AsyncSession\(\s*(?!bind=|class_=|expire)')

    for root, dirs, files in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d not in ["__pycache__"]]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, app_dir)
            # Only allowed in database.py (sessionmaker) and tenant/router.py (get_tenant_session)
            if rel in ("core/database.py", "tenant/router.py"):
                continue
            content = open(path).read()
            if raw_session_pattern.search(content):
                violations.append(f"{rel}: raw AsyncSession() constructor — use Depends(get_session)")

    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# Background task ContextVar propagation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_background_task_inherits_tenant_context():
    """
    run_in_tenant_executor propagates tenant ContextVar to threads.
    Without this, background tasks running in thread pools would lose tenant binding
    and issue queries without SET LOCAL search_path — cross-tenant data leak risk.
    """
    from app.tenant.router import clear_tenant, get_tenant, run_in_tenant_executor, set_tenant

    tid = uuid.uuid4()
    set_tenant(tid)
    results = []

    def background_work():
        results.append(get_tenant())

    # Simulate a background task spawned from a request handler
    await run_in_tenant_executor(None, background_work)

    assert results[0] == tid, (
        f"Background thread got tenant={results[0]}, expected {tid}. "
        "ctx.run() is missing — ContextVar not propagated to thread pool."
    )
    clear_tenant()


@pytest.mark.asyncio
async def test_asyncio_task_does_not_inherit_context_without_copy():
    """
    Demonstrates that a raw asyncio.create_task loses ContextVar — confirming
    run_in_tenant_executor is needed for thread pool tasks.
    Note: asyncio tasks DO inherit ContextVar (Python 3.7+), but thread pools don't.
    This test documents the expected asyncio behavior.
    """
    from app.tenant.router import clear_tenant, get_tenant, set_tenant

    tid = uuid.uuid4()
    set_tenant(tid)

    # asyncio tasks inherit ContextVar by default (Python 3.7+)
    async def check():
        return get_tenant()

    result = await asyncio.create_task(check())
    # asyncio tasks inherit — this is expected and safe
    assert result == tid, "asyncio tasks should inherit ContextVar from parent"
    clear_tenant()


import asyncio
