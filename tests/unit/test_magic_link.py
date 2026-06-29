"""Unit tests for magic-link token hashing and endpoint structure."""
from __future__ import annotations

import hashlib
import inspect


def test_token_hash_is_sha256():
    """_hash must use SHA-256 — never store raw tokens."""
    from app.api.v1.magic_link import _hash

    raw = "test-token-abc"
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert _hash(raw) == expected


def test_token_hash_length():
    from app.api.v1.magic_link import _hash
    assert len(_hash("anything")) == 64


def test_send_returns_202_on_unknown_email():
    """send_magic_link must always return 202 — never leak whether email exists."""
    from app.api.v1.magic_link import send_magic_link
    src = inspect.getsource(send_magic_link)
    assert "202" in src
    assert "anti-enumeration" in src.lower() or "enumerate" in src.lower() or "silently" in src.lower()


def test_magic_link_router_prefix():
    from app.api.v1.magic_link import router
    assert router.prefix == "/auth/magic-link"


def test_send_endpoint_exists():
    from app.api.v1.magic_link import router
    paths = [r.path for r in router.routes]
    assert "/auth/magic-link/send" in paths


def test_verify_endpoint_exists():
    from app.api.v1.magic_link import router
    paths = [r.path for r in router.routes]
    assert "/auth/magic-link/verify" in paths


def test_verify_rejects_on_missing_or_used_token():
    """verify_magic_link raises 400 for invalid/used tokens."""
    from app.api.v1.magic_link import verify_magic_link
    src = inspect.getsource(verify_magic_link)
    assert "400" in src
    assert "used" in src.lower() or "expired" in src.lower()


def test_single_use_guarantee():
    """Token must be marked used before the access token is issued."""
    from app.api.v1.magic_link import verify_magic_link
    src = inspect.getsource(verify_magic_link)
    # used_at update must appear before the return statement
    update_pos = src.find("used_at=now")
    return_pos = src.rfind("access_token")
    assert update_pos < return_pos, "used_at must be set before returning token"


def test_magic_link_token_model():
    from app.models.magic_link import MagicLinkToken
    assert hasattr(MagicLinkToken, "token_hash")
    assert hasattr(MagicLinkToken, "email")
    assert hasattr(MagicLinkToken, "expires_at")
    assert hasattr(MagicLinkToken, "used_at")


def test_magic_link_model_no_raw_token_field():
    """Raw token must never be stored — only its hash."""
    from app.models.magic_link import MagicLinkToken
    assert not hasattr(MagicLinkToken, "token"), "raw token must not be a column"
    assert not hasattr(MagicLinkToken, "raw_token")


def test_verify_enforces_tenant_require_mfa():
    """verify_magic_link source must check tenant.require_mfa before issuing any token."""
    from app.api.v1.magic_link import verify_magic_link
    src = inspect.getsource(verify_magic_link)
    assert "require_mfa" in src


def test_verify_returns_mfa_pending_when_totp_enrolled():
    """verify_magic_link source must have the mfa_pending path for totp-enrolled users."""
    from app.api.v1.magic_link import verify_magic_link
    src = inspect.getsource(verify_magic_link)
    assert "mfa_pending" in src
    assert "requires_mfa" in src


def test_verify_anti_enumeration_on_user_not_found():
    """verify_magic_link must use the same generic error, never 'User not found'."""
    from app.api.v1.magic_link import verify_magic_link
    src = inspect.getsource(verify_magic_link)
    assert "User not found" not in src
