"""
Unit tests for passwordless email OTP (6-digit sign-in code).

Covers the security-critical behaviours:
  - the stored hash binds the code to the target email (no cross-email matching)
  - /send is anti-enumeration: always 202, only emails when the user exists
  - /verify caps brute-force via the attempts counter and is single-use
  - the tenant email-sender override is threaded through to send_email
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.email_otp import _MAX_ATTEMPTS, _hash, router
from app.core.database import get_session
from app.core.rate_limit import limiter
from app.identity.password import get_user_manager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(session_mock):
    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(router)

    async def _session():
        yield session_mock

    async def _manager():
        yield AsyncMock()

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_user_manager] = _manager
    return app


def _user(tenant_id=None, totp_enabled=False):
    u = MagicMock()
    u.id = uuid.uuid4()
    u.tenant_id = tenant_id or uuid.uuid4()
    u.is_active = True
    u.is_verified = True
    u.is_totp_enabled = totp_enabled
    return u


def _otp_row(email, code, *, attempts=0, ttl_min=10):
    row = MagicMock()
    row.id = uuid.uuid4()
    row.email = email
    row.code_hash = _hash(email, code)
    row.tenant_id = uuid.uuid4()
    row.attempts = attempts
    row.used_at = None
    row.expires_at = datetime.now(UTC) + timedelta(minutes=ttl_min)
    return row


# ---------------------------------------------------------------------------
# _hash — binds the code to the email
# ---------------------------------------------------------------------------

def test_hash_binds_code_to_email():
    """Same 6-digit code for two different emails must produce different hashes."""
    assert _hash("alice@x.com", "123456") != _hash("bob@x.com", "123456")


def test_hash_is_deterministic():
    assert _hash("alice@x.com", "123456") == _hash("alice@x.com", "123456")


# ---------------------------------------------------------------------------
# /send — anti-enumeration
# ---------------------------------------------------------------------------

def test_send_no_user_returns_202_and_sends_nothing():
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=None)  # user not found

    with patch("app.notifications.email.send_email_otp", new=AsyncMock()) as send:
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/send", json={"email": "ghost@x.com"})
    assert resp.status_code == 202
    send.assert_not_called()


def test_send_existing_user_emails_a_six_digit_code():
    user = _user()
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=user)
    session.add = MagicMock()

    with patch("app.notifications.email.send_email_otp", new=AsyncMock()) as send, \
         patch("app.notifications.email.resolve_tenant_sender", new=AsyncMock(return_value=(None, None))), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/send", json={"email": "real@x.com"})

    assert resp.status_code == 202
    send.assert_awaited_once()
    code = send.await_args.kwargs["code"]
    assert code.isdigit() and len(code) == 6


def test_send_threads_tenant_sender_override():
    """A tenant with a custom From address must have it passed to the email."""
    user = _user()
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=user)
    session.add = MagicMock()

    with patch("app.notifications.email.send_email_otp", new=AsyncMock()) as send, \
         patch("app.notifications.email.resolve_tenant_sender",
               new=AsyncMock(return_value=("auth@bigcorp.com", "BigCorp"))), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            c.post("/auth/email-otp/send", json={"email": "real@x.com"})

    assert send.await_args.kwargs["from_address"] == "auth@bigcorp.com"
    assert send.await_args.kwargs["from_name"] == "BigCorp"


# ---------------------------------------------------------------------------
# /verify — brute-force cap + single-use
# ---------------------------------------------------------------------------

def test_verify_correct_code_returns_token():
    email, code = "real@x.com", "123456"
    row = _otp_row(email, code)
    user = _user(tenant_id=row.tenant_id, totp_enabled=False)
    tenant = _tenant(require_mfa=False)

    session = AsyncMock()
    # first scalar → OTP row, second scalar → user
    session.scalar = AsyncMock(side_effect=[row, user])
    # the single-use claim UPDATE matches exactly one row
    session.execute = AsyncMock(return_value=MagicMock(rowcount=1))
    session.get = AsyncMock(return_value=tenant)

    strat = MagicMock()
    strat.write_token = AsyncMock(return_value="jwt-token")

    with patch("app.api.v1.email_otp.get_jwt_strategy", return_value=strat), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": code})

    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] == "jwt-token"
    assert body["auth_stage"] == "complete"


def test_verify_loses_race_when_code_already_claimed():
    """Two concurrent verifies with the same valid code: the loser's claim UPDATE
    matches 0 rows (used_at already set) and must be rejected, not issued a token."""
    email, code = "real@x.com", "123456"
    row = _otp_row(email, code)
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=row)
    session.execute = AsyncMock(return_value=MagicMock(rowcount=0))  # someone else claimed it

    strat = MagicMock()
    strat.write_token = AsyncMock(return_value="jwt-token")

    with patch("app.api.v1.email_otp.get_jwt_strategy", return_value=strat), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": code})

    assert resp.status_code == 400
    strat.write_token.assert_not_called()


def test_verify_wrong_code_increments_attempts_and_400s():
    email = "real@x.com"
    row = _otp_row(email, "123456", attempts=1)
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=row)
    session.execute = AsyncMock()

    with patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": "000000"})

    assert resp.status_code == 400
    # An UPDATE incrementing attempts must have been issued
    assert session.execute.await_count == 1


def test_verify_too_many_attempts_burns_code():
    email = "real@x.com"
    row = _otp_row(email, "123456", attempts=_MAX_ATTEMPTS)
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=row)
    session.execute = AsyncMock()

    with patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": "123456"})

    assert resp.status_code == 400
    assert "Too many" in resp.json()["detail"]


def test_verify_no_active_code_400s():
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=None)

    with TestClient(_make_app(session), raise_server_exceptions=False) as c:
        resp = c.post("/auth/email-otp/verify", json={"email": "real@x.com", "code": "123456"})

    assert resp.status_code == 400


def test_verify_rejects_non_numeric_code():
    """Pydantic pattern guard rejects malformed codes before any DB work."""
    session = AsyncMock()
    with TestClient(_make_app(session), raise_server_exceptions=False) as c:
        resp = c.post("/auth/email-otp/verify", json={"email": "real@x.com", "code": "abcdef"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /verify — MFA enforcement
# ---------------------------------------------------------------------------

def _user_with_totp(tenant_id=None, totp_enabled=True):
    u = _user(tenant_id=tenant_id)
    u.is_totp_enabled = totp_enabled
    return u


def _tenant(require_mfa=False):
    t = MagicMock()
    t.require_mfa = require_mfa
    return t


def test_verify_issues_mfa_pending_when_totp_enrolled():
    """User with TOTP enabled: email OTP verify must issue mfa_pending, not a full token."""
    email, code = "real@x.com", "123456"
    row = _otp_row(email, code)
    user = _user_with_totp(tenant_id=row.tenant_id, totp_enabled=True)
    tenant = _tenant(require_mfa=False)

    session = AsyncMock()
    session.scalar = AsyncMock(side_effect=[row, user])
    session.execute = AsyncMock(return_value=MagicMock(rowcount=1))
    session.get = AsyncMock(return_value=tenant)

    strat = MagicMock()
    strat.write_mfa_pending_token = AsyncMock(return_value="pending-jwt")
    strat.write_token = AsyncMock(return_value="full-jwt")

    with patch("app.api.v1.email_otp.get_jwt_strategy", return_value=strat), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": code})

    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_stage"] == "mfa_pending"
    assert body["access_token"] == "pending-jwt"
    strat.write_token.assert_not_called()


def test_verify_blocks_when_tenant_requires_mfa_but_no_totp():
    """Tenant mandates MFA, user has no TOTP enrolled — must be 403, no token issued."""
    email, code = "real@x.com", "123456"
    row = _otp_row(email, code)
    user = _user_with_totp(tenant_id=row.tenant_id, totp_enabled=False)
    tenant = _tenant(require_mfa=True)

    session = AsyncMock()
    session.scalar = AsyncMock(side_effect=[row, user])
    session.execute = AsyncMock(return_value=MagicMock(rowcount=1))
    session.get = AsyncMock(return_value=tenant)

    strat = MagicMock()
    strat.write_token = AsyncMock(return_value="full-jwt")
    strat.write_mfa_pending_token = AsyncMock(return_value="pending-jwt")

    with patch("app.api.v1.email_otp.get_jwt_strategy", return_value=strat), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": code})

    assert resp.status_code == 403
    assert "TOTP" in resp.json()["detail"] or "enrol" in resp.json()["detail"].lower()
    strat.write_token.assert_not_called()
    strat.write_mfa_pending_token.assert_not_called()


def test_verify_issues_full_token_when_no_mfa_required_or_enrolled():
    """No tenant MFA, user has no TOTP — must issue a complete access token."""
    email, code = "real@x.com", "123456"
    row = _otp_row(email, code)
    user = _user_with_totp(tenant_id=row.tenant_id, totp_enabled=False)
    tenant = _tenant(require_mfa=False)

    session = AsyncMock()
    session.scalar = AsyncMock(side_effect=[row, user])
    session.execute = AsyncMock(return_value=MagicMock(rowcount=1))
    session.get = AsyncMock(return_value=tenant)

    strat = MagicMock()
    strat.write_token = AsyncMock(return_value="full-jwt")
    strat.write_mfa_pending_token = AsyncMock(return_value="pending-jwt")

    with patch("app.api.v1.email_otp.get_jwt_strategy", return_value=strat), \
         patch("app.api.v1.email_otp.emit", new=AsyncMock()):
        with TestClient(_make_app(session), raise_server_exceptions=False) as c:
            resp = c.post("/auth/email-otp/verify", json={"email": email, "code": code})

    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_stage"] == "complete"
    assert body["access_token"] == "full-jwt"
    strat.write_mfa_pending_token.assert_not_called()
