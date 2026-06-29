"""
Unit tests for per-tenant email sender configuration:
  - send_email honours the from_address/from_name override (visible From header)
  - the envelope sender stays the platform SMTP_FROM (SPF alignment)
  - the admin endpoint requires superuser and round-trips the value
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.admin.email_sender import router
from app.core.database import get_session
from app.identity.password import current_active_user

# ---------------------------------------------------------------------------
# send_email From-header override
# ---------------------------------------------------------------------------

def _send(**kwargs):
    from app.core.config import settings
    captured = {}

    def fake_send_sync(msg, to):
        captured["From"] = msg["From"]
        captured["to"] = to

    with patch.object(settings, "SMTP_HOST", "smtp.example.com"), \
         patch.object(settings, "SMTP_FROM", "noreply@example.com"), \
         patch("app.notifications.email._send_sync", side_effect=fake_send_sync):
        from app.notifications.email import send_email
        asyncio.get_event_loop().run_until_complete(
            send_email(to="user@x.com", subject="s", text_body="b", **kwargs)
        )
    return captured


def test_default_from_is_platform_sender():
    cap = _send()
    assert cap["From"] == "noreply@example.com"


def test_from_address_override():
    cap = _send(from_address="auth@bigcorp.com")
    assert cap["From"] == "auth@bigcorp.com"


def test_from_name_and_address_override():
    cap = _send(from_address="auth@bigcorp.com", from_name="BigCorp Security")
    assert cap["From"] == "BigCorp Security <auth@bigcorp.com>"


def test_from_name_with_comma_is_quoted_not_injected():
    """A display name with a comma must be quoted so it cannot split into a second
    address — formataddr handles this; a raw f-string would not."""
    cap = _send(from_address="auth@bigcorp.com", from_name="Acme, Inc.")
    # The whole name stays as one quoted phrase before the single real address.
    assert cap["From"] == '"Acme, Inc." <auth@bigcorp.com>'
    # exactly one angle-bracket address — no injected second address
    assert cap["From"].count("<") == 1


# ---------------------------------------------------------------------------
# Admin endpoint
# ---------------------------------------------------------------------------

def _make_app(session_mock, user_mock):
    app = FastAPI()
    app.include_router(router)

    async def _session():
        yield session_mock

    def _user():
        return user_mock

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[current_active_user] = _user
    return app


def _superuser():
    u = MagicMock()
    u.is_superuser = True
    return u


def test_get_email_sender_requires_superuser():
    user = MagicMock()
    user.is_superuser = False
    session = AsyncMock()
    tid = str(uuid.uuid4())
    with TestClient(_make_app(session, user), raise_server_exceptions=False) as c:
        resp = c.get(f"/admin/tenants/{tid}/email-sender")
    assert resp.status_code == 403


def test_put_email_sender_round_trips():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()
    tenant.email_from_address = None
    tenant.email_from_name = None
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=tenant)

    app = _make_app(session, _superuser())
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.put(
            f"/admin/tenants/{tenant.id}/email-sender",
            json={"email_from_address": "auth@bigcorp.com", "email_from_name": "BigCorp"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["email_from_address"] == "auth@bigcorp.com"
    assert body["email_from_name"] == "BigCorp"
    # The model was mutated with the new values
    assert tenant.email_from_address == "auth@bigcorp.com"


def test_put_email_sender_null_clears_override():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()
    tenant.email_from_address = "old@bigcorp.com"
    tenant.email_from_name = "Old"
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=tenant)

    with TestClient(_make_app(session, _superuser()), raise_server_exceptions=False) as c:
        resp = c.put(
            f"/admin/tenants/{tenant.id}/email-sender",
            json={"email_from_address": None, "email_from_name": None},
        )
    assert resp.status_code == 200
    assert tenant.email_from_address is None
    assert tenant.email_from_name is None
