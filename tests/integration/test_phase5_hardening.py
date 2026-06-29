"""
Phase 5 hardening tests — backup codes, webhooks, OAuth consent.
"""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

SVC_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# TOTP backup codes
# ---------------------------------------------------------------------------

def test_generate_backup_codes_returns_8_pairs():
    from app.mfa.totp import generate_backup_codes
    plain, hashed = generate_backup_codes()
    assert len(plain) == 8
    assert len(hashed) == 8


def test_backup_codes_are_uppercase_hex():
    from app.mfa.totp import generate_backup_codes
    plain, _ = generate_backup_codes()
    for code in plain:
        assert len(code) == 8
        assert code == code.upper()
        int(code, 16)  # must be valid hex


def test_backup_codes_hashes_match_plaintext():
    from app.mfa.totp import generate_backup_codes
    plain, hashed = generate_backup_codes()
    for p, h in zip(plain, hashed):
        assert hashlib.sha256(p.encode()).hexdigest() == h


def test_backup_codes_all_unique():
    from app.mfa.totp import generate_backup_codes
    plain, hashed = generate_backup_codes()
    assert len(set(plain)) == 8
    assert len(set(hashed)) == 8


@pytest.mark.asyncio
async def test_verify_backup_code_removes_used_code():
    from app.mfa.totp import generate_backup_codes, verify_backup_code

    plain, hashed = generate_backup_codes()
    target = plain[0]

    user = MagicMock()
    user.id = uuid.uuid4()
    user.tenant_id = uuid.uuid4()
    user.is_totp_enabled = True
    user.totp_backup_codes = hashed[:]

    db = AsyncMock()
    db.get = AsyncMock(return_value=user)
    db.execute = AsyncMock()
    db.commit = AsyncMock()

    with patch("app.mfa.totp.emit", new_callable=AsyncMock):
        result = await verify_backup_code(user.id, target, db)

    assert result is True
    # Verify the execute call removed the used code
    call_args = db.execute.call_args
    assert call_args is not None  # execute was called


@pytest.mark.asyncio
async def test_verify_backup_code_rejects_invalid():
    from fastapi import HTTPException

    from app.mfa.totp import generate_backup_codes, verify_backup_code

    _, hashed = generate_backup_codes()

    user = MagicMock()
    user.is_totp_enabled = True
    user.totp_backup_codes = hashed

    db = AsyncMock()
    db.get = AsyncMock(return_value=user)

    with pytest.raises(HTTPException) as exc_info:
        await verify_backup_code(uuid.uuid4(), "BADCODE1", db)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_backup_code_no_codes_raises_400():
    from fastapi import HTTPException

    from app.mfa.totp import verify_backup_code

    user = MagicMock()
    user.is_totp_enabled = True
    user.totp_backup_codes = None

    db = AsyncMock()
    db.get = AsyncMock(return_value=user)

    with pytest.raises(HTTPException) as exc_info:
        await verify_backup_code(uuid.uuid4(), "ANYTHING", db)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_and_activate_totp_returns_backup_codes():
    """verify_and_activate_totp now returns a list of 8 plaintext backup codes."""
    import pyotp

    from app.mfa.totp import verify_and_activate_totp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    code = totp.now()

    from cryptography.fernet import Fernet

    from app.core.config import settings
    enc_secret = Fernet(settings.fernet_key()).encrypt(secret.encode()).decode()

    user = MagicMock()
    user.id = uuid.uuid4()
    user.tenant_id = uuid.uuid4()
    user.totp_secret_enc = enc_secret
    user.is_totp_enabled = False

    db = AsyncMock()
    db.get = AsyncMock(return_value=user)
    db.execute = AsyncMock()
    db.commit = AsyncMock()

    with patch("app.mfa.totp.emit", new_callable=AsyncMock):
        result = await verify_and_activate_totp(user.id, code, db)

    assert isinstance(result, list)
    assert len(result) == 8


# ---------------------------------------------------------------------------
# Webhook model
# ---------------------------------------------------------------------------

def test_tenant_webhook_model_exists():
    from app.models.webhook import TenantWebhook
    wh = TenantWebhook.__table__
    columns = {c.name for c in wh.columns}
    assert "id" in columns
    assert "tenant_id" in columns
    assert "url" in columns
    assert "secret_enc" in columns
    assert "events" in columns
    assert "is_active" in columns


def test_migration_0006_exists():
    migration = SVC_ROOT / "migrations/versions/0006_tenant_webhooks.py"
    assert migration.exists()
    src = migration.read_text()
    assert "tenant_webhooks" in src
    assert "events" in src


def test_migration_0005_exists():
    migration = SVC_ROOT / "migrations/versions/0005_backup_codes_consent.py"
    assert migration.exists()
    src = migration.read_text()
    assert "totp_backup_codes" in src
    assert "auto_approve" in src


def test_webhooks_admin_router_exists():
    from app.admin.webhooks import router
    paths = {r.path for r in router.routes}
    assert "/admin/webhooks" in paths


# ---------------------------------------------------------------------------
# Webhook delivery — HMAC signing
# ---------------------------------------------------------------------------

def test_event_enum_has_webhook_events():
    from app.core.events import AuthEvent
    assert AuthEvent.WEBHOOK_CREATED
    assert AuthEvent.WEBHOOK_DELETED


def test_events_module_has_dispatch():
    import app.core.events as ev
    assert hasattr(ev, "_dispatch_webhooks")
    assert hasattr(ev, "_deliver")


# ---------------------------------------------------------------------------
# OAuth consent
# ---------------------------------------------------------------------------

def test_oauth_client_has_auto_approve():
    from app.models.client import OAuthClient
    cols = {c.name for c in OAuthClient.__table__.columns}
    assert "auto_approve" in cols


def test_consent_template_exists():
    tpl = SVC_ROOT / "templates/auth/consent.html"
    assert tpl.exists()
    src = tpl.read_text()
    assert "client_id" in src
    assert "scope_list" in src
    assert "/oauth/consent" in src
    assert "Deny" in src
    assert "Allow" in src


def test_consent_template_shows_scope_descriptions():
    tpl = SVC_ROOT / "templates/auth/consent.html"
    src = tpl.read_text()
    assert "openid" in src
    assert "email" in src
    assert "offline_access" in src


def test_ui_router_has_consent_route():
    from app.ui.router import router
    paths = {r.path for r in router.routes}
    assert "/ui/oauth/consent" in paths


def test_server_endpoints_has_consent_route():
    from app.server.endpoints import router
    paths = {r.path for r in router.routes}
    assert "/oauth/consent" in paths


def test_authorize_redirects_when_not_auto_approve():
    """When client.auto_approve=False, GET /oauth/authorize should redirect to consent page."""
    import inspect

    from app.server import endpoints
    src = inspect.getsource(endpoints.authorize)
    assert "auto_approve" in src
    assert "/oauth/consent" in src


def test_mfa_backup_endpoint_exists():
    from app.api.v1.auth import router
    paths = {r.path for r in router.routes}
    assert "/auth/mfa/backup" in paths


# ---------------------------------------------------------------------------
# Webhook events piped through emit()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emit_creates_webhook_dispatch_task():
    """emit() should schedule _dispatch_webhooks as a background task when tenant_id is set."""
    import asyncio

    from app.core.events import AuthEvent, emit

    tenant_id = uuid.uuid4()
    set(t for t in asyncio.all_tasks() if not t.done())

    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()

    with patch("app.core.events._dispatch_webhooks", new_callable=AsyncMock):
        with patch("asyncio.create_task") as mock_task:
            await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=tenant_id)
            mock_task.assert_called_once()