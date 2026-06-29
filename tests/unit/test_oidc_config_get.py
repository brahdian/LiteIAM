"""
Unit tests for GET /auth/enterprise/config/{tenant_id}.

The read-back endpoint exists so an admin UI can pre-populate the SSO form. It
must never return the encrypted client secret — only a boolean indicating one
is set.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.enterprise import current_superuser, router
from app.core.database import get_session


def _make_app(session_mock):
    app = FastAPI()
    app.include_router(router)

    async def _session():
        yield session_mock

    def _admin():
        u = MagicMock()
        u.is_superuser = True
        return u

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[current_superuser] = _admin
    return app


def test_get_config_returns_non_secret_fields():
    cfg = MagicMock()
    cfg.tenant_id = uuid.uuid4()
    cfg.discovery_url = "https://idp.example.com/.well-known/openid-configuration"
    cfg.client_id = "client-123"
    cfg.client_secret_enc = "gAAAAA-encrypted-blob"
    cfg.jit_enabled = True
    cfg.role_mapping = {"Admins": "admin"}

    session = AsyncMock()
    session.scalar = AsyncMock(return_value=cfg)

    with TestClient(_make_app(session), raise_server_exceptions=False) as c:
        resp = c.get(f"/auth/enterprise/config/{cfg.tenant_id}")

    assert resp.status_code == 200
    body = resp.json()
    # Secret must never be exposed — only the boolean.
    assert "client_secret" not in body
    assert "client_secret_enc" not in body
    assert body["has_client_secret"] is True
    assert body["client_id"] == "client-123"
    assert body["role_mapping"] == {"Admins": "admin"}


def test_get_config_404_when_missing():
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    with TestClient(_make_app(session), raise_server_exceptions=False) as c:
        resp = c.get(f"/auth/enterprise/config/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_get_config_has_client_secret_false_when_unset():
    cfg = MagicMock()
    cfg.tenant_id = uuid.uuid4()
    cfg.discovery_url = "https://idp.example.com/.well-known/openid-configuration"
    cfg.client_id = "client-123"
    cfg.client_secret_enc = ""
    cfg.jit_enabled = False
    cfg.role_mapping = None  # exercise the `or {}` fallback

    session = AsyncMock()
    session.scalar = AsyncMock(return_value=cfg)
    with TestClient(_make_app(session), raise_server_exceptions=False) as c:
        resp = c.get(f"/auth/enterprise/config/{cfg.tenant_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_client_secret"] is False
    assert body["role_mapping"] == {}
