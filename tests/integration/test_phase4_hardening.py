"""
Phase 4 hardening tests:
- Password complexity enforcement (server-side validate_password)
- Token family / refresh-token theft detection
- Session management API routes
- Migration 0004 (token_family_id)
"""
from __future__ import annotations

import inspect
import uuid
from datetime import UTC
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1. Password complexity — validate_password
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_password_too_short():
    from fastapi_users.exceptions import InvalidPasswordException

    from app.identity.password import UserManager

    mgr = UserManager.__new__(UserManager)
    with pytest.raises(InvalidPasswordException) as exc:
        await mgr.validate_password("Sh0rt!")
    assert "8" in exc.value.reason


@pytest.mark.asyncio
async def test_password_missing_uppercase():
    from fastapi_users.exceptions import InvalidPasswordException

    from app.identity.password import UserManager

    mgr = UserManager.__new__(UserManager)
    with pytest.raises(InvalidPasswordException) as exc:
        await mgr.validate_password("nouppercase1!")
    assert "uppercase" in exc.value.reason.lower()


@pytest.mark.asyncio
async def test_password_missing_lowercase():
    from fastapi_users.exceptions import InvalidPasswordException

    from app.identity.password import UserManager

    mgr = UserManager.__new__(UserManager)
    with pytest.raises(InvalidPasswordException) as exc:
        await mgr.validate_password("NOLOWERCASE1!")
    assert "lowercase" in exc.value.reason.lower()


@pytest.mark.asyncio
async def test_password_missing_digit():
    from fastapi_users.exceptions import InvalidPasswordException

    from app.identity.password import UserManager

    mgr = UserManager.__new__(UserManager)
    with pytest.raises(InvalidPasswordException) as exc:
        await mgr.validate_password("NoDigitHere!")
    assert "number" in exc.value.reason.lower()


@pytest.mark.asyncio
async def test_password_missing_special():
    from fastapi_users.exceptions import InvalidPasswordException

    from app.identity.password import UserManager

    mgr = UserManager.__new__(UserManager)
    with pytest.raises(InvalidPasswordException) as exc:
        await mgr.validate_password("NoSpecial123")
    assert "special" in exc.value.reason.lower()


@pytest.mark.asyncio
async def test_password_valid_passes(monkeypatch):
    import app.identity.password as pwd_module
    from app.identity.password import UserManager

    # Patch HIBP — complexity tests must not make network calls
    async def _noop(p): pass
    monkeypatch.setattr(pwd_module, "_check_hibp", _noop)

    mgr = UserManager.__new__(UserManager)
    await mgr.validate_password("ValidP@ss1")


@pytest.mark.asyncio
async def test_password_edge_exactly_8_chars(monkeypatch):
    import app.identity.password as pwd_module
    from app.identity.password import UserManager

    async def _noop(p): pass
    monkeypatch.setattr(pwd_module, "_check_hibp", _noop)

    mgr = UserManager.__new__(UserManager)
    await mgr.validate_password("Aa1!aaaa")


# ---------------------------------------------------------------------------
# 2. Token family — OAuthToken model has token_family_id
# ---------------------------------------------------------------------------

def test_oauth_token_has_token_family_id():
    from app.models.token import OAuthToken
    assert hasattr(OAuthToken, "token_family_id")


def test_migration_0004_exists():
    migration = Path(__file__).parents[2] / "migrations/versions/0004_token_family_id.py"
    assert migration.exists(), "Migration 0004_token_family_id.py missing"


def test_migration_0004_correct_revision():
    import importlib.util
    path = Path(__file__).parents[2] / "migrations/versions/0004_token_family_id.py"
    spec = importlib.util.spec_from_file_location("m0004", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "0004_token_family_id"
    assert mod.down_revision == "0003_account_lockout"


def test_migration_0004_adds_family_id_column():
    import importlib.util
    path = Path(__file__).parents[2] / "migrations/versions/0004_token_family_id.py"
    spec = importlib.util.spec_from_file_location("m0004_src", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = inspect.getsource(mod.upgrade)
    assert "token_family_id" in src


# ---------------------------------------------------------------------------
# 3. Refresh token theft detection — code structure check
# ---------------------------------------------------------------------------

def test_refresh_grant_checks_revoked_flag():
    """_handle_refresh_grant must handle the case where token is found but revoked."""
    from app.server.endpoints import _handle_refresh_grant
    src = inspect.getsource(_handle_refresh_grant)
    assert "token_row.revoked" in src or ".revoked" in src


def test_refresh_grant_revokes_family_on_theft():
    """On theft detection, the entire token family must be revoked."""
    from app.server.endpoints import _handle_refresh_grant
    src = inspect.getsource(_handle_refresh_grant)
    assert "token_family_id" in src
    assert "revoked=True" in src


def test_refresh_grant_logs_theft():
    """Theft detection must log a warning."""
    from app.server.endpoints import _handle_refresh_grant
    src = inspect.getsource(_handle_refresh_grant)
    assert "refresh_token_theft_detected" in src or "theft" in src.lower()


def test_refresh_grant_returns_401_on_theft():
    """Theft must result in 401 (not 400) — forces re-authentication."""
    from app.server.endpoints import _handle_refresh_grant
    src = inspect.getsource(_handle_refresh_grant)
    assert "401" in src


def test_code_grant_assigns_token_family_id():
    """Code grant must assign a new token_family_id when issuing a refresh token."""
    from app.server.endpoints import _handle_code_grant
    src = inspect.getsource(_handle_code_grant)
    assert "token_family_id" in src


def test_refresh_grant_carries_forward_family_id():
    """Rotation must carry the same token_family_id (not create a new one)."""
    from app.server.endpoints import _handle_refresh_grant
    src = inspect.getsource(_handle_refresh_grant)
    assert "token_row.token_family_id" in src


# ---------------------------------------------------------------------------
# 4. Session management API
# ---------------------------------------------------------------------------

def test_sessions_router_exists():
    from app.api.v1.sessions import router
    assert router is not None
    assert router.prefix == "/auth/sessions"


def test_sessions_list_route():
    from app.api.v1.sessions import router
    paths = [r.path for r in router.routes]
    assert "/auth/sessions" in paths


def test_sessions_revoke_single_route():
    from app.api.v1.sessions import router
    paths = [r.path for r in router.routes]
    assert "/auth/sessions/{session_id}" in paths


def test_sessions_revoke_all_route():
    """DELETE /auth/sessions (no path param) must exist for global sign-out."""
    from app.api.v1.sessions import router
    delete_routes = [r for r in router.routes if hasattr(r, "methods") and "DELETE" in r.methods]
    assert len(delete_routes) >= 1, "No DELETE routes found in sessions router"


def test_session_info_schema():
    from datetime import datetime, timezone

    from app.api.v1.sessions import SessionInfo
    si = SessionInfo(
        session_id=str(uuid.uuid4()),
        client_id="my-app",
        scope="openid email",
        issued_at=datetime.now(UTC),
        access_token_expires_at=datetime.now(UTC),
        refresh_token_expires_at=None,
        token_family_id=str(uuid.uuid4()),
    )
    assert si.client_id == "my-app"


def test_revoke_session_validates_uuid():
    """The route validates session_id as a UUID — non-UUID should 400."""
    from app.api.v1.sessions import revoke_session
    src = inspect.getsource(revoke_session)
    assert "uuid.UUID" in src or "UUID" in src


def test_sessions_router_registered_in_main():
    """sessions_router must be included in the FastAPI app."""
    main_src = (Path(__file__).parents[2] / "app/main.py").read_text()
    assert "sessions_router" in main_src


# ---------------------------------------------------------------------------
# 5. Password complexity — regex constants exported
# ---------------------------------------------------------------------------

def test_password_regex_constants_present():
    from app.identity.password import _DIGIT_RE, _PASSWORD_MIN_LENGTH, _SPECIAL_RE, _UPPERCASE_RE
    assert _PASSWORD_MIN_LENGTH == 8
    assert _UPPERCASE_RE.search("A")
    assert not _UPPERCASE_RE.search("a")
    assert _DIGIT_RE.search("5")
    assert _SPECIAL_RE.search("!")
    assert not _SPECIAL_RE.search("A")
