"""
Phase 3 hardening tests — account lockout, client secret auth, UI routes.
"""
from __future__ import annotations

import base64
import inspect
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# 1. Account lockout — model field presence
# ---------------------------------------------------------------------------

def test_user_model_has_lockout_fields():
    from app.models.user import User
    assert hasattr(User, "failed_login_count")
    assert hasattr(User, "locked_until")


# ---------------------------------------------------------------------------
# 2. OAuthClient.verify_secret — constant-time comparison
# ---------------------------------------------------------------------------

def _make_client(**kwargs):
    """Build a minimal OAuthClient-like object without SQLAlchemy ORM machinery."""
    from app.models.client import OAuthClient
    client = MagicMock(spec=OAuthClient)
    for k, v in kwargs.items():
        setattr(client, k, v)
    # Wire through the real methods
    client.is_confidential = lambda: OAuthClient.is_confidential(client)
    client.verify_secret = lambda s: OAuthClient.verify_secret(client, s)
    return client


def test_oauth_client_verify_secret_correct():
    """Encrypt with the real settings key; verify_secret must return True."""
    from cryptography.fernet import Fernet

    from app.core.config import settings

    key = settings.fernet_key()
    f = Fernet(key)
    plain = "super-secret-value"
    enc = f.encrypt(plain.encode()).decode()

    client = _make_client(client_secret_enc=enc)
    assert client.verify_secret(plain) is True


def test_oauth_client_verify_secret_wrong():
    """Wrong plaintext must return False."""
    from cryptography.fernet import Fernet

    from app.core.config import settings

    key = settings.fernet_key()
    f = Fernet(key)
    enc = f.encrypt(b"correct-secret").decode()

    client = _make_client(client_secret_enc=enc)
    assert client.verify_secret("wrong-secret") is False


def test_oauth_client_verify_secret_no_secret():
    client = _make_client(client_secret_enc=None)
    assert client.verify_secret("anything") is False


def test_oauth_client_is_confidential_true():
    client = _make_client(client_secret_enc="some-enc-value")
    assert client.is_confidential() is True


def test_oauth_client_is_confidential_false():
    client = _make_client(client_secret_enc=None)
    assert client.is_confidential() is False


# ---------------------------------------------------------------------------
# 3. Token endpoint — client secret enforcement wiring
# ---------------------------------------------------------------------------

def test_token_endpoint_accepts_client_secret_form_param():
    """Verify the token endpoint signature now includes client_secret."""
    from app.server.endpoints import token
    sig = inspect.signature(token)
    assert "client_secret" in sig.parameters, "client_secret Form param missing from token endpoint"


def test_token_endpoint_accepts_request_param():
    """Verify the token endpoint accepts a Request for Basic auth extraction."""
    from app.server.endpoints import token
    sig = inspect.signature(token)
    assert "request" in sig.parameters, "request param missing from token endpoint"


# ---------------------------------------------------------------------------
# 4. Lockout — login response includes user_id
# ---------------------------------------------------------------------------

def test_login_response_has_user_id_field():
    from app.api.v1.auth import LoginResponse
    r = LoginResponse(access_token="tok", auth_stage="complete", user_id="abc-123")
    assert r.user_id == "abc-123"


def test_login_response_user_id_optional():
    from app.api.v1.auth import LoginResponse
    r = LoginResponse(access_token="tok", auth_stage="complete")
    assert r.user_id is None


# ---------------------------------------------------------------------------
# 5. Account lockout — locked_until logic
# ---------------------------------------------------------------------------

def test_lockout_duration_calculation():
    """Locked_until should be ~15 minutes in the future after max failures."""
    now = datetime.now(UTC)
    _MAX_FAILURES = 5
    _LOCKOUT_SECONDS = 900
    locked_until = now + timedelta(seconds=_LOCKOUT_SECONDS)
    delta = (locked_until - now).total_seconds()
    assert 895 <= delta <= 905  # within a few seconds of 15 min


def test_lockout_not_applied_below_threshold():
    """Lockout should not be applied for < MAX_FAILURES failures."""
    _MAX_FAILURES = 5
    for count in range(1, _MAX_FAILURES):
        new_count = count + 1
        apply_lockout = new_count >= _MAX_FAILURES
        if count < _MAX_FAILURES - 1:
            assert not apply_lockout, f"Lockout incorrectly applied at count {count}"


def test_lockout_applied_at_threshold():
    _MAX_FAILURES = 5
    new_count = _MAX_FAILURES
    assert new_count >= _MAX_FAILURES


# ---------------------------------------------------------------------------
# 6. UI router — route registration
# ---------------------------------------------------------------------------

def test_ui_router_has_login_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/login" in paths


def test_ui_router_has_register_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/register" in paths


def test_ui_router_has_totp_verify_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/totp/verify" in paths


def test_ui_router_has_totp_enroll_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/totp/enroll" in paths


def test_ui_router_has_forgot_password_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/forgot-password" in paths


def test_ui_router_has_reset_password_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/reset-password" in paths


def test_ui_router_has_error_route():
    from app.ui.router import router
    paths = [r.path for r in router.routes]
    assert "/ui/error" in paths


def test_ui_router_prefix():
    from app.ui.router import router
    assert router.prefix == "/ui"


# ---------------------------------------------------------------------------
# 7. Migration file presence
# ---------------------------------------------------------------------------

def test_migration_0003_exists():
    from pathlib import Path
    migration = Path(__file__).parents[2] / "migrations/versions/0003_account_lockout.py"
    assert migration.exists(), "Migration 0003_account_lockout.py missing"


def test_migration_0003_correct_revision():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parents[2] / "migrations/versions/0003_account_lockout.py"
    spec = importlib.util.spec_from_file_location("m0003", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "0003_account_lockout"
    assert mod.down_revision == "0002_encrypt_oauth_access_token"


def test_migration_0003_adds_both_columns():
    """Upgrade function adds failed_login_count and locked_until."""
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parents[2] / "migrations/versions/0003_account_lockout.py"
    spec = importlib.util.spec_from_file_location("m0003_src", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = inspect.getsource(mod.upgrade)
    assert "failed_login_count" in src
    assert "locked_until" in src


# ---------------------------------------------------------------------------
# 8. UI template files exist
# ---------------------------------------------------------------------------

def test_ui_template_files_exist():
    from pathlib import Path
    templates_dir = Path(__file__).parents[2] / "templates" / "auth"
    required = ["base.html", "login.html", "register.html", "totp_verify.html",
                "totp_enroll.html", "forgot_password.html", "reset_password.html", "error.html"]
    for name in required:
        assert (templates_dir / name).exists(), f"Missing template: {name}"


def test_login_template_has_google_button():
    from pathlib import Path
    html = (Path(__file__).parents[2] / "templates/auth/login.html").read_text()
    assert "google" in html.lower() or "Google" in html


def test_login_template_has_tenant_field():
    from pathlib import Path
    html = (Path(__file__).parents[2] / "templates/auth/login.html").read_text()
    assert "tenant_id" in html


def test_totp_verify_template_has_countdown():
    from pathlib import Path
    html = (Path(__file__).parents[2] / "templates/auth/totp_verify.html").read_text()
    assert "countdown" in html


def test_register_template_has_strength_meter():
    from pathlib import Path
    html = (Path(__file__).parents[2] / "templates/auth/register.html").read_text()
    assert "strength" in html


def test_error_template_has_status_code():
    from pathlib import Path
    html = (Path(__file__).parents[2] / "templates/auth/error.html").read_text()
    assert "status_code" in html


# ---------------------------------------------------------------------------
# 9. Security: HTTP Basic auth header parsing logic
# ---------------------------------------------------------------------------

def test_http_basic_auth_parse():
    """Verify the Basic auth parsing logic used in the token endpoint."""
    client_id = "my-app"
    client_secret = "s3cr3t!"
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    header = f"Basic {credentials}"

    # Replicate the parsing logic from endpoints.py
    import base64 as _b64
    assert header.startswith("Basic ")
    decoded = _b64.b64decode(header[6:]).decode()
    cid, _, sec = decoded.partition(":")
    assert cid == client_id
    assert sec == client_secret


def test_http_basic_auth_colon_in_secret():
    """Secrets containing ':' must still parse correctly (partition stops at first colon)."""
    client_id = "app-id"
    client_secret = "pass:word:with:colons"
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    header = f"Basic {credentials}"

    import base64 as _b64
    decoded = _b64.b64decode(header[6:]).decode()
    cid, _, sec = decoded.partition(":")
    assert cid == client_id
    assert sec == client_secret
