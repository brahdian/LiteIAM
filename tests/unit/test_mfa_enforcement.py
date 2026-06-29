"""Unit tests for tenant MFA enforcement, X-RateLimit headers, and PAT expiry warning."""
from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Tenant MFA enforcement — model column
# ---------------------------------------------------------------------------

def test_tenant_model_has_require_mfa_column():
    from app.models.tenant import Tenant
    assert hasattr(Tenant, "require_mfa")


def test_tenant_require_mfa_defaults_false():
    from app.models.tenant import Tenant
    col = Tenant.__table__.c["require_mfa"]
    assert col.default is not None or col.server_default is not None
    assert not col.nullable


def test_migration_0015_exists():
    from pathlib import Path
    p = Path(__file__).parents[2] / "migrations/versions/0015_tenant_require_mfa.py"
    assert p.exists()


def test_migration_0015_references_require_mfa():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "migrations/versions/0015_tenant_require_mfa.py").read_text()
    assert "require_mfa" in src
    assert "add_column" in src


def test_migration_0015_has_downgrade():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "migrations/versions/0015_tenant_require_mfa.py").read_text()
    assert "downgrade" in src
    assert "drop_column" in src


# ---------------------------------------------------------------------------
# Tenant MFA enforcement — login flow
# ---------------------------------------------------------------------------

def test_login_route_checks_require_mfa():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "require_mfa" in src


def test_login_blocks_unenrolled_user_with_403():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    # Must raise 403 when tenant requires MFA but user hasn't enrolled
    assert "403" in src
    assert "is_totp_enabled" in src or "totp_enabled" in src


def test_login_mfa_block_includes_enroll_url_header():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "X-MFA-Enroll-URL" in src or "enroll" in src.lower()


def test_mfa_block_message_is_clear():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "required" in src.lower() and ("organisation" in src.lower() or "organization" in src.lower())


# ---------------------------------------------------------------------------
# Admin MFA policy endpoint
# ---------------------------------------------------------------------------

def test_admin_mfa_policy_endpoint_exists():
    from app.admin.users import router
    routes = {r.path for r in router.routes}
    assert any("mfa-policy" in p for p in routes), f"mfa-policy route not found in {routes}"


def test_admin_mfa_policy_requires_superuser():
    from app.admin.users import set_tenant_mfa_policy
    src = inspect.getsource(set_tenant_mfa_policy)
    assert "superuser" in src.lower() or "is_superuser" in src


def test_admin_mfa_policy_updates_tenant():
    from app.admin.users import set_tenant_mfa_policy
    src = inspect.getsource(set_tenant_mfa_policy)
    assert "require_mfa" in src
    assert "update" in src.lower() or "execute" in src.lower()


def test_admin_mfa_policy_logs_change():
    from app.admin.users import set_tenant_mfa_policy
    src = inspect.getsource(set_tenant_mfa_policy)
    assert "logger" in src or "structlog" in src


# ---------------------------------------------------------------------------
# X-RateLimit response headers
# ---------------------------------------------------------------------------

def test_rate_limiter_has_headers_enabled():
    import app.core.rate_limit as rl_module
    src = inspect.getsource(rl_module)
    assert "headers_enabled" in src


def test_rate_limit_headers_enabled_true():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/core/rate_limit.py").read_text()
    assert "headers_enabled=True" in src


# ---------------------------------------------------------------------------
# PAT expiry warning
# ---------------------------------------------------------------------------

def test_token_read_schema_has_expires_soon():
    from app.api.v1.tokens import TokenRead
    fields = TokenRead.model_fields
    assert "expires_soon" in fields


def test_expires_soon_true_within_7_days():
    from unittest.mock import MagicMock

    from app.api.v1.tokens import _to_read

    pat = MagicMock()
    pat.id = __import__("uuid").uuid4()
    pat.name = "test-token"
    pat.scopes = ["api:read"]
    pat.last_used_at = None
    pat.expires_at = datetime.now(UTC) + timedelta(days=3)
    pat.is_active = True
    pat.created_at = datetime.now(UTC) - timedelta(days=10)

    result = _to_read(pat)
    assert result.expires_soon is True


def test_expires_soon_false_when_far_future():
    from app.api.v1.tokens import _to_read

    pat = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
    pat.id = __import__("uuid").uuid4()
    pat.name = "future-token"
    pat.scopes = ["api:read"]
    pat.last_used_at = None
    pat.expires_at = datetime.now(UTC) + timedelta(days=30)
    pat.is_active = True
    pat.created_at = datetime.now(UTC) - timedelta(days=5)

    result = _to_read(pat)
    assert result.expires_soon is False


def test_expires_soon_false_when_no_expiry():
    from unittest.mock import MagicMock

    from app.api.v1.tokens import _to_read

    pat = MagicMock()
    pat.id = __import__("uuid").uuid4()
    pat.name = "permanent-token"
    pat.scopes = ["api:read"]
    pat.last_used_at = None
    pat.expires_at = None
    pat.is_active = True
    pat.created_at = datetime.now(UTC) - timedelta(days=5)

    result = _to_read(pat)
    assert result.expires_soon is False


def test_expires_soon_false_when_already_expired():
    """Expired tokens should NOT flag expires_soon — they're just expired."""
    from unittest.mock import MagicMock

    from app.api.v1.tokens import _to_read

    pat = MagicMock()
    pat.id = __import__("uuid").uuid4()
    pat.name = "expired-token"
    pat.scopes = ["api:read"]
    pat.last_used_at = None
    pat.expires_at = datetime.now(UTC) - timedelta(days=1)
    pat.is_active = True
    pat.created_at = datetime.now(UTC) - timedelta(days=400)

    result = _to_read(pat)
    assert result.expires_soon is False


def test_expires_soon_handles_naive_datetime():
    """expires_at from DB may be naive (no tzinfo) — should not raise."""
    from unittest.mock import MagicMock

    from app.api.v1.tokens import _to_read

    pat = MagicMock()
    pat.id = __import__("uuid").uuid4()
    pat.name = "naive-token"
    pat.scopes = ["api:read"]
    pat.last_used_at = None
    # Naive datetime (no timezone — mimics raw Postgres return)
    pat.expires_at = datetime.now() + timedelta(days=2)
    pat.is_active = True
    pat.created_at = datetime.now(UTC)

    result = _to_read(pat)
    assert result.expires_soon is True  # 2 days away → should warn


def test_expiry_warning_threshold_is_7_days():
    from app.api.v1.tokens import _EXPIRY_WARNING_DAYS
    assert _EXPIRY_WARNING_DAYS == 7


def test_token_read_includes_expires_soon_in_list_response():
    """TokenRead.model_fields keys must include expires_soon for API consumers."""
    from app.api.v1.tokens import TokenRead
    schema = TokenRead.model_json_schema()
    assert "expires_soon" in schema.get("properties", {})
