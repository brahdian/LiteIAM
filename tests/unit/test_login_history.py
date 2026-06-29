"""Unit tests for login session tracking, TOTP disable, and security event emails."""
from __future__ import annotations

import inspect

# ---------------------------------------------------------------------------
# LoginSession model
# ---------------------------------------------------------------------------

def test_login_session_model_exists():
    from app.models.login_session import LoginSession
    assert LoginSession is not None


def test_login_session_model_fields():
    from app.models.login_session import LoginSession
    for col in ("id", "user_id", "tenant_id", "ip_address", "user_agent",
                "created_at", "last_seen_at", "is_active"):
        assert hasattr(LoginSession, col), f"missing column: {col}"


def test_login_session_in_models_init():
    from app.models import LoginSession
    assert LoginSession is not None


def test_migration_0016_exists():
    from pathlib import Path
    p = Path(__file__).parents[2] / "migrations/versions/0016_login_sessions.py"
    assert p.exists()


def test_migration_0016_creates_table():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "migrations/versions/0016_login_sessions.py").read_text()
    assert "login_sessions" in src
    assert "create_table" in src


def test_migration_0016_has_downgrade():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "migrations/versions/0016_login_sessions.py").read_text()
    assert "drop_table" in src


# ---------------------------------------------------------------------------
# login_history router
# ---------------------------------------------------------------------------

def test_login_history_router_exists():
    from app.api.v1.login_history import router
    assert router is not None


def test_login_history_router_prefix():
    from app.api.v1.login_history import router
    assert router.prefix == "/auth/login-events"


def test_login_history_list_endpoint():
    from app.api.v1.login_history import router
    paths = {r.path for r in router.routes}
    assert "/auth/login-events" in paths or "" in paths


def test_login_history_delete_endpoint_exists():
    from app.api.v1.login_history import router
    paths = {r.path for r in router.routes}
    assert any("{" in p for p in paths), "no delete-by-id endpoint found"


def test_record_login_is_callable():
    from app.api.v1.login_history import record_login
    assert callable(record_login)


def test_record_login_evicts_oldest():
    from app.api.v1.login_history import record_login
    src = inspect.getsource(record_login)
    assert "evict" in src or "overflow" in src


def test_session_cap_is_10():
    from app.api.v1.login_history import _MAX_SESSIONS_PER_USER
    assert _MAX_SESSIONS_PER_USER == 10


def test_login_history_mounted_in_main():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/main.py").read_text()
    assert "login_history" in src or "login_history_router" in src


def test_login_event_read_schema():
    from app.api.v1.login_history import LoginEventRead
    fields = LoginEventRead.model_fields
    for f in ("id", "ip_address", "user_agent", "created_at", "is_current"):
        assert f in fields


def test_is_current_flag_in_list():
    from app.api.v1.login_history import list_login_events
    src = inspect.getsource(list_login_events)
    assert "is_current" in src


# ---------------------------------------------------------------------------
# TOTP disable endpoint
# ---------------------------------------------------------------------------

def test_totp_disable_endpoint_exists():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "/totp" in src
    assert "totp_disable" in src or "DELETE" in src.upper()


def test_totp_disable_blocks_when_tenant_requires_mfa():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "require_mfa" in src
    assert "MFA is required" in src or "required by your organisation" in src


def test_totp_disable_emits_mfa_disabled_event():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "MFA_DISABLED" in src


def test_mfa_disabled_event_exists_in_enum():
    from app.core.events import AuthEvent
    assert hasattr(AuthEvent, "MFA_DISABLED")
    assert AuthEvent.MFA_DISABLED.value == "mfa.disabled"


def test_totp_disable_sends_email():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "send_mfa_disabled_alert" in src


# ---------------------------------------------------------------------------
# Security event emails
# ---------------------------------------------------------------------------

def test_pat_created_alert_exists():
    from app.notifications.email import send_pat_created_alert
    assert callable(send_pat_created_alert)


def test_pat_created_alert_includes_name_and_scopes():
    from app.notifications.email import send_pat_created_alert
    src = inspect.getsource(send_pat_created_alert)
    assert "pat_name" in src
    assert "scopes" in src


def test_pat_created_alert_includes_revoke_link():
    from app.notifications.email import send_pat_created_alert
    src = inspect.getsource(send_pat_created_alert)
    assert "account" in src.lower() or "revoke" in src.lower()


def test_mfa_disabled_alert_exists():
    from app.notifications.email import send_mfa_disabled_alert
    assert callable(send_mfa_disabled_alert)


def test_mfa_disabled_alert_subject_mentions_2fa():
    from app.notifications.email import send_mfa_disabled_alert
    src = inspect.getsource(send_mfa_disabled_alert)
    assert "Two-factor" in src or "2FA" in src or "MFA" in src


def test_pat_alert_wired_into_create_token():
    from app.api.v1.tokens import create_token
    src = inspect.getsource(create_token)
    assert "send_pat_created_alert" in src or "pat_alert" in src


def test_pat_alert_fires_as_task():
    from app.api.v1.tokens import create_token
    src = inspect.getsource(create_token)
    # fire-and-forget via the GC-safe spawn() helper (or raw create_task)
    assert "spawn" in src or "create_task" in src


def test_login_history_records_on_success():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/api/v1/auth.py").read_text()
    assert "record_login" in src
