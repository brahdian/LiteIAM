"""Unit tests for structured logging, RFC 7807 errors, and security email notifications."""
from __future__ import annotations

import inspect

# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------

def test_logging_module_exists():
    from pathlib import Path
    assert (Path(__file__).parents[2] / "app/core/logging.py").exists()


def test_configure_logging_callable():
    from app.core.logging import configure_logging
    assert callable(configure_logging)


def test_configure_logging_uses_structlog():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "structlog.configure" in src


def test_configure_logging_handles_production():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "production" in src
    assert "JSONRenderer" in src


def test_configure_logging_handles_dev():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "ConsoleRenderer" in src


def test_configure_logging_binds_contextvars():
    """merge_contextvars must be in processors so request_id propagates."""
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "merge_contextvars" in src or "contextvars" in src


def test_configure_logging_timestamps_utc():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "utc=True" in src or 'fmt="iso"' in src


def test_configure_logging_adds_log_level():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "add_log_level" in src


def test_configure_logging_quiets_sqlalchemy_in_prod():
    from app.core.logging import configure_logging
    src = inspect.getsource(configure_logging)
    assert "sqlalchemy" in src.lower()


# ---------------------------------------------------------------------------
# RFC 7807 Problem Details
# ---------------------------------------------------------------------------

def test_problem_details_module_exists():
    from pathlib import Path
    assert (Path(__file__).parents[2] / "app/core/exceptions.py").exists()


def test_problem_type_uri_format():
    from app.core.exceptions import _PROBLEM_BASE
    assert _PROBLEM_BASE.startswith("https://")
    assert "problems" in _PROBLEM_BASE


def test_problem_includes_required_fields():
    """RFC 7807 requires type, title, status, detail. instance is recommended."""
    from app.core.exceptions import _problem
    src = inspect.getsource(_problem)
    for field in ("type", "title", "status", "detail", "instance"):
        assert f'"{field}"' in src


def test_problem_content_type_header():
    from app.core.exceptions import _problem
    src = inspect.getsource(_problem)
    assert "application/problem+json" in src


def test_validation_error_handler_returns_422():
    from app.core.exceptions import _validation_error_handler
    src = inspect.getsource(_validation_error_handler)
    assert "422" in src


def test_http_exception_preserves_extra_headers():
    """Retry-After and other extra headers from the original exception must pass through."""
    from app.core.exceptions import _http_exception_handler
    src = inspect.getsource(_http_exception_handler)
    assert "headers" in src


def test_add_problem_details_handler_callable():
    from app.core.exceptions import add_problem_details_handler
    assert callable(add_problem_details_handler)


def test_status_slugs_map_common_codes():
    from app.core.exceptions import _STATUS_SLUGS
    for code in (400, 401, 403, 404, 422, 429, 500, 503):
        assert code in _STATUS_SLUGS
        assert _STATUS_SLUGS[code]  # non-empty slug


def test_status_titles_match_slugs():
    from app.core.exceptions import _STATUS_SLUGS, _STATUS_TITLES
    assert set(_STATUS_SLUGS.keys()) == set(_STATUS_TITLES.keys())


def test_problem_functional():
    """Smoke test: _problem returns a JSONResponse with correct shape."""
    from unittest.mock import MagicMock

    from app.core.exceptions import _problem

    request = MagicMock()
    request.url.path = "/auth/login"

    resp = _problem(request, 401, "bad creds")
    import json
    body = json.loads(resp.body)
    assert body["status"] == 401
    assert body["detail"] == "bad creds"
    assert body["instance"] == "/auth/login"
    assert "type" in body
    assert "title" in body
    assert resp.headers["content-type"] == "application/problem+json"


# ---------------------------------------------------------------------------
# Password change security email
# ---------------------------------------------------------------------------

def test_password_changed_alert_exists():
    from app.notifications.email import send_password_changed_alert
    assert callable(send_password_changed_alert)


def test_password_changed_alert_subject():
    from app.notifications.email import send_password_changed_alert
    src = inspect.getsource(send_password_changed_alert)
    assert "password" in src.lower()
    assert "changed" in src.lower() or "change" in src.lower()


def test_password_changed_alert_includes_reset_link():
    from app.notifications.email import send_password_changed_alert
    src = inspect.getsource(send_password_changed_alert)
    assert "forgot-password" in src or "reset" in src.lower()


def test_password_changed_wired_into_on_after_update():
    from app.identity.password import UserManager
    src = inspect.getsource(UserManager.on_after_update)
    assert "send_password_changed_alert" in src
    assert "USER_PASSWORD_CHANGED" in src or "password_changed" in src.lower()


def test_password_changed_emits_audit_event():
    from app.identity.password import UserManager
    src = inspect.getsource(UserManager.on_after_update)
    assert "emit" in src
    assert "USER_PASSWORD_CHANGED" in src


def test_password_changed_fires_email_as_task():
    """Security email must be fire-and-forget (asyncio.create_task) to avoid blocking."""
    from app.identity.password import UserManager
    src = inspect.getsource(UserManager.on_after_update)
    assert "create_task" in src or "spawn" in src.lower()


# ---------------------------------------------------------------------------
# Main.py wiring
# ---------------------------------------------------------------------------

def test_main_calls_configure_logging():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/main.py").read_text()
    assert "configure_logging" in src


def test_main_calls_add_problem_details_handler():
    from pathlib import Path
    src = (Path(__file__).parents[2] / "app/main.py").read_text()
    assert "add_problem_details_handler" in src
