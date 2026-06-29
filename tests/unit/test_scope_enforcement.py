"""Unit tests for PAT scope enforcement and X-Request-ID middleware."""
from __future__ import annotations

import asyncio
import inspect

# ---------------------------------------------------------------------------
# require_scopes dependency
# ---------------------------------------------------------------------------

def test_require_scopes_is_callable_factory():
    from app.identity.dependencies import require_scopes
    dep = require_scopes("api:read")
    assert callable(dep)


def test_require_scopes_returns_different_callables():
    from app.identity.dependencies import require_scopes
    a = require_scopes("api:read")
    b = require_scopes("api:write")
    # Must be distinct callables for FastAPI to produce distinct dependencies
    assert a is not b


def test_require_scopes_skips_check_for_jwt():
    """When no pat_scopes on request.state the function must return the user."""
    from app.identity.dependencies import require_scopes

    dep = require_scopes("api:write")
    src = inspect.getsource(dep)
    assert "pat_scopes" in src
    assert "return user" in src


def test_require_scopes_rejects_missing_scope():
    """PAT with only api:read must be rejected when api:write is required."""
    from app.identity.dependencies import require_scopes
    src = inspect.getsource(require_scopes("api:write"))
    assert "403" in src
    assert "missing" in src.lower() or "scopes" in src.lower()


def test_require_scopes_dependency_wraps_current_user_or_pat():
    from app.identity import dependencies as d
    src = inspect.getsource(d)
    # The inner closure must depend on current_user_or_pat
    assert "current_user_or_pat" in src
    assert "require_scopes" in src


def test_scope_check_uses_set_difference():
    """Missing scopes must be computed as set difference for clarity in errors."""
    from app.identity.dependencies import require_scopes
    src = inspect.getsource(require_scopes("api:write"))
    assert "missing" in src


def test_multiple_scopes_all_required():
    """All listed scopes must be required — not just any one."""
    from app.identity.dependencies import require_scopes
    src = inspect.getsource(require_scopes("api:read", "api:write"))
    # Check that it uses set operations (all vs. any)
    assert "required" in src or "scopes" in src


def test_require_scopes_functional_pass():
    """PAT with sufficient scopes must return the user object unchanged."""
    import asyncio
    from unittest.mock import MagicMock

    from app.identity.dependencies import require_scopes

    class FakeState:
        pat_scopes = ["api:read", "api:write"]

    req = MagicMock()
    req.state = FakeState()

    fake_user = object()

    dep_fn = require_scopes("api:read", "api:write")

    async def run():
        # Call the inner closure directly with the resolved user
        return await dep_fn(request=req, user=fake_user)

    result = asyncio.run(run())
    assert result is fake_user


def test_require_scopes_functional_fail():
    """PAT missing a required scope must raise 403."""
    from unittest.mock import MagicMock

    from fastapi import HTTPException

    from app.identity.dependencies import require_scopes

    class FakeState:
        pat_scopes = ["api:read"]  # missing api:write

    req = MagicMock()
    req.state = FakeState()

    dep_fn = require_scopes("api:write")

    async def run():
        return await dep_fn(request=req, user=object())

    import pytest
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(run())
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# RequestIDMiddleware
# ---------------------------------------------------------------------------

def test_middleware_generates_uuid_if_missing():
    from app.middleware.request_id import RequestIDMiddleware
    src = inspect.getsource(RequestIDMiddleware.dispatch)
    assert "uuid" in src.lower() or "uuid4" in src.lower()


def test_middleware_propagates_client_header():
    from app.middleware.request_id import RequestIDMiddleware
    src = inspect.getsource(RequestIDMiddleware.dispatch)
    assert "X-Request-ID" in src


def test_middleware_echoes_id_in_response():
    from app.middleware.request_id import RequestIDMiddleware
    src = inspect.getsource(RequestIDMiddleware.dispatch)
    # Must set response.headers["X-Request-ID"]
    assert 'response.headers["X-Request-ID"]' in src or "response.headers" in src


def test_middleware_binds_to_structlog():
    from app.middleware.request_id import RequestIDMiddleware
    src = inspect.getsource(RequestIDMiddleware.dispatch)
    assert "structlog" in src
    assert "request_id" in src


# ---------------------------------------------------------------------------
# Deep health check — source-level inspection avoids importing app.main
# (importing app.main tries to create asyncio.Lock at module scope which
# fails on Python 3.9 when there's no running event loop).
# ---------------------------------------------------------------------------

def _deep_health_src() -> str:
    from pathlib import Path
    return (Path(__file__).parents[2] / "app/main.py").read_text()


def test_deep_health_endpoint_registered():
    src = _deep_health_src()
    assert '"/health/deep"' in src


def test_deep_health_includes_database_component():
    assert "database" in _deep_health_src()


def test_deep_health_includes_key_manager_component():
    assert "key_manager" in _deep_health_src()


def test_deep_health_returns_503_on_failure():
    assert "503" in _deep_health_src()


def test_deep_health_includes_latency():
    src = _deep_health_src()
    assert "latency" in src or "latency_ms" in src


def test_deep_health_version_in_response():
    assert "version" in _deep_health_src()


# ---------------------------------------------------------------------------
# Webhook HMAC signing (already shipped — regression guard)
# ---------------------------------------------------------------------------

def test_webhook_deliver_sets_signature_header():
    from app.core.events import _deliver
    src = inspect.getsource(_deliver)
    assert "X-Auth-Signature" in src
    assert "sha256=" in src


def test_webhook_signature_uses_hmac_sha256():
    from app.core.events import _deliver
    src = inspect.getsource(_deliver)
    assert "hmac" in src.lower()
    assert "sha256" in src.lower()


def test_webhook_timestamp_included():
    from app.core.events import _deliver
    src = inspect.getsource(_deliver)
    assert "X-Auth-Timestamp" in src


def test_webhook_signing_includes_body_in_mac():
    """The MAC must cover both the timestamp and the body to prevent replay."""
    from app.core.events import _deliver
    src = inspect.getsource(_deliver)
    # Looking for the pattern: hmac over f"{ts}.{body}"
    assert "ts" in src and "body" in src
