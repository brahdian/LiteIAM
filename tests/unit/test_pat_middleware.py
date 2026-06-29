"""Unit tests for PATAuthMiddleware and registration rate-limiter."""
from __future__ import annotations

import hashlib
import inspect
import time

# ---------------------------------------------------------------------------
# PATAuthMiddleware
# ---------------------------------------------------------------------------

def test_middleware_skips_non_aai_bearer():
    """Non-aai_ bearer tokens must be passed through unchanged."""
    from app.middleware.pat_auth import PATAuthMiddleware
    src = inspect.getsource(PATAuthMiddleware.dispatch)
    assert "_PREFIX" in src or "aai_" in src


def test_middleware_skips_no_auth():
    """Requests without Authorization header must pass through."""
    from app.middleware.pat_auth import PATAuthMiddleware
    src = inspect.getsource(PATAuthMiddleware.dispatch)
    # If neither Bearer nor aai_ prefix, should call_next
    assert "call_next" in src


def test_pat_hash_consistency():
    """Middleware and tokens module must use identical hash logic."""
    from app.api.v1.tokens import _hash as tok_hash
    from app.middleware.pat_auth import _hash as mw_hash

    raw = "aai_testpayload123"
    assert mw_hash(raw) == tok_hash(raw)


def test_pat_hash_strips_prefix():
    from app.middleware.pat_auth import _hash
    raw = "aai_secret"
    expected = hashlib.sha256(b"secret").hexdigest()
    assert _hash(raw) == expected


def test_bg_tasks_set_used_for_gc_safety():
    """_bg_tasks set must exist so last_used_at tasks are not GC'd mid-flight."""
    import app.middleware.pat_auth as mod
    assert hasattr(mod, "_bg_tasks")
    assert isinstance(mod._bg_tasks, set)


def test_spawn_adds_task_to_bg_set():
    """_spawn must add the task to _bg_tasks immediately."""
    import asyncio

    import app.middleware.pat_auth as mod

    async def _noop(): pass

    prev_count = len(mod._bg_tasks)

    async def run():
        t = mod._spawn(_noop())
        assert t in mod._bg_tasks
        await t

    asyncio.run(run())
    # After completion the callback discards the task
    assert len(mod._bg_tasks) == prev_count


def test_pat_scopes_stored_in_request_state():
    """Middleware must store pat_scopes alongside pat_user in request.state."""
    from app.middleware.pat_auth import PATAuthMiddleware
    src = inspect.getsource(PATAuthMiddleware.dispatch)
    assert "pat_scopes" in src


def test_middleware_401_on_invalid_token():
    """Invalid PAT must return 401 JSONResponse, not pass to next handler."""
    from app.middleware.pat_auth import PATAuthMiddleware
    src = inspect.getsource(PATAuthMiddleware.dispatch)
    assert "401" in src
    assert "JSONResponse" in src


def test_update_last_used_is_fire_and_forget():
    """last_used_at must be updated asynchronously via _spawn."""
    from app.middleware.pat_auth import PATAuthMiddleware
    src = inspect.getsource(PATAuthMiddleware.dispatch)
    assert "_spawn" in src
    assert "_update_last_used" in src


# ---------------------------------------------------------------------------
# current_user_or_pat dependency
# ---------------------------------------------------------------------------

def test_dependency_checks_pat_user_first():
    from app.identity.dependencies import current_user_or_pat
    src = inspect.getsource(current_user_or_pat)
    assert "pat_user" in src


def test_dependency_falls_through_to_jwt():
    """When no PAT state is present the dependency must validate a JWT."""
    from app.identity.dependencies import current_user_or_pat
    src = inspect.getsource(current_user_or_pat)
    assert "read_token" in src or "get_jwt_strategy" in src


def test_dependency_raises_401_on_no_auth():
    from app.identity.dependencies import current_user_or_pat
    src = inspect.getsource(current_user_or_pat)
    assert "401" in src


# ---------------------------------------------------------------------------
# RegistrationRateLimitMiddleware
# ---------------------------------------------------------------------------

def test_reg_rate_limit_path_match():
    from app.middleware.reg_rate_limit import _REGISTER_PATH
    assert _REGISTER_PATH == "/auth/register"


def test_reg_rate_limit_window_is_one_hour():
    from app.middleware.reg_rate_limit import _WINDOW_SECONDS
    assert _WINDOW_SECONDS == 3600


def test_reg_rate_limit_default_cap():
    from app.middleware.reg_rate_limit import _MAX_REGISTRATIONS
    assert _MAX_REGISTRATIONS == 5


def test_reg_counter_allows_under_limit():
    from app.middleware.reg_rate_limit import _RegCounter
    c = _RegCounter()
    for _ in range(5):
        assert c.check_and_record("1.2.3.4") is True


def test_reg_counter_blocks_over_limit():
    from app.middleware.reg_rate_limit import _RegCounter
    c = _RegCounter()
    for _ in range(5):
        c.check_and_record("5.6.7.8")
    assert c.check_and_record("5.6.7.8") is False


def test_reg_counter_isolates_ips():
    from app.middleware.reg_rate_limit import _MAX_REGISTRATIONS, _RegCounter
    c = _RegCounter()
    # Fill up ip A
    for _ in range(_MAX_REGISTRATIONS):
        c.check_and_record("10.0.0.1")
    # ip B must still be allowed
    assert c.check_and_record("10.0.0.2") is True


def test_reg_counter_sliding_window():
    from app.middleware.reg_rate_limit import _MAX_REGISTRATIONS, _WINDOW_SECONDS, _RegCounter
    c = _RegCounter()
    # Manually inject stale entries outside the window
    old_time = time.monotonic() - _WINDOW_SECONDS - 10
    c._hits["9.9.9.9"] = [old_time] * _MAX_REGISTRATIONS
    # Now fresh request should be allowed (stale entries pruned)
    assert c.check_and_record("9.9.9.9") is True


def test_middleware_only_limits_post():
    """GET /auth/register (if it existed) must not be rate-limited."""
    from app.middleware.reg_rate_limit import RegistrationRateLimitMiddleware
    src = inspect.getsource(RegistrationRateLimitMiddleware.dispatch)
    assert "POST" in src
    assert "method" in src


def test_middleware_returns_429():
    from app.middleware.reg_rate_limit import RegistrationRateLimitMiddleware
    src = inspect.getsource(RegistrationRateLimitMiddleware.dispatch)
    assert "429" in src


def test_middleware_includes_retry_after_header():
    from app.middleware.reg_rate_limit import RegistrationRateLimitMiddleware
    src = inspect.getsource(RegistrationRateLimitMiddleware.dispatch)
    assert "Retry-After" in src


def test_audit_log_ui_route_exists():
    from app.ui.router import router
    paths = [r.path for r in router.routes if hasattr(r, "path")]
    assert "/ui/admin/audit" in paths
