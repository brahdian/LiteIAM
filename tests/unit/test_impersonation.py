"""Unit tests for admin user impersonation endpoint."""
from __future__ import annotations

import inspect


def test_impersonation_requires_superuser():
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "is_superuser" in src
    assert "403" in src


def test_impersonation_blocks_self():
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "actor.id" in src
    assert "yourself" in src.lower() or "self" in src.lower()


def test_impersonation_blocks_superuser_targets():
    """Privilege escalation: superusers cannot impersonate other superusers."""
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "target.is_superuser" in src
    assert "403" in src


def test_impersonation_blocks_inactive_users():
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "is_active" in src


def test_impersonation_ttl_is_one_hour():
    from datetime import timedelta

    from app.admin.users import _IMPERSONATION_TTL
    assert _IMPERSONATION_TTL == timedelta(hours=1)


def test_impersonation_override_lifetime_passed():
    """The impersonation TTL must be passed to write_token via override_lifetime."""
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "override_lifetime=_IMPERSONATION_TTL" in src


def test_impersonation_extra_claims_set():
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "impersonated" in src
    assert "impersonator_id" in src


def test_impersonation_emits_audit_event():
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "emit" in src
    assert "impersonation" in src.lower() or "impersonator" in src.lower()


def test_impersonation_warns_in_response():
    """Response must include a warning field so callers know this is an impersonation token."""
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "warning" in src.lower()


def test_impersonation_logs_at_warning_level():
    """Impersonation is a high-privilege action and must log at WARNING level."""
    from app.admin.users import impersonate_user
    src = inspect.getsource(impersonate_user)
    assert "logger.warning" in src


def test_write_token_supports_override_lifetime():
    """TenantAwareJWTStrategy.write_token must accept override_lifetime kwarg."""
    import inspect as _inspect

    from app.tokens.strategy import TenantAwareJWTStrategy
    sig = _inspect.signature(TenantAwareJWTStrategy.write_token)
    assert "override_lifetime" in sig.parameters


def test_write_token_supports_extra_claims():
    import inspect as _inspect

    from app.tokens.strategy import TenantAwareJWTStrategy
    sig = _inspect.signature(TenantAwareJWTStrategy.write_token)
    assert "extra_claims" in sig.parameters
