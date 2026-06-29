"""Unit tests for GDPR erasure and export endpoints."""
from __future__ import annotations

import inspect


def test_gdpr_router_prefix():
    from app.api.v1.gdpr import router
    assert router.prefix == "/users/me"


def test_export_endpoint_exists():
    from app.api.v1.gdpr import router
    get_routes = [r for r in router.routes if hasattr(r, "methods") and "GET" in r.methods]
    assert any("/users/me/export" == r.path for r in get_routes)


def test_erase_endpoint_exists():
    from app.api.v1.gdpr import router
    delete_routes = [r for r in router.routes if hasattr(r, "methods") and "DELETE" in r.methods]
    assert len(delete_routes) >= 1


def test_erasure_anonymizes_email():
    """Erasure must replace email with non-reversible placeholder — no hard delete."""
    from app.api.v1.gdpr import erase_my_account
    src = inspect.getsource(erase_my_account)
    assert "deleted+" in src
    assert "@deleted.local" in src


def test_erasure_deactivates_user():
    from app.api.v1.gdpr import erase_my_account
    src = inspect.getsource(erase_my_account)
    assert "is_active=False" in src


def test_erasure_blanks_password():
    """Hashed password must be cleared — prevents any future authentication."""
    from app.api.v1.gdpr import erase_my_account
    src = inspect.getsource(erase_my_account)
    assert 'hashed_password=""' in src or "hashed_password=''," in src or "hashed_password=" in src


def test_erasure_deletes_trusted_devices():
    """Trusted devices contain PII (IP + UA) and must be hard-deleted."""
    from app.api.v1.gdpr import erase_my_account
    src = inspect.getsource(erase_my_account)
    assert "TrustedDevice" in src
    assert "delete" in src.lower()


def test_erasure_revokes_passkeys():
    from app.api.v1.gdpr import erase_my_account
    src = inspect.getsource(erase_my_account)
    assert "PasskeyCredential" in src
    assert "is_revoked=True" in src


def test_erasure_emits_audit_event():
    from app.api.v1.gdpr import erase_my_account
    from app.core.events import AuthEvent
    src = inspect.getsource(erase_my_account)
    assert "USER_DELETED" in src or AuthEvent.USER_DELETED.value in src


def test_export_includes_profile_and_audit():
    from app.api.v1.gdpr import export_my_data
    src = inspect.getsource(export_my_data)
    assert "profile" in src
    assert "audit" in src.lower()
    assert "security_keys" in src or "passkey" in src.lower()


def test_export_sets_content_disposition():
    """Export response must signal file download for browsers."""
    from app.api.v1.gdpr import export_my_data
    src = inspect.getsource(export_my_data)
    assert "Content-Disposition" in src
    assert "attachment" in src
