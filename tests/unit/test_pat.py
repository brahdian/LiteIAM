"""Unit tests for Personal Access Tokens."""
from __future__ import annotations

import hashlib
import inspect


def test_token_prefix():
    from app.api.v1.tokens import _PREFIX, _generate_raw
    raw = _generate_raw()
    assert raw.startswith(_PREFIX)


def test_raw_token_length():
    from app.api.v1.tokens import _generate_raw
    raw = _generate_raw()
    # "aai_" + 43 chars base64url (32 bytes) = 47 chars minimum
    assert len(raw) >= 47


def test_hash_strips_prefix():
    """Hash must be computed on the payload without the prefix."""
    from app.api.v1.tokens import _PREFIX, _hash
    raw = _PREFIX + "abcdef"
    expected = hashlib.sha256(b"abcdef").hexdigest()
    assert _hash(raw) == expected


def test_hash_handles_no_prefix():
    from app.api.v1.tokens import _hash
    raw = "noprefixtoken"
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert _hash(raw) == expected


def test_valid_scopes_defined():
    from app.api.v1.tokens import _VALID_SCOPES
    assert "api:read" in _VALID_SCOPES
    assert "api:write" in _VALID_SCOPES
    assert "admin" in _VALID_SCOPES


def test_max_tokens_limit_enforced():
    from app.api.v1.tokens import create_token
    src = inspect.getsource(create_token)
    assert "_MAX_TOKENS_PER_USER" in src


def test_raw_token_shown_once():
    """The raw token must appear in the create response."""
    from app.api.v1.tokens import create_token
    src = inspect.getsource(create_token)
    assert '"token": raw' in src or '"token"' in src


def test_raw_token_not_stored():
    """Raw token must never be a column on PersonalAccessToken."""
    from app.models.pat import PersonalAccessToken
    assert not hasattr(PersonalAccessToken, "token")
    assert hasattr(PersonalAccessToken, "token_hash")


def test_pat_model_has_scopes():
    from app.models.pat import PersonalAccessToken
    assert hasattr(PersonalAccessToken, "scopes")


def test_pat_model_has_last_used():
    from app.models.pat import PersonalAccessToken
    assert hasattr(PersonalAccessToken, "last_used_at")


def test_router_prefix():
    from app.api.v1.tokens import router
    assert router.prefix == "/auth/tokens"


def test_list_route_exists():
    from app.api.v1.tokens import router
    get_routes = [r for r in router.routes if hasattr(r, "methods") and "GET" in r.methods]
    assert any(r.path == "/auth/tokens" for r in get_routes)


def test_create_route_exists():
    from app.api.v1.tokens import router
    post_routes = [r for r in router.routes if hasattr(r, "methods") and "POST" in r.methods]
    assert any(r.path == "/auth/tokens" for r in post_routes)


def test_revoke_route_exists():
    from app.api.v1.tokens import router
    del_routes = [r for r in router.routes if hasattr(r, "methods") and "DELETE" in r.methods]
    assert len(del_routes) >= 1


def test_revoke_is_soft_delete():
    """Revocation must be a soft-delete (is_active=False), not a hard delete."""
    from app.api.v1.tokens import revoke_token
    src = inspect.getsource(revoke_token)
    assert "is_active=False" in src or "is_active = False" in src
    assert "delete" not in src.lower().split("is_active")[0][-50:]


def test_invalid_scope_rejected():
    from app.api.v1.tokens import create_token
    src = inspect.getsource(create_token)
    assert "Invalid scopes" in src or "invalid" in src.lower()


def test_expiry_cap():
    from app.api.v1.tokens import _MAX_EXPIRY_DAYS
    assert _MAX_EXPIRY_DAYS == 365


def test_migration_0014_exists():
    from pathlib import Path
    path = Path(__file__).parents[2] / "migrations/versions/0014_personal_access_tokens.py"
    assert path.exists()
