"""Unit tests for custom JWT claims: validation, cache, and reserved-name blocking."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.tokens.strategy import (
    _CLAIMS_CACHE,
    _RESERVED_CLAIMS,
    _get_tenant_custom_claims,
    invalidate_claims_cache,
)

# ---------------------------------------------------------------------------
# Reserved claim set
# ---------------------------------------------------------------------------

def test_reserved_claims_contains_security_critical_names():
    for name in ("sub", "iss", "aud", "exp", "iat", "nbf", "jti", "tenant_id", "auth_stage"):
        assert name in _RESERVED_CLAIMS, f"{name!r} must be reserved"


# ---------------------------------------------------------------------------
# _get_tenant_custom_claims cache
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_claims_cache():
    _CLAIMS_CACHE.clear()
    yield
    _CLAIMS_CACHE.clear()


@pytest.mark.asyncio
async def test_get_claims_returns_empty_when_no_tenant():
    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_db = AsyncMock()
        mock_db.scalar = AsyncMock(return_value=None)
        mock_sl.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        claims = await _get_tenant_custom_claims(str(uuid.uuid4()))
    assert claims == {}


@pytest.mark.asyncio
async def test_get_claims_returns_tenant_custom_claims():
    tenant_id = str(uuid.uuid4())
    tenant = MagicMock()
    tenant.custom_jwt_claims = {"org_plan": "enterprise", "region": "us-east"}

    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_db = AsyncMock()
        mock_db.scalar = AsyncMock(return_value=tenant)
        mock_sl.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        claims = await _get_tenant_custom_claims(tenant_id)

    assert claims == {"org_plan": "enterprise", "region": "us-east"}


@pytest.mark.asyncio
async def test_get_claims_strips_reserved_names():
    """Even if DB has reserved names in custom_jwt_claims, they must be stripped."""
    tenant_id = str(uuid.uuid4())
    tenant = MagicMock()
    tenant.custom_jwt_claims = {"sub": "hacked", "org_plan": "enterprise", "exp": 99999}

    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_db = AsyncMock()
        mock_db.scalar = AsyncMock(return_value=tenant)
        mock_sl.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        claims = await _get_tenant_custom_claims(tenant_id)

    assert "sub" not in claims
    assert "exp" not in claims
    assert claims.get("org_plan") == "enterprise"


@pytest.mark.asyncio
async def test_get_claims_uses_cache_on_second_call():
    """Second call should not hit DB if cache is fresh."""
    tenant_id = str(uuid.uuid4())
    tenant = MagicMock()
    tenant.custom_jwt_claims = {"plan": "free"}

    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_db = AsyncMock()
        mock_db.scalar = AsyncMock(return_value=tenant)
        mock_sl.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        await _get_tenant_custom_claims(tenant_id)
        await _get_tenant_custom_claims(tenant_id)

    # DB should only have been called once
    assert mock_db.scalar.await_count == 1


@pytest.mark.asyncio
async def test_get_claims_refreshes_after_invalidation():
    tenant_id = str(uuid.uuid4())
    tenant = MagicMock()
    tenant.custom_jwt_claims = {"plan": "free"}

    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_db = AsyncMock()
        mock_db.scalar = AsyncMock(return_value=tenant)
        mock_sl.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        await _get_tenant_custom_claims(tenant_id)
        invalidate_claims_cache(tenant_id)
        await _get_tenant_custom_claims(tenant_id)

    # Should have queried DB twice (before and after invalidation)
    assert mock_db.scalar.await_count == 2


@pytest.mark.asyncio
async def test_get_claims_returns_empty_on_db_error():
    """If DB raises, return empty dict rather than propagating — prevents auth breakage."""
    tenant_id = str(uuid.uuid4())

    with patch("app.tokens.strategy.AsyncSessionLocal") as mock_sl:
        mock_sl.return_value.__aenter__ = AsyncMock(side_effect=RuntimeError("db down"))
        mock_sl.return_value.__aexit__ = AsyncMock(return_value=False)

        claims = await _get_tenant_custom_claims(tenant_id)

    assert claims == {}


# ---------------------------------------------------------------------------
# JWTClaimsWrite validation (via admin endpoint schema)
# ---------------------------------------------------------------------------

def test_jwt_claims_write_rejects_reserved_sub():
    from app.admin.jwt_claims import JWTClaimsWrite
    with pytest.raises(Exception):
        JWTClaimsWrite(claims={"sub": "evil"})


def test_jwt_claims_write_rejects_reserved_exp():
    from app.admin.jwt_claims import JWTClaimsWrite
    with pytest.raises(Exception):
        JWTClaimsWrite(claims={"exp": 99999999})


def test_jwt_claims_write_accepts_valid_claims():
    from app.admin.jwt_claims import JWTClaimsWrite
    body = JWTClaimsWrite(claims={"org_plan": "enterprise", "region": "us-east", "tier": 3})
    assert body.claims["org_plan"] == "enterprise"


def test_jwt_claims_write_rejects_nested_objects():
    from app.admin.jwt_claims import JWTClaimsWrite
    with pytest.raises(Exception):
        JWTClaimsWrite(claims={"meta": {"nested": "value"}})


def test_jwt_claims_write_rejects_more_than_20():
    from app.admin.jwt_claims import JWTClaimsWrite
    with pytest.raises(Exception):
        JWTClaimsWrite(claims={f"k{i}": "v" for i in range(21)})


def test_jwt_claims_write_allows_bool_values():
    from app.admin.jwt_claims import JWTClaimsWrite
    body = JWTClaimsWrite(claims={"is_enterprise": True, "is_trial": False})
    assert body.claims["is_enterprise"] is True
