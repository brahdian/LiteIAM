from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Optional

import jwt
import structlog
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from fastapi_users.authentication.strategy.base import Strategy
from fastapi_users.manager import BaseUserManager

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.tokens.keys import KeyManager, key_manager
from app.tokens.revocation import is_revoked, revoke_token

logger = structlog.get_logger(__name__)

_AUDIENCE = ["open-auth:auth"]
_ALGORITHM = "RS256"

# Claims that must never be overwritten by tenant custom claims
_RESERVED_CLAIMS = frozenset({
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
    "email", "tenant_id", "tenant_name", "tenant_slug", "auth_stage",
})

# Simple in-memory cache: tenant_id → (record_dict, expires_at_monotonic)
# record holds {"custom": {...}, "name": str, "slug": str}.
# TTL of 60s balances freshness with DB pressure on high-traffic auth engines.
_CLAIMS_CACHE: dict[str, tuple[dict, float]] = {}
_CLAIMS_CACHE_TTL = 60.0


async def _get_tenant_record(tenant_id: str) -> dict:
    """Load a tenant's custom claims + descriptor (name/slug), 60s TTL cache."""
    entry = _CLAIMS_CACHE.get(tenant_id)
    if entry and time.monotonic() < entry[1]:
        return entry[0]

    record = {"custom": {}, "name": "", "slug": ""}
    try:
        from sqlalchemy import select

        from app.models.tenant import Tenant
        async with AsyncSessionLocal() as db:
            tenant = await db.scalar(
                select(Tenant).where(Tenant.id == uuid.UUID(tenant_id))
            )
            if tenant:
                raw = dict(tenant.custom_jwt_claims or {})
                record = {
                    # Strip reserved claims so custom config can't shadow them.
                    "custom": {k: v for k, v in raw.items() if k not in _RESERVED_CLAIMS},
                    "name": tenant.name or "",
                    "slug": tenant.slug or "",
                }
    except Exception as exc:
        logger.warning("tenant_record_load_failed", tenant_id=tenant_id, error=str(exc))

    _CLAIMS_CACHE[tenant_id] = (record, time.monotonic() + _CLAIMS_CACHE_TTL)
    return record


async def _get_tenant_custom_claims(tenant_id: str) -> dict:
    """Return only the custom JWT claims for a tenant (back-compat accessor)."""
    return (await _get_tenant_record(tenant_id))["custom"]


def invalidate_claims_cache(tenant_id: str) -> None:
    """Call after updating a tenant's custom_jwt_claims to force fresh load."""
    _CLAIMS_CACHE.pop(tenant_id, None)


class TenantAwareJWTStrategy(Strategy):
    """
    RSA-signed JWT strategy that injects tenant_id, roles, and auth_stage
    into every token. Overrides fastapi-users' default HMAC strategy.

    Two token types:
      - mfa_pending (TTL=5min): issued after password/OAuth, before MFA passes.
        All resource endpoints reject this token.
      - complete (TTL=access_token_lifetime): full access token with tenant claims.

    All tokens include RFC 7519-required claims:
      iss (issuer), sub, aud, iat, exp, nbf, jti
    """

    def __init__(self, km: KeyManager) -> None:
        self._km = km

    async def read_token(
        self,
        token: str | None,
        user_manager: BaseUserManager,
    ):
        if not token:
            return None
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            public_pem = self._km.get_public_pem_by_kid(kid) if kid else None

            if public_pem is None:
                logger.warning("JWT kid not found in JWKS", kid=kid)
                return None

            public_key = load_pem_public_key(public_pem)
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[_ALGORITHM],
                audience=_AUDIENCE,
            )

            if payload.get("auth_stage") != "complete":
                return None

            # Check revocation blacklist (O(1) in-memory set)
            jti = payload.get("jti")
            if jti and is_revoked(jti):
                logger.debug("JWT revoked", jti=jti[:8] + "...")
                return None

            user_id = payload.get("sub")
            if not user_id:
                return None

            return await user_manager.get(uuid.UUID(user_id))
        except jwt.ExpiredSignatureError:
            logger.debug("JWT expired")
            return None
        except (jwt.InvalidTokenError, ValueError, Exception) as exc:
            logger.debug("JWT validation failed", error=str(exc))
            return None

    async def write_token(
        self,
        user,
        *,
        override_lifetime: timedelta | None = None,
        extra_claims: dict | None = None,
    ) -> str:
        key = self._km.get_current_key()
        private_key = load_pem_private_key(key["private_pem"], password=None)
        now = datetime.now(UTC)
        jti = str(uuid.uuid4())
        lifetime = override_lifetime or timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS)

        # Start with tenant custom claims + descriptor (reserved names stripped)
        record = await _get_tenant_record(str(user.tenant_id))
        payload = {
            **record["custom"],
            **(extra_claims or {}),
            # Reserved claims always overwrite — custom claims cannot shadow them
            "iss": settings.BASE_URL,          # RFC 7519 §4.1.1 — issuer
            "sub": str(user.id),               # RFC 7519 §4.1.2
            "aud": _AUDIENCE,                  # RFC 7519 §4.1.3
            "iat": now,                        # RFC 7519 §4.1.6
            "nbf": now,                        # RFC 7519 §4.1.5 — not before
            "exp": now + lifetime,
            "jti": jti,                        # RFC 7519 §4.1.7 — unique ID for revocation
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            # Org descriptor so downstream (api-gateway) can JIT-provision a
            # meaningful tenant for self-serve SaaS signups without a back-call.
            "tenant_name": record["name"],
            "tenant_slug": record["slug"],
            "auth_stage": "complete",
        }
        return jwt.encode(payload, private_key, algorithm=_ALGORITHM, headers={"kid": key["kid"]})

    async def write_mfa_pending_token(self, user) -> str:
        """Short-lived token issued after first factor. Rejected by all resource endpoints."""
        key = self._km.get_current_key()
        private_key = load_pem_private_key(key["private_pem"], password=None)
        now = datetime.now(UTC)
        payload = {
            "iss": settings.BASE_URL,
            "sub": str(user.id),
            "aud": _AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=settings.MFA_PENDING_TOKEN_LIFETIME_SECONDS),
            "jti": str(uuid.uuid4()),
            "tenant_id": str(user.tenant_id),
            "auth_stage": "mfa_pending",
        }
        return jwt.encode(payload, private_key, algorithm=_ALGORITHM, headers={"kid": key["kid"]})

    async def read_mfa_pending_token(self, token: str) -> dict | None:
        """Decode a mfa_pending token. Returns payload or None."""
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            public_pem = self._km.get_public_pem_by_kid(kid) if kid else None
            if public_pem is None:
                return None
            public_key = load_pem_public_key(public_pem)
            payload = jwt.decode(
                token, public_key, algorithms=[_ALGORITHM], audience=_AUDIENCE
            )
            if payload.get("auth_stage") != "mfa_pending":
                return None
            return payload
        except Exception:
            return None

    async def destroy_token(self, token: str, user) -> None:
        """Revoke a specific token by adding its jti to the blacklist."""
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            public_pem = self._km.get_public_pem_by_kid(kid) if kid else None
            if public_pem:
                public_key = load_pem_public_key(public_pem)
                payload = jwt.decode(
                    token, public_key, algorithms=[_ALGORITHM],
                    audience=_AUDIENCE, options={"verify_exp": False}
                )
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp:
                    expires_at = datetime.fromtimestamp(exp, tz=UTC)
                    # Revocation watcher broadcasts to all workers via PG NOTIFY
                    from app.core.database import AsyncSessionLocal
                    async with AsyncSessionLocal() as db:
                        await revoke_token(jti, expires_at, db)
                        await db.commit()
        except Exception:
            logger.warning("destroy_token failed to parse token", user_id=str(user.id))


def get_jwt_strategy() -> TenantAwareJWTStrategy:
    return TenantAwareJWTStrategy(key_manager)
