from __future__ import annotations

"""
Enterprise BYOIDP (Bring Your Own Identity Provider).

Enables tenants to authenticate users against their own Okta / Azure AD /
Google Workspace OIDC provider. After the external IDP authenticates the user,
auth-engine issues its own JWT so the rest of the platform doesn't need to know
which IDP the user came from.

Flow:
  1. Tenant admin configures their IDP in TenantIDPConfig via admin API
  2. User visits /auth/enterprise/login?tenant_id=X
  3. DynamicIDPRouter loads the tenant's OIDC config from DB, builds the
     authorization URL, and redirects the user to their employer's IDP
  4. IDP redirects back to /auth/enterprise/callback?state=...
  5. We exchange the code, fetch userinfo from the IDP, and JIT-provision the
     user (create if new, update if existing)
  6. We map IDP groups → Casbin roles and issue our own JWT

Critical:
- client_secret is decrypted from TenantIDPConfig.client_secret_enc only
  at request time — never stored in plaintext in memory between requests
- The OIDC discovery URL is fetched fresh per request (or cached with a
  short TTL in Phase 6 hardening) — dynamic config loading avoids restarts
"""

import hashlib
import hmac
import secrets
import time
import uuid
from typing import Optional
from urllib.parse import urlencode

import structlog
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authz.enforcer import casbin_enforcer
from app.core.config import settings
from app.identity.social import upsert_oauth_user
from app.models.idp_config import TenantIDPConfig
from app.models.user import User

logger = structlog.get_logger(__name__)

_IDP_CALLBACK_PATH = "/auth/enterprise/callback"


# ---------------------------------------------------------------------------
# Config loading + secret decryption
# ---------------------------------------------------------------------------

async def get_tenant_idp_config(tenant_id: uuid.UUID, db: AsyncSession) -> TenantIDPConfig:
    config = await db.scalar(
        select(TenantIDPConfig).where(
            TenantIDPConfig.tenant_id == tenant_id,
            TenantIDPConfig.is_active,
        )
    )
    if config is None:
        raise HTTPException(404, f"No IDP configured for tenant {tenant_id}")
    return config


def _decrypt_client_secret(enc: str) -> str:
    f = Fernet(settings.fernet_key())
    return f.decrypt(enc.encode()).decode()


def _encrypt_client_secret(secret: str) -> str:
    f = Fernet(settings.fernet_key())
    return f.encrypt(secret.encode()).decode()


# ---------------------------------------------------------------------------
# OIDC discovery — fetch provider endpoints
# ---------------------------------------------------------------------------

async def fetch_oidc_metadata(discovery_url: str) -> dict:
    from app.identity.social import get_http_client
    client = await get_http_client()
    resp = await client.get(discovery_url)
    if resp.status_code != 200:
        raise HTTPException(502, f"Failed to fetch OIDC metadata from {discovery_url}")
    return resp.json()


# ---------------------------------------------------------------------------
# DynamicIDPRouter — load IDP config from DB and build authorization URL
# ---------------------------------------------------------------------------

class DynamicIDPRouter:
    """
    Builds the OIDC authorization URL for a tenant's configured IDP.
    Config is loaded from DB per request — no restart needed when admin
    updates a tenant's IDP credentials.
    """

    async def build_authorize_url(
        self,
        tenant_id: uuid.UUID,
        db: AsyncSession,
        nonce: str | None = None,
    ) -> str:
        config = await get_tenant_idp_config(tenant_id, db)
        metadata = await fetch_oidc_metadata(config.discovery_url)
        authorization_endpoint = metadata.get("authorization_endpoint")
        if not authorization_endpoint:
            raise HTTPException(502, "IDP discovery missing authorization_endpoint")

        state = _make_enterprise_state(tenant_id, settings.SECRET_KEY)
        redirect_uri = f"{settings.BASE_URL}{_IDP_CALLBACK_PATH}"

        params = {
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }
        if nonce:
            params["nonce"] = nonce

        return f"{authorization_endpoint}?{urlencode(params)}"

    async def handle_callback(
        self,
        code: str,
        state: str,
        db: AsyncSession,
    ) -> User:
        tenant_id_str = _verify_enterprise_state(state, settings.SECRET_KEY)
        tenant_id = uuid.UUID(tenant_id_str)

        config = await get_tenant_idp_config(tenant_id, db)
        metadata = await fetch_oidc_metadata(config.discovery_url)

        token_endpoint = metadata.get("token_endpoint")
        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if not token_endpoint or not userinfo_endpoint:
            raise HTTPException(502, "IDP discovery missing endpoints")

        client_secret = _decrypt_client_secret(config.client_secret_enc)
        redirect_uri = f"{settings.BASE_URL}{_IDP_CALLBACK_PATH}"

        from app.identity.social import get_http_client
        http = await get_http_client()

        # Exchange code for tokens
        token_resp = await http.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": config.client_id,
                "client_secret": client_secret,
            },
        )
        if token_resp.status_code != 200:
            raise HTTPException(400, "Enterprise IDP token exchange failed")
        token_data = token_resp.json()

        # Fetch userinfo
        userinfo_resp = await http.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(400, "Failed to fetch enterprise userinfo")
        userinfo = userinfo_resp.json()

        email = userinfo.get("email")
        if not email:
            raise HTTPException(400, "IDP did not return an email claim")

        provider_sub = userinfo.get("sub", email)

        # JIT-provision: create or update the user in our DB
        user = await upsert_oauth_user(
            email=email,
            tenant_id=tenant_id,
            provider=f"enterprise:{config.tenant_id}",
            provider_account_id=provider_sub,
            access_token=token_data.get("access_token", ""),
            db=db,
        )

        # Apply role mapping from IDP groups
        if config.role_mapping:
            await _apply_role_mapping(user, userinfo, config, db)

        return user


# ---------------------------------------------------------------------------
# Role mapping — IDP groups → Casbin roles
# ---------------------------------------------------------------------------

async def _apply_role_mapping(
    user: User,
    userinfo: dict,
    config: TenantIDPConfig,
    db: AsyncSession,
) -> None:
    # IDP may return groups as "groups" or "roles" claim
    idp_groups: list = userinfo.get("groups", userinfo.get("roles", []))

    for idp_group in idp_groups:
        internal_role = config.role_mapping.get(idp_group)
        if internal_role:
            await casbin_enforcer.safe_add_role_for_user(
                str(user.id),
                internal_role,
                config.tenant_id.hex,
            )
            logger.info(
                "enterprise_role_mapped",
                user_id=str(user.id),
                idp_group=idp_group,
                internal_role=internal_role,
            )


# ---------------------------------------------------------------------------
# HMAC state for enterprise flow (same pattern as Google OAuth state)
# ---------------------------------------------------------------------------

def _make_enterprise_state(tenant_id: uuid.UUID, secret_key: str) -> str:
    import base64
    nonce = secrets.token_urlsafe(16)
    ts = str(int(time.time()))
    payload = f"{tenant_id}:{nonce}:{ts}"
    sig = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def _verify_enterprise_state(state: str, secret_key: str, max_age: int = 300) -> str:
    import base64
    try:
        decoded = base64.urlsafe_b64decode(state.encode()).decode()
        tenant_id, nonce, ts, sig = decoded.rsplit(":", 3)
    except Exception:
        raise HTTPException(400, "Malformed enterprise OAuth state")

    payload = f"{tenant_id}:{nonce}:{ts}"
    expected = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(400, "Invalid enterprise OAuth state signature")

    age = int(time.time()) - int(ts)
    if age > max_age:
        raise HTTPException(400, "Enterprise OAuth state expired")

    return tenant_id


# Singleton per process
dynamic_idp_router = DynamicIDPRouter()
