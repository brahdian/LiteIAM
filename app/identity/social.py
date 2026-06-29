from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from typing import Optional
from urllib.parse import urlencode

import httpx
import structlog
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.events import AuthEvent, emit
from app.models.tenant import Tenant
from app.models.user import OAuthAccount, User
from app.tokens.revocation import is_revoked

logger = structlog.get_logger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# Module-level client: one connection pool shared across all Google OAuth requests,
# not a new pool per request (which exhausts file descriptors under load).
_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    from app.shared.http_clients import get_outbound_client
    return get_outbound_client("identity")


async def close_http_client() -> None:
    pass


# ---------------------------------------------------------------------------
# OAuth State — HMAC-signed, tenant-bound, timestamped
# ---------------------------------------------------------------------------

def generate_oauth_state(tenant_id: str, secret_key: str) -> str:
    nonce = secrets.token_urlsafe(16)
    ts = str(int(time.time()))
    payload = f"{tenant_id}:{nonce}:{ts}"
    sig = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_oauth_state(state: str, secret_key: str, max_age_seconds: int = 300) -> tuple:
    """
    Returns (tenant_id, nonce) if state is valid, raises HTTPException otherwise.

    The caller MUST consume the nonce via revoke_token(f"oauth_state:{nonce}", ...) to
    prevent replay of the same state within its TTL window (Phase 6 gate requirement).
    """
    try:
        decoded = base64.urlsafe_b64decode(state.encode()).decode()
        tenant_id, nonce, ts, sig = decoded.rsplit(":", 3)
    except (ValueError, Exception):
        raise HTTPException(400, "Malformed OAuth state")

    payload = f"{tenant_id}:{nonce}:{ts}"
    expected = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        raise HTTPException(400, "Invalid OAuth state signature")

    age = int(time.time()) - int(ts)
    if age > max_age_seconds:
        raise HTTPException(400, "OAuth state has expired")

    # Check nonce has not already been consumed (replay protection)
    if is_revoked(f"oauth_state:{nonce}"):
        raise HTTPException(400, "OAuth state already used")

    return tenant_id, nonce


# ---------------------------------------------------------------------------
# Google OAuth flow
# ---------------------------------------------------------------------------

def build_google_authorize_url(tenant_id: str) -> str:
    state = generate_oauth_state(tenant_id, settings.SECRET_KEY)
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_google_code(code: str) -> dict:
    client = await get_http_client()
    resp = await client.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
    )
    if resp.status_code != 200:
        logger.warning("Google token exchange failed", status=resp.status_code)
        raise HTTPException(400, "Google token exchange failed")
    return resp.json()


async def fetch_google_userinfo(access_token: str) -> dict:
    client = await get_http_client()
    resp = await client.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code != 200:
        raise HTTPException(400, "Failed to fetch Google user info")
    return resp.json()


# ---------------------------------------------------------------------------
# Atomic user upsert — no TOCTOU race, tenant guard on conflict
# ---------------------------------------------------------------------------

async def upsert_oauth_user(
    *,
    email: str,
    tenant_id: uuid.UUID,
    provider: str,
    provider_account_id: str,
    access_token: str,
    db: AsyncSession,
) -> User:
    """
    Atomically upsert a user for an OAuth provider login.
    The ON CONFLICT WHERE clause ensures cross-tenant collisions are rejected.
    """
    user_id = uuid.uuid4()

    # 1. Upsert the User row (email unique per provider)
    user_stmt = (
        pg_insert(User)
        .values(
            id=user_id,
            email=email,
            hashed_password="OAUTH_MANAGED",
            tenant_id=tenant_id,
            is_active=True,
            is_superuser=False,
            is_verified=True,
        )
        .on_conflict_do_update(
            index_elements=["email"],
            set_={"is_active": True},
            # CRITICAL: only update if tenant matches — rejects cross-tenant hijack
            where=User.tenant_id == tenant_id,
        )
        .returning(User)
    )
    result = await db.execute(user_stmt)
    user = result.scalar_one_or_none()

    if user is None:
        # ON CONFLICT WHERE failed — existing user belongs to a different tenant
        raise HTTPException(
            403,
            "This email is already registered under a different tenant. "
            "Contact your administrator.",
        )

    # 2. Upsert the OAuthAccount link — encrypt access_token at rest (Phase 6 hardening)
    from cryptography.fernet import Fernet
    _fernet = Fernet(settings.fernet_key())
    access_token_enc = _fernet.encrypt(access_token.encode()).decode()

    oauth_stmt = (
        pg_insert(OAuthAccount)
        .values(
            id=uuid.uuid4(),
            user_id=user.id,
            oauth_name=provider,
            account_id=provider_account_id,
            account_email=email,
            # Base class 'access_token' column holds a sentinel — real token is encrypted
            access_token="ENCRYPTED",
            access_token_enc=access_token_enc,
        )
        .on_conflict_do_update(
            index_elements=["oauth_name", "account_id"],
            set_={"access_token": "ENCRYPTED", "access_token_enc": access_token_enc, "account_email": email},
        )
    )
    await db.execute(oauth_stmt)

    # Emit audit event BEFORE commit so all writes land in the same transaction.
    # emit() calls db.flush() which adds the AuditLog row to the open transaction;
    # the subsequent commit persists both the oauth upsert and the audit row atomically.
    await emit(
        db,
        AuthEvent.OAUTH_LINKED,
        tenant_id=user.tenant_id,
        subject_id=user.id,
        metadata={"provider": provider},
    )

    await db.commit()
    await db.refresh(user)
    return user


async def get_tenant_by_id(tenant_id: str, db: AsyncSession) -> Tenant:
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid, Tenant.is_active))
    if tenant is None:
        raise HTTPException(404, f"Tenant {tenant_id} not found or inactive")
    return tenant
