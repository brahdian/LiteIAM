
"""
Enterprise BYOIDP API endpoints.

/auth/enterprise/login?tenant_id=X  — start enterprise SSO login
/auth/enterprise/callback           — IDP redirects back here

Admin APIs for managing per-tenant IDP configuration are in the admin module
(Phase 6 will move admin endpoints behind superuser RBAC).
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.identity.enterprise import (
    _encrypt_client_secret,
    dynamic_idp_router,
)
from app.identity.password import fastapi_users
from app.models.idp_config import TenantIDPConfig
from app.tokens.strategy import TenantAwareJWTStrategy, get_jwt_strategy

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth/enterprise", tags=["Enterprise SSO"])

current_superuser = fastapi_users.current_user(active=True, superuser=True)


# ---------------------------------------------------------------------------
# SSO initiation
# ---------------------------------------------------------------------------

@router.get("/login")
async def enterprise_login(
    tenant_id: str = Query(...),
    db: AsyncSession = Depends(get_session),
):
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    authorize_url = await dynamic_idp_router.build_authorize_url(tid, db)
    return RedirectResponse(authorize_url, status_code=302)


# ---------------------------------------------------------------------------
# Callback — IDP redirects here after authentication
# ---------------------------------------------------------------------------

@router.get("/callback")
async def enterprise_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    user = await dynamic_idp_router.handle_callback(code, state, db)
    access_token = await strategy.write_token(user)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        "user_id": str(user.id),
        "email": user.email,
    }


# ---------------------------------------------------------------------------
# Admin API — configure a tenant's IDP
# ---------------------------------------------------------------------------

class IDPConfigIn(BaseModel):
    tenant_id: uuid.UUID
    discovery_url: str
    client_id: str
    client_secret: str       # plaintext — encrypted before storage
    jit_enabled: bool = True
    role_mapping: dict = {}  # {"IDP Group": "casbin_role"}


@router.post("/config", status_code=201)
async def configure_idp(
    body: IDPConfigIn,
    db: AsyncSession = Depends(get_session),
    _admin: object = Depends(current_superuser),
):
    existing = await db.scalar(
        select(TenantIDPConfig).where(TenantIDPConfig.tenant_id == body.tenant_id)
    )
    if existing:
        raise HTTPException(409, f"IDP config already exists for tenant {body.tenant_id}")

    config = TenantIDPConfig(
        id=uuid.uuid4(),
        tenant_id=body.tenant_id,
        discovery_url=body.discovery_url,
        client_id=body.client_id,
        client_secret_enc=_encrypt_client_secret(body.client_secret),
        jit_enabled=body.jit_enabled,
        role_mapping=body.role_mapping,
    )
    db.add(config)
    await db.commit()
    return {"status": "created", "config_id": str(config.id)}


@router.put("/config/{tenant_id}")
async def update_idp_config(
    tenant_id: uuid.UUID,
    body: IDPConfigIn,
    db: AsyncSession = Depends(get_session),
    _admin: object = Depends(current_superuser),
):
    config = await db.scalar(
        select(TenantIDPConfig).where(TenantIDPConfig.tenant_id == tenant_id)
    )
    if config is None:
        raise HTTPException(404, "IDP config not found")

    config.discovery_url = body.discovery_url
    config.client_id = body.client_id
    config.client_secret_enc = _encrypt_client_secret(body.client_secret)
    config.jit_enabled = body.jit_enabled
    config.role_mapping = body.role_mapping
    await db.commit()
    return {"status": "updated"}


class IDPConfigOut(BaseModel):
    tenant_id: uuid.UUID
    discovery_url: str
    client_id: str
    jit_enabled: bool
    role_mapping: dict
    has_client_secret: bool  # never returns the secret itself


@router.get("/config/{tenant_id}", response_model=IDPConfigOut)
async def get_idp_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    _admin: object = Depends(current_superuser),
):
    """Read back a tenant's IDP config (non-secret fields only) so an admin UI can
    pre-populate the edit form. The encrypted client secret is never returned —
    only a boolean indicating one is set."""
    config = await db.scalar(
        select(TenantIDPConfig).where(TenantIDPConfig.tenant_id == tenant_id)
    )
    if config is None:
        raise HTTPException(404, "IDP config not found")
    return IDPConfigOut(
        tenant_id=config.tenant_id,
        discovery_url=config.discovery_url,
        client_id=config.client_id,
        jit_enabled=config.jit_enabled,
        role_mapping=config.role_mapping or {},
        has_client_secret=bool(config.client_secret_enc),
    )
