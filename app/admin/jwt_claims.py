
"""
Admin API for per-tenant custom JWT claims.

Endpoints (all require superuser):
  GET    /admin/tenants/{tenant_id}/jwt-claims   — read current custom claims
  PUT    /admin/tenants/{tenant_id}/jwt-claims   — replace custom claims
  DELETE /admin/tenants/{tenant_id}/jwt-claims   — clear all custom claims

Reserved claim names (sub, iss, aud, exp, iat, nbf, jti, email, tenant_id,
auth_stage) are rejected at write time — they cannot be overridden.

Changes take effect within CLAIMS_CACHE_TTL seconds (60s) on each worker.
"""

import uuid
from typing import Any, Dict

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.identity.password import current_active_user
from app.models.tenant import Tenant
from app.tokens.strategy import _RESERVED_CLAIMS, invalidate_claims_cache

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin/tenants", tags=["Admin"])

_ALLOWED_VALUE_TYPES = (str, int, float, bool)


class JWTClaimsRead(BaseModel):
    tenant_id: str
    custom_claims: dict[str, Any]


class JWTClaimsWrite(BaseModel):
    claims: dict[str, Any]

    @model_validator(mode="after")
    def validate_claims(self):
        for k, v in self.claims.items():
            if k in _RESERVED_CLAIMS:
                raise ValueError(
                    f"Claim {k!r} is reserved and cannot be customized. "
                    f"Reserved: {sorted(_RESERVED_CLAIMS)}"
                )
            if not isinstance(v, _ALLOWED_VALUE_TYPES):
                raise ValueError(
                    f"Claim {k!r} has unsupported type {type(v).__name__}. "
                    "Only str, int, float, bool values are allowed."
                )
            if isinstance(k, str) and (not k or len(k) > 64):
                raise ValueError(f"Claim key {k!r} must be 1–64 characters")
        if len(self.claims) > 20:
            raise ValueError("Maximum 20 custom claims per tenant")
        return self


@router.get("/{tenant_id}/jwt-claims", response_model=JWTClaimsRead)
async def get_jwt_claims(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """Read custom JWT claims for a tenant. Superuser only."""
    if not _user.is_superuser:
        raise HTTPException(403, "Superuser required")

    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    return JWTClaimsRead(
        tenant_id=str(tenant.id),
        custom_claims=dict(tenant.custom_jwt_claims or {}),
    )


@router.put("/{tenant_id}/jwt-claims", response_model=JWTClaimsRead)
async def set_jwt_claims(
    tenant_id: str,
    body: JWTClaimsWrite,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """
    Replace custom JWT claims for a tenant.

    All existing custom claims are replaced. Pass ``claims: {}`` to clear.
    Reserved claim names are rejected. Changes propagate to new tokens
    within 60 seconds (cache TTL).
    """
    if not _user.is_superuser:
        raise HTTPException(403, "Superuser required")

    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    new_claims = body.claims or None
    await db.execute(
        update(Tenant).where(Tenant.id == tid).values(custom_jwt_claims=new_claims)
    )
    await db.commit()

    # Bust cache so next token issuance picks up new claims without waiting
    invalidate_claims_cache(tenant_id)

    logger.info(
        "jwt_claims_updated",
        tenant_id=tenant_id,
        updated_by=str(_user.id),
        claim_count=len(body.claims),
    )

    return JWTClaimsRead(
        tenant_id=str(tid),
        custom_claims=body.claims,
    )


@router.delete("/{tenant_id}/jwt-claims", status_code=204)
async def clear_jwt_claims(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """Remove all custom JWT claims for a tenant."""
    if not _user.is_superuser:
        raise HTTPException(403, "Superuser required")

    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    await db.execute(update(Tenant).where(Tenant.id == tid).values(custom_jwt_claims=None))
    await db.commit()
    invalidate_claims_cache(tenant_id)
    logger.info("jwt_claims_cleared", tenant_id=tenant_id, cleared_by=str(_user.id))
