
"""
Admin API for per-tenant IP allowlist / blocklist management.

Endpoints (all require superuser):
  GET  /admin/tenants/{tenant_id}/ip-policy   — read current policy
  PUT  /admin/tenants/{tenant_id}/ip-policy   — replace policy (idempotent)
  DELETE /admin/tenants/{tenant_id}/ip-policy — clear all restrictions

CIDRs are validated at write time so malformed ranges are rejected before
they ever reach the enforcement layer.
"""

import ipaddress
import uuid
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.identity.password import current_active_user
from app.models.tenant import Tenant

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin/tenants", tags=["Admin"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IPPolicyRead(BaseModel):
    tenant_id: str
    ip_allowlist: list[str]
    ip_blocklist: list[str]


class IPPolicyWrite(BaseModel):
    ip_allowlist: list[str] | None = None
    ip_blocklist: list[str] | None = None

    @field_validator("ip_allowlist", "ip_blocklist", mode="before")
    @classmethod
    def validate_cidrs(cls, v):
        if v is None:
            return v
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR: {cidr!r}")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/{tenant_id}/ip-policy", response_model=IPPolicyRead)
async def get_ip_policy(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """Read the IP allowlist/blocklist for a tenant. Superuser only."""
    if not _user.is_superuser:
        raise HTTPException(403, "Superuser required")

    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    return IPPolicyRead(
        tenant_id=str(tenant.id),
        ip_allowlist=list(tenant.ip_allowlist or []),
        ip_blocklist=list(tenant.ip_blocklist or []),
    )


@router.put("/{tenant_id}/ip-policy", response_model=IPPolicyRead)
async def set_ip_policy(
    tenant_id: str,
    body: IPPolicyWrite,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """
    Replace the IP policy for a tenant.

    Pass ``ip_allowlist: []`` to remove all allowlist restrictions (allow all IPs).
    Pass ``ip_blocklist: []`` to clear the blocklist.
    Omit a field to leave it unchanged.
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

    updates: dict = {}
    if body.ip_allowlist is not None:
        updates["ip_allowlist"] = body.ip_allowlist or None
    if body.ip_blocklist is not None:
        updates["ip_blocklist"] = body.ip_blocklist or None

    if updates:
        await db.execute(update(Tenant).where(Tenant.id == tid).values(**updates))
        await db.commit()
        await db.refresh(tenant)

    logger.info(
        "ip_policy_updated",
        tenant_id=tenant_id,
        updated_by=str(_user.id),
        allowlist_len=len(tenant.ip_allowlist or []),
        blocklist_len=len(tenant.ip_blocklist or []),
    )

    return IPPolicyRead(
        tenant_id=str(tenant.id),
        ip_allowlist=list(tenant.ip_allowlist or []),
        ip_blocklist=list(tenant.ip_blocklist or []),
    )


@router.delete("/{tenant_id}/ip-policy", status_code=204)
async def clear_ip_policy(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    """Remove all IP restrictions for a tenant (open access)."""
    if not _user.is_superuser:
        raise HTTPException(403, "Superuser required")

    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")

    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    await db.execute(
        update(Tenant).where(Tenant.id == tid).values(ip_allowlist=None, ip_blocklist=None)
    )
    await db.commit()
    logger.info("ip_policy_cleared", tenant_id=tenant_id, cleared_by=str(_user.id))
