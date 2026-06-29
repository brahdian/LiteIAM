
"""
Admin API for per-tenant email sender (From address) configuration.

Endpoints (all require superuser):
  GET /admin/tenants/{tenant_id}/email-sender — read the tenant's From address/name
  PUT /admin/tenants/{tenant_id}/email-sender — set/clear them (null clears → platform default)

Only the visible From header is overridden; the SMTP relay stays global. Set the
address to a domain your relay is allowed to send for, or onboarding emails may
fail SPF/DKIM and land in spam.
"""

import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.identity.password import current_active_user
from app.models.tenant import Tenant

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin/tenants", tags=["Admin"])


class EmailSenderRead(BaseModel):
    tenant_id: str
    email_from_address: str | None = None
    email_from_name: str | None = None


class EmailSenderWrite(BaseModel):
    # Null clears the override and reverts to the platform default sender.
    email_from_address: EmailStr | None = None
    email_from_name: str | None = Field(default=None, max_length=256)


def _require_superuser(user) -> None:
    if not user.is_superuser:
        raise HTTPException(403, "Superuser required")


def _parse_tid(tenant_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(tenant_id)
    except ValueError:
        raise HTTPException(400, "Invalid tenant_id")


@router.get("/{tenant_id}/email-sender", response_model=EmailSenderRead)
async def get_email_sender(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    _require_superuser(_user)
    tid = _parse_tid(tenant_id)
    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")
    return EmailSenderRead(
        tenant_id=str(tenant.id),
        email_from_address=tenant.email_from_address,
        email_from_name=tenant.email_from_name,
    )


@router.put("/{tenant_id}/email-sender", response_model=EmailSenderRead)
async def set_email_sender(
    tenant_id: str,
    body: EmailSenderWrite,
    db: AsyncSession = Depends(get_session),
    _user=Depends(current_active_user),
):
    _require_superuser(_user)
    tid = _parse_tid(tenant_id)
    tenant = await db.scalar(select(Tenant).where(Tenant.id == tid))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    tenant.email_from_address = str(body.email_from_address) if body.email_from_address else None
    tenant.email_from_name = body.email_from_name or None
    await db.commit()

    logger.info("tenant_email_sender_updated", tenant_id=str(tid),
                from_address=tenant.email_from_address)
    return EmailSenderRead(
        tenant_id=str(tenant.id),
        email_from_address=tenant.email_from_address,
        email_from_name=tenant.email_from_name,
    )
