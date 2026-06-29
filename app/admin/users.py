
import uuid
from datetime import timedelta
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.user import User
from app.tokens.strategy import get_jwt_strategy

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin/users", tags=["Admin"])

_IMPERSONATION_TTL = timedelta(hours=1)


class UserSummary(BaseModel):
    id: str
    email: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    is_totp_enabled: bool
    failed_login_count: int
    locked_until: str | None
    created_at: str | None = None


class UserPatch(BaseModel):
    is_active: bool | None = None
    is_superuser: bool | None = None


@router.get("", response_model=dict)
async def list_users(
    page: int = 1,
    limit: int = 20,
    actor: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    if not actor.is_superuser:
        raise HTTPException(403, "Superuser access required")
    if limit > 100:
        limit = 100
    offset = (page - 1) * limit

    total = await db.scalar(
        select(func.count()).where(User.tenant_id == actor.tenant_id)
    )
    rows = await db.scalars(
        select(User)
        .where(User.tenant_id == actor.tenant_id)
        .order_by(User.email)
        .offset(offset)
        .limit(limit)
    )

    def _fmt(u: User) -> UserSummary:
        return UserSummary(
            id=str(u.id),
            email=u.email,
            is_active=u.is_active,
            is_superuser=u.is_superuser,
            is_verified=u.is_verified,
            is_totp_enabled=u.is_totp_enabled,
            failed_login_count=u.failed_login_count or 0,
            locked_until=u.locked_until.isoformat() if u.locked_until else None,
        )

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "users": [_fmt(u).model_dump() for u in rows.all()],
    }


@router.patch("/{user_id}")
async def patch_user(
    user_id: uuid.UUID,
    body: UserPatch,
    actor: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    if not actor.is_superuser:
        raise HTTPException(403, "Superuser access required")
    if user_id == actor.id:
        raise HTTPException(400, "Cannot modify your own account via this endpoint")

    target = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == actor.tenant_id)
    )
    if target is None:
        raise HTTPException(404, "User not found in your tenant")

    if body.is_active is not None:
        target.is_active = body.is_active
    if body.is_superuser is not None:
        target.is_superuser = body.is_superuser

    await db.commit()
    return {"id": str(target.id), "is_active": target.is_active, "is_superuser": target.is_superuser}


@router.post("/{user_id}/impersonate")
async def impersonate_user(
    user_id: uuid.UUID,
    request: Request,
    actor: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Issue a 1-hour JWT scoped to *target* user, stamped with the admin's id.

    Privilege-escalation guard: superusers cannot impersonate other superusers.
    Every impersonation is hard-logged in the audit trail.
    """
    if not actor.is_superuser:
        raise HTTPException(403, "Superuser access required")
    if user_id == actor.id:
        raise HTTPException(400, "Cannot impersonate yourself")

    target = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == actor.tenant_id)
    )
    if target is None:
        raise HTTPException(404, "User not found in your tenant")
    if target.is_superuser:
        raise HTTPException(403, "Superusers cannot impersonate other superusers")
    if not target.is_active:
        raise HTTPException(400, "Cannot impersonate an inactive user")

    strategy = get_jwt_strategy()
    token = await strategy.write_token(target, override_lifetime=_IMPERSONATION_TTL, extra_claims={
        "impersonated": True,
        "impersonator_id": str(actor.id),
        "impersonator_email": actor.email,
    })

    await emit(
        db,
        AuthEvent.USER_UPDATED,
        tenant_id=actor.tenant_id,
        actor_id=actor.id,
        subject_id=target.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "action": "impersonation_start",
            "impersonator_email": actor.email,
            "target_email": target.email,
        },
    )
    await db.commit()

    logger.warning(
        "admin_impersonation",
        actor_id=str(actor.id),
        actor_email=actor.email,
        target_id=str(target.id),
        target_email=target.email,
        ip=request.client.host if request.client else None,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(_IMPERSONATION_TTL.total_seconds()),
        "impersonated_user_id": str(target.id),
        "impersonated_user_email": target.email,
        "warning": "This token impersonates a real user. All actions will be audited.",
    }


# ---------------------------------------------------------------------------
# Tenant MFA enforcement management
# ---------------------------------------------------------------------------

class MFAPolicyUpdate(BaseModel):
    require_mfa: bool


@router.put("/mfa-policy", status_code=200)
async def set_tenant_mfa_policy(
    body: MFAPolicyUpdate,
    actor: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Enable or disable organisation-wide MFA enforcement for the caller's tenant.
    Requires superuser. When enabled, all users without TOTP enrolled are blocked
    from logging in until they complete enrolment.
    """
    if not actor.is_superuser:
        raise HTTPException(403, "Superuser required")
    if actor.tenant_id is None:
        raise HTTPException(400, "Actor has no tenant")

    from sqlalchemy import update as _update

    from app.models.tenant import Tenant

    await db.execute(
        _update(Tenant)
        .where(Tenant.id == actor.tenant_id)
        .values(require_mfa=body.require_mfa)
    )
    await db.commit()
    logger.info(
        "tenant_mfa_policy_updated",
        tenant_id=str(actor.tenant_id),
        require_mfa=body.require_mfa,
        actor_id=str(actor.id),
    )
    return {"tenant_id": str(actor.tenant_id), "require_mfa": body.require_mfa}
