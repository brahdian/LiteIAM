
"""
Invitation API.

Admin endpoints (superuser only):
  POST   /invitations            — create invitation, returns raw token
  GET    /invitations            — list all invitations for caller's tenant
  DELETE /invitations/{id}       — revoke a pending invitation

Public endpoint (no auth — uses invitation token):
  POST   /invitations/accept     — register with an invitation token

The accept flow is self-contained: it validates the token, creates the user
via fastapi-users (so password complexity + history checks apply), assigns the
role, and marks the invitation used — all in a single request.
"""

import uuid
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.core.rate_limit import limiter
from app.identity.invitation import (
    INVITATION_TTL_HOURS,
    accept_invitation,
    create_invitation,
    list_invitations,
    revoke_invitation,
    verify_invitation,
)
from app.identity.password import UserManager, current_active_user, get_user_manager

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/invitations", tags=["Invitations"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class InviteRequest(BaseModel):
    email: EmailStr
    role: str = "member"
    tenant_id: str | None = None  # superuser can invite to any tenant


class InviteResponse(BaseModel):
    invitation_id: str
    email: str
    role: str
    expires_in_hours: int
    # raw_token is returned here so the caller can construct the invite link.
    # In production the server would send the email directly; here we return it
    # for the caller to deliver (e.g., via their own email infrastructure).
    raw_token: str


class AcceptInviteRequest(BaseModel):
    token: str
    email: EmailStr
    password: str


# ---------------------------------------------------------------------------
# Admin — create / list / revoke
# ---------------------------------------------------------------------------

@router.post("", response_model=InviteResponse, status_code=201)
@limiter.limit("20/hour")
async def create_invite(
    request: Request,
    response: Response,
    body: InviteRequest,
    db: AsyncSession = Depends(get_session),
    current_user=Depends(current_active_user),
):
    """Create an invitation for a new user. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(403, "Superuser required")

    # Resolve target tenant
    if body.tenant_id:
        try:
            tid = uuid.UUID(body.tenant_id)
        except ValueError:
            raise HTTPException(400, "Invalid tenant_id")
    else:
        tid = current_user.tenant_id

    from sqlalchemy import select

    from app.identity.invitation import _hash_token
    from app.models.invitation import UserInvitation

    raw_token = await create_invitation(
        tenant_id=tid,
        email=str(body.email),
        role=body.role,
        invited_by_id=current_user.id,
        db=db,
    )
    inv_row = await db.scalar(
        select(UserInvitation).where(UserInvitation.token_hash == _hash_token(raw_token))
    )

    await emit(db, AuthEvent.USER_CREATED,
               tenant_id=tid, actor_id=current_user.id,
               metadata={"action": "invitation_sent", "email": str(body.email)})

    from app.core.config import settings
    from app.notifications.email import resolve_tenant_sender, send_invitation_email
    invite_url = f"{settings.BASE_URL}/ui/accept-invite?token={raw_token}"
    from_address, from_name = await resolve_tenant_sender(db, tid)
    await send_invitation_email(
        to=str(body.email),
        invite_url=invite_url,
        invited_by=current_user.email,
        from_address=from_address,
        from_name=from_name,
    )

    return InviteResponse(
        invitation_id=str(inv_row.id) if inv_row else "unknown",
        email=str(body.email),
        role=body.role,
        expires_in_hours=INVITATION_TTL_HOURS,
        raw_token=raw_token,
    )


@router.get("", response_model=list[dict])
async def list_invites(
    db: AsyncSession = Depends(get_session),
    current_user=Depends(current_active_user),
):
    """List all invitations for the caller's tenant."""
    if not current_user.is_superuser:
        raise HTTPException(403, "Superuser required")
    return await list_invitations(current_user.tenant_id, db)


@router.delete("/{invitation_id}", status_code=204)
async def revoke_invite(
    invitation_id: str,
    db: AsyncSession = Depends(get_session),
    current_user=Depends(current_active_user),
):
    """Revoke a pending invitation."""
    if not current_user.is_superuser:
        raise HTTPException(403, "Superuser required")
    try:
        iid = uuid.UUID(invitation_id)
    except ValueError:
        raise HTTPException(400, "Invalid invitation_id")
    removed = await revoke_invitation(iid, current_user.tenant_id, db)
    if not removed:
        raise HTTPException(404, "Invitation not found or already accepted")


# ---------------------------------------------------------------------------
# Public — accept an invitation and register
# ---------------------------------------------------------------------------

@router.post("/accept", status_code=201)
@limiter.limit("10/hour")
async def accept_invite(
    request: Request,
    response: Response,
    body: AcceptInviteRequest,
    db: AsyncSession = Depends(get_session),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Register using an invitation token.

    Rate-limited to 10/hour per IP to block token-bruteforce.
    The invitation is single-use and time-limited (72h by default).
    """
    # Verify token before doing any work
    inv = await verify_invitation(body.token, str(body.email), db)
    if inv is None:
        raise HTTPException(400, "Invalid, expired, or already used invitation")

    # Create the user via fastapi-users (password complexity + history enforced)
    from fastapi_users.exceptions import InvalidPasswordException, UserAlreadyExists

    try:
        from fastapi_users import schemas

        class _UserCreate(schemas.BaseUserCreate):
            tenant_id: uuid.UUID

        user = await user_manager.create(
            _UserCreate(
                email=str(body.email),
                password=body.password,
                tenant_id=inv.tenant_id,
                is_active=True,
                is_verified=True,  # invited users skip email verification
                is_superuser=False,
            ),
            safe=True,
            request=request,
        )
    except UserAlreadyExists:
        raise HTTPException(409, "An account with this email already exists")
    except InvalidPasswordException as e:
        raise HTTPException(422, e.reason or "Password does not meet requirements")

    # Mark invitation used
    await accept_invitation(inv, db)

    logger.info(
        "invitation_registration_complete",
        user_id=str(user.id),
        tenant_id=str(inv.tenant_id),
        role=inv.role,
    )

    return {
        "user_id": str(user.id),
        "email": str(user.email),
        "role": inv.role,
        "message": "Account created. You can now sign in.",
    }
