
"""
Passkey (WebAuthn) registration and authentication endpoints.

Registration flow (requires existing session):
  GET  /auth/passkey/register/begin    → challenge options (for browser)
  POST /auth/passkey/register/complete → verify + store credential

Authentication flow (no session required):
  GET  /auth/passkey/authenticate/begin    → challenge options
  POST /auth/passkey/authenticate/complete → verify + issue JWT
"""

import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.identity.passkey import (
    begin_authentication,
    begin_registration,
    complete_authentication,
    complete_registration,
    list_credentials,
    revoke_credential,
)
from app.identity.password import current_active_user
from app.models.user import User
from app.tokens.strategy import TenantAwareJWTStrategy, get_jwt_strategy

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth/passkey", tags=["Passkeys"])


class RegistrationCompleteRequest(BaseModel):
    credential: dict
    device_name: str | None = None


class AuthenticationBeginRequest(BaseModel):
    user_id: str | None = None  # None = discoverable credential flow


class AuthenticationCompleteRequest(BaseModel):
    credential: dict
    user_id: str | None = None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@router.get("/register/begin")
async def passkey_register_begin(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    return await begin_registration(user, db)


@router.post("/register/complete", status_code=201)
async def passkey_register_complete(
    body: RegistrationCompleteRequest,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    credential = await complete_registration(user, body.credential, body.device_name, db)
    return {"status": "registered", "credential_id": credential.id.hex}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@router.post("/authenticate/begin")
async def passkey_authenticate_begin(
    body: AuthenticationBeginRequest,
    db: AsyncSession = Depends(get_session),
):
    user_id = uuid.UUID(body.user_id) if body.user_id else None
    return await begin_authentication(user_id, db)


@router.post("/authenticate/complete")
async def passkey_authenticate_complete(
    body: AuthenticationCompleteRequest,
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    user_id = uuid.UUID(body.user_id) if body.user_id else None
    user = await complete_authentication(body.credential, user_id, db)
    access_token = await strategy.write_token(user)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_LIFETIME_SECONDS,
    }


# ---------------------------------------------------------------------------
# Credential management
# ---------------------------------------------------------------------------

@router.get("/credentials")
async def list_passkey_credentials(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """List the caller's registered passkey credentials."""
    creds = await list_credentials(user.id, db)
    return {"credentials": creds}


@router.delete("/credentials/{credential_id}", status_code=204)
async def revoke_passkey_credential(
    credential_id: str,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Remove a passkey credential. Only the owning user can revoke their own keys."""
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(400, "Invalid credential_id")
    await revoke_credential(cred_uuid, user.id, db)
