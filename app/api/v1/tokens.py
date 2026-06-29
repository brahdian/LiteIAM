
"""Personal Access Tokens (PAT) — long-lived API keys.

Token format: `aai_<url-safe-base64-32-bytes>` — prefix aids secret scanning.
Only the SHA-256 hash is stored. The raw token is returned ONCE at creation.

Scopes (open set, validated at middleware layer):
  api:read      — read-only access to all tenant data
  api:write     — read + write access
  admin         — full admin access (creates superuser-equivalent requests)
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.pat import PersonalAccessToken
from app.models.user import User

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth/tokens", tags=["Personal Access Tokens"])

_PREFIX = "aai_"
_VALID_SCOPES = {"api:read", "api:write", "admin"}
_MAX_TOKENS_PER_USER = 25
_MAX_EXPIRY_DAYS = 365


def _generate_raw() -> str:
    return _PREFIX + secrets.token_urlsafe(32)


def _hash(raw: str) -> str:
    value = raw[len(_PREFIX):] if raw.startswith(_PREFIX) else raw
    return hashlib.sha256(value.encode()).hexdigest()


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    scopes: list[str] = Field(default=["api:read"])
    expires_in_days: int | None = Field(default=90, ge=1, le=_MAX_EXPIRY_DAYS)


class TokenRead(BaseModel):
    id: str
    name: str
    scopes: list[str]
    last_used_at: str | None
    expires_at: str | None
    expires_soon: bool
    is_active: bool
    created_at: str


@router.get("", response_model=list[TokenRead])
async def list_tokens(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """List all active PATs for the authenticated user (raw values never returned)."""
    rows = (await db.scalars(
        select(PersonalAccessToken).where(
            PersonalAccessToken.user_id == user.id,
            PersonalAccessToken.is_active,
        ).order_by(PersonalAccessToken.created_at.desc())
    )).all()
    return [_to_read(t) for t in rows]


@router.post("", status_code=201)
async def create_token(
    body: TokenCreate,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Create a new PAT. The raw token is returned ONCE — store it securely."""
    # Validate scopes
    invalid = set(body.scopes) - _VALID_SCOPES
    if invalid:
        raise HTTPException(400, f"Invalid scopes: {sorted(invalid)}. Valid: {sorted(_VALID_SCOPES)}")

    # Enforce per-user token limit
    count = await db.scalar(
        select(PersonalAccessToken).where(
            PersonalAccessToken.user_id == user.id,
            PersonalAccessToken.is_active,
        ).with_only_columns(__import__("sqlalchemy").func.count())
    )
    if (count or 0) >= _MAX_TOKENS_PER_USER:
        raise HTTPException(400, f"Maximum of {_MAX_TOKENS_PER_USER} active tokens per user")

    raw = _generate_raw()
    expires_at = (
        datetime.now(UTC) + timedelta(days=body.expires_in_days)
        if body.expires_in_days else None
    )

    pat = PersonalAccessToken(
        id=uuid.uuid4(),
        user_id=user.id,
        tenant_id=user.tenant_id,
        name=body.name,
        token_hash=_hash(raw),
        scopes=body.scopes,
        expires_at=expires_at,
        created_at=datetime.now(UTC),
    )
    db.add(pat)
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id, subject_id=user.id,
               metadata={"token_type": "pat", "pat_name": body.name, "scopes": body.scopes})
    await db.commit()

    logger.info("pat_created", user_id=str(user.id), name=body.name, scopes=body.scopes)
    # Fire security notification — non-blocking; failure must not break the response
    from app.core.tasks import spawn
    from app.notifications.email import send_pat_created_alert as _pat_alert
    spawn(_pat_alert(to=user.email, pat_name=body.name, scopes=body.scopes))
    return {
        **_to_read(pat).model_dump(),
        "token": raw,
        "note": "This is the only time the token will be shown. Store it securely.",
    }


@router.delete("/{token_id}", status_code=204)
async def revoke_token(
    token_id: uuid.UUID,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Revoke (soft-delete) a PAT. Immediately invalidates it."""
    pat = await db.scalar(
        select(PersonalAccessToken).where(
            PersonalAccessToken.id == token_id,
            PersonalAccessToken.user_id == user.id,
        )
    )
    if pat is None:
        raise HTTPException(404, "Token not found")

    await db.execute(
        update(PersonalAccessToken)
        .where(PersonalAccessToken.id == token_id)
        .values(is_active=False)
    )
    await emit(db, AuthEvent.TOKEN_REVOKED, tenant_id=user.tenant_id, subject_id=user.id,
               metadata={"token_type": "pat", "pat_name": pat.name})
    await db.commit()


_EXPIRY_WARNING_DAYS = 7


def _to_read(t: PersonalAccessToken) -> TokenRead:
    _now = datetime.now(UTC)
    _exp = t.expires_at
    if _exp is not None and _exp.tzinfo is None:
        _exp = _exp.replace(tzinfo=UTC)
    expires_soon = bool(
        _exp is not None and _exp > _now and (_exp - _now).days < _EXPIRY_WARNING_DAYS
    )
    return TokenRead(
        id=str(t.id),
        name=t.name,
        scopes=t.scopes,
        last_used_at=t.last_used_at.isoformat() if t.last_used_at else None,
        expires_at=_exp.isoformat() if _exp else None,
        expires_soon=expires_soon,
        is_active=t.is_active,
        created_at=t.created_at.isoformat(),
    )
