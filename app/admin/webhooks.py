
import uuid
from typing import List, Optional

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.user import User
from app.models.webhook import TenantWebhook

router = APIRouter(prefix="/admin/webhooks", tags=["Admin"])


class WebhookCreate(BaseModel):
    url: str
    secret: str | None = None
    events: list[str] = ["*"]


class WebhookRead(BaseModel):
    id: str
    url: str
    events: list[str]
    is_active: bool
    created_at: str


@router.get("", response_model=list[WebhookRead])
async def list_webhooks(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    rows = await db.scalars(
        select(TenantWebhook).where(TenantWebhook.tenant_id == user.tenant_id)
    )
    return [
        WebhookRead(id=str(w.id), url=w.url, events=w.events,
                    is_active=w.is_active, created_at=w.created_at.isoformat())
        for w in rows.all()
    ]


@router.post("", status_code=201, response_model=WebhookRead)
async def create_webhook(
    body: WebhookCreate,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    secret_enc = None
    if body.secret:
        secret_enc = Fernet(settings.fernet_key()).encrypt(body.secret.encode()).decode()

    wh = TenantWebhook(
        id=uuid.uuid4(),
        tenant_id=user.tenant_id,
        url=body.url,
        secret_enc=secret_enc,
        events=body.events,
    )
    db.add(wh)
    await emit(db, AuthEvent.WEBHOOK_CREATED, tenant_id=user.tenant_id, actor_id=user.id)
    await db.commit()
    await db.refresh(wh)
    return WebhookRead(id=str(wh.id), url=wh.url, events=wh.events,
                       is_active=wh.is_active, created_at=wh.created_at.isoformat())


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: uuid.UUID,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    wh = await db.scalar(
        select(TenantWebhook).where(
            TenantWebhook.id == webhook_id,
            TenantWebhook.tenant_id == user.tenant_id,
        )
    )
    if wh is None:
        raise HTTPException(404, "Webhook not found")
    await db.delete(wh)
    await emit(db, AuthEvent.WEBHOOK_DELETED, tenant_id=user.tenant_id, actor_id=user.id)
    await db.commit()
