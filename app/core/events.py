from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime, timezone
from enum import Enum, StrEnum
from typing import Any, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# Strong references prevent asyncio.create_task results from being GC'd before completion.
# Tasks remove themselves on done via the callback.
_inflight_tasks: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _inflight_tasks.add(t)
    t.add_done_callback(_inflight_tasks.discard)
    return t


class AuthEvent(StrEnum):
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_LOGIN = "user.login"
    USER_LOGIN_NEW_IP = "user.login.new_ip"
    USER_LOGIN_FAILED = "user.login.failed"
    USER_PASSWORD_CHANGED = "user.password.changed"
    USER_PASSWORD_RESET = "user.password.reset"
    USER_EMAIL_VERIFIED = "user.email.verified"
    USER_INVITED = "user.invited"
    USER_INVITATION_ACCEPTED = "user.invitation.accepted"
    MFA_ENROLLED = "mfa.enrolled"
    MFA_CHALLENGED = "mfa.challenged"
    MFA_FAILED = "mfa.failed"
    MFA_BACKUP_CODE_USED = "mfa.backup_code.used"
    MFA_DISABLED = "mfa.disabled"
    USER_EMAIL_CHANGED = "user.email.changed"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REVOKED = "token.revoked"
    PASSKEY_REGISTERED = "passkey.registered"
    PASSKEY_USED = "passkey.used"
    PASSKEY_REVOKED = "passkey.revoked"
    MAGIC_LINK_SENT = "magic_link.sent"
    MAGIC_LINK_USED = "magic_link.used"
    EMAIL_OTP_SENT = "email_otp.sent"
    EMAIL_OTP_USED = "email_otp.used"
    EMAIL_OTP_FAILED = "email_otp.failed"
    OAUTH_LINKED = "oauth.linked"
    TENANT_CREATED = "tenant.created"
    WEBHOOK_CREATED = "webhook.created"
    WEBHOOK_DELETED = "webhook.deleted"
    SESSION_REVOKED = "session.revoked"
    IP_BLOCKED = "ip.blocked"


async def emit(
    db: AsyncSession,
    event: AuthEvent,
    *,
    tenant_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    subject_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    from app.models.audit import AuditLog

    try:
        log = AuditLog(
            id=uuid.uuid4(),
            event=str(event),
            tenant_id=tenant_id,
            actor_id=actor_id,
            subject_id=subject_id,
            ip_address=ip_address,
            user_agent=user_agent,
            event_metadata=metadata or {},
            created_at=datetime.now(UTC),
        )
        db.add(log)
        await db.flush()
        logger.info("auth_event", auth_event=str(event), tenant_id=str(tenant_id), subject_id=str(subject_id))
    except Exception:
        logger.exception("failed_to_emit_audit_event", auth_event=str(event))
        return

    if tenant_id is not None:
        payload = {
            "event": str(event),
            "tenant_id": str(tenant_id),
            "subject_id": str(subject_id) if subject_id else None,
            "ip_address": ip_address,
            "timestamp": datetime.now(UTC).isoformat(),
            **(metadata or {}),
        }
        _spawn(_dispatch_webhooks(tenant_id, event, payload))


async def _dispatch_webhooks(tenant_id: uuid.UUID, event: AuthEvent, payload: dict) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.webhook import TenantWebhook

    try:
        async with AsyncSessionLocal() as db:
            rows = await db.scalars(
                select(TenantWebhook).where(
                    TenantWebhook.tenant_id == tenant_id,
                    TenantWebhook.is_active,
                )
            )
            for wh in rows.all():
                if "*" in wh.events or event.value in wh.events:
                    _spawn(_deliver_with_retry(wh, payload))
    except Exception:
        logger.exception("webhook_dispatch_error", event=event.value)


# Retry schedule: attempt 0 immediately, then 30 s, 5 min (each attempt is independent)
_RETRY_DELAYS = [0, 30, 300]


async def _deliver_with_retry(wh: Any, payload: dict) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.webhook import WebhookDelivery

    delivery_id = uuid.uuid4()
    for attempt, delay in enumerate(_RETRY_DELAYS):
        if delay:
            await asyncio.sleep(delay)
        http_status: int | None = None
        error: str | None = None
        try:
            http_status = await _deliver(wh, payload)
        except Exception as exc:
            error = str(exc)[:500]

        success = http_status is not None and 200 <= http_status < 300
        try:
            async with AsyncSessionLocal() as db:
                db.add(
                    WebhookDelivery(
                        id=uuid.uuid4(),
                        webhook_id=wh.id,
                        delivery_group_id=delivery_id,
                        attempt=attempt + 1,
                        event=payload.get("event", ""),
                        payload_json=json.dumps(payload, default=str),
                        http_status=http_status,
                        error=error,
                        success=success,
                        created_at=datetime.now(UTC),
                    )
                )
                await db.commit()
        except Exception:
            logger.exception("webhook_delivery_log_error", webhook_id=str(wh.id))

        if success:
            logger.info("webhook_delivered", webhook_id=str(wh.id), attempt=attempt + 1)
            return
        logger.warning(
            "webhook_delivery_attempt_failed",
            webhook_id=str(wh.id),
            attempt=attempt + 1,
            status=http_status,
            error=error,
        )

    logger.error("webhook_delivery_exhausted", webhook_id=str(wh.id), auth_event=payload.get("event"))


async def _deliver(wh: Any, payload: dict) -> int:
    from cryptography.fernet import Fernet

    from app.core.config import settings

    body = json.dumps(payload, default=str)
    ts = str(int(time.time()))

    sig = ""
    if wh.secret_enc:
        secret = Fernet(settings.fernet_key()).decrypt(wh.secret_enc.encode())
        mac = hmac.new(secret, f"{ts}.{body}".encode(), hashlib.sha256)
        sig = f"sha256={mac.hexdigest()}"

    from app.shared.http_clients import get_outbound_client
    client = get_outbound_client("internal")
    resp = await client.post(
        wh.url,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Auth-Signature": sig,
            "X-Auth-Timestamp": ts,
            "X-Auth-Event": payload.get("event", ""),
            "User-Agent": "Auth-Webhooks/1.0",
        },
    )
    return resp.status_code


# ---------------------------------------------------------------------------
# Audit log retention — background cleanup
# ---------------------------------------------------------------------------

_retention_bg_task: asyncio.Task | None = None


async def _audit_retention_loop() -> None:
    """Delete audit log rows older than each tenant's retention policy.

    Runs indefinitely with a 24-hour sleep between passes. Uses SET LOCAL so
    the delete always targets the public.audit_logs table (not per-tenant schema).
    A retention value of 0 means "keep forever" — no rows deleted for that tenant.
    """
    import asyncio

    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.config import settings

    _logger = structlog.get_logger("audit_retention")

    while True:
        try:
            engine = create_async_engine(settings.DATABASE_URL, echo=False)
            async_session = sessionmaker(engine, class_=_AsyncSession, expire_on_commit=False)
            async with async_session() as session:
                from datetime import timedelta

                from sqlalchemy import delete, select

                from app.models.audit import AuditLog
                from app.models.tenant import Tenant

                tenants = (await session.scalars(
                    select(Tenant).where(
                        Tenant.is_active,
                        Tenant.audit_log_retention_days > 0,
                    )
                )).all()

                total_deleted = 0
                for tenant in tenants:
                    cutoff = datetime.now(UTC) - timedelta(days=tenant.audit_log_retention_days)
                    result = await session.execute(
                        delete(AuditLog).where(
                            AuditLog.tenant_id == tenant.id,
                            AuditLog.created_at < cutoff,
                        )
                    )
                    count = result.rowcount or 0
                    total_deleted += count

                await session.commit()
                await engine.dispose()

                if total_deleted:
                    _logger.info("audit_retention_cleanup", deleted=total_deleted)

        except Exception as exc:
            structlog.get_logger("audit_retention").error(
                "audit_retention_error", error=str(exc)
            )

        await asyncio.sleep(86400)  # Run once daily


def start_audit_retention_task() -> None:
    """Arm the daily retention cleanup. Call once from app startup (lifespan)."""
    import asyncio

    global _retention_bg_task
    if _retention_bg_task is not None and not _retention_bg_task.done():
        return  # Already running

    _retention_bg_task = asyncio.create_task(_audit_retention_loop())
    _retention_bg_task.add_done_callback(
        lambda t: structlog.get_logger("audit_retention").error(
            "retention_task_exited", exc=str(t.exception()) if not t.cancelled() else "cancelled"
        ) if not t.cancelled() and t.exception() else None
    )
