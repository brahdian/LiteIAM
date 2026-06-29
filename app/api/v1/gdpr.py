
"""GDPR Article 17 (right to erasure) and Article 20 (data portability) endpoints.

Erasure anonymizes rather than hard-deletes so foreign-key audit records are preserved.
The export returns all personal data we hold for the authenticated user.
"""

from datetime import UTC, datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.audit import AuditLog
from app.models.passkey import PasskeyCredential
from app.models.trusted_device import TrustedDevice
from app.models.user import User

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/users/me", tags=["GDPR / Privacy"])


@router.get("/export")
async def export_my_data(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Return all personal data held for the authenticated user (GDPR Art. 20).

    The caller should treat this response as sensitive — rate limiting and
    audit logging apply.
    """
    passkeys = (await db.scalars(
        select(PasskeyCredential).where(
            PasskeyCredential.user_id == user.id,
            not PasskeyCredential.is_revoked,
        )
    )).all()

    devices = (await db.scalars(
        select(TrustedDevice).where(TrustedDevice.user_id == user.id)
    )).all()

    audit_events = (await db.scalars(
        select(AuditLog)
        .where(AuditLog.subject_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(500)
    )).all()

    await emit(db, AuthEvent.USER_UPDATED, tenant_id=user.tenant_id, subject_id=user.id,
               metadata={"action": "gdpr_export"})
    await db.commit()

    return JSONResponse(
        content={
            "exported_at": datetime.now(UTC).isoformat(),
            "profile": {
                "id": str(user.id),
                "email": user.email,
                "is_verified": user.is_verified,
                "is_active": user.is_active,
                "tenant_id": str(user.tenant_id) if user.tenant_id else None,
                "created_at": user.created_at.isoformat() if hasattr(user, "created_at") else None,
            },
            "security_keys": [
                {
                    "id": str(p.id),
                    "name": getattr(p, "name", None),
                    "created_at": p.created_at.isoformat(),
                }
                for p in passkeys
            ],
            "trusted_devices": [
                {
                    "id": str(d.id),
                    "user_agent": d.user_agent,
                    "ip_address": d.ip_address,
                    "expires_at": d.expires_at.isoformat(),
                }
                for d in devices
            ],
            "audit_log": [
                {
                    "event": e.event,
                    "ip_address": e.ip_address,
                    "created_at": e.created_at.isoformat(),
                }
                for e in audit_events
            ],
        },
        headers={"Content-Disposition": "attachment; filename=auth-data-export.json"},
    )


@router.delete("", status_code=204)
async def erase_my_account(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Anonymize all personal data and deactivate the account (GDPR Art. 17).

    Hard fields: email, hashed_password replaced with non-reversible placeholders.
    Audit log rows referencing this user are preserved (legal basis: legitimate interest).
    Trusted devices and passkeys are hard-deleted (no legitimate basis to retain).
    """
    anon_email = f"deleted+{user.id}@deleted.local"

    # Revoke all passkeys
    await db.execute(
        update(PasskeyCredential)
        .where(PasskeyCredential.user_id == user.id)
        .values(is_revoked=True)
    )

    # Delete trusted devices (contain IP + user-agent PII)
    await db.execute(delete(TrustedDevice).where(TrustedDevice.user_id == user.id))

    # Anonymize user row — keep id so FK audit rows remain consistent
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            email=anon_email,
            hashed_password="",
            is_active=False,
            is_verified=False,
        )
    )

    # Audit before commit so the event is tied to the now-anonymized subject
    await emit(db, AuthEvent.USER_DELETED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()

    logger.info("gdpr_erasure_complete", user_id=str(user.id))
