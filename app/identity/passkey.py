from __future__ import annotations

"""
WebAuthn passkey registration and authentication.

Uses py_webauthn (not fastapi-users-webauthn) — gives us full control over:
- Sign-count replay detection (WebAuthn §6.5.3)
- AAGUID logging for device attestation policy
- Passkey as first factor OR second-factor step-up (orchestrator chooses)

Two ceremonies:
  1. Registration:
     a. GET /auth/passkey/registration/begin  → challenge + options
     b. POST /auth/passkey/registration/complete → verify + store credential
  2. Authentication (assertion):
     a. GET /auth/passkey/authentication/begin  → challenge + options
     b. POST /auth/passkey/authentication/complete → verify + issue JWT

Challenges are stored server-side in the DB (PasskeyChallenge) with a 5-minute
TTL so they can be used exactly once. A memory store would fail under multi-worker
deployments.
"""

import base64
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Optional

import structlog
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.events import AuthEvent, emit
from app.models.passkey import PasskeyCredential
from app.models.user import User

logger = structlog.get_logger(__name__)

_CHALLENGE_TTL = 300  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _from_b64url(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


# ---------------------------------------------------------------------------
# Registration ceremony
# ---------------------------------------------------------------------------

async def begin_registration(user: User, db: AsyncSession) -> dict:
    """
    Generate WebAuthn registration options.
    Returns a JSON-serializable dict to send to the browser.
    """
    try:
        import webauthn
        from webauthn.helpers import generate_challenge, options_to_json

        # Handle both old and new webauthn API versions
        try:
            attestation_preference = webauthn.AttestationConveyancePreference.NONE
        except AttributeError:
            # Fallback for older versions of webauthn
            attestation_preference = "none"

        challenge = generate_challenge()

        # Store challenge in DB keyed to user — single-use, 5-minute TTL
        await _store_challenge(user.id, challenge, "registration", db)

        options = webauthn.generate_registration_options(
            rp_id=_rp_id(),
            rp_name="LiteIAM",
            user_id=user.id.bytes,
            user_name=user.email,
            user_display_name=user.email,
            challenge=challenge,
            attestation=attestation_preference,
        )
        return options_to_json(options)
    except ImportError:
        raise HTTPException(501, "WebAuthn (py_webauthn) not installed")


async def complete_registration(
    user: User,
    credential_json: dict,
    device_name: str | None,
    db: AsyncSession,
) -> PasskeyCredential:
    """
    Verify the registration response and store the credential.
    """
    try:
        import webauthn
        from webauthn.helpers.structs import RegistrationCredential

        challenge = await _consume_challenge(user.id, "registration", db)

        credential = RegistrationCredential.model_validate(credential_json)
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=settings.BASE_URL,
        )

        # Check for existing credential with same ID (re-registration attempt)
        existing = await db.scalar(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == verification.credential_id
            )
        )
        if existing:
            raise HTTPException(409, "Passkey credential already registered")

        passkey = PasskeyCredential(
            id=uuid.uuid4(),
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            device_name=device_name,
            aaguid=str(verification.aaguid) if verification.aaguid else None,
        )
        db.add(passkey)
        await emit(db, AuthEvent.MFA_ENROLLED, tenant_id=user.tenant_id, subject_id=user.id,
                   metadata={"method": "passkey"})
        await db.commit()
        return passkey
    except ImportError:
        raise HTTPException(501, "WebAuthn (py_webauthn) not installed")


# ---------------------------------------------------------------------------
# Authentication ceremony
# ---------------------------------------------------------------------------

async def begin_authentication(user_id: uuid.UUID | None, db: AsyncSession) -> dict:
    """
    Generate WebAuthn authentication options.
    If user_id is provided, scope to that user's credentials (username-required flow).
    If None, allow any registered passkey (discoverable credentials / usernameless flow).
    """
    try:
        import webauthn
        from webauthn.helpers import generate_challenge, options_to_json

        challenge = generate_challenge()
        allow_credentials = []

        if user_id is not None:
            credentials = list(await db.scalars(
                select(PasskeyCredential).where(
                    PasskeyCredential.user_id == user_id,
                    not PasskeyCredential.is_revoked,
                )
            ))
            from webauthn.helpers.structs import PublicKeyCredentialDescriptor
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=cred.credential_id)
                for cred in credentials
            ]
            await _store_challenge(user_id, challenge, "authentication", db)
        else:
            # Discoverable credential flow: store challenge without user binding
            await _store_challenge(uuid.UUID(int=0), challenge, "authentication", db)

        options = webauthn.generate_authentication_options(
            rp_id=_rp_id(),
            challenge=challenge,
            allow_credentials=allow_credentials,
        )
        return options_to_json(options)
    except ImportError:
        raise HTTPException(501, "WebAuthn (py_webauthn) not installed")


async def complete_authentication(
    credential_json: dict,
    user_id: uuid.UUID | None,
    db: AsyncSession,
) -> User:
    """
    Verify the assertion and return the authenticated User.
    Updates sign_count (replay detection) and last_used_at.
    """
    try:
        import webauthn
        from webauthn.helpers.structs import AuthenticationCredential

        lookup_id = user_id if user_id is not None else uuid.UUID(int=0)
        challenge = await _consume_challenge(lookup_id, "authentication", db)

        credential = AuthenticationCredential.model_validate(credential_json)
        credential_id_bytes = credential.raw_id

        # Look up stored credential
        stored = await db.scalar(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == credential_id_bytes,
                not PasskeyCredential.is_revoked,
            )
        )
        if stored is None:
            raise HTTPException(400, "Passkey credential not found or revoked")

        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=settings.BASE_URL,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )

        # Sign count check — WebAuthn §6.5.3
        # verify_authentication_response raises if sign_count regresses (py_webauthn v2+)
        now = datetime.now(UTC)
        await db.execute(
            update(PasskeyCredential)
            .where(PasskeyCredential.id == stored.id)
            .values(sign_count=verification.new_sign_count, last_used_at=now)
        )

        user = await db.get(User, stored.user_id)
        if user is None or not user.is_active:
            raise HTTPException(400, "User not found or inactive")

        await emit(db, AuthEvent.MFA_CHALLENGED, tenant_id=user.tenant_id, subject_id=user.id,
                   metadata={"method": "passkey"})
        await db.commit()
        return user
    except ImportError:
        raise HTTPException(501, "WebAuthn (py_webauthn) not installed")


# ---------------------------------------------------------------------------
# Challenge storage (single-use, TTL-enforced)
# ---------------------------------------------------------------------------

async def _store_challenge(
    user_id: uuid.UUID, challenge: bytes, purpose: str, db: AsyncSession
) -> None:
    """Persist a WebAuthn challenge so it survives across workers."""
    # Delete any existing unused challenge for this user+purpose
    from sqlalchemy import delete

    from app.models.passkey_challenge import PasskeyChallenge
    await db.execute(
        delete(PasskeyChallenge).where(
            PasskeyChallenge.user_id == user_id,
            PasskeyChallenge.purpose == purpose,
        )
    )
    row = PasskeyChallenge(
        id=uuid.uuid4(),
        user_id=user_id,
        challenge=challenge,
        purpose=purpose,
        expires_at=datetime.now(UTC) + timedelta(seconds=_CHALLENGE_TTL),
    )
    db.add(row)
    await db.flush()


async def _consume_challenge(
    user_id: uuid.UUID, purpose: str, db: AsyncSession
) -> bytes:
    """Fetch and delete a challenge (single-use)."""
    from sqlalchemy import delete

    from app.models.passkey_challenge import PasskeyChallenge

    row = await db.scalar(
        select(PasskeyChallenge).where(
            PasskeyChallenge.user_id == user_id,
            PasskeyChallenge.purpose == purpose,
        )
    )
    if row is None:
        raise HTTPException(400, "No pending WebAuthn challenge found")

    now = datetime.now(UTC)
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    if now > exp:
        raise HTTPException(400, "WebAuthn challenge has expired")

    challenge = row.challenge
    await db.execute(
        delete(PasskeyChallenge).where(PasskeyChallenge.id == row.id)
    )
    return challenge


def _rp_id() -> str:
    """Relying party ID — the effective domain of BASE_URL."""
    from urllib.parse import urlparse
    return urlparse(settings.BASE_URL).hostname or "localhost"


# ---------------------------------------------------------------------------
# Credential management (list / revoke)
# ---------------------------------------------------------------------------

async def list_credentials(user_id: uuid.UUID, db: AsyncSession) -> list[dict]:
    """Return all active passkey credentials for a user (safe for UI display)."""
    rows = (
        await db.scalars(
            select(PasskeyCredential)
            .where(PasskeyCredential.user_id == user_id, PasskeyCredential.is_revoked == False)  # noqa: E712
            .order_by(PasskeyCredential.created_at.desc())
        )
    ).all()
    return [
        {
            "id": str(r.id),
            "name": r.device_name or "Security key",
            "created_at": r.created_at.isoformat(),
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
        }
        for r in rows
    ]


async def revoke_credential(
    credential_uuid: uuid.UUID, user_id: uuid.UUID, db: AsyncSession
) -> None:
    """Soft-delete a passkey credential. Only the owning user may revoke their own keys."""
    from sqlalchemy import update as sqla_update
    result = await db.execute(
        sqla_update(PasskeyCredential)
        .where(PasskeyCredential.id == credential_uuid, PasskeyCredential.user_id == user_id)
        .values(is_revoked=True)
        .returning(PasskeyCredential.id)
    )
    if result.first() is None:
        raise HTTPException(404, "Credential not found")
    await db.commit()
