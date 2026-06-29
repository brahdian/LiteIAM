from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PasskeyCredential(Base):
    """
    WebAuthn credential stored after registration ceremony.

    sign_count MUST be incremented on every assertion and compared against
    the stored value. If the device reports sign_count ≤ stored value, it
    may indicate a cloned authenticator — treat as suspicious.

    See WebAuthn L2 §6.5.3 for replay detection requirements.
    """

    __tablename__ = "passkey_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # WebAuthn credential ID (binary, base64url encoded for display)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False, index=True)
    # COSE public key bytes
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Human-readable name for the credential (set during registration)
    device_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # AAGUID identifies authenticator model (optional — useful for policy enforcement)
    aaguid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Whether the credential has been revoked by the user
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
