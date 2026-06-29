from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EmailOTP(Base):
    """One-time numeric code emailed for passwordless sign-in.

    A thin sibling of MagicLinkToken: instead of a high-entropy URL token, the
    user receives a 6-digit code they type in. Because the code space is small
    (1e6), brute-force is the real threat, so every code carries an `attempts`
    counter that is capped at verify time and the row is single-use.

    The stored hash is sha256(email:code) — binding the code to the target email
    means a leaked hash cannot be matched against codes issued for other emails.
    """

    __tablename__ = "email_otps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # sha256(f"{email}:{code}") — neither the raw code nor an email-agnostic hash is stored.
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
