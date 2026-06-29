from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PasskeyChallenge(Base):
    """
    Single-use WebAuthn challenge stored in DB.

    Challenges must be persisted (not in-memory) so multi-worker deployments
    work correctly — any worker may receive the begin request, a different
    worker may receive the complete request.

    Deleted on consumption (_consume_challenge). Expired rows are cleaned up
    by a background sweep (Phase 6 hardening).
    """

    __tablename__ = "passkey_challenges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)  # "registration" | "authentication"
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
