from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi_users.db import SQLAlchemyBaseOAuthAccountTableUUID, SQLAlchemyBaseUserTableUUID
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(SQLAlchemyBaseUserTableUUID, Base):
    # fastapi-users base expects this table to be named "user" —
    # OAuthAccount's built-in FK references "user.id"
    __tablename__ = "user"

    # fastapi-users base provides: id, email, hashed_password, is_active,
    # is_superuser, is_verified

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    is_totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_failure_count: Mapped[int] = mapped_column(default=0, nullable=False)
    # Timestamp of last failure — enables time-based lockout reset without external state
    totp_last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Last accepted TOTP code — prevents replay within the ~60-second TOTP window
    totp_last_used_code: Mapped[str | None] = mapped_column(String(8), nullable=True)

    # Account-level lockout (not per-TOTP — this is for failed password attempts)
    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # TOTP backup codes — stored as JSON array of sha256-hashed 8-char codes.
    # Shown to user ONCE at enrollment (plaintext); only hashes persist.
    totp_backup_codes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Last N argon2 password hashes — checked on password change to prevent reuse.
    # Oldest entry is index 0; newest is last. Max length is configurable (default 5).
    password_history: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Last IP that successfully authenticated — used to detect new-IP logins and
    # emit security notifications. Stored as a plain string (IPv4 or IPv6).
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="users", lazy="noload")
    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(
        "OAuthAccount", lazy="joined", primaryjoin="User.id == OAuthAccount.user_id"
    )


class OAuthAccount(SQLAlchemyBaseOAuthAccountTableUUID, Base):
    __tablename__ = "oauth_account"
    # fastapi-users base provides: id, oauth_name, access_token, expires_at,
    # refresh_token, account_id, account_email, user_id (FK → user.id)
    #
    # Phase 6 hardening: access_token_enc stores the Fernet-encrypted Google access token.
    # The base class's access_token column stores the literal string "ENCRYPTED" as a
    # sentinel so we satisfy the non-null constraint without leaking tokens.
    # Use get_decrypted_access_token() to retrieve the real value.
    access_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    def get_decrypted_access_token(self) -> str | None:
        if not self.access_token_enc:
            return None
        from cryptography.fernet import Fernet

        from app.core.config import settings
        f = Fernet(settings.fernet_key())
        return f.decrypt(self.access_token_enc.encode()).decode()

    def __repr__(self) -> str:
        return f"<OAuthAccount id={self.id} oauth={self.oauth_name}>"
