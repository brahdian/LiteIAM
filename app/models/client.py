from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class OAuthClient(Base):
    """
    Registered OAuth2/OIDC client application.
    PKCE is required by default — clients that want implicit flow must
    explicitly opt out, which is gated behind superuser approval.
    """

    __tablename__ = "oauth_clients"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    client_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # None = public client
    client_name: Mapped[str] = mapped_column(String(256), nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    allowed_scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    grant_types: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=lambda: ["authorization_code", "refresh_token"]
    )
    require_pkce: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # True = skip consent screen (first-party/trusted clients). False = show consent UI.
    auto_approve: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.grant_types

    def check_scope(self, scope: str) -> bool:
        requested = set(scope.split())
        return requested.issubset(set(self.allowed_scopes))

    def is_confidential(self) -> bool:
        return self.client_secret_enc is not None

    def verify_secret(self, plain_secret: str) -> bool:
        """Constant-time comparison after Fernet decrypt to prevent timing oracle."""
        if not self.client_secret_enc or not plain_secret:
            return False
        try:
            import hmac

            from cryptography.fernet import Fernet

            from app.core.config import settings
            f = Fernet(settings.fernet_key())
            stored = f.decrypt(self.client_secret_enc.encode()).decode()
            return hmac.compare_digest(stored, plain_secret)
        except Exception:
            return False
