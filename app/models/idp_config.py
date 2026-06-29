from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class TenantIDPConfig(Base):
    """
    Per-tenant external Identity Provider (IDP) configuration.

    Supports any OIDC-compliant provider: Okta, Azure AD, Google Workspace,
    Ping Identity, etc. Credentials are Fernet-encrypted at rest.

    The `role_mapping` JSONB field maps IDP group names to Casbin roles:
      {"Admins": "admin", "Engineers": "member", "Viewers": "viewer"}
    JIT-provisioned users inherit the role corresponding to their first matching group.
    """

    __tablename__ = "tenant_idp_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True, unique=True)

    # OIDC provider metadata
    discovery_url: Mapped[str] = mapped_column(Text, nullable=False)
    client_id: Mapped[str] = mapped_column(String(256), nullable=False)
    # Fernet-encrypted client_secret — decrypt before use, never log
    client_secret_enc: Mapped[str] = mapped_column(Text, nullable=False)

    # JIT provisioning
    jit_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Maps IDP group/role names → internal Casbin role names
    role_mapping: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
