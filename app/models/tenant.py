from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Per-tenant IP policy — null means "no restriction"
    # List of CIDR strings, e.g. ["10.0.0.0/8", "203.0.113.5/32"]
    ip_allowlist: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    ip_blocklist: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Custom JWT claims injected into every token issued for this tenant's users.
    # Flat dict of string→scalar values, e.g. {"org_plan": "enterprise", "region": "us-east"}
    # Reserved claim names (sub, iss, aud, exp, iat, nbf, jti, email, tenant_id, auth_stage)
    # are silently ignored at injection time.
    custom_jwt_claims: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # When True, all users in this tenant must have TOTP enrolled before they
    # can receive a full access token. Logins from users without TOTP enrolled
    # are blocked with 403 + enrollment URL until they complete setup.
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, server_default="false")

    # Audit log retention in days (0 = keep forever). Background cleanup purges
    # AuditLog rows older than this threshold daily. Default 90 days satisfies
    # SOC 2 Type II, GDPR, and most HIPAA audit trail requirements.
    audit_log_retention_days: Mapped[int] = mapped_column(
        Integer, default=90, nullable=False, server_default="90"
    )

    # Per-tenant email sender. Enterprise tenants set these so onboarding/auth
    # emails appear to come from their own address/brand rather than the global
    # noreply@example.com. Null falls back to the platform's SMTP_FROM. The SMTP
    # relay itself stays global — only the visible From header is overridden, so
    # deliverability depends on the relay being allowed to send for that domain.
    email_from_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    email_from_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    users: Mapped[list[User]] = relationship("User", back_populates="tenant", lazy="noload")

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} slug={self.slug}>"
