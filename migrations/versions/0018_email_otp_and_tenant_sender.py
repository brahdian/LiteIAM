"""Add email_otps table and per-tenant email sender columns.

Revision ID: 0018_email_otp_and_tenant_sender
Revises: 0017_audit_retention_email_change
Create Date: 2026-06-25

email_otps: passwordless 6-digit sign-in codes (sibling of magic_link_tokens),
with an attempts counter to cap brute-force against the small code space.
tenants.email_from_address/email_from_name: per-tenant From-header override so
enterprise tenants' onboarding/auth emails carry their own brand.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0018_email_otp_and_tenant_sender"
down_revision = "0017_audit_retention_email_change"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_otps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code_hash", sa.String(64), nullable=False, index=True),
        sa.Column("email", sa.String(320), nullable=False, index=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("ip_address", sa.String(45), nullable=True),
    )

    op.add_column("tenants", sa.Column("email_from_address", sa.String(320), nullable=True))
    op.add_column("tenants", sa.Column("email_from_name", sa.String(256), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "email_from_name")
    op.drop_column("tenants", "email_from_address")
    op.drop_table("email_otps")
