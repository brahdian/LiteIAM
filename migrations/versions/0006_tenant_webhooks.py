"""add tenant_webhooks table

Revision ID: 0006_tenant_webhooks
Revises: 0005_backup_codes_consent
Create Date: 2026-06-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, UUID

revision = "0006_tenant_webhooks"
down_revision = "0005_backup_codes_consent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_webhooks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret_enc", sa.Text(), nullable=True),
        sa.Column("events", ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenant_webhooks_tenant_id", "tenant_webhooks", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_tenant_webhooks_tenant_id")
    op.drop_table("tenant_webhooks")
