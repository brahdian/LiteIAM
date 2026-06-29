"""add trusted_devices table for remember-this-device MFA skip

Revision ID: 0007_trusted_devices
Revises: 0006_tenant_webhooks
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0007_trusted_devices"
down_revision = "0006_tenant_webhooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trusted_devices",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_trusted_devices_user_id", "trusted_devices", ["user_id"])
    op.create_index("ix_trusted_devices_tenant_id", "trusted_devices", ["tenant_id"])
    op.create_index(
        "ix_trusted_devices_token_hash", "trusted_devices", ["device_token_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_trusted_devices_token_hash")
    op.drop_index("ix_trusted_devices_tenant_id")
    op.drop_index("ix_trusted_devices_user_id")
    op.drop_table("trusted_devices")
