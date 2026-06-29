"""webhook_deliveries table + magic_link_tokens table

Revision ID: 0013_webhook_deliveries_magic_link
Revises: 0012_tenant_custom_jwt_claims
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0013_webhook_deliveries_magic_link"
down_revision = "0012_tenant_custom_jwt_claims"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("webhook_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("delivery_group_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("attempt", sa.Integer, nullable=False),
        sa.Column("event", sa.String(128), nullable=False, index=True),
        sa.Column("payload_json", sa.Text, nullable=False),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "magic_link_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("email", sa.String(320), nullable=False, index=True),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("magic_link_tokens")
    op.drop_table("webhook_deliveries")
