"""add ip_allowlist and ip_blocklist JSONB columns to tenants

Revision ID: 0009_tenant_ip_policy
Revises: 0008_password_history
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0009_tenant_ip_policy"
down_revision = "0008_password_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "ip_allowlist",
            JSONB,
            nullable=True,
            comment="CIDR ranges allowed to log in. NULL = unrestricted.",
        ),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "ip_blocklist",
            JSONB,
            nullable=True,
            comment="CIDR ranges always denied. Checked before allowlist.",
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "ip_blocklist")
    op.drop_column("tenants", "ip_allowlist")
