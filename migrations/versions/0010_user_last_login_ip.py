"""add last_login_ip and last_login_at columns to user table

Revision ID: 0010_user_last_login_ip
Revises: 0009_tenant_ip_policy
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_user_last_login_ip"
down_revision = "0009_tenant_ip_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("last_login_ip", sa.String(45), nullable=True,
                  comment="IPv4/IPv6 of the last successful login."),
    )
    op.add_column(
        "user",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True,
                  comment="Timestamp of the last successful login."),
    )


def downgrade() -> None:
    op.drop_column("user", "last_login_at")
    op.drop_column("user", "last_login_ip")
