"""Add account-level lockout columns to user table.

Revision ID: 0003_account_lockout
Revises: 0002_encrypt_oauth_access_token
Create Date: 2026-06-25

These columns track failed password attempts independently of TOTP lockout.
After settings.LOGIN_MAX_FAILURES consecutive failures the account is locked
for settings.LOGIN_LOCKOUT_SECONDS (default: 5 failures → 15-minute lockout).
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_account_lockout"
down_revision = "0002_encrypt_oauth_access_token"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "user",
        sa.Column(
            "locked_until",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("user", "locked_until")
    op.drop_column("user", "failed_login_count")
