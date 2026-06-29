"""add totp_backup_codes and oauth_client auto_approve

Revision ID: 0005_backup_codes_consent
Revises: 0004_token_family_id
Create Date: 2026-06-25
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_backup_codes_consent"
down_revision = "0004_token_family_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user", sa.Column("totp_backup_codes", sa.JSON(), nullable=True))
    op.add_column(
        "oauth_clients",
        sa.Column("auto_approve", sa.Boolean(), server_default=sa.text("true"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("oauth_clients", "auto_approve")
    op.drop_column("user", "totp_backup_codes")
