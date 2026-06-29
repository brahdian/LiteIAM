"""Add token_family_id to oauth_tokens for refresh-token theft detection.

Revision ID: 0004_token_family_id
Revises: 0003_account_lockout
Create Date: 2026-06-25

All tokens in a rotation chain share the same family_id (UUID).
When a rotated-out (already-revoked) refresh token is presented, the entire
family is revoked immediately — the canonical "refresh token theft" signal.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0004_token_family_id"
down_revision = "0003_account_lockout"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "oauth_tokens",
        sa.Column("token_family_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_oauth_tokens_token_family_id", "oauth_tokens", ["token_family_id"])


def downgrade() -> None:
    op.drop_index("ix_oauth_tokens_token_family_id", table_name="oauth_tokens")
    op.drop_column("oauth_tokens", "token_family_id")
