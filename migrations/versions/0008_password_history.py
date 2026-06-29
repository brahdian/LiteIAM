"""add password_history JSON column to user table

Revision ID: 0008_password_history
Revises: 0007_trusted_devices
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008_password_history"
down_revision = "0007_trusted_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # JSONB for efficient indexing and querying; default NULL (pre-existing users
    # have no history until their first password change post-migration).
    op.add_column(
        "user",
        sa.Column(
            "password_history",
            JSONB,
            nullable=True,
            comment="Ordered list of last N argon2 password hashes (oldest first).",
        ),
    )


def downgrade() -> None:
    op.drop_column("user", "password_history")
