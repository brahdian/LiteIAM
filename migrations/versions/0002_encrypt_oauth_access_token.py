"""Encrypt OAuthAccount access_token at rest.

Revision ID: 0002_encrypt_oauth_access_token
Revises: 0001_initial_schema
Create Date: 2026-06-25

Adds access_token_enc (Fernet-encrypted) column to oauth_account.
The base fastapi-users access_token column is retained as a sentinel
(set to "ENCRYPTED") to satisfy the non-null constraint.

Data migration: existing rows with real tokens in access_token should
be encrypted and moved to access_token_enc in a post-deploy script
before the next rotation. This migration only adds the schema — it does
not attempt to encrypt existing data (would need the SECRET_KEY at migration time).
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_encrypt_oauth_access_token"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "oauth_account",
        sa.Column("access_token_enc", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("oauth_account", "access_token_enc")
