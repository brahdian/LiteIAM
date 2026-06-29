"""Add require_mfa flag to tenants table.

Revision ID: 0015_tenant_require_mfa
Revises: 0014_personal_access_tokens
Create Date: 2026-06-25

When require_mfa=True, every user in that tenant must have TOTP enrolled
before they can receive a full access token. Login attempts from users
without TOTP enrolled are blocked with 403 and directed to enrollment.
"""

from alembic import op
import sqlalchemy as sa

revision = "0015_tenant_require_mfa"
down_revision = "0014_personal_access_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "require_mfa",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "require_mfa")
