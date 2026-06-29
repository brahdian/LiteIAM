"""add custom_jwt_claims JSONB column to tenants

Revision ID: 0012_tenant_custom_jwt_claims
Revises: 0011_user_invitations
Create Date: 2026-06-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0012_tenant_custom_jwt_claims"
down_revision = "0011_user_invitations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "custom_jwt_claims",
            JSONB,
            nullable=True,
            comment="Flat dict injected into every JWT for this tenant. Reserved claims ignored.",
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "custom_jwt_claims")
