"""Add audit_log_retention_days to tenants and email_change_requests table.

Revision ID: 0017_audit_retention_email_change
Revises: 0016_login_sessions
Create Date: 2026-06-25

audit_log_retention_days: per-tenant compliance knob (default 90 days).
email_change_requests: two-step email change flow with token verification.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0017_audit_retention_email_change"
down_revision = "0016_login_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Audit log retention — 90-day default satisfies SOC 2 / GDPR / HIPAA
    op.add_column(
        "tenants",
        sa.Column(
            "audit_log_retention_days",
            sa.Integer(),
            nullable=False,
            server_default="90",
        ),
    )

    # Email change requests — two-step verification
    op.create_table(
        "email_change_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("new_email", sa.String(320), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("email_change_requests")
    op.drop_column("tenants", "audit_log_retention_days")
