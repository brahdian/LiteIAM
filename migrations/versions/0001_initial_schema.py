"""Initial schema — all auth-engine tables.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-24

Tables created:
  tenants              — Tenant registry
  user                 — Users (fastapi-users compatible)
  oauth_account        — Linked OAuth provider accounts
  signing_keys         — RSA signing key pairs (KeyManager)
  audit_logs           — Append-only auth event log
  oauth_clients        — Registered OAuth2/OIDC clients (Phase 3)
  oauth_authorization_codes — PKCE authorization codes (Phase 3)
  oauth_tokens         — Access + refresh token store (Phase 3)
  tenant_idp_configs   — Per-tenant external IDP config (Phase 4)
  passkey_credentials  — WebAuthn credentials (Phase 5)
  passkey_challenges   — Single-use WebAuthn challenges (Phase 5)
  revoked_tokens       — Token revocation blacklist (Phase 6)
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tenants
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    # Users (fastapi-users base: id, email, hashed_password, is_active, is_superuser, is_verified)
    op.create_table(
        "user",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(1024), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("is_superuser", sa.Boolean, nullable=False, default=False),
        sa.Column("is_verified", sa.Boolean, nullable=False, default=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("is_totp_enabled", sa.Boolean, nullable=False, default=False),
        sa.Column("totp_secret_enc", sa.Text, nullable=True),
        sa.Column("totp_failure_count", sa.Integer, nullable=False, default=0),
        sa.Column("totp_last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_last_used_code", sa.String(8), nullable=True),
    )
    op.create_index("ix_user_email", "user", ["email"])
    op.create_index("ix_user_tenant_id", "user", ["tenant_id"])

    # OAuth accounts
    op.create_table(
        "oauth_account",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("oauth_name", sa.String(100), nullable=False),
        sa.Column("access_token", sa.Text, nullable=False),
        sa.Column("expires_at", sa.Integer, nullable=True),
        sa.Column("refresh_token", sa.Text, nullable=True),
        sa.Column("account_id", sa.String(320), nullable=False),
        sa.Column("account_email", sa.String(320), nullable=False),
        sa.UniqueConstraint("oauth_name", "account_id", name="uq_oauth_account_name_id"),
    )
    op.create_index("ix_oauth_account_user_id", "oauth_account", ["user_id"])

    # Signing keys
    op.create_table(
        "signing_keys",
        sa.Column("kid", sa.String(32), primary_key=True),
        sa.Column("private_key_enc", sa.Text, nullable=False),
        sa.Column("public_key_pem", sa.Text, nullable=False),
        sa.Column("is_current", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_signing_keys_is_current", "signing_keys", ["is_current"])

    # Audit log
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("event_metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_event", "audit_logs", ["event"])
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # OAuth2 clients (Phase 3)
    op.create_table(
        "oauth_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False, unique=True),
        sa.Column("client_secret_enc", sa.Text, nullable=True),
        sa.Column("client_name", sa.String(256), nullable=False),
        sa.Column("redirect_uris", postgresql.ARRAY(sa.Text), nullable=False),
        sa.Column("allowed_scopes", postgresql.ARRAY(sa.Text), nullable=False),
        sa.Column("grant_types", postgresql.ARRAY(sa.Text), nullable=False),
        sa.Column("require_pkce", sa.Boolean, nullable=False, default=True),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"])

    # Authorization codes (Phase 3)
    op.create_table(
        "oauth_authorization_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(128), nullable=False, unique=True),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("redirect_uri", sa.Text, nullable=False),
        sa.Column("scope", sa.Text, nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=True),
        sa.Column("code_challenge_method", sa.String(8), nullable=True),
        sa.Column("nonce", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, default=False),
    )
    op.create_index("ix_oauth_auth_codes_code", "oauth_authorization_codes", ["code"])
    op.create_index("ix_oauth_auth_codes_client_id", "oauth_authorization_codes", ["client_id"])

    # OAuth tokens (Phase 3)
    op.create_table(
        "oauth_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("access_token", sa.Text, nullable=False, unique=True),
        sa.Column("refresh_token", sa.String(128), nullable=True, unique=True),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.Text, nullable=False),
        sa.Column("token_type", sa.String(32), nullable=False, default="Bearer"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("refresh_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean, nullable=False, default=False),
    )
    op.create_index("ix_oauth_tokens_access_token", "oauth_tokens", ["access_token"])
    op.create_index("ix_oauth_tokens_refresh_token", "oauth_tokens", ["refresh_token"])
    op.create_index("ix_oauth_tokens_client_id", "oauth_tokens", ["client_id"])

    # Tenant IDP configs (Phase 4)
    op.create_table(
        "tenant_idp_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("discovery_url", sa.Text, nullable=False),
        sa.Column("client_id", sa.String(256), nullable=False),
        sa.Column("client_secret_enc", sa.Text, nullable=False),
        sa.Column("jit_enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("role_mapping", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenant_idp_configs_tenant_id", "tenant_idp_configs", ["tenant_id"])

    # Passkey credentials (Phase 5)
    op.create_table(
        "passkey_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("sign_count", sa.BigInteger, nullable=False, default=0),
        sa.Column("device_name", sa.String(256), nullable=True),
        sa.Column("aaguid", sa.String(64), nullable=True),
        sa.Column("is_revoked", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_passkey_credentials_user_id", "passkey_credentials", ["user_id"])
    op.create_index("ix_passkey_credentials_credential_id", "passkey_credentials", ["credential_id"])

    # Passkey challenges (Phase 5)
    op.create_table(
        "passkey_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("challenge", sa.LargeBinary, nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_passkey_challenges_user_id", "passkey_challenges", ["user_id"])

    # Revoked tokens (Phase 6)
    op.create_table(
        "revoked_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("jti", sa.String(128), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_revoked_tokens_jti", "revoked_tokens", ["jti"])

    # Casbin policy table (managed by casbin-async-sqlalchemy-adapter)
    # The adapter creates its own table; we create it here for explicit schema management
    op.create_table(
        "casbin_rule",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ptype", sa.String(255), nullable=True),
        sa.Column("v0", sa.String(255), nullable=True),
        sa.Column("v1", sa.String(255), nullable=True),
        sa.Column("v2", sa.String(255), nullable=True),
        sa.Column("v3", sa.String(255), nullable=True),
        sa.Column("v4", sa.String(255), nullable=True),
        sa.Column("v5", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("casbin_rule")
    op.drop_table("revoked_tokens")
    op.drop_table("passkey_challenges")
    op.drop_table("passkey_credentials")
    op.drop_table("tenant_idp_configs")
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_authorization_codes")
    op.drop_table("oauth_clients")
    op.drop_table("audit_logs")
    op.drop_table("signing_keys")
    op.drop_table("oauth_account")
    op.drop_table("user")
    op.drop_table("tenants")
