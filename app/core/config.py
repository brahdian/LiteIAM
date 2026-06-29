from __future__ import annotations

import base64
import hashlib
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_KEYS = {
    "change-this-secret-key",
    "secret",
    "supersecret",
    "your-secret-key",
    "changeme",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env", "../../../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "LiteIAM"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"  # "production" enables strict validators
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    DATABASE_URL: str = Field(..., description="Required: PostgreSQL async URL (postgresql+asyncpg://...)")

    SECRET_KEY: str = Field(..., description="Required: min 32-char secret for HMAC state + TOTP encryption")

    # CORS — never use "*" on an auth service; list allowed origins explicitly
    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:3010", "http://localhost:8080"],
        description="Allowed CORS origins. Never use '*' for auth endpoints.",
    )

    # Google OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"

    # JWT settings
    ACCESS_TOKEN_LIFETIME_SECONDS: int = 3600
    REFRESH_TOKEN_LIFETIME_SECONDS: int = 86400 * 30
    MFA_PENDING_TOKEN_LIFETIME_SECONDS: int = 300

    # RSA key size — 2048 is minimum; use 4096 for long-lived platform keys
    RSA_KEY_SIZE: int = 2048
    # Days before a signing key expires (old keys kept for verification until all tokens using them expire)
    SIGNING_KEY_ROTATION_DAYS: int = 90

    # TOTP lockout: consecutive failures before 60s cooldown
    TOTP_MAX_FAILURES: int = 5

    # Set True only when running behind a trusted reverse proxy (nginx/ALB/Cloudflare)
    # that guarantees X-Forwarded-For. Never True in direct-internet deployments.
    TRUST_X_FORWARDED_FOR: bool = False

    # Service base URL (used in OIDC discovery doc and as JWT `iss` claim)
    BASE_URL: str = "http://localhost:8000"
    # Next.js auth-ui base URL — used for email links and OIDC redirects.
    # Defaults to BASE_URL for backward compat; set to the auth-ui hostname in prod.
    AUTH_UI_URL: str = ""

    @property
    def ui_base(self) -> str:
        """Resolved auth-ui origin. Falls back to BASE_URL if AUTH_UI_URL is unset."""
        return (self.AUTH_UI_URL or self.BASE_URL).rstrip("/")

    # Metrics scrape token — if set, /metrics requires Authorization: Bearer <token>
    # Leave empty to allow unauthenticated scraping (only safe in a private network)
    METRICS_SCRAPE_TOKEN: str = ""

    # Email verification gating — if True, login is rejected for unverified users.
    # Set False for dev environments where email delivery is not configured.
    REQUIRE_EMAIL_VERIFICATION: bool = False

    # Password history — number of previous password hashes checked on password change.
    # 0 disables the check. NIST SP 800-63B recommends checking at least 5.
    PASSWORD_HISTORY_DEPTH: int = 5

    # SMTP — leave SMTP_HOST empty to disable email (all send calls become no-ops).
    # Supports STARTTLS (port 587, SMTP_TLS=True) and plain SMTP (port 25).
    # For production, use a transactional relay (SES, Sendgrid, Postmark).
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@example.com"
    SMTP_TLS: bool = True

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        env = (info.data or {}).get("ENVIRONMENT", "development")
        if (v.lower() in _WEAK_KEYS or len(v) < 32) and env == "production":
            raise ValueError("SECRET_KEY must be at least 32 chars and not a known weak value in production")
        return v

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: list[str], info) -> list[str]:
        env = (info.data or {}).get("ENVIRONMENT", "development")
        if env == "production" and ("*" in v or not v):
            raise ValueError("CORS_ORIGINS must list explicit origins in production — wildcard '*' is forbidden")
        return v

    def fernet_key(self) -> bytes:
        """Derive a Fernet-compatible 32-byte key from SECRET_KEY."""
        raw = hashlib.sha256(self.SECRET_KEY.encode()).digest()
        return base64.urlsafe_b64encode(raw)


settings = Settings()
