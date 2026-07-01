# LiteIAM

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/brahdian/LiteIAM/actions/workflows/ci.yml/badge.svg)](https://github.com/brahdian/LiteIAM/actions)
[![Docker](https://img.shields.io/badge/docker-ready-0db7ed.svg)](https://hub.docker.com/r/brahdian/liteiam)

A production-ready authentication and authorization service built for multi-tenant SaaS applications. LiteIAM provides complete identity management with support for modern authentication standards.

## Features

- **Multi-tenant architecture** - Tenant isolation with per-tenant configuration
- **OAuth 2.0 / OIDC** - Full OAuth2 server implementation with PKCE support
- **Passkey (WebAuthn)** - Passwordless authentication with hardware security keys
- **TOTP MFA** - Time-based one-time password support via authenticator apps
- **Magic Link** - Passwordless email-based authentication
- **Email OTP** - One-time password via email for MFA
- **JWT tokens** - RSA-signed access and refresh tokens with revocation support
- **Personal Access Tokens** - Long-lived API tokens for programmatic access
- **User Invitations** - Invite-only registration flow
- **Webhook system** - Event-driven notifications for auth events
- **Audit logging** - Comprehensive event tracking for compliance
- **IP Policy** - Per-tenant allowlist/blocklist for IP-based access control
- **GDPR Compliance** - Data export and deletion endpoints

## Quick Start

```bash
# Clone and setup
git clone https://github.com/brahdian/LiteIAM.git
cd LiteIAM

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start the service
uvicorn app.main:app --reload
```

## Configuration

Environment variables (configure in `.env`):

```bash
# Required
DATABASE_URL="postgresql+asyncpg://user:pass@localhost/db"
SECRET_KEY="your-32-character-secret-key"

# Optional (with defaults)
BASE_URL="http://localhost:8000"
SMS_FROM="noreply@example.com"
GOOGLE_CLIENT_ID=""  # For Google OAuth
GOOGLE_CLIENT_SECRET=""

# JWT Settings
ACCESS_TOKEN_LIFETIME_SECONDS=3600
REFRESH_TOKEN_LIFETIME_SECONDS=2592000

# CORS (never use "*" in production)
CORS_ORIGINS='["http://localhost:3000"]'

# SMTP Configuration (leave empty to disable email)
SMTP_HOST=""
SMTP_PORT=587
SMTP_USER=""
SMTP_PASSWORD=""

# Metrics scrape protection
METRICS_SCRAPE_TOKEN=""
```

## API Endpoints

### Authentication

| Endpoint | Description |
|----------|-------------|
| `POST /auth/login` | Username/password authentication |
| `POST /auth/logout` | Logout and revoke token |
| `POST /auth/register` | Register new user |
| `POST /auth/verify` | Verify email address |
| `POST /auth/forgot-password` | Request password reset |
| `POST /auth/reset-password` | Complete password reset |

### Magic Link

| Endpoint | Description |
|----------|-------------|
| `POST /auth/v1/magic-link/send` | Send magic link email |
| `POST /auth/v1/magic-link/verify` | Verify magic link token |

### Email OTP

| Endpoint | Description |
|----------|-------------|
| `POST /auth/v1/email-otp/send` | Send OTP email |
| `POST /auth/v1/email-otp/verify` | Verify OTP code |
| `POST /auth/v1/email-otp/login` | Login with OTP |

### OAuth / OIDC

| Endpoint | Description |
|----------|-------------|
| `GET /auth/google` | Google OAuth login |
| `GET /auth/google/callback` | Google OAuth callback |
| `POST /oauth/token` | OAuth token exchange |
| `GET /.well-known/jwks.json` | JSON Web Key Set for JWT verification |
| `GET /.well-known/openid-configuration` | OIDC discovery document |

### Passkey (WebAuthn)

| Endpoint | Description |
|----------|-------------|
| `GET /auth/v1/passkey/registration/begin` | Begin passkey registration |
| `POST /auth/v1/passkey/registration/complete` | Complete passkey registration |
| `GET /auth/v1/passkey/authentication/begin` | Begin passkey authentication |
| `POST /auth/v1/passkey/authentication/complete` | Complete passkey authentication |

### MFA

| Endpoint | Description |
|----------|-------------|
| `GET /auth/v1/totp/enroll` | Get TOTP enrollment URI |
| `POST /auth/v1/totp/verify` | Verify TOTP code |
| `POST /auth/v1/totp/verify-code` | Verify TOTP during login |

### Admin

| Endpoint | Description |
|----------|-------------|
| `GET /audit-logs` | List audit events |
| `POST /auth/v1/admin/ip-policy` | Configure IP allowlist/blocklist |
| `POST /auth/v1/admin/webhooks` | Create tenant webhook |
| `GET /auth/v1/admin/users` | List users (admin only) |

### Health

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe |
| `GET /health/ready` | Readiness probe |
| `GET /health/deep` | Deep health check with component status |

## Development

Run tests:

```bash
pip install -r requirements-dev.txt
pytest
```

Run with Docker:

```bash
docker build -t liteiam .
docker run -p 8000:8000 liteiam
```

## Architecture

- **Database**: PostgreSQL with async SQLAlchemy 2.x
- **Cache**: Redis-backed token revocation via PG NOTIFY
- **Tasks**: Background cleanup for audit log retention
- **Rate Limiting**: SlowAPI with per-IP limits

## Security Features

- Argon2 password hashing (OWASP recommended)
- RSA-2048 JWT signing with automatic key rotation
- TOTP replay prevention with sign count tracking
- Password history enforcement (NIST SP 800-63B)
- HIBP breach checking for passwords
- Structured audit logging for all auth events
- Optional metrics endpoint authentication

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details.
