# LiteIAM Runbook

Operational procedures for LiteIAM — a production-ready multi-tenant IAM platform.

---

## Startup

### Normal start (Docker Compose)

```bash
docker compose up liteiam
```

On startup the service:
1. Initialises `KeyManager` — loads current RSA key pair from `signing_keys` table or creates one if absent
2. Initialises `SafeCasbinEnforcer` — loads policy from `casbin_rule` table
3. Starts PG LISTEN on `casbin_policy_update` (cross-worker policy sync)
4. Starts PG LISTEN on `token_revoked` (revocation blacklist broadcast)
5. Starts key rotation scheduler (daily check; rotates if key expires within 7 days)
6. Runs DB migrations (in production, run Alembic manually before restart — see below)

**Health check:**

```bash
curl http://localhost:8100/health
# {"status":"ok","version":"0.1.0","active_kid":"<hex>","revoked_tokens_in_memory":<n>}
```

### First-time setup

```bash
# Run migrations against production DB
DATABASE_URL="postgresql+asyncpg://..." alembic upgrade head

# Generate initial superuser via one-shot script (replace values)
docker compose run --rm liteiam python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from app.identity.password import get_user_manager, get_user_db
from app.models.tenant import Tenant
import uuid

async def main():
    async with AsyncSessionLocal() as db:
        # Create default tenant
        tenant = Tenant(id=uuid.uuid4(), slug='default', name='LiteIAM Default')
        db.add(tenant)
        await db.commit()
        print(f'Tenant created: {tenant.id}')

asyncio.run(main())
"
```

---

## Key Rotation

### Automatic rotation

The key rotation scheduler runs daily. It rotates the signing key automatically when the current key is within 7 days of expiry (`SIGNING_KEY_ROTATION_DAYS`, default 90).

**Zero-downtime guarantee:** The old `kid` remains in `_public_pems` and is served from `/.well-known/jwks.json` until its `expires_at` passes. Tokens signed with the old key continue to verify.

### Manual rotation (emergency)

Trigger an immediate rotation without waiting for the scheduler:

```bash
docker compose exec liteiam python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from app.tokens.keys import key_manager

async def main():
    async with AsyncSessionLocal() as db:
        await key_manager.initialize(db)  # ensure loaded
    async with AsyncSessionLocal() as db:
        new_key = await key_manager.rotate(db)
        print(f'Rotated. New kid: {new_key[\"kid\"]}')

asyncio.run(main())
"
```

After rotation, confirm both kids are in JWKS:

```bash
curl http://localhost:8100/.well-known/jwks.json | python3 -m json.tool | grep kid
```

### Verify downstream services pick up new key

```bash
# Downstream service verifies token — must succeed after key rotation
TOKEN=$(curl -s -X POST http://localhost:8100/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin@example.com","password":"..."}' | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/health
```

---

## Emergency Token Revocation

### Revoke a single token by JTI

```bash
# Extract JTI from a token (decode without verifying)
python3 -c "
import jwt, sys
tok = sys.argv[1]
p = jwt.decode(tok, options={'verify_signature': False})
print(p.get('jti'))
" <TOKEN>

# Revoke via admin API (requires superuser JWT)
curl -X POST http://localhost:8100/auth/revoke \
  -H "Authorization: Bearer <SUPERUSER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"token": "<TOKEN>"}'
```

The revocation is broadcast via PG NOTIFY to all workers within milliseconds. All workers reject the token on next request.

### Revoke all tokens for a user (emergency account lockout)

```bash
# Disable the user account — all subsequent token reads fail auth
docker compose exec liteiam python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from sqlalchemy import update
from app.models.user import User
import uuid

USER_ID = uuid.UUID('<USER_UUID_HERE>')

async def main():
    async with AsyncSessionLocal() as db:
        await db.execute(update(User).where(User.id == USER_ID).values(is_active=False))
        await db.commit()
        print(f'User {USER_ID} deactivated')

asyncio.run(main())
"
```

### Revoke all tokens for a tenant (tenant suspension)

```bash
# Deactivate tenant — all users' tokens fail the tenant_id check
docker compose exec liteiam python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from sqlalchemy import update
from app.models.tenant import Tenant
import uuid

TENANT_ID = uuid.UUID('<TENANT_UUID_HERE>')

async def main():
    async with AsyncSessionLocal() as db:
        await db.execute(update(Tenant).where(Tenant.id == TENANT_ID).values(is_active=False))
        await db.commit()
        print(f'Tenant {TENANT_ID} suspended')

asyncio.run(main())
"
```

---

## Rollback Procedure

### Service rollback (code regression)

Rollback when experiencing issues with the deployed version:

```bash
# Roll back to previous Docker image
docker compose pull liteiam  # or specify previous tag
docker compose up -d liteiam

# Confirm health
curl http://localhost:8100/health
```

Trigger conditions:
- p99 auth latency > 1s for >2 minutes
- Error rate > 1% over 5-minute window
- Any 5xx on `/auth/login` or `/oauth/token`
- Token rejection rate > 0.1% (valid tokens being rejected)

**DB schema rollback:** Only roll back migrations if the new code cannot tolerate the schema. Downgrade degrades the running service — coordinate with the team first.

```bash
alembic downgrade -1  # one step back
```

---

## Observability

### Key Prometheus metrics

| Metric | Alert threshold |
|---|---|
| `auth_login_total{result="failure"}` | > 10% failure rate over 5min |
| `auth_token_issued_total` | Drops to 0 for >1min |
| `auth_mfa_total{result="lockout"}` | > 50/min (brute force signal) |
| `auth_key_rotation_total` | Watch for unexpected rotations |
| `auth_token_revoked_total` | Spike may indicate breach |

### Grafana dashboard

Import `infrastructure/monitoring/dashboards/liteiam.json` into Grafana.
Alert rule file: `infrastructure/monitoring/alert.rules.yml` — add liteiam section.

### Log queries (structlog JSON)

```bash
# Failed logins in the last hour
docker compose logs liteiam | jq 'select(.event=="user.login.failed")' | tail -50

# Token revocations
docker compose logs liteiam | jq 'select(.event=="token.revoked")'

# Key rotations
docker compose logs liteiam | jq 'select(.event=="signing_key.rotated")'
```

---

## 30-Day Secret Rotation Schedule

| Secret | Rotation period | Procedure |
|---|---|---|
| RSA signing key | 90 days | Automatic via scheduler; verify via JWKS kid count |
| `SECRET_KEY` (HMAC state + TOTP encryption) | 90 days | Update env var + redeploy; existing TOTP secrets re-encrypted on next use |
| `FERNET_KEY` (derived from `SECRET_KEY`) | Same as `SECRET_KEY` | No separate action needed |
| Google OAuth client secret | Per Google policy | Update `GOOGLE_CLIENT_SECRET` env var |
| IDP client secrets (per-tenant) | Per IDP policy | Use `PUT /auth/enterprise/config/{tenant_id}` |
| PostgreSQL password | 90 days | Update `DATABASE_URL` env var + redeploy |

**`SECRET_KEY` rotation procedure:**

1. Generate new key: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. Deploy new `SECRET_KEY` env var — new logins get new HMAC states
3. In-flight OAuth callbacks with old `SECRET_KEY` will fail (5min window) — acceptable
4. TOTP secrets encrypted with old key remain readable during dual-key transition period (not yet implemented — tracked in Phase 6 hardening)

---

## On-Call Checklist

Before your first on-call shift:

- [ ] Confirm you have access to production DB
- [ ] Confirm you can run `docker compose exec liteiam` commands
- [ ] Know where Grafana liteiam dashboard is
- [ ] Know how to read structlog JSON output
- [ ] Test emergency revocation procedure on staging
