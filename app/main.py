from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.exceptions import add_problem_details_handler

# Configure structured logging before anything else obtains a logger.
# This ensures all log lines (including import-time warnings) are formatted.
from app.core.logging import configure_logging

configure_logging()

from app.authz.enforcer import casbin_enforcer
from app.authz.watcher import start_policy_watcher, stop_policy_watcher
from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.core.rate_limit import limiter
from app.middleware.pat_auth import PATAuthMiddleware
from app.middleware.reg_rate_limit import RegistrationRateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.tenant_bind import TenantBindMiddleware
from app.models.base import Base
from app.tokens.keys import key_manager
from app.tokens.revocation import start_revocation_watcher, stop_revocation_watcher
from app.tokens.scheduler import start_key_rotation_scheduler, stop_key_rotation_scheduler

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables (dev convenience — use Alembic migrations in production)
    if settings.DEBUG:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # Phase 1: KeyManager — loads or creates RSA signing key pair
    async with AsyncSessionLocal() as db:
        await key_manager.initialize(db)

    # Phase 2: Casbin enforcer + PG policy watcher
    await casbin_enforcer.initialize(settings.DATABASE_URL)
    await start_policy_watcher(settings.DATABASE_URL)

    # Phase 6: Token revocation watcher + key rotation scheduler
    await start_revocation_watcher(settings.DATABASE_URL)
    await start_key_rotation_scheduler()

    # Daily audit log retention cleanup
    from app.core.events import start_audit_retention_task
    start_audit_retention_task()

    logger.info(
        "auth_engine_started",
        version=settings.APP_VERSION,
        base_url=settings.BASE_URL,
        environment=settings.ENVIRONMENT,
    )
    yield
    logger.info("auth_engine_stopping")
    await stop_key_rotation_scheduler()
    await stop_revocation_watcher()
    await stop_policy_watcher()
    from app.identity.social import close_http_client
    await close_http_client()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
except ImportError:
    pass

# RFC 7807 Problem Details — replaces FastAPI's default {"detail": "..."} format
# with structured application/problem+json on all HTTP exceptions and validation errors.
add_problem_details_handler(app)


@app.exception_handler(Exception)
async def _pool_exhaustion_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Return 503 (not 500) when the asyncpg connection pool is exhausted.
    A 503 signals upstream load balancers to retry on a different pod,
    while 500 would be cached as a permanent error by some clients.
    """
    exc_name = type(exc).__name__
    if "TooManyConnections" in exc_name or "PoolTimeout" in exc_name or "pool" in str(exc).lower():
        logger.warning("db_pool_exhausted", exc=str(exc), path=str(request.url.path))
        return JSONResponse(
            status_code=503,
            content={"error": "service_unavailable"},
            headers={"Retry-After": "2"},
        )
    raise exc


# Request ID propagation — outermost so every log line gets request_id.
# Must be first (outermost) because Starlette applies middleware in reverse
# registration order: last-registered = outermost = runs first.
app.add_middleware(RequestIDMiddleware)

# Security headers before CORS so they're always applied
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
)

# Bind tenant_id from JWT into ContextVar before endpoint runs.
# get_tenant_session() reads this to issue SET LOCAL search_path.
app.add_middleware(TenantBindMiddleware)

# PAT validation: resolves aai_* bearer tokens into User objects before routing.
# Must run after TenantBindMiddleware so tenant context is available.
app.add_middleware(PATAuthMiddleware)

# Registration abuse prevention: 5 registrations per IP per hour.
app.add_middleware(RegistrationRateLimitMiddleware)

# Metrics endpoint — optionally protected by a scrape token
_instrumentator = Instrumentator()
_instrumentator.instrument(app)


def _metrics_handler(request: Request):
    """Protect /metrics with a bearer token if METRICS_SCRAPE_TOKEN is set."""
    if settings.METRICS_SCRAPE_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != settings.METRICS_SCRAPE_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return _instrumentator.expose(app)


# Expose /metrics with optional auth guard
@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    if settings.METRICS_SCRAPE_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != settings.METRICS_SCRAPE_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    from starlette.responses import Response
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from app.admin.audit import router as audit_router
from app.admin.email_sender import router as email_sender_router
from app.admin.ip_policy import router as ip_policy_router
from app.admin.jwt_claims import router as jwt_claims_router
from app.admin.users import router as admin_users_router
from app.admin.webhooks import router as webhooks_router
from app.api.v1.auth import router as auth_router
from app.api.v1.email_change import router as email_change_router
from app.api.v1.email_otp import router as email_otp_router
from app.api.v1.enterprise import router as enterprise_router
from app.api.v1.gdpr import router as gdpr_router
from app.api.v1.invitations import router as invitations_router
from app.api.v1.jwks import router as jwks_router
from app.api.v1.login_history import router as login_history_router
from app.api.v1.magic_link import router as magic_link_router
from app.api.v1.passkey import router as passkey_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.tokens import router as pat_router
from app.authz.policies import router as policies_router
from app.server.endpoints import router as oidc_router

app.include_router(auth_router)
app.include_router(enterprise_router)
app.include_router(gdpr_router)
app.include_router(pat_router)
app.include_router(invitations_router)
app.include_router(jwks_router)
app.include_router(magic_link_router)
app.include_router(email_otp_router)
app.include_router(passkey_router)
app.include_router(policies_router)
app.include_router(oidc_router)
app.include_router(sessions_router)
app.include_router(login_history_router)
app.include_router(email_change_router)
app.include_router(audit_router)
app.include_router(ip_policy_router)
app.include_router(jwt_claims_router)
app.include_router(admin_users_router)
app.include_router(webhooks_router)
app.include_router(email_sender_router)
# fastapi-users built-in routers (register, reset-password, verify, user CRUD)
from app.api.v1.auth import get_fastapi_users_routers

for fu_router, prefix, tags in get_fastapi_users_routers():
    app.include_router(fu_router, prefix=prefix, tags=tags)


# ---------------------------------------------------------------------------
# Health — public minimal check, no internal state leak
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe — minimal response; no internal state exposed."""
    return JSONResponse({"status": "ok", "version": settings.APP_VERSION})


@app.get("/health/ready", tags=["Health"])
async def ready():
    """Readiness probe — confirms KeyManager is initialized."""
    if key_manager._current is None:
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return JSONResponse({"status": "ready"})


@app.get("/health/deep", tags=["Health"])
async def deep_health():
    """Deep health check — probes DB connectivity and key material.

    Returns 200 only when all subsystems are reachable and operational.
    Returns 503 with a per-component breakdown on any failure so load balancers
    and on-call engineers can identify the failing subsystem immediately.
    """
    import time
    components: dict[str, dict] = {}
    overall_ok = True

    # --- Database ---
    t0 = time.monotonic()
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(__import__("sqlalchemy").text("SELECT 1"))
        components["database"] = {"status": "ok", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as exc:
        components["database"] = {"status": "error", "detail": str(exc)[:200]}
        overall_ok = False

    # --- Key manager ---
    if key_manager._current is None:
        components["key_manager"] = {"status": "error", "detail": "no active signing key"}
        overall_ok = False
    else:
        components["key_manager"] = {
            "status": "ok",
            "active_kid": key_manager._current.kid,
            "key_count": len(key_manager._keys),
        }

    status_code = 200 if overall_ok else 503
    return JSONResponse(
        {
            "status": "ok" if overall_ok else "degraded",
            "version": settings.APP_VERSION,
            "components": components,
        },
        status_code=status_code,
    )


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
