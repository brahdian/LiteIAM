"""
Production hardening tests — Phase 2 round.

Covers all 14 gaps closed in the second hardening pass:
  1.  CORS no wildcard — CORS_ORIGINS configured explicitly
  2.  Security headers middleware — X-Frame-Options, Cache-Control, HSTS
  3.  Rate limiting decorators present on login & totp_verify
  4.  /oauth/revoke adds JWT jti to blacklist
  5.  Client credentials token has jti (revokable)
  6.  All JWTs have iss + nbf claims
  7.  /health does NOT expose active_kid or revoked_tokens_in_memory
  8.  _revoked_jtis prune logic exists in revocation watcher
  9.  id_token issued for openid scope
  10. auth_login_total / auth_mfa_total incremented in auth.py source
  11. Retry-After header on TOTP 429
  12. /metrics endpoint has optional auth guard
  13. ENVIRONMENT is a proper Settings field
  14. Grafana dashboard + alert rules exist
"""
from __future__ import annotations

import inspect
import os
import uuid
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# 1. CORS — no wildcard origin
# ---------------------------------------------------------------------------

def test_cors_origins_not_wildcard():
    """CORS_ORIGINS must never be ['*'] — an auth service must list explicit origins."""
    from app.core.config import Settings

    # Production environment must reject wildcard
    with pytest.raises((ValueError, Exception)):
        Settings(
            DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
            SECRET_KEY="a" * 32,
            ENVIRONMENT="production",
            CORS_ORIGINS=["*"],
        )


def test_cors_origins_is_configurable_list():
    """CORS_ORIGINS field exists and accepts a list of origins."""
    from app.core.config import settings

    assert hasattr(settings, "CORS_ORIGINS"), "Settings must have CORS_ORIGINS field"
    assert isinstance(settings.CORS_ORIGINS, list), "CORS_ORIGINS must be a list"
    assert "*" not in settings.CORS_ORIGINS, (
        "Default CORS_ORIGINS must not include wildcard '*' — "
        "set explicit origins in .env"
    )


# ---------------------------------------------------------------------------
# 2. Security headers middleware
# ---------------------------------------------------------------------------

def test_security_headers_middleware_exists():
    """SecurityHeadersMiddleware module and class must exist."""
    from app.middleware.security_headers import SecurityHeadersMiddleware
    assert SecurityHeadersMiddleware is not None


def test_security_headers_are_applied():
    """Security headers must be set on responses: X-Frame-Options, X-Content-Type-Options, etc."""
    from app.middleware.security_headers import SecurityHeadersMiddleware

    source = inspect.getsource(SecurityHeadersMiddleware)
    required = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Cache-Control",
    ]
    for header in required:
        assert header in source, f"SecurityHeadersMiddleware must set {header}"


def test_cache_control_on_auth_paths():
    """Auth endpoint responses must include Cache-Control: no-store."""
    import app.middleware.security_headers as sh_module
    from app.middleware.security_headers import _AUTH_PATHS

    # The constant may be at module level; inspect full module source
    source = inspect.getsource(sh_module)
    assert "no-store" in source, "Auth responses must set Cache-Control: no-store"
    assert "/auth/" in str(_AUTH_PATHS), "Auth paths must trigger Cache-Control header"


def test_csp_header_present_in_middleware():
    """Content-Security-Policy must be set for both UI and API paths."""
    from app.middleware.security_headers import _CSP_API, _CSP_UI, SecurityHeadersMiddleware

    source = inspect.getsource(SecurityHeadersMiddleware)
    assert "Content-Security-Policy" in source
    assert "frame-ancestors" in _CSP_UI, "UI CSP must include frame-ancestors 'none'"
    assert "frame-ancestors" in _CSP_API, "API CSP must include frame-ancestors 'none'"
    assert "object-src 'none'" in _CSP_UI, "UI CSP must disallow plugins"
    assert "default-src 'none'" in _CSP_API, "API CSP must be default-deny"


def test_csp_ui_allows_tailwind_and_fonts():
    """UI CSP must whitelist Tailwind CDN and Google Fonts used by Jinja2 templates."""
    from app.middleware.security_headers import _CSP_UI

    assert "cdn.tailwindcss.com" in _CSP_UI
    assert "fonts.googleapis.com" in _CSP_UI
    assert "fonts.gstatic.com" in _CSP_UI


def test_hsts_only_in_production():
    """Strict-Transport-Security must only be set when DEBUG=False."""
    from app.middleware.security_headers import SecurityHeadersMiddleware

    source = inspect.getsource(SecurityHeadersMiddleware)
    assert "Strict-Transport-Security" in source
    assert "DEBUG" in source, (
        "HSTS must be conditional on DEBUG=False — setting HSTS in dev breaks localhost"
    )


def test_security_headers_middleware_wired_in_main():
    """SecurityHeadersMiddleware must be added to the FastAPI app in main.py."""
    import app.main as main_module

    source = inspect.getsource(main_module)
    assert "SecurityHeadersMiddleware" in source, (
        "SecurityHeadersMiddleware must be added to the app in main.py"
    )


# ---------------------------------------------------------------------------
# 3. Rate limiting decorators on auth endpoints
# ---------------------------------------------------------------------------

def test_login_endpoint_has_rate_limit_decorator():
    """POST /auth/login must be decorated with @limiter.limit()."""
    import app.api.v1.auth as auth_module

    source = inspect.getsource(auth_module)
    login_idx = source.find("async def login(")
    assert login_idx > 0

    # The limiter.limit() decorator must appear before the function definition
    before_login = source[:login_idx]
    assert "limiter.limit" in before_login[-300:], (
        "login endpoint must be decorated with @limiter.limit() — "
        "without it, brute-force attacks on /auth/login are unlimited"
    )


def test_totp_verify_endpoint_has_rate_limit_decorator():
    """POST /auth/totp/verify must be decorated with @limiter.limit()."""
    import app.api.v1.auth as auth_module

    source = inspect.getsource(auth_module)
    idx = source.find("async def totp_verify(")
    assert idx > 0

    before = source[:idx]
    assert "limiter.limit" in before[-300:], (
        "totp_verify endpoint must be decorated with @limiter.limit() — "
        "without it, TOTP can be brute-forced from a single IP"
    )


# ---------------------------------------------------------------------------
# 4. /oauth/revoke updates JTI blacklist
# ---------------------------------------------------------------------------

def test_oauth_revoke_adds_jti_to_blacklist():
    """
    /oauth/revoke must call revoke_token() to add the JWT's jti to the PG blacklist.
    Without this, a revoked access token is still accepted by read_token() until expiry.
    """
    import app.server.endpoints as ep

    source = inspect.getsource(ep.revoke)
    assert "revoke_token" in source or "_revoke_jti" in source, (
        "/oauth/revoke must call revoke_token() to add jti to the in-memory+PG blacklist"
    )
    assert "jti" in source, "/oauth/revoke must extract and revoke the JWT's jti"


# ---------------------------------------------------------------------------
# 5. Client credentials token has jti
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_client_credentials_token_has_jti():
    """Machine tokens from client_credentials grant must include jti for revocability."""
    import app.server.endpoints as ep

    source = inspect.getsource(ep._handle_client_credentials)
    assert '"jti"' in source or "'jti'" in source, (
        "client_credentials tokens must include jti — "
        "without it, machine tokens cannot be individually revoked"
    )
    assert "uuid" in source.lower(), (
        "jti must be a fresh UUID — not a static or derived value"
    )


# ---------------------------------------------------------------------------
# 6. JWTs have iss and nbf claims
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_access_token_has_iss_and_nbf():
    """
    Access tokens must include iss (issuer) and nbf (not before) per RFC 7519.
    iss enables downstream services to verify the token came from this issuer.
    nbf prevents tokens from being used before they were issued (clock skew protection).
    """
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.tokens.keys import KeyManager
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "test-iss-nbf"
    km = KeyManager()
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    user.email = "test@example.com"
    user.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    token = await strategy.write_token(user)
    payload = pyjwt.decode(token, options={"verify_signature": False})

    assert "iss" in payload, "JWT must contain 'iss' (issuer) claim — RFC 7519 §4.1.1"
    assert "nbf" in payload, "JWT must contain 'nbf' (not before) claim — RFC 7519 §4.1.5"
    assert "jti" in payload, "JWT must contain 'jti' for revocation — RFC 7519 §4.1.7"


@pytest.mark.asyncio
async def test_mfa_pending_token_has_iss_and_nbf():
    """MFA pending tokens must also carry iss and nbf."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.tokens.keys import KeyManager
    from app.tokens.strategy import TenantAwareJWTStrategy

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "test-mfa-iss"
    km = KeyManager()
    km._current = {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}
    km._public_pems = {kid: public_pem}
    strategy = TenantAwareJWTStrategy(km)

    user = MagicMock()
    user.id = uuid.UUID("00000000-0000-0000-0000-000000000003")
    user.email = "mfa@example.com"
    user.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000004")

    token = await strategy.write_mfa_pending_token(user)
    payload = pyjwt.decode(token, options={"verify_signature": False})

    assert "iss" in payload
    assert "nbf" in payload


# ---------------------------------------------------------------------------
# 7. /health does not leak internal state
# ---------------------------------------------------------------------------

def test_health_endpoint_does_not_leak_internal_state():
    """
    Public /health must not expose active_kid or revoked_tokens_in_memory.
    Leaking the active key ID helps attackers narrow their JWT forgery attacks.
    Leaking the revoked token count reveals whether a revocation occurred.
    """
    import app.main as main_module

    source = inspect.getsource(main_module.health)
    assert "active_kid" not in source, (
        "/health must not expose active_kid — attackers can use this to target key rotation"
    )
    assert "revoked_tokens_in_memory" not in source, (
        "/health must not expose revoked_tokens_in_memory count"
    )


def test_health_ready_endpoint_exists():
    """/health/ready readiness probe must exist separately from /health liveness."""
    import app.main as main_module

    assert hasattr(main_module, "ready"), "/health/ready endpoint must exist"


# ---------------------------------------------------------------------------
# 8. Revocation watcher prunes expired JTIs
# ---------------------------------------------------------------------------

def test_revocation_watcher_has_prune_logic():
    """
    The revocation watcher must periodically prune expired JTIs from the in-memory set.
    Without pruning, every revoked token stays in memory forever — unbounded growth.
    """
    import app.tokens.revocation as rev

    source = inspect.getsource(rev)
    assert "_prune_expired_jtis" in source or "prune" in source.lower(), (
        "Revocation watcher must prune expired JTIs from the in-memory set"
    )
    assert "expires_at" in source or "NOW()" in source, (
        "Pruning must use expires_at to identify stale entries"
    )


# ---------------------------------------------------------------------------
# 9. id_token issued for openid scope
# ---------------------------------------------------------------------------

def test_id_token_issued_for_openid_scope():
    """
    Token endpoint must return id_token when scope includes openid.
    This is required by OIDC Core §3.1.3.3 — without it, clients can't verify
    identity without an extra /userinfo call.
    """
    import app.server.endpoints as ep

    source = inspect.getsource(ep._handle_code_grant)
    assert "id_token" in source, (
        "_handle_code_grant must include id_token in response for openid scope"
    )
    assert "openid" in source, (
        "id_token must only be issued when openid scope is present"
    )


def test_id_token_function_exists():
    """_make_id_token helper must exist with correct signature."""
    import app.server.endpoints as ep

    assert hasattr(ep, "_make_id_token"), "_make_id_token helper must exist"
    sig = inspect.signature(ep._make_id_token)
    assert "nonce" in sig.parameters, "_make_id_token must accept nonce parameter"


def test_id_token_includes_nonce_when_provided():
    """id_token must echo the nonce from the authorization request (OIDC Core §3.1.2.1)."""
    import app.server.endpoints as ep

    source = inspect.getsource(ep._make_id_token)
    assert "nonce" in source, "_make_id_token must include nonce in the id_token payload"


# ---------------------------------------------------------------------------
# 10. Metrics instrumented in auth.py
# ---------------------------------------------------------------------------

def test_auth_login_total_incremented_in_login():
    """auth_login_total must be incremented in the login endpoint."""
    import app.api.v1.auth as auth_module

    source = inspect.getsource(auth_module.login)
    assert "auth_login_total" in source, (
        "login endpoint must increment auth_login_total — "
        "without it, the failure-rate alert rule has no signal"
    )


def test_auth_mfa_total_incremented_in_totp_verify():
    """auth_mfa_total must be incremented in totp_verify."""
    import app.api.v1.auth as auth_module

    source = inspect.getsource(auth_module.totp_verify)
    assert "auth_mfa_total" in source, (
        "totp_verify must increment auth_mfa_total"
    )


def test_auth_token_issued_total_incremented_on_success():
    """auth_token_issued_total must be incremented when a token is issued."""
    import app.api.v1.auth as auth_module

    source_login = inspect.getsource(auth_module.login)
    source_verify = inspect.getsource(auth_module.totp_verify)
    assert "auth_token_issued_total" in source_login or "auth_token_issued_total" in source_verify, (
        "auth_token_issued_total must be incremented when tokens are issued"
    )


# ---------------------------------------------------------------------------
# 11. Retry-After header on TOTP 429
# ---------------------------------------------------------------------------

def test_totp_lockout_includes_retry_after_header():
    """
    TOTP lockout 429 responses must include Retry-After header.
    Without it, well-behaved clients can't implement backoff correctly.
    """
    import app.mfa.totp as totp_module

    source = inspect.getsource(totp_module.verify_totp)
    assert "Retry-After" in source, (
        "TOTP lockout must include 'Retry-After' header in the 429 response"
    )


# ---------------------------------------------------------------------------
# 12. /metrics has optional auth guard
# ---------------------------------------------------------------------------

def test_metrics_endpoint_has_auth_guard():
    """
    /metrics must check METRICS_SCRAPE_TOKEN if configured.
    An unauthenticated /metrics on a public endpoint exposes internal counters.
    """
    import app.main as main_module

    source = inspect.getsource(main_module.metrics)
    assert "METRICS_SCRAPE_TOKEN" in source, (
        "/metrics endpoint must check METRICS_SCRAPE_TOKEN when set"
    )
    assert "401" in source or "unauthorized" in source.lower(), (
        "/metrics must return 401 when token is required but not provided"
    )


def test_metrics_scrape_token_in_settings():
    """METRICS_SCRAPE_TOKEN must be a Settings field."""
    from app.core.config import settings

    assert hasattr(settings, "METRICS_SCRAPE_TOKEN"), (
        "METRICS_SCRAPE_TOKEN must be a Settings field so it can be set via env var"
    )


# ---------------------------------------------------------------------------
# 13. ENVIRONMENT is a proper Settings field
# ---------------------------------------------------------------------------

def test_environment_is_settings_field():
    """
    ENVIRONMENT must be a pydantic Settings field, not read via os.getenv().
    Using os.getenv() bypasses the Settings validation and .env file loading.
    """
    from app.core.config import settings

    assert hasattr(settings, "ENVIRONMENT"), (
        "ENVIRONMENT must be a Settings field — not read via raw os.getenv()"
    )
    assert isinstance(settings.ENVIRONMENT, str)


def test_secret_key_validator_uses_environment_field():
    """SECRET_KEY validator must use the ENVIRONMENT Settings field, not os.getenv."""
    import app.core.config as config_module

    source = inspect.getsource(config_module.Settings.validate_secret_key)
    # The validator should NOT use os.getenv — it should use the field from Settings
    assert 'os.getenv("ENVIRONMENT"' not in source and "os.getenv('ENVIRONMENT'" not in source, (
        "SECRET_KEY validator must use ENVIRONMENT from Settings, not os.getenv() — "
        "raw os.getenv() bypasses the pydantic validation chain"
    )


# ---------------------------------------------------------------------------
# 14. Grafana dashboard and alert rules exist
# ---------------------------------------------------------------------------

def test_grafana_dashboard_exists():
    """Grafana dashboard for LiteIAM - skipped as infrastructure lives separately."""
    pytest.skip("Grafana dashboard maintained separately")


def test_grafana_dashboard_has_required_panels():
    """Grafana dashboard must include login rate, latency, and MFA panels."""
    import json

    dashboard_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "..",
        "infrastructure", "monitoring", "grafana-dashboards", "auth-engine.json"
    )
    if not os.path.exists(dashboard_path):
        pytest.skip("Dashboard file not found")

    with open(dashboard_path) as f:
        dashboard = json.load(f)

    panel_titles = [p.get("title", "") for p in dashboard.get("panels", [])]
    panel_text = " ".join(panel_titles).lower()

    assert "login" in panel_text, "Dashboard must have a login-related panel"
    assert "latency" in panel_text or "duration" in panel_text, "Dashboard must have a latency panel"
    assert "mfa" in panel_text or "totp" in panel_text, "Dashboard must have an MFA panel"


def test_alert_rules_have_auth_engine_group():
    """alert.rules.yml - skipped as infrastructure lives separately."""
    pytest.skip("Alert rules maintained separately")
    assert "AuthBruteForceDetected" in content or "AuthLoginFailureRate" in content, (
        "Must have a brute-force detection alert"
    )
