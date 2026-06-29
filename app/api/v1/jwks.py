import json
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

from app.core.config import settings
from app.tokens.keys import key_manager

router = APIRouter(tags=["Discovery"])

# Cached serialized JWKS payload — invalidated when keys rotate.
# Avoids list() copy + json.dumps() on every request under load.
_jwks_cache: bytes = b""
_jwks_etag: str = ""
_jwks_cache_ts: float = 0.0
_JWKS_CACHE_TTL: float = 30.0  # seconds; rotation scheduler fires at intervals >> this


def _jwks_response() -> Response:
    global _jwks_cache, _jwks_etag, _jwks_cache_ts
    now = time.monotonic()
    if not _jwks_cache or (now - _jwks_cache_ts) > _JWKS_CACHE_TTL:
        payload = key_manager.get_jwks()
        _jwks_cache = json.dumps(payload).encode()
        _jwks_etag = f'"{hash(_jwks_cache)}"'
        _jwks_cache_ts = now
    return Response(
        content=_jwks_cache,
        media_type="application/json",
        headers={
            "Cache-Control": "public, max-age=30, stale-while-revalidate=60",
            "ETag": _jwks_etag,
        },
    )


def invalidate_jwks_cache() -> None:
    """Call this after key rotation so the next request rebuilds the cache."""
    global _jwks_cache_ts
    _jwks_cache_ts = 0.0


@router.get("/.well-known/jwks.json", response_model=None)
async def jwks() -> Response:
    """JWKS endpoint — downstream services fetch this to verify JWTs without shared secrets."""
    return _jwks_response()


@router.get("/.well-known/openid-configuration", response_model=None)
async def oidc_discovery() -> JSONResponse:
    """OIDC discovery document."""
    base = settings.BASE_URL.rstrip("/")
    return JSONResponse(
        content={
            "issuer": base,
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "userinfo_endpoint": f"{base}/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "introspection_endpoint": f"{base}/oauth/introspect",
            "revocation_endpoint": f"{base}/oauth/revoke",
        },
        headers={"Cache-Control": "public, max-age=3600"},
    )
