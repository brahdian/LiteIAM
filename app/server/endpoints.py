
"""
OIDC/OAuth2 server endpoints.

Implements the four core flows:
  - Authorization Code + PKCE  (RFC 7636)
  - Client Credentials          (machine → machine)
  - Refresh Token rotation      (RFC 6749 §6)

All endpoints validate against the OAuthClient registry. PKCE is enforced
unless the client explicitly sets require_pkce=False AND is confidential.

Scopes supported:
  openid, email, profile, offline_access
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import current_active_user
from app.models.client import OAuthClient
from app.models.token import OAuthAuthorizationCode, OAuthToken
from app.models.user import User
from app.tokens.strategy import TenantAwareJWTStrategy, get_jwt_strategy

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/oauth", tags=["OAuth2/OIDC"])

_AUTH_CODE_TTL = 60  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkce_verify(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method != "S256":
        # plain and unknown methods are rejected — S256 is the only safe method
        raise HTTPException(status_code=400, detail="only S256 code_challenge_method is supported")
    import base64
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == code_challenge


async def _get_client(client_id: str, db: AsyncSession) -> OAuthClient:
    client = await db.scalar(
        select(OAuthClient).where(OAuthClient.client_id == client_id, OAuthClient.is_active)
    )
    if client is None:
        raise HTTPException(401, "Unknown or inactive client")
    return client


# ---------------------------------------------------------------------------
# Authorization endpoint — issues an authorization code
# ---------------------------------------------------------------------------

@router.get("/authorize")
async def authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query(...),
    scope: str = Query("openid"),
    state: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query("S256"),
    nonce: str | None = Query(None),
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    client = await _get_client(client_id, db)

    if not client.check_redirect_uri(redirect_uri):
        raise HTTPException(400, "Invalid redirect_uri")
    if response_type != "code":
        raise HTTPException(400, "Only response_type=code is supported")
    if not client.check_grant_type("authorization_code"):
        raise HTTPException(400, "Client not authorized for authorization_code grant")
    if not client.check_scope(scope):
        raise HTTPException(400, f"Requested scope(s) not allowed: {scope}")

    if client.require_pkce and not code_challenge:
        raise HTTPException(400, "PKCE code_challenge is required for this client")

    # Third-party clients (auto_approve=False) require user consent before issuing a code.
    if not client.auto_approve:
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state or "",
            "code_challenge": code_challenge or "",
            "code_challenge_method": code_challenge_method or "S256",
            "nonce": nonce or "",
        }
        return RedirectResponse(f"{settings.ui_base}/oauth/consent?{urlencode(params)}", status_code=302)

    code = secrets.token_urlsafe(32)
    auth_code = OAuthAuthorizationCode(
        id=uuid.uuid4(),
        code=code,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        expires_at=datetime.now(UTC) + timedelta(seconds=_AUTH_CODE_TTL),
    )
    db.add(auth_code)
    await db.commit()

    params = f"code={code}"
    if state:
        params += f"&state={state}"
    return RedirectResponse(f"{redirect_uri}?{params}", status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint — exchanges code → tokens, or refreshes
# ---------------------------------------------------------------------------

@router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    # Authorization code params
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    # Refresh token params
    refresh_token: str | None = Form(None),
    # Client credentials params
    scope: str | None = Form("openid"),
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    client = await _get_client(client_id, db)

    # RFC 6749 §2.3.1: confidential clients MUST authenticate at the token endpoint.
    # Accept client_secret via form body OR HTTP Basic auth (Authorization: Basic b64(id:secret)).
    if client.is_confidential():
        effective_secret = client_secret
        if not effective_secret:
            # Try HTTP Basic auth
            import base64 as _b64
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                try:
                    decoded = _b64.b64decode(auth_header[6:]).decode()
                    _cid, _, _sec = decoded.partition(":")
                    if _cid == client_id:
                        effective_secret = _sec
                except Exception:
                    pass
        if not effective_secret or not client.verify_secret(effective_secret):
            raise HTTPException(
                status_code=401,
                detail="Client authentication failed",
                headers={"WWW-Authenticate": "Basic"},
            )

    if grant_type == "authorization_code":
        return await _handle_code_grant(code, redirect_uri, code_verifier, client, db, strategy)
    elif grant_type == "refresh_token":
        return await _handle_refresh_grant(refresh_token, client, db, strategy)
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(scope, client, db, strategy)
    else:
        raise HTTPException(400, f"Unsupported grant_type: {grant_type}")


async def _handle_code_grant(
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
    client: OAuthClient,
    db: AsyncSession,
    strategy: TenantAwareJWTStrategy,
) -> dict:
    if not code:
        raise HTTPException(400, "code is required")

    auth_code = await db.scalar(
        select(OAuthAuthorizationCode).where(
            OAuthAuthorizationCode.code == code,
            OAuthAuthorizationCode.client_id == client.client_id,
            not OAuthAuthorizationCode.used,
        )
    )
    if auth_code is None:
        raise HTTPException(400, "Invalid or expired authorization code")

    now = datetime.now(UTC)
    exp = auth_code.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    if now > exp:
        raise HTTPException(400, "Authorization code has expired")

    if auth_code.redirect_uri != redirect_uri:
        raise HTTPException(400, "redirect_uri mismatch")

    # PKCE verification
    if client.require_pkce:
        if not code_verifier or not auth_code.code_challenge:
            raise HTTPException(400, "PKCE code_verifier required")
        if not _pkce_verify(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method or "S256"):
            raise HTTPException(400, "PKCE verification failed")

    # Mark code as used (single-use)
    await db.execute(
        update(OAuthAuthorizationCode)
        .where(OAuthAuthorizationCode.id == auth_code.id)
        .values(used=True)
    )

    user = await db.get(User, auth_code.user_id)
    if user is None or not user.is_active:
        raise HTTPException(400, "User not found or inactive")

    access_token = await strategy.write_token(user)
    refresh = secrets.token_urlsafe(48) if "offline_access" in auth_code.scope else None

    token_row = OAuthToken(
        id=uuid.uuid4(),
        access_token=access_token,
        refresh_token=refresh,
        client_id=client.client_id,
        user_id=user.id,
        scope=auth_code.scope,
        access_token_expires_at=now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS),
        refresh_token_expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_LIFETIME_SECONDS) if refresh else None,
        token_family_id=uuid.uuid4() if refresh else None,  # new chain = new family
    )
    db.add(token_row)
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        "scope": auth_code.scope,
    }
    if refresh:
        response["refresh_token"] = refresh

    # OIDC Core §3.1.3.3: include id_token when openid scope was requested
    if "openid" in (auth_code.scope or ""):
        response["id_token"] = _make_id_token(
            user=user,
            client_id=client.client_id,
            nonce=auth_code.nonce,
            auth_time=int(now.timestamp()),
        )

    return response


def _make_id_token(user, client_id: str, nonce: str | None, auth_time: int) -> str:
    """
    Issue an OIDC ID token (RFC 7519 / OIDC Core §2).
    The ID token is a JWT containing identity claims and is verified by the client
    using the issuer's JWKS — not the access token.
    """
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from app.tokens.keys import key_manager

    key = key_manager.get_current_key()
    private_key = load_pem_private_key(key["private_pem"], password=None)
    now = datetime.now(UTC)
    payload: dict = {
        "iss": settings.BASE_URL,                    # OIDC Core §2: required
        "sub": str(user.id),                         # OIDC Core §2: required
        "aud": client_id,                            # OIDC Core §2: required (client_id for id_token)
        "iat": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS),
        "auth_time": auth_time,                      # OIDC Core §2: when authentication occurred
        "email": user.email,
        "email_verified": user.is_verified,
        "tenant_id": str(user.tenant_id),
    }
    if nonce:
        payload["nonce"] = nonce   # OIDC Core §3.1.2.1: echo nonce to prevent replay
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": key["kid"]})


async def _handle_refresh_grant(
    refresh_token: str | None,
    client: OAuthClient,
    db: AsyncSession,
    strategy: TenantAwareJWTStrategy,
) -> dict:
    if not refresh_token:
        raise HTTPException(400, "refresh_token is required")

    # Search including revoked rows — needed to detect theft (rotated-out token replay).
    token_row = await db.scalar(
        select(OAuthToken).where(
            OAuthToken.refresh_token == refresh_token,
            OAuthToken.client_id == client.client_id,
        )
    )
    if token_row is None:
        raise HTTPException(400, "Invalid refresh token")

    if token_row.revoked:
        # A rotated-out token was presented. This is the classic refresh-token theft signal.
        # Revoke the entire token family so any legitimate active session is also invalidated
        # and the real user is forced to re-authenticate.
        if token_row.token_family_id:
            await db.execute(
                update(OAuthToken)
                .where(
                    OAuthToken.token_family_id == token_row.token_family_id,
                    OAuthToken.client_id == client.client_id,
                )
                .values(revoked=True)
            )
            await db.commit()
            logger.warning(
                "refresh_token_theft_detected",
                family_id=str(token_row.token_family_id),
                client_id=client.client_id,
                user_id=str(token_row.user_id),
            )
        raise HTTPException(401, "Refresh token already used — possible token theft detected. Please sign in again.")

    now = datetime.now(UTC)
    rt_exp = token_row.refresh_token_expires_at
    if rt_exp:
        if rt_exp.tzinfo is None:
            rt_exp = rt_exp.replace(tzinfo=UTC)
        if now > rt_exp:
            raise HTTPException(400, "Refresh token has expired")

    user = await db.get(User, token_row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(400, "User not found or inactive")

    new_access = await strategy.write_token(user)
    new_refresh = secrets.token_urlsafe(48)

    # Rotate: revoke old token, issue new one — carry the family_id forward so
    # any future replay of this (now-rotated) token triggers family revocation.
    await db.execute(
        update(OAuthToken).where(OAuthToken.id == token_row.id).values(revoked=True)
    )
    new_row = OAuthToken(
        id=uuid.uuid4(),
        access_token=new_access,
        refresh_token=new_refresh,
        client_id=client.client_id,
        user_id=user.id,
        scope=token_row.scope,
        access_token_expires_at=now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS),
        refresh_token_expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_LIFETIME_SECONDS),
        token_family_id=token_row.token_family_id,  # same family chain
    )
    db.add(new_row)
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id, subject_id=user.id)
    await db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_LIFETIME_SECONDS,
    }


async def _handle_client_credentials(
    scope: str | None,
    client: OAuthClient,
    db: AsyncSession,
    strategy: TenantAwareJWTStrategy,
) -> dict:
    if not client.check_grant_type("client_credentials"):
        raise HTTPException(400, "Client not authorized for client_credentials")

    # Machine tokens don't have a user — issue a service token
    # Represented as a synthetic user-less JWT with sub=client_id
    now = datetime.now(UTC)
    import uuid as _uuid

    import jwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from app.tokens.keys import key_manager

    key = key_manager.get_current_key()
    private_key = load_pem_private_key(key["private_pem"], password=None)
    jti = str(_uuid.uuid4())
    payload = {
        "iss": settings.BASE_URL,
        "sub": f"client:{client.client_id}",
        "aud": ["open-auth:auth"],
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS),
        "jti": jti,             # machine tokens are revokable too
        "client_id": client.client_id,
        "auth_stage": "complete",
        "scope": scope or "openid",
    }
    access_token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": key["kid"]})

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        "scope": scope or "openid",
    }


# ---------------------------------------------------------------------------
# Introspect — RFC 7662
# ---------------------------------------------------------------------------

@router.post("/introspect")
async def introspect(
    token: str = Form(...),
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    """Token introspection — returns active=true/false with claims."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from app.tokens.keys import key_manager

    try:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        pem = key_manager.get_public_pem_by_kid(kid) if kid else None
        if pem is None:
            return {"active": False}
        pub = load_pem_public_key(pem)
        payload = pyjwt.decode(token, pub, algorithms=["RS256"], audience=["open-auth:auth"])
        return {
            "active": True,
            "sub": payload.get("sub"),
            "tenant_id": payload.get("tenant_id"),
            "scope": payload.get("scope", "openid"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "auth_stage": payload.get("auth_stage"),
        }
    except Exception:
        return {"active": False}


# ---------------------------------------------------------------------------
# Revoke — RFC 7009
# ---------------------------------------------------------------------------

@router.post("/revoke")
async def revoke(
    token: str = Form(...),
    db: AsyncSession = Depends(get_session),
):
    """Revoke an access or refresh token (RFC 7009).

    For access tokens (JWTs): adds the jti to the in-memory + PG blacklist so
    read_token() rejects it immediately — even before the token would naturally expire.
    For refresh tokens: marks the OAuthToken row as revoked.
    RFC 7009 requires HTTP 200 even when the token is unknown.
    """
    import jwt as pyjwt

    from app.tokens.keys import key_manager
    from app.tokens.revocation import revoke_token as _revoke_jti

    # 1. If this looks like a JWT, extract its jti and blacklist it immediately
    try:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        pem = key_manager.get_public_pem_by_kid(kid) if kid else None
        if pem:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            pub = load_pem_public_key(pem)
            payload = pyjwt.decode(
                token, pub, algorithms=["RS256"], audience=["open-auth:auth"],
                options={"verify_exp": False},  # revoke even if already expired
            )
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                exp_dt = datetime.fromtimestamp(exp, tz=UTC)
                await _revoke_jti(jti=jti, expires_at=exp_dt, db=db)
    except Exception:
        pass  # Not a JWT or already expired — fall through to DB lookup

    # 2. Also mark the OAuthToken row as revoked (covers refresh tokens)
    row = await db.scalar(
        select(OAuthToken).where(
            (OAuthToken.refresh_token == token) | (OAuthToken.access_token == token)
        )
    )
    if row and not row.revoked:
        await db.execute(
            update(OAuthToken).where(OAuthToken.id == row.id).values(revoked=True)
        )
        await emit(db, AuthEvent.TOKEN_REVOKED, subject_id=row.user_id)

    await db.commit()
    # RFC 7009: always return 200, even if token not found
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Userinfo — OIDC §5.3
# ---------------------------------------------------------------------------

@router.get("/userinfo")
@router.post("/userinfo")
async def userinfo(
    user: User = Depends(current_active_user),
):
    """Return standard OIDC userinfo claims for the authenticated user."""
    return {
        "sub": str(user.id),
        "email": user.email,
        "email_verified": user.is_verified,
        "tenant_id": str(user.tenant_id),
    }


# ---------------------------------------------------------------------------
# OAuth consent — user explicitly approves scope access for third-party clients
# ---------------------------------------------------------------------------

class ConsentRequest(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str = "openid"
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = "S256"
    nonce: str | None = None


@router.post("/consent")
async def consent(
    body: ConsentRequest,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """User grants consent for a third-party client. Returns redirect URL with auth code."""
    client = await _get_client(body.client_id, db)

    if not client.check_redirect_uri(body.redirect_uri):
        raise HTTPException(400, "Invalid redirect_uri")
    if not client.check_scope(body.scope):
        raise HTTPException(400, f"Requested scope(s) not allowed: {body.scope}")
    if client.require_pkce and not body.code_challenge:
        raise HTTPException(400, "PKCE code_challenge is required for this client")

    code = secrets.token_urlsafe(32)
    auth_code = OAuthAuthorizationCode(
        id=uuid.uuid4(),
        code=code,
        client_id=body.client_id,
        user_id=user.id,
        redirect_uri=body.redirect_uri,
        scope=body.scope,
        code_challenge=body.code_challenge,
        code_challenge_method=body.code_challenge_method,
        nonce=body.nonce,
        expires_at=datetime.now(UTC) + timedelta(seconds=_AUTH_CODE_TTL),
    )
    db.add(auth_code)
    await db.commit()

    redirect_url = f"{body.redirect_uri}?code={code}"
    if body.state:
        redirect_url += f"&state={body.state}"
    return JSONResponse({"redirect_url": redirect_url})

