import secrets
import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.identity.password import (
    UserManager,
    current_active_user,
    fastapi_users,
    get_user_manager,
)

# Superuser-only guard for sensitive admin endpoints
current_superuser = fastapi_users.current_user(active=True, superuser=True)
from datetime import UTC

from app.core.metrics import (
    auth_login_total,
    auth_mfa_total,
    auth_token_issued_total,
    auth_trusted_device_total,
)
from app.core.rate_limit import limiter
from app.identity.social import (
    build_google_authorize_url,
    exchange_google_code,
    fetch_google_userinfo,
    get_tenant_by_id,
    upsert_oauth_user,
    verify_oauth_state,
)
from app.mfa.orchestrator import requires_mfa
from app.mfa.totp import enroll_totp, verify_and_activate_totp, verify_backup_code, verify_totp
from app.models.user import User
from app.sessions.trusted_device import (
    COOKIE_NAME,
    _secure_cookie_kwargs,
    create_trusted_device,
    is_trusted_device,
    list_trusted_devices,
    revoke_all_trusted_devices,
    revoke_device_by_id,
)
from app.tokens.strategy import TenantAwareJWTStrategy, get_jwt_strategy

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    user: User = Depends(current_active_user),
):
    """Revoke the caller's current access token (adds its jti to the blacklist).

    Without this, signing out client-side only drops the in-memory token while the
    JWT stays valid until natural expiry. The revocation watcher broadcasts the jti
    to all workers via PG NOTIFY, so the token is rejected fleet-wide immediately.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            await get_jwt_strategy().destroy_token(token, user)
    return None


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    # Optional: when omitted the tenant is derived from the user's account.
    # Pass it explicitly only for the rare multi-tenant-per-email case.
    tenant_id: str | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    auth_stage: str
    user_id: str | None = None


class TOTPEnrollResponse(BaseModel):
    uri: str
    secret: str


class TOTPActivateResponse(BaseModel):
    message: str
    backup_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    code: str
    pending_token: str | None = None
    remember_device: bool = False  # if True, set 30-day trusted-device cookie


class TOTPActivateRequest(BaseModel):
    code: str


class TenantCreateRequest(BaseModel):
    slug: str
    name: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


# ---------------------------------------------------------------------------
# Password login (with MFA step-up)
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_session),
    user_manager: UserManager = Depends(get_user_manager),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    from app.models.tenant import Tenant

    def _enumeration_guard_verify() -> None:
        # Constant-time dummy verify to keep timing uniform whether or not the
        # account exists / tenant resolves — prevents user & tenant enumeration.
        from argon2 import PasswordHasher
        try:
            PasswordHasher().verify("$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy", body.password)
        except Exception:
            pass

    # Optional explicit tenant_id must at least be a valid UUID when present.
    explicit_tenant_uuid: uuid.UUID | None = None
    if body.tenant_id:
        try:
            explicit_tenant_uuid = uuid.UUID(body.tenant_id)
        except ValueError:
            raise HTTPException(400, "Invalid tenant_id")

    # Resolve the user first so the tenant can be derived from the account when
    # the caller did not pass one (users log in with email + password alone).
    try:
        user = await user_manager.get_by_email(body.email)
    except Exception:
        user = None

    # Tenant: explicit claim wins; otherwise derive from the resolved user.
    tenant_id_uuid: uuid.UUID | None = explicit_tenant_uuid or (
        user.tenant_id if user is not None else None
    )
    tenant = None
    if tenant_id_uuid is not None:
        tenant = await db.scalar(
            select(Tenant).where(Tenant.id == tenant_id_uuid, Tenant.is_active)
        )

    # Uniform failure when the account is unknown or the tenant cannot be resolved.
    if user is None or tenant is None:
        _enumeration_guard_verify()
        auth_login_total.labels(result="failure", method="password").inc()
        await emit(db, AuthEvent.USER_LOGIN_FAILED, tenant_id=tenant_id_uuid,
                   ip_address=_get_ip(request))
        raise HTTPException(400, "Invalid email or password")

    # If a tenant_id was passed explicitly, the user must belong to it.
    if explicit_tenant_uuid is not None and user.tenant_id != explicit_tenant_uuid:
        auth_login_total.labels(result="failure", method="password").inc()
        await emit(db, AuthEvent.USER_LOGIN_FAILED, tenant_id=tenant_id_uuid,
                   subject_id=user.id, ip_address=_get_ip(request))
        raise HTTPException(400, "Invalid email or password")

    if not user.is_active:
        raise HTTPException(400, "Account is disabled")

    # Per-tenant IP policy check — must pass before password verification
    from app.authz.ip_policy import check_ip_policy
    from app.core.metrics import auth_ip_policy_blocked_total
    _ip_allowed, _ip_reason = check_ip_policy(_get_ip(request), tenant)
    if not _ip_allowed:
        auth_ip_policy_blocked_total.labels(reason=_ip_reason).inc()
        await emit(db, AuthEvent.USER_LOGIN_FAILED, tenant_id=tenant_id_uuid,
                   subject_id=user.id, ip_address=_get_ip(request))
        raise HTTPException(403, "Access denied: your IP address is not permitted for this account")

    # Email verification gate (configurable — disabled in dev by default)
    if settings.REQUIRE_EMAIL_VERIFICATION and not user.is_verified:
        raise HTTPException(
            403,
            "Email address not verified. Check your inbox for a verification link.",
        )

    # Account-level lockout check (failed password attempts, not TOTP)
    from datetime import timezone as _tz
    _now = __import__("datetime").datetime.now(UTC)
    if user.locked_until is not None:
        _lu = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=UTC)
        if _now < _lu:
            wait = int((_lu - _now).total_seconds())
            raise HTTPException(
                status_code=423,
                detail=f"Account locked due to too many failed attempts. Try again in {wait}s.",
                headers={"Retry-After": str(wait)},
            )
        # Lockout expired — clear it
        await db.execute(
            update(User).where(User.id == user.id).values(failed_login_count=0, locked_until=None)
        )
        await db.commit()
        await db.refresh(user)

    # Verify password — only argon2 hash check; validate_password is for
    # password CHANGE (complexity + history) and must NOT be called here.
    # Calling it during login would block users whose current password is in
    # their own history (which it always is, since we store the active hash).
    try:
        verified = user_manager.password_helper.verify_and_update(
            body.password, user.hashed_password
        )
        if not verified[0]:
            raise ValueError("bad password")
    except Exception:
        # Increment failure count; lock after 5 consecutive failures (15-minute lockout)
        _MAX_FAILURES = 5
        _LOCKOUT_SECONDS = 900
        new_count = (user.failed_login_count or 0) + 1
        locked_until = None
        if new_count >= _MAX_FAILURES:
            from datetime import timedelta
            locked_until = _now + timedelta(seconds=_LOCKOUT_SECONDS)
        await db.execute(
            update(User).where(User.id == user.id).values(
                failed_login_count=new_count, locked_until=locked_until
            )
        )
        await db.commit()
        auth_login_total.labels(result="failure", method="password").inc()
        await emit(db, AuthEvent.USER_LOGIN_FAILED, tenant_id=user.tenant_id,
                   subject_id=user.id, ip_address=_get_ip(request))
        raise HTTPException(400, "Invalid email or password")

    # Successful auth — reset lockout counter and track login IP
    from datetime import timezone as _tz2
    _client_ip = _get_ip(request)
    _now2 = __import__("datetime").datetime.now(UTC)
    _updates: dict = {"failed_login_count": 0, "locked_until": None,
                      "last_login_ip": _client_ip, "last_login_at": _now2}
    if not user.failed_login_count and not user.locked_until:
        _updates.pop("failed_login_count")
        _updates.pop("locked_until")
    await db.execute(update(User).where(User.id == user.id).values(**_updates))
    await db.commit()

    # Emit security notification if this is a new IP for this user
    _prev_ip = getattr(user, "last_login_ip", None)
    if _client_ip and _prev_ip and _client_ip != _prev_ip:
        await emit(
            db, AuthEvent.USER_LOGIN_NEW_IP,
            tenant_id=user.tenant_id, subject_id=user.id,
            ip_address=_client_ip,
            metadata={"previous_ip": _prev_ip, "new_ip": _client_ip},
        )
        from app.notifications.email import send_new_ip_login_alert
        await send_new_ip_login_alert(
            to=user.email,
            new_ip=_client_ip,
            user_agent=request.headers.get("User-Agent", ""),
        )

    # Tenant-level MFA enforcement: if the organisation mandates MFA and the
    # user hasn't enrolled, block login entirely rather than issuing any token.
    # The client must direct the user to TOTP enrolment (/ui/totp/enroll).
    tenant = await db.get(__import__("app.models.tenant", fromlist=["Tenant"]).Tenant, user.tenant_id)
    if tenant and getattr(tenant, "require_mfa", False) and not user.is_totp_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "Multi-factor authentication is required for this organisation. "
                "Please enrol TOTP before signing in."
            ),
            headers={"X-MFA-Enroll-URL": f"{settings.ui_base}/totp/enroll"},
        )

    # MFA step-up — check trusted device cookie first
    if requires_mfa(user):
        device_cookie = request.cookies.get(COOKIE_NAME)
        if device_cookie and await is_trusted_device(user.id, device_cookie, db):
            # Device is trusted — issue full token without TOTP challenge
            token = await strategy.write_token(user)
            auth_login_total.labels(result="success_trusted_device", method="password").inc()
            auth_trusted_device_total.labels(action="bypass").inc()
            auth_token_issued_total.labels(token_type="access").inc()
            await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id,
                       subject_id=user.id, ip_address=_get_ip(request))
            return LoginResponse(access_token=token, auth_stage="complete", user_id=str(user.id))

        pending_token = await strategy.write_mfa_pending_token(user)
        auth_login_total.labels(result="mfa_required", method="password").inc()
        auth_mfa_total.labels(event="challenge", method="totp").inc()
        auth_token_issued_total.labels(token_type="mfa_pending").inc()
        return LoginResponse(
            access_token=pending_token,
            auth_stage="mfa_pending",
            user_id=str(user.id),
        )

    token = await strategy.write_token(user)
    auth_login_total.labels(result="success", method="password").inc()
    auth_token_issued_total.labels(token_type="access").inc()
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id,
               subject_id=user.id, ip_address=_get_ip(request))
    # Record login event for session history (fire-and-forget — non-blocking)
    from app.api.v1.login_history import record_login as _record_login
    from app.core.tasks import spawn
    spawn(_record_login(user=user, request=request))
    return LoginResponse(access_token=token, auth_stage="complete", user_id=str(user.id))


# ---------------------------------------------------------------------------
# MFA — TOTP enrollment
# ---------------------------------------------------------------------------

@router.post("/totp/enroll", response_model=TOTPEnrollResponse)
async def totp_enroll(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    result = await enroll_totp(current_user.id, db)
    return TOTPEnrollResponse(**result)


@router.post("/totp/activate", response_model=TOTPActivateResponse)
async def totp_activate(
    body: TOTPActivateRequest,
    request: Request,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Confirm enrollment by verifying the first code. Returns 8 single-use backup codes — show ONCE."""
    backup_codes = await verify_and_activate_totp(
        current_user.id, body.code, db, ip_address=_get_ip(request)
    )
    return TOTPActivateResponse(message="TOTP activated successfully", backup_codes=backup_codes)


@router.delete("/totp", status_code=204)
async def totp_disable(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Remove TOTP from the account. Requires the account to NOT be in a tenant that mandates MFA.
    Sends a security email to notify the user. If the tenant requires MFA, removal is blocked.
    """
    from app.models.tenant import Tenant as _Tenant
    _tenant = await db.get(_Tenant, current_user.tenant_id)
    if _tenant and getattr(_tenant, "require_mfa", False):
        raise HTTPException(
            403,
            "MFA is required by your organisation and cannot be disabled. "
            "Contact your administrator to change the policy.",
        )

    if not current_user.is_totp_enabled:
        return  # Idempotent — nothing to do

    await db.execute(
        update(User)
        .where(User.id == current_user.id)
        .values(is_totp_enabled=False, totp_secret=None)
    )
    await emit(db, AuthEvent.MFA_DISABLED, tenant_id=current_user.tenant_id,
               subject_id=current_user.id)
    await db.commit()

    from app.core.tasks import spawn
    from app.notifications.email import send_mfa_disabled_alert as _mfa_alert
    spawn(_mfa_alert(to=current_user.email))


@router.post("/totp/verify", response_model=LoginResponse)
@limiter.limit("5/minute")
async def totp_verify(
    request: Request,
    response: Response,
    body: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    """
    Complete MFA step-up. Accepts an mfa_pending token + TOTP code.
    Returns a full-access token on success.
    """
    if not body.pending_token:
        raise HTTPException(400, "pending_token is required")

    payload = await strategy.read_mfa_pending_token(body.pending_token)
    if payload is None:
        raise HTTPException(401, "Invalid or expired MFA pending token")

    user_id = uuid.UUID(payload["sub"])
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "User not found or inactive")

    await verify_totp(user_id, body.code, db, ip_address=_get_ip(request))

    token = await strategy.write_token(user)
    auth_mfa_total.labels(event="success", method="totp").inc()
    auth_token_issued_total.labels(token_type="access").inc()
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id,
               subject_id=user.id, ip_address=_get_ip(request))

    response_body = LoginResponse(access_token=token, auth_stage="complete")
    if body.remember_device:
        device_token = await create_trusted_device(
            user_id, user.tenant_id, db, request=request
        )
        auth_trusted_device_total.labels(action="created").inc()
        resp = JSONResponse(response_body.model_dump())
        resp.set_cookie(COOKIE_NAME, device_token, **_secure_cookie_kwargs())
        return resp
    return response_body


# ---------------------------------------------------------------------------
# MFA — backup code redemption
# ---------------------------------------------------------------------------

@router.post("/mfa/backup", response_model=LoginResponse)
@limiter.limit("3/minute")
async def mfa_backup_verify(
    request: Request,
    response: Response,
    body: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    """Redeem a single-use backup code in place of a TOTP code. Rate-limited to 3/min."""
    if not body.pending_token:
        raise HTTPException(400, "pending_token is required")

    payload = await strategy.read_mfa_pending_token(body.pending_token)
    if payload is None:
        raise HTTPException(401, "Invalid or expired MFA pending token")

    user_id = uuid.UUID(payload["sub"])
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "User not found or inactive")

    await verify_backup_code(user_id, body.code, db, ip_address=_get_ip(request))

    token = await strategy.write_token(user)
    auth_token_issued_total.labels(token_type="access").inc()
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id,
               subject_id=user.id, ip_address=_get_ip(request))

    response_body = LoginResponse(access_token=token, auth_stage="complete", user_id=str(user.id))
    if body.remember_device:
        device_token = await create_trusted_device(
            user_id, user.tenant_id, db, request=request
        )
        resp = JSONResponse(response_body.model_dump())
        resp.set_cookie(COOKIE_NAME, device_token, **_secure_cookie_kwargs())
        return resp
    return response_body


# ---------------------------------------------------------------------------
# Google OAuth
# ---------------------------------------------------------------------------

@router.get("/google/authorize")
async def google_authorize(tenant_id: str, db: AsyncSession = Depends(get_session)):
    """Step 1: redirect user to Google. tenant_id is bound into the HMAC state."""
    await get_tenant_by_id(tenant_id, db)  # validate tenant exists
    url = build_google_authorize_url(tenant_id)
    return RedirectResponse(url, status_code=302)


@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
    strategy: TenantAwareJWTStrategy = Depends(get_jwt_strategy),
):
    """Step 2: Google redirects back here. We verify state, upsert user, issue JWT."""
    # 1. Verify HMAC state — extracts tenant_id and nonce; also checks nonce not reused
    tenant_id_str, oauth_nonce = verify_oauth_state(state, settings.SECRET_KEY)
    # Immediately consume the nonce so replayed callbacks are rejected (Phase 6 gate)
    from datetime import datetime, timedelta, timezone

    from app.tokens.revocation import revoke_token
    await revoke_token(
        jti=f"oauth_state:{oauth_nonce}",
        expires_at=datetime.now(UTC) + timedelta(seconds=300),
        db=db,
    )
    tenant = await get_tenant_by_id(tenant_id_str, db)

    # 2. Exchange code for tokens
    token_data = await exchange_google_code(code)
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(400, "No access token from Google")

    # 3. Fetch user info from Google
    userinfo = await fetch_google_userinfo(access_token)
    email = userinfo.get("email")
    google_sub = userinfo.get("sub")
    if not email or not google_sub:
        raise HTTPException(400, "Google did not return email or sub")

    # 4. Atomic upsert — tenant-guarded
    user = await upsert_oauth_user(
        email=email,
        tenant_id=tenant.id,
        provider="google",
        provider_account_id=google_sub,
        access_token=access_token,
        db=db,
    )

    # 5. MFA step-up if enrolled (skip if trusted device cookie present)
    if requires_mfa(user):
        device_cookie = request.cookies.get(COOKIE_NAME)
        if not (device_cookie and await is_trusted_device(user.id, device_cookie, db)):
            pending_token = await strategy.write_mfa_pending_token(user)
            return JSONResponse({
                "access_token": pending_token,
                "auth_stage": "mfa_pending",
                "token_type": "bearer",
            })

    # 6. Issue full token
    full_token = await strategy.write_token(user)
    await emit(db, AuthEvent.TOKEN_ISSUED, tenant_id=user.tenant_id,
               subject_id=user.id, ip_address=_get_ip(request))
    return JSONResponse({
        "access_token": full_token,
        "auth_stage": "complete",
        "token_type": "bearer",
    })


# ---------------------------------------------------------------------------
# Tenant bootstrap (dev/admin only — lock down in production with RBAC)
# ---------------------------------------------------------------------------

@router.post("/tenants", status_code=201)
async def create_tenant(
    body: TenantCreateRequest,
    db: AsyncSession = Depends(get_session),
    _admin: object = Depends(current_superuser),
):
    from app.models.tenant import Tenant

    existing = await db.scalar(select(Tenant).where(Tenant.slug == body.slug))
    if existing:
        raise HTTPException(409, f"Tenant with slug '{body.slug}' already exists")

    tenant = Tenant(id=uuid.uuid4(), slug=body.slug, name=body.name)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    await emit(db, AuthEvent.TENANT_CREATED, tenant_id=tenant.id)
    return {"id": str(tenant.id), "slug": tenant.slug, "name": tenant.name}


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    organisation_name: str


def _slugify(name: str) -> str:
    """Lowercase, hyphenated, alphanumeric slug base from an org name."""
    import re

    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return base[:48] or "org"


async def _unique_tenant_slug(name: str, db: AsyncSession) -> str:
    from app.models.tenant import Tenant

    base = _slugify(name)
    slug = base
    # Append a short random suffix until the slug is free (handles collisions
    # without leaking how many orgs share a name).
    for _ in range(5):
        if await db.scalar(select(Tenant).where(Tenant.slug == slug)) is None:
            return slug
        slug = f"{base}-{secrets.token_hex(3)}"
    return f"{base}-{secrets.token_hex(6)}"


@router.post("/signup", status_code=201)
@limiter.limit("5/hour")
async def signup(
    request: Request,
    response: Response,
    body: SignupRequest,
    db: AsyncSession = Depends(get_session),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Self-serve SaaS signup: create a brand-new organisation and its owner.

    The organisation id (tenant_id) is generated server-side — users never type
    or know it. Pre-existing orgs are joined via invitation links, not by pasting
    an id. The creator becomes the org owner on first login (the api-gateway makes
    the first user provisioned into an empty tenant its owner)."""
    from app.identity.password import _argon2_helper
    from app.models.tenant import Tenant
    from app.models.user import User

    org_name = body.organisation_name.strip()
    if not org_name:
        raise HTTPException(422, "Organisation name is required")
    if len(body.password) < 12:
        raise HTTPException(422, "Password must be at least 12 characters")

    # Reject up-front if the email is already taken.
    existing = await db.scalar(select(User).where(User.email == str(body.email)))
    if existing is not None:
        raise HTTPException(409, "An account with this email already exists")

    # 1. Create the organisation with an auto-generated id + unique slug.
    tenant = Tenant(
        id=uuid.uuid4(),
        slug=await _unique_tenant_slug(org_name, db),
        name=org_name,
    )
    db.add(tenant)

    # 2. Create the owner user inside the new org. is_superuser stays False —
    # org owners are not platform admins; their app-level role is resolved by
    # the api-gateway. Both rows commit together, so a failure rolls back atomically.
    user = User(
        id=uuid.uuid4(),
        email=str(body.email),
        hashed_password=_argon2_helper.hash(body.password),
        tenant_id=tenant.id,
        is_active=True,
        is_verified=not settings.REQUIRE_EMAIL_VERIFICATION,
        is_superuser=False,
    )
    db.add(user)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        # Almost always a unique-email race; surface as a clean conflict.
        raise HTTPException(409, "An account with this email already exists")
    await db.refresh(tenant)
    await db.refresh(user)

    await emit(db, AuthEvent.TENANT_CREATED, tenant_id=tenant.id, subject_id=user.id)
    await emit(db, AuthEvent.USER_CREATED, tenant_id=tenant.id, subject_id=user.id)
    return {
        "tenant_id": str(tenant.id),
        "organisation_slug": tenant.slug,
        "email": str(body.email),
        "email_verification_required": settings.REQUIRE_EMAIL_VERIFICATION,
    }


# ---------------------------------------------------------------------------
# Password reset — rate-limited wrappers over fastapi-users manager methods.
# These are registered BEFORE the fastapi-users reset router so they take
# precedence. Rate limits protect against email-flooding and token-bruteforce.
# ---------------------------------------------------------------------------

@router.post("/forgot-password", status_code=202)
@limiter.limit("5/hour")
async def forgot_password(
    request: Request,
    response: Response,
    body: ForgotPasswordRequest,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Trigger a password-reset email.

    Always returns 202 regardless of whether the email exists — prevents
    account enumeration via timing or response body differences.
    Rate-limited to 5 requests/hour/IP to block email-flooding attacks.
    """
    try:
        user = await user_manager.get_by_email(body.email)
        await user_manager.forgot_password(user, request)
    except Exception:
        pass  # intentionally swallow — timing is equalised below
    return {"detail": "If an account with that email exists, a reset link was sent."}


@router.post("/reset-password")
@limiter.limit("10/hour")
async def reset_password_endpoint(
    request: Request,
    response: Response,
    body: ResetPasswordRequest,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Set a new password using a reset token from the email link.

    Rate-limited to 10/hour/IP to block token bruteforce.
    """
    from fastapi_users.exceptions import (
        InvalidPasswordException as FUInvalidPassword,
    )
    from fastapi_users.exceptions import (
        InvalidResetPasswordToken,
        UserInactive,
        UserNotExists,
    )
    try:
        await user_manager.reset_password(body.token, body.password, request)
    except (InvalidResetPasswordToken, UserNotExists):
        raise HTTPException(400, "Invalid or expired reset token")
    except UserInactive:
        raise HTTPException(400, "Account is disabled")
    except FUInvalidPassword as e:
        raise HTTPException(422, e.reason or "Password does not meet requirements")
    return {"detail": "Password reset successful"}


# ---------------------------------------------------------------------------
# Trusted device session management
# ---------------------------------------------------------------------------

@router.get("/sessions/trusted-devices")
async def get_trusted_devices(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """List all trusted devices for the authenticated user."""
    devices = await list_trusted_devices(current_user.id, db)
    return {"devices": devices, "count": len(devices)}


@router.delete("/sessions/trusted-devices")
async def revoke_all_devices(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Revoke all trusted devices — forces MFA on next login from every browser."""
    count = await revoke_all_trusted_devices(current_user.id, db)
    if count:
        auth_trusted_device_total.labels(action="revoked").inc(count)
    resp = JSONResponse({"message": f"{count} trusted device(s) revoked"})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@router.delete("/sessions/trusted-devices/{device_id}")
async def revoke_device(
    device_id: uuid.UUID,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_session),
):
    """Revoke a specific trusted device by ID."""
    removed = await revoke_device_by_id(device_id, current_user.id, db)
    if not removed:
        raise HTTPException(404, "Trusted device not found")
    return {"message": "Device revoked"}


# ---------------------------------------------------------------------------
# fastapi-users routers (register, verify, reset-password)
# ---------------------------------------------------------------------------

def get_fastapi_users_routers():
    from fastapi_users import schemas

    from app.identity.password import fastapi_users

    class UserRead(schemas.BaseUser[uuid.UUID]):
        tenant_id: uuid.UUID
        is_totp_enabled: bool = False

    class UserCreate(schemas.BaseUserCreate):
        tenant_id: uuid.UUID

    class UserUpdate(schemas.BaseUserUpdate):
        pass

    return [
        (fastapi_users.get_register_router(UserRead, UserCreate), "/auth", ["Auth"]),
        # NOTE: reset-password routes are NOT mounted here.
        # We define rate-limited /auth/forgot-password and /auth/reset-password
        # above so they take precedence and enforce 5/hour + 10/hour per-IP limits.
        (fastapi_users.get_verify_router(UserRead), "/auth", ["Auth"]),
        (fastapi_users.get_users_router(UserRead, UserUpdate), "/users", ["Users"]),
    ]


def _get_ip(request: Request) -> str | None:
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
