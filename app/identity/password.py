from __future__ import annotations

import re
import uuid
from typing import Optional

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, BearerTransport
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.exceptions import InvalidPasswordException
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.events import AuthEvent, emit
from app.core.metrics import auth_password_reuse_blocked_total
from app.models.user import OAuthAccount, User
from app.tokens.strategy import get_jwt_strategy

logger = structlog.get_logger(__name__)

_PASSWORD_MIN_LENGTH = 8
_UPPERCASE_RE = re.compile(r"[A-Z]")
_LOWERCASE_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


async def _check_hibp(password: str) -> None:
    """K-anonymity HIBP lookup. Raises InvalidPasswordException if the password is in a breach.

    Fail-open: network errors and timeouts are logged and ignored so users are
    never blocked by HIBP availability. Only the first 5 SHA1 hex chars leave
    this process — the full hash and plaintext are never transmitted.
    """
    import hashlib

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        from app.shared.http_clients import get_outbound_client
        client = get_outbound_client("identity", timeout=2.0)
        resp = await client.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
        if resp.status_code != 200:
            logger.warning("hibp_api_non_200", status=resp.status_code)
            return
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1].strip())
                if count > 0:
                    raise InvalidPasswordException(
                        reason=(
                            f"This password has appeared in {count:,} data breaches. "
                            "Choose a different password."
                        )
                    )
    except InvalidPasswordException:
        raise
    except Exception as exc:
        logger.warning("hibp_check_failed", error=str(exc))


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.SECRET_KEY
    verification_token_secret = settings.SECRET_KEY

    async def validate_password(self, password: str, user=None) -> None:
        """Enforce complexity + password-history check (NIST SP 800-63B)."""
        if len(password) < _PASSWORD_MIN_LENGTH:
            raise InvalidPasswordException(
                reason=f"Password must be at least {_PASSWORD_MIN_LENGTH} characters."
            )
        if not _UPPERCASE_RE.search(password):
            raise InvalidPasswordException(reason="Password must contain an uppercase letter.")
        if not _LOWERCASE_RE.search(password):
            raise InvalidPasswordException(reason="Password must contain a lowercase letter.")
        if not _DIGIT_RE.search(password):
            raise InvalidPasswordException(reason="Password must contain a number.")
        if not _SPECIAL_RE.search(password):
            raise InvalidPasswordException(reason="Password must contain a special character.")

        # HIBP breach-list check (NIST SP 800-63B §5.1.1.2).
        # Uses k-anonymity: only the first 5 hex chars of SHA1 are sent to HIBP.
        # Fail-open: if HIBP is unreachable we log a warning and continue.
        await _check_hibp(password)

        # Password-history check — only when changing (user exists with a history).
        depth = settings.PASSWORD_HISTORY_DEPTH
        if depth > 0 and user is not None:
            history = list(getattr(user, "password_history", None) or [])
            # Also include the current active hash so the user can't reuse their own password.
            if user.hashed_password:
                history = history + [user.hashed_password]
            if history:
                from argon2 import PasswordHasher
                from argon2.exceptions import VerificationError, VerifyMismatchError
                ph = PasswordHasher()
                for old_hash in history[-depth:]:
                    try:
                        if ph.verify(old_hash, password):
                            auth_password_reuse_blocked_total.inc()
                            raise InvalidPasswordException(
                                reason=f"Cannot reuse one of your last {depth} passwords."
                            )
                    except (VerifyMismatchError, VerificationError):
                        pass  # different password — expected path

    async def on_after_register(self, user: User, request: Request | None = None) -> None:
        db = self.user_db.session
        await emit(
            db,
            AuthEvent.USER_CREATED,
            tenant_id=user.tenant_id,
            subject_id=user.id,
            ip_address=_get_ip(request),
            user_agent=_get_ua(request),
        )
        logger.info("user_registered", user_id=str(user.id), tenant_id=str(user.tenant_id))

    async def on_after_login(
        self, user: User, request: Request | None = None, response=None
    ) -> None:
        db = self.user_db.session
        await emit(
            db,
            AuthEvent.USER_LOGIN,
            tenant_id=user.tenant_id,
            actor_id=user.id,
            subject_id=user.id,
            ip_address=_get_ip(request),
            user_agent=_get_ua(request),
        )

    async def on_after_request_verify(
        self, user: User, token: str, request: Request | None = None
    ) -> None:
        from app.core.config import settings
        from app.notifications.email import resolve_tenant_sender, send_email_verification
        verify_url = f"{settings.ui_base}/verify-email?token={token}"
        from_address, from_name = await resolve_tenant_sender(self.user_db.session, user.tenant_id)
        await send_email_verification(
            to=user.email, verify_url=verify_url,
            from_address=from_address, from_name=from_name,
        )
        logger.info("email_verification_requested", user_id=str(user.id))

    async def on_after_forgot_password(
        self, user: User, token: str, request: Request | None = None
    ) -> None:
        logger.info("password_reset_requested", user_id=str(user.id))
        from app.core.config import settings
        from app.notifications.email import send_password_reset_email
        reset_url = f"{settings.ui_base}/reset-password?token={token}"
        await send_password_reset_email(to=user.email, reset_url=reset_url)

    async def on_after_reset_password(self, user: User, request: Request | None = None) -> None:
        db = self.user_db.session
        await self._push_password_history(user, db)
        await emit(
            db,
            AuthEvent.USER_PASSWORD_RESET,
            tenant_id=user.tenant_id,
            subject_id=user.id,
            ip_address=_get_ip(request),
        )

    async def on_after_update(
        self, user: User, update_dict: dict, request: Request | None = None
    ) -> None:
        if "password" in update_dict:
            db = self.user_db.session
            await self._push_password_history(user, db)
            await emit(
                db,
                AuthEvent.USER_PASSWORD_CHANGED,
                tenant_id=user.tenant_id,
                subject_id=user.id,
                ip_address=_get_ip(request),
            )
            # Security notification — fire-and-forget; never block the response
            from app.core.tasks import spawn
            from app.notifications.email import send_password_changed_alert
            spawn(send_password_changed_alert(to=user.email))

    async def _push_password_history(self, user: User, db: AsyncSession) -> None:
        """Append the user's current hashed_password to their history, trimming to depth."""
        depth = settings.PASSWORD_HISTORY_DEPTH
        if depth <= 0 or not user.hashed_password:
            return
        history = list(user.password_history or [])
        history.append(user.hashed_password)
        history = history[-depth:]
        await db.execute(
            update(User).where(User.id == user.id).values(password_history=history)
        )
        await db.commit()


def _get_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # Only trust X-Forwarded-For when running behind a known reverse proxy —
    # an unauthenticated client can trivially spoof this header otherwise.
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request | None) -> str | None:
    if request is None:
        return None
    return request.headers.get("User-Agent")


class _Argon2PasswordHelper:
    """Argon2-based PasswordHelper — replaces passlib/bcrypt.

    passlib 1.7.x is incompatible with bcrypt 5.x (which raised ValueError
    on passwords >72 bytes during its own wrap-bug detection). argon2 is
    already a first-class dependency and is the preferred algorithm (OWASP 2024).
    """

    _ph = PasswordHasher()

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify_and_update(self, plain: str, hashed: str) -> tuple[bool, str | None]:
        try:
            self._ph.verify(hashed, plain)
        except VerifyMismatchError:
            return False, None
        except (VerificationError, Exception):
            return False, None
        if self._ph.check_needs_rehash(hashed):
            return True, self._ph.hash(plain)
        return True, None

    def generate(self) -> tuple[str, str]:
        import secrets
        pw = secrets.token_urlsafe(16)
        return pw, self.hash(pw)


_argon2_helper = _Argon2PasswordHelper()


async def get_user_db(session: AsyncSession = Depends(get_session)):
    yield SQLAlchemyUserDatabase(session, User, OAuthAccount)


async def get_user_manager(user_db: SQLAlchemyUserDatabase = Depends(get_user_db)):
    yield UserManager(user_db, password_helper=_argon2_helper)


bearer_transport = BearerTransport(tokenUrl="/auth/login")

auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)

current_active_user = fastapi_users.current_user(active=True)
