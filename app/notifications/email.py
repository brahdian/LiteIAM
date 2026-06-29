from __future__ import annotations

"""
Async email sender for the auth engine.

All outbound email goes through this module. When SMTP_HOST is empty (default in
dev/test), every call is a no-op that logs at DEBUG level — no real emails sent,
no smtplib import errors. When SMTP_HOST is set, emails are delivered via
aiosmtplib (async SMTP) with STARTTLS on port 587 by default.

Error handling: SMTP errors are caught and logged at ERROR level; they are never
re-raised, because a failed transactional email must never break the caller's
HTTP response (e.g., a password reset 202 stays 202 even if the relay is down).
"""

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


async def send_email(
    *,
    to: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    from_address: str | None = None,
    from_name: str | None = None,
) -> None:
    """Send a transactional email.  Silently no-ops when SMTP_HOST is unset.

    `from_address`/`from_name` override the visible From header (used for
    per-tenant sender branding). The SMTP envelope sender stays SMTP_FROM so SPF
    alignment against the platform's verified domain is preserved.
    """
    if not settings.SMTP_HOST:
        logger.debug("email_skipped_no_smtp_host", to=to, subject=subject)
        return

    from email.utils import formataddr
    sender = from_address or settings.SMTP_FROM
    # formataddr quotes/encodes the display name (RFC 2047 + special-char quoting),
    # so a tenant-set from_name with a comma or angle brackets can't inject a second
    # address or break the header.
    from_header = formataddr((from_name, sender)) if from_name else sender

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    if html_body:
        msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        await asyncio.get_event_loop().run_in_executor(
            None, _send_sync, msg, to
        )
        logger.info("email_sent", to=to, subject=subject)
    except Exception as exc:
        logger.error("email_send_failed", to=to, subject=subject, error=str(exc))


def _send_sync(msg: MIMEMultipart, to: str) -> None:
    """Blocking SMTP send — runs in thread executor to avoid blocking the event loop."""
    if settings.SMTP_TLS:
        smtp = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
    else:
        smtp = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)

    try:
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        smtp.sendmail(settings.SMTP_FROM, [to], msg.as_string())
    finally:
        smtp.quit()


# ---------------------------------------------------------------------------
# Per-tenant sender resolution
# ---------------------------------------------------------------------------

async def resolve_tenant_sender(db, tenant_id) -> tuple[str | None, str | None]:
    """Return (from_address, from_name) for a tenant, or (None, None) to use the
    platform default. Safe to call with tenant_id=None."""
    if tenant_id is None:
        return None, None
    from sqlalchemy import select

    from app.models.tenant import Tenant
    row = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if row is None:
        return None, None
    return row.email_from_address, row.email_from_name


# ---------------------------------------------------------------------------
# Named email templates
# ---------------------------------------------------------------------------

async def send_email_otp(
    *, to: str, code: str, ttl_minutes: int,
    from_address: str | None = None, from_name: str | None = None,
) -> None:
    """One-time numeric sign-in code (passwordless email OTP)."""
    await send_email(
        to=to,
        subject=f"{code} is your sign-in code",
        from_address=from_address,
        from_name=from_name,
        text_body=(
            f"Your sign-in code is: {code}\n\n"
            f"It expires in {ttl_minutes} minutes and can only be used once.\n\n"
            f"If you did not request this, you can safely ignore this email."
        ),
        html_body=(
            f'<p>Your sign-in code is:</p>'
            f'<p style="font-size:32px;font-weight:700;letter-spacing:8px;font-family:monospace">{code}</p>'
            f'<p>It expires in <strong>{ttl_minutes} minutes</strong> and can only be used once.</p>'
            f'<p style="color:#6b7280;font-size:12px">If you did not request this, you can safely ignore this email.</p>'
        ),
    )

async def send_password_reset_email(*, to: str, reset_url: str) -> None:
    await send_email(
        to=to,
        subject="Reset your password",
        text_body=(
            f"You requested a password reset for your account.\n\n"
            f"Click the link below to set a new password. This link expires in 1 hour.\n\n"
            f"{reset_url}\n\n"
            f"If you did not request this, you can safely ignore this email.\n"
            f"Your password will not change until you follow the link above.\n\n"
            f"— Security"
        ),
        html_body=(
            f"<p>You requested a password reset for your account.</p>"
            f"<p><a href=\"{reset_url}\">Reset my password</a></p>"
            f"<p>This link expires in 1 hour. If you did not request this, ignore this email.</p>"
            f"<p><em>— Security</em></p>"
        ),
    )


async def send_invitation_email(
    *, to: str, invite_url: str, invited_by: str = "",
    from_address: str | None = None, from_name: str | None = None,
) -> None:
    by_line = f" by {invited_by}" if invited_by else ""
    await send_email(
        to=to,
        from_address=from_address,
        from_name=from_name,
        subject="You've been invited",
        text_body=(
            f"You've been invited{by_line} to join the platform.\n\n"
            f"Click the link below to create your account. This invitation expires in 7 days.\n\n"
            f"{invite_url}\n\n"
            f"If you weren't expecting this invitation, you can safely ignore this email.\n\n"
            f"— the service"
        ),
        html_body=(
            f"<p>You've been invited{by_line} to join the platform.</p>"
            f"<p><a href=\"{invite_url}\">Accept invitation</a></p>"
            f"<p>This invitation expires in 7 days.</p>"
            f"<p><em>— the service</em></p>"
        ),
    )


async def send_email_verification(
    *, to: str, verify_url: str,
    from_address: str | None = None, from_name: str | None = None,
) -> None:
    await send_email(
        to=to,
        from_address=from_address,
        from_name=from_name,
        subject="Verify your email address",
        text_body=(
            f"Welcome to the service! Please verify your email address by clicking the link below.\n\n"
            f"{verify_url}\n\n"
            f"This link expires in 24 hours. If you did not create an account, ignore this email.\n\n"
            f"— the service"
        ),
        html_body=(
            f"<p>Welcome! Please verify your email address.</p>"
            f"<p><a href=\"{verify_url}\">Verify email address</a></p>"
            f"<p>This link expires in 24 hours.</p>"
            f"<p><em>— the service</em></p>"
        ),
    )


async def send_password_changed_alert(*, to: str) -> None:
    """Security notification when a user changes their own password."""
    await send_email(
        to=to,
        subject="Your password was changed",
        text_body=(
            "The password for your account was just changed.\n\n"
            "If you made this change, no action is needed.\n\n"
            "If you did NOT change your password, your account may be compromised.\n"
            "Reset your password immediately and contact support:\n"
            f"{settings.BASE_URL}/ui/forgot-password\n\n"
            "— Security"
        ),
        html_body=(
            "<p>The password for your account was just changed.</p>"
            "<p>If you made this change, no action is needed.</p>"
            "<p><strong>If you did NOT change your password</strong>, your account may be "
            "compromised. <a href=\""
            f"{settings.BASE_URL}/ui/forgot-password"
            "\">Reset your password immediately</a> and contact support.</p>"
            "<p><em>— Security</em></p>"
        ),
    )


async def send_new_ip_login_alert(*, to: str, new_ip: str, user_agent: str = "") -> None:
    ua_line = f"\nDevice: {user_agent}" if user_agent else ""
    await send_email(
        to=to,
        subject="New sign-in from an unfamiliar location",
        text_body=(
            f"We noticed a sign-in to your account from a new IP address.\n\n"
            f"IP address: {new_ip}{ua_line}\n\n"
            f"If this was you, no action is needed.\n"
            f"If this wasn't you, please reset your password immediately at:\n"
            f"{settings.BASE_URL}/ui/forgot-password\n\n"
            f"— Security"
        ),
    )


async def send_pat_created_alert(*, to: str, pat_name: str, scopes: list) -> None:
    """Security notification when a new Personal Access Token is created."""
    scope_str = ", ".join(sorted(scopes)) if scopes else "none"
    await send_email(
        to=to,
        subject="New API token created",
        text_body=(
            f"A new Personal Access Token (API key) was created for your account.\n\n"
            f"Token name: {pat_name}\n"
            f"Scopes: {scope_str}\n\n"
            f"If you did NOT create this token, it may represent unauthorized access.\n"
            f"Revoke all tokens immediately at:\n"
            f"{settings.BASE_URL}/ui/account\n\n"
            f"— Security"
        ),
        html_body=(
            f"<p>A new Personal Access Token (API key) was created for your account.</p>"
            f"<ul><li><strong>Token name:</strong> {pat_name}</li>"
            f"<li><strong>Scopes:</strong> {scope_str}</li></ul>"
            f"<p>If you did NOT create this token, it may represent unauthorized access. "
            f'<a href="{settings.BASE_URL}/ui/account">Revoke all tokens immediately</a>.</p>'
            f"<p><em>— Security</em></p>"
        ),
    )


async def send_mfa_disabled_alert(*, to: str) -> None:
    """Security notification when TOTP / MFA is removed from an account."""
    await send_email(
        to=to,
        subject="Two-factor authentication removed",
        text_body=(
            "Two-factor authentication (TOTP) was just removed from your account.\n\n"
            "If you made this change, no action is needed.\n\n"
            "If you did NOT remove 2FA, your account may be compromised.\n"
            "Reset your password and re-enable 2FA immediately:\n"
            f"{settings.BASE_URL}/ui/account\n\n"
            "— Security"
        ),
        html_body=(
            "<p>Two-factor authentication (TOTP) was just removed from your account.</p>"
            "<p>If you made this change, no action is needed.</p>"
            "<p><strong>If you did NOT remove 2FA</strong>, your account may be compromised. "
            f'<a href="{settings.BASE_URL}/ui/account">Reset your password and re-enable 2FA immediately</a>.</p>'
            "<p><em>— Security</em></p>"
        ),
    )


async def send_email_change_verification(*, to: str, confirm_url: str) -> None:
    """Sent to the NEW email address to verify ownership before the change takes effect."""
    await send_email(
        to=to,
        subject="Verify your new email address",
        text_body=(
            f"Someone requested to change an account email to this address.\n\n"
            f"Click the link below to confirm the change (valid for 24 hours):\n"
            f"{confirm_url}\n\n"
            f"If you did not request this change, you can safely ignore this email.\n\n"
            f"— Security"
        ),
        html_body=(
            f"<p>Someone requested to change an account email to this address.</p>"
            f'<p><a href="{confirm_url}">Confirm email change</a> (valid for 24 hours)</p>'
            f"<p>If you did not request this change, you can safely ignore this email.</p>"
            f"<p><em>— Security</em></p>"
        ),
    )


async def send_email_change_notification(*, to: str, new_email: str) -> None:
    """Sent to the OLD email address to alert the user that a change was requested."""
    await send_email(
        to=to,
        subject="Email address change requested",
        text_body=(
            f"A request was made to change the email address on your account "
            f"to: {new_email}\n\n"
            f"If you made this request, check your new inbox for a verification link.\n\n"
            f"If you did NOT make this request, your account may be compromised.\n"
            f"Reset your password immediately:\n"
            f"{settings.BASE_URL}/ui/forgot-password\n\n"
            f"— Security"
        ),
    )


async def send_email_change_complete(*, to: str, new_email: str) -> None:
    """Sent to the OLD email address confirming the change was completed."""
    await send_email(
        to=to,
        subject="Email address changed",
        text_body=(
            f"The email address on your account has been changed to: {new_email}\n\n"
            f"If you did not make this change, contact support immediately and reset your password:\n"
            f"{settings.BASE_URL}/ui/forgot-password\n\n"
            f"— Security"
        ),
    )
