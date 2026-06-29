from __future__ import annotations

from app.models.user import User


def requires_mfa(user: User) -> bool:
    """
    Policy: does this user need to complete MFA before receiving a full token?
    Extend this with risk signals, tenant policy, IP reputation, etc.
    """
    return user.is_totp_enabled
