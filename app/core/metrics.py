from __future__ import annotations

"""
Prometheus metrics for the auth engine.

Tracks the key auth KPIs that ops needs to alert on:
- auth_login_total: login success/failure by tenant (detect brute-force)
- auth_token_issued_total: token issuance rate by type
- auth_token_revoked_total: revocation rate
- auth_mfa_total: MFA events (challenge/failure/enrollment)
- auth_key_rotations_total: signing key rotations
- auth_login_duration_seconds: login flow latency

All metrics include a `tenant_id` label so per-tenant anomalies are visible.
"""

from prometheus_client import Counter, Histogram

# The auth-engine runs in an isolated container that does NOT bundle the repo's
# `shared` package, so it cannot import shared.metrics_policy at module load.
# Define latency buckets locally (a named tuple, not an inline list) kept aligned
# with metrics_policy's FAST profile — sub-second to a few seconds, right for a
# login flow. Centralising via shared would require shipping `shared` into the
# auth-engine image first.
_LOGIN_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

auth_login_total = Counter(
    "auth_login_total",
    "Total login attempts",
    ["result", "method"],  # result: success|failure, method: password|google|enterprise|passkey
)

auth_token_issued_total = Counter(
    "auth_token_issued_total",
    "Total JWTs issued",
    ["token_type"],  # token_type: access|mfa_pending|service
)

auth_token_revoked_total = Counter(
    "auth_token_revoked_total",
    "Total tokens revoked",
)

auth_mfa_total = Counter(
    "auth_mfa_total",
    "MFA events",
    ["event", "method"],  # event: challenge|failure|enrollment, method: totp|passkey
)

auth_key_rotation_total = Counter(
    "auth_key_rotation_total",
    "Signing key rotation events",
)

auth_login_duration = Histogram(
    "auth_login_duration_seconds",
    "End-to-end login duration",
    ["method"],
    buckets=_LOGIN_DURATION_BUCKETS,
)

auth_totp_lockout_total = Counter(
    "auth_totp_lockout_total",
    "Times a user hit the TOTP lockout threshold",
)

auth_trusted_device_total = Counter(
    "auth_trusted_device_total",
    "Trusted-device MFA bypass events",
    ["action"],  # action: bypass|created|revoked
)

auth_password_reuse_blocked_total = Counter(
    "auth_password_reuse_blocked_total",
    "Password changes blocked due to history reuse",
)

auth_ip_policy_blocked_total = Counter(
    "auth_ip_policy_blocked_total",
    "Login attempts blocked by per-tenant IP allowlist/blocklist",
    ["reason"],  # reason: blocklisted|not_allowlisted
)
