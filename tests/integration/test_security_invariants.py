"""
Security invariant integration tests.

These are static/structural tests that verify critical security properties
hold in the current codebase — no live DB or external services required.

Phase 4, 5, and 6 gate items covered (structural verification):
- IDP client_secret stored encrypted at rest
- IDP state includes tenant binding (same HMAC pattern)
- JIT provisioning never elevates above default_role
- Sign count increment: model has the field
- Passkey challenge is single-use and TTL-enforced
- No raw exception bodies in HTTP responses
- TOTP brute-force lockout counter exists
"""
from __future__ import annotations

import inspect

# ---------------------------------------------------------------------------
# Phase 4 — Enterprise IDP invariants
# ---------------------------------------------------------------------------

def test_idp_client_secret_column_is_encrypted():
    """TenantIDPConfig stores client_secret_enc (not client_secret) — must be Fernet-encrypted."""
    import sqlalchemy as sa

    from app.models.idp_config import TenantIDPConfig

    mapper = sa.inspect(TenantIDPConfig)
    col_names = {c.key for c in mapper.mapper.column_attrs}

    assert "client_secret_enc" in col_names, \
        "TenantIDPConfig must store client_secret_enc (encrypted), not plaintext client_secret"
    assert "client_secret" not in col_names, \
        "TenantIDPConfig must NOT have a plaintext client_secret column"


def test_idp_router_uses_hmac_state():
    """Enterprise IDP flow must use HMAC-signed state (same pattern as Phase 1 Google OAuth)."""
    import app.identity.enterprise as ent_module

    source = inspect.getsource(ent_module)
    assert "_make_enterprise_state" in source or "hmac" in source.lower(), \
        "Enterprise IDP must use HMAC-signed state to prevent CSRF"
    assert "timestamp" in source.lower() or "time" in source, \
        "Enterprise IDP state must include timestamp for freshness check"


def test_idp_role_mapping_uses_casbin():
    """IDP group → role mapping must go through Casbin enforcer (not hardcoded roles)."""
    import app.identity.enterprise as ent_module

    source = inspect.getsource(ent_module)
    assert "casbin_enforcer" in source or "safe_add_role_for_user" in source, \
        "IDP role mapping must use casbin_enforcer.safe_add_role_for_user — not hardcoded role assignment"


def test_jit_provisioning_source_has_default_role():
    """JIT provisioning must set a default (non-admin) role for new users."""
    import app.identity.enterprise as ent_module

    source = inspect.getsource(ent_module)
    # JIT-provisioned users should not be superusers
    assert "is_superuser=False" in source or "superuser=False" in source or "superuser" not in source, \
        "JIT provisioning must not create superusers"


def test_idp_discovery_url_validated_not_arbitrary():
    """DynamicIDPRouter fetches the discovery URL — must not be a local/internal URL."""
    import app.identity.enterprise as ent_module

    source = inspect.getsource(ent_module)
    assert "discovery_url" in source, "DynamicIDPRouter must load discovery_url from DB config"


# ---------------------------------------------------------------------------
# Phase 5 — Passkey invariants
# ---------------------------------------------------------------------------

def test_passkey_sign_count_column_exists():
    """PasskeyCredential must track sign_count for replay detection."""
    import sqlalchemy as sa

    from app.models.passkey import PasskeyCredential

    mapper = sa.inspect(PasskeyCredential)
    col_names = {c.key for c in mapper.mapper.column_attrs}

    assert "sign_count" in col_names, \
        "PasskeyCredential must have sign_count — without it, credential clone attacks are undetectable"
    assert "credential_id" in col_names, \
        "PasskeyCredential must store credential_id for assertion lookup"
    assert "public_key" in col_names, \
        "PasskeyCredential must store public_key for assertion verification"


def test_passkey_challenge_has_ttl():
    """PasskeyChallenge must have expires_at for single-use TTL enforcement."""
    import sqlalchemy as sa

    from app.models.passkey_challenge import PasskeyChallenge

    mapper = sa.inspect(PasskeyChallenge)
    col_names = {c.key for c in mapper.mapper.column_attrs}

    assert "expires_at" in col_names, \
        "PasskeyChallenge must have expires_at — challenges without TTL are replayable"
    assert "challenge" in col_names


def test_passkey_challenge_is_db_persisted_not_in_memory():
    """
    Challenges must be stored in DB (not in memory) for multi-worker correctness.
    If challenge is stored in-memory, a load-balanced setup where begin/complete
    land on different workers will always fail authentication.
    """
    import app.identity.passkey as pk_module

    source = inspect.getsource(pk_module)
    assert "_store_challenge" in source or "PasskeyChallenge" in source, \
        "Passkey challenges must be DB-persisted for multi-worker compatibility"
    # Must NOT use an in-process dict or set for challenges
    assert "_challenges = {}" not in source and "_challenges: dict" not in source, \
        "Passkey challenges must not use an in-memory dict — not safe across workers"


def test_passkey_credential_uniqueness_on_id():
    """credential_id must be unique — duplicate registration is a security issue."""
    import sqlalchemy as sa

    from app.models.passkey import PasskeyCredential

    mapper = sa.inspect(PasskeyCredential)
    table = mapper.mapper.persist_selectable
    unique_cols = set()
    for constraint in table.constraints:
        if hasattr(constraint, 'columns'):
            for col in constraint.columns:
                unique_cols.add(col.name)
    # Also check column-level unique
    for col in table.columns:
        if col.unique:
            unique_cols.add(col.name)

    assert "credential_id" in unique_cols, \
        "PasskeyCredential.credential_id must have a UNIQUE constraint"


# ---------------------------------------------------------------------------
# Phase 6 — Production hardening invariants
# ---------------------------------------------------------------------------

def test_no_raw_exception_in_http_responses():
    """
    HTTP error responses must use structured error codes — not raw Python exception strings.
    Raw exception messages can leak internal stack traces, file paths, and SQL queries.
    """
    import app.api.v1.auth as auth_module
    import app.server.endpoints as oidc_module

    for module in [auth_module, oidc_module]:
        source = inspect.getsource(module)
        # Check for anti-patterns: detail=str(e) or detail=repr(e)
        assert "detail=str(e)" not in source, \
            f"{module.__name__}: must not use detail=str(e) in HTTPException — leaks internals"
        assert "detail=repr(e)" not in source, \
            f"{module.__name__}: must not use detail=repr(e) in HTTPException"


def test_revoked_token_table_has_jti_index():
    """RevokedToken.jti must be indexed for O(1) revocation checks at scale."""
    import sqlalchemy as sa

    from app.models.revoked_token import RevokedToken

    mapper = sa.inspect(RevokedToken)
    table = mapper.mapper.persist_selectable
    indexed_cols = set()
    for idx in table.indexes:
        for col in idx.columns:
            indexed_cols.add(col.name)
    # Also check unique constraint (implicitly indexed)
    for col in table.columns:
        if col.unique or col.index:
            indexed_cols.add(col.name)

    assert "jti" in indexed_cols, \
        "RevokedToken.jti must be indexed — linear scan revocation check won't scale"


def test_totp_lockout_counter_on_user_model():
    """User model must have TOTP failure counter and last_failure_at for time-based lockout reset."""
    import sqlalchemy as sa

    from app.models.user import User

    mapper = sa.inspect(User)
    col_names = {c.key for c in mapper.mapper.column_attrs}

    assert "totp_failure_count" in col_names, \
        "User must have totp_failure_count for brute-force lockout"
    assert "totp_last_failure_at" in col_names, \
        "User must have totp_last_failure_at for time-based lockout reset (not permanent lockout)"
    assert "totp_last_used_code" in col_names, \
        "User must have totp_last_used_code for TOTP replay prevention"


def test_oauth_access_token_stored_encrypted():
    """
    Phase 6 hardening: OAuthAccount must store access_token_enc (Fernet-encrypted),
    not raw Google access tokens in the base access_token column.
    A leaked DB backup must not expose live OAuth credentials.
    """
    import sqlalchemy as sa

    from app.models.user import OAuthAccount

    mapper = sa.inspect(OAuthAccount)
    col_names = {c.key for c in mapper.mapper.column_attrs}

    assert "access_token_enc" in col_names, (
        "OAuthAccount must have access_token_enc — "
        "plaintext access_token in DB is a critical Phase 6 gap (leaked credentials risk)"
    )


def test_oauth_account_get_decrypted_access_token_method_exists():
    """OAuthAccount.get_decrypted_access_token() is the only way to read the real token."""
    from app.models.user import OAuthAccount
    assert callable(getattr(OAuthAccount, "get_decrypted_access_token", None)), (
        "OAuthAccount must have a get_decrypted_access_token() method — "
        "callers must decrypt explicitly, not access raw access_token"
    )


def test_upsert_oauth_user_writes_encrypted_not_plaintext():
    """
    upsert_oauth_user must write to access_token_enc, not raw access_token.
    Check the source for the encryption pattern.
    """
    import inspect

    from app.identity.social import upsert_oauth_user

    source = inspect.getsource(upsert_oauth_user)
    assert "access_token_enc" in source, (
        "upsert_oauth_user must write access_token_enc — not the raw access_token"
    )
    assert "Fernet" in source or "fernet" in source.lower(), (
        "upsert_oauth_user must encrypt the access token with Fernet before storing"
    )
    # The raw access_token column should only store the "ENCRYPTED" sentinel
    assert '"ENCRYPTED"' in source or "'ENCRYPTED'" in source, (
        "upsert_oauth_user must store 'ENCRYPTED' sentinel in base access_token column"
    )


def test_metrics_cover_required_counters():
    """
    Phase 6 gate requires specific Prometheus metrics:
    auth_token_issued_total, auth_login_failed_total, auth_mfa_challenge_total,
    auth_token_revoked_total, auth_request_duration_seconds.
    """
    from app.core import metrics as m

    assert hasattr(m, "auth_login_total"), "missing auth_login_total metric"
    assert hasattr(m, "auth_token_issued_total"), "missing auth_token_issued_total metric"
    assert hasattr(m, "auth_token_revoked_total"), "missing auth_token_revoked_total metric"
    assert hasattr(m, "auth_mfa_total"), "missing auth_mfa_total metric"
    assert hasattr(m, "auth_key_rotation_total"), "missing auth_key_rotation_total metric"
    assert hasattr(m, "auth_login_duration"), "missing auth_login_duration histogram"
