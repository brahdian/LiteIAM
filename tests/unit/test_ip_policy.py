"""Unit tests for app.authz.ip_policy.check_ip_policy."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.authz.ip_policy import check_ip_policy


def _tenant(allowlist=None, blocklist=None):
    t = MagicMock()
    t.id = "test-tenant"
    t.ip_allowlist = allowlist
    t.ip_blocklist = blocklist
    return t


# ---------------------------------------------------------------------------
# No restrictions → always allow
# ---------------------------------------------------------------------------

def test_no_policy_allows_any_ip():
    assert check_ip_policy("1.2.3.4", _tenant())[0] is True


def test_empty_lists_allow_any_ip():
    assert check_ip_policy("1.2.3.4", _tenant(allowlist=[], blocklist=[]))[0] is True


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

def test_blocklisted_ip_denied():
    ok, reason = check_ip_policy("10.0.0.1", _tenant(blocklist=["10.0.0.0/8"]))
    assert ok is False
    assert reason == "blocklisted"


def test_blocklisted_exact_ip_denied():
    ok, reason = check_ip_policy("192.168.1.100", _tenant(blocklist=["192.168.1.100/32"]))
    assert ok is False
    assert reason == "blocklisted"


def test_non_blocklisted_ip_allowed():
    ok, _ = check_ip_policy("172.16.0.1", _tenant(blocklist=["10.0.0.0/8"]))
    assert ok is True


def test_ipv6_blocklist():
    ok, reason = check_ip_policy("::1", _tenant(blocklist=["::1/128"]))
    assert ok is False
    assert reason == "blocklisted"


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def test_allowlisted_ip_passes():
    ok, reason = check_ip_policy("10.10.10.5", _tenant(allowlist=["10.10.0.0/16"]))
    assert ok is True
    assert reason == "allowed"


def test_ip_outside_allowlist_denied():
    ok, reason = check_ip_policy("8.8.8.8", _tenant(allowlist=["10.0.0.0/8"]))
    assert ok is False
    assert reason == "not_allowlisted"


def test_allowlist_with_multiple_ranges():
    ok, _ = check_ip_policy("172.31.0.5", _tenant(allowlist=["10.0.0.0/8", "172.16.0.0/12"]))
    assert ok is True


def test_ip_not_in_any_allowlist_range():
    ok, reason = check_ip_policy("1.1.1.1", _tenant(allowlist=["10.0.0.0/8", "172.16.0.0/12"]))
    assert ok is False
    assert reason == "not_allowlisted"


# ---------------------------------------------------------------------------
# Blocklist takes priority over allowlist
# ---------------------------------------------------------------------------

def test_blocklist_overrides_allowlist():
    """An IP in both allowlist and blocklist must be DENIED (blocklist wins)."""
    ok, reason = check_ip_policy(
        "10.0.0.1",
        _tenant(allowlist=["10.0.0.0/8"], blocklist=["10.0.0.0/24"]),
    )
    assert ok is False
    assert reason == "blocklisted"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_none_ip_is_allowed():
    """Unknown IPs are allowed but logged — availability > lockout for unknown clients."""
    ok, reason = check_ip_policy(None, _tenant(allowlist=["10.0.0.0/8"]))
    assert ok is True
    assert reason == "unknown_ip"


def test_unparseable_ip_is_allowed():
    ok, reason = check_ip_policy("not-an-ip", _tenant(blocklist=["10.0.0.0/8"]))
    assert ok is True
    assert reason == "unparseable"


def test_malformed_cidr_in_blocklist_is_skipped():
    """Bad CIDR entries are logged but don't crash or deny legitimate IPs."""
    ok, _ = check_ip_policy("1.2.3.4", _tenant(blocklist=["not-a-cidr", "10.0.0.0/8"]))
    # 1.2.3.4 is not in 10.0.0.0/8 so it should be allowed (bad CIDR skipped)
    assert ok is True


def test_malformed_cidr_in_allowlist_skipped_but_ip_may_be_denied():
    """Only the valid CIDRs in allowlist are checked — bad ones are ignored."""
    # allowlist has one bad CIDR and one valid range that does NOT include 8.8.8.8
    ok, reason = check_ip_policy("8.8.8.8", _tenant(allowlist=["not-a-cidr", "10.0.0.0/8"]))
    assert ok is False  # 8.8.8.8 not in any valid allowlist range
    assert reason == "not_allowlisted"


def test_exact_host_in_allowlist():
    ok, _ = check_ip_policy("203.0.113.42", _tenant(allowlist=["203.0.113.42/32"]))
    assert ok is True
