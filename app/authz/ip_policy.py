from __future__ import annotations

"""
Per-tenant IP allowlist / blocklist enforcement.

Rules (applied in this order):
  1. If the tenant has a non-empty blocklist and the client IP is in any range → DENY
  2. If the tenant has a non-empty allowlist and the client IP is NOT in any range → DENY
  3. Otherwise → ALLOW

CIDR ranges are stored as JSON arrays on the Tenant row, e.g.
  ip_allowlist: ["10.0.0.0/8", "203.0.113.5/32"]
  ip_blocklist: ["198.51.100.0/24"]

Both IPv4 and IPv6 are supported via stdlib ipaddress.

Failure mode: if the stored CIDRs are malformed, we log and ALLOW rather than
blocking every login (availability > security for corrupt config).
"""

import ipaddress
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


def _in_any(ip_obj, cidrs: list) -> bool:
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return True
        except ValueError:
            logger.warning("ip_policy_invalid_cidr", cidr=cidr)
    return False


def check_ip_policy(client_ip: str | None, tenant) -> tuple[bool, str]:
    """
    Return ``(allowed, reason)``.

    ``allowed=True`` means the request should proceed.
    ``tenant`` must have ``ip_allowlist`` and ``ip_blocklist`` attributes
    (both nullable lists of CIDR strings).
    """
    if not client_ip:
        # Can't determine IP — allow but log (happens in tests / local dev)
        logger.debug("ip_policy_unknown_ip", tenant_id=str(getattr(tenant, "id", "?")))
        return True, "unknown_ip"

    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning("ip_policy_unparseable_ip", ip=client_ip)
        return True, "unparseable"

    blocklist = list(getattr(tenant, "ip_blocklist", None) or [])
    allowlist = list(getattr(tenant, "ip_allowlist", None) or [])

    if blocklist and _in_any(ip_obj, blocklist):
        logger.info(
            "ip_policy_blocked",
            ip=client_ip,
            tenant_id=str(getattr(tenant, "id", "?")),
        )
        return False, "blocklisted"

    if allowlist and not _in_any(ip_obj, allowlist):
        logger.info(
            "ip_policy_not_allowlisted",
            ip=client_ip,
            tenant_id=str(getattr(tenant, "id", "?")),
        )
        return False, "not_allowlisted"

    return True, "allowed"
