"""Server-side allow-list guardrails (Rule #3) and block-target sanity rails.

Every IP block passes through `verify_not_allowlisted` at request time and again at approval time; the
`trg_approvals_allow_list` DB trigger is the last line behind both. Nothing in a request can skip it.
"""

import ipaddress

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

PROTECTED_DETAIL = "DENIED: Protected Entity"
MIN_PREFIX = {4: 24, 6: 64}  # never block more than a /24 (v4) or /64 (v6) in one target


def parse_block_target(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """IP or CIDR -> network. Rejects malformed, overly broad and non-public targets (422)."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Invalid IP/CIDR: {value!r}") from exc
    if network.prefixlen < MIN_PREFIX[network.version]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Refusing to block {network}: broader than /{MIN_PREFIX[network.version]}",
        )
    if not network.is_global:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Refusing to block non-public range {network}")
    return network


async def protected_matches(db: AsyncSession, networks: list) -> list[dict]:
    """Active allow-list entries overlapping any of `networks` (GiST-indexed `&&`)."""
    if not networks:
        return []
    rows = await db.execute(text(
        "SELECT DISTINCT a.cidr_or_value, a.name, a.category FROM allow_list_entries a"
        " WHERE a.is_active AND a.ip_network IS NOT NULL AND a.ip_network && ANY(CAST(:nets AS cidr[]))"
    ), {"nets": [str(n) for n in networks]})
    return [dict(r) for r in rows.mappings()]


async def verify_not_allowlisted(db: AsyncSession, networks: list) -> None:
    matches = await protected_matches(db, networks)
    if matches:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {
            "message": PROTECTED_DETAIL,
            "protected": [{"cidr": m["cidr_or_value"], "name": m["name"], "category": m["category"]} for m in matches],
        })
