"""RBAC permission logic (PRD section 3, CLAUDE.md section 10).

Role -> permission grants live in the `roles` table (seeded by migration 0001) so they are loaded fresh on
every request. A grant is either a base permission ("APPROVE") or a qualified one ("APPROVE:TEMP_BLOCK",
"INVESTIGATE:SCOPED"). Any grant of a base permission passes the endpoint gate; qualifiers narrow what the
holder may actually do and are enforced by the caller (approval policy engine, account scoping).
"""

from collections.abc import Iterable

PERMISSIONS = frozenset({
    "VIEW", "INVESTIGATE", "SIMULATE", "CREATE_CHANGE", "APPROVE",
    "EXECUTE", "ROLLBACK", "MANAGE_TI", "MANAGE_USERS",
})

SCOPED = "SCOPED"
UNQUALIFIED = "*"


def qualifiers(grants: Iterable[str], permission: str) -> frozenset[str]:
    """Qualifiers held for `permission`: {"*"} for an unqualified grant, e.g. {"TEMP_BLOCK"}, or empty."""
    if permission not in PERMISSIONS:
        raise ValueError(f"unknown permission {permission!r}")
    held: set[str] = set()
    for grant in grants:
        base, _, qualifier = grant.partition(":")
        if base == permission:
            held.add(qualifier or UNQUALIFIED)
    return frozenset(held)


def has_permission(grants: Iterable[str], permission: str) -> bool:
    return bool(qualifiers(grants, permission))


def account_scope(grants: Iterable[str], permission: str, scoped_account_ids: Iterable[str]) -> frozenset[str] | None:
    """Accounts the holder may act on for `permission`: None = all accounts, a set = only those.

    Raises PermissionError when the permission is not held at all.
    """
    held = qualifiers(grants, permission)
    if not held:
        raise PermissionError(permission)
    if SCOPED in held and UNQUALIFIED not in held:
        return frozenset(scoped_account_ids)
    return None
