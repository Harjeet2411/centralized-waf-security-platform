"""Idempotent writes of one account's collection results. Re-running a sync (Step Functions retry) converges to
the same rows: upserts keyed on natural AWS identifiers, events deduped by event_hash."""

import json
from datetime import datetime

from account_collector.collect import DiscoveredEndpoint, WebAclSnapshot, waf_status

UPSERT_WEB_ACL = """
INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action, capacity, logging_enabled,
                      logging_destination, visibility_level, baseline_config, current_config, last_synced_at)
VALUES (%(id)s, %(arn)s, %(name)s, %(account_id)s, %(region)s, %(scope)s, %(default_action)s, %(capacity)s,
        %(logging_enabled)s, %(logging_destination)s, %(visibility_level)s, %(config)s::jsonb, %(config)s::jsonb,
        now())
ON CONFLICT (arn) DO UPDATE SET
    name = EXCLUDED.name, default_action = EXCLUDED.default_action, capacity = EXCLUDED.capacity,
    logging_enabled = EXCLUDED.logging_enabled, logging_destination = EXCLUDED.logging_destination,
    visibility_level = EXCLUDED.visibility_level, last_synced_at = now(),
    -- Config snapshots come from full syncs only ('{}' on telemetry runs leaves them untouched).
    -- First-seen configuration becomes the drift baseline; afterwards only an approved change may move it.
    baseline_config = CASE WHEN web_acls.baseline_config = '{}'::jsonb THEN EXCLUDED.baseline_config
                           ELSE web_acls.baseline_config END,
    current_config = CASE WHEN EXCLUDED.current_config = '{}'::jsonb THEN web_acls.current_config
                          ELSE EXCLUDED.current_config END
RETURNING id
"""

UPSERT_RULE = """
INSERT INTO rules (webacl_id, account_id, name, priority, type, action, statement, managed_group_name, vendor_name,
                   current_version, available_version, version_status, excluded_rules, scope_down_statement,
                   rate_limit, updated_at)
VALUES (%(webacl_id)s, %(account_id)s, %(name)s, %(priority)s, %(type)s, %(action)s, %(statement)s::jsonb,
        %(managed_group_name)s, %(vendor_name)s, %(current_version)s, %(available_version)s, %(version_status)s,
        %(excluded_rules)s, %(scope_down_statement)s, %(rate_limit)s, now())
ON CONFLICT (webacl_id, name) DO UPDATE SET
    priority = EXCLUDED.priority, type = EXCLUDED.type, action = EXCLUDED.action, statement = EXCLUDED.statement,
    managed_group_name = EXCLUDED.managed_group_name, vendor_name = EXCLUDED.vendor_name,
    current_version = EXCLUDED.current_version, available_version = EXCLUDED.available_version,
    version_status = EXCLUDED.version_status, excluded_rules = EXCLUDED.excluded_rules,
    scope_down_statement = EXCLUDED.scope_down_statement, rate_limit = EXCLUDED.rate_limit,
    updated_at = CASE WHEN rules.statement IS DISTINCT FROM EXCLUDED.statement OR rules.action <> EXCLUDED.action
                      THEN now() ELSE rules.updated_at END
RETURNING id
"""

UPSERT_ENDPOINT = """
INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing, waf_status, webacl_id,
                       logging_enabled, visibility_level, last_verified_at)
VALUES (%(resource_arn)s, %(account_id)s, %(name)s, %(type)s, %(region)s, %(dns_name)s, %(internet_facing)s,
        %(waf_status)s, %(webacl_id)s, %(logging_enabled)s, %(visibility_level)s, now())
ON CONFLICT (resource_arn) DO UPDATE SET
    name = EXCLUDED.name, dns_name = EXCLUDED.dns_name, internet_facing = EXCLUDED.internet_facing,
    waf_status = EXCLUDED.waf_status, webacl_id = EXCLUDED.webacl_id, logging_enabled = EXCLUDED.logging_enabled,
    visibility_level = EXCLUDED.visibility_level, last_verified_at = now()
"""


def config_document(snap: WebAclSnapshot, associated: list[str]) -> dict:
    """Full WebACL JSON plus the two facts drift needs that GetWebACL doesn't return."""
    return {**snap.raw, "_logging_destination": snap.logging_destination, "_associated_resources": sorted(associated)}


def save_web_acl(cur, account_id: str, snap: WebAclSnapshot, config: dict | None = None) -> str:
    cur.execute(UPSERT_WEB_ACL, {
        "id": snap.id, "arn": snap.arn, "name": snap.name, "account_id": account_id, "region": snap.region,
        "scope": snap.scope, "default_action": snap.default_action, "capacity": snap.capacity,
        "logging_enabled": snap.logging_destination is not None, "logging_destination": snap.logging_destination,
        "visibility_level": snap.visibility_level, "config": json.dumps(config or {}, default=str),
    })
    return cur.fetchone()["id"]


def save_rules(cur, account_id: str, webacl_db_id, snap: WebAclSnapshot) -> None:
    """Upsert current rules, drop rules removed in AWS, rebuild managed_rule_versions for this WebACL."""
    cur.execute("DELETE FROM managed_rule_versions WHERE webacl_id = %s", (webacl_db_id,))
    for rule in snap.rules:
        cur.execute(UPSERT_RULE, {
            **rule, "webacl_id": webacl_db_id, "account_id": account_id,
            "statement": json.dumps(rule["statement"], default=str),
        })
        rule_id = cur.fetchone()["id"]
        if rule["type"] == "MANAGED":
            cur.execute(
                "INSERT INTO managed_rule_versions (webacl_id, rule_id, vendor_name, managed_group_name,"
                " current_version, available_version, version_status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (webacl_db_id, rule_id, rule["vendor_name"], rule["managed_group_name"],
                 rule["current_version"] or "UNKNOWN", rule["available_version"] or "UNKNOWN",
                 rule["version_status"] or "UNKNOWN"),
            )
    cur.execute("DELETE FROM rules WHERE webacl_id = %s AND NOT (name = ANY(%s))",
                (webacl_db_id, [r["name"] for r in snap.rules]))


def save_metric_totals(cur, webacl_db_id, snap: WebAclSnapshot, totals: dict) -> None:
    acl = totals.get((snap.arn, "ALL"))
    if acl is not None:
        allowed, blocked, counted = (acl.get(m, 0) for m in ("AllowedRequests", "BlockedRequests", "CountedRequests"))
        cur.execute(
            "UPDATE web_acls SET requests_24h = %s, allowed_24h = %s, blocked_24h = %s, counted_24h = %s"
            " WHERE id = %s",
            (allowed + blocked + counted, allowed, blocked, counted, webacl_db_id),
        )
    for rule in snap.rules:
        values = totals.get((snap.arn, rule["metric_name"]))
        if values is None:
            continue
        blocked, counted = values.get("BlockedRequests", 0), values.get("CountedRequests", 0)
        matches = blocked + counted + values.get("AllowedRequests", 0)
        cur.execute(
            "UPDATE rules SET matches_24h = %s, blocked_24h = %s, counted_24h = %s WHERE webacl_id = %s AND name = %s",
            (matches, blocked, counted, webacl_db_id, rule["name"]),
        )


def save_endpoints(cur, account_id: str, endpoints: list[DiscoveredEndpoint], snapshots: dict[str, WebAclSnapshot],
                   webacl_db_ids: dict[str, str], complete_scopes: set[tuple[str, str]]) -> None:
    """Upsert discovered endpoints. Endpoints that vanished are deleted only for (region, type) scopes whose
    discovery fully succeeded this run - a failed region must never wipe its inventory."""
    for ep in endpoints:
        snap = snapshots.get(ep.webacl_arn) if ep.webacl_arn else None
        cur.execute(UPSERT_ENDPOINT, {
            "resource_arn": ep.resource_arn, "account_id": account_id, "name": ep.name, "type": ep.type,
            "region": ep.region, "dns_name": ep.dns_name, "internet_facing": ep.internet_facing,
            "waf_status": waf_status(ep, snapshots), "webacl_id": webacl_db_ids.get(ep.webacl_arn or ""),
            "logging_enabled": bool(snap and snap.logging_destination),
            "visibility_level": snap.visibility_level if snap else "none",
        })
    seen = [ep.resource_arn for ep in endpoints]
    for region, ep_type in sorted(complete_scopes):
        cur.execute(
            "DELETE FROM endpoints WHERE account_id = %s AND region = %s AND type = %s"
            " AND NOT (resource_arn = ANY(%s))",
            (account_id, region, ep_type, seen),
        )


def save_account(cur, account_id: str, snapshots: list[WebAclSnapshot], errors: list[str], full_sync: bool,
                 now: datetime) -> str:
    levels = {s.visibility_level for s in snapshots}
    visibility = next((lvl for lvl in ("full", "sampled", "metrics") if lvl in levels), "none")
    status = "DEGRADED" if errors else "HEALTHY"
    cur.execute(
        """
        UPDATE accounts SET status = %s, visibility_level = %s, logging_enabled = %s, last_error = %s,
            last_discovered = CASE WHEN %s THEN %s ELSE last_discovered END, updated_at = now()
        WHERE account_id = %s
        """,
        (status, visibility, "full" in levels, "; ".join(errors)[:4000] or None, full_sync, now, account_id),
    )
    return status
