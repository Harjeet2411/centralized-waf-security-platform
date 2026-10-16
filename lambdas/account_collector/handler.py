"""sas-account-collector: one Step Functions Map iteration = one AWS account.

Event: {"account": {"account_id", "discovery_role_arn", "regions"}, "mode": "full" | "telemetry"}
  full      (6h):  endpoint discovery, WebACL rule trees, managed rule versions, metrics, sampled requests
  telemetry (30m): WebACL rule trees (needed for metric names), metrics, sampled requests

Failure model: AssumeRole failure raises AccountAccessError (the ASL Catch routes to MarkAccountDegraded);
throttling raises WAFLimitsExceededException/ThrottlingException (ASL Retry); any other per-API error is
recorded and the account finishes as DEGRADED with the evidence in accounts.last_error / platform_health.
"""

import logging
from datetime import UTC, datetime

from botocore.exceptions import ClientError

from account_collector import collect, store
from common import db
from common.aws import ClientFactory, assume_discovery_role
from common.normalize import insert_events

log = logging.getLogger()
log.setLevel(logging.INFO)


def collect_account(account: dict, mode: str, clients: ClientFactory, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    account_id = account["account_id"]
    full = mode == "full"
    errors = collect.CollectionErrors()
    snapshots: dict[str, collect.WebAclSnapshot] = {}
    associations: dict[str, str] = {}
    version_cache: dict = {}

    scopes = [("REGIONAL", region) for region in account["regions"]] + [("CLOUDFRONT", collect.CLOUDFRONT_REGION)]
    for scope, region in scopes:
        wafv2 = clients("wafv2", region)
        try:
            summaries = collect.list_web_acls(wafv2, scope)
        except ClientError as exc:
            errors.record("webacl_inventory", f"{scope}/{region}", exc)
            continue
        for summary in summaries:
            try:
                snap = collect.describe_web_acl(wafv2, summary, scope, region, errors)
            except ClientError as exc:
                errors.record("webacl_inventory", summary.get("Name", "?"), exc)
                continue
            if full:
                collect.resolve_managed_versions(wafv2, snap, errors, version_cache)
                associations.update(collect.web_acl_resources(wafv2, snap, errors))
            snapshots[snap.arn] = snap

    endpoints: list[collect.DiscoveredEndpoint] = []
    complete_scopes: set[tuple[str, str]] = set()
    if full:
        for region in account["regions"]:
            for ep_type, discover in (
                ("ALB", lambda r: collect.discover_albs(clients("elbv2", r), r, associations)),
                ("APIGW", lambda r: collect.discover_api_gateways(clients("apigateway", r), r)),
            ):
                try:
                    endpoints += discover(region)
                    complete_scopes.add((region, ep_type))
                except ClientError as exc:
                    errors.record("endpoint_discovery", f"{ep_type}/{region}", exc)
        try:
            endpoints += collect.discover_cloudfront(clients("cloudfront", collect.CLOUDFRONT_REGION))
            complete_scopes.add(("global", "CLOUDFRONT"))
        except ClientError as exc:
            errors.record("endpoint_discovery", "CLOUDFRONT", exc)

    totals: dict = {}
    for region in {s.region for s in snapshots.values()}:
        regional = [s for s in snapshots.values() if s.region == region]
        totals.update(collect.metric_totals(clients("cloudwatch", region), regional, now, errors))

    inserted = 0
    with db.transaction() as cur:
        webacl_db_ids = {}
        associated: dict[str, list[str]] = {}
        for ep in endpoints:
            if ep.webacl_arn:
                associated.setdefault(ep.webacl_arn, []).append(ep.resource_arn)
        for snap in snapshots.values():
            config = store.config_document(snap, associated.get(snap.arn, [])) if full else None
            webacl_db_ids[snap.arn] = store.save_web_acl(cur, account_id, snap, config)
            store.save_rules(cur, account_id, webacl_db_ids[snap.arn], snap)
            store.save_metric_totals(cur, webacl_db_ids[snap.arn], snap, totals)
        if full:
            store.save_endpoints(cur, account_id, endpoints, snapshots, webacl_db_ids, complete_scopes)

    # Sampled requests are written per WebACL after the inventory commit so a slow sample call can't hold
    # the inventory transaction open.
    for snap in snapshots.values():
        events = collect.sampled_events(clients("wafv2", snap.region), snap, webacl_db_ids[snap.arn], account_id,
                                        now, errors)
        with db.transaction() as cur:
            inserted += insert_events(cur, events)

    with db.transaction() as cur:
        status = store.save_account(cur, account_id, list(snapshots.values()), errors.items, full, now)
        db.upsert_health(
            cur, component="collector", account_id=account_id, status=status,
            detail=f"{mode} sync: {len(snapshots)} WebACLs, {len(endpoints)} endpoints, {inserted} new events",
            error="; ".join(errors.items)[:4000] or None, affected_modules=sorted(errors.modules), success=True,
        )

    summary = {"account_id": account_id, "mode": mode, "status": status, "webacls": len(snapshots),
               "endpoints": len(endpoints), "events_inserted": inserted, "errors": errors.items}
    log.info("collector summary %s", summary)
    return summary


def lambda_handler(event: dict, _context) -> dict:
    account = event["account"]
    clients = assume_discovery_role(account["discovery_role_arn"], account["account_id"])
    return collect_account(account, event.get("mode", "telemetry"), clients)
