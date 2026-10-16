"""Read-only AWS collection for one account (through SASWafDiscoveryRole). No database access here.

Every function takes boto3 clients so tests can pass stubs/fakes. Call counts are kept low on purpose:
WebACL<->resource associations come from ListResourcesForWebACL (one call per WebACL) instead of
GetWebACLForResource per load balancer.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

from common.aws import raise_if_throttled
from common.normalize import DEFAULT_ACTION_RULE, from_sampled_request

CLOUDFRONT_REGION = "us-east-1"  # CloudFront-scope WAFv2 and CloudFront APIs are global, served from us-east-1
SAMPLE_WINDOW = timedelta(minutes=30)
SAMPLE_MAX_ITEMS = 500
METRIC_WINDOW = timedelta(hours=24)
ENFORCING_ACTIONS = {"BLOCK", "CAPTCHA", "CHALLENGE"}


@dataclass
class WebAclSnapshot:
    arn: str
    id: str
    name: str
    scope: str  # REGIONAL | CLOUDFRONT
    region: str
    default_action: str
    capacity: int
    metric_name: str
    sampled_enabled: bool
    rules: list[dict]  # normalized rule rows, see parse_rule()
    logging_destination: str | None
    raw: dict  # full WebACL JSON, used as the initial drift baseline

    @property
    def visibility_level(self) -> str:
        if self.logging_destination:
            return "full"
        if self.sampled_enabled or any(r["sampled_enabled"] for r in self.rules):
            return "sampled"
        return "metrics"

    @property
    def enforcing(self) -> bool:
        """At least one rule (or the default action) can actually stop a request."""
        return self.default_action == "BLOCK" or any(r["action"] in ENFORCING_ACTIONS for r in self.rules)


@dataclass
class DiscoveredEndpoint:
    resource_arn: str
    name: str
    type: str  # ALB | CLOUDFRONT | APIGW
    region: str
    dns_name: str
    internet_facing: bool
    webacl_arn: str | None


@dataclass
class CollectionErrors:
    """Non-fatal per-API failures; the account is reported DEGRADED with these as evidence."""

    items: list[str] = field(default_factory=list)
    modules: set[str] = field(default_factory=set)

    def record(self, module: str, where: str, exc: ClientError) -> None:
        raise_if_throttled(exc)  # throttling escapes so Step Functions retries the whole (idempotent) account
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        self.items.append(f"{module} {where}: {code}")
        self.modules.add(module)


# --- WebACLs and rules ----------------------------------------------------------------------------


def _action(rule: dict) -> str:
    if "Action" in rule:
        return next(iter(rule["Action"])).upper()
    override = rule.get("OverrideAction", {})
    # Rule-group references: "None" means the group's own rule actions apply (managed groups block).
    return "COUNT" if "Count" in override else "BLOCK"


def parse_rule(rule: dict) -> dict:
    statement = rule.get("Statement", {})
    managed = statement.get("ManagedRuleGroupStatement")
    rate = statement.get("RateBasedStatement")
    group_ref = statement.get("RuleGroupReferenceStatement")
    if managed:
        kind = "MANAGED"
    elif rate:
        kind = "RATE_BASED"
    elif "IPSetReferenceStatement" in statement:
        kind = "IP_SET"
    else:
        kind = "CUSTOM"
    container = managed or group_ref or {}
    excluded = [r["Name"] for r in container.get("ExcludedRules", [])]
    excluded += [o["Name"] for o in container.get("RuleActionOverrides", []) if "Count" in o.get("ActionToUse", {})]
    scope_down = (managed or rate or {}).get("ScopeDownStatement")
    visibility = rule.get("VisibilityConfig", {})
    return {
        "name": rule["Name"],
        "priority": rule.get("Priority", 0),
        "type": kind,
        "action": _action(rule),
        "statement": statement,
        "vendor_name": managed.get("VendorName") if managed else None,
        "managed_group_name": managed.get("Name") if managed else None,
        "current_version": managed.get("Version") if managed else None,
        "available_version": None,
        "version_status": None,
        "excluded_rules": excluded,
        "scope_down_statement": str(scope_down) if scope_down else None,
        "rate_limit": rate.get("Limit") if rate else None,
        "metric_name": visibility.get("MetricName", rule["Name"]),
        "sampled_enabled": bool(visibility.get("SampledRequestsEnabled", False)),
    }


def list_web_acls(wafv2, scope: str) -> list[dict]:
    summaries, marker = [], None
    while True:
        kwargs = {"Scope": scope, "Limit": 100, **({"NextMarker": marker} if marker else {})}
        page = wafv2.list_web_acls(**kwargs)
        summaries.extend(page.get("WebACLs", []))
        marker = page.get("NextMarker")
        if not marker or not page.get("WebACLs"):
            return summaries


def describe_web_acl(wafv2, summary: dict, scope: str, region: str, errors: CollectionErrors) -> WebAclSnapshot:
    acl = wafv2.get_web_acl(Name=summary["Name"], Scope=scope, Id=summary["Id"])["WebACL"]
    destination = None
    try:
        config = wafv2.get_logging_configuration(ResourceArn=acl["ARN"])["LoggingConfiguration"]
        destination = (config.get("LogDestinationConfigs") or [None])[0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "WAFNonexistentItemException":  # = logging disabled
            errors.record("logging_visibility", acl["Name"], exc)
    visibility = acl.get("VisibilityConfig", {})
    return WebAclSnapshot(
        arn=acl["ARN"], id=acl["Id"], name=acl["Name"], scope=scope, region=region,
        default_action=next(iter(acl.get("DefaultAction", {"Allow": {}}))).upper(), capacity=acl.get("Capacity", 0),
        metric_name=visibility.get("MetricName", acl["Name"]),
        sampled_enabled=bool(visibility.get("SampledRequestsEnabled", False)),
        rules=[parse_rule(r) for r in acl.get("Rules", [])], logging_destination=destination, raw=acl,
    )


def version_status(pinned: str | None, available: list[str], default: str | None) -> str:
    """CURRENT: unpinned (tracks AWS default) or pinned at/after the default. OUTDATED: pinned before the
    default. DEPRECATED: pinned version no longer offered by AWS. UNKNOWN: AWS returned no version data."""
    if pinned is None:
        return "CURRENT"
    if not available:
        return "UNKNOWN"
    if pinned not in available:
        return "DEPRECATED"
    if default is None or default not in available:
        return "UNKNOWN"
    # `available` is sorted newest first (by LastUpdateTimestamp) in resolve_managed_versions.
    return "CURRENT" if available.index(pinned) <= available.index(default) else "OUTDATED"


def resolve_managed_versions(wafv2, snapshot: WebAclSnapshot, errors: CollectionErrors, cache: dict) -> None:
    for rule in snapshot.rules:
        if rule["type"] != "MANAGED":
            continue
        key = (rule["vendor_name"], rule["managed_group_name"], snapshot.scope)
        if key not in cache:
            try:
                resp = wafv2.list_available_managed_rule_group_versions(
                    VendorName=key[0], Name=key[1], Scope=key[2], Limit=100
                )
                versions = sorted(resp.get("Versions", []), key=lambda v: v.get("LastUpdateTimestamp") or 0,
                                  reverse=True)
                cache[key] = ([v["Name"] for v in versions], resp.get("CurrentDefaultVersion"))
            except ClientError as exc:
                errors.record("managed_rule_versions", f"{key[0]}/{key[1]}", exc)
                cache[key] = ([], None)
        available, default = cache[key]
        rule["available_version"] = default or rule["current_version"]
        rule["version_status"] = version_status(rule["current_version"], available, default)
        if rule["current_version"] is None:
            rule["current_version"] = default  # unpinned groups run the AWS default version


def web_acl_resources(wafv2, snapshot: WebAclSnapshot, errors: CollectionErrors) -> dict[str, str]:
    """resource ARN -> WebACL ARN for regional associations (CloudFront associations live on distributions)."""
    if snapshot.scope != "REGIONAL":
        return {}
    mapping = {}
    for resource_type in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY"):
        try:
            arns = wafv2.list_resources_for_web_acl(WebACLArn=snapshot.arn, ResourceType=resource_type)
            mapping.update({arn: snapshot.arn for arn in arns.get("ResourceArns", [])})
        except ClientError as exc:
            errors.record("waf_coverage", f"{snapshot.name}/{resource_type}", exc)
    return mapping


# --- endpoints ------------------------------------------------------------------------------------


def discover_albs(elbv2, region: str, associations: dict[str, str]) -> list[DiscoveredEndpoint]:
    found = []
    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers", []):
            if lb.get("Type") != "application":  # only ALBs can carry a WAFv2 WebACL
                continue
            found.append(DiscoveredEndpoint(
                resource_arn=lb["LoadBalancerArn"], name=lb["LoadBalancerName"], type="ALB", region=region,
                dns_name=lb["DNSName"], internet_facing=lb.get("Scheme") == "internet-facing",
                webacl_arn=associations.get(lb["LoadBalancerArn"]),
            ))
    return found


def discover_api_gateways(apigateway, region: str) -> list[DiscoveredEndpoint]:
    """REST API stages (HTTP APIs / apigatewayv2 cannot be associated with WAF and are out of scope)."""
    found = []
    for page in apigateway.get_paginator("get_rest_apis").paginate():
        for api in page.get("items", []):
            types = api.get("endpointConfiguration", {}).get("types", [])
            for stage in apigateway.get_stages(restApiId=api["id"]).get("item", []):
                found.append(DiscoveredEndpoint(
                    resource_arn=f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage['stageName']}",
                    name=f"{api.get('name', api['id'])}/{stage['stageName']}", type="APIGW", region=region,
                    dns_name=f"{api['id']}.execute-api.{region}.amazonaws.com", internet_facing="PRIVATE" not in types,
                    webacl_arn=stage.get("webAclArn"),
                ))
    return found


def discover_cloudfront(cloudfront) -> list[DiscoveredEndpoint]:
    found = []
    for page in cloudfront.get_paginator("list_distributions").paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            webacl = dist.get("WebACLId") or None
            found.append(DiscoveredEndpoint(
                resource_arn=dist["ARN"], name=(dist.get("Aliases", {}).get("Items") or [dist["Id"]])[0],
                type="CLOUDFRONT", region="global", dns_name=dist["DomainName"], internet_facing=True,
                # Only WAFv2 associations count; a WAF Classic ID is not a WAFv2 WebACL.
                webacl_arn=webacl if webacl and webacl.startswith("arn:aws:wafv2:") else None,
            ))
    return found


def waf_status(endpoint: DiscoveredEndpoint, snapshots: dict[str, WebAclSnapshot]) -> str:
    if endpoint.webacl_arn is None:
        return "UNPROTECTED"
    snapshot = snapshots.get(endpoint.webacl_arn)
    if snapshot is None:
        return "UNKNOWN"  # attached to a WebACL we could not read
    return "PROTECTED" if snapshot.enforcing else "PARTIALLY_PROTECTED"


# --- telemetry ------------------------------------------------------------------------------------


def sampled_events(wafv2, snapshot: WebAclSnapshot, webacl_db_id, account_id: str, now: datetime,
                   errors: CollectionErrors) -> list[dict]:
    """GetSampledRequests samples at most 500 of the first 5,000 requests *per RuleMetricName*, so query the
    WebACL default-action metric and every rule's metric separately (TRD 3.2)."""
    metrics = [(snapshot.metric_name, DEFAULT_ACTION_RULE, snapshot.sampled_enabled)]
    metrics += [(r["metric_name"], r["name"], r["sampled_enabled"]) for r in snapshot.rules]
    rows: dict[str, dict] = {}
    for metric_name, rule_name, enabled in metrics:
        if not enabled:
            continue
        try:
            resp = wafv2.get_sampled_requests(
                WebAclArn=snapshot.arn, RuleMetricName=metric_name, Scope=snapshot.scope,
                TimeWindow={"StartTime": now - SAMPLE_WINDOW, "EndTime": now}, MaxItems=SAMPLE_MAX_ITEMS,
            )
        except ClientError as exc:
            errors.record("sampled_requests", f"{snapshot.name}/{metric_name}", exc)
            continue
        for sample in resp.get("SampledRequests", []):
            row = from_sampled_request(
                sample, webacl_arn=snapshot.arn, webacl_db_id=webacl_db_id, account_id=account_id, rule_name=rule_name
            )
            rows[row["event_hash"]] = row  # in-batch dedup; DB dedups across runs
    return list(rows.values())


def metric_totals(cloudwatch, snapshots: list[WebAclSnapshot], now: datetime,
                  errors: CollectionErrors) -> dict[tuple[str, str], dict[str, int]]:
    """Exact 24h Allowed/Blocked/Counted sums from CloudWatch, keyed by (WebACL ARN, rule metric | "ALL")."""
    queries, keys = [], {}
    for snapshot in snapshots:
        for rule_metric in ["ALL", *(r["metric_name"] for r in snapshot.rules)]:
            dims = [{"Name": "WebACL", "Value": snapshot.name}, {"Name": "Rule", "Value": rule_metric}]
            if snapshot.scope == "REGIONAL":
                dims.append({"Name": "Region", "Value": snapshot.region})
            for metric in ("AllowedRequests", "BlockedRequests", "CountedRequests"):
                query_id = f"q{len(queries)}"
                keys[query_id] = ((snapshot.arn, rule_metric), metric)
                queries.append({
                    "Id": query_id, "ReturnData": True,
                    "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": dims},
                                   "Period": int(METRIC_WINDOW.total_seconds()), "Stat": "Sum"},
                })
    totals: dict[tuple[str, str], dict[str, int]] = {}
    for start in range(0, len(queries), 500):  # GetMetricData accepts at most 500 queries per call
        try:
            token = None
            while True:
                kwargs = {"MetricDataQueries": queries[start:start + 500], "StartTime": now - METRIC_WINDOW,
                          "EndTime": now, **({"NextToken": token} if token else {})}
                resp = cloudwatch.get_metric_data(**kwargs)
                for result in resp.get("MetricDataResults", []):
                    key, metric = keys[result["Id"]]
                    totals.setdefault(key, {})[metric] = totals.get(key, {}).get(metric, 0) + int(
                        sum(result.get("Values", []))
                    )
                token = resp.get("NextToken")
                if not token:
                    break
        except ClientError as exc:
            errors.record("cloudwatch_metrics", "GetMetricData", exc)
    return totals
