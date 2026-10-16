"""In-memory AWS fakes for one account: a regional WebACL (eu-west-1) and a CloudFront WebACL (us-east-1).

Response shapes follow the real boto3 output; tests/test_collector.py additionally pins request parameter
shapes against the botocore service models with Stubber.
"""

from datetime import UTC, datetime

from botocore.exceptions import ClientError

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGIONAL_ARN = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/webacl/prod-payments-waf/r-1"
CF_ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/cdn-waf/c-1"
JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"


def client_error(code: str, op: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


def rule(name, priority, statement, metric, sampled=True, action=None, override=None):
    r = {"Name": name, "Priority": priority, "Statement": statement,
         "VisibilityConfig": {"SampledRequestsEnabled": sampled, "CloudWatchMetricsEnabled": True,
                              "MetricName": metric}}
    if action:
        r["Action"] = {action: {}}
    else:
        r["OverrideAction"] = {override or "None": {}}
    return r


REGIONAL_ACL = {
    "Name": "prod-payments-waf", "Id": "r-1", "ARN": REGIONAL_ARN, "Capacity": 900, "DefaultAction": {"Allow": {}},
    "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                         "MetricName": "prodPayments"},
    "Rules": [
        rule("AWS-AWSManagedRulesSQLiRuleSet", 1, {"ManagedRuleGroupStatement": {
            "VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet", "Version": "Version_1.0",
            "ExcludedRules": [{"Name": "SQLi_BODY"}],
            "RuleActionOverrides": [{"Name": "SQLi_QUERYARGUMENTS", "ActionToUse": {"Count": {}}}],
        }}, "SQLi"),
        rule("Custom-Checkout-RateLimit", 2, {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
             "RateLimit", action="Count"),
        rule("Block-BadIPs", 3, {"IPSetReferenceStatement": {"ARN": "arn:ipset"}}, "BadIPs", sampled=False,
             action="Block"),
    ],
}

CF_ACL = {
    "Name": "cdn-waf", "Id": "c-1", "ARN": CF_ARN, "Capacity": 700, "DefaultAction": {"Allow": {}},
    "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "cdnWaf"},
    "Rules": [rule("AWS-AWSManagedRulesCommonRuleSet", 1, {"ManagedRuleGroupStatement": {
        "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}, "Common", override="Count")],
}


def sample(ip, uri, ts_offset_s, action="BLOCK", headers=(), labels=(), method="GET", group_rule=None):
    s = {
        "Request": {"ClientIP": ip, "Country": "DE", "URI": uri, "Method": method, "HTTPVersion": "HTTP/2.0",
                    "Headers": [{"Name": "Host", "Value": "pay.example.com"},
                                {"Name": "User-Agent", "Value": "python-requests/2.31"}, *headers]},
        "Weight": 1, "Timestamp": datetime.fromtimestamp(NOW.timestamp() - ts_offset_s, tz=UTC), "Action": action,
        "Labels": [{"Name": label} for label in labels],
    }
    if group_rule:
        s["RuleNameWithinRuleGroup"] = group_rule
    return s


SAMPLES = {
    "SQLi": [
        sample("185.220.101.42", "/api/v2/checkout/validate", 60, group_rule="SQLi_QUERYARGUMENTS"),
        sample("185.220.101.42", "/api/v2/checkout/validate", 60, group_rule="SQLi_QUERYARGUMENTS"),  # duplicate
    ],
    "prodPayments": [sample("185.220.101.43", "/api/v2/checkout/validate", 120, action="ALLOW",
                            headers=[{"Name": "CloudFront-Viewer-JA4-Fingerprint", "Value": JA4}])],
    "RateLimit": [sample("185.220.101.44", "/login", 30, action="COUNT", method="POST",
                         labels=["awswaf:clientip:geo:country:NL"])],
    "cdnWaf": [sample("203.0.113.9", "/", 10, action="ALLOW", labels=[f"sas:ja4:{JA4}"])],
}


class Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        yield from self.pages


class FakeWafv2:
    def __init__(self, region, account):
        self.region, self.account, self.calls = region, account, []

    def _acls(self, scope):
        if scope == "CLOUDFRONT":
            return [CF_ACL] if self.region == "us-east-1" else []
        return [REGIONAL_ACL] if self.region == "eu-west-1" else []

    def list_web_acls(self, Scope, Limit, **_):  # noqa: N803 - boto3 kwarg names
        self.calls.append(("list_web_acls", Scope))
        if self.account.get("throttle"):
            raise client_error("WAFLimitsExceededException", "ListWebACLs")
        return {"WebACLs": [{"Name": a["Name"], "Id": a["Id"], "ARN": a["ARN"]} for a in self._acls(Scope)]}

    def get_web_acl(self, Name, Scope, Id):  # noqa: N803
        self.calls.append(("get_web_acl", Name))
        return {"WebACL": next(a for a in self._acls(Scope) if a["Id"] == Id), "LockToken": "lock-1"}

    def get_logging_configuration(self, ResourceArn):  # noqa: N803
        if ResourceArn == REGIONAL_ARN:
            return {"LoggingConfiguration": {"ResourceArn": ResourceArn,
                                             "LogDestinationConfigs": ["arn:aws:s3:::aws-waf-logs-sas-123456789012"]}}
        raise client_error("WAFNonexistentItemException", "GetLoggingConfiguration")

    def list_available_managed_rule_group_versions(self, VendorName, Name, Scope, Limit):  # noqa: N803
        self.calls.append(("list_versions", Name))
        if Name == "AWSManagedRulesSQLiRuleSet":
            return {"CurrentDefaultVersion": "Version_1.5", "Versions": [
                {"Name": "Version_1.0", "LastUpdateTimestamp": datetime(2024, 1, 1, tzinfo=UTC)},
                {"Name": "Version_2.0", "LastUpdateTimestamp": datetime(2026, 6, 1, tzinfo=UTC)},
                {"Name": "Version_1.5", "LastUpdateTimestamp": datetime(2025, 3, 1, tzinfo=UTC)},
            ]}
        return {"CurrentDefaultVersion": "Version_1.12", "Versions": [
            {"Name": "Version_1.12", "LastUpdateTimestamp": datetime(2026, 1, 1, tzinfo=UTC)}]}

    def list_resources_for_web_acl(self, WebACLArn, ResourceType):  # noqa: N803
        if ResourceType == "APPLICATION_LOAD_BALANCER":
            return {"ResourceArns": ["arn:alb/alb-public"]}
        return {"ResourceArns": []}

    def get_sampled_requests(self, WebAclArn, RuleMetricName, Scope, TimeWindow, MaxItems):  # noqa: N803
        self.calls.append(("get_sampled_requests", RuleMetricName))
        return {"SampledRequests": SAMPLES.get(RuleMetricName, []), "PopulationSize": 10, "TimeWindow": TimeWindow}


class FakeElbv2:
    def __init__(self, account):
        self.account = account

    def get_paginator(self, _name):
        if self.account.get("elb_denied"):
            raise client_error("AccessDenied", "DescribeLoadBalancers")
        lbs = [
            {"LoadBalancerArn": "arn:alb/alb-public", "LoadBalancerName": "alb-public", "DNSName": "pub.elb",
             "Scheme": "internet-facing", "Type": "application"},
            {"LoadBalancerArn": "arn:alb/alb-internal", "LoadBalancerName": "alb-internal", "DNSName": "int.elb",
             "Scheme": "internal", "Type": "application"},
            {"LoadBalancerArn": "arn:nlb/nlb-1", "LoadBalancerName": "nlb-1", "DNSName": "nlb.elb",
             "Scheme": "internet-facing", "Type": "network"},
        ]
        if not self.account.get("onboarding_removed"):
            lbs.append({"LoadBalancerArn": "arn:alb/alb-public-onboarding-prod", "DNSName": "onb.elb",
                        "LoadBalancerName": "alb-public-onboarding-prod", "Scheme": "internet-facing",
                        "Type": "application"})
        return Paginator([{"LoadBalancers": lbs}])


class FakeApiGateway:
    def get_paginator(self, _name):
        return Paginator([{"items": [
            {"id": "abc123", "name": "payments-api", "endpointConfiguration": {"types": ["REGIONAL"]}},
            {"id": "prv999", "name": "private-api", "endpointConfiguration": {"types": ["PRIVATE"]}},
        ]}])

    def get_stages(self, restApiId):  # noqa: N803
        if restApiId == "abc123":
            return {"item": [{"stageName": "prod", "webAclArn": REGIONAL_ARN}]}
        return {"item": [{"stageName": "v1"}]}


class FakeCloudFront:
    def get_paginator(self, _name):
        return Paginator([{"DistributionList": {"Items": [
            {"Id": "E1", "ARN": "arn:cf/E1", "DomainName": "d1.cloudfront.net", "WebACLId": CF_ARN,
             "Aliases": {"Items": ["cdn.example.com"]}},
            {"Id": "E2", "ARN": "arn:cf/E2", "DomainName": "d2.cloudfront.net", "WebACLId": "",
             "Aliases": {"Quantity": 0}},
        ]}}])


class FakeCloudWatch:
    VALUES = {"AllowedRequests": [600.0, 400.0], "BlockedRequests": [300.0], "CountedRequests": [50.0]}

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **_):  # noqa: N803
        return {"MetricDataResults": [
            {"Id": q["Id"], "Values": self.VALUES[q["MetricStat"]["Metric"]["MetricName"]]} for q in MetricDataQueries
        ]}


class FakeAccount:
    """ClientFactory replacement: clients(service, region). `flags` toggles failure modes."""

    def __init__(self, **flags):
        self.flags = flags
        self.wafv2: dict[str, FakeWafv2] = {}
        self.services_called: list[tuple[str, str]] = []

    def __call__(self, service: str, region: str):
        self.services_called.append((service, region))
        if service == "wafv2":
            return self.wafv2.setdefault(region, FakeWafv2(region, self.flags))
        return {"elbv2": lambda: FakeElbv2(self.flags), "apigateway": FakeApiGateway, "cloudfront": FakeCloudFront,
                "cloudwatch": FakeCloudWatch}[service]()
