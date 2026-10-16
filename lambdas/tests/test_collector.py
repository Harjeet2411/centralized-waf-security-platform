"""account_collector end-to-end against fakes + real Postgres, plus Stubber pins of real AWS request shapes."""

import json

import boto3
import pytest
from botocore.stub import ANY, Stubber

from account_collector import collect
from account_collector.handler import collect_account
from common.aws import WAFLimitsExceededException
from fetch_accounts.handler import lambda_handler as fetch_accounts
from mark_account_degraded.handler import lambda_handler as mark_degraded
from tests.conftest import query
from tests.fakes import CF_ARN, JA4, NOW, REGIONAL_ARN, FakeAccount


def test_full_sync_writes_inventory_events_and_health(account):
    fake = FakeAccount()
    summary = collect_account(account, "full", fake, now=NOW)
    assert summary["status"] == "HEALTHY" and summary["errors"] == []

    acls = {r["name"]: r for r in query("SELECT * FROM web_acls")}
    assert acls["prod-payments-waf"]["visibility_level"] == "full"
    assert acls["prod-payments-waf"]["logging_destination"] == "arn:aws:s3:::aws-waf-logs-sas-123456789012"
    assert acls["cdn-waf"]["visibility_level"] == "sampled" and acls["cdn-waf"]["scope"] == "CLOUDFRONT"
    baseline = acls["prod-payments-waf"]["baseline_config"]
    assert baseline["ARN"] == REGIONAL_ARN and baseline == acls["prod-payments-waf"]["current_config"]
    assert baseline["_associated_resources"] == sorted([
        "arn:alb/alb-public", "arn:aws:apigateway:eu-west-1::/restapis/abc123/stages/prod"])
    assert baseline["_logging_destination"] == "arn:aws:s3:::aws-waf-logs-sas-123456789012"
    assert acls["prod-payments-waf"]["requests_24h"] == 1350 and acls["prod-payments-waf"]["blocked_24h"] == 300

    rules = {r["name"]: r for r in query("SELECT * FROM rules")}
    sqli = rules["AWS-AWSManagedRulesSQLiRuleSet"]
    assert (sqli["type"], sqli["action"], sqli["version_status"]) == ("MANAGED", "BLOCK", "OUTDATED")
    assert sqli["current_version"] == "Version_1.0" and sqli["available_version"] == "Version_1.5"
    assert sqli["excluded_rules"] == ["SQLi_BODY", "SQLi_QUERYARGUMENTS"]
    assert sqli["matches_24h"] == 1350 and sqli["counted_24h"] == 50
    assert rules["Custom-Checkout-RateLimit"]["type"] == "RATE_BASED" and rules["Custom-Checkout-RateLimit"][
        "rate_limit"] == 100
    assert rules["Block-BadIPs"]["type"] == "IP_SET"
    common = rules["AWS-AWSManagedRulesCommonRuleSet"]
    assert (common["action"], common["version_status"], common["current_version"]) == (
        "COUNT", "CURRENT", "Version_1.12")  # unpinned -> runs AWS default
    assert len(query("SELECT * FROM managed_rule_versions")) == 2

    endpoints = {r["name"]: r for r in query("SELECT * FROM endpoints")}
    assert "nlb-1" not in endpoints  # NLBs can't carry WAF
    assert endpoints["alb-public"]["waf_status"] == "PROTECTED" and endpoints["alb-public"]["logging_enabled"]
    assert endpoints["alb-public-onboarding-prod"]["waf_status"] == "UNPROTECTED"
    assert endpoints["alb-public-onboarding-prod"]["internet_facing"] is True
    assert endpoints["alb-internal"]["internet_facing"] is False
    assert endpoints["payments-api/prod"]["waf_status"] == "PROTECTED"
    assert endpoints["private-api/v1"]["internet_facing"] is False
    # CloudFront WebACL only counts (COUNT override, default ALLOW) -> attached but not enforcing.
    assert endpoints["cdn.example.com"]["waf_status"] == "PARTIALLY_PROTECTED"
    assert endpoints["E2"]["waf_status"] == "UNPROTECTED" and endpoints["E2"]["region"] == "global"

    events = query("SELECT * FROM waf_events ORDER BY timestamp")
    assert len(events) == 4  # duplicate SQLi sample collapsed by event_hash
    assert {e["source"] for e in events} == {"SAMPLED"}
    by_ip = {str(e["client_ip"]): e for e in events}
    assert by_ip["185.220.101.43"]["ja4"] == JA4 and by_ip["185.220.101.43"]["action"] == "ALLOW"
    assert by_ip["185.220.101.42"]["attack_techniques"] == ["SQLI"]
    assert by_ip["185.220.101.44"]["country"] == "DE"
    assert by_ip["203.0.113.9"]["ja4"] == JA4  # from sas:ja4: label on the CloudFront sample

    [acct] = query("SELECT * FROM accounts")
    assert acct["status"] == "HEALTHY" and acct["visibility_level"] == "full" and acct["logging_enabled"]
    assert acct["last_discovered"] == NOW and acct["score_confidence"] == "SAMPLED"  # scoring engine owns this
    [health] = query("SELECT * FROM platform_health")
    assert health["component"] == "collector" and health["status"] == "HEALTHY" and health["last_success"]


def test_sampled_requests_queried_per_rule_metric(account):
    fake = FakeAccount()
    collect_account(account, "telemetry", fake, now=NOW)
    sampled = [c[1] for w in fake.wafv2.values() for c in w.calls if c[0] == "get_sampled_requests"]
    # Default-action metric + every rule metric with sampling enabled; BadIPs has sampling disabled.
    assert sorted(sampled) == ["Common", "RateLimit", "SQLi", "cdnWaf", "prodPayments"]


def test_sync_is_idempotent(account):
    for _ in range(2):
        collect_account(account, "full", FakeAccount(), now=NOW)
    assert len(query("SELECT * FROM waf_events")) == 4
    assert len(query("SELECT * FROM endpoints")) == 7
    assert len(query("SELECT * FROM rules")) == 4
    assert len(query("SELECT * FROM managed_rule_versions")) == 2


def test_telemetry_mode_skips_discovery(account):
    fake = FakeAccount()
    collect_account(account, "telemetry", fake, now=NOW)
    services = {s for s, _ in fake.services_called}
    assert services == {"wafv2", "cloudwatch"}
    assert query("SELECT * FROM endpoints") == []
    assert query("SELECT last_discovered FROM accounts")[0]["last_discovered"] is None
    assert {r["baseline_config"] == {} and r["current_config"] == {} for r in query("SELECT * FROM web_acls")} == {True}


def test_removed_endpoint_is_deleted_but_failed_region_keeps_inventory(account):
    collect_account(account, "full", FakeAccount(), now=NOW)
    collect_account(account, "full", FakeAccount(onboarding_removed=True), now=NOW)
    names = {r["name"] for r in query("SELECT name FROM endpoints")}
    assert "alb-public-onboarding-prod" not in names and "alb-public" in names

    summary = collect_account(account, "full", FakeAccount(elb_denied=True), now=NOW)
    assert summary["status"] == "DEGRADED"
    assert "alb-public" in {r["name"] for r in query("SELECT name FROM endpoints")}  # not wiped
    [acct] = query("SELECT status, last_error FROM accounts")
    assert acct["status"] == "DEGRADED" and "endpoint_discovery ALB/eu-west-1: AccessDenied" in acct["last_error"]
    [health] = query("SELECT * FROM platform_health")
    assert health["status"] == "DEGRADED" and health["affected_modules"] == ["endpoint_discovery"]


def test_throttling_escapes_for_step_functions_retry(account):
    with pytest.raises(WAFLimitsExceededException):
        collect_account(account, "full", FakeAccount(throttle=True), now=NOW)


def test_version_status_rules():
    available = ["Version_2.0", "Version_1.5", "Version_1.0"]  # newest first
    assert collect.version_status(None, available, "Version_1.5") == "CURRENT"
    assert collect.version_status("Version_2.0", available, "Version_1.5") == "CURRENT"
    assert collect.version_status("Version_1.0", available, "Version_1.5") == "OUTDATED"
    assert collect.version_status("Version_0.9", available, "Version_1.5") == "DEPRECATED"
    assert collect.version_status("Version_1.0", [], None) == "UNKNOWN"


# --- helper Lambdas ---------------------------------------------------------------------------------


def test_fetch_accounts_emits_map_items(account):
    out = fetch_accounts({"mode": "full"}, None)
    assert out == {"mode": "full", "accounts": [account]}
    with pytest.raises(ValueError):
        fetch_accounts({"mode": "everything"}, None)


@pytest.mark.parametrize(("error", "status", "confidence"), [
    ("AccountAccessError", "UNAVAILABLE", "NONE"),
    ("States.Timeout", "DEGRADED", "SAMPLED"),
])
def test_mark_account_degraded(account, error, status, confidence):
    cause = json.dumps({"errorMessage": "AssumeRole failed: AccessDenied"})
    out = mark_degraded({"account": account, "mode": "full", "error": {"Error": error, "Cause": cause}}, None)
    assert out["status"] == status
    [acct] = query("SELECT status, score_confidence, last_error FROM accounts")
    assert (acct["status"], acct["score_confidence"]) == (status, confidence)
    assert error in acct["last_error"]
    [health] = query("SELECT status, last_success FROM platform_health")
    assert health["status"] == status and health["last_success"] is None


# --- request shapes pinned against botocore service models -----------------------------------------


def test_get_sampled_requests_params_match_wafv2_model():
    wafv2 = boto3.client("wafv2", region_name="eu-west-1")
    snap = collect.WebAclSnapshot(
        arn=REGIONAL_ARN, id="r-1", name="prod-payments-waf", scope="REGIONAL", region="eu-west-1",
        default_action="ALLOW", capacity=1, metric_name="prodPayments", sampled_enabled=True,
        rules=[collect.parse_rule({"Name": "R", "Priority": 1, "Action": {"Block": {}}, "Statement": {},
                                   "VisibilityConfig": {"MetricName": "RMetric", "SampledRequestsEnabled": True,
                                                        "CloudWatchMetricsEnabled": True}})],
        logging_destination=None, raw={},
    )
    with Stubber(wafv2) as stub:
        for metric in ("prodPayments", "RMetric"):
            stub.add_response(
                "get_sampled_requests",
                {"SampledRequests": [], "PopulationSize": 0, "TimeWindow": {"StartTime": NOW, "EndTime": NOW}},
                {"WebAclArn": REGIONAL_ARN, "RuleMetricName": metric, "Scope": "REGIONAL",
                 "TimeWindow": {"StartTime": ANY, "EndTime": ANY}, "MaxItems": 500},
            )
        assert collect.sampled_events(wafv2, snap, "w", "123456789012", NOW, collect.CollectionErrors()) == []
        stub.assert_no_pending_responses()


def test_metric_queries_match_cloudwatch_model():
    cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")
    snap = collect.WebAclSnapshot(
        arn=CF_ARN, id="c-1", name="cdn-waf", scope="CLOUDFRONT", region="us-east-1", default_action="ALLOW",
        capacity=1, metric_name="cdnWaf", sampled_enabled=True, rules=[], logging_destination=None, raw={},
    )
    with Stubber(cloudwatch) as stub:
        stub.add_response("get_metric_data", {"MetricDataResults": [
            {"Id": "q0", "Values": [5.0]}, {"Id": "q1", "Values": [2.0]}, {"Id": "q2", "Values": []},
        ]}, {"MetricDataQueries": ANY, "StartTime": ANY, "EndTime": ANY})
        totals = collect.metric_totals(cloudwatch, [snap], NOW, collect.CollectionErrors())
    assert totals[(CF_ARN, "ALL")] == {"AllowedRequests": 5, "BlockedRequests": 2, "CountedRequests": 0}


def test_list_versions_and_resources_params_match_wafv2_model():
    wafv2 = boto3.client("wafv2", region_name="eu-west-1")
    snap = collect.WebAclSnapshot(
        arn=REGIONAL_ARN, id="r-1", name="w", scope="REGIONAL", region="eu-west-1", default_action="ALLOW",
        capacity=1, metric_name="m", sampled_enabled=False,
        rules=[collect.parse_rule({"Name": "M", "Priority": 1, "OverrideAction": {"None": {}}, "Statement": {
            "ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}},
            "VisibilityConfig": {"MetricName": "M", "SampledRequestsEnabled": False,
                                 "CloudWatchMetricsEnabled": True}})],
        logging_destination=None, raw={},
    )
    with Stubber(wafv2) as stub:
        stub.add_response("list_available_managed_rule_group_versions",
                          {"Versions": [{"Name": "Version_1.0"}], "CurrentDefaultVersion": "Version_1.0"},
                          {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet", "Scope": "REGIONAL",
                           "Limit": 100})
        for resource_type in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY"):
            stub.add_response("list_resources_for_web_acl", {"ResourceArns": []},
                              {"WebACLArn": REGIONAL_ARN, "ResourceType": resource_type})
        errors = collect.CollectionErrors()
        collect.resolve_managed_versions(wafv2, snap, errors, {})
        collect.web_acl_resources(wafv2, snap, errors)
        stub.assert_no_pending_responses()
    assert snap.rules[0]["version_status"] == "CURRENT" and errors.items == []
