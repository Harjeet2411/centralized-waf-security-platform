import hashlib
import json

from common.normalize import event_hash, from_log_record, from_sampled_request, techniques_for
from tests.fakes import JA4, REGIONAL_ARN, sample


def test_event_hash_matches_spec_formula():
    expected = hashlib.sha256(b"arn||1.2.3.4||1700000000000||GET||/x||RuleA").hexdigest()
    assert event_hash("arn", "1.2.3.4", 1700000000000, "GET", "/x", "RuleA") == expected
    assert event_hash("arn", "1.2.3.4", 1700000000000, "GET", "/x", "RuleB") != expected  # rule is part of identity


def test_techniques_from_rule_and_group_names():
    assert techniques_for("AWS-AWSManagedRulesSQLiRuleSet") == ["SQLI"]
    assert techniques_for("AWSManagedRulesCommonRuleSet:CrossSiteScripting_BODY", "Log4JRCE") == ["XSS", "LOG4J"]
    assert techniques_for("Custom-Checkout-RateLimit") == ["RATE_ABUSE"]
    assert techniques_for(None, "allow-health-checks") == []


def test_sampled_request_extracts_headers_ja4_and_group_rule():
    s = sample("185.220.101.43", "/pay", 5, action="ALLOW", group_rule="SQLi_BODY",
               headers=[{"Name": "CloudFront-Viewer-JA4-Fingerprint", "Value": JA4}])
    row = from_sampled_request(s, webacl_arn=REGIONAL_ARN, webacl_db_id="w", account_id="123456789012",
                               rule_name="AWS-AWSManagedRulesSQLiRuleSet")
    assert row["ja4"] == JA4 and row["ja3"] is None
    assert row["host"] == "pay.example.com" and row["user_agent"] == "python-requests/2.31"
    assert row["matched_rule_name"] == "AWS-AWSManagedRulesSQLiRuleSet:SQLi_BODY"
    assert row["rule_groups"] == ["AWS-AWSManagedRulesSQLiRuleSet"] and row["attack_techniques"] == ["SQLI"]
    assert row["source"] == "SAMPLED" and row["country"] == "DE"
    ts_ms = int(s["Timestamp"].timestamp() * 1000)
    assert row["event_hash"] == event_hash(REGIONAL_ARN, "185.220.101.43", ts_ms, "GET", "/pay",
                                           "AWS-AWSManagedRulesSQLiRuleSet:SQLi_BODY")


def test_ja4_from_label_when_no_header():
    s = sample("1.1.1.1", "/", 1, labels=[f"sas:ja4:{JA4}", "awswaf:clientip:geo:country:NL"])
    s["Request"].pop("Country")
    row = from_sampled_request(s, webacl_arn="a", webacl_db_id="w", account_id="1", rule_name="Default_Action")
    assert row["ja4"] == JA4 and row["country"] == "NL"


LOG_RECORD = {
    "timestamp": 1792238400000, "formatVersion": 1, "webaclId": REGIONAL_ARN,
    "terminatingRuleId": "AWS-AWSManagedRulesSQLiRuleSet", "terminatingRuleType": "MANAGED_RULE_GROUP",
    "action": "BLOCK", "httpSourceName": "ALB", "httpSourceId": "123456789012-app/alb-public/abc",
    "ruleGroupList": [{"ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet", "terminatingRule": {"ruleId": "SQLi_BODY"}}],
    "labels": [{"name": "awswaf:managed:aws:sql-database:SQLi_Body"}],
    "httpRequest": {"clientIp": "185.220.101.42", "country": "RO", "uri": "/api/v2/checkout/validate",
                    "args": "id=1'--", "httpVersion": "HTTP/1.1", "httpMethod": "POST", "requestId": "req-1",
                    "headers": [{"name": "Host", "value": "pay.example.com"}, {"name": "User-Agent", "value": "curl"}]},
    "ja3Fingerprint": "e7d705a3286e19ea42f587b344ee6865", "ja4Fingerprint": JA4,
}


def test_full_log_record_carries_native_fingerprints():
    row = from_log_record(LOG_RECORD, webacl_db_id="w", account_id="123456789012")
    assert row["source"] == "FULL_LOG" and row["ja4"] == JA4 and row["ja3"] == "e7d705a3286e19ea42f587b344ee6865"
    assert row["action"] == "BLOCK" and row["http_method"] == "POST" and row["country"] == "RO"
    assert "SQLI" in row["attack_techniques"]
    assert json.loads(row["http_request"])["args"] == "id=1'--"
    assert row["timestamp"].isoformat() == "2026-10-17T12:00:00+00:00"
