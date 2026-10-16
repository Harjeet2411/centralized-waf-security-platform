"""Drift/scoring and detection/campaign engines end-to-end on a seeded test database."""

import copy
import hashlib
import itertools
import json
from datetime import UTC, datetime, timedelta

import pytest

from common import db, scoring
from detection_campaign_engine.handler import campaign_code
from detection_campaign_engine.handler import lambda_handler as detect
from drift_scoring_engine.handler import diff_webacl, drift_code
from drift_scoring_engine.handler import lambda_handler as drift_score
from tests.conftest import query

JA4_CAMPAIGN = "t13d1516h2_8daaf6152771_b186095e22b6"
JA4_LOGIN = "t13d1715h2_5b57614c22b0_3d5424432f57"
_SEQ = itertools.count()

BASELINE = {
    "Name": "prod-payments-waf", "DefaultAction": {"Allow": {}},
    "Rules": [
        {"Name": "Custom-Checkout-RateLimit", "Action": {"Block": {}}, "Statement": {"RateBasedStatement": {}}},
        {"Name": "AWS-SQLi", "OverrideAction": {"None": {}},
         "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}}},
    ],
    "_logging_destination": "arn:aws:s3:::aws-waf-logs-sas", "_associated_resources": ["arn:alb/a1"],
}


@pytest.fixture
def webacl(account):
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action, visibility_level,"
            " logging_enabled, baseline_config, current_config, requests_24h)"
            " VALUES ('r-1', 'arn:waf:r-1', 'prod-payments-waf', %s, 'eu-west-1', 'REGIONAL', 'ALLOW', 'full', true,"
            " %s, %s, 1000) RETURNING id",
            (account["account_id"], json.dumps(BASELINE), json.dumps(BASELINE)),
        )
        webacl_id = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing,"
            " waf_status, webacl_id) VALUES ('arn:alb/a1', %s, 'alb-1', 'ALB', 'eu-west-1', 'a1', true,"
            " 'PROTECTED', %s), ('arn:alb/a2', %s, 'alb-2', 'ALB', 'eu-west-1', 'a2', true, 'UNPROTECTED', NULL)",
            (account["account_id"], webacl_id, account["account_id"]),
        )
    return webacl_id


def set_current(webacl_id, doc):
    with db.transaction() as cur:
        cur.execute("UPDATE web_acls SET current_config = %s WHERE id = %s", (json.dumps(doc), webacl_id))


# --- drift ------------------------------------------------------------------------------------------

def test_diff_detects_downgrade_removal_logging_and_association():
    current = copy.deepcopy(BASELINE)
    current["Rules"][0]["Action"] = {"Count": {}}
    current["Rules"].pop(1)
    current["_logging_destination"] = None
    current["_associated_resources"] = []
    findings = {(f["drift_type"], f["subject"]): f["severity"] for f in diff_webacl(BASELINE, current)}
    assert findings == {
        ("RULE_ACTION_CHANGED", "Custom-Checkout-RateLimit"): "CRITICAL",
        ("RULE_REMOVED", "AWS-SQLi"): "CRITICAL",
        ("LOGGING_DISABLED", "logging"): "HIGH",
        ("ASSOCIATION_REMOVED", "arn:alb/a1"): "CRITICAL",
    }
    assert diff_webacl(BASELINE, copy.deepcopy(BASELINE)) == []


def test_drift_lifecycle_open_resolve_reopen(webacl):
    broken = copy.deepcopy(BASELINE)
    broken["Rules"][0]["Action"] = {"Count": {}}
    set_current(webacl, broken)
    drift_score({}, None)
    [d] = query("SELECT * FROM drift_events")
    assert d["drift_code"] == drift_code(webacl, "RULE_ACTION_CHANGED", "Custom-Checkout-RateLimit")
    assert (d["status"], d["severity"]) == ("OPEN", "CRITICAL")
    assert json.loads(d["expected_state"]) == {"rule": "Custom-Checkout-RateLimit", "action": "BLOCK"}

    set_current(webacl, BASELINE)
    drift_score({}, None)
    assert query("SELECT status FROM drift_events")[0]["status"] == "RESOLVED"

    set_current(webacl, broken)
    drift_score({}, None)
    rows = query("SELECT status FROM drift_events")
    assert [r["status"] for r in rows] == ["OPEN"]  # same finding re-opened, not duplicated


def test_scores_written_with_evidence(webacl, account):
    broken = copy.deepcopy(BASELINE)
    broken["Rules"][0]["Action"] = {"Count": {}}
    set_current(webacl, broken)
    drift_score({}, None)

    [acl] = query("SELECT security_score, score_confidence, score_evidence FROM web_acls")
    dims = {k: v["value"] for k, v in acl["score_evidence"]["dimensions"].items()}
    assert dims["drift"] == 60.0 and dims["coverage"] == 100.0 and dims["logging"] == 100.0
    assert float(acl["security_score"]) == scoring.waf_score(dims)
    assert acl["score_confidence"] == "FULL"

    [acct] = query("SELECT security_score, score_confidence, score_evidence FROM accounts")
    assert acct["score_evidence"]["coverage"] == {"internet_facing_endpoints": 2, "attached": 1}
    assert acct["score_evidence"]["dimensions"]["coverage"]["value"] == 50.0
    assert acct["score_confidence"] == "FULL"


# --- detection / campaigns ------------------------------------------------------------------------------

def event(webacl_id, account_id, ip, uri, minutes_ago, action="BLOCK", ja4=None, method="GET", techniques=(),
          source="FULL_LOG"):
    ts = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    key = f"{ip}|{uri}|{ts.isoformat()}|{action}|{method}|{next(_SEQ)}"
    return {"event_hash": hashlib.sha256(key.encode()).hexdigest(), "timestamp": ts, "account_id": account_id,
            "webacl_id": webacl_id, "client_ip": ip, "uri": uri, "action": action, "ja4": ja4, "method": method,
            "techniques": list(techniques), "source": source, "asn": f"AS{int(ip.split('.')[-1]) % 3 + 100}"}


def insert_events(rows):
    with db.transaction() as cur:
        cur.executemany(
            "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri, action,"
            " ja4, attack_techniques, source, asn, country) VALUES (%(event_hash)s, %(timestamp)s, %(account_id)s,"
            " %(webacl_id)s, %(client_ip)s, %(method)s, %(uri)s, %(action)s, %(ja4)s, %(techniques)s, %(source)s,"
            " %(asn)s, 'RO')",
            rows,
        )


@pytest.fixture
def traffic(webacl, account):
    acct = account["account_id"]
    rows = []
    for i in range(6):  # JA4 campaign: 6 IPs, 2 blocked SQLi probes + 1 allowed checkout request each
        ip = f"185.220.101.{40 + i}"
        rows += [event(webacl, acct, ip, "/api/v2/checkout/validate", 10 + n, "BLOCK", JA4_CAMPAIGN,
                       techniques=["SQLI"]) for n in range(2)]
        rows.append(event(webacl, acct, ip, "/api/v2/checkout/validate", 5, "ALLOW", JA4_CAMPAIGN, method="POST"))
    rows += [event(webacl, acct, "45.155.205.233", f"/scan/{n}", 3, "BLOCK") for n in range(30)]  # scanner
    rows += [event(webacl, acct, "103.75.190.12", "/login", 2, "COUNT", JA4_LOGIN, method="POST")
             for _ in range(55)]  # credential attack
    rows += [event(webacl, acct, "10.1.2.3", f"/admin/{n}", 4, "BLOCK", techniques=["SQLI"]) for n in range(5)]
    insert_events(rows)
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by)"
            " VALUES ('10.0.0.0/8', '10.0.0.0/8', 'Corp NAT', 'INTERNAL_NETWORK', 'netops', 'egress', 'test')"
        )
        cur.execute("INSERT INTO entities (type, value) VALUES ('IP', '185.220.101.42') RETURNING id")
        entity_id = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO threat_intelligence (entity_id, provider, score, classification, confidence, expires_at)"
            " VALUES (%s, 'AbuseIPDB', 98, 'malicious', 98, now() + interval '1 day'),"
            " (%s, 'VirusTotal', 100, 'malicious', 95, now() + interval '1 day')",
            (entity_id, entity_id),
        )
    return webacl


def test_detection_engine_end_to_end(traffic):
    summary = detect({}, None)
    assert summary["campaigns"] == 1

    ents = {(r["type"], r["value"]): r for r in query("SELECT * FROM entities")}
    assert {t for t, _ in ents} == {"IP", "JA4", "ASN"}
    tor = ents[("IP", "185.220.101.42")]
    assert tor["request_count"] == 3 and tor["attack_techniques"] == ["SQLI"]
    assert tor["classification"] == "MALICIOUS" and tor["risk_level"] == "CRITICAL"
    assert float(tor["business_impact"]) == 90.0  # allowed on a production checkout path
    assert tor["metadata"]["score_inputs"]["t_campaign"] > 0 and tor["metadata"]["webacls"] == ["prod-payments-waf"]
    corp = ents[("IP", "10.1.2.3")]
    assert corp["is_allow_listed"] and "Protected entity" in corp["recommended_action"]

    rels = query("SELECT relationship_type, count(*) AS n FROM entity_relationships GROUP BY 1 ORDER BY 1")
    assert {r["relationship_type"]: r["n"] for r in rels}["USES_JA4"] == 7  # 6 campaign IPs + login IP

    [camp] = query("SELECT * FROM campaigns")
    assert camp["campaign_code"] == campaign_code(JA4_CAMPAIGN) and camp["shared_ja4"] == JA4_CAMPAIGN
    assert camp["total_requests"] == 18 and camp["blocked_requests"] == 12 and camp["allowed_requests"] == 6
    assert camp["risk_level"] in ("HIGH", "CRITICAL") and camp["techniques"] == ["SQLI"]
    assert "6 IPs" in camp["attack_story"] and "full WAF logs" in camp["attack_story"]
    member_ips = query("SELECT count(*) AS n FROM entities WHERE type = 'IP' AND id = ANY(%s)", (camp["entity_ids"],))
    assert member_ips[0]["n"] == 6

    types = {r["type"] for r in query("SELECT type FROM detections")}
    assert {"SCANNER", "CREDENTIAL_ATTACK", "MALICIOUS_ALLOWED", "JA4_CORRELATION"} <= types
    [mal] = query("SELECT * FROM detections WHERE type = 'MALICIOUS_ALLOWED' AND title LIKE %s", ("%185.220.101.42",))
    assert mal["severity"] == "CRITICAL" and mal["campaign_id"] == camp["id"]

    classified = query("SELECT classification FROM waf_events WHERE client_ip = '185.220.101.42'")
    assert {r["classification"] for r in classified} == {"MALICIOUS"}


def test_detection_engine_is_idempotent(traffic):
    detect({}, None)
    first = query("SELECT type, count(*) AS n FROM detections GROUP BY type ORDER BY type")
    detect({}, None)  # nothing newly ingested: counts must not double, detections must not duplicate
    assert query("SELECT type, count(*) AS n FROM detections GROUP BY type ORDER BY type") == first
    assert query("SELECT request_count FROM entities WHERE value = '185.220.101.42'")[0]["request_count"] == 3
    assert len(query("SELECT id FROM campaigns")) == 1
