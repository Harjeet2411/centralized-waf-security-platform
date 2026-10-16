"""/api/v1/bootstrap honours the frontend wire contract (WAF_PLATFORM/src/types/index.ts) and maps DB values."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.schemas import contract as c
from tests.conftest import login_as

TYPES_TS = Path(__file__).resolve().parents[2] / "WAF_PLATFORM" / "src" / "types" / "index.ts"

TS_TO_SCHEMA = {
    "AWSAccount": c.AWSAccountOut, "Endpoint": c.EndpointOut, "WebACL": c.WebACLOut, "WafRule": c.WafRuleOut,
    "Entity": c.EntityOut, "ThreatIntel": c.ThreatIntelOut, "Campaign": c.CampaignOut, "Detection": c.DetectionOut,
    "DetectionEvidence": c.DetectionEvidenceOut, "Approval": c.ApprovalOut, "DriftEvent": c.DriftEventOut,
    "PlatformHealth": c.PlatformHealthOut, "CollectorHealth": c.CollectorHealthOut,
    "ComponentHealth": c.ComponentHealthOut,
}


def ts_interface_fields() -> dict[str, set[str]]:
    source = TYPES_TS.read_text(encoding="utf-8")
    interfaces = {}
    for name, body in re.findall(r"export interface (\w+) \{\n(.*?)\n\}", source, flags=re.S):
        interfaces[name] = set(re.findall(r"^  (\w+)\??:", body, flags=re.M))  # top-level fields only
    return interfaces


@pytest.mark.parametrize("ts_name", sorted(TS_TO_SCHEMA))
def test_every_ts_field_is_served(ts_name):
    ts_fields = ts_interface_fields()[ts_name]
    assert ts_fields, f"could not parse interface {ts_name} from index.ts"
    missing = ts_fields - set(TS_TO_SCHEMA[ts_name].model_fields)
    assert not missing, f"{ts_name} schema lacks TS fields {missing}"


async def test_empty_platform_bootstrap_has_no_synthetic_data(client):
    client.cookies.update(await login_as("Executive"))
    body = (await client.get("/api/v1/bootstrap")).json()
    for key in ("accounts", "endpoints", "webacls", "entities", "campaigns", "detections", "drift_events", "approvals"):
        assert body[key] == []
    assert body["rules"] == {} and body["posture_dimensions"] == []
    health = body["platform_health"]
    assert health["aws_api"]["status"] == "unavailable" and health["overall"] == "critical"
    assert health["database"]["status"] == "healthy" and health["data_freshness"] == "no sync yet"


async def seed(db) -> dict:
    now = datetime.now(UTC)
    acct = "123456789012"
    await db.execute(text(
        "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn,"
        " visibility_level, score_confidence, security_score, last_discovered, regions)"
        " VALUES (:a, 'prod-payments-04', 'production', 'payments', 'arn:d', 'arn:r', 'full', 'FULL', 81.5, :now,"
        " ARRAY['eu-west-1','us-east-1'])"
    ), {"a": acct, "now": now})
    webacl_id = await db.scalar(text(
        "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action, security_score,"
        " score_confidence, visibility_level, logging_enabled, score_evidence)"
        " VALUES ('w-1', 'arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/prod-payments-waf/w-1',"
        " 'prod-payments-waf', :a, 'eu-west-1', 'REGIONAL', 'ALLOW', 77.25, 'FULL', 'full', true,"
        " '{\"d_coverage\": 50}') RETURNING id"
    ), {"a": acct})
    await db.execute(text(
        "INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing, waf_status,"
        " webacl_id) VALUES"
        " ('arn:alb:1', :a, 'prod-payments-alb', 'ALB', 'eu-west-1', 'alb.example', true, 'PROTECTED', :w),"
        " ('arn:cf:1', :a, 'cdn-onboarding', 'CLOUDFRONT', 'global', 'd1.cloudfront.net', true, 'UNPROTECTED', NULL),"
        " ('arn:apigw:1', :a, 'internal-api', 'APIGW', 'eu-west-1', 'api.internal', false, 'UNPROTECTED', NULL)"
    ), {"a": acct, "w": webacl_id})
    rule_id = await db.scalar(text(
        "INSERT INTO rules (webacl_id, account_id, name, priority, type, action, managed_group_name, current_version,"
        " available_version, version_status, matches_24h, blocked_24h, counted_24h)"
        " VALUES (:w, :a, 'AWS-SQLi', 1, 'MANAGED', 'BLOCK', 'AWSManagedRulesSQLiRuleSet', 'Version_2.0',"
        " 'Version_2.1', 'OUTDATED', 1500, 1240, 40) RETURNING id"
    ), {"a": acct, "w": webacl_id})
    await db.execute(text(
        "INSERT INTO managed_rule_versions (webacl_id, rule_id, vendor_name, managed_group_name, current_version,"
        " available_version, version_status) VALUES (:w, :r, 'AWS', 'AWSManagedRulesSQLiRuleSet', 'Version_2.0',"
        " 'Version_2.1', 'OUTDATED')"
    ), {"w": webacl_id, "r": rule_id})
    await db.execute(text(
        "INSERT INTO drift_events (drift_code, account_id, account_name, webacl_id, webacl_name, drift_type, severity,"
        " expected_state, actual_state) VALUES ('DRF-402', :a, 'prod-payments-04', :w, 'prod-payments-waf',"
        " 'RULE_ACTION_CHANGED', 'CRITICAL', '{\"action\": \"BLOCK\"}', '{\"action\": \"COUNT\"}')"
    ), {"a": acct, "w": webacl_id})
    entity_id = await db.scalar(text(
        "INSERT INTO entities (type, value, asn, organization, ja4, threat_score, confidence, business_impact,"
        " final_risk, risk_level, classification, request_count, targeted_uris, metadata)"
        " VALUES ('IP', '185.220.101.42', 'AS4224', 'Tor Exit', 't13d1516h2_8daaf6152771_b186095e22b6', 94, 92, 95,"
        " 94, 'CRITICAL', 'MALICIOUS', 1282, ARRAY['/a','/b','/c'], '{\"not_found_ratio\": 0.4}') RETURNING id"
    ))
    await db.execute(text(
        "INSERT INTO threat_intelligence (entity_id, provider, score, classification, confidence, expires_at)"
        " VALUES (:e, 'AbuseIPDB', 98, 'malicious', 98, :exp)"
    ), {"e": entity_id, "exp": now + timedelta(hours=24)})
    campaign_id = await db.scalar(text(
        "INSERT INTO campaigns (campaign_code, name, type, status, risk_level, confidence, entity_ids, asns,"
        " targeted_accounts, total_requests, blocked_requests, allowed_requests, start_time, last_active,"
        " attack_story, recommended_action) VALUES ('CMP-2026-089', 'Coordinated SQLi', 'JA4_CORRELATION', 'ACTIVE',"
        " 'CRITICAL', 88, ARRAY[CAST(:e AS uuid)], ARRAY['AS4224'], ARRAY[:a], 4862, 4820, 42,"
        " :start, :now, 'story', 'block JA4') RETURNING id"
    ), {"e": entity_id, "a": acct, "start": now - timedelta(hours=4), "now": now})
    await db.execute(text(
        "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri, action,"
        " source) VALUES ('h1', :ts, :a, :w, '185.220.101.42', 'POST', '/api/v2/checkout/validate', 'ALLOW',"
        " 'FULL_LOG')"
    ), {"ts": now - timedelta(hours=1), "a": acct, "w": webacl_id})
    await db.execute(text(
        "INSERT INTO detections (type, title, description, severity, confidence, entity_ids, campaign_id, accounts,"
        " evidence, recommended_action) VALUES ('MALICIOUS_ALLOWED', 'Malicious allowed', 'desc', 'CRITICAL', 92,"
        " ARRAY[CAST(:e AS uuid)], :cp, ARRAY[:a], '[{\"type\": \"waf\", \"label\": \"allowed\", \"value\": \"42\"}]',"
        " 'restore BLOCK')"
    ), {"e": entity_id, "cp": campaign_id, "a": acct})
    await db.execute(text(
        "INSERT INTO approvals (approval_code, action_type, title, target, account_id, account_name, webacl_id,"
        " webacl_name, application, requested_by, requested_by_role, reason, risk_level, allow_list_check,"
        " simulation_summary, impact_scope, required_approver_role, previous_state, proposed_state)"
        " VALUES ('APR-1', 'TEMP_BLOCK_IP', 'Block', '185.220.101.42/32', :a, 'prod-payments-04', :w,"
        " 'prod-payments-waf', 'payments', 'soc@sas.test', 'SOC Analyst', 'campaign', 'CRITICAL', 'PASSED',"
        " '{\"summary\": \"4820 would block\", \"affected_accounts\": 3}', '3 accounts', 'Security Admin', '{}', '{}')"
    ), {"a": acct, "w": webacl_id})
    await db.execute(text(
        "INSERT INTO platform_health (component, status, detail) VALUES ('aws_api', 'HEALTHY', 'ok'),"
        " ('queue', 'HEALTHY', 'ok'), ('workers', 'HEALTHY', 'ok'), ('threat_intel', 'DEGRADED', 'GreyNoise 429')"
    ))
    await db.commit()
    return {"webacl_id": str(webacl_id), "entity_id": str(entity_id)}


async def test_seeded_bootstrap_maps_db_to_contract(client, db):
    ids = await seed(db)
    client.cookies.update(await login_as("SOC Analyst"))
    resp = await client.get("/api/v1/bootstrap")
    assert resp.status_code == 200
    body = resp.json()

    [account] = body["accounts"]
    assert account["environment"] == "prod" and account["status"] == "healthy"
    assert account["waf_coverage"] == 50.0  # 1 of 2 internet-facing endpoints protected; internal API ignored
    assert account["endpoint_count"] == 3 and account["webacl_count"] == 1
    assert account["logging_visibility"] == "full" and account["score_confidence"] == "FULL"
    assert account["region"] == "eu-west-1"

    types = {e["name"]: (e["type"], e["status"], e["waf_enabled"]) for e in body["endpoints"]}
    assert types["cdn-onboarding"] == ("CloudFront", "unprotected", False)
    assert types["prod-payments-alb"] == ("ALB", "protected", True)

    [webacl] = body["webacls"]
    assert webacl["rule_count"] == 1 and webacl["drift_count"] == 1 and webacl["managed_rule_health"] == 0.0
    assert webacl["score_evidence"] == {"d_coverage": 50}

    [rule] = body["rules"][ids["webacl_id"]]
    assert rule["type"] == "managed" and rule["allowed"] == 220 and rule["version_status"] == "outdated"

    [entity] = body["entities"]
    assert entity["type"] == "ip" and entity["risk_level"] == "critical" and entity["confidence"] == "high"
    assert entity["uri_diversity"] == 3 and entity["not_found_ratio"] == 0.4
    assert entity["campaigns"] == ["CMP-2026-089"]
    assert entity["threat_intel"][0]["source"] == "abuseipdb"

    [campaign] = body["campaigns"]
    assert campaign["type"] == "ja4_campaign" and campaign["ip_count"] == 1 and campaign["webacl_count"] == 1
    assert campaign["waf_action_breakdown"] == {"BLOCK": 4820, "ALLOW": 42, "COUNT": 0}

    [detection] = body["detections"]
    assert detection["type"] == "malicious_allowed" and detection["status"] == "correlated"
    assert detection["evidence_count"] == 1 and detection["entity_ids"] == [ids["entity_id"]]

    [drift] = body["drift_events"]
    assert drift["severity"] == "critical" and drift["status"] == "open"

    [approval] = body["approvals"]
    assert approval["status"] == "pending" and approval["lifecycle_stage"] == "approval"
    assert approval["simulation_result"] == "4820 would block" and approval["impact"]["affected_accounts"] == 3

    health = body["platform_health"]
    assert health["overall"] == "degraded" and health["threat_intel"]["detail"] == "GreyNoise 429"
    assert health["collectors"][0]["account_name"] == "prod-payments-04"
    assert health["data_freshness"] == "0 min ago"
