"""Milestone 3 read APIs: WebACLs, endpoints, entities (+ investigation graph / 'why allowed'), campaigns, posture."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from tests.conftest import login_as

ACCT, OTHER = "123456789012", "210987654321"
JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"


@pytest.fixture
async def seeded(db):
    now = datetime.now(UTC)
    for acct, name in ((ACCT, "prod-payments-04"), (OTHER, "prod-other-07")):
        await db.execute(text(
            "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn,"
            " security_score, score_evidence) VALUES (:a, :n, 'production', 'o', 'arn:d', 'arn:r', 72.5, :ev)"
        ), {"a": acct, "n": name, "ev": json.dumps({"dimensions": {
            k: {"value": 80.0, "weight": 0.1} for k in ("coverage", "blocking", "malicious_allowed", "count_exposure",
                                                       "drift", "managed_versions", "logging")}})})
    w = await db.scalar(text(
        "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action)"
        " VALUES ('r-1', 'arn:waf:r-1', 'prod-payments-waf', :a, 'eu-west-1', 'REGIONAL', 'ALLOW') RETURNING id"
    ), {"a": ACCT})
    await db.execute(text(
        "INSERT INTO rules (webacl_id, account_id, name, priority, type, action) VALUES"
        " (:w, :a, 'AWS-SQLi', 1, 'MANAGED', 'BLOCK'), (:w, :a, 'Custom-Checkout-RateLimit', 2, 'RATE_BASED', 'COUNT')"
    ), {"w": w, "a": ACCT})
    await db.execute(text(
        "INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing, waf_status,"
        " webacl_id) VALUES ('arn:alb/1', :a, 'prod-payments-alb', 'ALB', 'eu-west-1', 'x', true, 'PROTECTED', :w),"
        " ('arn:alb/2', :a, 'alb-public-onboarding-prod', 'ALB', 'eu-west-1', 'y', true, 'UNPROTECTED', NULL)"
    ), {"w": w, "a": ACCT})
    await db.execute(text(
        "INSERT INTO drift_events (drift_code, account_id, account_name, webacl_id, webacl_name, drift_type, severity,"
        " expected_state, actual_state) VALUES ('DRF-402', :a, 'prod-payments-04', :w, 'prod-payments-waf',"
        " 'RULE_ACTION_CHANGED', 'CRITICAL', '{\"action\": \"BLOCK\"}', '{\"action\": \"COUNT\"}')"
    ), {"w": w, "a": ACCT})
    ip = await db.scalar(text(
        "INSERT INTO entities (type, value, ja4, risk_level, final_risk, threat_score, targeted_accounts,"
        " recommended_action) VALUES ('IP', '185.220.101.42', :j, 'CRITICAL', 94, 94, ARRAY[:a], 'Simulate block')"
        " RETURNING id"
    ), {"j": JA4, "a": ACCT})
    peer = await db.scalar(text(
        "INSERT INTO entities (type, value, risk_level, targeted_accounts) VALUES ('IP', '185.220.101.43', 'HIGH',"
        " ARRAY[:a]) RETURNING id"), {"a": ACCT})
    ja4 = await db.scalar(text("INSERT INTO entities (type, value) VALUES ('JA4', :j) RETURNING id"), {"j": JA4})
    await db.execute(text(
        "INSERT INTO entity_relationships (source_entity_id, target_entity_id, relationship_type, observation_count)"
        " VALUES (:ip, :ja4, 'USES_JA4', 12), (:peer, :ja4, 'USES_JA4', 4)"
    ), {"ip": ip, "peer": peer, "ja4": ja4})
    for i, (action, cls, rule) in enumerate([("BLOCK", "MALICIOUS", "AWS-SQLi"), ("BLOCK", "MALICIOUS", "AWS-SQLi"),
                                            ("ALLOW", "MALICIOUS", "Custom-Checkout-RateLimit")]):
        await db.execute(text(
            "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri,"
            " action, classification, matched_rule_name, ja4, source) VALUES (:h, :ts, :a, :w, '185.220.101.42',"
            " 'POST', '/api/v2/checkout/validate', :act, :cls, :rule, :j, 'FULL_LOG')"
        ), {"h": f"h{i}", "ts": now - timedelta(minutes=10 + i), "a": ACCT, "w": w, "act": action, "cls": cls,
            "rule": rule, "j": JA4})
    campaign = await db.scalar(text(
        "INSERT INTO campaigns (campaign_code, name, type, risk_level, confidence, entity_ids, targeted_accounts,"
        " start_time, last_active, attack_story, recommended_action, correlation_evidence)"
        " VALUES ('CMP-2026-089', 'Coordinated SQLi', 'JA4_CORRELATION', 'CRITICAL', 90, ARRAY[CAST(:ip AS uuid),"
        " CAST(:peer AS uuid)], ARRAY[:a], :s, :n, 'story', 'block', '[{\"type\": \"shared_ja4\"}]') RETURNING id"
    ), {"ip": ip, "peer": peer, "a": ACCT, "s": now - timedelta(hours=4), "n": now})
    await db.commit()
    return {"webacl": str(w), "ip": str(ip), "campaign": str(campaign)}


async def test_webacls_and_endpoints(client, seeded):
    client.cookies.update(await login_as("Read Only"))
    [acl] = (await client.get("/api/v1/webacls")).json()
    assert acl["rule_count"] == 2 and acl["drift_count"] == 1
    assert [r["name"] for r in acl["rules"]] == ["AWS-SQLi", "Custom-Checkout-RateLimit"]
    unprotected = (await client.get("/api/v1/endpoints", params={"waf_status": "unprotected"})).json()
    assert [e["name"] for e in unprotected] == ["alb-public-onboarding-prod"]


async def test_entity_list_filters_and_pagination(client, seeded):
    client.cookies.update(await login_as("Read Only"))
    page = (await client.get("/api/v1/entities", params={"type": "ip", "q": "185.220", "limit": 1})).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert page["items"][0]["value"] == "185.220.101.42"  # highest risk first


async def test_entity_investigation_graph_and_why_allowed(client, seeded):
    client.cookies.update(await login_as("SOC Analyst"))
    body = (await client.get(f"/api/v1/entities/{seeded['ip']}")).json()
    node_types = {n["type"] for n in body["graph"]["nodes"]}
    assert {"ip", "ja4", "webacl", "campaign"} <= node_types
    edge_types = {e["type"] for e in body["graph"]["edges"]}
    assert {"USES_JA4", "BLOCKED", "MALICIOUS_ALLOWED", "CAMPAIGN_MEMBER"} <= edge_types
    assert any(n["label"] == "185.220.101.43" for n in body["graph"]["nodes"])  # second hop via shared JA4
    [why] = body["allowed_explanations"]
    assert why["count_mode_rules"] == ["Custom-Checkout-RateLimit"]
    assert why["matched_rules"] == ["Custom-Checkout-RateLimit"]
    assert why["open_drift"][0]["drift_code"] == "DRF-402"
    assert body["visibility"] == {"FULL_LOG": 3}
    assert sum(b["BLOCK"] + b["ALLOW"] for b in body["timeline"]) == 3
    assert len(body["recent_events"]) == 3 and body["recommended_action"] == "Simulate block"


@pytest.mark.parametrize(("role", "scoped", "expected"), [
    ("Executive", None, 403), ("Application Owner", [OTHER], 404), ("Application Owner", [ACCT], 200),
])
async def test_entity_detail_rbac_and_scope(client, seeded, role, scoped, expected):
    client.cookies.update(await login_as(role, scoped=scoped))
    assert (await client.get(f"/api/v1/entities/{seeded['ip']}")).status_code == expected


async def test_campaign_detail(client, seeded):
    client.cookies.update(await login_as("Security Analyst"))
    assert [cp["campaign_code"] for cp in (await client.get("/api/v1/campaigns")).json()] == ["CMP-2026-089"]
    body = (await client.get(f"/api/v1/campaigns/{seeded['campaign']}")).json()
    assert [m["value"] for m in body["members"]] == ["185.220.101.42", "185.220.101.43"]
    assert body["campaign"]["ip_count"] == 2 and body["correlation_evidence"] == [{"type": "shared_ja4"}]


@pytest.mark.parametrize(("path", "message"), [
    ("/api/v1/entities?type=ipv4", "Unknown type 'ipv4'"),
    ("/api/v1/entities?risk_level=severe", "Unknown risk_level 'severe'"),
    ("/api/v1/campaigns?status=open", "Unknown status 'open'"),
])
async def test_unknown_filter_values_are_rejected(client, seeded, path, message):
    client.cookies.update(await login_as("Security Analyst"))
    resp = await client.get(path)
    assert resp.status_code == 422
    assert message in resp.json()["detail"]


async def test_filters_are_case_insensitive(client, seeded):
    client.cookies.update(await login_as("Security Analyst"))
    campaigns = (await client.get("/api/v1/campaigns?status=active")).json()
    assert [cp["campaign_code"] for cp in campaigns] == ["CMP-2026-089"]
    assert (await client.get("/api/v1/entities", params={"risk_level": "high"})).json()["total"] >= 1


async def test_bootstrap_posture_from_scored_accounts(client, seeded):
    client.cookies.update(await login_as("Executive"))
    posture = {p["key"]: p for p in (await client.get("/api/v1/bootstrap")).json()["posture_dimensions"]}
    assert posture["waf_coverage"]["value"] == 50.0  # 1 of 2 internet-facing endpoints attached
    assert posture["config_hygiene"]["value"] == 80.0 and posture["overall"]["value"] == 72.5
    assert posture["waf_coverage"]["evidence_count"] == 2


async def test_campaign_limit_is_validated(client, seeded):
    client.cookies.update(await login_as("Security Analyst"))
    assert len((await client.get("/api/v1/campaigns", params={"limit": 1})).json()) == 1
    for bad in (0, 501):
        assert (await client.get("/api/v1/campaigns", params={"limit": bad})).status_code == 422
