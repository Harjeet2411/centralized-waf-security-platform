"""Guardrails (service + DB trigger) and the read-only Rule Impact Simulator / False Positive Analyzer."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.services import guardrail_service
from tests.conftest import login_as

ACCT = "123456789012"


@pytest.mark.parametrize(("target", "ok"), [
    ("185.220.101.42", True), ("185.220.101.0/24", True), ("185.220.0.0/16", False),
    ("10.1.2.3", False), ("not-an-ip", False), ("2001:4860:4860::8888", True), ("2001:4860::/32", False),
])
def test_block_target_rails(target, ok):
    if ok:
        assert guardrail_service.parse_block_target(target)
    else:
        with pytest.raises(HTTPException) as exc:
            guardrail_service.parse_block_target(target)
        assert exc.value.status_code == 422


@pytest.fixture
async def world(db):
    await db.execute(text(
        "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn)"
        " VALUES (:a, 'prod-payments-04', 'production', 'o', 'arn:d', 'arn:r')"), {"a": ACCT})
    webacl = await db.scalar(text(
        "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action)"
        " VALUES ('r-1', 'arn:waf', 'prod-payments-waf', :a, 'eu-west-1', 'REGIONAL', 'ALLOW') RETURNING id"),
        {"a": ACCT})
    await db.execute(text(
        "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by)"
        " VALUES ('8.8.8.0/24', '8.8.8.0/24', 'Partner API', 'PARTNER_API', 'partners', 'contract', 't')"))
    now = datetime.now(UTC) - timedelta(minutes=20)
    bucket = now.replace(minute=now.minute - now.minute % 5, second=0, microsecond=0)  # one 5-min rate window
    rows = []
    rows += [("185.220.101.42", "/api/v2/checkout", "BLOCK", "MALICIOUS", "AWS-SQLi:SQLi_BODY", ["SQLI"], "JA4X")] * 5
    rows += [("185.220.101.42", "/api/v2/checkout", "ALLOW", "MALICIOUS", None, [], "JA4X")] * 2
    rows += [("8.8.8.8", "/partner/sync", "ALLOW", "LEGITIMATE", None, [], "JA4X")] * 3
    rows += [("93.184.216.34", "/pay", "COUNT", "UNKNOWN", "Custom-Checkout-RateLimit", [], None)] * 4
    rows += [("93.184.216.35", "/pay", "COUNT", "MALICIOUS", "Custom-Checkout-RateLimit", ["RATE_ABUSE"], None)] * 6
    rows += [("93.184.216.36", "/home", "BLOCK", "UNKNOWN", "AWS-SQLi:SQLi_BODY", [], None)] * 3
    rows += [("45.155.205.233", "/burst", "ALLOW", "UNKNOWN", None, [], None)] * 30
    for i, (ip, uri, action, cls, rule, tech, ja4) in enumerate(rows):
        await db.execute(text(
            "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri,"
            " action, classification, matched_rule_name, attack_techniques, ja4, source)"
            " VALUES (:h, :ts, :a, :w, :ip, 'GET', :uri, :act, :cls, :rule, :tech, :ja4, 'SAMPLED')"
        ), {"h": f"e{i}", "ts": bucket + timedelta(seconds=i % 50),
            "a": ACCT, "w": webacl, "ip": ip, "uri": uri, "act": action, "cls": cls, "rule": rule, "tech": tech,
            "ja4": ja4})
    await db.commit()
    return str(webacl)


async def simulate(client, proposal, role="SOC Analyst"):
    client.cookies.update(await login_as(role))
    return await client.post("/api/v1/simulations", json={"title": "test", "proposal": proposal})


async def test_block_ip_simulation(client, world):
    resp = await simulate(client, {"type": "BLOCK_IPS", "targets": ["185.220.101.42"]})
    assert resp.status_code == 201
    body = resp.json()
    assert (body["would_block"], body["potential_false_positives"], body["allow_list_passed"]) == (7, 0, True)
    assert body["legitimate_impact"] == "NONE" and body["visibility"] == {"FULL_LOG": 0, "SAMPLED": 7}
    assert "lower bounds" in body["visibility_note"]


async def test_simulation_flags_protected_traffic(client, world):
    body = (await simulate(client, {"type": "BLOCK_JA4", "ja4": "JA4X"})).json()
    assert body["would_block"] == 10 and body["allow_list_passed"] is False
    assert body["protected_requests_matched"] == 3 and body["potential_false_positives"] == 3


async def test_rule_action_simulation_counts_fp_candidates(client, world):
    body = (await simulate(client, {"type": "RULE_ACTION", "webacl_id": world, "rule_name": "Custom-Checkout-RateLimit",
                                    "new_action": "BLOCK"})).json()
    assert (body["would_block"], body["potential_false_positives"], body["malicious_matched"]) == (10, 4, 6)
    assert body["legitimate_impact"] == "HIGH" and len(body["false_positive_samples"]) == 4


async def test_rate_limit_simulation(client, world):
    body = (await simulate(client, {"type": "RATE_LIMIT", "webacl_id": world, "limit": 10})).json()
    assert body["would_block"] == 20  # 30 requests from one IP inside one 5-minute window, limit 10


async def test_false_positive_analyzer_and_rbac(client, world):
    client.cookies.update(await login_as("Security Analyst"))
    [candidate] = (await client.get("/api/v1/simulations/false-positives", params={"webacl_id": world})).json()
    assert (candidate["rule_name"], candidate["sub_rule"], candidate["blocked"]) == ("AWS-SQLi", "SQLi_BODY", 3)
    assert (await simulate(client, {"type": "BLOCK_JA4", "ja4": "JA4X"}, role="Executive")).status_code == 403


async def test_db_trigger_blocks_protected_targets_even_without_the_app(db, world):
    insert = text(
        "INSERT INTO approvals (approval_code, action_type, title, target, account_id, account_name, webacl_name,"
        " application, requested_by, requested_by_role, reason, risk_level, allow_list_check, impact_scope,"
        " required_approver_role, previous_state, proposed_state) VALUES (:code, 'PERM_BLOCK_IP', 't', :target,"
        " :a, 'n', 'w', '', 'x@sas.test', 'SOC Analyst', 'r', 'HIGH', 'PASSED', 's', 'Security Admin', '{}', :prop)")
    with pytest.raises(DBAPIError, match="Protected Entity"):
        await db.execute(insert, {"code": "APR-T-1", "target": "8.8.8.8/32", "a": ACCT, "prop": "{}"})
    await db.rollback()
    with pytest.raises(DBAPIError, match="Protected Entity"):  # hidden in the add list
        await db.execute(insert, {"code": "APR-T-2", "target": "185.220.101.42/32", "a": ACCT,
                                  "prop": '{"add": ["185.220.101.42/32", "8.8.8.9/32"]}'})
    await db.rollback()
