"""12-step controlled response lifecycle end-to-end: request -> guardrails -> tiered approval -> execute -> verify ->
audit -> rollback / TTL expiry, against a stateful fake WAFv2 (and botocore Stubber for real request shapes)."""

import csv
import io
import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import ANY, Stubber
from sqlalchemy import text

from app.api.v1.response import get_executor_factory
from app.main import app
from app.services.aws_executor import WafExecutor
from app.workers import ttl_expiry
from tests.conftest import login_as, user_email
from tests.fake_waf import BASE_ACL, IPSET_ARN, WEBACL_ARN, FakeExecutorFactory, FakeWafv2

ACCT, OTHER = "123456789012", "210987654321"
ATTACKER = "185.220.101.42/32"


@pytest.fixture
def waf():
    fake = FakeWafv2()
    factory = FakeExecutorFactory(fake)
    app.dependency_overrides[get_executor_factory] = lambda: factory
    yield fake, factory
    app.dependency_overrides.clear()


@pytest.fixture
async def world(db):
    await db.execute(text(
        "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn, regions)"
        " VALUES (:a, 'prod-payments-04', 'production', 'o', 'arn:d',"
        " 'arn:aws:iam::123456789012:role/SASWafResponseRole', ARRAY['eu-west-1'])"), {"a": ACCT})
    baseline = {**BASE_ACL, "_logging_destination": None, "_associated_resources": []}
    webacl = await db.scalar(text(
        "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action, baseline_config,"
        " current_config) VALUES ('r-1', :arn, 'prod-payments-waf', :a, 'eu-west-1', 'REGIONAL', 'ALLOW', :b, :b)"
        " RETURNING id"), {"arn": WEBACL_ARN, "a": ACCT, "b": json.dumps(baseline)})
    await db.execute(text(
        "INSERT INTO rules (webacl_id, account_id, name, priority, type, action, statement) VALUES"
        " (:w, :a, 'SAS-Platform-Blocklist', 0, 'IP_SET', 'BLOCK', :ipset),"
        " (:w, :a, 'AWS-SQLi', 1, 'MANAGED', 'BLOCK', '{}'),"
        " (:w, :a, 'Custom-Checkout-RateLimit', 2, 'RATE_BASED', 'COUNT', '{}')"
    ), {"w": webacl, "a": ACCT, "ipset": json.dumps({"IPSetReferenceStatement": {"ARN": IPSET_ARN}})})
    await db.execute(text(
        "INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing, waf_status)"
        " VALUES ('arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/onb/1', :a,"
        " 'alb-public-onboarding-prod', 'ALB', 'eu-west-1', 'onb', true, 'UNPROTECTED')"), {"a": ACCT})
    now = datetime.now(UTC)
    for i in range(3):
        await db.execute(text(
            "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri,"
            " action, classification, matched_rule_name, source) VALUES (:h, :ts, :a, :w, '185.220.101.42', 'POST',"
            " '/api/v2/checkout', 'COUNT', 'MALICIOUS', 'Custom-Checkout-RateLimit', 'FULL_LOG')"
        ), {"h": f"lc{i}", "ts": now - timedelta(minutes=i + 1), "a": ACCT, "w": webacl})
    await db.commit()
    return str(webacl)


async def as_role(client, role, **kwargs):
    cookies = await login_as(role, **kwargs)
    client.cookies.clear()
    client.cookies.update(cookies)
    return await user_email(cookies)


async def request_block(client, webacl, ttl=1, target=ATTACKER, simulate=True):
    await as_role(client, "SOC Analyst")
    sim_id = None
    if simulate:
        sim = await client.post("/api/v1/simulations", json={
            "title": "block attacker", "proposal": {"type": "BLOCK_IPS", "targets": [target]}})
        sim_id = sim.json()["id"]
    return await client.post("/api/v1/approvals", json={
        "action_type": "TEMP_BLOCK_IP", "account_id": ACCT, "webacl_id": webacl, "target": target,
        "ttl_hours": ttl, "reason": "Campaign CMP-2026-089 SQLi probing", "simulation_id": sim_id})


async def audit_actions(db) -> list[str]:
    return [a for (a,) in (await db.execute(text("SELECT action FROM audit_events ORDER BY timestamp, audit_code")))]


async def test_temp_block_full_lifecycle_then_rollback(client, world, waf, db):
    fake, factory = waf
    created = await request_block(client, world)
    assert created.status_code == 201, created.text
    body = created.json()
    approval_id = body["approval"]["id"]
    assert body["approval"]["status"] == "pending"
    assert body["approval"]["required_approver_role"] == "Security Analyst or Security Admin"
    assert body["proposed_state"]["op"] == "ip_set_add" and body["proposed_state"]["add"] == [ATTACKER]
    assert body["proposed_state"]["ip_set"]["name"] == "sas-platform-blocklist"

    decide = f"/api/v1/approvals/{approval_id}/decide"
    assert (await client.post(decide, json={"decision": "APPROVE"})).status_code == 403  # requester = SOC (no APPROVE)
    await as_role(client, "Executive")
    assert (await client.post(decide, json={"decision": "APPROVE"})).status_code == 403
    await as_role(client, "Security Analyst", mfa=False)
    assert "MFA" in (await client.post(decide, json={"decision": "APPROVE"})).json()["detail"]

    analyst = await as_role(client, "Security Analyst")
    resp = await client.post(decide, json={"decision": "APPROVE", "comment": "confirmed malicious"})
    assert resp.status_code == 200, resp.text
    detail = resp.json()
    assert detail["approval"]["status"] == "completed" and detail["approval"]["status_detail"] == "VERIFIED"
    assert ATTACKER in fake.ip_set["Addresses"] and "192.0.2.0/32" in fake.ip_set["Addresses"]
    session = factory.sessions[-1]
    assert session["approval_code"] == detail["approval"]["approval_code"] and session["approver"] == analyst
    assert session["role_arn"].endswith(":role/SASWafResponseRole")
    [change] = detail["changes"]
    assert change["verification_status"] == "VERIFIED" and change["ttl_status"] == "ACTIVE"
    assert change["aws_request_id"].startswith("req-")
    expires = datetime.fromisoformat(change["expires_at"])
    assert timedelta(minutes=59) < expires - datetime.now(UTC) <= timedelta(hours=1)
    states = {s["step"]: s["state"] for s in detail["lifecycle"]}
    assert states["EXECUTE"] == states["VERIFY"] == states["AUDIT"] == "completed"
    assert await audit_actions(db) == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED", "AWS_EXECUTE", "AWS_VERIFY"]

    await as_role(client, "Security Admin")
    rolled = await client.post(f"/api/v1/changes/{change['id']}/rollback", json={"reason": "false positive"})
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["execution_status"] == "ROLLED_BACK" and rolled.json()["ttl_status"] == "REMOVED"
    assert fake.ip_set["Addresses"] == ["192.0.2.0/32"]  # only our IP removed; pre-existing entries untouched
    assert (await client.post(f"/api/v1/changes/{change['id']}/rollback", json={})).status_code == 409
    assert (await audit_actions(db))[-1] == "ROLLBACK"
    assert [ch["id"] for ch in (await client.get("/api/v1/changes?status=rolled_back")).json()] == [change["id"]]
    assert (await client.get("/api/v1/changes?status=executed")).json() == []
    by_account = (await client.get("/api/v1/changes", params={"account_id": change["account_id"], "limit": 1})).json()
    assert [ch["id"] for ch in by_account] == [change["id"]]
    assert (await client.get("/api/v1/changes", params={"account_id": "999999999999"})).json() == []
    assert (await client.get("/api/v1/changes", params={"account_id": "prod"})).status_code == 422
    assert (await client.get("/api/v1/changes", params={"limit": 0})).status_code == 422
    bad = await client.get("/api/v1/changes?status=rolledback")
    assert bad.status_code == 422 and "expected one of executed, rolled_back" in bad.json()["detail"]
    status = await db.scalar(text("SELECT status FROM approvals WHERE id = :i"), {"i": approval_id})
    assert status == "ROLLED_BACK"


async def test_longer_ttl_needs_security_admin(client, world, waf):
    approval_id = (await request_block(client, world, ttl=24)).json()["approval"]["id"]
    await as_role(client, "Security Analyst")
    resp = await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    assert resp.status_code == 403 and "Security Admin" in resp.json()["detail"]


async def test_guardrail_denies_protected_target_at_request(client, world, waf, db):
    await db.execute(text(
        "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by)"
        " VALUES ('185.220.101.0/24', '185.220.101.0/24', 'Payment PSP', 'PAYMENT_GATEWAY', 'pay', 'psp', 't')"))
    await db.commit()
    resp = await request_block(client, world, simulate=False)
    assert resp.status_code == 403
    assert resp.json()["detail"]["message"] == "DENIED: Protected Entity"
    assert resp.json()["detail"]["protected"][0]["name"] == "Payment PSP"
    assert await db.scalar(text("SELECT count(*) FROM approvals")) == 0
    assert await audit_actions(db) == ["GUARDRAIL_DENIED"]


async def test_guardrail_rechecked_at_approval(client, world, waf, db):
    fake, _ = waf
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    await db.execute(text(
        "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by)"
        " VALUES ('185.220.101.42/32', '185.220.101.42/32', 'Newly onboarded partner', 'PARTNER_API', 'p', 'r', 't')"))
    await db.commit()
    await as_role(client, "Security Admin")
    resp = await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    assert resp.status_code == 403
    row = (await db.execute(text("SELECT status, allow_list_check FROM approvals"))).one()
    assert tuple(row) == ("REJECTED", "BLOCKED_PROTECTED_ENTITY")
    assert fake.calls == []  # AWS never touched


async def test_simulation_is_mandatory_and_must_match(client, world, waf):
    assert (await request_block(client, world, simulate=False)).status_code == 422
    sim = (await client.post("/api/v1/simulations", json={
        "title": "other", "proposal": {"type": "BLOCK_IPS", "targets": ["45.155.205.233"]}})).json()
    resp = await client.post("/api/v1/approvals", json={
        "action_type": "TEMP_BLOCK_IP", "account_id": ACCT, "webacl_id": world, "target": ATTACKER, "ttl_hours": 1,
        "reason": "mismatched simulation", "simulation_id": sim["id"]})
    assert resp.status_code == 422 and "not all simulated" in resp.json()["detail"]


async def test_rule_change_needs_admin_and_scoped_app_owner_then_moves_baseline(client, world, waf, db):
    fake, _ = waf
    await as_role(client, "SOC Analyst")
    sim = (await client.post("/api/v1/simulations", json={"title": "restore", "proposal": {
        "type": "RULE_ACTION", "webacl_id": world, "rule_name": "Custom-Checkout-RateLimit",
        "new_action": "BLOCK"}})).json()
    created = await client.post("/api/v1/approvals", json={
        "action_type": "MODIFY_RULE", "account_id": ACCT, "webacl_id": world, "rule_name": "Custom-Checkout-RateLimit",
        "action": "BLOCK", "reason": "Restore BLOCK after drift DRF-402", "simulation_id": sim["id"]})
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval"]["id"]
    assert created.json()["approval"]["required_approver_role"] == "Security Admin + Application Owner"
    decide = f"/api/v1/approvals/{approval_id}/decide"

    await as_role(client, "Security Admin")
    first = await client.post(decide, json={"decision": "APPROVE"})
    assert first.json()["approval"]["status"] == "pending" and fake.calls == []
    await as_role(client, "Application Owner", scoped=[OTHER])
    assert (await client.post(decide, json={"decision": "APPROVE"})).status_code == 403
    await as_role(client, "Application Owner", scoped=[ACCT])
    done = await client.post(decide, json={"decision": "APPROVE"})
    assert done.status_code == 200 and done.json()["approval"]["status_detail"] == "VERIFIED"
    assert fake.rule("Custom-Checkout-RateLimit")["Action"] == {"Block": {}}
    assert len(done.json()["decisions"]) == 2

    baseline = await db.scalar(text("SELECT baseline_config FROM web_acls"))
    rule = next(r for r in baseline["Rules"] if r["Name"] == "Custom-Checkout-RateLimit")
    assert rule["Action"] == {"Block": {}}  # approved change is the new drift baseline

    change_id = done.json()["changes"][0]["id"]
    await as_role(client, "AWS Administrator")
    assert (await client.post(f"/api/v1/changes/{change_id}/rollback", json={})).status_code == 200
    assert fake.rule("Custom-Checkout-RateLimit")["Action"] == {"Count": {}}


async def test_unverified_change_is_never_reported_success(client, world, waf, db):
    fake, _ = waf
    fake.silent = True  # AWS accepts the call but state never converges
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    await as_role(client, "Security Admin")
    detail = (await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})).json()
    assert detail["approval"]["status"] == "failed" and detail["approval"]["status_detail"] == "EXECUTED"
    assert detail["changes"][0]["verification_status"] == "FAILED" and detail["changes"][0]["ttl_status"] is None
    verify = (await db.execute(text(
        "SELECT verification_status FROM audit_events WHERE action = 'AWS_VERIFY'"))).scalar_one()
    assert verify == "FAILED"


async def test_aws_failure_is_audited(client, world, waf, db):
    fake, _ = waf
    fake.deny = True
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    await as_role(client, "Security Admin")
    resp = await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    assert resp.status_code == 502
    assert await db.scalar(text("SELECT count(*) FROM changes")) == 0
    row = (await db.execute(text("SELECT status, verification_status FROM approvals"))).one()
    assert tuple(row) == ("APPROVED", "FAILED")
    failed = (await db.execute(text(
        "SELECT execution_status FROM audit_events WHERE action = 'AWS_EXECUTE'"))).scalar_one()
    assert failed == "FAILED"


async def test_ttl_expiry_removes_block(client, world, waf, db):
    fake, factory = waf
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    await as_role(client, "Security Admin")
    await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    expires = await db.scalar(text("SELECT expires_at FROM changes"))

    assert (await ttl_expiry.run_once(factory, now=expires - timedelta(minutes=5)))["expiring"] == 1
    assert await db.scalar(text("SELECT ttl_status FROM changes")) == "EXPIRING"
    stats = await ttl_expiry.run_once(factory, now=expires + timedelta(minutes=1))
    assert stats["removed"] == 1 and ATTACKER not in fake.ip_set["Addresses"]
    await db.commit()  # new snapshot
    row = (await db.execute(text(
        "SELECT ch.ttl_status, ch.execution_status, ap.status FROM changes ch JOIN approvals ap"
        " ON ap.id = ch.approval_id"))).one()
    assert tuple(row) == ("REMOVED", "ROLLED_BACK", "EXPIRED")
    assert factory.sessions[-1]["approver"] == "ttl-expiry@sas-platform.internal"
    assert (await audit_actions(db))[-1] == "TTL_EXPIRY"


async def test_remediate_drift_restores_baseline_action(client, world, waf, db):
    fake, _ = waf
    drift_id = await db.scalar(text(
        "INSERT INTO drift_events (drift_code, account_id, account_name, webacl_id, webacl_name, drift_type, severity,"
        " expected_state, actual_state) VALUES ('DRF-402', :a, 'prod-payments-04', :w, 'prod-payments-waf',"
        " 'RULE_ACTION_CHANGED', 'CRITICAL', :e, :x) RETURNING id"
    ), {"a": ACCT, "w": world, "e": json.dumps({"rule": "Custom-Checkout-RateLimit", "action": "BLOCK"}),
        "x": json.dumps({"rule": "Custom-Checkout-RateLimit", "action": "COUNT"})})
    await db.commit()
    await as_role(client, "SOC Analyst")
    created = await client.post("/api/v1/approvals", json={
        "action_type": "REMEDIATE_DRIFT", "account_id": ACCT, "drift_id": str(drift_id),
        "reason": "Remediate DRF-402 back to baseline"})
    assert created.status_code == 201, created.text
    assert created.json()["proposed_state"]["op"] == "set_rule_action"
    approval_id = created.json()["approval"]["id"]
    for role, kwargs in (("Security Admin", {}), ("Application Owner", {"scoped": [ACCT]})):
        await as_role(client, role, **kwargs)
        await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    assert fake.rule("Custom-Checkout-RateLimit")["Action"] == {"Block": {}}
    await db.commit()
    assert await db.scalar(text("SELECT status FROM drift_events")) == "REMEDIATING"


async def test_attach_waf_two_person(client, world, waf):
    fake, _ = waf
    await as_role(client, "AWS Administrator")
    resource = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/onb/1"
    created = await client.post("/api/v1/approvals", json={
        "action_type": "ATTACH_WAF", "account_id": ACCT, "webacl_id": world, "resource_arn": resource,
        "reason": "Protect unprotected onboarding ALB"})
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval"]["id"]
    for role in ("Security Admin", "AWS Administrator"):
        await as_role(client, role)
        resp = await client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "APPROVE"})
    assert resp.json()["approval"]["status_detail"] == "VERIFIED"
    assert fake.associations[resource] == WEBACL_ARN


async def test_reject_records_decision(client, world, waf, db):
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    await as_role(client, "Security Admin")
    detail = (await client.post(f"/api/v1/approvals/{approval_id}/decide",
                                json={"decision": "REJECT", "comment": "insufficient evidence"})).json()
    assert detail["approval"]["status"] == "rejected" and detail["decisions"][0]["decision"] == "REJECT"
    assert (await audit_actions(db))[-1] == "APPROVAL_REJECTED"


async def test_approvals_status_filter(client, world, waf):
    approval_id = (await request_block(client, world)).json()["approval"]["id"]
    assert [a["id"] for a in (await client.get("/api/v1/approvals?status=pending")).json()] == [approval_id]
    assert (await client.get("/api/v1/approvals?status=rejected")).json() == []
    resp = await client.get("/api/v1/approvals?status=pendng")
    assert resp.status_code == 422
    assert "Unknown status 'pendng'" in resp.json()["detail"]


async def test_allow_list_management_and_audit_export(client, world, db):
    await as_role(client, "Security Analyst")
    added = await client.post("/api/v1/allow-list", json={
        "cidr_or_value": "203.0.113.0/24", "name": "PSP egress", "category": "PAYMENT_GATEWAY", "owner": "payments",
        "reason": "Card processor callbacks"})
    assert added.status_code == 201
    entry_id = added.json()["id"]
    duplicate = await client.post("/api/v1/allow-list", json={
        "cidr_or_value": "203.0.113.7/24", "name": "PSP egress again", "category": "PAYMENT_GATEWAY",
        "owner": "payments", "reason": "Card processor callbacks"})
    assert duplicate.status_code == 409 and duplicate.json()["detail"] == "203.0.113.0/24 is already on the allow-list"
    deactivate = f"/api/v1/allow-list/{entry_id}/deactivate"
    assert (await client.post(deactivate, json={"reason": "contract ended"})).status_code == 403
    await as_role(client, "Security Admin")
    assert (await client.post(deactivate, json={"reason": "contract ended"})).json()["is_active"] is False
    again = await client.post(deactivate, json={"reason": "contract ended"})
    assert again.status_code == 409 and again.json()["detail"] == "Allow-list entry is already inactive"

    await as_role(client, "Auditor")
    csv_resp = await client.get("/api/v1/governance/audit", params={"format": "csv"})
    lines = csv_resp.text.strip().splitlines()
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert lines[0].startswith("audit_code,timestamp,user_email") and len(lines) == 3
    actions = [r["action"] for r in (await client.get("/api/v1/governance/audit")).json()]
    assert actions == ["ALLOW_LIST_DEACTIVATE", "ALLOW_LIST_ADD"]


async def test_audit_csv_neutralises_formulas(client, world, db):
    await as_role(client, "Security Analyst")
    await client.post("/api/v1/allow-list", json={
        "cidr_or_value": "198.51.100.0/24", "name": "Partner", "category": "PAYMENT_GATEWAY", "owner": "payments",
        "reason": "=HYPERLINK(\"http://evil.example\")"})
    await as_role(client, "Auditor")
    rows = list(csv.DictReader(io.StringIO(
        (await client.get("/api/v1/governance/audit", params={"format": "csv"})).text)))
    assert rows[0]["reason"] == "'=HYPERLINK(\"http://evil.example\")"
    assert (await client.get("/api/v1/governance/audit")).json()[0]["reason"].startswith("=HYPERLINK")


async def test_audit_export_rejects_reversed_range(client):
    await as_role(client, "Auditor")
    resp = await client.get("/api/v1/governance/audit",
                            params={"from": "2026-11-05T00:00:00Z", "to": "2026-11-01T00:00:00Z"})
    assert resp.status_code == 422
    assert "'from' must not be later than 'to'" in resp.json()["detail"]


# --- real request shapes (botocore service model validation) -------------------------------------------------

def test_update_web_acl_and_ip_set_params_match_wafv2_model():
    wafv2 = boto3.client("wafv2", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")
    executor = WafExecutor(lambda service, region: wafv2, wait_seconds=0)
    ref = {"name": "prod-payments-waf", "id": "r-1", "scope": "REGIONAL", "region": "eu-west-1", "arn": WEBACL_ARN}
    acl = dict(BASE_ACL)
    after = json.loads(json.dumps(acl))
    after["Rules"][2]["Action"] = {"Block": {}}
    with Stubber(wafv2) as stub:
        stub.add_response("get_web_acl", {"WebACL": acl, "LockToken": "t1"},
                          {"Name": "prod-payments-waf", "Scope": "REGIONAL", "Id": "r-1"})
        stub.add_response("update_web_acl", {"NextLockToken": "t2", "ResponseMetadata": {"RequestId": "rid-1"}}, {
            "Name": "prod-payments-waf", "Scope": "REGIONAL", "Id": "r-1", "LockToken": "t1", "DefaultAction": ANY,
            "Description": ANY, "Rules": ANY, "VisibilityConfig": ANY})
        stub.add_response("get_web_acl", {"WebACL": after, "LockToken": "t2"},
                          {"Name": "prod-payments-waf", "Scope": "REGIONAL", "Id": "r-1"})
        result = executor.execute({"op": "set_rule_action", "webacl": ref, "rule_name": "Custom-Checkout-RateLimit",
                                   "action": "BLOCK"})
        stub.assert_no_pending_responses()
    assert result.verified and result.lock_token_before == "t1" and result.aws_request_id == "rid-1"

    ip_ref = {"name": "sas-platform-blocklist", "id": "ips-1", "scope": "REGIONAL", "region": "eu-west-1"}
    ipset = {"Name": "sas-platform-blocklist", "Id": "ips-1", "ARN": IPSET_ARN, "IPAddressVersion": "IPV4",
             "Addresses": []}
    with Stubber(wafv2) as stub:
        stub.add_response("get_ip_set", {"IPSet": ipset, "LockToken": "a"},
                          {"Name": "sas-platform-blocklist", "Scope": "REGIONAL", "Id": "ips-1"})
        stub.add_response("update_ip_set", {"NextLockToken": "b", "ResponseMetadata": {"RequestId": "rid-2"}}, {
            "Name": "sas-platform-blocklist", "Scope": "REGIONAL", "Id": "ips-1", "Addresses": [ATTACKER],
            "LockToken": "a"})
        stub.add_response("get_ip_set", {"IPSet": {**ipset, "Addresses": [ATTACKER]}, "LockToken": "b"},
                          {"Name": "sas-platform-blocklist", "Scope": "REGIONAL", "Id": "ips-1"})
        assert executor.execute({"op": "ip_set_add", "ip_set": ip_ref, "add": [ATTACKER]}).verified
        stub.assert_no_pending_responses()


async def test_approvals_limit_is_validated(client, world, waf):
    created = await request_block(client, world)
    assert created.status_code == 201, created.text
    assert len((await client.get("/api/v1/approvals", params={"limit": 1})).json()) == 1
    for bad in (0, 501):
        assert (await client.get("/api/v1/approvals", params={"limit": bad})).status_code == 422
