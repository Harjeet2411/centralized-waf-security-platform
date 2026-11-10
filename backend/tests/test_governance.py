"""Account/user registry: RBAC, validation, audit, session revocation, lock-out guard, bootstrap CLI."""

import json

import pytest
from sqlalchemy import text
from starlette.responses import Response

from app import cli
from app.database import redis_client
from app.models import User
from app.security import create_session
from tests.conftest import login_as

ACCT = "123456789012"
ACCOUNT = {"account_id": ACCT, "name": "prod-payments-04", "environment": "production", "owner": "payments",
           "regions": ["eu-west-1", "us-east-1"]}


async def admin(client):
    client.cookies.clear()
    client.cookies.update(await login_as("Security Admin"))


async def audit_actions(db) -> list[str]:
    return [a for (a,) in await db.execute(text("SELECT action FROM audit_events ORDER BY timestamp"))]


async def test_only_security_admin_manages_registry(client):
    for role in ("Security Analyst", "AWS Administrator", "Auditor"):
        client.cookies.clear()
        client.cookies.update(await login_as(role))
        assert (await client.post("/api/v1/governance/accounts", json=ACCOUNT)).status_code == 403
        assert (await client.get("/api/v1/governance/users")).status_code == 403


async def test_register_account_derives_stackset_roles_and_audits(client, db):
    await admin(client)
    resp = await client.post("/api/v1/governance/accounts", json=ACCOUNT)
    assert resp.status_code == 201
    body = resp.json()
    assert body["discovery_role_arn"] == f"arn:aws:iam::{ACCT}:role/SASWafDiscoveryRole"
    assert body["response_role_arn"] == f"arn:aws:iam::{ACCT}:role/SASWafResponseRole"
    assert (await client.post("/api/v1/governance/accounts", json=ACCOUNT)).status_code == 409
    patched = await client.patch(f"/api/v1/governance/accounts/{ACCT}", json={"owner": "payments-platform"})
    assert patched.json()["owner"] == "payments-platform"
    assert await audit_actions(db) == ["ACCOUNT_REGISTERED", "ACCOUNT_UPDATED"]
    # Sending the same value again, or nothing, changes nothing and is not audited
    for body in ({"owner": "payments-platform"}, {}):
        again = await client.patch(f"/api/v1/governance/accounts/{ACCT}", json=body)
        assert again.status_code == 200 and again.json()["owner"] == "payments-platform"
    assert await audit_actions(db) == ["ACCOUNT_REGISTERED", "ACCOUNT_UPDATED"]


@pytest.mark.parametrize("patch", [
    {"account_id": "12345"},
    {"regions": ["mars-1"]},
    {"environment": "prod"},
    {"discovery_role_arn": "arn:aws:iam::999999999999:role/SASWafDiscoveryRole"},  # role in another account
])
async def test_account_validation(client, patch):
    await admin(client)
    assert (await client.post("/api/v1/governance/accounts", json={**ACCOUNT, **patch})).status_code == 422


async def test_duplicate_regions_are_dropped(client):
    await admin(client)
    body = {**ACCOUNT, "regions": ["eu-west-1", "us-east-1", "eu-west-1"]}
    created = await client.post("/api/v1/governance/accounts", json=body)
    assert created.json()["regions"] == ["eu-west-1", "us-east-1"]
    patched = await client.patch(f"/api/v1/governance/accounts/{ACCT}",
                                 json={"regions": ["us-east-1", "us-east-1", "ap-south-1"]})
    assert patched.json()["regions"] == ["us-east-1", "ap-south-1"]


async def test_user_provisioning_validation(client):
    await admin(client)
    base = {"email": "bob@sas.test", "full_name": "Bob", "sso_subject_id": "sub-bob"}
    assert (await client.post("/api/v1/governance/users", json={**base, "role": "Superuser"})).status_code == 422
    unknown_scope = {**base, "role": "Application Owner", "scoped_account_ids": ["210987654321"]}
    resp = await client.post("/api/v1/governance/users", json=unknown_scope)
    assert resp.status_code == 422 and "210987654321" in resp.json()["detail"]
    await client.post("/api/v1/governance/accounts", json=ACCOUNT)
    created = await client.post("/api/v1/governance/users", json={**unknown_scope, "scoped_account_ids": [ACCT]})
    assert created.status_code == 201 and created.json()["role"] == "Application Owner"
    assert (await client.post("/api/v1/governance/users", json={**base, "role": "Auditor"})).status_code == 409


async def test_deactivation_revokes_sessions_immediately(client, db):
    await admin(client)
    user = (await client.post("/api/v1/governance/users", json={
        "email": "carol@sas.test", "full_name": "Carol", "role": "SOC Analyst", "sso_subject_id": "sub-carol"})).json()
    orm_user = await db.get(User, user["id"])
    session_id = await create_session(redis_client, Response(), orm_user, mfa=True)
    assert await redis_client.exists(f"session:user:{session_id}")

    resp = await client.patch(f"/api/v1/governance/users/{user['id']}", json={"is_active": False})
    assert resp.status_code == 200 and resp.json()["is_active"] is False
    assert not await redis_client.exists(f"session:user:{session_id}")
    assert not await redis_client.exists(f"session:index:{user['id']}")
    [row] = (await db.execute(text(
        "SELECT risk_level, previous_state FROM audit_events WHERE action = 'USER_DEACTIVATED'"))).all()
    assert row.risk_level == "HIGH" and json.loads(row.previous_state)["is_active"] is True


async def test_last_security_admin_cannot_be_removed(client, db):
    await admin(client)
    me = (await client.get("/api/v1/me")).json()
    resp = await client.patch(f"/api/v1/governance/users/{me['user_id']}", json={"is_active": False})
    assert resp.status_code == 409
    resp = await client.patch(f"/api/v1/governance/users/{me['user_id']}", json={"role": "Read Only"})
    assert resp.status_code == 409
    second = (await client.post("/api/v1/governance/users", json={
        "email": "dana@sas.test", "full_name": "Dana", "role": "Security Admin", "sso_subject_id": "sub-dana"}))
    assert second.status_code == 201
    assert (await client.patch(f"/api/v1/governance/users/{me['user_id']}",
                               json={"role": "Read Only"})).status_code == 200


async def test_cli_bootstrap(tmp_path, db, capsys):
    assert await cli.create_admin("root@sas.test", "Root Admin", "sub-root") == 0
    assert await cli.create_admin("second@sas.test", "Second", "sub-2") == 2  # bootstrap only once
    csv_file = tmp_path / "accounts.csv"
    csv_file.write_text(
        "account_id,name,environment,owner,regions\n"
        f"{ACCT},prod-payments-04,production,payments,eu-west-1;us-east-1\n"
        "210987654321,prod-auth-02,production,identity,us-east-1\n"
        "bad-id,broken,production,x,us-east-1\n", encoding="utf-8")
    assert await cli.register_accounts(csv_file) == 1  # one invalid row
    assert await cli.register_accounts(csv_file) == 1  # re-run: existing rows skipped, invalid still reported
    out = capsys.readouterr().out
    assert "registered 2, already present 0, invalid 1" in out and "registered 0, already present 2" in out
    regions = await db.scalar(text("SELECT regions FROM accounts WHERE account_id = :a"), {"a": ACCT})
    assert regions == ["eu-west-1", "us-east-1"]
    actors = {a for (a,) in await db.execute(text("SELECT DISTINCT user_email FROM audit_events"))}
    assert actors == {"cli@sas-platform.internal"}
