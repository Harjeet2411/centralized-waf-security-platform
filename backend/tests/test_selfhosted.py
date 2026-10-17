"""Self-hosted staging: optional operator sign-in (never in production) and the Redis-queued sync worker."""

import json

import pytest
from sqlalchemy import text

from app.config import Settings, get_settings
from app.database import SessionLocal, redis_client
from tests.conftest import create_user, login_as


async def user_email(user_id) -> str:
    async with SessionLocal() as session:
        return await session.scalar(text("SELECT email FROM users WHERE id = :id"), {"id": user_id})


async def test_operator_login_is_off_by_default(client):
    assert (await client.get("/api/v1/auth/config")).json() == {"oidc_enabled": True, "operator_login": False}
    assert (await client.post("/api/v1/auth/operator-login", json={"email": "a@b.co"})).status_code == 404


def test_operator_login_refused_in_production():
    with pytest.raises(ValueError, match="SAS_OPERATOR_LOGIN"):
        Settings(environment="production", cookie_secure=True, operator_login=True)


async def test_operator_login_signs_in_active_users_and_audits(client, db, monkeypatch):
    monkeypatch.setattr(get_settings(), "operator_login", True)
    admin = await create_user("Security Admin")
    email = await user_email(admin["id"])
    assert (await client.post("/api/v1/auth/operator-login", json={"email": "nobody@example.com"})).status_code == 403
    resp = await client.post("/api/v1/auth/operator-login", json={"email": email.upper()})
    assert resp.status_code == 204
    me = (await client.get("/api/v1/me")).json()
    assert me["email"] == email and me["mfa"] is True
    assert await db.scalar(text("SELECT count(*) FROM audit_events WHERE action = 'OPERATOR_LOGIN'")) == 1

    inactive = await create_user("SOC Analyst", active=False)
    client.cookies.clear()
    body = {"email": await user_email(inactive["id"])}
    assert (await client.post("/api/v1/auth/operator-login", json=body)).status_code == 403


async def test_worker_backend_queues_one_sync(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "sync_backend", "worker")
    client.cookies.update(await login_as("SOC Analyst"))
    first = await client.post("/api/v1/refresh", params={"force": True})
    assert first.status_code == 202 and first.json()["status"] == "syncing"
    second = await client.post("/api/v1/refresh", params={"force": True})
    assert second.status_code == 202
    queued = await redis_client.lrange("sync:requests", 0, -1)
    assert len(queued) == 1 and json.loads(queued[0])["mode"] == "full"
    assert await redis_client.get("sync:global:lock") == "api"
