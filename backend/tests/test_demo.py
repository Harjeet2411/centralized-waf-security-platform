"""Local demo: seed-demo loads a usable dataset; demo sign-in is off by default and refused in deployed envs."""

import pytest
from sqlalchemy import text

from app import cli
from app.config import Settings, get_settings


async def test_demo_login_disabled_by_default(client):
    assert (await client.get("/api/v1/auth/config")).json()["demo_login_enabled"] is False
    assert (await client.post("/api/v1/auth/demo-login")).status_code == 404


def test_demo_login_refused_outside_local():
    with pytest.raises(ValueError, match="SAS_DEMO_LOGIN_EMAIL"):
        Settings(environment="production", cookie_secure=True, demo_login_email="admin@sas.local")


async def test_seed_demo_then_demo_login_loads_bootstrap(client, db, monkeypatch):
    assert await cli.seed_demo() == 0
    assert await db.scalar(text("SELECT count(*) FROM accounts")) == 3
    assert await db.scalar(text("SELECT count(*) FROM waf_events")) > 0
    assert await cli.seed_demo() == 0  # idempotent: skips when accounts exist
    assert await db.scalar(text("SELECT count(*) FROM accounts")) == 3

    monkeypatch.setattr(get_settings(), "demo_login_email", "admin@sas.local")
    assert (await client.post("/api/v1/auth/demo-login")).status_code == 204
    me = (await client.get("/api/v1/me")).json()
    assert me["role"] == "Security Admin"
    boot = (await client.get("/api/v1/bootstrap")).json()
    assert len(boot["accounts"]) == 3
    assert any(e["status"] == "unprotected" for e in boot["endpoints"])
