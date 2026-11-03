"""RBAC gate, server-side sessions and the OIDC (IAM Identity Center) login flow."""

import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from sqlalchemy import text

from app.api.v1 import auth
from app.config import Settings
from app.database import redis_client
from app.main import app
from app.security import Principal, require
from app.services import rbac_service
from tests.conftest import create_user, login_as

# --- rbac_service ---------------------------------------------------------------------------------


def test_qualified_grants_pass_base_gate_but_keep_qualifier():
    analyst = ["VIEW", "APPROVE:TEMP_BLOCK"]
    assert rbac_service.has_permission(analyst, "APPROVE")
    assert rbac_service.qualifiers(analyst, "APPROVE") == {"TEMP_BLOCK"}
    assert not rbac_service.has_permission(analyst, "EXECUTE")
    assert rbac_service.qualifiers(["APPROVE"], "APPROVE") == {"*"}


def test_account_scope():
    owner = ["VIEW", "INVESTIGATE:SCOPED"]
    assert rbac_service.account_scope(owner, "INVESTIGATE", ["111111111111"]) == {"111111111111"}
    assert rbac_service.account_scope(owner, "VIEW", ["111111111111"]) is None
    with pytest.raises(PermissionError):
        rbac_service.account_scope(owner, "APPROVE", [])
    with pytest.raises(ValueError, match="unknown permission 'DELETE_EVERYTHING'"):
        rbac_service.has_permission(owner, "DELETE_EVERYTHING")


# --- endpoint gate --------------------------------------------------------------------------------

gate_app = FastAPI()


@gate_app.get("/approve-gate")
async def approve_gate(principal: Principal = Depends(require("APPROVE"))):
    return {"role": principal.role, "approve": sorted(rbac_service.qualifiers(principal.permissions, "APPROVE"))}


@pytest.mark.parametrize(("role", "expected"), [
    ("Security Admin", 200), ("Security Analyst", 200), ("AWS Administrator", 200), ("Application Owner", 200),
    ("SOC Analyst", 403), ("Auditor", 403), ("Executive", 403), ("Read Only", 403),
])
async def test_require_approve_matches_prd(role, expected):
    cookies = await login_as(role)
    transport = httpx.ASGITransport(app=gate_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies) as c:
        assert (await c.get("/approve-gate")).status_code == expected


async def test_bootstrap_requires_session(client):
    assert (await client.get("/api/v1/bootstrap")).status_code == 401
    client.cookies.set("sas_session", "forged-session-id")
    assert (await client.get("/api/v1/bootstrap")).status_code == 401


async def test_read_only_can_view_and_me_reports_role(client):
    client.cookies.update(await login_as("Read Only"))
    assert (await client.get("/api/v1/bootstrap")).status_code == 200
    me = (await client.get("/api/v1/me")).json()
    assert me["role"] == "Read Only" and me["permissions"] == ["VIEW"]


async def test_deactivated_user_loses_access_immediately(client, db):
    cookies = await login_as("Security Admin")
    client.cookies.update(cookies)
    assert (await client.get("/api/v1/me")).status_code == 200
    await db.execute(text("UPDATE users SET is_active = false"))
    await db.commit()
    assert (await client.get("/api/v1/me")).status_code == 401
    assert await redis_client.get(f"session:user:{cookies['sas_session']}") is None


def test_insecure_settings_rejected_outside_local():
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        Settings(environment="production", cookie_secure=False)
    with pytest.raises(ValueError, match="MFA"):
        Settings(environment="staging", cookie_secure=True, oidc_require_mfa=False)


# --- OIDC flow ------------------------------------------------------------------------------------

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
DISCOVERY = {
    "authorization_endpoint": "https://idp.test/authorize",
    "token_endpoint": "https://idp.test/token",
    "jwks_uri": "https://idp.test/jwks",
}


@pytest.fixture
def idp(monkeypatch):
    """Fake IdP: discovery, token endpoint (returns whatever id_token the test sets) and signing key."""
    state = {"id_token": None}

    async def discovery():
        return DISCOVERY

    async def exchange(code, verifier):
        assert code == "auth-code" and verifier
        return {"id_token": state["id_token"]}

    async def key(_token):
        return _KEY.public_key()

    monkeypatch.setattr(auth, "oidc_discovery", discovery)
    monkeypatch.setattr(auth, "exchange_code", exchange)
    monkeypatch.setattr(auth, "signing_key", key)
    return state


def make_id_token(sub: str, nonce: str, amr=("pwd", "mfa"), **overrides) -> str:
    now = int(time.time())
    claims = {"iss": "https://idp.test", "aud": "sas-test-client", "sub": sub, "nonce": nonce,
              "iat": now, "exp": now + 300, "amr": list(amr), **overrides}
    return jwt.encode(claims, _KEY, algorithm="RS256")


async def start_login(client) -> tuple[str, str]:
    resp = await client.get("/api/v1/auth/login")
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"] and query["client_id"] == ["sas-test-client"]
    state = query["state"][0]
    pending = json.loads(await redis_client.get(f"oidc:state:{state}"))
    return state, pending["nonce"]


async def test_oidc_login_creates_session(client, idp):
    user = await create_user("SOC Analyst")
    state, nonce = await start_login(client)
    idp["id_token"] = make_id_token(user["sub"], nonce)
    resp = await client.get("/api/v1/auth/callback", params={"code": "auth-code", "state": state})
    assert resp.status_code == 302 and resp.headers["location"] == "http://frontend.test"
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    me = (await client.get("/api/v1/me")).json()
    assert me["role"] == "SOC Analyst" and me["mfa"] is True
    # State is single-use.
    replay = await client.get("/api/v1/auth/callback", params={"code": "auth-code", "state": state})
    assert replay.status_code == 400

    assert (await client.post("/api/v1/auth/logout")).status_code == 204
    assert (await client.get("/api/v1/me")).status_code == 401


@pytest.mark.parametrize(("case", "expected"), [
    ("no_mfa", 403), ("unknown_user", 403), ("inactive_user", 403), ("bad_nonce", 401), ("wrong_audience", 401),
    ("expired", 401),
])
async def test_oidc_callback_rejections(client, idp, case, expected):
    user = await create_user("Security Admin", active=case != "inactive_user")
    state, nonce = await start_login(client)
    sub = "sub-not-provisioned" if case == "unknown_user" else user["sub"]
    kwargs = {}
    if case == "no_mfa":
        kwargs["amr"] = ("pwd",)
    if case == "bad_nonce":
        nonce = "attacker-nonce"
    if case == "wrong_audience":
        kwargs["aud"] = "some-other-app"
    if case == "expired":
        kwargs["exp"] = int(time.time()) - 60
    idp["id_token"] = make_id_token(sub, nonce, **kwargs)
    resp = await client.get("/api/v1/auth/callback", params={"code": "auth-code", "state": state})
    assert resp.status_code == expected
    assert "set-cookie" not in resp.headers


async def test_unknown_state_rejected(client, idp):
    resp = await client.get("/api/v1/auth/callback", params={"code": "auth-code", "state": "never-issued"})
    assert resp.status_code == 400


async def test_routes_registered_and_healthz(client):
    paths = set(app.openapi()["paths"])
    assert {"/api/v1/bootstrap", "/api/v1/me", "/api/v1/auth/login", "/api/v1/auth/callback"} <= paths
    assert (await client.get("/healthz")).json() == {"status": "ok"}


def test_database_url_composed_from_ecs_secret_parts():
    s = Settings(environment="test", db_host="db.internal", db_user="sas_admin", db_password="p@ss/w:rd")
    assert s.database_url == "postgresql+asyncpg://sas_admin:p%40ss%2Fw%3Ard@db.internal:5432/sas_waf?ssl=require"
    assert Settings(environment="test", database_url="postgresql+asyncpg://x").database_url == "postgresql+asyncpg://x"
