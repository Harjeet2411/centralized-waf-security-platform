"""OIDC authorization-code + PKCE login against the IdP fronting AWS IAM Identity Center.

Users are never auto-provisioned: the token's `sub` must match an active `users.sso_subject_id`.
MFA is required via the `amr` claim unless SAS_OIDC_REQUIRE_MFA=false (local/test only, see config).
"""

import asyncio
import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db, get_redis
from app.models import User
from app.security import create_session, destroy_session

router = APIRouter(prefix="/auth", tags=["auth"])

STATE_TTL_SECONDS = 600
_discovery_cache: dict[str, dict] = {}
_jwk_clients: dict[str, jwt.PyJWKClient] = {}


async def oidc_discovery() -> dict:
    issuer = get_settings().oidc_issuer.rstrip("/")
    if issuer not in _discovery_cache:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{issuer}/.well-known/openid-configuration")
            resp.raise_for_status()
            _discovery_cache[issuer] = resp.json()
    return _discovery_cache[issuer]


async def exchange_code(code: str, verifier: str) -> dict:
    settings = get_settings()
    discovery = await oidc_discovery()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(discovery["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret.get_secret_value(),
            "code_verifier": verifier,
        })
    if resp.status_code != 200:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token exchange failed")
    return resp.json()


async def signing_key(id_token: str):
    jwks_uri = (await oidc_discovery())["jwks_uri"]
    client = _jwk_clients.setdefault(jwks_uri, jwt.PyJWKClient(jwks_uri))
    return (await asyncio.to_thread(client.get_signing_key_from_jwt, id_token)).key


async def validate_id_token(id_token: str, nonce: str) -> dict:
    settings = get_settings()
    try:
        claims = jwt.decode(
            id_token, await signing_key(id_token), algorithms=["RS256", "ES256"],
            audience=settings.oidc_client_id, issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ID token") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ID token nonce")
    return claims


@router.get("/login")
async def login(redis: Redis = Depends(get_redis)) -> RedirectResponse:
    settings = get_settings()
    discovery = await oidc_discovery()
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    await redis.set(f"oidc:state:{state}", json.dumps({"nonce": nonce, "verifier": verifier}), ex=STATE_TTL_SECONDS)
    query = urlencode({
        "response_type": "code", "client_id": settings.oidc_client_id, "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    return RedirectResponse(f"{discovery['authorization_endpoint']}?{query}", status.HTTP_302_FOUND)


@router.get("/callback")
async def callback(
    code: str, state: str, db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis)
) -> RedirectResponse:
    settings = get_settings()
    stored = await redis.getdel(f"oidc:state:{state}")
    if stored is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown or expired login state")
    pending = json.loads(stored)

    tokens = await exchange_code(code, pending["verifier"])
    claims = await validate_id_token(tokens.get("id_token", ""), pending["nonce"])

    mfa = "mfa" in (claims.get("amr") or [])
    if settings.oidc_require_mfa and not mfa:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA required")

    user = await db.scalar(select(User).where(User.sso_subject_id == claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User is not provisioned for this platform")
    user.last_login_at = datetime.now(UTC)
    await db.commit()

    response = RedirectResponse(settings.frontend_url, status.HTTP_302_FOUND)
    await create_session(redis, response, user, mfa)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, redis: Redis = Depends(get_redis)) -> Response:
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    await destroy_session(redis, request, response)
    return response
