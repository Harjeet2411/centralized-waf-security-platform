"""Server-side sessions (Redis `session:user:{id}`, 8h) and RBAC dependencies.

The browser only ever holds an opaque HttpOnly/Secure/SameSite=Strict cookie. The user's role and
active flag are re-read from PostgreSQL on every request, so deactivating a user or changing a role
takes effect immediately rather than at session expiry.
"""

import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db, get_redis
from app.models import User
from app.services import rbac_service


def _session_key(session_id: str) -> str:
    return f"session:user:{session_id}"


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    email: str
    full_name: str
    role: str
    permissions: tuple[str, ...]
    scoped_account_ids: tuple[str, ...]
    mfa: bool

    def has(self, permission: str) -> bool:
        return rbac_service.has_permission(self.permissions, permission)

    def account_scope(self, permission: str) -> frozenset[str] | None:
        return rbac_service.account_scope(self.permissions, permission, self.scoped_account_ids)


async def create_session(redis: Redis, response: Response, user: User, mfa: bool) -> str:
    settings = get_settings()
    session_id = secrets.token_urlsafe(32)
    payload = {"user_id": str(user.id), "mfa": mfa, "created_at": datetime.now(UTC).isoformat()}
    await redis.set(_session_key(session_id), json.dumps(payload), ex=settings.session_ttl_seconds)
    response.set_cookie(
        settings.session_cookie_name, session_id,
        max_age=settings.session_ttl_seconds, httponly=True, secure=settings.cookie_secure,
        samesite="strict", path="/",
    )
    return session_id


async def destroy_session(redis: Redis, request: Request, response: Response) -> None:
    settings = get_settings()
    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        await redis.delete(_session_key(session_id))
    response.delete_cookie(settings.session_cookie_name, path="/")


_UNAUTHENTICATED = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")


async def get_principal(
    request: Request, db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis)
) -> Principal:
    session_id = request.cookies.get(get_settings().session_cookie_name)
    if not session_id:
        raise _UNAUTHENTICATED
    raw = await redis.get(_session_key(session_id))
    if raw is None:
        raise _UNAUTHENTICATED
    session = json.loads(raw)
    user = await db.scalar(select(User).where(User.id == uuid.UUID(session["user_id"])))
    if user is None or not user.is_active:
        await redis.delete(_session_key(session_id))
        raise _UNAUTHENTICATED
    return Principal(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.name,
        permissions=tuple(user.role.permissions),
        scoped_account_ids=tuple(user.scoped_account_ids or ()),
        mfa=bool(session.get("mfa")),
    )


def require(permission: str) -> Callable:
    """FastAPI dependency: authenticated principal holding `permission` (any qualifier), else 403."""
    if permission not in rbac_service.PERMISSIONS:
        raise ValueError(f"unknown permission {permission!r}")

    async def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission}")
        return principal

    return _dependency
