"""Governance: AWS account registry and platform users (Security Admin only - MANAGE_USERS)."""

import uuid

from fastapi import APIRouter, Depends, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, get_redis
from app.models import Account, User
from app.security import Principal, require
from app.services import registry_service as reg

router = APIRouter(prefix="/governance", tags=["governance"])


def _actor(principal: Principal) -> reg.Actor:
    return reg.Actor(email=principal.email, role=principal.role)


@router.get("/accounts")
async def list_accounts(_: Principal = Depends(require("MANAGE_USERS")), db: AsyncSession = Depends(get_db)):
    return [reg.account_row(a) for a in (await db.scalars(select(Account).order_by(Account.name))).all()]


@router.post("/accounts", status_code=status.HTTP_201_CREATED)
async def register_account(body: reg.AccountCreate, principal: Principal = Depends(require("MANAGE_USERS")),
                           db: AsyncSession = Depends(get_db)):
    return reg.account_row(await reg.create_account(db, body, _actor(principal)))


@router.patch("/accounts/{account_id}")
async def update_account(account_id: str, body: reg.AccountUpdate,
                         principal: Principal = Depends(require("MANAGE_USERS")), db: AsyncSession = Depends(get_db)):
    return reg.account_row(await reg.update_account(db, account_id, body, _actor(principal)))


@router.get("/users")
async def list_users(_: Principal = Depends(require("MANAGE_USERS")), db: AsyncSession = Depends(get_db)):
    return [reg.user_row(u) for u in (await db.scalars(select(User).order_by(User.email))).all()]


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def provision_user(body: reg.UserCreate, principal: Principal = Depends(require("MANAGE_USERS")),
                         db: AsyncSession = Depends(get_db)):
    return reg.user_row(await reg.create_user(db, body, _actor(principal)))


@router.patch("/users/{user_id}")
async def update_user(user_id: uuid.UUID, body: reg.UserUpdate,
                      principal: Principal = Depends(require("MANAGE_USERS")), db: AsyncSession = Depends(get_db),
                      redis: Redis = Depends(get_redis)):
    return reg.user_row(await reg.update_user(db, redis, user_id, body, _actor(principal)))
