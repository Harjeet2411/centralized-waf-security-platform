"""Account and user registry, shared by the governance API (Security Admin) and the bootstrap CLI.

Every write is audited. Guard rails: role ARNs must belong to the account they are registered for, scoped
accounts must exist, and the last active Security Admin can never be deactivated or demoted (lock-out).
"""

import re
from typing import Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, model_validator
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Account, Role, User
from app.security import revoke_user_sessions
from app.services import audit_service

RoleName = Literal["Security Admin", "Security Analyst", "SOC Analyst", "AWS Administrator", "Application Owner",
                   "Auditor", "Executive", "Read Only"]
Environment = Literal["production", "staging", "development", "shared-services", "security"]
ACCOUNT_ID = r"^[0-9]{12}$"
REGION = r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$"
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::([0-9]{12}):role/[\w+=,.@/-]+$")


class Actor(BaseModel):
    email: str
    role: str


class AccountCreate(BaseModel):
    account_id: str = Field(pattern=ACCOUNT_ID)
    name: str = Field(min_length=2, max_length=128)
    environment: Environment
    owner: str = Field(min_length=2, max_length=128)
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"], min_length=1, max_length=20)
    discovery_role_arn: str | None = None  # default: arn:aws:iam::<account>:role/SASWafDiscoveryRole (StackSet)
    response_role_arn: str | None = None

    @model_validator(mode="after")
    def _arns(self) -> "AccountCreate":
        for region in self.regions:
            if not re.match(REGION, region):
                raise ValueError(f"invalid region {region!r}")
        self.discovery_role_arn = self.discovery_role_arn or f"arn:aws:iam::{self.account_id}:role/SASWafDiscoveryRole"
        self.response_role_arn = self.response_role_arn or f"arn:aws:iam::{self.account_id}:role/SASWafResponseRole"
        for arn in (self.discovery_role_arn, self.response_role_arn):
            match = ROLE_ARN.match(arn)
            if not match or match.group(1) != self.account_id:
                raise ValueError(f"role ARN {arn!r} must be an IAM role in account {self.account_id}")
        return self


class AccountUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=128)
    environment: Environment | None = None
    owner: str | None = Field(None, min_length=2, max_length=128)
    regions: list[str] | None = Field(None, min_length=1, max_length=20)

    @model_validator(mode="after")
    def _regions(self) -> "AccountUpdate":
        for region in self.regions or []:
            if not re.match(REGION, region):
                raise ValueError(f"invalid region {region!r}")
        return self


class UserCreate(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=255)
    full_name: str = Field(min_length=2, max_length=128)
    role: RoleName
    sso_subject_id: str = Field(min_length=1, max_length=255)
    scoped_account_ids: list[str] = Field(default_factory=list, max_length=100)
    is_active: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, min_length=2, max_length=128)
    role: RoleName | None = None
    scoped_account_ids: list[str] | None = Field(None, max_length=100)
    is_active: bool | None = None


def account_row(a: Account) -> dict:
    return {"id": str(a.id), "account_id": a.account_id, "name": a.name, "environment": a.environment,
            "owner": a.owner, "regions": list(a.regions or []), "discovery_role_arn": a.discovery_role_arn,
            "response_role_arn": a.response_role_arn, "status": a.status}


def user_row(u: User) -> dict:
    return {"id": str(u.id), "email": u.email, "full_name": u.full_name, "role": u.role.name,
            "sso_subject_id": u.sso_subject_id, "scoped_account_ids": list(u.scoped_account_ids or []),
            "is_active": u.is_active, "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None}


def _audit(db, actor: Actor, *, account_id: str, action: str, target: str, previous, new, risk: str = "MEDIUM"):
    audit_service.record(db, actor_email=actor.email, actor_role=actor.role, account_id=account_id, region="global",
                         action=action, target_resource=target, previous_state=previous, new_state=new,
                         reason=f"{action} by {actor.email}", risk_level=risk, execution_status="EXECUTED")


# --- accounts -------------------------------------------------------------------------------------------

async def create_account(db: AsyncSession, body: AccountCreate, actor: Actor) -> Account:
    if await db.scalar(select(Account).where(Account.account_id == body.account_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Account {body.account_id} is already registered")
    account = Account(**body.model_dump())
    db.add(account)
    _audit(db, actor, account_id=body.account_id, action="ACCOUNT_REGISTERED", target=body.account_id, previous=None,
           new=body.model_dump())
    await db.commit()
    return account


async def update_account(db: AsyncSession, account_id: str, body: AccountUpdate, actor: Actor) -> Account:
    account = await db.scalar(select(Account).where(Account.account_id == account_id))
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    # Only fields that really differ: an empty or repeated PATCH must not add an ACCOUNT_UPDATED audit event
    changes = {k: v for k, v in body.model_dump(exclude_none=True).items() if getattr(account, k) != v}
    if not changes:
        return account
    previous = {k: getattr(account, k) for k in changes}
    for key, value in changes.items():
        setattr(account, key, value)
    _audit(db, actor, account_id=account_id, action="ACCOUNT_UPDATED", target=account_id, previous=previous,
           new=changes)
    await db.commit()
    return account


# --- users ------------------------------------------------------------------------------------------------

async def _role(db: AsyncSession, name: str) -> Role:
    return await db.scalar(select(Role).where(Role.name == name))


async def _validate_scope(db: AsyncSession, account_ids: list[str]) -> None:
    bad = [a for a in account_ids if not re.match(ACCOUNT_ID, a)]
    known = set((await db.scalars(select(Account.account_id).where(Account.account_id.in_(account_ids)))).all())
    unknown = sorted(set(account_ids) - known) + bad
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown scoped account(s): {', '.join(unknown)}")


async def _active_admins(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(User).join(Role, Role.id == User.role_id)
                           .where(Role.name == "Security Admin", User.is_active))


async def create_user(db: AsyncSession, body: UserCreate, actor: Actor) -> User:
    if await db.scalar(select(User).where((User.email == body.email) | (User.sso_subject_id == body.sso_subject_id))):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with that email or SSO subject already exists")
    await _validate_scope(db, body.scoped_account_ids)
    role = await _role(db, body.role)
    user = User(email=body.email, full_name=body.full_name, role_id=role.id, sso_subject_id=body.sso_subject_id,
                scoped_account_ids=body.scoped_account_ids, is_active=body.is_active)
    db.add(user)
    _audit(db, actor, account_id="GLOBAL", action="USER_PROVISIONED", target=body.email, previous=None,
           new=body.model_dump(), risk="HIGH" if body.role == "Security Admin" else "MEDIUM")
    await db.commit()
    await db.refresh(user, ["role"])
    return user


async def update_user(db: AsyncSession, redis: Redis, user_id, body: UserUpdate, actor: Actor) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    changes = body.model_dump(exclude_none=True)
    previous = {"full_name": user.full_name, "role": user.role.name,
                "scoped_account_ids": list(user.scoped_account_ids or []), "is_active": user.is_active}
    loses_admin = user.role.name == "Security Admin" and user.is_active and (
        changes.get("is_active") is False or changes.get("role", "Security Admin") != "Security Admin")
    if loses_admin and await _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Refusing to remove the last active Security Admin")
    if "scoped_account_ids" in changes:
        await _validate_scope(db, changes["scoped_account_ids"])
        user.scoped_account_ids = changes["scoped_account_ids"]
    if "full_name" in changes:
        user.full_name = changes["full_name"]
    if "role" in changes:
        user.role_id = (await _role(db, changes["role"])).id
    if "is_active" in changes:
        user.is_active = changes["is_active"]
    action = "USER_DEACTIVATED" if changes.get("is_active") is False else "USER_UPDATED"
    escalation = changes.get("role") == "Security Admin" or loses_admin
    _audit(db, actor, account_id="GLOBAL", action=action, target=user.email, previous=previous, new=changes,
           risk="HIGH" if escalation or action == "USER_DEACTIVATED" else "MEDIUM")
    await db.commit()
    if "role" in changes or "is_active" in changes or "scoped_account_ids" in changes:
        await revoke_user_sessions(redis, user.id)  # privileges changed: force a fresh login
    # Reload row + joined role (role_id may have changed); async sessions can't lazy-load expired attributes.
    return await db.scalar(select(User).where(User.id == user.id).execution_options(populate_existing=True))
