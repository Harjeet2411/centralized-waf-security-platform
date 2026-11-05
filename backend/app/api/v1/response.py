"""Simulation, controlled response, rollback, allow-list and audit APIs (Milestone 4)."""

import csv
import io
import ipaddress
import json
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import events
from app.database import get_db, get_redis
from app.models import AllowListEntry, Approval, ApprovalDecision, AuditEvent, Change
from app.schemas import contract as c
from app.security import Principal, require
from app.services import approval_service, audit_service, simulator_service

router = APIRouter(tags=["response"])


def get_executor_factory() -> approval_service.ExecutorFactory:
    """Overridden in tests; production assumes SASWafResponseRole per approval."""
    return approval_service.default_executor_factory


# --- simulation -----------------------------------------------------------------------------------------

@router.post("/simulations", status_code=status.HTTP_201_CREATED)
async def create_simulation(req: simulator_service.SimulationRequest,
                            principal: Principal = Depends(require("SIMULATE")), db: AsyncSession = Depends(get_db)):
    result = await simulator_service.simulate(db, req, principal.email, principal.account_scope("SIMULATE"))
    await db.commit()
    return result


@router.get("/simulations/false-positives")
async def false_positives(webacl_id: uuid.UUID, window_hours: int = Query(168, ge=1, le=720),
                          _: Principal = Depends(require("SIMULATE")), db: AsyncSession = Depends(get_db)):
    return await simulator_service.false_positive_candidates(db, str(webacl_id), window_hours)


# --- approvals ------------------------------------------------------------------------------------------

async def _detail(db: AsyncSession, approval: Approval) -> dict:
    decisions = (await db.scalars(select(ApprovalDecision).where(ApprovalDecision.approval_id == approval.id)
                                  .order_by(ApprovalDecision.decided_at))).all()
    changes = (await db.scalars(select(Change).where(Change.approval_id == approval.id))).all()
    return {
        "approval": approval_service.approval_out(approval).model_dump(),
        "lifecycle": approval_service.lifecycle(approval),
        "decisions": [{"slot": d.slot, "decided_by": d.decided_by, "role": d.decided_by_role, "decision": d.decision,
                       "comment": d.comment, "decided_at": c.iso(d.decided_at)} for d in decisions],
        "proposed_state": json.loads(approval.proposed_state), "previous_state": json.loads(approval.previous_state),
        "changes": [_change(ch) for ch in changes],
    }


def _change(ch: Change) -> dict:
    return {"id": str(ch.id), "approval_id": str(ch.approval_id), "account_id": ch.account_id,
            "aws_request_id": ch.aws_request_id, "execution_status": ch.execution_status,
            "verification_status": ch.verification_status, "ttl_status": ch.ttl_status,
            "expires_at": c.iso(ch.expires_at) or None, "executed_at": c.iso(ch.executed_at),
            "rolled_back_at": c.iso(ch.rolled_back_at) or None, "rolled_back_by": ch.rolled_back_by,
            "rollback_available": ch.rollback_available and ch.execution_status == "EXECUTED"}


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
async def create_approval(req: approval_service.ApprovalRequest,
                          principal: Principal = Depends(require("CREATE_CHANGE")),
                          db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis)):
    approval = await approval_service.create_approval(db, req, principal)
    await events.publish(redis, "APPROVAL_REQUESTED", {"id": str(approval.id), "code": approval.approval_code})
    return await _detail(db, approval)


# The approvals.status CHECK constraint (alembic 0001)
APPROVAL_STATUSES = ("PENDING", "APPROVED", "REJECTED", "EXECUTED", "VERIFIED", "ROLLED_BACK", "EXPIRED")


@router.get("/approvals", response_model=list[c.ApprovalOut])
async def list_approvals(status_filter: str | None = Query(None, alias="status"),
                         _: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)):
    query = select(Approval).order_by(Approval.requested_at.desc()).limit(500)
    if status_filter:
        wanted = status_filter.upper()
        if wanted not in APPROVAL_STATUSES:
            # A typo used to return an empty list, which looks like "nothing pending"
            expected = ", ".join(APPROVAL_STATUSES).lower()
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                f"Unknown status {status_filter!r}; expected one of {expected}")
        query = query.where(Approval.status == wanted)
    return [approval_service.approval_out(a) for a in (await db.scalars(query)).all()]


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: uuid.UUID, _: Principal = Depends(require("VIEW")),
                       db: AsyncSession = Depends(get_db)):
    approval = await db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    return await _detail(db, approval)


class Decision(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    comment: str | None = Field(None, max_length=2000)


@router.post("/approvals/{approval_id}/decide")
async def decide(approval_id: uuid.UUID, body: Decision, principal: Principal = Depends(require("APPROVE")),
                 db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
                 executor_factory: approval_service.ExecutorFactory = Depends(get_executor_factory)):
    approval = await approval_service.decide(db, approval_id, body.decision, body.comment, principal, executor_factory)
    await db.refresh(approval)
    await events.publish(redis, "APPROVAL_UPDATED", {"id": str(approval.id), "status": approval.status})
    return await _detail(db, approval)


# --- changes / rollback -----------------------------------------------------------------------------------

@router.get("/changes")
async def list_changes(_: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)):
    return [_change(ch) for ch in (await db.scalars(select(Change).order_by(Change.executed_at.desc())
                                                    .limit(500))).all()]


@router.get("/response/active-blocks")
async def active_blocks(_: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)):
    return [{**b, "id": str(b["id"]), "expires_at": c.iso(b["expires_at"]) or None,
             "executed_at": c.iso(b["executed_at"])} for b in await approval_service.active_blocks(db)]


class RollbackRequest(BaseModel):
    reason: str = Field("Manual rollback", min_length=3, max_length=2000)


@router.post("/changes/{change_id}/rollback")
async def rollback_change(change_id: uuid.UUID, body: RollbackRequest | None = None,
                          principal: Principal = Depends(require("ROLLBACK")), db: AsyncSession = Depends(get_db),
                          executor_factory: approval_service.ExecutorFactory = Depends(get_executor_factory)):
    change = await approval_service.rollback(db, change_id, principal, executor_factory,
                                             reason=(body or RollbackRequest()).reason)
    return _change(change)


# --- allow-list ---------------------------------------------------------------------------------------------

class AllowListCreate(BaseModel):
    cidr_or_value: str = Field(max_length=128)
    entity_type: Literal["IP_CIDR", "ASN", "HEALTH_CHECK"] = "IP_CIDR"
    name: str = Field(min_length=2, max_length=128)
    category: Literal["INTERNAL_NETWORK", "PAYMENT_GATEWAY", "PARTNER_API", "MONITORING", "SECURITY_SCANNER"]
    owner: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=5, max_length=2000)


def _allow_entry(a: AllowListEntry) -> dict:
    return {"id": str(a.id), "cidr_or_value": a.cidr_or_value, "entity_type": a.entity_type, "name": a.name,
            "category": a.category, "owner": a.owner, "reason": a.reason, "is_active": a.is_active,
            "created_by": a.created_by, "created_at": c.iso(a.created_at)}


@router.get("/allow-list")
async def list_allow_list(_: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)):
    return [_allow_entry(a) for a in (await db.scalars(select(AllowListEntry).order_by(AllowListEntry.name))).all()]


@router.post("/allow-list", status_code=status.HTTP_201_CREATED)
async def add_allow_list(body: AllowListCreate, principal: Principal = Depends(require("MANAGE_TI")),
                         db: AsyncSession = Depends(get_db)):
    network = None
    if body.entity_type in ("IP_CIDR", "HEALTH_CHECK"):
        try:
            network = str(ipaddress.ip_network(body.cidr_or_value.strip(), strict=False))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid CIDR") from exc
    entry = AllowListEntry(cidr_or_value=network or body.cidr_or_value.strip(), ip_network=network,
                           entity_type=body.entity_type, name=body.name, category=body.category, owner=body.owner,
                           reason=body.reason, created_by=principal.email)
    db.add(entry)
    audit_service.record(db, actor_email=principal.email, actor_role=principal.role, account_id="GLOBAL",
                         region="global", action="ALLOW_LIST_ADD", target_resource=entry.cidr_or_value,
                         new_state=body.model_dump(), reason=body.reason, risk_level="MEDIUM",
                         execution_status="EXECUTED")
    await db.commit()
    return _allow_entry(entry)


@router.post("/allow-list/{entry_id}/deactivate")
async def deactivate_allow_list(entry_id: uuid.UUID, body: RollbackRequest,
                                principal: Principal = Depends(require("APPROVE")),
                                db: AsyncSession = Depends(get_db)):
    # Removing protection exposes partners/payment gateways to blocking: Security Admin (unqualified APPROVE) only.
    if "*" not in approval_service.rbac_service.qualifiers(principal.permissions, "APPROVE"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a Security Admin can remove allow-list protection")
    entry = await db.get(AllowListEntry, entry_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Allow-list entry not found")
    entry.is_active = False
    audit_service.record(db, actor_email=principal.email, actor_role=principal.role, account_id="GLOBAL",
                         region="global", action="ALLOW_LIST_DEACTIVATE", target_resource=entry.cidr_or_value,
                         previous_state={"is_active": True}, new_state={"is_active": False}, reason=body.reason,
                         risk_level="HIGH", execution_status="EXECUTED")
    await db.commit()
    return _allow_entry(entry)


# --- audit export (governance) -------------------------------------------------------------------------------

AUDIT_FIELDS = ["audit_code", "timestamp", "user_email", "user_role", "account_id", "region", "action",
                "target_resource", "previous_state", "new_state", "reason", "risk_level", "approver", "approval_id",
                "execution_status", "aws_request_id", "verification_status", "rollback_available"]


@router.get("/governance/audit")
async def audit_trail(
    start: datetime | None = Query(None, alias="from"), end: datetime | None = Query(None, alias="to"),
    action: str | None = None, account_id: str | None = None,
    export: Literal["json", "csv"] = Query("json", alias="format"),
    limit: int = Query(1000, ge=1, le=10_000), _: Principal = Depends(require("VIEW")),
    db: AsyncSession = Depends(get_db),
):
    if start and end and start > end:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "'from' must not be later than 'to'")
    query = select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit)
    if start:
        query = query.where(AuditEvent.timestamp >= start)
    if end:
        query = query.where(AuditEvent.timestamp <= end)
    if action:
        query = query.where(AuditEvent.action == action.upper())
    if account_id:
        query = query.where(AuditEvent.account_id == account_id)
    rows = [{f: (c.iso(getattr(e, f)) if f == "timestamp" else (str(getattr(e, f)) if f == "approval_id" and
             getattr(e, f) else getattr(e, f))) for f in AUDIT_FIELDS} for e in (await db.scalars(query)).all()]
    if export == "json":
        return rows
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=AUDIT_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return Response(buffer.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sas-waf-audit.csv"})
