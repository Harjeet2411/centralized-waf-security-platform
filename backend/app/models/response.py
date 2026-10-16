"""Guardrails, simulation, controlled response, audit and drift."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base
from app.models.inventory import NOW, TZ, pk


class AllowListEntry(Base):
    __tablename__ = "allow_list_entries"
    __table_args__ = (
        Index("idx_allow_list_cidr", "ip_network", postgresql_using="gist", postgresql_ops={"ip_network": "inet_ops"}),
    )

    id: Mapped[uuid.UUID] = pk()
    cidr_or_value: Mapped[str] = mapped_column(String(128), unique=True)
    ip_network: Mapped[str | None] = mapped_column(CIDR)
    entity_type: Mapped[str] = mapped_column(String(16), server_default=text("'IP_CIDR'"))
    name: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Simulation(Base):
    __tablename__ = "simulations"

    id: Mapped[uuid.UUID] = pk()
    title: Mapped[str] = mapped_column(String(255))
    proposed_action: Mapped[str] = mapped_column(String(64))
    target_webacl_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)))
    target_accounts: Mapped[list[str]] = mapped_column(ARRAY(String(12)))
    target_apps: Mapped[list[str]] = mapped_column(ARRAY(Text))
    proposed_statement: Mapped[dict] = mapped_column(JSONB)
    evaluated_requests: Mapped[int] = mapped_column(BigInteger)
    would_block: Mapped[int] = mapped_column(BigInteger)
    would_allow: Mapped[int] = mapped_column(BigInteger)
    potential_false_positives: Mapped[int] = mapped_column(BigInteger)
    fp_rate_percent: Mapped[Decimal] = mapped_column(Numeric(6, 3))
    legitimate_impact: Mapped[str] = mapped_column(String(16))
    risk_reduction: Mapped[str] = mapped_column(String(16))
    allow_list_passed: Mapped[bool] = mapped_column(Boolean)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = pk()
    approval_code: Mapped[str] = mapped_column(String(32), unique=True)
    action_type: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(255))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id"))
    account_name: Mapped[str] = mapped_column(String(128))
    webacl_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("web_acls.id"))
    webacl_name: Mapped[str] = mapped_column(String(128))
    application: Mapped[str] = mapped_column(String(128))
    requested_by: Mapped[str] = mapped_column(String(255))
    requested_by_role: Mapped[str] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    reason: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(16))
    ttl_hours: Mapped[int | None] = mapped_column(Integer)
    expires_at: Mapped[datetime | None] = mapped_column(TZ)
    allow_list_check: Mapped[str] = mapped_column(String(32))
    simulation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("simulations.id"))
    simulation_summary: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    impact_scope: Mapped[str] = mapped_column(Text)
    required_approver_role: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), server_default=text("'PENDING'"))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(TZ)
    aws_request_id: Mapped[str | None] = mapped_column(String(128))
    verification_status: Mapped[str | None] = mapped_column(String(16), server_default=text("'PENDING'"))
    previous_state: Mapped[str] = mapped_column(Text)
    proposed_state: Mapped[str] = mapped_column(Text)


class Change(Base):
    __tablename__ = "changes"

    id: Mapped[uuid.UUID] = pk()
    approval_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("approvals.id", ondelete="RESTRICT"))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id"))
    webacl_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("web_acls.id"))
    previous_state_json: Mapped[dict] = mapped_column(JSONB)
    new_state_json: Mapped[dict] = mapped_column(JSONB)
    aws_lock_token_before: Mapped[str | None] = mapped_column(String(128))
    aws_lock_token_after: Mapped[str | None] = mapped_column(String(128))
    aws_request_id: Mapped[str] = mapped_column(String(128))
    execution_status: Mapped[str] = mapped_column(String(24))
    verification_status: Mapped[str] = mapped_column(String(24))
    ttl_status: Mapped[str | None] = mapped_column(String(24))
    expires_at: Mapped[datetime | None] = mapped_column(TZ)
    executed_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    rolled_back_at: Mapped[datetime | None] = mapped_column(TZ)
    rolled_back_by: Mapped[str | None] = mapped_column(String(255))
    rollback_available: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class ApprovalDecision(Base):
    __tablename__ = "approval_decisions"
    __table_args__ = (UniqueConstraint("approval_id", "decided_by", name="uq_approval_decisions_person"),)

    id: Mapped[uuid.UUID] = pk()
    approval_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("approvals.id", ondelete="RESTRICT"))
    slot: Mapped[int] = mapped_column(Integer)
    decided_by: Mapped[str] = mapped_column(String(255))
    decided_by_role: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))
    comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class AuditEvent(Base):
    """Append-only (Rule #6): UPDATE/DELETE/TRUNCATE raise via trg_immutable_audit*."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = pk()
    audit_code: Mapped[str] = mapped_column(String(32), unique=True)
    timestamp: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    user_email: Mapped[str] = mapped_column(String(255))
    user_role: Mapped[str] = mapped_column(String(64))
    account_id: Mapped[str] = mapped_column(String(12))
    region: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(128))
    target_resource: Mapped[str] = mapped_column(String(512))
    previous_state: Mapped[str] = mapped_column(Text)
    new_state: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(16))
    approver: Mapped[str] = mapped_column(String(255))
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"))
    execution_status: Mapped[str] = mapped_column(String(32))
    aws_request_id: Mapped[str] = mapped_column(String(128))
    verification_status: Mapped[str] = mapped_column(String(32))
    rollback_available: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class DriftEvent(Base):
    __tablename__ = "drift_events"

    id: Mapped[uuid.UUID] = pk()
    drift_code: Mapped[str] = mapped_column(String(32), unique=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    account_name: Mapped[str] = mapped_column(String(128))
    webacl_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("web_acls.id", ondelete="CASCADE"))
    webacl_name: Mapped[str] = mapped_column(String(128))
    drift_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    expected_state: Mapped[str] = mapped_column(Text)
    actual_state: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    status: Mapped[str] = mapped_column(String(24), server_default=text("'OPEN'"))
