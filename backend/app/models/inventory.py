"""Accounts, identity, AWS resource inventory and platform health."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base

TZ = TIMESTAMP(timezone=True)
NOW = text("now()")


def pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        Index("idx_accounts_status", "status"),
        Index("idx_accounts_env", "environment"),
    )

    id: Mapped[uuid.UUID] = pk()
    account_id: Mapped[str] = mapped_column(String(12), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    environment: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(128))
    regions: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("ARRAY['us-east-1'::text]"))
    discovery_role_arn: Mapped[str] = mapped_column(String(255))
    response_role_arn: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), server_default=text("'HEALTHY'"))
    visibility_level: Mapped[str] = mapped_column(String(16), server_default=text("'sampled'"))
    logging_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    security_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    score_confidence: Mapped[str] = mapped_column(String(16), server_default=text("'SAMPLED'"))
    monthly_waf_cost: Mapped[Decimal] = mapped_column(Numeric(10, 2), server_default=text("0.00"))
    last_discovered: Mapped[datetime | None] = mapped_column(TZ)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = pk()
    name: Mapped[str] = mapped_column(String(64), unique=True)
    permissions: Mapped[list[str]] = mapped_column(ARRAY(Text))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = pk()
    email: Mapped[str] = mapped_column(String(255), unique=True)
    full_name: Mapped[str] = mapped_column(String(128))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"))
    sso_subject_id: Mapped[str] = mapped_column(String(255), unique=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    scoped_account_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(12)), server_default=text("'{}'"))
    last_login_at: Mapped[datetime | None] = mapped_column(TZ)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)

    role: Mapped[Role] = relationship(lazy="joined")


class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (UniqueConstraint("account_id", "name"),)

    id: Mapped[uuid.UUID] = pk()
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    owner_email: Mapped[str] = mapped_column(String(255))
    criticality: Mapped[str] = mapped_column(String(16), server_default=text("'HIGH'"))
    security_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    created_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class WebAcl(Base):
    __tablename__ = "web_acls"
    __table_args__ = (
        Index("idx_web_acls_account", "account_id"),
        Index("idx_web_acls_score", "security_score"),
    )

    id: Mapped[uuid.UUID] = pk()
    webacl_id: Mapped[str] = mapped_column(String(128))
    arn: Mapped[str] = mapped_column(String(512), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    region: Mapped[str] = mapped_column(String(32))
    scope: Mapped[str] = mapped_column(String(16))
    default_action: Mapped[str] = mapped_column(String(16))
    capacity: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    security_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    score_confidence: Mapped[str] = mapped_column(String(16), server_default=text("'SAMPLED'"))
    score_evidence: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    logging_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    logging_destination: Mapped[str | None] = mapped_column(String(512))
    visibility_level: Mapped[str] = mapped_column(String(16), server_default=text("'sampled'"))
    requests_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    blocked_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    allowed_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    counted_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    malicious_allowed_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    baseline_config: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    monthly_cost: Mapped[Decimal] = mapped_column(Numeric(10, 2), server_default=text("0.00"))
    last_synced_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        Index("idx_endpoints_account_waf", "account_id", "waf_status"),
        Index(
            "idx_endpoints_unprotected", "internet_facing", "waf_status",
            postgresql_where=text("internet_facing = true AND waf_status = 'UNPROTECTED'"),
        ),
    )

    id: Mapped[uuid.UUID] = pk()
    resource_arn: Mapped[str] = mapped_column(String(512), unique=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    application_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("applications.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(255))
    type: Mapped[str] = mapped_column(String(16))
    region: Mapped[str] = mapped_column(String(32))
    dns_name: Mapped[str] = mapped_column(String(512))
    internet_facing: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    waf_status: Mapped[str] = mapped_column(String(24))
    webacl_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("web_acls.id", ondelete="SET NULL"))
    logging_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    visibility_level: Mapped[str] = mapped_column(String(16), server_default=text("'sampled'"))
    requests_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    blocked_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    malicious_allowed_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    last_verified_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        UniqueConstraint("webacl_id", "name"),
        Index("idx_rules_webacl", "webacl_id"),
        Index("idx_rules_action", "action"),
    )

    id: Mapped[uuid.UUID] = pk()
    webacl_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("web_acls.id", ondelete="CASCADE"))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    priority: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(16))
    statement: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    managed_group_name: Mapped[str | None] = mapped_column(String(255))
    vendor_name: Mapped[str | None] = mapped_column(String(64))
    current_version: Mapped[str | None] = mapped_column(String(64))
    available_version: Mapped[str | None] = mapped_column(String(64))
    version_status: Mapped[str | None] = mapped_column(String(16))
    excluded_rules: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    scope_down_statement: Mapped[str | None] = mapped_column(Text)
    rate_limit: Mapped[int | None] = mapped_column(Integer)
    matches_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    blocked_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    counted_24h: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    false_positives_30d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    effectiveness: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("100.00"))
    updated_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class ManagedRuleVersion(Base):
    __tablename__ = "managed_rule_versions"

    id: Mapped[uuid.UUID] = pk()
    webacl_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("web_acls.id", ondelete="CASCADE"))
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"))
    vendor_name: Mapped[str] = mapped_column(String(64))
    managed_group_name: Mapped[str] = mapped_column(String(255))
    current_version: Mapped[str] = mapped_column(String(64))
    available_version: Mapped[str] = mapped_column(String(64))
    version_status: Mapped[str] = mapped_column(String(16))
    last_checked_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class PlatformHealth(Base):
    __tablename__ = "platform_health"
    __table_args__ = (
        UniqueConstraint(
            "component", "account_id", name="uq_platform_health_component_account",
            postgresql_nulls_not_distinct=True,
        ),
    )

    id: Mapped[uuid.UUID] = pk()
    component: Mapped[str] = mapped_column(String(32))
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(24))
    detail: Mapped[str] = mapped_column(Text, server_default=text("''"))
    error: Mapped[str | None] = mapped_column(Text)
    affected_modules: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    last_success: Mapped[datetime | None] = mapped_column(TZ)
    last_check: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
