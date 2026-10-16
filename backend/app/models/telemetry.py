"""WAF events, entity intelligence, campaigns, detections and threat-intel cache."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Numeric, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base
from app.models.inventory import NOW, TZ, pk


class WafEvent(Base):
    __tablename__ = "waf_events"
    __table_args__ = (
        Index("idx_waf_events_timestamp", text("timestamp DESC")),
        Index("idx_waf_events_client_ip", "client_ip", text("timestamp DESC")),
        Index("idx_waf_events_ja4", "ja4", text("timestamp DESC"), postgresql_where=text("ja4 IS NOT NULL")),
        Index(
            "idx_waf_events_malicious_allow", "action", "classification", text("timestamp DESC"),
            postgresql_where=text("action = 'ALLOW'"),
        ),
        Index("idx_waf_events_http_jsonb", "http_request", postgresql_using="gin"),
        Index("idx_waf_events_ingested", "ingested_at"),
    )

    id: Mapped[uuid.UUID] = pk()
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(TZ)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
    webacl_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("web_acls.id", ondelete="CASCADE"))
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"))
    client_ip: Mapped[str] = mapped_column(INET)
    country: Mapped[str | None] = mapped_column(String(8))
    asn: Mapped[str | None] = mapped_column(String(32))
    organization: Mapped[str | None] = mapped_column(String(255))
    http_method: Mapped[str] = mapped_column(String(16))
    host: Mapped[str | None] = mapped_column(String(255))
    uri: Mapped[str] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    ja3: Mapped[str | None] = mapped_column(String(64))
    ja4: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(16))
    matched_rule_name: Mapped[str | None] = mapped_column(String(255))
    rule_groups: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    labels: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    attack_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    classification: Mapped[str] = mapped_column(String(16), server_default=text("'UNKNOWN'"))
    source: Mapped[str] = mapped_column(String(16))
    http_request: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    ingested_at: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("type", "value"),
        Index("idx_entities_risk", "risk_level", text("final_risk DESC")),
        Index("idx_entities_ja4", "ja4", postgresql_where=text("ja4 IS NOT NULL")),
        Index("idx_entities_type_value", "type", "value"),
    )

    id: Mapped[uuid.UUID] = pk()
    type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(Text)
    asn: Mapped[str | None] = mapped_column(String(32))
    organization: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(8))
    country_name: Mapped[str | None] = mapped_column(String(128))
    ja3: Mapped[str | None] = mapped_column(String(64))
    ja4: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)
    threat_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    business_impact: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    final_risk: Mapped[Decimal] = mapped_column(Numeric(5, 2), server_default=text("0.00"))
    risk_level: Mapped[str] = mapped_column(String(16), server_default=text("'LOW'"))
    classification: Mapped[str] = mapped_column(String(16), server_default=text("'UNKNOWN'"))
    first_seen: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    last_seen: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    request_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    blocked_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    allowed_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    counted_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    targeted_accounts: Mapped[list[str] | None] = mapped_column(ARRAY(String(12)), server_default=text("'{}'"))
    targeted_apps: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    targeted_uris: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    attack_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    is_allow_listed: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    allow_list_reason: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    # "metadata" is reserved on declarative classes; the column keeps its DB name.
    meta: Mapped[dict] = mapped_column("metadata", JSONB, server_default=text("'{}'::jsonb"))


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"
    __table_args__ = (UniqueConstraint("source_entity_id", "target_entity_id", "relationship_type"),)

    id: Mapped[uuid.UUID] = pk()
    source_entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    target_entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    relationship_type: Mapped[str] = mapped_column(String(32))
    observation_count: Mapped[int] = mapped_column(BigInteger, server_default=text("1"))
    first_observed: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    last_observed: Mapped[datetime] = mapped_column(TZ, server_default=NOW)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = pk()
    campaign_code: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), server_default=text("'ACTIVE'"))
    risk_level: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    shared_ja4: Mapped[str | None] = mapped_column(String(64))
    shared_ja3: Mapped[str | None] = mapped_column(String(64))
    entity_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), server_default=text("'{}'"))
    asns: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    countries: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    targeted_accounts: Mapped[list[str] | None] = mapped_column(ARRAY(String(12)), server_default=text("'{}'"))
    targeted_apps: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    targeted_uris: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    total_requests: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    blocked_requests: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    allowed_requests: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    start_time: Mapped[datetime] = mapped_column(TZ)
    last_active: Mapped[datetime] = mapped_column(TZ)
    correlation_evidence: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    attack_story: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text)


class Detection(Base):
    __tablename__ = "detections"
    __table_args__ = (Index("idx_detections_fingerprint", "fingerprint"),)

    id: Mapped[uuid.UUID] = pk()
    type: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, server_default=text("''"))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    status: Mapped[str] = mapped_column(String(24), server_default=text("'OPEN'"))
    entity_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), server_default=text("'{}'"))
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("campaigns.id", ondelete="SET NULL"))
    accounts: Mapped[list[str]] = mapped_column(ARRAY(String(12)), server_default=text("'{}'"))
    applications: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    requests_involved: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    allowed_requests: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    evidence: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    recommended_action: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    fingerprint: Mapped[str | None] = mapped_column(String(64))


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    __table_args__ = (UniqueConstraint("entity_id", "provider"),)

    id: Mapped[uuid.UUID] = pk()
    entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(32))
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    classification: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    raw_response: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    last_checked: Mapped[datetime] = mapped_column(TZ, server_default=NOW)
    expires_at: Mapped[datetime] = mapped_column(TZ)
