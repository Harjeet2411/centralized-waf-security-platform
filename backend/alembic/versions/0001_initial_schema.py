"""Initial schema: docs/BACKEND_SCHEMA.md DDL (20 tables) + platform_health + role seed.

Deviations from the doc, per CLAUDE.md section 9:
  * detections.description added (the frontend Detection type renders it).
  * platform_health added (TRD writes provider/collector health; PlatformHealth type reads it).

CHECK constraints, the audit immutability trigger and partial/GiST/GIN indexes live here; the ORM
models in app/models mirror columns, keys and indexes only.

Revision ID: 0001
Revises:
Create Date: 2026-10-17
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

DDL = r"""
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id VARCHAR(12) NOT NULL UNIQUE CHECK (account_id ~ '^[0-9]{12}$'),
    name VARCHAR(128) NOT NULL,
    environment VARCHAR(32) NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'shared-services', 'security')),
    owner VARCHAR(128) NOT NULL,
    regions TEXT[] NOT NULL DEFAULT ARRAY['us-east-1'],
    discovery_role_arn VARCHAR(255) NOT NULL,
    response_role_arn VARCHAR(255) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'HEALTHY' CHECK (status IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE')),
    visibility_level VARCHAR(16) NOT NULL DEFAULT 'sampled' CHECK (visibility_level IN ('full', 'sampled', 'metrics', 'none')),
    logging_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    security_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    score_confidence VARCHAR(16) NOT NULL DEFAULT 'SAMPLED' CHECK (score_confidence IN ('FULL', 'PARTIAL', 'SAMPLED', 'NONE')),
    monthly_waf_cost NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    last_discovered TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_accounts_status ON accounts(status);
CREATE INDEX idx_accounts_env ON accounts(environment);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE CHECK (name IN (
        'Security Admin', 'Security Analyst', 'SOC Analyst',
        'AWS Administrator', 'Application Owner', 'Auditor',
        'Executive', 'Read Only'
    )),
    permissions TEXT[] NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(128) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    sso_subject_id VARCHAR(255) NOT NULL UNIQUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    scoped_account_ids VARCHAR(12)[] DEFAULT '{}',
    last_login_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    owner_email VARCHAR(255) NOT NULL,
    criticality VARCHAR(16) NOT NULL DEFAULT 'HIGH' CHECK (criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    security_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(account_id, name)
);

CREATE TABLE web_acls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webacl_id VARCHAR(128) NOT NULL,
    arn VARCHAR(512) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    region VARCHAR(32) NOT NULL,
    scope VARCHAR(16) NOT NULL CHECK (scope IN ('REGIONAL', 'CLOUDFRONT')),
    default_action VARCHAR(16) NOT NULL CHECK (default_action IN ('ALLOW', 'BLOCK')),
    capacity INTEGER NOT NULL DEFAULT 0,
    security_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    score_confidence VARCHAR(16) NOT NULL DEFAULT 'SAMPLED' CHECK (score_confidence IN ('FULL', 'PARTIAL', 'SAMPLED', 'NONE')),
    score_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    logging_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    logging_destination VARCHAR(512),
    visibility_level VARCHAR(16) NOT NULL DEFAULT 'sampled' CHECK (visibility_level IN ('full', 'sampled', 'metrics', 'none')),
    requests_24h BIGINT NOT NULL DEFAULT 0,
    blocked_24h BIGINT NOT NULL DEFAULT 0,
    allowed_24h BIGINT NOT NULL DEFAULT 0,
    counted_24h BIGINT NOT NULL DEFAULT 0,
    malicious_allowed_24h BIGINT NOT NULL DEFAULT 0,
    baseline_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    monthly_cost NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_web_acls_account ON web_acls(account_id);
CREATE INDEX idx_web_acls_score ON web_acls(security_score);

CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_arn VARCHAR(512) NOT NULL UNIQUE,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(16) NOT NULL CHECK (type IN ('ALB', 'CLOUDFRONT', 'APIGW')),
    region VARCHAR(32) NOT NULL,
    dns_name VARCHAR(512) NOT NULL,
    internet_facing BOOLEAN NOT NULL DEFAULT TRUE,
    waf_status VARCHAR(24) NOT NULL CHECK (waf_status IN ('PROTECTED', 'PARTIALLY_PROTECTED', 'UNPROTECTED', 'UNKNOWN')),
    webacl_id UUID REFERENCES web_acls(id) ON DELETE SET NULL,
    logging_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    visibility_level VARCHAR(16) NOT NULL DEFAULT 'sampled' CHECK (visibility_level IN ('full', 'sampled', 'metrics', 'none')),
    requests_24h BIGINT NOT NULL DEFAULT 0,
    blocked_24h BIGINT NOT NULL DEFAULT 0,
    malicious_allowed_24h BIGINT NOT NULL DEFAULT 0,
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_endpoints_account_waf ON endpoints(account_id, waf_status);
CREATE INDEX idx_endpoints_unprotected ON endpoints(internet_facing, waf_status) WHERE internet_facing = TRUE AND waf_status = 'UNPROTECTED';

CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webacl_id UUID NOT NULL REFERENCES web_acls(id) ON DELETE CASCADE,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    priority INTEGER NOT NULL,
    type VARCHAR(16) NOT NULL CHECK (type IN ('MANAGED', 'CUSTOM', 'RATE_BASED', 'IP_SET')),
    action VARCHAR(16) NOT NULL CHECK (action IN ('BLOCK', 'ALLOW', 'COUNT', 'CAPTCHA', 'CHALLENGE')),
    statement JSONB NOT NULL DEFAULT '{}'::jsonb,
    managed_group_name VARCHAR(255),
    vendor_name VARCHAR(64),
    current_version VARCHAR(64),
    available_version VARCHAR(64),
    version_status VARCHAR(16) CHECK (version_status IN ('CURRENT', 'OUTDATED', 'DEPRECATED', 'UNKNOWN')),
    excluded_rules TEXT[] DEFAULT '{}',
    scope_down_statement TEXT,
    rate_limit INTEGER,
    matches_24h BIGINT NOT NULL DEFAULT 0,
    blocked_24h BIGINT NOT NULL DEFAULT 0,
    counted_24h BIGINT NOT NULL DEFAULT 0,
    false_positives_30d INTEGER NOT NULL DEFAULT 0,
    effectiveness NUMERIC(5,2) NOT NULL DEFAULT 100.00,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(webacl_id, name)
);
CREATE INDEX idx_rules_webacl ON rules(webacl_id);
CREATE INDEX idx_rules_action ON rules(action);

CREATE TABLE managed_rule_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webacl_id UUID NOT NULL REFERENCES web_acls(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    vendor_name VARCHAR(64) NOT NULL,
    managed_group_name VARCHAR(255) NOT NULL,
    current_version VARCHAR(64) NOT NULL,
    available_version VARCHAR(64) NOT NULL,
    version_status VARCHAR(16) NOT NULL CHECK (version_status IN ('CURRENT', 'OUTDATED', 'DEPRECATED', 'UNKNOWN')),
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ponytail: single unpartitioned table; add monthly range partitions on timestamp + retention job
-- once waf_events volume makes the 24h/30d scans slow.
CREATE TABLE waf_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_hash VARCHAR(64) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    webacl_id UUID NOT NULL REFERENCES web_acls(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,
    client_ip INET NOT NULL,
    country VARCHAR(8),
    asn VARCHAR(32),
    organization VARCHAR(255),
    http_method VARCHAR(16) NOT NULL,
    host VARCHAR(255),
    uri TEXT NOT NULL,
    user_agent TEXT,
    ja3 VARCHAR(64),
    ja4 VARCHAR(64),
    action VARCHAR(16) NOT NULL CHECK (action IN ('BLOCK', 'ALLOW', 'COUNT', 'CAPTCHA', 'CHALLENGE')),
    matched_rule_name VARCHAR(255),
    rule_groups TEXT[] DEFAULT '{}',
    labels TEXT[] DEFAULT '{}',
    attack_techniques TEXT[] DEFAULT '{}',
    classification VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN' CHECK (classification IN ('LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
    source VARCHAR(16) NOT NULL CHECK (source IN ('SAMPLED', 'FULL_LOG')),
    http_request JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_waf_events_timestamp ON waf_events(timestamp DESC);
CREATE INDEX idx_waf_events_client_ip ON waf_events(client_ip, timestamp DESC);
CREATE INDEX idx_waf_events_ja4 ON waf_events(ja4, timestamp DESC) WHERE ja4 IS NOT NULL;
CREATE INDEX idx_waf_events_malicious_allow ON waf_events(action, classification, timestamp DESC) WHERE action = 'ALLOW';
CREATE INDEX idx_waf_events_http_jsonb ON waf_events USING GIN (http_request);

CREATE TABLE entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(24) NOT NULL CHECK (type IN ('IP', 'ASN', 'COUNTRY', 'ORG', 'JA3', 'JA4', 'USER_AGENT', 'URI_PATTERN')),
    value TEXT NOT NULL,
    asn VARCHAR(32),
    organization VARCHAR(255),
    country VARCHAR(8),
    country_name VARCHAR(128),
    ja3 VARCHAR(64),
    ja4 VARCHAR(64),
    user_agent TEXT,
    threat_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    confidence NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    business_impact NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    final_risk NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    classification VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN' CHECK (classification IN ('LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_count BIGINT NOT NULL DEFAULT 0,
    blocked_count BIGINT NOT NULL DEFAULT 0,
    allowed_count BIGINT NOT NULL DEFAULT 0,
    counted_count BIGINT NOT NULL DEFAULT 0,
    targeted_accounts VARCHAR(12)[] DEFAULT '{}',
    targeted_apps TEXT[] DEFAULT '{}',
    targeted_uris TEXT[] DEFAULT '{}',
    attack_techniques TEXT[] DEFAULT '{}',
    is_allow_listed BOOLEAN NOT NULL DEFAULT FALSE,
    allow_list_reason TEXT,
    recommended_action TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE(type, value)
);
CREATE INDEX idx_entities_risk ON entities(risk_level, final_risk DESC);
CREATE INDEX idx_entities_ja4 ON entities(ja4) WHERE ja4 IS NOT NULL;
CREATE INDEX idx_entities_type_value ON entities(type, value);

CREATE TABLE entity_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship_type VARCHAR(32) NOT NULL CHECK (relationship_type IN ('BELONGS_TO_ASN', 'USES_JA4', 'USES_JA3', 'USES_UA', 'TARGETS_URI', 'CORRELATED_WITH')),
    observation_count BIGINT NOT NULL DEFAULT 1,
    first_observed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_observed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_entity_id, target_entity_id, relationship_type)
);

CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INVESTIGATING', 'MITIGATED', 'RESOLVED')),
    risk_level VARCHAR(16) NOT NULL CHECK (risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    confidence NUMERIC(5,2) NOT NULL,
    shared_ja4 VARCHAR(64),
    shared_ja3 VARCHAR(64),
    entity_ids UUID[] NOT NULL DEFAULT '{}',
    asns TEXT[] DEFAULT '{}',
    countries TEXT[] DEFAULT '{}',
    targeted_accounts VARCHAR(12)[] DEFAULT '{}',
    targeted_apps TEXT[] DEFAULT '{}',
    targeted_uris TEXT[] DEFAULT '{}',
    techniques TEXT[] DEFAULT '{}',
    total_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    allowed_requests BIGINT NOT NULL DEFAULT 0,
    start_time TIMESTAMPTZ NOT NULL,
    last_active TIMESTAMPTZ NOT NULL,
    correlation_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    attack_story TEXT NOT NULL,
    recommended_action TEXT NOT NULL
);

CREATE TABLE detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(32) NOT NULL CHECK (type IN (
        'SCANNER', 'CREDENTIAL_ATTACK', 'DISTRIBUTED_ATTACK',
        'SLOW_DISTRIBUTED', 'BOT_AUTOMATION', 'SQLI_CAMPAIGN',
        'MALICIOUS_ALLOWED', 'JA4_CORRELATION'
    )),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    confidence NUMERIC(5,2) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'PENDING_APPROVAL', 'MITIGATED')),
    entity_ids UUID[] NOT NULL DEFAULT '{}',
    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    accounts VARCHAR(12)[] NOT NULL DEFAULT '{}',
    applications TEXT[] NOT NULL DEFAULT '{}',
    requests_involved BIGINT NOT NULL DEFAULT 0,
    allowed_requests BIGINT NOT NULL DEFAULT 0,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_action TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('AbuseIPDB', 'GreyNoise', 'VirusTotal', 'GuardDuty', 'Internal')),
    score NUMERIC(5,2) NOT NULL,
    classification VARCHAR(16) NOT NULL CHECK (classification IN ('malicious', 'suspicious', 'benign', 'unknown')),
    confidence NUMERIC(5,2) NOT NULL,
    tags TEXT[] DEFAULT '{}',
    raw_response JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(entity_id, provider)
);

CREATE TABLE allow_list_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr_or_value VARCHAR(128) NOT NULL UNIQUE,
    ip_network CIDR,
    entity_type VARCHAR(16) NOT NULL DEFAULT 'IP_CIDR' CHECK (entity_type IN ('IP_CIDR', 'ASN', 'HEALTH_CHECK')),
    name VARCHAR(128) NOT NULL,
    category VARCHAR(32) NOT NULL CHECK (category IN ('INTERNAL_NETWORK', 'PAYMENT_GATEWAY', 'PARTNER_API', 'MONITORING', 'SECURITY_SCANNER')),
    owner VARCHAR(128) NOT NULL,
    reason TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_allow_list_cidr ON allow_list_entries USING GIST (ip_network inet_ops);

CREATE TABLE simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    proposed_action VARCHAR(64) NOT NULL,
    target_webacl_ids UUID[] NOT NULL,
    target_accounts VARCHAR(12)[] NOT NULL,
    target_apps TEXT[] NOT NULL,
    proposed_statement JSONB NOT NULL,
    evaluated_requests BIGINT NOT NULL,
    would_block BIGINT NOT NULL,
    would_allow BIGINT NOT NULL,
    potential_false_positives BIGINT NOT NULL,
    fp_rate_percent NUMERIC(6,3) NOT NULL,
    legitimate_impact VARCHAR(16) NOT NULL CHECK (legitimate_impact IN ('NONE', 'LOW', 'MEDIUM', 'HIGH')),
    risk_reduction VARCHAR(16) NOT NULL CHECK (risk_reduction IN ('HIGH', 'MEDIUM', 'LOW')),
    allow_list_passed BOOLEAN NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_code VARCHAR(32) NOT NULL UNIQUE,
    action_type VARCHAR(32) NOT NULL CHECK (action_type IN (
        'TEMP_BLOCK_IP', 'PERM_BLOCK_IP', 'REMOVE_BLOCK',
        'MODIFY_RULE', 'ADD_EXCEPTION', 'MODIFY_RATE_LIMIT',
        'ATTACH_WAF', 'REMEDIATE_DRIFT'
    )),
    title VARCHAR(255) NOT NULL,
    target VARCHAR(255) NOT NULL,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id),
    account_name VARCHAR(128) NOT NULL,
    webacl_id UUID REFERENCES web_acls(id),
    webacl_name VARCHAR(128) NOT NULL,
    application VARCHAR(128) NOT NULL,
    requested_by VARCHAR(255) NOT NULL,
    requested_by_role VARCHAR(64) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL,
    risk_level VARCHAR(16) NOT NULL CHECK (risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    ttl_hours INTEGER,
    expires_at TIMESTAMPTZ,
    allow_list_check VARCHAR(16) NOT NULL CHECK (allow_list_check IN ('PASSED', 'BLOCKED_PROTECTED_ENTITY')),
    simulation_id UUID REFERENCES simulations(id),
    simulation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    impact_scope TEXT NOT NULL,
    required_approver_role VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'VERIFIED', 'ROLLED_BACK', 'EXPIRED'
    )),
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ,
    aws_request_id VARCHAR(128),
    verification_status VARCHAR(16) DEFAULT 'PENDING' CHECK (verification_status IN ('VERIFIED', 'PENDING', 'FAILED')),
    previous_state TEXT NOT NULL,
    proposed_state TEXT NOT NULL
);

CREATE TABLE changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_id UUID NOT NULL REFERENCES approvals(id) ON DELETE RESTRICT,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id),
    webacl_id UUID REFERENCES web_acls(id),
    previous_state_json JSONB NOT NULL,
    new_state_json JSONB NOT NULL,
    aws_lock_token_before VARCHAR(128),
    aws_lock_token_after VARCHAR(128),
    aws_request_id VARCHAR(128) NOT NULL,
    execution_status VARCHAR(24) NOT NULL CHECK (execution_status IN ('EXECUTED', 'FAILED', 'ROLLED_BACK')),
    verification_status VARCHAR(24) NOT NULL CHECK (verification_status IN ('VERIFIED', 'FAILED')),
    ttl_status VARCHAR(24) CHECK (ttl_status IN ('ACTIVE', 'EXPIRING', 'EXPIRED', 'REMOVED')),
    expires_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rolled_back_at TIMESTAMPTZ,
    rolled_back_by VARCHAR(255)
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_code VARCHAR(32) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_email VARCHAR(255) NOT NULL,
    user_role VARCHAR(64) NOT NULL,
    account_id VARCHAR(12) NOT NULL,
    region VARCHAR(32) NOT NULL,
    action VARCHAR(128) NOT NULL,
    target_resource VARCHAR(512) NOT NULL,
    previous_state TEXT NOT NULL,
    new_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    approver VARCHAR(255) NOT NULL,
    approval_id UUID REFERENCES approvals(id),
    execution_status VARCHAR(32) NOT NULL,
    aws_request_id VARCHAR(128) NOT NULL,
    verification_status VARCHAR(32) NOT NULL,
    rollback_available BOOLEAN NOT NULL DEFAULT FALSE
);

-- Rule #6: audit_events is append-only. Also blocks TRUNCATE (statement-level trigger).
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events table is strictly append-only and immutable.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_immutable_audit
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER trg_immutable_audit_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_mutation();

CREATE TABLE drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    drift_code VARCHAR(32) NOT NULL UNIQUE,
    account_id VARCHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    account_name VARCHAR(128) NOT NULL,
    webacl_id UUID NOT NULL REFERENCES web_acls(id) ON DELETE CASCADE,
    webacl_name VARCHAR(128) NOT NULL,
    drift_type VARCHAR(32) NOT NULL CHECK (drift_type IN (
        'RULE_ACTION_CHANGED', 'RULE_REMOVED', 'MANAGED_VERSION_OUTDATED',
        'LOGGING_DISABLED', 'ASSOCIATION_REMOVED', 'IPSET_MODIFIED'
    )),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    expected_state TEXT NOT NULL,
    actual_state TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(24) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'REMEDIATING', 'RESOLVED'))
);

-- Health of pipeline components and per-account collectors (account_id NULL = global component).
CREATE TABLE platform_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component VARCHAR(32) NOT NULL CHECK (component IN ('aws_api', 'queue', 'workers', 'threat_intel', 'collector')),
    account_id VARCHAR(12) REFERENCES accounts(account_id) ON DELETE CASCADE,
    status VARCHAR(24) NOT NULL CHECK (status IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE')),
    detail TEXT NOT NULL DEFAULT '',
    error TEXT,
    affected_modules TEXT[] NOT NULL DEFAULT '{}',
    last_success TIMESTAMPTZ,
    last_check TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_platform_health_component_account UNIQUE NULLS NOT DISTINCT (component, account_id)
);

-- RBAC seed (PRD section 3). Qualified grants ("APPROVE:TEMP_BLOCK", "INVESTIGATE:SCOPED", ...)
-- satisfy the base permission at the endpoint gate; the qualifier is enforced by the approval
-- policy engine (Milestone 4) and by account scoping (users.scoped_account_ids).
INSERT INTO roles (name, permissions, description) VALUES
 ('Security Admin', ARRAY['VIEW','INVESTIGATE','SIMULATE','CREATE_CHANGE','APPROVE','EXECUTE','ROLLBACK','MANAGE_TI','MANAGE_USERS'], 'Lead Security Architect / SecOps Lead'),
 ('Security Analyst', ARRAY['VIEW','INVESTIGATE','SIMULATE','CREATE_CHANGE','APPROVE:TEMP_BLOCK','MANAGE_TI'], 'Tier-2/3 Incident Responder'),
 ('SOC Analyst', ARRAY['VIEW','INVESTIGATE','SIMULATE','CREATE_CHANGE'], 'Tier-1 Triage Analyst'),
 ('AWS Administrator', ARRAY['VIEW','INVESTIGATE','SIMULATE','CREATE_CHANGE','APPROVE:INFRA','EXECUTE','ROLLBACK'], 'Cloud Platform Engineer'),
 ('Application Owner', ARRAY['VIEW','INVESTIGATE:SCOPED','SIMULATE','CREATE_CHANGE:SCOPED','APPROVE:APP_RULES'], 'Service / Product Engineering Lead'),
 ('Auditor', ARRAY['VIEW','INVESTIGATE'], 'Internal / External Compliance Auditor'),
 ('Executive', ARRAY['VIEW'], 'CISO / VP of Engineering'),
 ('Read Only', ARRAY['VIEW'], 'General Engineering / Observer');
"""

TABLES = [
    "platform_health", "drift_events", "audit_events", "changes", "approvals", "simulations",
    "allow_list_entries", "threat_intelligence", "detections", "campaigns", "entity_relationships",
    "entities", "waf_events", "managed_rule_versions", "rules", "endpoints", "web_acls", "applications",
    "users", "roles", "accounts",
]


def _statements(sql: str) -> list[str]:
    """Split DDL into single statements (asyncpg rejects multi-statement strings); $$ bodies stay whole."""
    statements, buf, in_dollar = [], [], False
    for line in sql.splitlines():
        if not in_dollar and (not line.strip() or line.lstrip().startswith("--")):
            continue
        buf.append(line)
        if line.count("$$") % 2:
            in_dollar = not in_dollar
        if not in_dollar and line.rstrip().endswith(";"):
            statements.append("\n".join(buf))
            buf = []
    if buf:
        raise ValueError("unterminated DDL statement")
    return statements


def upgrade() -> None:
    for statement in _statements(DDL):
        op.execute(statement)


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_mutation()")
