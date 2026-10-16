# Backend Database, Cache & API Schema Specification
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17
- **Database Engine:** Amazon RDS PostgreSQL 16 (`db.t3.large`, Multi-AZ)
- **Cache Engine:** Amazon ElastiCache Redis 7 (`cache.t3.micro`)

---

## 1. PostgreSQL 16 Complete DDL Schema (19 Core Tables)

```sql
-- Enable required extensions for UUID generation, CIDR/INET indexing, and JSONB search
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- ============================================================================
-- 1. ACCOUNTS (39 AWS Accounts)
-- ============================================================================
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

-- ============================================================================
-- 2. ROLES & 3. USERS (RBAC & IAM Identity Center Mapping)
-- ============================================================================
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

-- ============================================================================
-- 4. APPLICATIONS
-- ============================================================================
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

-- ============================================================================
-- 5. WEB_ACLS
-- ============================================================================
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

-- ============================================================================
-- 6. ENDPOINTS (ALB, CloudFront, API Gateway)
-- ============================================================================
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

-- ============================================================================
-- 7. RULES & 8. MANAGED_RULE_VERSIONS
-- ============================================================================
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

-- ============================================================================
-- 9. WAF_EVENTS (Sampled Requests + Full Log Events)
-- ============================================================================
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

-- ============================================================================
-- 10. ENTITIES & 11. ENTITY_RELATIONSHIPS
-- ============================================================================
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

-- ============================================================================
-- 12. CAMPAIGNS & 13. DETECTIONS
-- ============================================================================
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

-- ============================================================================
-- 14. THREAT_INTELLIGENCE (Cached Feed Results)
-- ============================================================================
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

-- ============================================================================
-- 15. ALLOW_LIST_ENTRIES (Server-Side Guardrails)
-- ============================================================================
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

-- ============================================================================
-- 16. SIMULATIONS
-- ============================================================================
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

-- ============================================================================
-- 17. APPROVALS & 18. CHANGES (Controlled Response Engine)
-- ============================================================================
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

-- ============================================================================
-- 19. AUDIT_EVENTS (Immutable Append-Only Audit Log) & 20. DRIFT_EVENTS
-- ============================================================================
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

-- Enforce immutability on audit_events
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events table is strictly append-only and immutable.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_immutable_audit
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

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
```

---

## 2. ElastiCache Redis Keyspace Specification

| Key Pattern | Value Type | TTL | Purpose |
| :--- | :--- | :--- | :--- |
| `ti:ip:{ip_address}` | JSON Hash | $86,400\text{ s}$ ($24\text{h}$) | Cached AbuseIPDB, GreyNoise, and VirusTotal lookup results |
| `sync:global:status` | JSON String | $21,600\text{ s}$ ($6\text{h}$) | Current pipeline execution state, last sync timestamp, account progress |
| `sync:global:lock` | String (`execution_arn`) | $300\text{ s}$ ($5\text{m}$) | Distributed lock preventing duplicate manual Step Functions triggers |
| `session:user:{session_id}` | JSON Hash | $28,800\text{ s}$ ($8\text{h}$) | Authenticated IAM Identity Center user profile, RBAC role, MFA status |
| `pubsub:platform_events` | Pub/Sub Channel | N/A | Real-time broadcast of sync completion, critical detections, and approvals |

---

## 3. FastAPI REST & WebSocket API Contracts

| Method | Endpoint | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/bootstrap` | `VIEW` | Returns hydrated platform state (`accounts`, `posture`, `health`, summary counts) |
| `POST` | `/api/v1/refresh` | `VIEW` | Checks $< 1\text{h}$ freshness; triggers Step Functions sync if stale |
| `GET` | `/api/v1/entities` | `VIEW` | Paginated, filterable list of entities (`IP`, `ASN`, `JA4`, `riskLevel`) |
| `GET` | `/api/v1/entities/{id}` | `INVESTIGATE` | Full entity profile, D3 relationship graph nodes/edges, TI feeds, timeline |
| `POST` | `/api/v1/investigation/query` | `INVESTIGATE` | Executes structured Query Builder AST against `waf_events` and `entities` |
| `GET` | `/api/v1/campaigns` | `VIEW` | Lists active/mitigated JA4 and behavioral attack campaigns |
| `GET` | `/api/v1/webacls` | `VIEW` | Lists all WebACLs, rules, managed rule versions, and security scores |
| `GET` | `/api/v1/endpoints` | `VIEW` | Lists all discovered ALBs, CloudFronts, and API Gateways + WAF coverage |
| `POST` | `/api/v1/simulations` | `SIMULATE` | Runs historical rule/block simulation against `waf_events` (non-mutating) |
| `POST` | `/api/v1/approvals` | `CREATE_CHANGE` | Validates allow-list guardrails and creates a pending approval request |
| `POST` | `/api/v1/approvals/{id}/decide` | `APPROVE` | Approves or rejects a change request; triggers `ResponseRole` execution + verification |
| `POST` | `/api/v1/changes/{id}/rollback` | `ROLLBACK` | Restores `previous_state_json` in AWS WAFv2, verifies, and logs audit event |
| `GET` | `/api/v1/governance/audit` | `VIEW` | Queries immutable `audit_events` with CSV/JSON compliance export |
| `WS` | `/ws/events` | `VIEW` | Pushes real-time sync progress, new critical detections, and approval updates |