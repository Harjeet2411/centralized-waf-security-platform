# SAS Threat Intelligence Platform — Master Specification

**Version:** 1.0
**Date:** 2026-10-11
**Environment:** Production financial-services AWS environment
**Scope:** 39 AWS accounts, regional + global WAF

---

## 1. PRODUCT VISION

Build a **real, production-grade centralized WAF Security + Threat Intelligence + Detection + Investigation + Controlled Response platform** for an organization with 39 AWS accounts.

This is NOT a mockup. NOT a PoC. NOT a static dashboard.

The platform answers:
- What is attacking us?
- What are they attacking?
- How are they attacking?
- Did WAF stop the request?
- If not, why?
- Is the WAF effective?
- What should we do?
- Can we safely do it?
- Who changed it?

Every number must have evidence. Every recommendation must be explainable. Every AWS-changing operation must require approval. Every change must be verified. Every change must be audited.

---

## 2. HARD CONSTRAINTS

**Do NOT use:**
- AWS Firewall Manager
- AWS Shield Advanced
- Centralized WAF Data Lake architecture
- Third-party managed firewall platforms
- Autonomous AI-driven AWS changes
- Direct browser-to-AWS privileged operations
- Fake/mock security data in production
- Hardcoded account data, threat entities, or attack statistics

**AI may be used for:**
- Investigation assistance
- Evidence summarization
- Attack-story generation
- Analyst recommendations
- Natural-language explanation

AI MUST NOT autonomously change AWS infrastructure.

---

## 3. ARCHITECTURE OVERVIEW

```
                    USERS
                      │
                      ▼
              ┌──────────────┐
              │  Web Dashboard│  (Next.js, React)
              │  Security SOC │  Dark theme, 2D investigation-first
              │  Interface    │  3D globe deferred to v2
              └──────┬───────┘
                     │ HTTPS/WSS
                     ▼
              ┌──────────────┐
              │  CloudFront  │  + ALB + WAF (protect the platform)
              │  + ALB + WAF │
              └──────┬───────┘
                     │
                     ▼
              ┌──────────────┐
              │  FastAPI     │  Backend (REST + WebSocket)
              │  Backend      │  Auth, RBAC, business logic
              └──────┬───────┘
                     │
              ┌──────┴──────────────┐
              │                     │
              ▼                     ▼
        ┌──────────┐        ┌──────────────┐
        │ RDS      │        │  ElastiCache │
        │PostgreSQL│        │  Redis       │
        │(source   │        │  (TI cache,  │
        │ of truth)│        │   sessions)  │
        └──────────┘        └──────────────┘
                     │
                     ▼
        ┌──────────────────────────────┐
        │  Lambda (per-account,        │
        │  serverless data pipeline)   │
        │                              │
        │  Triggered by:               │
        │  • EventBridge (every 6h)    │
        │  • Manual refresh (user)     │
        │  • S3 events (WAF logs)      │
        └──────┬───────────────────────┘
               │
       AssumeRole (cross-account)
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
 Account 1  Account 2  ...  Account 39
```

---

## 4. HOSTING & INFRASTRUCTURE

### 4.1 Central Security Account

- VPC with private subnets (multi-AZ)
- RDS PostgreSQL (db.t3.large, Multi-AZ) — source of truth
- ElastiCache Redis (cache.t3.micro) — TI cache, sessions
- Lambda functions (data pipeline, S3 enrichment)
- Step Functions (orchestrate per-account Lambda fan-out)
- EventBridge (6-hour sync schedule)
- S3 (audit exports, temp data, WAF log staging for 6 accounts)
- SQS (optional: manual sync requests)
- Secrets Manager (AWS cross-account role ARNs, TI API keys)
- ALB (internet-facing for platform)
- CloudFront + ACM certificate
- WAF on the platform's own ALB
- IAM Identity Center (SSO + MFA)

### 4.2 VPC Endpoints (AWS APIs stay private)

- com.amazonaws.region.sts
- com.amazonaws.region.wafv2
- com.amazonaws.region.monitoring
- com.amazonaws.region.logs
- com.amazonaws.region.organizations (optional)

### 4.3 Monthly Infrastructure Cost Estimate

| Component | Monthly |
|---|---|
| Lambda + Step Functions | ~$1 |
| RDS db.t3.large Multi-AZ | ~$200 |
| ElastiCache cache.t3.micro | ~$15 |
| ALB | ~$25 |
| NAT Gateway (1 AZ) | ~$32 |
| CloudFront | ~$10 |
| S3 + SQS + Secrets + CloudWatch Logs | ~$20 |
| VPC Endpoints | ~$25 |
| Threat Intel APIs | ~$20 |
| **Total** | **~$350/mo** |

---

## 5. CROSS-ACCOUNT IAM

### 5.1 DiscoveryRole (per account, read-only)

**Trust policy:** Central security account

**Permissions:**
- wafv2:List*, Get*, GetSampledRequests
- elbv2:DescribeLoadBalancers
- apigateway:GET (list/get)
- cloudfront:ListDistributions, GetDistribution
- cloudwatch:GetMetricData, ListMetrics
- ec2:Describe*
- logs:DescribeLogGroups, DescribeLogStreams
- sts:GetCallerIdentity

### 5.2 ResponseRole (per account, tightly scoped)

**Trust policy:** Central security account + MFA condition

**Permissions:**
- wafv2:Update*, Create*, Delete* (except DeleteWebACL)
- wafv2:AssociateWebACL, DisassociateWebACL
- waf:UpdateIPSet (for blocks)
- NO unrestricted AdministratorAccess

### 5.3 Deployment

- CloudFormation StackSet (push to all 39 accounts)
- Central platform stores role ARNs in `accounts` table
- Lambda assumes role per account during sync

---

## 6. DATA MODEL (PostgreSQL)

### Core Tables

| Table | Purpose |
|---|---|
| `accounts` | 39 AWS accounts (id, account_id, name, environment, owner, status, discovery_role_arn, response_role_arn, last_discovered) |
| `users` | Platform users (id, email, role, sso_id, mfa_enabled) |
| `roles` | RBAC definitions (name, permissions[]) |
| `applications` | Named applications per account |
| `endpoints` | ALB, CloudFront, API Gateway resources (type, dns, internet_facing, waf_status, logging_enabled, status) |
| `web_acls` | WebACL config (account_id, name, arn, scope, default_action, security_score, score_confidence, score_evidence) |
| `rules` | Every rule in every WebACL (type, action, priority, statement JSONB, managed_rule_name, managed_rule_version, excluded_rules, scope_down, rate_limit) |
| `managed_rule_versions` | Per WebACL, per rule group (current_version, available_version, version_status) |
| `waf_events` | Sampled requests + log events (timestamp, http_request JSONB, action, rule_groups, labels, ja3, ja4, country, asn, attack_techniques, source) |
| `entities` | IP, ASN, Country, Org, JA3, JA4, User-Agent (type, value, threat_score, confidence, risk_level, metadata JSONB) |
| `entity_relationships` | IP→ASN, IP→JA4, IP→Application, etc. |
| `campaigns` | First-class campaign objects (type, risk_level, confidence, correlation_evidence JSONB, recommended_action, status) |
| `detections` | Behavioral detections (type, severity, status, entity_ids, evidence) |
| `threat_intelligence` | Cached TI per entity (source, score, classification, confidence, expiration) |
| `approvals` | Change requests (action_type, target, reason, impact_analysis, simulation_result, allow_list_check, status, approver) |
| `changes` | Executed changes (approval_id, previous_state, new_state, execution_status, verification_status, rollback_data) |
| `audit_events` | Immutable audit log (audit_id, timestamp, user, role, action, previous_state, new_state, approval_id, aws_request_id, verification_status) |
| `drift_events` | Configuration drift (expected_state, actual_state, drift_type, severity, status) |
| `simulations` | Rule impact simulations (proposed_change, affected_requests, potential_fp, current_vs_proposed) |

---

## 7. DATA PIPELINE

### 7.1 Scheduled Sync (every 6 hours)

```
EventBridge (cron)
  → Step Function (fan-out)
    → Lambda × 39 (one per account, parallel)
      ├── AssumeRole(DiscoveryRole)
      ├── List WebACLs, ALBs, APIGWs, CloudFronts
      ├── Get WAF config, rules, managed versions
      ├── Get CloudWatch metrics
      ├── Get WAF sampled requests
      ├── Normalize + write to RDS
      └── Update platform health status
```

### 7.2 Manual Refresh (user clicks "Refresh")

```
Frontend → FastAPI /api/refresh
  ├── Data < 1h old → return "ready" immediately
  └── Data stale → trigger Step Function in background
                   return "syncing" + show progress
                   WebSocket push when complete
```

### 7.3 WAF Log Ingestion (6 accounts with logging)

```
S3 (WAF logs in account)
  → S3 event notification
    → Lambda (parse WAF logs)
      ├── Enrich with existing entity data
      ├── Classify: LEGITIMATE / SUSPICIOUS / MALICIOUS / UNKNOWN
      └── Write to RDS waf_events table
```

### 7.4 Detection Engines (after data sync)

```
Post-sync trigger
  ├── Drift Engine (compare baseline vs. actual)
  ├── Detection Engine (behavioral, JA3/JA4, campaign)
  ├── Scoring Engine (recalculate security scores)
  └── Threat Intel Lookup (queue new entities for TI check)
```

### 7.5 Threat Intelligence (async, cached)

```
Triggered by: new entity in waf_events
  ├── Check Redis cache (TTL 24h)
  ├── If miss → call AbuseIPDB, GreyNoise, VirusTotal
  ├── Cache result
  ├── Write to PostgreSQL
  └── Update entity threat_score, confidence, risk_level
```

---

## 8. CORE MODULES

### 8.1 Account Discovery
- 39/39 accounts discovered and tracked
- Account health: HEALTHY / DEGRADED / UNAVAILABLE
- Dashboard: Total, Healthy, Warning, Critical, Unknown

### 8.2 Application & Endpoint Discovery
- Discovers ALB, CloudFront, API Gateway per account/region
- For each: dns_name, internet_facing, web_acl, waf_enabled, logging_enabled
- Status: PROTECTED / PARTIALLY_PROTECTED / UNPROTECTED / UNKNOWN
- Internet-facing without WAF = CRITICAL

### 8.3 WAF Coverage Engine
- Every endpoint checked for WAF attachment
- Coverage dashboard (per application, per account)
- Request-to-attach flow (approval required, never auto-attach)

### 8.4 WAF Security Score (0–100)
- Transparent, evidence-backed
- Dimensions: coverage, blocking effectiveness, malicious allowed, COUNT exposure, drift, managed rule health, logging visibility
- Configurable weights
- Confidence: FULL / PARTIAL / SAMPLED / NONE
- Data sources always shown

### 8.5 WAF Metrics & Sampled Requests
- CloudWatch metrics: ProvisionedCapacity, BlockedRequests, AllowedRequests, CountedRequests
- Sampled requests: IP, URI, Host, method, rule, action, labels, JA3, JA4, UA, timestamp
- Classification: LEGITIMATE / SUSPICIOUS / MALICIOUS / UNKNOWN

### 8.6 WAF Logging Visibility
- Detects which accounts/WebACLs have logging enabled
- 6/39 accounts expected to have logging (do not assume all have it)
- Logging disabled = reduced visibility score (not "insecure WAF")
- Full logs enrich sampled data where both exist

### 8.7 Managed Rule Version Tracking
- Tracks every AWS Managed Rule Group version
- Status: CURRENT / OUTDATED / DEPRECATED / UNKNOWN
- Per account, per WebACL
- Drift detection across accounts

### 8.8 Configuration Drift Engine
- Continuous comparison: Expected Baseline vs. Actual AWS State
- Detects: missing rules, action changes, BLOCK→COUNT, version changes, IP Set changes, logging changes, association changes
- Severity: CRITICAL / HIGH / MEDIUM / LOW
- Every drift event audited

### 8.9 Entity Intelligence Model
- Types: IP, ASN, Country, Organization, JA3, JA4, User-Agent, URI pattern, Application, Account, WebACL, Rule, Attack Technique, Campaign
- Every entity: Threat Score, Confidence, Business Impact, Final Risk
- Relationships stored: IP→ASN→Org→JA4→Application→Campaign

### 8.10 Entity Investigation
- Full profile: IP, ASN, Country, Org, JA3, JA4, UA, targets, techniques, campaigns, threat intel, recommended action
- Interactive relationship graph (2D, D3.js)
- Attack timeline
- Attack Story (evidence-based narrative)

### 8.11 JA3/JA4 Correlation
- Core detection mechanism
- Same JA4 across many IPs/ASNs/countries/applications = correlated attack
- JA4 campaign detection
- JA4 + malicious ALLOW = CRITICAL alert

### 8.12 Behavioral Detection
- Scanner (high URI diversity + 404 ratio)
- Credential Attack (login endpoints + POST + same JA4)
- Distributed Attack (many IPs + same JA4 + same URI)
- Slow Distributed Attack (low rate/IP + many IPs + same JA4)
- Bot/Automation (repetitive patterns, abnormal UA)
- SQLi Campaign
- Malicious Allowed Traffic (HIGH_RISK + ALLOW = CRITICAL)

### 8.13 Campaign Engine
- First-class Campaign object
- Correlates: IPs, ASNs, countries, JA3, JA4, URIs, methods, rules, techniques, timing, apps, accounts, TI
- Campaign page: overview, entities, infrastructure, timeline, techniques, impact, recommended response

### 8.14 Threat Intelligence
- Integrations: AbuseIPDB, GreyNoise, VirusTotal, GuardDuty (if approved), internal history
- Cached (Redis TTL 24h + PostgreSQL history)
- Graceful degradation when provider unavailable
- Every result: source, score, classification, confidence, timestamps, expiration

### 8.15 Threat Score
- Separates: Threat Score, Confidence, Business Impact, Final Risk
- Evidence-backed, not a black box
- Considers: TI, WAF behavior, JA3/JA4, campaign membership, targeting breadth, malicious ALLOW

### 8.16 Query Builder
- Fields: IP, ASN, country, organization, URI, host, method, rule, action, JA3, JA4, UA, account, application, WebACL, technique, campaign, threat score, risk, timestamp
- Operators: =, !=, >, <, >=, <=, contains, starts_with, ends_with, in, AND, OR, NOT
- Save, export investigations

### 8.17 Attack Timeline
- Per entity, campaign, incident
- Events: First Seen, Detection, WAF Rule Hit, Threat Intel, Campaign Created, Approval Request, Approval, AWS Change, Verification, Resolution, Rollback

### 8.18 Rule Impact Simulator
- Propose: new rule, modification, scope-down, rate limit, exception, managed rule version change
- Evaluate against historical data
- Shows: Current vs. Proposed (would block, would allow, potential FP, affected apps/accounts)
- Never executes

### 8.19 False Positive Analyzer
- Shows exact rule, sub-rule, WebACL, evidence
- Proposed remediation: exclusion, COUNT, scope-down, exception, allow-list
- Simulates before applying

### 8.20 Change Impact Analysis
- Before every change: affected accounts, WebACLs, applications, endpoints
- Legitimate traffic impact, security benefit, risk level
- Allow-list validation result

### 8.21 Response Engine (Controlled)
Supported actions:
- Temporary IP block (TTL)
- Permanent IP block
- Remove block
- Add/remove exception
- Modify WAF rule
- Modify rate limit
- Modify scope-down
- Modify IP Set
- Attach/detach WAF

No direct execution from UI. All actions follow lifecycle.

### 8.22 Approval Engine
- Every AWS-changing action requires approval
- Configurable policies:
  - 1-hour temporary block → Analyst approval
  - Permanent block → Security Admin
  - WAF rule modification → Security Admin + Application Owner
  - Critical WebACL change → Two-person approval
- Notifications: SNS + Email

### 8.23 Allow-List Guardrails
- Protected entities: internal networks, partners, payment gateways, monitoring, security scanners, business-critical IPs
- Server-side enforcement — cannot be bypassed
- Block denied with reason: "Protected Entity"

### 8.24 Temporary Blocks & TTL
- Auto-expiry, automatic removal
- Statuses: ACTIVE / EXPIRING / EXPIRED / REMOVED
- Every TTL operation audited

### 8.25 Complete Audit Engine
- Immutable audit records (append-only)
- Every security-sensitive operation
- Record: audit_id, timestamp, user, role, account, region, action, previous_state, new_state, reason, risk, approver, execution_status, aws_request_id, verification_status, rollback_info

### 8.26 Rollback Engine
- Previous state stored before every modification
- Rollback for: IP blocks, rule actions, rate limits, scope-down, exceptions
- Every rollback audited

### 8.27 RBAC (8 Roles)
- Security Admin, Security Analyst, SOC Analyst, AWS Administrator, Application Owner, Auditor, Executive, Read Only
- Permissions: VIEW, INVESTIGATE, SIMULATE, CREATE_CHANGE, APPROVE, EXECUTE, ROLLBACK, MANAGE_TI, MANAGE_USERS
- Investigation ≠ Modification permissions

### 8.28 Application Investigation
- Per application: endpoints, WAF rules, attack traffic, malicious entities, campaigns, TI, security score, drift, logging

### 8.29 Rule Investigation
- Per rule: match count, blocked/counted/allowed, affected entities, affected applications, false positives, managed version, exclusions, scope-down, recent changes

### 8.30 Cost Analysis
- WAF cost by account, WebACL, feature
- Platform cost visibility
- Recommendations go through approval

### 8.31 Executive Reporting
- Executive Security Report, Weekly Threat Report, WAF Posture, Drift Report, Incident Report, Campaign Report
- Evidence and timestamps

### 8.32 Platform Health
- Account connectivity, STS failures, WAF API failures, throttling
- Queue health, Lambda health, RDS health, Redis health
- TI API health, data freshness, failed jobs

### 8.33 Notifications
- SNS + Email
- Alerts: critical campaigns, high-risk entities, malicious allowed, WAF missing, drift, attack spikes, JA4 campaigns, approval required, AWS execution failure

---

## 9. UI NAVIGATION STRUCTURE

```
COMMAND CENTER
├── Global Overview
├── Security Score
├── Active Incidents
└── Platform Health

THREAT INTELLIGENCE
├── Entities (IP / ASN / JA3 / JA4 / Org / UA)
├── Campaigns
├── Threat Intel Lookup
└── IOC Search

WAF SECURITY
├── All WebACLs
├── WAF Coverage
├── WAF Security Score
├── Managed Rule Versions
├── Rule Effectiveness
├── Configuration Drift
├── WAF Health
└── Logging Visibility

INVESTIGATION
├── Query Builder
├── Entity Investigation
├── Application Investigation
├── Rule Investigation
├── Campaign Investigation
├── Attack Timeline
└── Attack Story

DETECTION
├── Behavioral Detection
├── Anomalies
├── Attack Techniques
├── Campaign Detection
└── Malicious Allowed Traffic

SIMULATION
├── Rule Simulator
├── False Positive Analysis
└── Change Impact

RESPONSE
├── Active Blocks
├── Temporary Blocks
├── Allow Lists
├── Exceptions
├── Pending Approvals
└── Rollback

GOVERNANCE
├── Accounts
├── Applications
├── Configuration Drift
├── Approval Policies
├── Audit Trail
└── RBAC

COST
├── WAF Cost
├── Account Cost
├── WebACL Cost
└── Platform Cost

REPORTS
├── Executive Report
├── Weekly Threat Report
├── WAF Posture
├── Drift Report
└── Incident Report
```

---

## 10. THE APPROVAL LIFECYCLE (enforced in backend)

```
DETECT
  → UNDERSTAND
  → CORRELATE
  → SCORE
  → SIMULATE
  → CHECK GUARDRAILS
  → REQUEST APPROVAL
  → APPROVE
  → EXECUTE
  → VERIFY
  → AUDIT
  → ROLLBACK IF REQUIRED
```

Every AWS-changing action follows this sequence. No shortcuts.

---

## 11. TECHNOLOGY STACK

| Layer | Technology | Why |
|---|---|---|
| **Frontend** | Next.js + React + TypeScript | Production framework, SSR, great DX |
| **Backend** | FastAPI (Python) | Async perfect for cross-account fan-out, boto3 native |
| **Database** | PostgreSQL (RDS) | Source of truth, relational data, indexes |
| **Cache** | Redis (ElastiCache) | TI cache, sessions, rate limiting |
| **Compute** | Lambda (per-account) | Serverless, auto-scales, zero ops, cheap |
| **Orchestration** | Step Functions | Reliable fan-out, retries, error handling |
| **Scheduling** | EventBridge | Cron-based sync |
| **Auth** | AWS IAM Identity Center | Free SSO + MFA |
| **Secrets** | AWS Secrets Manager | AWS creds, TI API keys |
| **Graph Viz** | D3.js (2D) | Investigation graphs, defer 3D to v2 |
| **State Management** | React Query + Zustand | Server state + UI state |
| **API Docs** | OpenAPI (auto-generated) | FastAPI built-in |

---

## 12. BUILD PHASES

### Phase 1: Foundation (Weeks 1–4)
Goal: Platform running with real AWS data from all 39 accounts
- Provision infrastructure
- IAM Identity Center + RBAC
- Cross-account IAM roles (CloudFormation StackSet)
- Account discovery Lambda
- WebACL + rule sync Lambda
- WAF metrics collector Lambda
- Basic React dashboard (login, accounts, WebACLs, coverage)
- Platform health screen
- End-to-end verification with all 39 accounts

### Phase 2: WAF Governance (Weeks 5–8)
Goal: Security scores, drift detection, managed rule versions
- Security score engine (evidence-backed)
- Configuration drift engine
- Managed rule version tracking
- WAF coverage governance
- Request-to-attach flow

### Phase 3: Threat Intelligence & Entity Intelligence (Weeks 9–12)
Goal: Entity model, threat intel, JA3/JA4 correlation
- AbuseIPDB + GreyNoise + VirusTotal integration
- Entity model (IP, ASN, JA3, JA4, Org, UA)
- Entity investigation page
- Relationship graph (2D, D3.js)
- JA3/JA4 correlation engine
- JA4 campaign detection
- Behavioral detection (scanner, credential attack, distributed)
- Campaign engine core

### Phase 4: Controlled Response (Weeks 13–18)
Goal: Full approval lifecycle
- Approval engine (backend + UI)
- Approval policy engine
- Allow-list system + guardrails
- Temporary blocks with TTL
- Response engine (backend)
- AWS execution + verification
- Rollback engine
- Complete audit engine
- End-to-end lifecycle test

### Phase 5: Simulation & Advanced (Weeks 19–24)
Goal: Rule simulation, false positive analysis, advanced features
- Rule impact simulator
- False positive analyzer
- Campaign investigation + visualization
- Attack Timeline + Attack Story
- Query Builder (full)
- Executive dashboard + reporting
- Cost analysis
- Advanced behavioral detection
- Malicious Allowed Traffic detection
- Production security review

---

## 13. PRODUCTION ACCEPTANCE CRITERIA

The platform is NOT complete until:

| Criterion | Requirement |
|---|---|
| Account visibility | 39/39 discovered |
| Cross-account access | All 39 accounts reachable |
| WAF inventory | All WebACLs, rules, managed versions discovered |
| Coverage | All ALB, API Gateway, CloudFront checked |
| Security score | Every WebACL has score + evidence + confidence |
| Logging visibility | Known which accounts have logging (6/39) |
| Detection | Entity, JA3/JA4, behavioral, campaign detection |
| Investigation | Entity, application, rule, campaign investigation |
| Timeline | Per entity, campaign, incident |
| Simulation | Rule simulation, false positive analysis |
| Response | Temporary blocks, TTL, allow-list, approval |
| Governance | Configuration drift, managed rule drift, RBAC, audit |
| Rollback | Supported for all change types |
| Reliability | AWS API failures, throttling, partial failures handled |
| No mock data | All data from real AWS APIs |
| No autonomous changes | All AWS changes via approval lifecycle |

---

## 14. WHAT THIS PLATFORM IS NOT

| Not | Why |
|---|---|
| AWS Firewall Manager | Cost — not needed with this platform |
| AWS Shield Advanced | Cost — $3K/account/mo |
| Centralized WAF Data Lake | Cost — platform works with sampled requests, metrics, config APIs |
| Autonomous AI changes | Security principle — human approval required |
| Third-party SIEM/SOAR | Cost — $5K–50K+/mo |
| Static dashboard | This is an operational platform with controlled response |
| Mock data platform | Production evidence-only |
| 3D-first interface | 2D investigation-first; 3D deferred |

---

## 15. IMPLEMENTATION RULES

1. **Evidence-first**: Every number, score, recommendation traces to data
2. **No shortcuts on approval**: Every AWS change follows the full lifecycle
3. **No bypassing allow-list**: Server-side enforcement, no frontend override
4. **Never claim sampled = complete**: Always show data source and confidence
5. **No secrets in frontend**: AWS credentials never reach the browser
6. **Immutable audit**: Append-only, no modifications by normal users
7. **Verify before claiming success**: Re-read AWS state after every change
8. **Graceful degradation**: TI provider down, account unreachable, API throttled
9. **Cost-aware**: Optimize Lambda calls, cache TI, don't build unnecessary infrastructure
10. **Start small, prove lifecycle, then scale**: 5 pilot accounts first, then 39

---

*This document is the single source of truth for the SAS Threat Intelligence Platform. All implementation decisions must align with this specification.*
