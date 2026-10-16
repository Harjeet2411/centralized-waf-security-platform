# Product Requirements Document (PRD)
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17
- **Target Environment:** Production Financial-Services AWS Organization (39 AWS Accounts, Regional + CloudFront Global WAFv2)
- **Monthly Infrastructure Budget Ceiling:** $\$350\text{/month}$

---

## 1. Executive Summary & Product Vision

The **SAS Threat Intelligence Platform** is a centralized, production-grade Web Application Firewall (WAF) Security, Threat Intelligence, Behavioral Detection, Investigation, and Controlled Response platform purpose-built for a financial-services organization operating across **39 AWS accounts**.

Security Operations Center (SOC) analysts, Security Engineers, and Application Owners currently face fragmented visibility across 39 isolated AWS accounts, where only **6 accounts** have full WAF logging enabled and **33 accounts** operate solely with AWS WAFv2 configuration APIs, CloudWatch metrics, and `GetSampledRequests`. Commercial alternatives (AWS Firewall Manager, AWS Shield Advanced, or centralized SIEM/WAF data lakes) are cost-prohibitive at scale.

This platform solves multi-account WAF visibility, correlation, and governance within a strict **$\$350\text{/month}$** infrastructure footprint while enforcing human-in-the-loop approval guardrails for every AWS-mutating action.

### 1.1 The 9 Core Operational Questions
Every screen, data pipeline, and workflow in the platform is engineered to answer nine foundational questions with verifiable evidence:
1. **What is attacking us?** (IPs, ASNs, Organizations, Countries, JA3/JA4 TLS fingerprints, User-Agents)
2. **What are they attacking?** (Accounts, Applications, ALBs, CloudFront distributions, API Gateways, specific URIs)
3. **How are they attacking?** (SQLi, XSS, Credential Stuffing, Scanners, Slow Distributed Botnets, Behavioral Anomalies)
4. **Did WAF stop the request?** (`BLOCK`, `ALLOW`, `COUNT`, `CAPTCHA`, `CHALLENGE`)
5. **If not, why?** (Unprotected endpoint, rule in `COUNT` mode, scope-down exclusion, configuration drift, missing managed rule group)
6. **Is the WAF effective?** (Evidence-backed $0\text{--}100$ Security Score with explicit data confidence)
7. **What should we do?** (Explainable analyst recommendations backed by historical traffic simulation)
8. **Can we safely do it?** (Pre-execution Rule Impact Simulation, False Positive Analysis, and Server-Side Allow-List Guardrails)
9. **Who changed it?** (Immutable, append-only audit trail with AWS Request IDs, post-change verification, and 1-click rollback)

---

## 2. Hard Constraints & Anti-Goals

### 2.1 Strict Prohibitions
| Prohibited Component / Pattern | Rationale |
| :--- | :--- |
| **AWS Firewall Manager** | Prohibitive per-policy/per-account cost across 39 accounts. |
| **AWS Shield Advanced** | $\$3,000\text{/month}$ base fee plus data transfer fees; outside budget. |
| **Centralized WAF Data Lake** | Ingesting full WAF logs for 39 accounts into OpenSearch/Splunk/Athena costs $\$5,000\text{--}\$50,000+\text{/month}$. |
| **Autonomous AI Infrastructure Changes** | High risk of self-inflicted production outage; all changes require human approval. |
| **Direct Browser-to-AWS Privileged Calls** | Violates zero-trust architecture; no AWS credentials or IAM roles are ever exposed to the frontend. |
| **Mock / Hardcoded Production Data** | Every metric, score, and entity in production must originate from live AWS APIs, S3 logs, or Threat Intelligence providers. |
| **3D-First Visualizations** | 3D globes obscure actionable telemetry; the UI is strictly a high-density 2D investigation-first interface. |

### 2.2 Permitted AI Usage
AI/LLM capabilities are strictly restricted to **read-only analytical assistance**:
- Summarizing multi-signal investigation evidence.
- Generating human-readable **Attack Stories** from correlated `waf_events` and `campaigns`.
- Recommending candidate WAF rule adjustments or IP blocks for analyst review and simulation.

---

## 3. User Personas & Role-Based Access Control (RBAC)

The platform enforces 8 distinct roles authenticated via **AWS IAM Identity Center (SSO + MFA)**. Investigation permissions are strictly separated from modification and approval permissions.

| Role | Primary Persona | `VIEW` | `INVESTIGATE` | `SIMULATE` | `CREATE_CHANGE` | `APPROVE` | `EXECUTE` | `ROLLBACK` | `MANAGE_TI` | `MANAGE_USERS` |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Security Admin** | Lead Security Architect / SecOps Lead | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Security Analyst** | Tier-2/3 Incident Responder | Yes | Yes | Yes | Yes | Temp Only | No | No | Yes | No |
| **SOC Analyst** | Tier-1 Triage Analyst | Yes | Yes | Yes | Yes | No | No | No | No | No |
| **AWS Administrator** | Cloud Platform Engineer | Yes | Yes | Yes | Yes | Infra Only | Yes | Yes | No | No |
| **Application Owner** | Service / Product Engineering Lead | Yes | Scoped | Yes | Scoped | App Rules | No | No | No | No |
| **Auditor** | Internal / External Compliance Auditor | Yes | Yes | No | No | No | No | No | No | No |
| **Executive** | CISO / VP of Engineering | Yes | No | No | No | No | No | No | No | No |
| **Read Only** | General Engineering / Observer | Yes | No | No | No | No | No | No | No | No |

---

## 4. Mathematical Scoring & Confidence Models

### 4.1 WAF Security Score ($S_{\text{WAF}}$)
Every WebACL and Account is assigned a transparent, evidence-backed score $S_{\text{WAF}} \in [0, 100]$ calculated across 7 weighted dimensions:

$$S_{\text{WAF}} = \sum_{i=1}^{7} w_i \cdot d_i \quad \text{where} \quad \sum_{i=1}^{7} w_i = 1.0$$

- $d_1$ (**Endpoint Coverage**, $w_1 = 0.25$): Ratio of internet-facing ALBs, CloudFront distributions, and API Gateways attached to a WebACL.
- $d_2$ (**Blocking Effectiveness**, $w_2 = 0.20$): Proportion of classified `MALICIOUS` and `SUSPICIOUS` requests that resulted in `BLOCK` vs. `ALLOW` or `COUNT`.
- $d_3$ (**Malicious Allowed Penalty**, $w_3 = 0.20$): Inverse penalty score based on volume and severity of high-risk traffic permitted (`action = 'ALLOW'`).
- $d_4$ (**COUNT Mode Exposure**, $w_4 = 0.10$): Penalty for critical managed rules or custom rules left in `COUNT` mode beyond their tuning window.
- $d_5$ (**Configuration Drift Health**, $w_5 = 0.10$): Deduction for unresolved `CRITICAL` or `HIGH` drift events against the golden baseline.
- $d_6$ (**Managed Rule Version Currency**, $w_6 = 0.10$): Ratio of AWS Managed Rule Groups running `CURRENT` vs. `OUTDATED` or `DEPRECATED` versions.
- $d_7$ (**Logging Visibility**, $w_7 = 0.05$): Presence of comprehensive S3/CloudWatch logging. *Note: Disabled logging reduces visibility confidence and $d_7$, but never falsely marks a well-configured WebACL as "critical".*

**Data Confidence Level ($C_{\text{data}}$):**
Every score is accompanied by an explicit confidence badge:
- `FULL`: Full WAF logs enabled + CloudWatch metrics + Config APIs (6 accounts).
- `PARTIAL`: Sampled requests + partial flow/ALB logs + CloudWatch metrics.
- `SAMPLED`: `wafv2:GetSampledRequests` + CloudWatch metrics + Config APIs (33 accounts).
- `NONE`: Account unreachable or STS/API failure.

### 4.2 Entity Threat & Risk Score ($R_{\text{entity}}$)
Every tracked entity (IP, ASN, JA3, JA4, User-Agent) maintains four distinct metrics to prevent black-box scoring:
1. **Threat Score ($T \in [0, 100]$)**:

$$T = \min\left(100, \; 0.35 \cdot T_{\text{TI}} + 0.25 \cdot T_{\text{WAF}} + 0.20 \cdot T_{\text{JA4}} + 0.20 \cdot T_{\text{Campaign}}\right)$$

   where $T_{\text{TI}}$ is the normalized consensus score from AbuseIPDB, GreyNoise, and VirusTotal; $T_{\text{WAF}}$ measures block ratio, attack technique severity, and URI probing diversity; $T_{\text{JA4}}$ reflects JA3/JA4 fingerprint malice correlation; and $T_{\text{Campaign}}$ reflects active multi-IP campaign membership.
2. **Confidence ($C \in [0, 100]$)**: Weighted by sample size, number of corroborating TI feeds, and visibility level (`FULL` vs. `SAMPLED`).
3. **Business Impact ($B \in [0, 100]$)**: Criticality of targeted applications and whether requests were permitted (`ALLOW` on a production payment or authentication endpoint yields $B \ge 90$).
4. **Final Risk ($R_{\text{entity}}$)**:

$$R_{\text{entity}} = \text{round}\left(0.60 \cdot T + 0.40 \cdot B\right)$$

   Mapped to `CRITICAL` ($R_{\text{entity}} \ge 85$ or Malicious Allowed $> 0$), `HIGH` ($70 \le R_{\text{entity}} < 85$), `MEDIUM` ($40 \le R_{\text{entity}} < 70$), and `LOW` ($R_{\text{entity}} < 40$).

---

## 5. Functional Requirements by Module

### 5.1 Multi-Account & Endpoint Discovery (FR-01 to FR-03)
- **FR-01 (Account Inventory)**: Track all 39 AWS accounts with health status (`HEALTHY`, `DEGRADED`, `UNAVAILABLE`), environment classification, owner, and last sync timestamp.
- **FR-02 (Endpoint Discovery)**: Automatically discover all Application Load Balancers (`elbv2`), CloudFront distributions (`cloudfront`), and API Gateways (`apigateway`) across all active regions.
- **FR-03 (Unprotected Exposure Alerting)**: Flag any internet-facing endpoint without an attached WebACL as `CRITICAL` (`waf_status = 'UNPROTECTED'`) and provide a guided "Request to Attach WAF" approval workflow.

### 5.2 WAF Governance, Drift & Versioning (FR-04 to FR-08)
- **FR-04 (WebACL & Rule Inventory)**: Parse and store full rule trees, priority orders, JSON statements, rate limits, scope-down statements, and rule group exclusions for every WebACL.
- **FR-05 (Managed Rule Version Tracking)**: Compare active AWS Managed Rule Group versions against the latest available AWS versions (`CURRENT`, `OUTDATED`, `DEPRECATED`, `UNKNOWN`).
- **FR-06 (Configuration Drift Engine)**: Continuously compare live AWS WebACL configurations against approved baseline snapshots. Detect rule deletions, `BLOCK` $\rightarrow$ `COUNT` downgrades, IP Set tampering, logging removal, and disassociations.
- **FR-07 (Logging Visibility Honesty)**: Clearly distinguish the 6 full-logging accounts from the 33 sampled-request accounts on every chart, table, and score breakdown.
- **FR-08 (WAF Cost Analysis)**: Attribute monthly AWS WAF costs by account, WebACL, WCU consumption, request volume, and logging overhead alongside the central platform's own infrastructure cost.

### 5.3 Entity Intelligence, JA3/JA4 & Behavioral Detection (FR-09 to FR-15)
- **FR-09 (First-Class Entity Model)**: Normalize and link `IP`, `ASN`, `Country`, `Organization`, `JA3`, `JA4`, `User-Agent`, `URI Pattern`, `Application`, `WebACL`, `Rule`, and `Campaign`.
- **FR-10 (JA3/JA4 Fingerprint Correlation)**: Identify botnets rotating across ratusan/thousands of residential proxy IPs and ASNs that share identical `JA4` TLS client fingerprints.
- **FR-11 (Behavioral Detection Rules)**:
  - *Scanner*: High URI diversity ($> 25$ unique URIs per window) combined with elevated $404\text{/BLOCK}$ ratios.
  - *Credential Attack*: High-frequency `POST` requests targeting `/login`, `/auth`, or `/oauth/token` sharing a common `JA4`.
  - *Distributed & Slow Distributed Attack*: Low request rate per individual IP ($< 10\text{ req/min}$) evading WAF rate-based rules, but high aggregate volume across $\ge 15$ IPs sharing a `JA4` and target URI.
  - *Malicious Allowed Traffic*: Any request from an entity with $T \ge 75$ or matched COUNT rule that resulted in `action = 'ALLOW'`. Triggers an immediate `CRITICAL` alert.
- **FR-12 (Campaign Engine)**: Automatically cluster correlated IPs, JA4s, ASNs, and target URIs into first-class `Campaign` objects with unified timelines and response playbooks.
- **FR-13 (Threat Intelligence Enrichment)**: Asynchronous, Redis-cached (24h TTL) lookups against AbuseIPDB, GreyNoise, and VirusTotal with graceful degradation if an external API is rate-limited or offline.
- **FR-14 (Interactive Query Builder)**: Support multi-clause queries across 19 fields using `=`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `starts_with`, `ends_with`, `in`, `AND`, `OR`, `NOT`.
- **FR-15 (2D Relationship Graph & Attack Story)**: Render interactive 2D D3.js force-directed graphs (`IP` $\leftrightarrow$ `ASN` $\leftrightarrow$ `JA4` $\leftrightarrow$ `Application` $\leftrightarrow$ `Campaign`) and evidence-backed chronological Attack Stories.

### 5.4 Simulation, Controlled Response & Audit (FR-16 to FR-22)
- **FR-16 (Rule Impact Simulator)**: Evaluate proposed WAF changes (new block, rate limit, scope-down, managed rule upgrade) against historical `waf_events` to project blocked malicious requests vs. potential false positives before requesting approval.
- **FR-17 (False Positive Analyzer)**: Identify legitimate traffic blocked by overly broad managed sub-rules and simulate scoped-down exclusions.
- **FR-18 (Server-Side Allow-List Guardrails)**: Hard-block any attempt to block protected CIDR ranges, internal NAT gateways, payment processors, or authorized security scanners with `DENIED: Protected Entity`.
- **FR-19 (Tiered Approval Policies)**:
  - Temporary IP Block ($\le 1\text{ hour TTL}$): Security Analyst approval.
  - Permanent IP Block: Security Admin approval.
  - WAF Rule / Rate-Limit / Exception Modification: Security Admin + Application Owner approval.
  - Critical WebACL Association / Default Action Change: Two-person Security Admin approval.
- **FR-20 (Post-Execution Verification)**: After `ResponseRole` applies a change in AWS, re-read the live AWS WAFv2 resource state and compare `LockToken` / configuration to verify convergence before marking the change `VERIFIED`.
- **FR-21 (TTL Auto-Expiry & 1-Click Rollback)**: Automatically remove expired temporary IP blocks via scheduled cleanup and store pre-change state snapshots for 1-click rollback.
- **FR-22 (Immutable Audit Trail)**: Record every approval request, approval decision, AWS API call, `aws_request_id`, verification result, and rollback in an append-only `audit_events` table.

---

## 6. Non-Functional Requirements (NFRs)

| Category | Requirement | Target Metric |
| :--- | :--- | :--- |
| **Scale** | Concurrent AWS accounts monitored | $39\text{ accounts}$ (extensible to $100+$) |
| **Data Freshness** | Scheduled full config & discovery sync | Every $6\text{ hours}$ ($\le 5\text{ mins}$ total fan-out duration) |
| **Telemetry Polling** | `GetSampledRequests` & CloudWatch metrics | Every $30\text{ minutes}$ across all active WebACLs |
| **Manual Refresh** | `/api/v1/refresh` response latency | Immediate (`< 200\text{ ms}`) if data $< 1\text{h}$ old; async WebSocket push if stale |
| **UI Performance** | Dashboard & table rendering latency | $P_{95} < 300\text{ ms}$ for REST queries backed by RDS indexes |
| **Availability** | Central Platform uptime | $99.9\%$ (Multi-AZ RDS PostgreSQL + ALB) |
| **Cost Efficiency** | Total AWS infrastructure + TI APIs | $\le \$350\text{/month}$ |
| **Audit Retention** | Immutable `audit_events` retention | $1\text{ year}$ hot in RDS PostgreSQL; $7\text{ years}$ archived in S3 Object Lock |

---

## 7. Production Acceptance Criteria

1. $39/39$ AWS accounts discovered and reachable via `DiscoveryRole`.
2. $100\%$ of ALBs, CloudFront distributions, and API Gateways inventoried with accurate WAF attachment status.
3. Every WebACL displays an evidence-backed Security Score ($0\text{--}100$) and explicit data confidence (`FULL`, `PARTIAL`, `SAMPLED`, `NONE`).
4. All 6 logging-enabled accounts ingest S3 WAF logs; all 33 non-logging accounts ingest `GetSampledRequests` and CloudWatch metrics every 30 minutes.
5. Zero mock or hardcoded data remains in the frontend bundle (`mockData.ts` completely retired).
6. Full 12-step Approval Lifecycle (`DETECT` $\rightarrow$ `ROLLBACK`) verified end-to-end with server-side Allow-List guardrails and MFA-enforced `ResponseRole` execution.