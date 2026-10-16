# Technical Requirements Document (TRD)
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17
- **Architecture Pattern:** Hub-and-Spoke Serverless Data Pipeline + FastAPI Control Plane + React SPA

---

## 1. System Architecture & Network Topology

### 1.1 Central Security Account VPC Architecture
The platform is deployed into a dedicated **Central Security AWS Account** inside a Multi-AZ VPC (`10.240.0.0/16`):
- **Public Subnets (`10.240.1.0/24`, `10.240.2.0/24`)**: Host the internet-facing Application Load Balancer (ALB) protected by AWS WAFv2 and CloudFront with an ACM TLS 1.3 certificate, plus a single-AZ NAT Gateway (for outbound Threat Intelligence API calls to AbuseIPDB, GreyNoise, and VirusTotal).
- **Private Application Subnets (`10.240.11.0/24`, `10.240.12.0/24`)**: Host the FastAPI backend containers/instances and the per-account AWS Lambda functions.
- **Private Data Subnets (`10.240.21.0/24`, `10.240.22.0/24`)**: Host **Amazon RDS PostgreSQL 16** (`db.t3.large`, Multi-AZ, encrypted with KMS) and **Amazon ElastiCache Redis 7** (`cache.t3.micro`, in-transit and at-rest encryption).

### 1.2 Private AWS API Routing (VPC Interface Endpoints)
To ensure cross-account AWS API traffic never traverses the public internet or incurs NAT Gateway data processing charges, the VPC provisions 5 Interface Endpoints (`PrivateDnsEnabled: true`):
1. `com.amazonaws.<region>.sts` (Cross-account `AssumeRole` calls)
2. `com.amazonaws.<region>.wafv2` (Regional WAFv2 API calls)
3. `com.amazonaws.<region>.monitoring` (CloudWatch `GetMetricData` / `ListMetrics`)
4. `com.amazonaws.<region>.logs` (CloudWatch Logs inspection)
5. `com.amazonaws.<region>.states` (Step Functions orchestration triggers)

---

## 2. Cross-Account IAM Architecture

Deployed across all 39 spoke accounts via **AWS CloudFormation StackSets** with `SERVICE_managed` permissions.

### 2.1 `SASWafDiscoveryRole` (Read-Only, Assumed by Pipeline Lambdas)
- **Trust Policy**: Allows `sts:AssumeRole` only from `arn:aws:iam::<CENTRAL_ACCOUNT_ID>:role/SASLambdaCollectorExecutionRole` with an `sts:ExternalId` condition stored in AWS Secrets Manager.
- **Permissions Policy**:
  - `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `wafv2:GetWebACLForResource`, `wafv2:ListResourcesForWebACL`, `wafv2:GetSampledRequests`, `wafv2:GetLoggingConfiguration`, `wafv2:ListRuleGroups`, `wafv2:GetRuleGroup`, `wafv2:ListIPSets`, `wafv2:GetIPSet`, `wafv2:ListAvailableManagedRuleGroups`, `wafv2:ListAvailableManagedRuleGroupVersions`
  - `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`
  - `apigateway:GET`
  - `cloudfront:ListDistributions`, `cloudfront:GetDistribution`
  - `cloudwatch:GetMetricData`, `cloudwatch:ListMetrics`
  - `ec2:DescribeRegions`
  - `logs:DescribeLogGroups`, `logs:DescribeLogStreams`

### 2.2 `SASWafResponseRole` (Tightly Scoped Write, Assumed Only by Approval Execution Worker)
- **Trust Policy**: Allows `sts:AssumeRole` only from `arn:aws:iam::<CENTRAL_ACCOUNT_ID>:role/SASFastAPIResponseExecutorRole` AND requires `"Bool": {"aws:MultiFactorAuthPresent": "true"}` or signed approval token context.
- **Permissions Policy**:
  - **Allow**: `wafv2:UpdateIPSet`, `wafv2:UpdateWebACL`, `wafv2:AssociateWebACL`, `wafv2:DisassociateWebACL`, `wafv2:PutLoggingConfiguration`, `wafv2:GetWebACL`, `wafv2:GetIPSet`
  - **Explicit Deny**: `wafv2:DeleteWebACL`, `wafv2:DeleteRuleGroup`, `wafv2:DeleteIPSet`, `iam:*`, `organizations:*`, `s3:Delete*`

---

## 3. Serverless Data Pipeline Specification

### 3.1 Step Functions Fan-Out State Machine
Triggered by **Amazon EventBridge** on two schedules:
- **Telemetry Sync (`rate(30 minutes)`)**: Collects `GetSampledRequests` and CloudWatch metrics (`AllowedRequests`, `BlockedRequests`, `CountedRequests`) across all 39 accounts.
- **Full Discovery & Governance Sync (`rate(6 hours)`)**: Performs full endpoint discovery (ALB, CloudFront, API Gateway), WebACL rule tree sync, managed rule version check, and configuration drift evaluation.

```json
{
  "Comment": "SAS 39-Account Parallel WAF Discovery & Telemetry Pipeline",
  "StartAt": "FetchActiveAccounts",
  "States": {
    "FetchActiveAccounts": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-fetch-accounts",
      "Next": "PerAccountFanOut"
    },
    "PerAccountFanOut": {
      "Type": "Map",
      "ItemsPath": "$.accounts",
      "MaxConcurrency": 20,
      "Retry": [
        {
          "ErrorEquals": ["WAFLimitsExceededException", "ThrottlingException"],
          "IntervalSeconds": 2,
          "MaxAttempts": 4,
          "BackoffRate": 2.5
        }
      ],
      "Iterator": {
        "StartAt": "CollectAccountWafData",
        "States": {
          "CollectAccountWafData": {
            "Type": "Task",
            "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-account-collector",
            "TimeoutSeconds": 180,
            "Catch": [
              {
                "ErrorEquals": ["States.ALL"],
                "ResultPath": "$.error",
                "Next": "MarkAccountDegraded"
              }
            ],
            "End": true
          },
          "MarkAccountDegraded": {
            "Type": "Task",
            "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-mark-account-degraded",
            "End": true
          }
        }
      },
      "Next": "RunPostSyncEngines"
    },
    "RunPostSyncEngines": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "RunDriftAndScoringEngine",
          "States": {
            "RunDriftAndScoringEngine": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-drift-scoring-engine",
              "End": true
            }
          }
        },
        {
          "StartAt": "RunDetectionAndCampaignEngine",
          "States": {
            "RunDetectionAndCampaignEngine": {
              "Type": "Task",
            "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-detection-campaign-engine",
              "End": true
            }
          }
        },
        {
          "StartAt": "EnqueueThreatIntelLookups",
          "States": {
            "EnqueueThreatIntelLookups": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:us-east-1:CENTRAL_ACCT:function:sas-ti-enrichment-worker",
              "End": true
            }
          }
        }
      ],
      "End": true
    }
  }
}
```

### 3.2 `GetSampledRequests` Multi-Rule Collection Algorithm
Because `wafv2:GetSampledRequests` only samples up to 500 requests from the first 5,000 requests matching a **single** `RuleMetricName`:
1. The collector Lambda retrieves the WebACL definition via `get_web_acl`.
2. It extracts the WebACL top-level `VisibilityConfig.MetricName` (representing the `DefaultAction`) and iterates over every rule in `WebACL.Rules[]` to collect each rule's `VisibilityConfig.MetricName`.
3. For each metric name, it calls `get_sampled_requests(WebAclArn, RuleMetricName, Scope, TimeWindow={StartTime: now - 30m, EndTime: now}, MaxItems=500)`.
4. It deduplicates requests within the batch using a deterministic SHA-256 fingerprint:

$$H_{\text{event}} = \text{SHA256}\left(\text{WebACL\_ARN} \;\|\; \text{ClientIP} \;\|\; \text{Timestamp\_ms} \;\|\; \text{Method} \;\|\; \text{URI} \;\|\; \text{RuleName}\right)$$

5. It extracts TLS fingerprints (`JA3`, `JA4`) from CloudFront/ALB forwarded headers or WAF labels (`awswaf:clientip:geo:...`, custom token labels) and writes normalized rows to `waf_events` with `source = 'SAMPLED'`.

### 3.3 Full WAF Log S3 Ingestion (6 Logging-Enabled Accounts)
For the 6 accounts with full WAF logging enabled:
1. WAF logs are delivered every 5 minutes to a regional S3 staging bucket or cross-account S3 prefix (`aws-waf-logs-sas-<account_id>`).
2. `s3:ObjectCreated:*` events trigger `sas-s3-log-ingestor` Lambda.
3. The Lambda streams `.gz` JSON lines, extracts `httpRequest`, `terminatingRuleId`, `action`, `ja3Fingerprint`, `ja4Fingerprint`, `labels`, and writes to `waf_events` with `source = 'FULL_LOG'`.

---

## 4. Detection, Correlation & Campaign Engine Specifications

### 4.1 JA3/JA4 Correlation & Campaign Clustering
Executed after every 30-minute telemetry sync over a sliding 24-hour window:
1. Group `waf_events` by `ja4` where `ja4 IS NOT NULL`.
2. Flag a **JA4 Coordinated Campaign** when a single `ja4` fingerprint satisfies:

$$\left|\text{distinct}(\text{client\_ip})\right| \ge 5 \quad \land \quad \left(\text{block\_rate} \ge 0.40 \;\lor\; \left|\text{attack\_techniques}\right| \ge 1\right)$$

3. Automatically create or update a `campaigns` record, linking all participating `IP`, `ASN`, `JA4`, and targeted `Application` entities into `entity_relationships`.

### 4.2 Behavioral Detection Heuristics
| Detection Type | Mathematical Trigger Condition (30-Min Window) | Default Severity |
| :--- | :--- | :--- |
| `SCANNER` | $\left|\text{distinct}(\text{uri})\right| \ge 25 \;\land\; \frac{N_{\text{BLOCK}} + N_{404}}{N_{\text{total}}} \ge 0.60$ | `MEDIUM` / `HIGH` |
| `CREDENTIAL_ATTACK` | $\text{URI} \in \{\text{/login}, \text{/auth}, \text{/api/v1/token}\} \;\land\; \text{Method} = \text{'POST'} \;\land\; N_{\text{req}} \ge 50$ | `HIGH` |
| `DISTRIBUTED_ATTACK` | $\left|\text{distinct}(\text{ip})\right| \ge 15 \;\land\; \text{same}(\text{ja4}) \;\land\; \text{same}(\text{uri\_prefix})$ | `CRITICAL` |
| `SLOW_DISTRIBUTED` | $\max_{i}(\text{rate}(\text{ip}_i)) \le 10\text{ req/min} \;\land\; \sum_{i} N_{\text{req}}(\text{ip}_i) \ge 300 \;\land\; \text{same}(\text{ja4})$ | `HIGH` |
| `MALICIOUS_ALLOWED` | $\text{Entity.threat\_score} \ge 75 \;\land\; \text{waf\_event.action} = \text{'ALLOW'}$ | `CRITICAL` |

---

## 5. FastAPI Backend & Control Plane Specification

### 5.1 Technology Stack
- **Runtime**: Python 3.12, FastAPI 0.115+, Uvicorn with Gunicorn workers.
- **Database ORM**: SQLAlchemy 2.0 (`AsyncSession` + `asyncpg`) with Alembic migrations.
- **Caching & Pub/Sub**: `redis.asyncio` for Threat Intel caching (`ti:ip:<ip>` TTL $86,400\text{ s}$), `/api/v1/refresh` cooldown locks, and WebSocket event broadcasting.
- **Validation**: Pydantic v2 strict models.

### 5.2 Optimistic Locking & Verification on AWS WAFv2 Changes
Every AWS WAFv2 mutation (`UpdateIPSet`, `UpdateWebACL`) requires an AWS `LockToken`:
1. The Execution Worker assumes `SASWafResponseRole` in the target account.
2. It calls `get_ip_set` or `get_web_acl` to capture:
   - `previous_state` (stored in `changes.previous_state` JSONB for 1-click rollback).
   - Current `LockToken`.
3. It executes `update_ip_set` or `update_web_acl` using the `LockToken` and captures `ResponseMetadata.RequestId` (`aws_request_id`).
4. **Verification Step (Rule #7)**: The worker waits $2\text{ seconds}$, calls `get_ip_set` / `get_web_acl` again, and verifies that the new `LockToken` changed and the target IP/rule statement is present in the returned AWS state before setting `verification_status = 'VERIFIED'`.

---

## 6. Security & Reliability Controls

- **Zero Browser Secrets**: The React SPA communicates exclusively with FastAPI over HTTPS/WSS using `HttpOnly`, `Secure`, `SameSite=Strict` session cookies issued after IAM Identity Center SAML/OIDC authentication.
- **Server-Side Allow-List Interceptor**: Implemented as a mandatory FastAPI dependency (`verify_not_allowlisted`) and database trigger before any row in `approvals` can transition to `APPROVED` or `EXECUTING`.
- **Graceful Degradation**:
  - If AbuseIPDB, GreyNoise, or VirusTotal returns HTTP `429` or `5xx`, the TI worker logs the provider degradation in `platform_health`, marks `confidence` using internal WAF telemetry only, and does not block the pipeline.
  - If an AWS account's `DiscoveryRole` fails STS assumption, only that account is marked `DEGRADED`/`UNAVAILABLE`; the remaining 38 accounts complete normally.