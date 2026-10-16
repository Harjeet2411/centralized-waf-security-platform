# CLAUDE.md — SAS Threat Intelligence & Centralized WAF Security Platform

Persistent context for every Claude Code session in this repository. Read this first. When this file and a doc in `docs/` disagree, **this file wins** (conflicts are resolved in §9). When this file and the actual code disagree on a *fact about the code*, the code wins and this file must be fixed.

---

## 1. Mission

Production-grade centralized WAF Security, Threat Intelligence, Behavioral Detection, Investigation, Simulation and Controlled Response platform for a financial-services AWS Organization of **39 accounts** (Regional ALB / API Gateway WAFv2 + Global CloudFront WAFv2).

- **Logging reality:** only **6/39** accounts have full WAF logging (S3). The other **33/39** rely on `wafv2:GetSampledRequests`, CloudWatch `GetMetricData`, and WAFv2 configuration APIs. Never assume an account has logging.
- **Cost ceiling:** central infrastructure + Threat Intel APIs **≤ $350/month**. The fixed baseline (Multi-AZ `db.t3.large` ~$200, NAT ~$32, ALB ~$17–25, Redis ~$12–15, VPC endpoints) already consumes most of it — every new AWS resource needs a cost line.

Every screen, pipeline and workflow exists to answer, with evidence:

1. What is attacking us? (IP, ASN, Org, Country, JA3/JA4, User-Agent)
2. What are they attacking? (account, application, ALB/CloudFront/APIGW, URI)
3. How are they attacking? (SQLi, XSS, credential stuffing, scanner, slow distributed, bots)
4. Did WAF stop it? (`BLOCK` / `ALLOW` / `COUNT` / `CAPTCHA` / `CHALLENGE`)
5. If not, why? (unprotected endpoint, rule in COUNT, scope-down exclusion, drift, missing managed group)
6. Is the WAF effective? (0–100 Security Score with explicit confidence)
7. What should we do? (explainable recommendation backed by simulation)
8. Can we safely do it? (simulation, false-positive analysis, server-side allow-list)
9. Who changed it? (immutable audit, AWS request IDs, verification, rollback)

---

## 2. Non-Negotiable Hard Constraints

1. **NO** AWS Firewall Manager. **NO** AWS Shield Advanced. **NO** centralized WAF data lake (no shipping 39 accounts of full logs into OpenSearch/Splunk/Athena). **NO** third-party SIEM/SOAR or managed firewall platform.
2. **NO autonomous AI-driven AWS changes.** AI/LLM use is read-only: investigation summaries, evidence summarization, attack stories, analyst recommendations, natural-language explanation. An AI output may *pre-fill* an approval request; it may never approve or execute one.
3. **NO browser-to-AWS calls and NO AWS credentials in the frontend.** The SPA talks only to FastAPI over HTTPS/WSS with `HttpOnly; Secure; SameSite=Strict` session cookies issued after IAM Identity Center (SSO + MFA) login.
4. **NO mock, fake or hardcoded security data in production.** `WAF_PLATFORM/src/data/mockData.ts` is prototype scaffolding; it is retired in Milestone 5. Test fixtures live under `tests/` only and are never imported by app code.
5. **2D investigation-first UI.** D3.js v7 2D force graphs. No 3D globes, no decorative hero visuals.

---

## 3. The 10 Golden Implementation Rules

Numbering matches `WAF_PLATFORM_SPEC.md` §15 — refer to them by number in code comments and reviews.

1. **Evidence-first.** Every score, metric and recommendation links to the records that produced it (`score_evidence`, `evidence`, `correlation_evidence` JSONB). No number without a drill-down.
2. **Every AWS-mutating action follows the 12-step Approval Lifecycle**, enforced in the backend, no shortcuts:
   `DETECT → UNDERSTAND → CORRELATE → SCORE → SIMULATE → CHECK GUARDRAILS → REQUEST APPROVAL → APPROVE → EXECUTE → VERIFY → AUDIT → ROLLBACK IF REQUIRED`
3. **Server-side allow-list enforcement.** `allow_list_entries` is checked in PostgreSQL with GiST CIDR containment (`ip <<= ip_network`) as a mandatory FastAPI dependency (`verify_not_allowlisted`) **and** re-checked before an approval moves to `APPROVED`/execution. A match hard-denies with HTTP `403` and detail `"DENIED: Protected Entity"`. No UI flag, role or request field can bypass it.
4. **Never claim sampled = complete.** Every telemetry API response, score and entity profile carries `visibility_level` (`full` | `sampled` | `metrics` | `none`) and `score_confidence` (`FULL` | `PARTIAL` | `SAMPLED` | `NONE`). The UI renders the Visibility Pill (§7) next to the number. Aggregate counts come from CloudWatch (exact); request payloads from `GetSampledRequests` (sampled) — say which.
5. **No secrets in the frontend.** AWS creds, TI API keys and the StackSet `ExternalId` live in AWS Secrets Manager, read only by backend/Lambda.
6. **Immutable audit.** `audit_events` is append-only, enforced by the `prevent_audit_mutation()` trigger (`BEFORE UPDATE OR DELETE`). The app DB role gets `INSERT, SELECT` only on it. Never write a migration that drops or weakens that trigger.
7. **Verify before claiming success.** After `SASWafResponseRole` calls `UpdateIPSet` / `UpdateWebACL` with the current `LockToken`: capture `ResponseMetadata.RequestId` as `aws_request_id`, wait ~2 s, re-read the resource, confirm the `LockToken` rotated **and** the target state is present. Only then set `verification_status = 'VERIFIED'`. Otherwise `FAILED` — never optimistic success in UI or DB.
8. **Graceful degradation.** TI provider `429`/`5xx` → record degradation in platform health, score from internal WAF telemetry only, never block the pipeline. One account's STS failure → that account `DEGRADED`/`UNAVAILABLE`, the other 38 finish.
9. **Cost-aware.** Cache TI (24 h), batch AWS calls, no new always-on infrastructure without a cost line against the $350 ceiling.
10. **Start small, prove the lifecycle, then scale.** 5 pilot accounts first, then 39.

---

## 4. Repository Layout & Tech Stack

```
/
├── CLAUDE.md                 # this file
├── WAF_PLATFORM_SPEC.md      # master spec (source of the 10 rules)
├── docs/                     # PRD, TRD, APP_FLOW, DESIGN_LANGUAGE, BACKEND_SCHEMA, IMPLEMENTATION_PLAN, CHANGELOG
├── WAF_PLATFORM/             # existing frontend (the docs call it "frontend/" — same thing, keep this name)
├── backend/                  # FastAPI control plane            (Milestone 1)
├── lambdas/                  # serverless pipeline              (Milestones 2–3)
└── infra/                    # StackSets + central account IaC  (Milestone 2)
```

### `WAF_PLATFORM/` — actual versions from `package.json`
Vite 8, React 19.2, TypeScript 6, Tailwind CSS 4 (`@tailwindcss/postcss`), Zustand 5, TanStack React Query 5 (installed, not yet used), D3 7, date-fns 4, lucide-react, react-router-dom 7 (installed, navigation currently uses `currentPage` in the store). Path alias `@/` → `src/`. Dev server port **5000**.

- `src/types/index.ts` — **the wire contract** (see §8).
- `src/store.ts` — Zustand store exported as **`useAppStore`** (not `usePlatformStore`). Holds navigation, drawer, workspace tabs, context breadcrumb, filters, and (today) mock data. It has **no** mutation actions yet; `approveRequest`, `rejectRequest`, `rollbackChange`, `createApprovalRequest`, `triggerRefresh` are added in Milestone 5.
- `src/data/mockData.ts` — imported **only** by `src/store.ts`. Delete in Milestone 5.
- `src/components/` — `commandCenter`, `threat-intelligence`, `entities` (+ `EntityDetailPanel`), `waf-security`, `investigation` (+ `CampaignDetail`), `detection`, `simulation`, `response`, `governance`, `cost`, `reports`, `layout` (`Sidebar`, `TopBar`, `ContextBar`), `common` (`Drawer`).
- `src/index.css` — design tokens as CSS variables (`--color-bg-primary`, `--color-critical`, …). **These are the real tokens**; `docs/DESIGN_LANGUAGE.md` hex values are approximations of them.

### `backend/`
Python 3.12, FastAPI 0.115+, Uvicorn (Gunicorn workers in prod), SQLAlchemy 2.0 async (`AsyncSession` + `asyncpg`), Alembic, Pydantic v2 (strict), `redis.asyncio`, `boto3`, pytest.

```
backend/app/
  main.py  config.py  database.py
  models/  schemas/  api/v1/
  services/ guardrail_service.py  simulator_service.py  aws_executor.py  rbac_service.py
backend/alembic/   backend/tests/
```

### `lambdas/` (Python 3.12, psycopg 3 sync)
Built: `fetch_accounts` (Map input), `account_collector` (`handler.py` orchestration · `collect.py` read-only AWS calls · `store.py` idempotent DB writes), `mark_account_degraded` (ASL Catch target), `s3_log_ingestor`, `ti_enrichment_worker`, `detection_campaign_engine`, `drift_scoring_engine` (post-sync, in that order). Scoring formulas live only in `common/scoring.py`. TTL expiry runs in the backend (`app/workers/ttl_expiry.py`) because it must reuse the approval executor. Each function is a package with `handler.py` → Lambda handler `<pkg>.handler.lambda_handler`; the zip holds the package + `common/` + Linux wheels for psycopg. Shared code lives only in `lambdas/common/` (`db.py`, `aws.py`, `normalize.py`). Tests in `lambdas/tests/` (one suite, real Postgres, botocore `Stubber` pins request shapes).

Pipeline facts that are easy to get wrong:
- Step Functions retries match the Lambda `errorType` = Python exception class name. Throttling `ClientError`s are re-raised as `common.aws.WAFLimitsExceededException` / `ThrottlingException` so the ASL `Retry` matches. Retries sit on the per-account task, **never on the Map** (a Map retry re-runs all 39 accounts).
- `account_collector` never writes `score_confidence` — `drift_scoring_engine` owns it; `mark_account_degraded` sets `NONE` for unreachable accounts. WebACL confidence: full→FULL, sampled→SAMPLED, metrics-only→NONE (no request-level evidence). Account: all full→FULL, mixed full/sampled→PARTIAL, sampled→SAMPLED.
- Engines process `waf_events` by **ingestion** watermark (`engine_state`, DB clock minus `SAS_WATERMARK_LAG_SECONDS`), never by event timestamp — late S3 logs must not be skipped. Window queries (24h / 30 min) use event `timestamp`.
- `web_acls.current_config` / `baseline_config` are written on full syncs only and include `_logging_destination` and `_associated_resources` (drift needs both; GetWebACL returns neither).
- Endpoint deletion happens only for `(region, type)` scopes whose discovery fully succeeded in that run.
- First-seen WebACL JSON becomes `web_acls.baseline_config`; after that only an approved change may move the baseline.
- JA3/JA4 are native in full logs. In `GetSampledRequests` they exist only if injected upstream (CloudFront `CloudFront-Viewer-JA4-Fingerprint` header via viewer-request function / `x-ja4` header / `sas:ja4:<hash>` label) — otherwise `NULL`. Never fabricate.
- Removed WebACLs are not deleted (cascade would erase `waf_events` history). ponytail: add `web_acls.deleted_at` when the drift engine needs it.

### `infra/` (see `infra/README.md` for deploy order and the cost table)
- `stacksets/cross-account-waf-roles.yaml` — `SASWafDiscoveryRole` + `SASWafResponseRole` (CloudFormation StackSet, `SERVICE_MANAGED`).
- `central_account/platform.yaml` — VPC `10.240.0.0/16`, 5 interface endpoints + S3 gateway endpoint, Multi-AZ RDS PostgreSQL 16, Redis 7, KMS, secrets, ECR, WAF-log + audit-archive buckets, SNS, the 7 Lambdas, Step Functions + EventBridge schedules.
- `central_account/app.yaml` — ECS Fargate API (task role `SASFastAPIResponseExecutorRole`), ALB + WAF reachable only via CloudFront (`X-Origin-Verify`), SPA on S3/CloudFront, TTL-expiry scheduled task.
- `central_account/step_functions.asl.json` — uploaded by `lambdas/build.py` next to the zips.
- **Cost:** default config is ~$407/month on-demand, over the $350 ceiling. It fits (~$345) only with a 1-year RDS reservation. Any new always-on resource must be added to the cost table in `infra/README.md`.

### Cross-account IAM (TRD §2 is authoritative)
- **`SASWafDiscoveryRole`** — read-only; trusted only by `SASLambdaCollectorExecutionRole` with `sts:ExternalId`. `wafv2:List*/Get*/GetSampledRequests/ListAvailableManagedRuleGroupVersions`, `elasticloadbalancing:Describe*`, `apigateway:GET`, `cloudfront:List/GetDistribution`, `cloudwatch:GetMetricData/ListMetrics`, `ec2:DescribeRegions`, `logs:Describe*`.
- **`SASWafResponseRole`** — trusted only by `SASFastAPIResponseExecutorRole` with MFA / signed-approval condition. Allow: `wafv2:UpdateIPSet, UpdateWebACL, AssociateWebACL, DisassociateWebACL, PutLoggingConfiguration, GetWebACL, GetIPSet`. **Explicit Deny:** `wafv2:DeleteWebACL, DeleteRuleGroup, DeleteIPSet, iam:*, organizations:*, s3:Delete*`.

---

## 5. Data Model & Pipeline Essentials

- **Schema:** `docs/BACKEND_SCHEMA.md` DDL — **20 tables** (the doc says 19; `drift_events` is #20) plus `platform_health` (see §9). Keep the CHECK constraints, partial indexes, GIN index on `waf_events.http_request`, GiST index on `allow_list_entries.ip_network`, and the audit trigger.
- **Schedules (EventBridge → Step Functions Map, `MaxConcurrency: 20`):** telemetry `rate(30 minutes)` (sampled requests + CloudWatch metrics); full discovery/governance `rate(6 hours)`. Retry `WAFLimitsExceededException`/`ThrottlingException`: interval 2 s, 4 attempts, backoff 2.5. Per-account `Catch` → mark account degraded, continue.
- **Manual refresh:** `POST /api/v1/refresh` — data < 60 min old and not `force` → `200 {"status":"ready"}` (< 200 ms). Else take Redis lock `sync:global:lock` (TTL 300 s), start the state machine, `202 {"status":"syncing","execution_arn":...}`, push progress over `/ws/events`, broadcast `SYNC_COMPLETED`.
- **Multi-rule sampling:** `GetSampledRequests` samples max 500 of the first 5,000 requests **per `RuleMetricName`** → iterate the WebACL `VisibilityConfig.MetricName` (default action) **and** every `Rules[].VisibilityConfig.MetricName`, 30-min window, `MaxItems=500`.
- **Dedup hash:** `event_hash = SHA256(WebACL_ARN || ClientIP || Timestamp_ms || Method || URI || RuleName)` — unique column; inserts use `ON CONFLICT (event_hash) DO NOTHING`.
- **Full logs (6 accounts):** S3 `ObjectCreated` → `s3_log_ingestor` streams `.gz` JSON lines → `waf_events` with `source = 'FULL_LOG'`. Sampled rows use `source = 'SAMPLED'`.
- **Redis keys:** `ti:ip:{ip}` (24 h), `sync:global:status` (6 h), `sync:global:lock` (5 min), `session:user:{id}` (8 h), channel `pubsub:platform_events`.

---

## 6. Exact Mathematical Models

All scores are on `[0, 100]`. Every computed score stores its inputs in an evidence JSONB column (Rule #1).

### 6.1 WAF Security Score (per WebACL, rolled up per account)
```
S_WAF = 0.25·d_coverage + 0.20·d_blocking + 0.20·d_malicious_allowed
      + 0.10·d_count_exposure + 0.10·d_drift + 0.10·d_managed_versions + 0.05·d_logging
```
Each `d_i ∈ [0,100]`, weights sum to 1.0 (weights configurable, defaults above).
- `d_coverage` — % of internet-facing ALB/CloudFront/APIGW attached to a WebACL.
- `d_blocking` — % of `MALICIOUS`+`SUSPICIOUS` requests that ended in `BLOCK` (vs `ALLOW`/`COUNT`).
- `d_malicious_allowed` — inverse penalty on volume × severity of high-risk `ALLOW` traffic.
- `d_count_exposure` — penalty for critical managed/custom rules left in `COUNT` past their tuning window.
- `d_drift` — deduction per unresolved `CRITICAL`/`HIGH` drift event.
- `d_managed_versions` — % of managed rule groups at `CURRENT` (vs `OUTDATED`/`DEPRECATED`).
- `d_logging` — logging present. Disabled logging lowers `d_logging` and confidence; it **never** by itself makes a well-configured WebACL "critical".

**Confidence badge:** `FULL` = full logs + metrics + config (6 accounts); `PARTIAL` = sampled + partial logs + metrics; `SAMPLED` = `GetSampledRequests` + metrics + config (33 accounts); `NONE` = account unreachable / STS or API failure.

### 6.2 Entity scoring (IP, ASN, JA3, JA4, UA, …) — four separate numbers, never one black box
- **Threat** `T = min(100, 0.35·T_TI + 0.25·T_WAF + 0.20·T_JA4 + 0.20·T_Campaign)`
  - `T_TI` normalized AbuseIPDB/GreyNoise/VirusTotal consensus; `T_WAF` block ratio + technique severity + URI diversity; `T_JA4` fingerprint malice correlation; `T_Campaign` active campaign membership.
- **Confidence** `C` — weighted by sample size, number of corroborating TI feeds, and visibility (`FULL` > `SAMPLED`). Exact weights are not specified in the docs: define them once in code, document them in the evidence JSON, and mark with a `ponytail:` comment until signed off.
- **Business Impact** `B` — criticality of targeted applications (`applications.criticality`); any `ALLOW` on a production payment/auth endpoint ⇒ `B ≥ 90`.
- **Final Risk** `R = round(0.60·T + 0.40·B)`
- **Risk level:** `CRITICAL` if `R ≥ 85` **or** malicious-allowed count > 0; `HIGH` 70–84; `MEDIUM` 40–69; `LOW` < 40.

### 6.3 Detections (30-min window unless stated)
| Type | Trigger | Default severity |
|---|---|---|
| `SCANNER` | distinct(uri) ≥ 25 **and** (N_BLOCK + N_404) / N_total ≥ 0.60 | `MEDIUM` / `HIGH` |
| `CREDENTIAL_ATTACK` | URI ∈ {`/login`, `/auth`, `/oauth/token`, `/api/v1/token`} **and** method = POST **and** N ≥ 50 (same JA4 raises confidence) | `HIGH` |
| `DISTRIBUTED_ATTACK` | distinct(ip) ≥ 15 **and** same JA4 **and** same URI prefix | `CRITICAL` |
| `SLOW_DISTRIBUTED` | max per-IP rate ≤ 10 req/min **and** Σ requests ≥ 300 **and** same JA4 | `HIGH` |
| `MALICIOUS_ALLOWED` | action = ALLOW **and** (entity `T ≥ 75` **or** request matched a rule in COUNT) | `CRITICAL` |
| `JA4_CORRELATION` (campaign) | 24-h sliding window: one JA4 with distinct(client_ip) ≥ 5 **and** (block_rate ≥ 0.40 **or** ≥ 1 attack technique) → create/update `campaigns`, link entities in `entity_relationships` | from member risk |

---

## 7. UI Rules (from `docs/DESIGN_LANGUAGE.md`)

- Tactical dark mode, high density, color reserved for severity / WAF action / visibility. Use the CSS variables in `src/index.css`.
- **Monospace + `tabular-nums`** for IPs, CIDRs, ASNs, JA3/JA4, account IDs, ARNs, URIs, ISO timestamps and all numeric columns.
- **Visibility Pill on every telemetry card and WebACL row:** `FULL LOGS` (emerald), `SAMPLED` (purple, tooltip: *"Request payloads are sampled via AWS GetSampledRequests; aggregate block/allow counts are exact via CloudWatch Metrics."*), `METRICS ONLY` (amber), `UNAVAILABLE` (red).
- Clicking an IP/ASN/JA4/WebACL opens the right-hand `Drawer` — never a full-page navigation. "Open Full Investigation" adds a workspace tab in `ContextBar`.
- D3 graph: IP = circle colored by risk; JA4 = purple hexagon/diamond; ASN/Org = blue rounded rect; App/Endpoint = emerald square (red dashed ring if unprotected or malicious-allowed). Edges: solid red = malicious allowed, dashed slate = blocked, purple pulse = JA4 correlation.
- Approval stepper: completed = emerald, active = pulsing blue, guardrail-blocked = red.

---

## 8. Contract Alignment Rule (backend ⇄ `src/types/index.ts`)

The existing frontend types are the wire contract. Facts about them that override the docs:

- **Field names are `snake_case`** (`account_id`, `security_score`, `last_discovered`). So Pydantic response schemas use plain snake_case field names. **Do NOT use `alias_generator = to_camel`** (the docs' convention predates checking the code; camelCase would break every component).
- **Enum values are lowercase** in TS (`'healthy'`, `'critical'`, `'pending'`) while DB CHECK constraints are uppercase (`'HEALTHY'`, `'CRITICAL'`, `'PENDING'`). Translate in the schema layer (one shared mapper per enum, in `backend/app/schemas/`), never in components.
- **Shapes differ from tables.** TS types include derived fields (`AWSAccount.waf_coverage`, `endpoint_count`, `webacl_count`; `WebACL.drift_count`, `managed_rule_health`; `Entity.threat_intel[]`). Schemas compute them from SQL; they are not stored columns.
- Known value-set mismatches to map explicitly: `AccountEnv` (`prod|uat|dev|shared`) vs DB `environment` (`production|staging|development|shared-services|security`); TS `Confidence` (`high|medium|low|none`) vs DB numeric `0–100` (default mapping: ≥ 80 high, ≥ 50 medium, > 0 low, 0 none); `ApprovalStatus` and `LifecycleStage` vs DB `approvals.status`; `EndpointType` `CloudFront` vs DB `CLOUDFRONT`.
- Response models live in `backend/app/schemas/contract.py`. `tests/test_bootstrap_contract.py` parses `index.ts` and fails if any TS interface field is missing from its schema — keep it green.
- **Additive "contract+" fields** (marked in `contract.py`: `score_confidence`, `visibility_level`, `score_evidence`, raw status/type values) may ship ahead of `index.ts`; the TS side adopts them in Milestone 5. Removing or renaming an existing TS field is never additive.
- **Any non-additive contract change edits `src/types/index.ts` and the matching Pydantic schema in the same change**, and `npm run build` + `pytest` must both pass.

---

## 9. Resolved Doc Conflicts (decisions in force)

| Conflict | Decision |
|---|---|
| Spec says Next.js; repo is Vite | Vite SPA (the code). No Next.js migration. |
| Docs say `frontend/`; repo has `WAF_PLATFORM/` | Keep `WAF_PLATFORM/`. |
| "19 tables" vs 20 in DDL | 20 tables + `platform_health` (TRD writes it; `PlatformHealth` type needs it). |
| `changes.previous_state` vs `previous_state_json` | `previous_state_json` (DDL). |
| Credential-attack URIs differ (TRD vs PRD) | Union of both lists (§6.3). |
| `MALICIOUS_ALLOWED` trigger differs | PRD: `T ≥ 75` **or** matched COUNT rule. |
| Temp-block approver (APP_FLOW shows 24 h block by Admin) | Spec/PRD policy: TTL ≤ 1 h → Security Analyst; any longer or permanent → Security Admin; rule/rate-limit/exception → Security Admin + Application Owner; WebACL association / default-action change → two Security Admins. |
| Spec ResponseRole allows `Create*`/`Delete*` | TRD's narrower allow-list + explicit deny. |
| Spec VPC endpoint `organizations` vs TRD `states` | TRD: `sts, wafv2, monitoring, logs, states`. |
| Docs camelCase convention | snake_case — §8. |
| TRD puts the throttling `Retry` on the Map state | On the per-account task (a Map retry re-runs every account). |
| TRD: ResponseRole trust requires `aws:MultiFactorAuthPresent` | Impossible through a service-role chain. Trust instead requires the response ExternalId + session tag `sas:approval-id=APR-*` + `sts:SourceIdentity` = approver email (lands in CloudTrail). Human MFA is enforced at platform login. Verify on the pilot account. |
| ResponseRole action list | Adds `elasticloadbalancing:SetWebACL` + `apigateway:SetWebACL` (required by `AssociateWebACL`). CloudFront attach needs `cloudfront:UpdateDistribution`, which is explicitly **denied** (too broad) — CloudFront attachments stay manual. |
| `approvals.allow_list_check VARCHAR(16)` in BACKEND_SCHEMA.md | Widened to 32 in migration 0003 (its own CHECK value `BLOCKED_PROTECTED_ENTITY` is 24 chars). |
| `ttl_expiry_worker` Lambda | Backend module `app/workers/ttl_expiry.py` (`python -m app.workers.ttl_expiry`) — it must reuse the approval executor and audit path. |
| SIMULATE for every change | Mandatory for TEMP/PERM block, MODIFY_RULE, MODIFY_RATE_LIMIT, ADD_EXCEPTION. Optional (lifecycle shows `skipped`) for REMEDIATE_DRIFT (restores an approved baseline), ATTACH_WAF and REMOVE_BLOCK (no traffic to replay). |

Interface VPC endpoints are regional: WAFv2/CloudWatch calls to regions other than the central one go via NAT. CloudFront-scope WAFv2 calls always target `us-east-1`.

---

### Controlled response facts (Milestone 4)
- **Code:** `app/services/approval_service.py` (policy + lifecycle), `aws_executor.py` (AWS calls), `guardrail_service.py`, `simulator_service.py`, `audit_service.py`; routes in `app/api/v1/response.py`.
- **IP blocks** go into a platform-owned IP set referenced by a WebACL rule named `SAS-Platform-Block*` (an `IP_SET` BLOCK rule). A WebACL without it returns 409 — provisioning that rule is a platform-team prerequisite per WebACL.
- **Block-target rails:** IP/CIDR only, no broader than /24 (v4) or /64 (v6), public ranges only. Allow-list checks happen at request time, again at approval time, and in the `trg_approvals_allow_list` DB trigger.
- **Tiered approval** (`approval_service.policy`): TEMP block ≤1h → Analyst or Admin; longer/permanent/remove → Admin; rule/rate/exception/drift → Admin + scoped Application Owner; ATTACH_WAF → Admin + (App Owner or AWS Administrator). Requesters can't approve, one person fills one slot, approvers need an MFA session.
- **Execution** runs inline on the final approval (boto3 in a thread). Verified WebACL changes move `baseline_config` so drift doesn't re-flag approved changes. Rollback applies the inverse of our own change (removes only the IPs we added, restores only the rule we touched) and refuses non-reversible changes (`changes.rollback_available = false`, e.g. enabling logging).
- **Executor tests** use `tests/fake_waf.py` (stateful, rotating LockTokens) via the `get_executor_factory` dependency override; `botocore.stub.Stubber` pins real UpdateWebACL/UpdateIPSet request shapes.
- **Audit rows** use `clock_timestamp()` so several rows written in one transaction keep their order. Only the test harness may suspend the audit triggers (cleanup in `tests/conftest.py`).

## 10. RBAC (8 roles, 9 permissions)

Permissions: `VIEW, INVESTIGATE, SIMULATE, CREATE_CHANGE, APPROVE, EXECUTE, ROLLBACK, MANAGE_TI, MANAGE_USERS`. Investigation permissions never imply modification permissions.

| Role | VIEW | INVESTIGATE | SIMULATE | CREATE_CHANGE | APPROVE | EXECUTE | ROLLBACK | MANAGE_TI | MANAGE_USERS |
|---|---|---|---|---|---|---|---|---|---|
| Security Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Security Analyst | ✓ | ✓ | ✓ | ✓ | temp blocks only | – | – | ✓ | – |
| SOC Analyst | ✓ | ✓ | ✓ | ✓ | – | – | – | – | – |
| AWS Administrator | ✓ | ✓ | ✓ | ✓ | infra only | ✓ | ✓ | – | – |
| Application Owner | ✓ | scoped | ✓ | scoped | app rules | – | – | – | – |
| Auditor | ✓ | ✓ | – | – | – | – | – | – | – |
| Executive | ✓ | – | – | – | – | – | – | – | – |
| Read Only | ✓ | – | – | – | – | – | – | – | – |

"Scoped" = limited to `users.scoped_account_ids`. A requester can never approve their own request. Enforce on the server per endpoint (see `docs/BACKEND_SCHEMA.md` §3 for the endpoint → permission map); UI hiding is cosmetic only.

---

## 11. Commands

Environment is Windows; commands below work in Git Bash and PowerShell unless noted.

### Frontend (`WAF_PLATFORM/`)
```bash
npm install
npm run dev          # Vite on http://localhost:5000
npm run build        # tsc -b && vite build — must pass with zero TS errors
npx tsc -b           # type-check only
```

### Local dependencies (repo root)
```bash
docker compose up -d --wait   # Postgres 16 on host port 5433 (5432 is taken by a native install), Redis 7 on 6379
```
Creates databases `sas_waf` (dev) and `sas_waf_test` (pytest; migrated down/up on every test session).

### Backend (`backend/`) — Python 3.12 venv
```bash
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
cp .env.example .env
.venv/Scripts/alembic upgrade head
.venv/Scripts/uvicorn app.main:app --reload --port 8000
.venv/Scripts/alembic revision --autogenerate -m "description"
.venv/Scripts/python -m pytest -q
.venv/Scripts/ruff check .
```
Migration 0001 is hand-written SQL (CHECKs, trigger, partial/GiST/GIN indexes). For later migrations, autogenerate then review — `tests/test_schema.py` fails if ORM models and the migrated schema drift apart.

### Lambdas (`lambdas/`) — shares the backend venv
```bash
../backend/.venv/Scripts/python -m pip install -e ".[dev]"
../backend/.venv/Scripts/python -m pytest -q        # migrates sas_waf_test via backend Alembic
../backend/.venv/Scripts/ruff check .
../backend/.venv/Scripts/cfn-lint ../infra/stacksets/*.yaml ../infra/central_account/*.yaml
../backend/.venv/Scripts/python build.py            # dist/<function>.zip with Linux wheels + the ASL
```

### Backend image
```bash
docker build -t sas-waf-backend:local backend      # API by default; TTL worker / alembic via command override
```

### Auth in local dev
Login is OIDC-only (`/api/v1/auth/login` → IdP fronting IAM Identity Center → `/api/v1/auth/callback`); users must be pre-provisioned in `users` by `sso_subject_id`. There is deliberately **no** dev-login bypass. Tests create sessions directly in Redis (`tests/conftest.py::login_as`).

---

## 12. Working Agreement

- Build in milestone order (`docs/IMPLEMENTATION_PLAN.md`, refined in the session brief): M1 DB + FastAPI foundation → M2 pipeline + IaC → M3 engines → M4 simulation/guardrails/response/audit → M5 frontend de-mocking. Stop after each milestone with a summary + test results and wait for confirmation.
- Non-trivial logic (scoring, detections, guardrail, executor, rollback, hash) ships with a pytest that fails if the logic breaks. AWS calls are tested with `botocore.stub.Stubber` or `moto` — never against real accounts from tests.
- Never weaken a constraint in §2–§3 to make something pass. If a requirement seems to need it, stop and ask.
- Update `docs/CHANGELOG.md` when a milestone lands.
