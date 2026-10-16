# Changelog
## SAS Threat Intelligence & Centralized WAF Security Platform

All notable architectural, schema, and application changes to the SAS Threat Intelligence Platform are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] - Account & User Registry
### Added
- Governance API (Security Admin / `MANAGE_USERS` only): `GET/POST /api/v1/governance/accounts`, `PATCH /api/v1/governance/accounts/{account_id}`, `GET/POST /api/v1/governance/users`, `PATCH /api/v1/governance/users/{id}`. Role ARNs default to the StackSet roles and must belong to the registered account; scoped accounts must exist; the last active Security Admin can't be deactivated or demoted; every write is audited (`ACCOUNT_REGISTERED`, `ACCOUNT_UPDATED`, `USER_PROVISIONED`, `USER_UPDATED`, `USER_DEACTIVATED`).
- Per-user session index (`session:index:{user_id}`): role, scope or active-flag changes revoke all of that user's sessions immediately.
- Bootstrap CLI `python -m app.cli create-admin | register-accounts` (first admin only once; CSV import idempotent; audited as `cli@sas-platform.internal`).
- 10 tests (RBAC, validation, audit, revocation, lock-out guard, CLI).

## [Unreleased] - Milestone 6: Central Account Infrastructure & Lambda Packaging
### Added
- `infra/central_account/platform.yaml`: VPC 10.240.0.0/16 (public / private-app / isolated data tiers, single-AZ NAT), 5 interface endpoints (sts, wafv2, monitoring, logs, states; 1 or 2 AZs) + free S3 gateway endpoint, KMS CMK, RDS PostgreSQL 16 Multi-AZ (encrypted, deletion-protected, secret in the format `lambdas/common/db.py` reads), Redis 7 (TLS + at-rest), generated discovery/response external IDs, TI and OIDC secrets, ECR, WAF-log staging bucket (`aws-waf-logs-*`, replication policy for the logging accounts, 30-day expiry, ingestor trigger), 7-year COMPLIANCE Object Lock audit archive, SNS approvals topic, the 7 pipeline Lambdas (`SASLambdaCollectorExecutionRole` for the collector), the sync state machine with DefinitionSubstitutions and the 30-minute / 6-hour EventBridge schedules.
- `infra/central_account/app.yaml`: FastAPI on ECS Fargate (read-only root FS, task role `SASFastAPIResponseExecutorRole`), ALB that only forwards CloudFront-verified requests, AWS WAF on the ALB, SPA on private S3 via CloudFront OAC with an SPA-routing function, TTL-expiry worker as a 5-minute scheduled task.
- `backend/Dockerfile` (non-root, read-only-FS ready; same image for API, TTL worker and migrations); backend builds `database_url` from `SAS_DB_HOST/USER/PASSWORD` injected by ECS.
- `lambdas/build.py`: one zip per function with Linux x86_64 wheels (verified importing in the official Lambda python3.12 image).
- `infra/README.md`: deploy order (pilot accounts first) and a monthly cost table - ~$407 on-demand, ~$345 with a 1-year RDS reservation; the spec's estimate under-counted interface endpoints, public IPv4, platform WAF and Fargate.
- 13 IaC/build tests (role names vs StackSet trust, ASL substitutions, schedules, encryption, public-access blocks, Object Lock, CloudFront-only ALB, TTL worker wiring).

## [Unreleased] - Milestone 4: Simulation, Guardrails, Controlled Response & Audit
### Added
- Migration `0003`: `approval_decisions` (multi-person approvals), `changes.rollback_available`, and the `trg_approvals_allow_list` trigger that refuses any IP-block approval overlapping an active allow-list CIDR (checks `target` and every `proposed_state.add` entry).
- Guardrails: server-side allow-list check (GiST `&&`) at request and approval time; block-target rails (/24 v4, /64 v6, public ranges only); denials audited as `GUARDRAIL_DENIED`.
- Rule Impact Simulator (`POST /api/v1/simulations`): BLOCK_IPS, BLOCK_JA4, RULE_ACTION, RATE_LIMIT over historical `waf_events` with would-block / false-positive / allow-list results and visibility caveats; False Positive Analyzer (`GET /api/v1/simulations/false-positives`).
- Controlled Response Engine: `POST /api/v1/approvals`, `GET /api/v1/approvals[/{id}]` (with the 12-step lifecycle state), `POST /api/v1/approvals/{id}/decide`. Tiered policies, no self-approval, one slot per person, MFA sessions, SNS notifications (best effort).
- AWS executor via `SASWafResponseRole` (approval code session tag + approver SourceIdentity): IP set add/remove, rule action, rate limit, managed-rule exception, restore removed rule, enable logging, associate WebACL. Every write uses the LockToken, captures the AWS RequestId, waits, re-reads and verifies; unverified changes are never reported as success.
- Rollback (`POST /api/v1/changes/{id}/rollback`) by inverse operation; TTL auto-expiry worker (`python -m app.workers.ttl_expiry`) with EXPIRING/REMOVED states; verified WebACL changes move the drift baseline.
- Allow-list management (`/api/v1/allow-list`, deactivation Security Admin only), active blocks, change list, and audit export (`GET /api/v1/governance/audit?format=csv|json`).
- 27 new backend tests (lifecycle end-to-end on a stateful fake WAFv2, botocore Stubber request-shape pins, DB trigger bypass attempts, RBAC/scope/MFA denials).
### Fixed
- `approvals.allow_list_check` widened to VARCHAR(32): the spec's VARCHAR(16) could never store `BLOCKED_PROTECTED_ENTITY`.
- Audit rows written in the same transaction now keep their order (`clock_timestamp()`).

## [Unreleased] - Milestone 3: Detection, Correlation, Drift, Scoring & Threat Intel
### Added
- Migration `0002`: `web_acls.current_config`, `accounts.score_evidence`, `waf_events.ingested_at`, `detections.fingerprint`, `engine_state` (per-engine watermarks).
- `lambdas/common/scoring.py`: the 7-dimension WAF Security Score and entity T/C/B/R models as pure, unit-tested functions.
- `drift_scoring_engine`: baseline-vs-current WebACL diff (BLOCK->COUNT downgrades, removed rules, default action, logging disabled, association removed, outdated/deprecated managed versions); idempotent drift codes with resolve/re-open; per-WebACL and per-account scores with per-dimension evidence and honest confidence (FULL / PARTIAL / SAMPLED / NONE).
- `detection_campaign_engine`: watermark-based entity folding (IP, JA4, JA3, ASN, User-Agent) and relationships; entity scoring with TI, JA4 malice, campaign membership, business impact and allow-list awareness; JA4 campaigns with evidence-based attack stories; SCANNER, CREDENTIAL_ATTACK, DISTRIBUTED_ATTACK, SLOW_DISTRIBUTED, MALICIOUS_ALLOWED and JA4_CORRELATION detections (deduplicated by fingerprint); event classification.
- `ti_enrichment_worker`: AbuseIPDB / GreyNoise / VirusTotal with Redis 24h cache, per-provider daily budgets, private/allow-listed IPs never sent out, graceful degradation reported in platform health.
- Step Functions post-sync engines now run in order TI -> detection -> drift/scoring, each failure-isolated.
- API: `GET /api/v1/webacls`, `/endpoints`, `/entities` (filter + paginate), `/entities/{id}` (graph, timeline, recent events, "why was it allowed?"), `/campaigns`, `/campaigns/{id}`; bootstrap `posture_dimensions` from account score evidence.
### Fixed
- Engine watermarks use the DB clock with a configurable lag (`SAS_WATERMARK_LAG_SECONDS`, default 120s) so host/DB clock skew and in-flight ingest transactions can't drop events.

## [Unreleased] - Milestone 2: Cross-Account Serverless Data Pipeline
### Added
- `infra/stacksets/cross-account-waf-roles.yaml` (cfn-lint clean): read-only `SASWafDiscoveryRole` (ExternalId trust) and `SASWafResponseRole` (ExternalId + `sas:approval-id` session tag + approver `SourceIdentity`; explicit deny on WAF deletes, `iam:*`, `organizations:*`, `s3:Delete*`, role chaining, `cloudfront:UpdateDistribution`).
- `infra/central_account/step_functions.asl.json`: fetch -> Map (`MaxConcurrency: 20`, throttling retry 2s/x4/2.5 + Catch on the per-account task) -> post-sync engines (M3 targets).
- `lambdas/account_collector`: ALB / REST API stage / CloudFront discovery with WAF coverage (`PROTECTED`, `PARTIALLY_PROTECTED` = attached but nothing enforces, `UNPROTECTED`, `UNKNOWN`), WebACL rule trees, managed rule version status, per-rule-metric `GetSampledRequests` with SHA-256 dedup, exact 24h CloudWatch totals, per-account health. Idempotent; partial failures mark the account `DEGRADED` with evidence.
- `lambdas/s3_log_ingestor`: streams gzip WAF logs (native JA3/JA4) into `waf_events` as `FULL_LOG`; redelivery-safe.
- `lambdas/fetch_accounts`, `lambdas/mark_account_degraded`; shared `lambdas/common` (psycopg DB, STS/throttle mapping, event normalization).
- 27 Lambda/IaC tests (real Postgres, botocore Stubber request-shape pins, IAM least-privilege assertions, ASL graph checks).

## [Unreleased] - Milestone 1: Database Layer & FastAPI Control Plane
### Added
- `backend/` FastAPI control plane (Python 3.12): settings with deploy-time guards (no insecure cookies / MFA bypass outside local/test), async SQLAlchemy 2.0 engine, `redis.asyncio` client, `/healthz`.
- Alembic migration `0001`: the full `BACKEND_SCHEMA.md` DDL (20 tables) plus `platform_health`, `detections.description`, a `TRUNCATE` guard on `audit_events`, and the 8-role RBAC seed. ORM models mirror it, and a test asserts the two never drift.
- RBAC: role grants loaded from `roles` on every request, qualified grants (`APPROVE:TEMP_BLOCK`, `INVESTIGATE:SCOPED`, …) and `require(permission)` dependency.
- Auth: OIDC authorization-code + PKCE against the IdP fronting IAM Identity Center; `amr` MFA enforcement; no auto-provisioning; Redis server-side sessions (`session:user:{id}`, 8h) in an `HttpOnly; SameSite=Strict` cookie; immediate revocation on user deactivation.
- `GET /api/v1/bootstrap` and `GET /api/v1/me`: Pydantic contract models mirroring `WAF_PLATFORM/src/types/index.ts` (snake_case, DB→TS enum mapping), all values from SQL with no synthetic data.
- `docker-compose.yml` (Postgres 16 on host port 5433, Redis 7) and 48 pytest tests against real Postgres/Redis.

---

## [1.0.0] - 2026-10-17
### Added
- **Production Specification Suite**:
  - Added `docs/PRD.md` defining the 9 core security questions, 8 RBAC roles, mathematical scoring formulas ($S_{\text{WAF}}$ and $R_{\text{entity}}$), and 22 functional requirements.
  - Added `docs/TRD.md` detailing the Central Security Account VPC topology, 5 private VPC Interface Endpoints, cross-account `SASWafDiscoveryRole` and MFA-enforced `SASWafResponseRole`, and Step Functions 39-account parallel fan-out state machine.
  - Added `docs/APP_FLOW.md` documenting the 4-zone SOC UI navigation model, $< 1\text{h}$ smart manual refresh flow, JA4 campaign pivot workflow, and the 12-step Controlled Response state machine.
  - Added `docs/DESIGN_LANGUAGE.md` codifying the tactical dark-mode color tokens, monospace telemetry rules, 2D D3.js graph conventions, and mandatory `FULL` / `SAMPLED` visibility honesty badges.
  - Added `docs/BACKEND_SCHEMA.md` containing the complete PostgreSQL 16 DDL for all 19 core tables, GIN/GiST indexes, append-only `audit_events` trigger, Redis keyspace design, and FastAPI REST/WebSocket contracts.
  - Added `docs/IMPLEMENTATION_PLAN.md` outlining the 24-week, 5-phase rollout from 5 pilot accounts to all 39 production AWS accounts and the retirement of `src/data/mockData.ts`.
- **Multi-Rule `GetSampledRequests` Collection Architecture**:
  - Designed per-rule metric iteration (`WebACL.VisibilityConfig.MetricName` + `Rules[].VisibilityConfig.MetricName`) with SHA-256 request deduplication so the 33 non-logging accounts achieve maximum sampled request coverage every 30 minutes without a centralized WAF data lake.

---

## [0.5.0] - 2026-10-11
### Added
- **Master Specification (`WAF_PLATFORM_SPEC.md`)**:
  - Established hard architectural constraints: no AWS Firewall Manager, no AWS Shield Advanced, no centralized WAF data lake, no autonomous AI infrastructure changes, and a $\le \$350\text{/month}$ infrastructure budget.
  - Defined the 39-account scope (6 accounts with full S3 WAF logs; 33 accounts with sampled requests and CloudWatch metrics).
  - Defined the 12-step approval lifecycle (`DETECT` $\rightarrow$ `ROLLBACK`).

---

## [0.1.0] - 2026-10-01
### Added
- **Initial Frontend Application (`WAF_PLATFORM`)**:
  - Built Vite + React 19 + TypeScript + Tailwind CSS + Zustand operational UI shell.
  - Implemented 10 core operational views: `CommandCenter`, `ThreatIntelligencePage`, `EntitiesPage` + `EntityDetailPanel`, `WafSecurityPage`, `InvestigationPage` + `CampaignDetail`, `DetectionPage`, `SimulationPage`, `ResponsePage`, `GovernancePage`, `CostPage`, and `ReportsPage`.
  - Implemented persistent `TopBar`, `ContextBar` with workspace tabs, collapsible `Sidebar`, and slide-over `Drawer`.