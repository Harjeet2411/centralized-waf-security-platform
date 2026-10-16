# Changelog
## SAS Threat Intelligence & Centralized WAF Security Platform

All notable architectural, schema, and application changes to the SAS Threat Intelligence Platform are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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