# Production Implementation & Migration Plan
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17
- **Rollout Strategy:** 5 Pilot Accounts First $\rightarrow$ 39 Production Accounts

---

## 1. Repository & Directory Structure

To transition your existing `WAF_PLATFORM` frontend and build out the backend and serverless pipeline cleanly, organize the monorepo as follows:

```
sas-waf-platform/
├── frontend/                        # Your existing WAF_PLATFORM Vite + React + TS app
│   ├── src/
│   │   ├── api/
│   │   │   ├── client.ts            # Fetch wrapper + WebSocket client
│   │   │   └── hooks.ts             # @tanstack/react-query hooks replacing mockData.ts
│   │   ├── components/              # Existing 10 modules (CommandCenter, Entities, etc.)
│   │   ├── store.ts                 # Zustand store (UI state + API hydration)
│   │   └── types/index.ts           # Existing shared TypeScript interfaces
├── backend/                         # FastAPI Control Plane
│   ├── app/
│   │   ├── main.py                  # FastAPI app, CORS, WebSocket manager
│   │   ├── config.py                # Settings (RDS, Redis, Secrets Manager ARNs)
│   │   ├── database.py              # Async SQLAlchemy engine & session
│   │   ├── models/                  # SQLAlchemy 2.0 models (19 tables)
│   │   ├── schemas/                 # Pydantic v2 request/response models
│   │   ├── api/v1/                  # Routers (bootstrap, entities, waf, approvals, etc.)
│   │   ├── services/
│   │   │   ├── guardrail_service.py # Server-side Allow-List CIDR verification
│   │   │   ├── simulator_service.py # Historical waf_events impact simulator
│   │   │   ├── aws_executor.py      # AssumeRole(ResponseRole) + LockToken + Verify
│   │   │   └── rbac_service.py      # 8-role permission enforcement
│   └── alembic/                     # Database migrations
├── lambdas/                         # Serverless Data Pipeline Functions
│   ├── account_collector/           # Per-account Discovery + GetSampledRequests + Metrics
│   ├── s3_log_ingestor/             # Full WAF log parser for 6 logging accounts
│   ├── detection_campaign_engine/   # JA3/JA4 correlation + behavioral detections
│   ├── drift_scoring_engine/        # Config drift diffing + 0-100 Security Score
│   └── ti_enrichment_worker/        # Redis-cached AbuseIPDB, GreyNoise, VirusTotal
└── infra/                           # Terraform / CloudFormation IaC
    ├── central_account/             # VPC, RDS, Redis, ALB, Step Functions, EventBridge
    └── stacksets/                   # Cross-account DiscoveryRole & ResponseRole YAML
```

---

## 2. Frontend De-Mocking Plan (Replacing `src/data/mockData.ts`)

Your frontend (`WAF_PLATFORM`) already has `@tanstack/react-query` installed in `package.json` and all 10 UI views wired to `usePlatformStore` in `src/store.ts`.

### Step 2.1: Create `src/api/client.ts`
Replace the static imports from `./data/mockData` in `src/store.ts` with live API hydration:
1. **`GET /api/v1/bootstrap`**: Hydrates `accounts`, `endpoints`, `webAcls`, `rules`, `entities`, `campaigns`, `detections`, `approvals`, `auditEvents`, `driftEvents`, `simulations`, `platformHealth`, and `securityPosture`.
2. **Action Mutations in `src/store.ts`**:
   - `approveRequest(id)` $\rightarrow$ calls `POST /api/v1/approvals/${id}/decide` (`{ decision: 'APPROVE' }`). Only updates state to `VERIFIED` after the backend confirms AWS WAFv2 convergence.
   - `rejectRequest(id)` $\rightarrow$ calls `POST /api/v1/approvals/${id}/decide` (`{ decision: 'REJECT' }`).
   - `rollbackChange(id)` $\rightarrow$ calls `POST /api/v1/changes/${id}/rollback`.
   - `createApprovalRequest(...)` $\rightarrow$ calls `POST /api/v1/approvals` (enforcing server-side `allow_list_entries` validation).
   - `triggerRefresh()` $\rightarrow$ calls `POST /api/v1/refresh` and listens to `/ws/events` for live Step Functions completion.

---

## 3. Phased Execution Roadmap (24 Weeks)

### Phase 1: Foundation & 5-Account Pilot (Weeks 1–4)
- **Week 1**: Provision Central Security Account VPC, Multi-AZ RDS PostgreSQL, ElastiCache Redis, and 5 VPC Interface Endpoints (`sts`, `wafv2`, `monitoring`, `logs`, `states`).
- **Week 2**: Deploy `SASWafDiscoveryRole` and `SASWafResponseRole` via CloudFormation StackSet to **5 pilot accounts** (including 1 account with full S3 WAF logging and 4 accounts with `GetSampledRequests`).
- **Week 3**: Deploy `sas-account-collector` Lambda and Step Functions Map state machine. Verify 30-minute `GetSampledRequests` polling and 6-hour full discovery across ALBs, CloudFronts, and API Gateways.
- **Week 4**: Deploy FastAPI backend + IAM Identity Center SSO/MFA integration. Connect `WAF_PLATFORM` React frontend to `/api/v1/bootstrap` and `/api/v1/refresh`. Scale StackSet from 5 pilot accounts to all **39 AWS accounts**.

### Phase 2: WAF Governance, Scoring & Drift (Weeks 5–8)
- **Week 5**: Implement the 7-dimension WAF Security Score Engine ($S_{\text{WAF}}$) and explicit Confidence Level badges (`FULL`, `PARTIAL`, `SAMPLED`, `NONE`).
- **Week 6**: Implement Managed Rule Version Tracking (`ListAvailableManagedRuleGroupVersions`) across all 39 accounts.
- **Week 7**: Build the Configuration Drift Engine comparing live WebACL JSON trees against `web_acls.baseline_config`.
- **Week 8**: Enable the "Request to Attach WAF" approval workflow for unprotected internet-facing endpoints.

### Phase 3: Threat Intelligence, JA3/JA4 & Campaign Engine (Weeks 9–12)
- **Week 9**: Integrate AbuseIPDB, GreyNoise, and VirusTotal APIs in `ti_enrichment_worker` with 24-hour Redis caching and graceful degradation.
- **Week 10**: Build the Entity Intelligence aggregator (`IP`, `ASN`, `JA3`, `JA4`, `Organization`, `User-Agent`) and populate `entity_relationships`.
- **Week 11**: Implement the JA3/JA4 Correlation Engine and the 5 Behavioral Detection rules (`SCANNER`, `CREDENTIAL_ATTACK`, `DISTRIBUTED_ATTACK`, `SLOW_DISTRIBUTED`, `MALICIOUS_ALLOWED`).
- **Week 12**: Connect the 2D D3.js Relationship Graph and automated Attack Story generator in `InvestigationPage.tsx` and `CampaignDetail.tsx`.

### Phase 4: Controlled Response, Guardrails & Audit (Weeks 13–18)
- **Week 13**: Populate `allow_list_entries` with all internal NAT gateways, partner CIDRs, payment gateways, and health-check IPs. Enable the server-side guardrail interceptor.
- **Week 14**: Build the Tiered Approval Policy Engine and SNS/Email notification dispatcher.
- **Week 15**: Implement `aws_executor.py` with `SASWafResponseRole` assumption, `LockToken` optimistic locking, and post-change AWS state verification.
- **Week 16**: Implement the TTL Auto-Expiry cron Lambda for temporary IP blocks.
- **Week 17**: Implement the 1-Click Rollback Engine using `changes.previous_state_json`.
- **Week 18**: Verify append-only immutability on `audit_events` and conduct end-to-end red-team/blue-team approval lifecycle testing.

### Phase 5: Simulation, Cost & Executive Readiness (Weeks 19–24)
- **Week 19–20**: Build the Rule Impact Simulator and False Positive Analyzer against historical `waf_events`.
- **Week 21**: Complete the AST-backed Query Builder in `/api/v1/investigation/query`.
- **Week 22**: Build the AWS Cost Explorer / WCU estimator for `CostPage.tsx` and PDF/CSV report generators for `ReportsPage.tsx`.
- **Week 23–24**: Chaos testing (simulate STS failure, WAF API throttling, TI provider outage), penetration testing, and production sign-off against all 16 Acceptance Criteria.