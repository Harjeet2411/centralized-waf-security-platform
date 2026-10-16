# Application Flow & Operational User Journeys
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17

---

## 1. Global Application Shell & Context Propagation

The React frontend (`WAF_PLATFORM/src/`) uses a persistent 4-zone operational layout designed so analysts never lose investigative context when pivoting across views:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ TOP BAR: Global Posture KPIs | Active Critical Alerts | Sync Status | [Refresh] │
├──────────────────────────────────────────────────────────────────────────────────┤
│ CONTEXT BAR: Breadcrumb Path | Active Account/Severity Filters | Workspace Tabs │
├────────────┬───────────────────────────────────────────────────┬─────────────────┤
│            │                                                   │                 │
│  SIDEBAR   │              MAIN OPERATIONAL VIEWPORT            │  SLIDE-OVER     │
│  (10 Core  │  (Command Center / Entities / WAF Security /      │  INVESTIGATION  │
│   Modules) │   Investigation / Detection / Simulation /        │  DRAWER         │
│            │   Response / Governance / Cost / Reports)         │  (Entity / Rule │
│            │                                                   │   Quick Pivot)  │
└────────────┴───────────────────────────────────────────────────┴─────────────────┘
```

### 1.1 Cross-View Pivot Mechanics
1. Clicking any **IP, ASN, JA3/JA4 fingerprint, or WebACL** in any table (`CommandCenter`, `WafSecurityPage`, `DetectionPage`) opens the right-hand **Slide-Over Drawer (`Drawer.tsx` / `EntityDetailPanel.tsx`)** without leaving the current page.
2. Clicking **"Open Full Investigation"** or **"Simulate Block"** in the Drawer appends a persistent tab to the **Context Bar (`ContextBar.tsx`)** and transitions the main viewport to `InvestigationPage` or `SimulationPage` with the target entity pre-loaded.

---

## 2. Manual & Scheduled Data Sync Flow

```
User clicks [Refresh] in TopBar
       │
       ▼
POST /api/v1/refresh
       │
       ├──► Is (NOW() - last_global_sync) < 60 minutes AND force == false?
       │         │
       │         └──► YES: Return HTTP 200 { "status": "ready", "last_sync": "..." }
       │                   Frontend displays "Data is current (<1h old)" toast.
       │
       └──► NO (Data is stale or force == true):
                 │
                 ├──► Acquire Redis lock `sync:global:lock` (TTL 300s)
                 ├──► Start AWS Step Functions execution `SAS-39Account-Sync`
                 ├──► Return HTTP 202 { "status": "syncing", "execution_arn": "..." }
                 │
                 ▼
       TopBar shows live progress bar via WebSocket `/ws/events`
       (e.g., "Syncing 24/39 accounts... Running JA4 correlation...")
                 │
                 ▼
       Step Functions completes → FastAPI broadcasts `SYNC_COMPLETED` over WebSocket
                 │
                 ▼
       React Query invalidates queries (`['bootstrap']`, `['entities']`, `['webacls']`)
       UI updates seamlessly without page reload.
```

---

## 3. Core User Journey 1: Investigating a "Malicious Allowed Traffic" Alert

1. **Alert Surface (`CommandCenter.tsx`)**:
   - The SOC Analyst logs in via AWS IAM Identity Center MFA and lands on the **Command Center**.
   - The **"Malicious Allowed Traffic"** banner highlights `142 ALLOWED requests` from high-risk entities targeting `prod-payments-alb` (Account: `prod-payments-04`).
2. **Entity Triage (`EntityDetailPanel.tsx`)**:
   - The analyst clicks IP `185.220.101.42` in the Priority Threat Queue.
   - The right-hand **Entity Detail Drawer** slides open, displaying:
     - **Threat Score**: $94/100$ | **Confidence**: $92\%$ (`FULL` log visibility) | **Business Impact**: $95/100$ | **Final Risk**: `CRITICAL`.
     - **Threat Intel Consensus**: AbuseIPDB ($98\%$ confidence), GreyNoise (`malicious`), VirusTotal ($14/90$ engines).
     - **WAF Behavior**: $1,240\text{ blocked}$ by `AWSManagedRulesSQLiRuleSet`, but $42\text{ allowed}$ on `/api/v2/checkout/validate`.
     - **TLS Fingerprint**: `JA4: t13d1516h2_8daaf6152771_b186095e22b6`.
3. **JA4 Campaign Pivot (`InvestigationPage.tsx` & `CampaignDetail.tsx`)**:
   - The analyst clicks the `JA4` hash badge.
   - The 2D D3.js Relationship Graph reveals that `t13d1516h2_8daaf6152771_b186095e22b6` is shared across **18 distinct IPs** spanning **4 ASNs** targeting 3 financial accounts (`prod-payments-04`, `prod-core-banking-01`, `prod-auth-02`), linked to Campaign `CMP-2026-089 (Coordinated SQLi & Checkout Probing)`.
   - The **Why Was It Allowed?** panel explains: *Rule `Custom-Checkout-RateLimit` in WebACL `prod-payments-waf` was switched from `BLOCK` to `COUNT` 4 hours ago (Drift Event `DRF-402`).*
4. **Rule Impact Simulation (`SimulationPage.tsx`)**:
   - The analyst clicks **"Simulate Response"** $\rightarrow$ selects **"Block JA4 / IP Set & Restore Rule to BLOCK"**.
   - The Simulator evaluates the proposed change against the last 24 hours of `waf_events` and reports:
     - **Would Block**: $4,820\text{ malicious requests}$ across 18 campaign IPs.
     - **Potential False Positives**: $0\text{ legitimate requests}$ affected ($0.00\%$ FP rate).
     - **Allow-List Check**: `PASSED` (0 protected partner/internal IPs matched).

---

## 4. Core User Journey 2: The 12-Step Controlled Response Lifecycle

Every infrastructure-changing operation enforces this exact state machine in the backend:

```
[1. DETECT] ──► [2. UNDERSTAND] ──► [3. CORRELATE] ──► [4. SCORE]
                                                           │
┌──────────────────────────────────────────────────────────┘
▼
[5. SIMULATE] ──► [6. CHECK GUARDRAILS] ──► [7. REQUEST APPROVAL]
                         │                           │
                         ▼ (If Protected IP)         ▼ (SNS + Email sent)
                  [HARD DENY: 403]            [8. APPROVE (MFA)]
                                                     │
┌────────────────────────────────────────────────────┘
▼
[9. EXECUTE (ResponseRole)] ──► [10. VERIFY (Re-read AWS)] ──► [11. AUDIT]
                                       │                            │
                                       ▼ (If drift/FP)              ▼
                                [12. 1-CLICK ROLLBACK] ◄────────────┘
```

### Step-by-Step Execution in UI (`ResponsePage.tsx` & `GovernancePage.tsx`):
1. **Request Creation**: From the Simulation results screen, the analyst clicks **"Request Approval"**, enters the business justification, selects `Temporary Block (TTL: 24 Hours)`, and submits `POST /api/v1/approvals`.
2. **Guardrail Verification**: FastAPI checks `allow_list_entries` using CIDR containment (`ip <<= cidr_block`). If the IP belongs to a payment gateway, internal NAT, or partner network, the request is immediately rejected with HTTP `403 Forbidden ("Protected Entity")`.
3. **Approval Queue**: A **Security Admin** receives an SNS/Email notification, opens **Response $\rightarrow$ Pending Approvals**, reviews the attached Simulation Report and Impact Analysis, and clicks **"Approve & Execute"**.
4. **Execution & Verification**:
   - The backend assumes `SASWafResponseRole` in `prod-payments-04`, snapshots the current IPSet into `changes.previous_state`, updates the IPSet, and records the `aws_request_id`.
   - The backend re-queries AWS WAFv2 to confirm the IP is active in the IPSet, transitions the change to `VERIFIED`, and writes an immutable entry to `audit_events`.
5. **Rollback (If Needed)**: At any time, an authorized Security Admin can click **"Rollback"** on the change record in `ResponsePage.tsx`, which restores `previous_state` using a fresh `LockToken` and audits the rollback.

---

## 5. Core User Journey 3: Unprotected Endpoint & Configuration Drift Governance

1. **Coverage Inspection (`WafSecurityPage.tsx`)**:
   - A Cloud Platform Engineer opens **WAF Security $\rightarrow$ WAF Coverage**.
   - The table highlights an internet-facing ALB `alb-public-onboarding-prod` in account `prod-onboarding-19` with `waf_status = 'UNPROTECTED'` (Risk: `CRITICAL`).
2. **Request-to-Attach Flow**:
   - The engineer clicks **"Request WAF Attachment"**, selects the standard regional WebACL `waf-regional-baseline-prod`, runs a Change Impact Check, and submits the approval request for joint **Security Admin + Application Owner** sign-off.
3. **Drift Remediation (`GovernancePage.tsx`)**:
   - In **Governance $\rightarrow$ Configuration Drift**, the engineer inspects `DRF-402` showing a `CRITICAL` diff (`expected_state: {"action": "BLOCK"}` vs. `actual_state: {"action": "COUNT"}`).
   - Clicking **"Remediate Drift"** pre-populates an approval request to restore the baseline rule action.