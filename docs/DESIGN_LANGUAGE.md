# Design Language & UI System Specification
## SAS Threat Intelligence & Centralized WAF Security Platform

- **Document Version:** 1.0.0
- **Date:** 2026-10-17
- **Aesthetic Direction:** High-Density 2D Investigation-First SOC Interface (Tactical Dark Mode)

---

## 1. Core Design Principles

1. **Evidence-First Telemetry**: Every score, KPI card, and risk badge must display its underlying evidence count and data source confidence (`FULL`, `PARTIAL`, `SAMPLED`, `NONE`) right next to the number.
2. **2D Investigation-First Density**: Security analysts triage dozens of IPs, JA4 hashes, and WebACL rules simultaneously. Avoid decorative 3D globes, oversized hero banners, or excessive whitespace. Prioritize scannable tabular density, monospace technical identifiers, and inline sparklines/bars.
3. **Zero-Ambiguity Semantic Color**: Color is reserved strictly for security severity, WAF action (`BLOCK`, `ALLOW`, `COUNT`), and visibility confidence.
4. **Slide-Over Contextual Continuity**: Never force a full-page navigation when an analyst clicks an entity or rule. Use the right-hand slide-over drawer (`Drawer.tsx`) for instant inspection.

---

## 2. Color System & Semantic Tokens

Derived from `WAF_PLATFORM/src/index.css` and Tailwind configuration:

### 2.1 Surface & Structural Palette
| Token | Hex Code | Tailwind Equivalent | Usage |
| :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#06090F` | `bg-[#06090F]` / `bg-slate-950` | Primary application background |
| `--bg-panel` | `#0B111E` | `bg-[#0B111E]` / `bg-slate-900/90` | Cards, tables, sidebar, topbar |
| `--bg-elevated` | `#111827` | `bg-gray-900` / `bg-slate-800/80` | Slide-over drawer, modals, hover rows |
| `--border-subtle` | `#1E293B` | `border-slate-800` | Default card and table row dividers |
| `--border-focus` | `#3B82F6` | `border-blue-500` | Active workspace tab, focused input |

### 2.2 Severity & Risk Palette
| Severity / State | Primary Hex | Badge Background | Badge Border | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL / BLOCK / MALICIOUS** | `#EF4444` | `bg-red-500/10` | `border-red-500/30` | Malicious Allowed traffic, Unprotected public ALB, Critical drift |
| **HIGH / SUSPICIOUS** | `#F97316` | `bg-orange-500/10` | `border-orange-500/30` | High-risk entities, Outdated managed rules, Credential attacks |
| **MEDIUM / COUNT / WARNING** | `#F59E0B` | `bg-amber-500/10` | `border-amber-500/30` | Rules in `COUNT` mode, Degraded account sync, Scanners |
| **LOW / INFO** | `#3B82F6` | `bg-blue-500/10` | `border-blue-500/30` | Informational telemetry, Low-severity drift |
| **HEALTHY / PROTECTED / ALLOW** | `#10B981` | `bg-emerald-500/10` | `border-emerald-500/30` | Protected endpoints, Verified changes, Legitimate traffic |
| **SAMPLED / CORRELATION (JA4)** | `#8B5CF6` | `bg-purple-500/10` | `border-purple-500/30` | `SAMPLED` visibility badge, JA3/JA4 fingerprint correlation |

---

## 3. Typography & Technical Formatting

- **Primary UI Font (`font-sans`)**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `sans-serif`
  - Page Headers: `text-lg font-semibold tracking-tight text-slate-100`
  - Section Headers: `text-xs font-semibold uppercase tracking-wider text-slate-400`
  - Body / Table Cells: `text-xs` or `text-sm text-slate-300`
- **Technical Telemetry Font (`font-mono`)**: `JetBrains Mono`, `Fira Code`, `monospace`
  - **Mandatory Monospace Elements**: All IPv4/IPv6 addresses, CIDR blocks, ASN numbers (`AS14061`), JA3/JA4 hashes (`t13d1516h2_...`), AWS Account IDs (`123456789012`), WebACL ARNs, HTTP URIs, and ISO-8601 timestamps.
  - Numeric columns must use `tabular-nums` (`font-variant-numeric: tabular-nums`) so request counts, percentages, and scores align vertically.

---

## 4. Mandatory Honesty & Confidence Badges (Rule #4)

Because 33 of the 39 AWS accounts use `GetSampledRequests` while 6 accounts use Full WAF Logs, every telemetry card and WebACL row must render a standardized **Visibility Pill**:

- **`FULL LOGS` (`bg-emerald-500/10 text-emerald-400 border-emerald-500/30`)**: 100% request capture via S3 WAF logs + CloudWatch metrics.
- **`SAMPLED` (`bg-purple-500/10 text-purple-400 border-purple-500/30`)**: Up to 500 sampled requests per rule metric per 30m window + 100% CloudWatch metric totals. Tooltip must state: *"Request payloads are sampled via AWS GetSampledRequests; aggregate block/allow counts are exact via CloudWatch Metrics."*
- **`METRICS ONLY` (`bg-amber-500/10 text-amber-400 border-amber-500/30`)**: CloudWatch metrics only; request-level sampling disabled on rules.
- **`UNAVAILABLE` (`bg-red-500/10 text-red-400 border-red-500/30`)**: Cross-account role unreachable or API throttled.

---

## 5. Interactive Visualization Specifications

### 5.1 2D D3.js Relationship Graph (`InvestigationPage.tsx`)
- **Node Types & Shapes**:
  - `IP`: Circle (`r = 14px`), colored by Risk Level (`CRITICAL` red, `HIGH` orange).
  - `JA4`: Hexagon / Diamond (`#8B5CF6` purple), highlighting shared TLS fingerprints across IPs.
  - `ASN / Organization`: Rounded Rectangle (`#3B82F6` blue).
  - `Application / Endpoint`: Shield / Square (`#10B981` emerald if protected, `#EF4444` red dashed ring if unprotected or experiencing Malicious Allowed traffic).
- **Edge Encoding**:
  - Solid red edge: `MALICIOUS_ALLOWED` request path.
  - Dashed slate edge: `BLOCKED` request path.
  - Purple pulsing edge: `JA4_CORRELATION` link.

### 5.2 Attack Timeline & Approval Stepper
- **Horizontal Lifecycle Stepper (`ResponsePage.tsx`)**: Displays the 12-step Approval Lifecycle with completed steps in emerald (`#10B981`), the active step pulsing in blue (`#3B82F6`), and blocked guardrail steps in red (`#EF4444`).