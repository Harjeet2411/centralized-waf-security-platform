"""Response models mirroring WAF_PLATFORM/src/types/index.ts (the wire contract, CLAUDE.md section 8).

Field names are snake_case exactly as in the TS interfaces; enum values are translated from the DB's
uppercase CHECK values to the TS lowercase unions by the mappers below - never in components.
Fields marked "contract+" are additive (not yet in index.ts) and carry Rule #4 visibility honesty or raw
values the TS unions can't express; index.ts gains them in Milestone 5.
"""

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict

# --- enum value mappers (DB -> TS) ------------------------------------------------------------------

ACCOUNT_ENV = {
    "production": "prod", "staging": "uat", "development": "dev",
    "shared-services": "shared", "security": "shared",
}
ENDPOINT_TYPE = {"ALB": "ALB", "CLOUDFRONT": "CloudFront", "APIGW": "APIGW"}
ENTITY_TYPE = {
    "IP": "ip", "ASN": "asn", "COUNTRY": "country", "ORG": "org", "JA3": "ja3", "JA4": "ja4",
    "USER_AGENT": "ua", "URI_PATTERN": "uri",
}
RISK_LEVEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "none"}
DETECTION_TYPE = {
    "SCANNER": "scanner", "CREDENTIAL_ATTACK": "credential_attack", "DISTRIBUTED_ATTACK": "distributed_attack",
    "SLOW_DISTRIBUTED": "slow_distributed", "BOT_AUTOMATION": "bot_automation", "SQLI_CAMPAIGN": "sql_injection",
    "MALICIOUS_ALLOWED": "malicious_allowed", "JA4_CORRELATION": "ja4_campaign",
}
DETECTION_STATUS = {
    "OPEN": "new", "INVESTIGATING": "investigating", "PENDING_APPROVAL": "actioned", "MITIGATED": "actioned",
}
CAMPAIGN_STATUS = {"ACTIVE": "active", "INVESTIGATING": "active", "MITIGATED": "monitoring", "RESOLVED": "resolved"}
DRIFT_STATUS = {"OPEN": "open", "ACKNOWLEDGED": "acknowledged", "REMEDIATING": "acknowledged", "RESOLVED": "resolved"}
APPROVAL_STATUS = {
    "PENDING": "pending", "APPROVED": "approved", "REJECTED": "rejected", "EXECUTED": "executing",
    "VERIFIED": "completed", "ROLLED_BACK": "rolled_back", "EXPIRED": "completed",
}
LIFECYCLE_STAGE = {
    "PENDING": "approval", "APPROVED": "execution", "REJECTED": "approval", "EXECUTED": "verification",
    "VERIFIED": "audit", "ROLLED_BACK": "audit", "EXPIRED": "audit",
}
TI_SOURCE = {
    "AbuseIPDB": "abuseipdb", "GreyNoise": "greynoise", "VirusTotal": "virustotal",
    "GuardDuty": "guardduty", "Internal": "internal",
}


def lower(value: str | None, default: str = "unknown") -> str:
    return value.lower() if value else default


def confidence_band(score: Decimal | float | None) -> str:
    """Numeric 0-100 confidence -> TS Confidence. Default bands per CLAUDE.md section 8."""
    value = float(score or 0)
    if value >= 80:
        return "high"
    if value >= 50:
        return "medium"
    if value > 0:
        return "low"
    return "none"


def iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


# --- models ---------------------------------------------------------------------------------------

VisibilityLevel = Literal["full", "sampled", "metrics", "none"]
ScoreConfidence = Literal["FULL", "PARTIAL", "SAMPLED", "NONE"]
HealthStatus = Literal["healthy", "degraded", "unavailable"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AWSAccountOut(Contract):
    id: str
    account_id: str
    name: str
    environment: Literal["prod", "uat", "dev", "shared"]
    owner: str
    status: HealthStatus
    last_discovered: str
    waf_coverage: float
    security_score: float
    endpoint_count: int
    webacl_count: int
    logging_visibility: VisibilityLevel
    region: str
    score_confidence: ScoreConfidence  # contract+
    regions: list[str]  # contract+


class EndpointOut(Contract):
    id: str
    account_id: str
    account_name: str
    name: str
    type: Literal["ALB", "CloudFront", "APIGW"]
    dns_name: str
    internet_facing: bool
    waf_enabled: bool
    waf_arn: str | None
    logging_enabled: bool
    status: Literal["protected", "partially_protected", "unprotected", "unknown"]
    region: str
    visibility_level: VisibilityLevel  # contract+


class WebACLOut(Contract):
    id: str
    account_id: str
    account_name: str
    name: str
    arn: str
    scope: Literal["REGIONAL", "CLOUDFRONT"]
    default_action: Literal["BLOCK", "ALLOW"]
    security_score: float
    managed_rule_health: float
    drift_count: int
    rule_count: int
    logging_enabled: bool
    region: str
    score_confidence: ScoreConfidence  # contract+
    visibility_level: VisibilityLevel  # contract+
    score_evidence: dict  # contract+ (Rule #1)


class WafRuleOut(Contract):
    id: str
    webacl_id: str
    name: str
    type: Literal["managed", "custom"]
    action: Literal["BLOCK", "ALLOW", "COUNT", "CAPTCHA", "CHALLENGE"]  # TS lacks CAPTCHA/CHALLENGE (M5)
    priority: int
    managed_group: str | None
    managed_version: str | None
    latest_version: str | None
    match_count: int
    blocked: int
    counted: int
    allowed: int
    false_positives: int
    effectiveness: float
    scope_down: str | None
    rate_limit: int | None
    version_status: Literal["current", "outdated", "deprecated", "unknown"]
    last_modified: str
    rule_type: Literal["MANAGED", "CUSTOM", "RATE_BASED", "IP_SET"]  # contract+ (TS type is lossy)


class ThreatIntelOut(Contract):
    source: Literal["abuseipdb", "greynoise", "virustotal", "guardduty", "internal"]
    score: float
    classification: str
    confidence: Literal["high", "medium", "low", "none"]
    timestamp: str
    expires_at: str


class EntityOut(Contract):
    id: str
    type: Literal["ip", "asn", "country", "org", "ja3", "ja4", "ua", "uri"]
    value: str
    label: str
    threat_score: float
    confidence: Literal["high", "medium", "low", "none"]
    risk_level: Literal["critical", "high", "medium", "low", "none"]
    country: str | None
    asn: str | None
    organization: str | None
    ja3: str | None
    ja4: str | None
    user_agent: str | None
    first_seen: str
    last_seen: str
    request_count: int
    uri_diversity: int
    not_found_ratio: float
    applications: list[str]
    webacls: list[str]
    campaigns: list[str]
    techniques: list[str]
    threat_intel: list[ThreatIntelOut]
    confidence_score: float  # contract+
    business_impact: float  # contract+
    final_risk: float  # contract+
    classification: str  # contract+
    is_allow_listed: bool  # contract+


class CampaignOut(Contract):
    id: str
    name: str
    type: str
    risk_level: Literal["critical", "high", "medium", "low", "none"]
    confidence: Literal["high", "medium", "low", "none"]
    first_seen: str
    last_seen: str
    ip_count: int
    asn_count: int
    country_count: int
    ja4_count: int
    application_count: int
    webacl_count: int
    account_count: int
    technique_count: int
    waf_action_breakdown: dict[Literal["BLOCK", "ALLOW", "COUNT"], int]
    description: str
    status: Literal["active", "monitoring", "resolved", "suppressed"]
    campaign_code: str  # contract+
    recommended_action: str  # contract+


class DetectionEvidenceOut(Contract):
    type: str
    label: str
    value: str
    detail: str | None = None


class DetectionOut(Contract):
    id: str
    type: str
    severity: Literal["critical", "high", "medium", "low", "healthy", "unknown"]
    title: str
    description: str
    timestamp: str
    entity_ids: list[str]
    campaign_id: str | None
    evidence_count: int
    confidence: float
    affected_apps: list[str]
    affected_accounts: list[str]
    status: Literal["new", "investigating", "correlated", "actioned", "false_positive"]
    evidence: list[DetectionEvidenceOut]
    recommended_action: str  # contract+


class ApprovalImpactOut(Contract):
    affected_accounts: int
    affected_webacls: int
    affected_apps: int
    potential_fp: int
    security_gain: str
    fp_risk: str


class ApprovalOut(Contract):
    id: str
    action_type: str
    target: str
    reason: str
    status: Literal["pending", "approved", "rejected", "executing", "completed", "failed", "rolled_back"]
    requested_by: str
    requested_at: str
    approver: str | None
    approved_at: str | None
    simulation_result: str | None
    impact: ApprovalImpactOut
    lifecycle_stage: str
    approval_code: str  # contract+
    status_detail: str  # contract+ raw DB status (e.g. EXPIRED)
    risk_level: str  # contract+
    allow_list_check: str  # contract+
    verification_status: str | None  # contract+
    aws_request_id: str | None  # contract+
    required_approver_role: str  # contract+
    expires_at: str | None  # contract+


class DriftEventOut(Contract):
    id: str
    webacl_id: str
    webacl_name: str
    account_id: str
    drift_type: str
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    expected: str
    actual: str
    detected_at: str
    status: Literal["open", "acknowledged", "resolved", "suppressed"]
    drift_code: str  # contract+


class ComponentHealthOut(Contract):
    status: HealthStatus
    detail: str
    last_check: str


class CollectorHealthOut(Contract):
    account_id: str
    account_name: str
    status: HealthStatus
    last_success: str
    error: str | None
    affected_modules: list[str]


class PlatformHealthOut(Contract):
    overall: Literal["healthy", "degraded", "critical"]
    collectors: list[CollectorHealthOut]
    aws_api: ComponentHealthOut
    queue: ComponentHealthOut
    workers: ComponentHealthOut
    database: ComponentHealthOut
    threat_intel: ComponentHealthOut
    last_sync: str
    data_freshness: str


class BootstrapOut(Contract):
    accounts: list[AWSAccountOut]
    endpoints: list[EndpointOut]
    webacls: list[WebACLOut]
    rules: dict[str, list[WafRuleOut]]
    entities: list[EntityOut]
    campaigns: list[CampaignOut]
    detections: list[DetectionOut]
    drift_events: list[DriftEventOut]
    approvals: list[ApprovalOut]
    platform_health: PlatformHealthOut
    # Security posture dimensions are produced by the scoring engine (Milestone 3); empty until then.
    posture_dimensions: list[dict]
    generated_at: str


class PrincipalOut(Contract):
    user_id: str
    email: str
    full_name: str
    role: str
    permissions: list[str]
    scoped_account_ids: list[str]
    mfa: bool
