// Wire contract with the FastAPI backend (backend/app/schemas/contract.py). Field names are snake_case exactly as
// served; backend/tests/test_bootstrap_contract.py fails if any interface field below is not served.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'healthy' | 'unknown';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';
export type Confidence = 'high' | 'medium' | 'low' | 'none';
export type VisibilityLevel = 'full' | 'sampled' | 'metrics' | 'none';
export type ScoreConfidence = 'FULL' | 'PARTIAL' | 'SAMPLED' | 'NONE';
export type AccountEnv = 'prod' | 'uat' | 'dev' | 'shared';
export type EntityType = 'ip' | 'asn' | 'country' | 'org' | 'ja3' | 'ja4' | 'ua' | 'uri' | 'application' | 'account' | 'webacl' | 'rule';
export type WafAction = 'BLOCK' | 'ALLOW' | 'COUNT';
export type RuleAction = WafAction | 'CAPTCHA' | 'CHALLENGE';
export type EndpointType = 'ALB' | 'CloudFront' | 'APIGW';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executing' | 'completed' | 'failed' | 'rolled_back';
export type DriftSeverity = 'critical' | 'high' | 'medium' | 'low';
export type DetectionType = 'scanner' | 'credential_attack' | 'distributed_attack' | 'sql_injection' | 'bot_automation' | 'malicious_allowed' | 'ja4_campaign' | 'slow_distributed';
export type AttackPhaseName = 'reconnaissance' | 'endpoint_discovery' | 'credential_attempts' | 'sqli_probing' | 'distributed_campaign' | 'malicious_allowed';
export type HealthStatus = 'healthy' | 'degraded' | 'unavailable';

export interface AWSAccount {
  id: string;
  account_id: string;
  name: string;
  environment: AccountEnv;
  owner: string;
  status: HealthStatus;
  last_discovered: string;
  waf_coverage: number;
  security_score: number;
  endpoint_count: number;
  webacl_count: number;
  logging_visibility: VisibilityLevel;
  region: string;
  score_confidence: ScoreConfidence;
  regions: string[];
}

export interface Endpoint {
  id: string;
  resource_arn: string;
  account_id: string;
  account_name: string;
  name: string;
  type: EndpointType;
  dns_name: string;
  internet_facing: boolean;
  waf_enabled: boolean;
  waf_arn: string | null;
  logging_enabled: boolean;
  status: 'protected' | 'partially_protected' | 'unprotected' | 'unknown';
  region: string;
  visibility_level: VisibilityLevel;
}

export interface WebACL {
  id: string;
  account_id: string;
  account_name: string;
  name: string;
  arn: string;
  scope: 'REGIONAL' | 'CLOUDFRONT';
  default_action: 'BLOCK' | 'ALLOW';
  security_score: number;
  managed_rule_health: number;
  drift_count: number;
  rule_count: number;
  logging_enabled: boolean;
  region: string;
  score_confidence: ScoreConfidence;
  visibility_level: VisibilityLevel;
  score_evidence: Record<string, unknown>;
  requests_24h: number;
}

export interface WafRule {
  id: string;
  webacl_id: string;
  name: string;
  type: 'managed' | 'custom';
  action: RuleAction;
  priority: number;
  managed_group: string | null;
  managed_version: string | null;
  latest_version: string | null;
  match_count: number;
  blocked: number;
  counted: number;
  allowed: number;
  false_positives: number;
  effectiveness: number;
  scope_down: string | null;
  rate_limit: number | null;
  version_status: 'current' | 'outdated' | 'deprecated' | 'unknown';
  last_modified: string;
  rule_type: 'MANAGED' | 'CUSTOM' | 'RATE_BASED' | 'IP_SET';
}

export interface Entity {
  id: string;
  type: EntityType;
  value: string;
  label: string;
  threat_score: number;
  confidence: Confidence;
  risk_level: RiskLevel;
  country: string | null;
  asn: string | null;
  organization: string | null;
  ja3: string | null;
  ja4: string | null;
  user_agent: string | null;
  first_seen: string;
  last_seen: string;
  request_count: number;
  uri_diversity: number;
  not_found_ratio: number;
  applications: string[];
  webacls: string[];
  campaigns: string[];
  techniques: string[];
  threat_intel: ThreatIntel[];
  confidence_score: number;
  business_impact: number;
  final_risk: number;
  classification: string;
  is_allow_listed: boolean;
}

export interface ThreatIntel {
  source: 'abuseipdb' | 'greynoise' | 'virustotal' | 'guardduty' | 'internal';
  score: number;
  classification: string;
  confidence: Confidence;
  timestamp: string;
  expires_at: string;
}

export interface Campaign {
  id: string;
  name: string;
  type: DetectionType | string;
  risk_level: RiskLevel;
  confidence: Confidence;
  first_seen: string;
  last_seen: string;
  ip_count: number;
  asn_count: number;
  country_count: number;
  ja4_count: number;
  application_count: number;
  webacl_count: number;
  account_count: number;
  technique_count: number;
  waf_action_breakdown: Record<WafAction, number>;
  description: string;
  status: 'active' | 'monitoring' | 'resolved' | 'suppressed';
  campaign_code: string;
  recommended_action: string;
}

export interface Detection {
  id: string;
  type: DetectionType;
  severity: Severity;
  title: string;
  description: string;
  timestamp: string;
  entity_ids: string[];
  campaign_id: string | null;
  evidence_count: number;
  confidence: number;
  affected_apps: string[];
  affected_accounts: string[];
  status: 'new' | 'investigating' | 'correlated' | 'actioned' | 'false_positive';
  evidence: DetectionEvidence[];
  recommended_action: string;
}

export interface DetectionEvidence {
  type: string;
  label: string;
  value: string;
  detail?: string | null;
}

export interface AttackPhase {
  phase: AttackPhaseName | string;
  label: string;
  description: string;
  evidence_count: number;
  completed: boolean;
}

export interface Approval {
  id: string;
  action_type: string;
  target: string;
  reason: string;
  status: ApprovalStatus;
  requested_by: string;
  requested_at: string;
  approver: string | null;
  approved_at: string | null;
  simulation_result: string | null;
  impact: {
    affected_accounts: number;
    affected_webacls: number;
    affected_apps: number;
    potential_fp: number;
    security_gain: string;
    fp_risk: string;
  };
  lifecycle_stage: LifecycleStage;
  approval_code: string;
  status_detail: string;
  risk_level: string;
  allow_list_check: string;
  verification_status: string | null;
  aws_request_id: string | null;
  required_approver_role: string;
  expires_at: string | null;
}

export type LifecycleStage =
  | 'detect' | 'understand' | 'correlate' | 'score'
  | 'simulate' | 'guardrails' | 'approval'
  | 'execution' | 'verification' | 'audit';

export interface DriftEvent {
  id: string;
  webacl_id: string;
  webacl_name: string;
  account_id: string;
  drift_type: string;
  severity: DriftSeverity;
  description: string;
  expected: string;
  actual: string;
  detected_at: string;
  status: 'open' | 'acknowledged' | 'resolved' | 'suppressed';
  drift_code: string;
}

export interface PlatformHealth {
  overall: 'healthy' | 'degraded' | 'critical';
  collectors: CollectorHealth[];
  aws_api: ComponentHealth;
  queue: ComponentHealth;
  workers: ComponentHealth;
  database: ComponentHealth;
  threat_intel: ComponentHealth;
  last_sync: string;
  data_freshness: string;
}

export interface CollectorHealth {
  account_id: string;
  account_name: string;
  status: HealthStatus;
  last_success: string;
  error: string | null;
  affected_modules: string[];
}

export interface ComponentHealth {
  status: HealthStatus;
  detail: string;
  last_check: string;
}

export interface SecurityPosture {
  waf_coverage: number;
  endpoint_protection: number;
  rule_effectiveness: number;
  config_hygiene: number;
  managed_rule_health: number;
  detection_coverage: number;
  logging_visibility: number;
  threat_exposure: number;
  response_readiness: number;
  evidence_confidence: number;
  count_exposure: number;
  overall: number;
}

export interface PostureDimension {
  key: keyof SecurityPosture;
  label: string;
  value: number;
  why: { label: string; value: number; positive: boolean }[];
  evidence_count: number;
}

export interface ThreatActivity {
  id: string;
  time: string;
  title: string;
  type: DetectionType;
  severity: string;
  ja4: string | null;
  ip_count: number;
  asn_count: number;
  country_count: number;
  target: string;
  technique: string;
  waf_action: WafAction;
  risk: string;
  confidence: Confidence;
  campaign_id: string | null;
}

export interface Bootstrap {
  accounts: AWSAccount[];
  endpoints: Endpoint[];
  webacls: WebACL[];
  rules: Record<string, WafRule[]>;
  entities: Entity[];
  campaigns: Campaign[];
  detections: Detection[];
  drift_events: DriftEvent[];
  approvals: Approval[];
  platform_health: PlatformHealth;
  posture_dimensions: PostureDimension[];
  generated_at: string;
  threat_activity: ThreatActivity[];
}

// --- views fetched on demand (not part of the bootstrap) -------------------------------------------------

export interface Principal {
  user_id: string;
  email: string;
  full_name: string;
  role: string;
  permissions: string[];
  scoped_account_ids: string[];
  mfa: boolean;
}

export interface CampaignDetailView {
  campaign: Campaign;
  correlation_evidence: DetectionEvidence[];
  members: Entity[];
  targeted_uris: string[];
  techniques: string[];
}

export interface EntityDetailView {
  entity: Entity;
  graph: {
    nodes: { id: string; type: string; label: string; risk_level: string | null }[];
    edges: { source: string; target: string; type: string; count: number }[];
  };
  timeline: { bucket: string; BLOCK: number; ALLOW: number; COUNT: number }[];
  recent_events: Record<string, unknown>[];
  allowed_explanations: {
    webacl_id: string; webacl_name: string; allowed_requests: number; default_action: string;
    matched_rules: string[]; count_mode_rules: string[]; open_drift: Record<string, unknown>[];
  }[];
  visibility: Record<string, number>;
  recommended_action: string | null;
}

export interface SimulationResult {
  id: string;
  title: string;
  proposal: Record<string, unknown>;
  evaluated_requests: number;
  would_block: number;
  would_allow: number;
  newly_allowed: number;
  potential_false_positives: number;
  fp_rate_percent: number;
  malicious_matched: number;
  legitimate_impact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  risk_reduction: 'HIGH' | 'MEDIUM' | 'LOW';
  allow_list_passed: boolean;
  protected_requests_matched: number;
  affected_accounts: string[];
  affected_webacls: string[];
  visibility: Record<string, number>;
  visibility_note: string | null;
  false_positive_samples: Record<string, unknown>[];
  window_hours: number;
}

export interface SyncStatus {
  status: 'ready' | 'syncing' | 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT' | 'ABORTED' | string;
  last_sync?: string;
  execution_arn?: string;
}

export interface InvestigationWorkspace {
  id: string;
  title: string;
  type: 'entity' | 'campaign' | 'application' | 'webacl' | 'rule' | 'incident';
  active_tab: string;
  pinned: boolean;
}

export type Page =
  | 'command-center'
  | 'threat-intelligence'
  | 'waf-security'
  | 'investigation'
  | 'detection'
  | 'simulation'
  | 'response'
  | 'governance'
  | 'cost'
  | 'reports';
