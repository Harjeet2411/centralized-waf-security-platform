export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'healthy' | 'unknown';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';
export type Confidence = 'high' | 'medium' | 'low' | 'none';
export type VisibilityLevel = 'full' | 'sampled' | 'metrics' | 'none';
export type AccountEnv = 'prod' | 'uat' | 'dev' | 'shared';
export type EntityType = 'ip' | 'asn' | 'country' | 'org' | 'ja3' | 'ja4' | 'ua' | 'uri' | 'application' | 'account' | 'webacl' | 'rule';
export type WafAction = 'BLOCK' | 'ALLOW' | 'COUNT';
export type EndpointType = 'ALB' | 'CloudFront' | 'APIGW';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executing' | 'completed' | 'failed' | 'rolled_back';
export type DriftSeverity = 'critical' | 'high' | 'medium' | 'low';
export type DetectionType = 'scanner' | 'credential_attack' | 'distributed_attack' | 'sql_injection' | 'bot_automation' | 'malicious_allowed' | 'ja4_campaign' | 'slow_distributed';
export type AttackPhase = 'reconnaissance' | 'endpoint_discovery' | 'credential_attempts' | 'sqli_probing' | 'distributed_campaign' | 'malicious_allowed';

export interface AWSAccount {
  id: string;
  account_id: string;
  name: string;
  environment: AccountEnv;
  owner: string;
  status: 'healthy' | 'degraded' | 'unavailable';
  last_discovered: string;
  waf_coverage: number;
  security_score: number;
  endpoint_count: number;
  webacl_count: number;
  logging_visibility: VisibilityLevel;
  region: string;
}

export interface Endpoint {
  id: string;
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
}

export interface WebACL {
  id: string;
  account_id: string;
  account_name: string;
  name: string;
  arn: string;
  scope: 'REGIONAL' | 'CLOUDFRONT';
  default_action: WafAction;
  security_score: number;
  managed_rule_health: number;
  drift_count: number;
  rule_count: number;
  logging_enabled: boolean;
  region: string;
}

export interface WafRule {
  id: string;
  webacl_id: string;
  name: string;
  type: 'managed' | 'custom';
  action: WafAction;
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
  type: DetectionType;
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
}

export interface DetectionEvidence {
  type: string;
  label: string;
  value: string;
  detail?: string;
}

export interface AttackPhase {
  phase: AttackPhase;
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
  status: 'healthy' | 'degraded' | 'unavailable';
  last_success: string;
  error: string | null;
  affected_modules: string[];
}

export interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unavailable';
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
  overall: number;
}

export interface PostureDimension {
  key: keyof SecurityPosture;
  label: string;
  value: number;
  why: { label: string; value: number; positive: boolean }[];
  evidence_count: number;
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
