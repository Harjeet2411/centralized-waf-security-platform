const ACCOUNTS = [
  { id: 'acc-001', account_id: '111111111111', name: 'kfintech-prod-core', env: 'prod', owner: 'Cloud Engineering', region: 'ap-south-1' },
  { id: 'acc-002', account_id: '222222222222', name: 'kfintech-prod-payments', env: 'prod', owner: 'Payments Team', region: 'ap-south-1' },
  { id: 'acc-003', account_id: '333333333333', name: 'kfintech-prod-data', env: 'prod', owner: 'Data Engineering', region: 'ap-south-1' },
  { id: 'acc-004', account_id: '444444444444', name: 'kfintech-uat', env: 'uat', owner: 'QA Team', region: 'ap-south-1' },
  { id: 'acc-005', account_id: '555555555555', name: 'kfintech-dev', env: 'dev', owner: 'Development', region: 'ap-south-1' },
  { id: 'acc-006', account_id: '666666666666', name: 'kfintech-shared-services', env: 'shared', owner: 'Platform', region: 'ap-south-1' },
  { id: 'acc-007', account_id: '777777777777', name: 'kfintech-prod-emea', env: 'prod', owner: 'Cloud Engineering', region: 'eu-west-1' },
  { id: 'acc-008', account_id: '888888888888', name: 'kfintech-prod-apac', env: 'prod', owner: 'Cloud Engineering', region: 'ap-southeast-1' },
];

const APPS = [
  { id: 'app-001', name: 'payments-api', account_id: 'acc-002', criticality: 'critical' },
  { id: 'app-002', name: 'investor-portal', account_id: 'acc-001', criticality: 'critical' },
  { id: 'app-003', name: 'mutual-funds-api', account_id: 'acc-001', criticality: 'high' },
  { id: 'app-004', name: 'admin-console', account_id: 'acc-001', criticality: 'high' },
  { id: 'app-005', name: 'kyc-service', account_id: 'acc-002', criticality: 'high' },
  { id: 'app-006', name: 'reporting-engine', account_id: 'acc-003', criticality: 'medium' },
  { id: 'app-007', name: 'notification-svc', account_id: 'acc-001', criticality: 'medium' },
  { id: 'app-008', name: 'partner-gateway', account_id: 'acc-002', criticality: 'high' },
  { id: 'app-009', name: 'ema-portal', account_id: 'acc-007', criticality: 'critical' },
  { id: 'app-010', name: 'apac-cdn', account_id: 'acc-008', criticality: 'high' },
];

const COUNTRIES = ['IN', 'US', 'CN', 'RU', 'BR', 'DE', 'GB', 'JP', 'KR', 'VN', 'BD', 'PK', 'NG', 'UA', 'IR', 'ID', 'PH', 'MX', 'FR', 'CA'];
const ORGS = ['Example Networks', 'DataCenter Inc', 'CloudHost Ltd', 'Telco Provider', 'Residential ISP', 'Corporate Net', 'Mobile Carrier', 'Unknown'];

function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }
function pickN<T>(arr: T[], n: number): T[] {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, Math.min(n, arr.length));
}
function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFloat(min: number, max: number, dec = 1) { return parseFloat((Math.random() * (max - min) + min).toFixed(dec)); }

function generateIP(): string {
  const avoid = ['10.', '172.16.', '192.168.', '127.'];
  let ip: string;
  do {
    ip = `${randInt(1,223)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}`;
  } while (avoid.some(p => ip.startsWith(p)) && Math.random() > 0.1);
  return ip;
}

function generateJA4(seed: number): string {
  const chars = '0123456789abcdef';
  let h = '';
  for (let i = 0; i < (8 + (seed % 8)); i++) h += chars[randInt(0, 15)];
  return `ja4_${h}${seed > 20 ? randInt(0,9) : ''}`;
}

function generateASN(): string {
  const orgs = ['AS174', 'AS15169', 'AS4134', 'AS9002', 'AS9808', 'AS4812', 'AS1239', 'AS7018', 'AS701', 'AS20940', 'AS4788', 'AS24511'];
  return pick(orgs);
}

function generateEntities(count: number) {
  const entities: any[] = [];
  const ja4Pool = Array.from({ length: 8 }, (_, i) => generateJA4(i));

  for (let i = 0; i < count; i++) {
    const ja4 = ja4Pool[randInt(0, ja4Pool.length - 1)];
    const country = pick(COUNTRIES);
    const asn = generateASN();
    const org = pick(ORGS);
    const techniques = pickN(['Scanner', 'Credential Attack', 'SQLi', 'Bot Automation', 'Path Traversal', 'XSS'], randInt(1, 3));
    const riskScore = randInt(15, 96);
    const risk: any = riskScore > 75 ? 'critical' : riskScore > 55 ? 'high' : riskScore > 35 ? 'medium' : 'low';
    const confidence: any = riskScore > 70 ? 'high' : riskScore > 40 ? 'medium' : 'low';

    entities.push({
      id: `ent-${String(i + 1).padStart(3, '0')}`,
      type: 'ip',
      value: generateIP(),
      label: `${generateIP()} (${country})`,
      threat_score: riskScore,
      confidence,
      risk_level: risk,
      country,
      asn,
      organization: org,
      ja3: `771,${randInt(0,3).toString(16).toUpperCase()}-${randInt(0,15).toString(16)}-${randInt(0,255).toString(16).padStart(2,'0')}`,
      ja4,
      user_agent: pick(['curl/7.68.0', 'python-requests/2.28', 'Go-http-client/1.1', 'Mozilla/5.0 ...', 'scanner/1.0', 'sqlmap/1.7']),
      first_seen: new Date(Date.now() - randInt(1, 30) * 86400000).toISOString(),
      last_seen: new Date(Date.now() - randInt(0, 2) * 3600000).toISOString(),
      request_count: randInt(10, 50000),
      uri_diversity: randInt(3, 150),
      not_found_ratio: randFloat(0, 0.95),
      applications: pickN(APPS.map(a => a.id), randInt(1, 4)).map(id => APPS.find(a => a.id === id)!.name),
      webacls: [],
      campaigns: [],
      techniques,
      threat_intel: [
        {
          source: pick(['abuseipdb', 'greynoise', 'virustotal'] as const),
          score: randInt(0, 100),
          classification: pick(['Malicious', 'Suspicious', 'Benign', 'Unknown']),
          confidence: pick(['high', 'medium', 'low'] as const),
          timestamp: new Date(Date.now() - randInt(0, 24) * 3600000).toISOString(),
          expires_at: new Date(Date.now() + 24 * 3600000).toISOString(),
        }
      ],
    });
  }
  return entities;
}

const JA4_CLUSTER_DATA = [
  { ja4: 'ja4_a1b2c3d', ip_count: 41, asn_count: 8, country_count: 11, app_count: 17, account_count: 5, campaign_count: 3, risk: 'critical' },
  { ja4: 'ja4_e4f5g6h', ip_count: 28, asn_count: 5, country_count: 7, app_count: 9, account_count: 3, campaign_count: 2, risk: 'high' },
  { ja4: 'ja4_i7j8k9l', ip_count: 14, asn_count: 3, country_count: 4, app_count: 5, account_count: 2, campaign_count: 1, risk: 'medium' },
  { ja4: 'ja4_m0n1o2p', ip_count: 63, asn_count: 12, country_count: 15, app_count: 22, account_count: 7, campaign_count: 4, risk: 'critical' },
  { ja4: 'ja4_q3r4s5t', ip_count: 8, asn_count: 2, country_count: 3, app_count: 4, account_count: 1, campaign_count: 0, risk: 'low' },
  { ja4: 'ja4_u6v7w8x', ip_count: 19, asn_count: 4, country_count: 6, app_count: 8, account_count: 3, campaign_count: 1, risk: 'high' },
  { ja4: 'ja4_y9z0a1b', ip_count: 37, asn_count: 9, country_count: 10, app_count: 14, account_count: 6, campaign_count: 3, risk: 'critical' },
  { ja4: 'ja4_c2d3e4f', ip_count: 5, asn_count: 1, country_count: 2, app_count: 3, account_count: 1, campaign_count: 0, risk: 'low' },
];

const THREAT_ACTIVITY = [
  { time: '17:42', title: 'Distributed Attack Detected', type: 'distributed_attack', severity: 'critical', ja4: 'ja4_a1b2c3d', ip_count: 41, asn_count: 8, country_count: 11, target: 'payments-api', technique: 'Credential Attack', waf_action: 'COUNT', risk: 'CRITICAL', confidence: 'HIGH' },
  { time: '17:38', title: 'Scanner Campaign Identified', type: 'scanner', severity: 'high', ja4: 'ja4_m0n1o2p', ip_count: 63, asn_count: 12, country_count: 15, target: 'investor-portal', technique: 'Scanner', waf_action: 'COUNT', risk: 'HIGH', confidence: 'HIGH' },
  { time: '17:31', title: 'Malicious Allowed Traffic', type: 'malicious_allowed', severity: 'critical', ja4: 'ja4_y9z0a1b', ip_count: 37, asn_count: 9, country_count: 10, target: 'admin-console', technique: 'SQLi', waf_action: 'ALLOW', risk: 'CRITICAL', confidence: 'HIGH' },
  { time: '17:25', title: 'JA4 Campaign Correlation', type: 'ja4_campaign', severity: 'high', ja4: 'ja4_e4f5g6h', ip_count: 28, asn_count: 5, country_count: 7, target: 'partner-gateway', technique: 'Bot Automation', waf_action: 'COUNT', risk: 'HIGH', confidence: 'MEDIUM' },
  { time: '17:18', title: 'Credential Attack Pattern', type: 'credential_attack', severity: 'high', ja4: 'ja4_u6v7w8x', ip_count: 19, asn_count: 4, country_count: 6, target: 'kyc-service', technique: 'Credential Attack', waf_action: 'BLOCK', risk: 'HIGH', confidence: 'HIGH' },
  { time: '17:10', title: 'Slow Distributed Attack', type: 'slow_distributed', severity: 'medium', ja4: 'ja4_i7j8k9l', ip_count: 14, asn_count: 3, country_count: 4, target: 'reporting-engine', technique: 'Scanner', waf_action: 'COUNT', risk: 'MEDIUM', confidence: 'MEDIUM' },
  { time: '17:02', title: 'Bot Automation Detected', type: 'bot_automation', severity: 'medium', ja4: 'ja4_q3r4s5t', ip_count: 8, asn_count: 2, country_count: 3, target: 'notification-svc', technique: 'Bot Automation', waf_action: 'COUNT', risk: 'LOW', confidence: 'MEDIUM' },
  { time: '16:55', title: 'SQLi Probing Detected', type: 'sql_injection', severity: 'high', ja4: 'ja4_y9z0a1b', ip_count: 12, asn_count: 3, country_count: 5, target: 'mutual-funds-api', technique: 'SQLi', waf_action: 'BLOCK', risk: 'HIGH', confidence: 'HIGH' },
];

const CAMPAIGNS = [
  { id: 'cmp-001', name: 'Credential Campaign Alpha', type: 'credential_attack', risk_level: 'critical', confidence: 'high', first_seen: '2025-01-15T09:21:00Z', last_seen: new Date(Date.now() - 3600000).toISOString(), ip_count: 41, asn_count: 8, country_count: 11, ja4_count: 1, application_count: 6, webacl_count: 8, account_count: 3, technique_count: 2, waf_action_breakdown: { BLOCK: 1200, COUNT: 4800, ALLOW: 42 }, description: 'Distributed credential attack campaign targeting authentication endpoints across 6 applications. Same JA4 fingerprint across 41 source IPs from 11 countries. WAF configured to COUNT only.', status: 'active' },
  { id: 'cmp-002', name: 'Scanner Campaign Beta', type: 'scanner', risk_level: 'high', confidence: 'high', first_seen: '2025-01-14T14:05:00Z', last_seen: new Date(Date.now() - 7200000).toISOString(), ip_count: 63, asn_count: 12, country_count: 15, ja4_count: 1, application_count: 9, webacl_count: 12, account_count: 5, technique_count: 1, waf_action_breakdown: { BLOCK: 300, COUNT: 15000, ALLOW: 200 }, description: 'Large-scale URI scanning campaign targeting endpoint discovery. High 404 ratio (92%) indicates automated scanning tool.', status: 'active' },
  { id: 'cmp-003', name: 'SQLi Campaign Gamma', type: 'sql_injection', risk_level: 'critical', confidence: 'high', first_seen: '2025-01-13T08:00:00Z', last_seen: new Date(Date.now() - 1800000).toISOString(), ip_count: 37, asn_count: 9, country_count: 10, ja4_count: 1, application_count: 4, webacl_count: 6, account_count: 4, technique_count: 2, waf_action_breakdown: { BLOCK: 2400, COUNT: 1800, ALLOW: 156 }, description: 'SQL injection campaign with 156 requests allowed through WAF. Targets admin and API endpoints. Same JA4 distributed across 10 countries.', status: 'active' },
  { id: 'cmp-004', name: 'Bot Automation Delta', type: 'bot_automation', risk_level: 'medium', confidence: 'medium', first_seen: '2025-01-12T11:30:00Z', last_seen: new Date(Date.now() - 14400000).toISOString(), ip_count: 19, asn_count: 4, country_count: 6, ja4_count: 1, application_count: 8, webacl_count: 10, account_count: 3, technique_count: 1, waf_action_breakdown: { BLOCK: 800, COUNT: 6000, ALLOW: 1200 }, description: 'Automated bot traffic with repetitive patterns. Lower risk due to non-sensitive targets but shows coordinated behavior.', status: 'monitoring' },
  { id: 'cmp-005', name: 'Slow Distributed Epsilon', type: 'slow_distributed', risk_level: 'medium', confidence: 'medium', first_seen: '2025-01-10T16:00:00Z', last_seen: new Date(Date.now() - 28800000).toISOString(), ip_count: 14, asn_count: 3, country_count: 4, ja4_count: 1, application_count: 5, webacl_count: 7, account_count: 2, technique_count: 1, waf_action_breakdown: { BLOCK: 200, COUNT: 2500, ALLOW: 500 }, description: 'Slow-rate distributed attack designed to evade rate limits. Low volume per IP but coordinated across multiple sources.', status: 'monitoring' },
];

const WEBACLS = [
  { id: 'wacl-001', account_id: 'acc-001', account_name: 'kfintech-prod-core', name: 'payments-prod-webacl', arn: 'arn:aws:wafv2:ap-south-1:111111111111:regional/webacl/payments-prod/...', scope: 'REGIONAL', default_action: 'BLOCK' as const, security_score: 82, managed_rule_health: 91, drift_count: 2, rule_count: 15, logging_enabled: true, region: 'ap-south-1' },
  { id: 'wacl-002', account_id: 'acc-001', account_name: 'kfintech-prod-core', name: 'investor-portal-webacl', arn: 'arn:aws:wafv2:ap-south-1:111111111111:regional/webacl/investor-portal/...', scope: 'REGIONAL', default_action: 'BLOCK' as const, security_score: 78, managed_rule_health: 88, drift_count: 1, rule_count: 14, logging_enabled: true, region: 'ap-south-1' },
  { id: 'wacl-003', account_id: 'acc-002', account_name: 'kfintech-prod-payments', name: 'payments-api-webacl', arn: 'arn:aws:wafv2:ap-south-1:222222222222:regional/webacl/payments-api/...', scope: 'REGIONAL', default_action: 'COUNT' as const, security_score: 61, managed_rule_health: 85, drift_count: 3, rule_count: 18, logging_enabled: true, region: 'ap-south-1' },
  { id: 'wacl-004', account_id: 'acc-003', account_name: 'kfintech-prod-data', name: 'data-api-webacl', arn: 'arn:aws:wafv2:ap-south-1:333333333333:regional/webacl/data-api/...', scope: 'REGIONAL', default_action: 'BLOCK' as const, security_score: 71, managed_rule_health: 79, drift_count: 0, rule_count: 12, logging_enabled: false, region: 'ap-south-1' },
  { id: 'wacl-005', account_id: 'acc-004', account_name: 'kfintech-uat', name: 'uat-webacl', arn: 'arn:aws:wafv2:ap-south-1:444444444444:regional/webacl/uat/...', scope: 'REGIONAL', default_action: 'BLOCK' as const, security_score: 65, managed_rule_health: 72, drift_count: 4, rule_count: 10, logging_enabled: false, region: 'ap-south-1' },
  { id: 'wacl-006', account_id: 'acc-007', account_name: 'kfintech-prod-emea', name: 'emea-webacl', arn: 'arn:aws:wafv2:eu-west-1:777777777777:regional/webacl/emea/...', scope: 'REGIONAL', default_action: 'BLOCK' as const, security_score: 74, managed_rule_health: 86, drift_count: 1, rule_count: 13, logging_enabled: true, region: 'eu-west-1' },
  { id: 'wacl-007', account_id: 'acc-008', account_name: 'kfintech-prod-apac', name: 'apac-cdn-webacl', arn: 'arn:aws:wafv2:ap-southeast-1:888888888888:cloudfront/webacl/apac-cdn/...', scope: 'CLOUDFRONT', default_action: 'BLOCK' as const, security_score: 69, managed_rule_health: 82, drift_count: 2, rule_count: 16, logging_enabled: true, region: 'ap-southeast-1' },
  { id: 'wacl-008', account_id: 'acc-006', account_name: 'kfintech-shared-services', name: 'shared-services-webacl', arn: 'arn:aws:wafv2:ap-south-1:666666666666:regional/webacl/shared/...', scope: 'REGIONAL', default_action: 'COUNT' as const, security_score: 54, managed_rule_health: 65, drift_count: 5, rule_count: 8, logging_enabled: false, region: 'ap-south-1' },
];

const RULE_NAMES = [
  'AWSManagedRulesCommonRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet', 'AWSManagedRulesSQLiRuleSet',
  'AWSManagedRulesLinuxRuleSet', 'AWSManagedRulesAmazonIpReputationList', 'AWSManagedRulesAnonymousIpList',
  'AWSManagedRulesAdminProtectionRuleSet', 'RateLimitRule', 'IPAllowList', 'GeoBlockRule',
  'JA4AnomalyDetection', 'CustomBotRule', 'SQLiAdvancedRule', 'XSSProtectionRule',
];

function generateRules(webaclId: string) {
  const rules: any[] = [];
  const managedRules = pickN(RULE_NAMES, randInt(5, 8));
  let priority = 0;
  for (const name of managedRules) {
    const isManaged = !name.includes('RateLimit') && !name.includes('Allow') && !name.includes('GeoBlock') && !name.includes('JA4') && !name.includes('Custom');
    const action: any = name.includes('Allow') || name.includes('RateLimit') ? 'COUNT' : name.includes('GeoBlock') ? 'BLOCK' : pick(['BLOCK', 'COUNT', 'ALLOW'] as const);
    const matchCount = randInt(100, 50000);
    const effectiveness = randInt(40, 99);
    const blocked = Math.floor(matchCount * effectiveness / 100);
    const allowed = Math.floor(matchCount * (100 - effectiveness) / 200);
    const counted = matchCount - blocked - allowed;
    const versionStatus: any = pick(['current', 'current', 'current', 'outdated', 'unknown'] as const);

    rules.push({
      id: `rule-${webaclId}-${priority}`,
      webacl_id: webaclId,
      name,
      type: isManaged ? 'managed' : 'custom',
      action,
      priority: priority++,
      managed_group: isManaged ? name : null,
      managed_version: isManaged ? `v${randInt(1,4)}.${randInt(0,9)}` : null,
      latest_version: isManaged ? `v${randInt(1,5)}.${randInt(0,12)}` : null,
      match_count: matchCount,
      blocked: Math.max(0, blocked),
      counted: Math.max(0, counted),
      allowed: Math.max(0, allowed),
      false_positives: randInt(0, 15),
      effectiveness,
      scope_down: Math.random() > 0.7 ? `/api/v1/*` : null,
      rate_limit: name.includes('RateLimit') ? randInt(100, 2000) : null,
      version_status: versionStatus,
      last_modified: new Date(Date.now() - randInt(0, 30) * 86400000).toISOString(),
    });
  }
  return rules.sort((a, b) => a.priority - b.priority);
}

function generateEndpoints(accountId: string, accountName: string, region: string) {
  const endpoints: any[] = [];
  const appMap = new Map<string, { name: string; criticality: string }>();
  APPS.filter(a => a.account_id === accountId).forEach(a => appMap.set(a.id, a));

  if (accountId === 'acc-001') {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: 'payments-alb', type: 'ALB' as const, dns_name: 'payments-api.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:111111111111:regional/webacl/payments-prod/...', logging_enabled: true, status: 'protected' as const, region },
      { id: `ep-${accountId}-2`, account_id: accountId, account_name: accountName, name: 'investor-cf', type: 'CloudFront' as const, dns_name: 'investor.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:111111111111:regional/webacl/investor-portal/...', logging_enabled: true, status: 'protected' as const, region },
      { id: `ep-${accountId}-3`, account_id: accountId, account_name: accountName, name: 'admin-api-gw', type: 'APIGW' as const, dns_name: 'api-admin.kfintech.com', internet_facing: true, waf_enabled: false, waf_arn: null, logging_enabled: false, status: 'unprotected' as const, region },
      { id: `ep-${accountId}-4`, account_id: accountId, account_name: accountName, name: 'mf-api-alb', type: 'ALB' as const, dns_name: 'mf-api.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:111111111111:regional/webacl/payments-prod/...', logging_enabled: true, status: 'protected' as const, region },
    );
  } else if (accountId === 'acc-002') {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: 'payments-alb-primary', type: 'ALB' as const, dns_name: 'pay.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:222222222222:regional/webacl/payments-api/...', logging_enabled: true, status: 'protected' as const, region },
      { id: `ep-${accountId}-2`, account_id: accountId, account_name: accountName, name: 'kyc-alb', type: 'ALB' as const, dns_name: 'kyc.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:222222222222:regional/webacl/payments-api/...', logging_enabled: true, status: 'protected' as const, region },
      { id: `ep-${accountId}-3`, account_id: accountId, account_name: accountName, name: 'partner-api', type: 'ALB' as const, dns_name: 'partner.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:222222222222:regional/webacl/payments-api/...', logging_enabled: true, status: 'protected' as const, region },
    );
  } else if (accountId === 'acc-003') {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: 'reporting-alb', type: 'ALB' as const, dns_name: 'reports.kfintech.com', internet_facing: false, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:333333333333:regional/webacl/data-api/...', logging_enabled: false, status: 'partially_protected' as const, region },
      { id: `ep-${accountId}-2`, account_id: accountId, account_name: accountName, name: 'data-api-gw', type: 'APIGW' as const, dns_name: 'data-api.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-south-1:333333333333:regional/webacl/data-api/...', logging_enabled: false, status: 'protected' as const, region },
    );
  } else if (accountId === 'acc-007') {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: 'ema-cf', type: 'CloudFront' as const, dns_name: 'ema.kfintech-eu.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:eu-west-1:777777777777:regional/webacl/emea/...', logging_enabled: true, status: 'protected' as const, region },
    );
  } else if (accountId === 'acc-008') {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: 'apac-cf', type: 'CloudFront' as const, dns_name: 'apac.kfintech.com', internet_facing: true, waf_enabled: true, waf_arn: 'arn:aws:wafv2:ap-southeast-1:888888888888:cloudfront/webacl/apac-cdn/...', logging_enabled: true, status: 'protected' as const, region },
    );
  } else {
    endpoints.push(
      { id: `ep-${accountId}-1`, account_id: accountId, account_name: accountName, name: `${accountName.split('-').pop()}-alb`, type: 'ALB' as const, dns_name: `${accountName.split('-').pop()}.kfintech.com`, internet_facing: true, waf_enabled: false, waf_arn: null, logging_enabled: false, status: 'unprotected' as const, region },
    );
  }
  return endpoints;
}

const DRIFT_EVENTS = [
  { id: 'drift-001', webacl_id: 'wacl-003', webacl_name: 'payments-api-webacl', account_id: 'acc-002', drift_type: 'Rule Action Change', severity: 'critical', description: 'AWSManagedRulesCommonRuleSet changed from BLOCK to COUNT', expected: 'BLOCK', actual: 'COUNT', detected_at: '2025-01-15T12:00:00Z', status: 'open' },
  { id: 'drift-002', webacl_id: 'wacl-003', webacl_name: 'payments-api-webacl', account_id: 'acc-002', drift_type: 'Managed Rule Version Change', severity: 'high', description: 'AWSManagedRulesSQLiRuleSet version changed from v4.0 to v3.2', expected: 'v4.0', actual: 'v3.2', detected_at: '2025-01-15T10:30:00Z', status: 'open' },
  { id: 'drift-003', webacl_id: 'wacl-008', webacl_name: 'shared-services-webacl', account_id: 'acc-006', drift_type: 'Rule Added', severity: 'medium', description: 'New custom rule "CustomBotRule" added with COUNT action', expected: 'absent', actual: 'present (COUNT)', detected_at: '2025-01-14T18:00:00Z', status: 'acknowledged' },
  { id: 'drift-004', webacl_id: 'wacl-005', webacl_name: 'uat-webacl', account_id: 'acc-004', drift_type: 'IP Set Modified', severity: 'high', description: 'IP Allow List modified: 3 entries removed', expected: '10 entries', actual: '7 entries', detected_at: '2025-01-14T09:00:00Z', status: 'open' },
  { id: 'drift-005', webacl_id: 'wacl-001', webacl_name: 'payments-prod-webacl', account_id: 'acc-001', drift_type: 'Scope Down Changed', severity: 'medium', description: 'RateLimitRule scope changed from /api/v1/* to /*', expected: '/api/v1/*', actual: '/*', detected_at: '2025-01-13T22:00:00Z', status: 'resolved' },
  { id: 'drift-006', webacl_id: 'wacl-002', webacl_name: 'investor-portal-webacl', account_id: 'acc-001', drift_type: 'Rule Removed', severity: 'high', description: 'AWSManagedRulesAdminProtectionRuleSet removed from WebACL', expected: 'present', actual: 'removed', detected_at: '2025-01-13T15:00:00Z', status: 'open' },
  { id: 'drift-007', webacl_id: 'wacl-007', webacl_name: 'apac-cdn-webacl', account_id: 'acc-008', drift_type: 'Logging Disabled', severity: 'medium', description: 'WAF logging was disabled for this CloudFront WebACL', expected: 'enabled', actual: 'disabled', detected_at: '2025-01-12T20:00:00Z', status: 'open' },
  { id: 'drift-008', webacl_id: 'wacl-005', webacl_name: 'uat-webacl', account_id: 'acc-004', drift_type: 'Default Action Changed', severity: 'low', description: 'Default action changed from COUNT to ALLOW for testing', expected: 'COUNT', actual: 'ALLOW', detected_at: '2025-01-12T14:00:00Z', status: 'resolved' },
  { id: 'drift-009', webacl_id: 'wacl-004', webacl_name: 'data-api-webacl', account_id: 'acc-003', drift_type: 'Managed Rule Version Change', severity: 'medium', description: 'AWSManagedRulesAmazonIpReputationList updated to v5.1', expected: 'v4.0', actual: 'v5.1', detected_at: '2025-01-11T10:00:00Z', status: 'acknowledged' },
  { id: 'drift-010', webacl_id: 'wacl-008', webacl_name: 'shared-services-webacl', account_id: 'acc-006', drift_type: 'Rate Limit Changed', severity: 'medium', description: 'RateLimitRule threshold changed from 2000 to 500', expected: '2000', actual: '500', detected_at: '2025-01-10T08:00:00Z', status: 'open' },
];

const APPROVALS = [
  { id: 'apr-001', action_type: 'IP Block', target: '203.0.113.50', reason: 'Active credential attack campaign participant. Threat score 96. 183 legitimate requests observed over 30 days.', status: 'pending' as const, requested_by: 'analyst.ram', requested_at: new Date(Date.now() - 3600000).toISOString(), approver: null, approved_at: null, simulation_result: 'LOW IMPACT', impact: { affected_accounts: 2, affected_webacls: 3, affected_apps: 4, potential_fp: 183, security_gain: 'HIGH', fp_risk: 'LOW' }, lifecycle_stage: 'approval' as const },
  { id: 'apr-002', action_type: 'Rule Modification', target: 'wacl-003 / AWSManagedRulesCommonRuleSet', reason: 'Change action from COUNT to BLOCK. Currently allowing malicious requests through. Would block ~4,800 requests monthly with 183 potential FPs.', status: 'pending' as const, requested_by: 'analyst.priya', requested_at: new Date(Date.now() - 7200000).toISOString(), approver: null, approved_at: null, simulation_result: 'HIGH SECURITY GAIN', impact: { affected_accounts: 1, affected_webacls: 1, affected_apps: 3, potential_fp: 183, security_gain: 'HIGH', fp_risk: 'LOW' }, lifecycle_stage: 'approval' as const },
  { id: 'apr-003', action_type: 'Managed Rule Version', target: 'wacl-003 / AWSManagedRulesSQLiRuleSet', reason: 'Downgrade detected: v4.0 → v3.2. Restore to v4.0 for latest SQLi protections.', status: 'pending' as const, requested_by: 'admin.karthik', requested_at: new Date(Date.now() - 86400000).toISOString(), approver: null, approved_at: null, simulation_result: 'NO IMPACT', impact: { affected_accounts: 1, affected_webacls: 1, affected_apps: 3, potential_fp: 0, security_gain: 'HIGH', fp_risk: 'NONE' }, lifecycle_stage: 'approval' as const },
  { id: 'apr-004', action_type: 'WAF Attach', target: 'acc-004 / admin-api-gw', reason: 'Internet-facing endpoint without WAF protection. Attach existing WebACL.', status: 'approved' as const, requested_by: 'admin.karthik', requested_at: new Date(Date.now() - 172800000).toISOString(), approver: 'security.admin', approved_at: new Date(Date.now() - 86400000).toISOString(), simulation_result: 'NO IMPACT', impact: { affected_accounts: 1, affected_webacls: 0, affected_apps: 1, potential_fp: 0, security_gain: 'CRITICAL', fp_risk: 'NONE' }, lifecycle_stage: 'execution' as const },
  { id: 'apr-005', action_type: 'IP Block', target: '198.51.100.25', reason: 'Scanner campaign member. Threat score 87. Part of cmp-002.', status: 'completed' as const, requested_by: 'analyst.ram', requested_at: new Date(Date.now() - 259200000).toISOString(), approver: 'security.admin', approved_at: new Date(Date.now() - 172800000).toISOString(), simulation_result: 'LOW IMPACT', impact: { affected_accounts: 1, affected_webacls: 2, affected_apps: 2, potential_fp: 45, security_gain: 'MEDIUM', fp_risk: 'LOW' }, lifecycle_stage: 'verification' as const },
];

const DETECTIONS = [
  { id: 'det-001', type: 'distributed_attack', severity: 'critical', title: 'Distributed Credential Attack', description: '41 unique IPs across 11 countries using the same JA4 fingerprint targeting login endpoints. WAF configured to COUNT only.', timestamp: new Date(Date.now() - 600000).toISOString(), entity_ids: ['ent-001', 'ent-003'], campaign_id: 'cmp-001', evidence_count: 12, confidence: 92, affected_apps: ['payments-api', 'investor-portal', 'mutual-funds-api'], affected_accounts: ['kfintech-prod-core', 'kfintech-prod-payments'], status: 'new', evidence: [
    { type: 'JA4 Correlation', label: 'Shared fingerprint', value: 'ja4_a1b2c3d across 41 IPs' },
    { type: 'Distribution', label: 'Source diversity', value: '8 ASNs, 11 countries' },
    { type: 'Targets', label: 'Affected applications', value: '6 applications, 8 WebACLs' },
    { type: 'WAF Config', label: 'Current action', value: 'COUNT (requests passed through)' },
    { type: 'Volume', label: 'Request count', value: '5,042 requests in 24h' },
    { type: 'Technique', label: 'Attack technique', value: 'Credential stuffing' },
  ]},
  { id: 'det-002', type: 'malicious_allowed', severity: 'critical', title: 'Malicious Traffic Allowed Through WAF', description: '37 source IPs with threat score > 80 were ALLOWED by WAF. Current action is COUNT, not BLOCK.', timestamp: new Date(Date.now() - 1200000).toISOString(), entity_ids: ['ent-007', 'ent-012'], campaign_id: 'cmp-003', evidence_count: 8, confidence: 95, affected_apps: ['admin-console', 'mutual-funds-api'], affected_accounts: ['kfintech-prod-core', 'kfintech-prod-payments'], status: 'investigating', evidence: [
    { type: 'WAF Action', label: 'Action taken', value: 'ALLOW on high-threat entities' },
    { type: 'Threat Score', label: 'Average entity threat score', value: '87/100' },
    { type: 'Rule', label: 'Non-blocking rule', value: 'AWSManagedRulesCommonRuleSet (COUNT)' },
    { type: 'Impact', label: 'Affected applications', value: '4 applications' },
  ]},
  { id: 'det-003', type: 'scanner', severity: 'high', title: 'Large-Scale URI Scanner', description: '63 unique IPs scanning for endpoints. 92% 404 response rate. Same JA4 across all sources.', timestamp: new Date(Date.now() - 1800000).toISOString(), entity_ids: ['ent-015', 'ent-022'], campaign_id: 'cmp-002', evidence_count: 6, confidence: 94, affected_apps: ['investor-portal', 'partner-gateway'], affected_accounts: ['kfintech-prod-core', 'kfintech-prod-payments'], status: 'correlated', evidence: [
    { type: 'URI Diversity', label: 'Unique URIs probed', value: '148 unique URIs' },
    { type: '404 Ratio', label: 'Not found rate', value: '92%' },
    { type: 'IP Count', label: 'Unique sources', value: '63 IPs, 12 ASNs' },
    { type: 'Pattern', label: 'Scanning pattern', value: 'Automated reconnaissance' },
  ]},
  { id: 'det-004', type: 'sql_injection', severity: 'high', title: 'SQL Injection Probing', description: 'SQL injection patterns detected across 12 IPs targeting API endpoints. 156 requests allowed through.', timestamp: new Date(Date.now() - 2400000).toISOString(), entity_ids: ['ent-008', 'ent-019'], campaign_id: 'cmp-003', evidence_count: 7, confidence: 88, affected_apps: ['mutual-funds-api', 'admin-console'], affected_accounts: ['kfintech-prod-core'], status: 'new', evidence: [
    { type: 'Pattern', label: 'SQLi pattern detected', value: 'UNION SELECT, OR 1=1 variants' },
    { type: 'Targets', label: 'Targeted endpoints', value: '/api/v1/query, /admin/search' },
    { type: 'WAF Action', label: 'Current WAF response', value: 'Mixed: BLOCK + ALLOW' },
  ]},
  { id: 'det-005', type: 'ja4_campaign', severity: 'high', title: 'JA4 Campaign Detection', description: 'New JA4 fingerprint associated with 28 IPs across 7 countries targeting partner gateway.', timestamp: new Date(Date.now() - 3600000).toISOString(), entity_ids: ['ent-030'], campaign_id: 'cmp-004', evidence_count: 5, confidence: 78, affected_apps: ['partner-gateway'], affected_accounts: ['kfintech-prod-payments'], status: 'new', evidence: [
    { type: 'JA4', label: 'New fingerprint', value: 'ja4_e4f5g6h' },
    { type: 'Scale', label: 'Entity count', value: '28 IPs, 5 ASNs, 7 countries' },
  ]},
  { id: 'det-006', type: 'drift', severity: 'high', title: 'WAF Configuration Drift', description: 'Rule action changed from BLOCK to COUNT on payments-api WebACL. 3 other drift events on same WebACL.', timestamp: new Date(Date.now() - 5400000).toISOString(), entity_ids: [], campaign_id: null, evidence_count: 4, confidence: 100, affected_apps: ['payments-api'], affected_accounts: ['kfintech-prod-payments'], status: 'investigating', evidence: [
    { type: 'WebACL', label: 'Affected WebACL', value: 'payments-api-webacl' },
    { type: 'Rule', label: 'Changed rule', value: 'AWSManagedRulesCommonRuleSet' },
    { type: 'Change', label: 'Modification', value: 'BLOCK → COUNT' },
  ]},
  { id: 'det-007', type: 'bot_automation', severity: 'medium', title: 'Bot Automation Detected', description: 'Repetitive request patterns with abnormal user-agent strings detected on notification service.', timestamp: new Date(Date.now() - 7200000).toISOString(), entity_ids: ['ent-045'], campaign_id: 'cmp-004', evidence_count: 4, confidence: 72, affected_apps: ['notification-svc'], affected_accounts: ['kfintech-prod-core'], status: 'new', evidence: [
    { type: 'Pattern', label: 'Request interval', value: 'Exactly 3.2s between requests' },
    { type: 'UA', label: 'User agent', value: 'curl/7.68.0 on non-CLI endpoint' },
  ]},
  { id: 'det-008', type: 'slow_distributed', severity: 'medium', title: 'Slow Distributed Attack', description: 'Coordinated low-rate attack across 14 IPs designed to evade rate limits.', timestamp: new Date(Date.now() - 9000000).toISOString(), entity_ids: ['ent-050'], campaign_id: 'cmp-005', evidence_count: 5, confidence: 68, affected_apps: ['reporting-engine'], affected_accounts: ['kfintech-prod-data'], status: 'new', evidence: [
    { type: 'Rate', label: 'Requests per IP', value: '2-5 req/hour' },
    { type: 'Coordination', label: 'Shared fingerprint', value: 'Same JA4 across all IPs' },
  ]},
];

const POSTURE_DIMENSIONS = [
  { key: 'waf_coverage', label: 'WAF Coverage', value: 87, why: [
    { label: 'Protected endpoints', value: 22, positive: true },
    { label: 'Unprotected endpoints', value: 4, positive: false },
    { label: 'Partial coverage', value: 3, positive: false },
  ], evidence_count: 29 },
  { key: 'endpoint_protection', label: 'Endpoint Protection', value: 82, why: [
    { label: 'Internet-facing with WAF', value: 18, positive: true },
    { label: 'Internal endpoints', value: 8, positive: true },
    { label: 'Unprotected internet-facing', value: 3, positive: false },
  ], evidence_count: 29 },
  { key: 'rule_effectiveness', label: 'Rule Effectiveness', value: 73, why: [
    { label: 'High effectiveness (>80%)', value: 45, positive: true },
    { label: 'Medium effectiveness (50-80%)', value: 28, positive: false },
    { label: 'Low effectiveness (<50%)', value: 12, positive: false },
  ], evidence_count: 85 },
  { key: 'config_hygiene', label: 'Configuration Hygiene', value: 68, why: [
    { label: 'Clean WebACLs', value: 5, positive: true },
    { label: 'Open drift events', value: 10, positive: false },
    { label: 'Resolved drift', value: 2, positive: true },
  ], evidence_count: 17 },
  { key: 'managed_rule_health', label: 'Managed Rule Health', value: 79, why: [
    { label: 'Current versions', value: 62, positive: true },
    { label: 'Outdated versions', value: 18, positive: false },
    { label: 'Deprecated', value: 2, positive: false },
  ], evidence_count: 82 },
  { key: 'detection_coverage', label: 'Detection Coverage', value: 76, why: [
    { label: 'Behavioral detections active', value: 6, positive: true },
    { label: 'JA4 correlation enabled', value: 8, positive: true },
    { label: 'Missing detections', value: 3, positive: false },
  ], evidence_count: 24 },
  { key: 'logging_visibility', label: 'Logging Visibility', value: 48, why: [
    { label: 'Full logging', value: 3, positive: true },
    { label: 'No logging', value: 5, positive: false },
    { label: 'Sampled only', value: 0, positive: false },
  ], evidence_count: 8 },
  { key: 'threat_exposure', label: 'Threat Exposure', value: 62, why: [
    { label: 'Active campaigns', value: 5, positive: false },
    { label: 'Malicious allowed', value: 156, positive: false },
    { label: 'Blocked effectively', value: 9200, positive: true },
  ], evidence_count: 156 },
  { key: 'response_readiness', label: 'Response Readiness', value: 91, why: [
    { label: 'Approval policies configured', value: 4, positive: true },
    { label: 'Pending approvals', value: 3, positive: false },
    { label: 'Guardrails active', value: 8, positive: true },
  ], evidence_count: 5 },
  { key: 'evidence_confidence', label: 'Evidence Confidence', value: 74, why: [
    { label: 'Full visibility data', value: 3, positive: true },
    { label: 'Sampled data only', value: 4, positive: false },
    { label: 'No visibility', value: 1, positive: false },
  ], evidence_count: 8 },
];

const PLATFORM_HEALTH = {
  overall: 'degraded' as const,
  collectors: ACCOUNTS.slice(0, 8).map((acc, i) => ({
    account_id: acc.id,
    account_name: acc.name,
    status: i === 2 ? 'degraded' : i === 5 ? 'unavailable' : 'healthy' as const,
    last_success: new Date(Date.now() - (i === 5 ? 86400000 : i === 2 ? 3600000 : randInt(1, 6) * 3600000)).toISOString(),
    error: i === 5 ? 'AccessDenied: Role DiscoveryRole not assumable' : i === 2 ? 'ThrottlingException: Rate exceeded' : null,
    affected_modules: i === 5 ? ['all'] : i === 2 ? ['metrics', 'rules'] : ['none'],
  })),
  aws_api: { status: 'healthy' as const, detail: 'All API calls within limits', last_check: new Date(Date.now() - 60000).toISOString() },
  queue: { status: 'healthy' as const, detail: '0 messages pending', last_check: new Date(Date.now() - 30000).toISOString() },
  workers: { status: 'healthy' as const, detail: 'All 6 workers active', last_check: new Date(Date.now() - 45000).toISOString() },
  database: { status: 'healthy' as const, detail: 'RDS healthy, 23ms avg query time', last_check: new Date(Date.now() - 15000).toISOString() },
  threat_intel: { status: 'degraded' as const, detail: 'GreyNoise rate limited (429)', last_check: new Date(Date.now() - 120000).toISOString() },
  last_sync: new Date(Date.now() - 3600000).toISOString(),
  data_freshness: '1 hour old',
};

const ATTACK_STORY_PHASES = [
  { phase: 'reconnaissance', label: 'Reconnaissance', description: 'Attacker identified application endpoints through search engine discovery and subdomain enumeration. 148 unique URIs probed across 6 applications.', evidence_count: 23, completed: true },
  { phase: 'endpoint_discovery', label: 'Endpoint Discovery', description: 'WAF request sampling and response analysis used to map application structure. High 404 ratio (92%) indicates systematic probing.', evidence_count: 15, completed: true },
  { phase: 'credential_attempts', label: 'Credential Attempts', description: 'Login endpoints targeted with credential stuffing using common username/password combinations. WAF configured to COUNT — requests passed through.', evidence_count: 31, completed: true },
  { phase: 'sqli_probing', label: 'SQLi Probing', description: 'SQL injection patterns detected on query endpoints. UNION SELECT, OR 1=1, and stacked query patterns observed. 156 requests allowed.', evidence_count: 18, completed: true },
  { phase: 'distributed_campaign', label: 'Distributed Campaign', description: 'Coordinated campaign launched from 41 IPs across 11 countries using same JA4 fingerprint. Targets 6 applications simultaneously.', evidence_count: 42, completed: true },
  { phase: 'malicious_allowed', label: 'Malicious Traffic Allowed', description: 'WAF rule action is COUNT, not BLOCK. High-threat entities (score > 80) passed through. This is the current critical exposure point.', evidence_count: 28, completed: false },
];

export {
  ACCOUNTS,
  APPS,
  COUNTRIES,
  ORGS,
  JA4_CLUSTER_DATA,
  THREAT_ACTIVITY,
  CAMPAIGNS,
  WEBACLS,
  generateRules,
  generateEndpoints,
  generateEntities,
  DRIFT_EVENTS,
  APPROVALS,
  DETECTIONS,
  POSTURE_DIMENSIONS,
  PLATFORM_HEALTH,
  ATTACK_STORY_PHASES,
  pick,
  pickN,
  randInt,
  randFloat,
  generateIP,
};
