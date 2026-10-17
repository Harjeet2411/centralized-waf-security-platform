-- LOCAL DEMO DATASET - loaded only by `python -m app.cli seed-demo` (refused outside local/test environments).
-- Synthetic accounts and traffic so the console can be explored without AWS. Never used in production.
INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn, regions, status,
  visibility_level, logging_enabled, security_score, score_confidence, last_discovered, last_error, score_evidence) VALUES
 ('111122223333', 'prod-payments-04', 'production', 'payments-platform', 'arn:aws:iam::111122223333:role/SASWafDiscoveryRole',
  'arn:aws:iam::111122223333:role/SASWafResponseRole', ARRAY['eu-west-1', 'us-east-1'], 'HEALTHY', 'full', true, 71.5, 'FULL',
  now() - interval '18 minutes', NULL,
  '{"dimensions": {"coverage": {"value": 67, "weight": 0.25}, "blocking": {"value": 82, "weight": 0.2}, "malicious_allowed": {"value": 45, "weight": 0.2}, "count_exposure": {"value": 75, "weight": 0.1}, "drift": {"value": 60, "weight": 0.1}, "managed_versions": {"value": 50, "weight": 0.1}, "logging": {"value": 100, "weight": 0.05}}}'),
 ('444455556666', 'prod-core-banking-01', 'production', 'core-banking', 'arn:aws:iam::444455556666:role/SASWafDiscoveryRole',
  'arn:aws:iam::444455556666:role/SASWafResponseRole', ARRAY['eu-west-1'], 'HEALTHY', 'sampled', false, 84.0, 'SAMPLED',
  now() - interval '22 minutes', NULL,
  '{"dimensions": {"coverage": {"value": 100, "weight": 0.25}, "blocking": {"value": 91, "weight": 0.2}, "malicious_allowed": {"value": 83, "weight": 0.2}, "count_exposure": {"value": 100, "weight": 0.1}, "drift": {"value": 100, "weight": 0.1}, "managed_versions": {"value": 50, "weight": 0.1}, "logging": {"value": 0, "weight": 0.05}}}'),
 ('777788889999', 'prod-onboarding-19', 'production', 'onboarding', 'arn:aws:iam::777788889999:role/SASWafDiscoveryRole',
  'arn:aws:iam::777788889999:role/SASWafResponseRole', ARRAY['us-east-1'], 'DEGRADED', 'sampled', false, 52.0, 'SAMPLED',
  now() - interval '25 minutes', 'endpoint_discovery APIGW/us-east-1: AccessDenied',
  '{"dimensions": {"coverage": {"value": 0, "weight": 0.25}, "blocking": {"value": 100, "weight": 0.2}, "malicious_allowed": {"value": 100, "weight": 0.2}, "count_exposure": {"value": 100, "weight": 0.1}, "drift": {"value": 100, "weight": 0.1}, "managed_versions": {"value": 100, "weight": 0.1}, "logging": {"value": 0, "weight": 0.05}}}');

INSERT INTO web_acls (id, webacl_id, arn, name, account_id, region, scope, default_action, capacity, security_score,
  score_confidence, visibility_level, logging_enabled, logging_destination, requests_24h, blocked_24h, allowed_24h, counted_24h,
  malicious_allowed_24h, score_evidence) VALUES
 ('a1000000-0000-0000-0000-000000000001', 'r-pay', 'arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/prod-payments-waf/r-pay',
  'prod-payments-waf', '111122223333', 'eu-west-1', 'REGIONAL', 'ALLOW', 910, 71.5, 'FULL', 'full', true,
  'arn:aws:s3:::aws-waf-logs-sas-111122223333', 1250000, 48210, 1196928, 4862, 42,
  '{"dimensions": {"coverage": {"value": 100, "weight": 0.25, "inputs": {"internet_facing_endpoints_attached": 1}}, "blocking": {"value": 82, "weight": 0.2, "inputs": {"blocked_malicious_24h": 4820, "malicious_or_suspicious_24h": 5878}}, "malicious_allowed": {"value": 10.6, "weight": 0.2, "inputs": {"allowed_malicious_24h": 42}}, "count_exposure": {"value": 75, "weight": 0.1, "inputs": {"tuning_window_days": 14}}, "drift": {"value": 60, "weight": 0.1, "inputs": {"open_by_severity": {"CRITICAL": 1}}}, "managed_versions": {"value": 50, "weight": 0.1, "inputs": {"statuses": ["OUTDATED", "CURRENT"]}}, "logging": {"value": 100, "weight": 0.05, "inputs": {"enabled": true}}}, "visibility_level": "full"}'),
 ('a1000000-0000-0000-0000-000000000002', 'r-bank', 'arn:aws:wafv2:eu-west-1:444455556666:regional/webacl/core-banking-waf/r-bank',
  'core-banking-waf', '444455556666', 'eu-west-1', 'REGIONAL', 'BLOCK', 640, 84.0, 'SAMPLED', 'sampled', false, NULL,
  880000, 12400, 867100, 500, 0, '{"dimensions": {}, "visibility_level": "sampled", "note": "Request-level dimensions use sampled requests"}'),
 ('a1000000-0000-0000-0000-000000000003', 'c-cdn', 'arn:aws:wafv2:us-east-1:777788889999:global/webacl/onboarding-cdn-waf/c-cdn',
  'onboarding-cdn-waf', '777788889999', 'us-east-1', 'CLOUDFRONT', 'ALLOW', 300, 52.0, 'SAMPLED', 'sampled', false, NULL,
  310000, 2100, 305400, 2500, 0, '{"dimensions": {}, "visibility_level": "sampled"}');

INSERT INTO rules (id, webacl_id, account_id, name, priority, type, action, statement, managed_group_name, vendor_name,
  current_version, available_version, version_status, excluded_rules, rate_limit, matches_24h, blocked_24h, counted_24h,
  false_positives_30d, effectiveness) VALUES
 ('b1000000-0000-0000-0000-000000000001', 'a1000000-0000-0000-0000-000000000001', '111122223333', 'SAS-Platform-Blocklist', 0, 'IP_SET', 'BLOCK',
  '{"IPSetReferenceStatement": {"ARN": "arn:aws:wafv2:eu-west-1:111122223333:regional/ipset/sas-platform-blocklist/ips-1"}}',
  NULL, NULL, NULL, NULL, NULL, '{}', NULL, 310, 310, 0, 0, 100),
 ('b1000000-0000-0000-0000-000000000002', 'a1000000-0000-0000-0000-000000000001', '111122223333', 'AWS-AWSManagedRulesSQLiRuleSet', 1, 'MANAGED', 'BLOCK',
  '{"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet", "Version": "Version_1.0"}}',
  'AWSManagedRulesSQLiRuleSet', 'AWS', 'Version_1.0', 'Version_1.5', 'OUTDATED', ARRAY['SQLi_BODY'], NULL, 4820, 4820, 0, 3, 94),
 ('b1000000-0000-0000-0000-000000000003', 'a1000000-0000-0000-0000-000000000001', '111122223333', 'AWS-AWSManagedRulesCommonRuleSet', 2, 'MANAGED', 'BLOCK',
  '{"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}',
  'AWSManagedRulesCommonRuleSet', 'AWS', 'Version_1.12', 'Version_1.12', 'CURRENT', '{}', NULL, 43080, 43080, 0, 11, 97),
 ('b1000000-0000-0000-0000-000000000004', 'a1000000-0000-0000-0000-000000000001', '111122223333', 'Custom-Checkout-RateLimit', 3, 'RATE_BASED', 'COUNT',
  '{"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}}', NULL, NULL, NULL, NULL, NULL, '{}', 100, 4862, 0, 4862, 0, 0),
 ('b1000000-0000-0000-0000-000000000005', 'a1000000-0000-0000-0000-000000000002', '444455556666', 'AWS-AWSManagedRulesKnownBadInputsRuleSet', 1, 'MANAGED', 'BLOCK',
  '{"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesKnownBadInputsRuleSet"}}',
  'AWSManagedRulesKnownBadInputsRuleSet', 'AWS', 'Version_1.18', 'Version_1.20', 'OUTDATED', '{}', NULL, 12400, 12400, 0, 0, 100),
 ('b1000000-0000-0000-0000-000000000006', 'a1000000-0000-0000-0000-000000000003', '777788889999', 'AWS-AWSManagedRulesCommonRuleSet', 1, 'MANAGED', 'COUNT',
  '{"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}',
  'AWSManagedRulesCommonRuleSet', 'AWS', 'Version_1.12', 'Version_1.12', 'CURRENT', '{}', NULL, 2500, 0, 2500, 0, 0);

INSERT INTO managed_rule_versions (webacl_id, rule_id, vendor_name, managed_group_name, current_version, available_version, version_status) VALUES
 ('a1000000-0000-0000-0000-000000000001', 'b1000000-0000-0000-0000-000000000002', 'AWS', 'AWSManagedRulesSQLiRuleSet', 'Version_1.0', 'Version_1.5', 'OUTDATED'),
 ('a1000000-0000-0000-0000-000000000001', 'b1000000-0000-0000-0000-000000000003', 'AWS', 'AWSManagedRulesCommonRuleSet', 'Version_1.12', 'Version_1.12', 'CURRENT'),
 ('a1000000-0000-0000-0000-000000000002', 'b1000000-0000-0000-0000-000000000005', 'AWS', 'AWSManagedRulesKnownBadInputsRuleSet', 'Version_1.18', 'Version_1.20', 'OUTDATED'),
 ('a1000000-0000-0000-0000-000000000003', 'b1000000-0000-0000-0000-000000000006', 'AWS', 'AWSManagedRulesCommonRuleSet', 'Version_1.12', 'Version_1.12', 'CURRENT');

INSERT INTO endpoints (resource_arn, account_id, name, type, region, dns_name, internet_facing, waf_status, webacl_id,
  logging_enabled, visibility_level, requests_24h, blocked_24h) VALUES
 ('arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/prod-payments-alb/1', '111122223333', 'prod-payments-alb', 'ALB',
  'eu-west-1', 'prod-payments-alb-123.eu-west-1.elb.amazonaws.com', true, 'PROTECTED', 'a1000000-0000-0000-0000-000000000001', true, 'full', 1250000, 48210),
 ('arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/payments-internal/2', '111122223333', 'payments-internal', 'ALB',
  'eu-west-1', 'internal-payments-456.eu-west-1.elb.amazonaws.com', false, 'UNPROTECTED', NULL, false, 'none', 0, 0),
 ('arn:aws:apigateway:eu-west-1::/restapis/a1b2c3/stages/prod', '444455556666', 'core-banking-api/prod', 'APIGW',
  'eu-west-1', 'a1b2c3.execute-api.eu-west-1.amazonaws.com', true, 'PROTECTED', 'a1000000-0000-0000-0000-000000000002', false, 'sampled', 880000, 12400),
 ('arn:aws:cloudfront::777788889999:distribution/E2ONBOARD', '777788889999', 'onboard.example.com', 'CLOUDFRONT',
  'global', 'd2onb.cloudfront.net', true, 'PARTIALLY_PROTECTED', 'a1000000-0000-0000-0000-000000000003', false, 'sampled', 310000, 2100),
 ('arn:aws:elasticloadbalancing:us-east-1:777788889999:loadbalancer/app/alb-public-onboarding-prod/3', '777788889999', 'alb-public-onboarding-prod', 'ALB',
  'us-east-1', 'alb-public-onboarding-prod-789.us-east-1.elb.amazonaws.com', true, 'UNPROTECTED', NULL, false, 'none', 0, 0);

INSERT INTO entities (id, type, value, asn, organization, country, ja4, user_agent, threat_score, confidence, business_impact,
  final_risk, risk_level, classification, first_seen, last_seen, request_count, blocked_count, allowed_count, counted_count,
  targeted_accounts, targeted_uris, attack_techniques, is_allow_listed, allow_list_reason, recommended_action, metadata) VALUES
 ('c1000000-0000-0000-0000-000000000001', 'IP', '185.220.101.42', 'AS4224', 'Tor exit relay', 'RO', 't13d1516h2_8daaf6152771_b186095e22b6',
  'python-requests/2.31', 94, 92, 95, 94, 'CRITICAL', 'MALICIOUS', now() - interval '6 hours', now() - interval '6 minutes', 1282, 1240, 42, 0,
  ARRAY['111122223333'], ARRAY['/api/v2/checkout/validate', '/api/v2/login', '/admin'], ARRAY['SQLI'], false, NULL,
  'Malicious traffic was ALLOWED. Simulate a temporary IP block, then request approval (Response > Simulation).',
  '{"webacls": ["prod-payments-waf"], "not_found_ratio": 0.08, "uri_diversity_24h": 3}'),
 ('c1000000-0000-0000-0000-000000000002', 'IP', '45.155.205.233', 'AS9009', 'M247 Ltd', 'NL', NULL, 'Mozilla/5.0 zgrab/0.x',
  78, 70, 70, 75, 'HIGH', 'MALICIOUS', now() - interval '3 hours', now() - interval '20 minutes', 610, 598, 12, 0,
  ARRAY['111122223333', '444455556666'], ARRAY['/.env', '/wp-login.php', '/.git/config'], ARRAY['KNOWN_BAD_INPUT'], false, NULL,
  'Investigate; consider a rate limit or temporary block after simulation.', '{"webacls": ["prod-payments-waf", "core-banking-waf"], "not_found_ratio": 0.71}'),
 ('c1000000-0000-0000-0000-000000000003', 'IP', '103.75.190.12', 'AS60729', 'Zwiebelfreunde', 'DE', 't13d1715h2_5b57614c22b0_3d5424432f57', 'okhttp/4.9',
  66, 64, 90, 76, 'HIGH', 'SUSPICIOUS', now() - interval '2 hours', now() - interval '35 minutes', 940, 0, 0, 940,
  ARRAY['111122223333'], ARRAY['/api/v2/login'], ARRAY['CREDENTIAL_STUFFING'], false, NULL,
  'Simulate a rate-based rule on the login path.', '{"webacls": ["prod-payments-waf"], "not_found_ratio": 0.0}'),
 ('c1000000-0000-0000-0000-000000000004', 'IP', '203.0.113.25', 'AS64500', 'Card processor (partner)', 'US', NULL, 'PSP-Callback/2.0',
  12, 55, 90, 41, 'MEDIUM', 'LEGITIMATE', now() - interval '20 hours', now() - interval '2 minutes', 5400, 0, 5400, 0,
  ARRAY['111122223333'], ARRAY['/api/v2/payments/callback'], '{}', true, 'Payment PSP callbacks (PAYMENT_GATEWAY)',
  'Protected entity (Payment PSP callbacks, PAYMENT_GATEWAY): investigate only - automated blocking is denied by allow-list guardrails.',
  '{"webacls": ["prod-payments-waf"]}'),
 ('c1000000-0000-0000-0000-000000000005', 'JA4', 't13d1516h2_8daaf6152771_b186095e22b6', NULL, NULL, NULL, 't13d1516h2_8daaf6152771_b186095e22b6', NULL,
  88, 80, 95, 91, 'CRITICAL', 'MALICIOUS', now() - interval '6 hours', now() - interval '6 minutes', 4862, 4820, 42, 0,
  ARRAY['111122223333', '444455556666'], ARRAY['/api/v2/checkout/validate'], ARRAY['SQLI'], false, NULL,
  'Review the campaign and simulate a JA4-scoped block.', '{"distinct_ips_24h": 18}'),
 ('c1000000-0000-0000-0000-000000000006', 'ASN', 'AS4224', NULL, 'Tor exit relays', NULL, NULL, NULL,
  70, 60, 70, 70, 'HIGH', 'SUSPICIOUS', now() - interval '6 hours', now() - interval '6 minutes', 2410, 2300, 110, 0,
  ARRAY['111122223333'], '{}', ARRAY['SQLI'], false, NULL, 'Monitor.', '{}');

INSERT INTO entity_relationships (source_entity_id, target_entity_id, relationship_type, observation_count) VALUES
 ('c1000000-0000-0000-0000-000000000001', 'c1000000-0000-0000-0000-000000000005', 'USES_JA4', 1282),
 ('c1000000-0000-0000-0000-000000000001', 'c1000000-0000-0000-0000-000000000006', 'BELONGS_TO_ASN', 1282);

INSERT INTO threat_intelligence (entity_id, provider, score, classification, confidence, tags, expires_at) VALUES
 ('c1000000-0000-0000-0000-000000000001', 'AbuseIPDB', 98, 'malicious', 98, ARRAY['tor'], now() + interval '1 day'),
 ('c1000000-0000-0000-0000-000000000001', 'VirusTotal', 100, 'malicious', 95, ARRAY['14/90 engines'], now() + interval '1 day'),
 ('c1000000-0000-0000-0000-000000000002', 'AbuseIPDB', 81, 'malicious', 80, ARRAY['Data Center/Web Hosting'], now() + interval '1 day'),
 ('c1000000-0000-0000-0000-000000000002', 'GreyNoise', 90, 'malicious', 80, ARRAY['noise'], now() + interval '1 day');

INSERT INTO campaigns (id, campaign_code, name, type, status, risk_level, confidence, shared_ja4, entity_ids, asns, countries,
  targeted_accounts, targeted_uris, techniques, total_requests, blocked_requests, allowed_requests, start_time, last_active,
  correlation_evidence, attack_story, recommended_action) VALUES
 ('d1000000-0000-0000-0000-000000000001', 'CMP-8F3A21C4', 'JA4 campaign t13d1516h2_8daaf6... (18 IPs, 4 ASNs)', 'JA4_CORRELATION', 'ACTIVE',
  'CRITICAL', 95, 't13d1516h2_8daaf6152771_b186095e22b6',
  ARRAY['c1000000-0000-0000-0000-000000000001'::uuid, 'c1000000-0000-0000-0000-000000000005'::uuid, 'c1000000-0000-0000-0000-000000000006'::uuid],
  ARRAY['AS4224', 'AS9009', 'AS60729', 'AS200052'], ARRAY['RO', 'NL', 'DE'], ARRAY['111122223333', '444455556666'],
  ARRAY['/api/v2/checkout/validate', '/api/v2/login', '/admin'], ARRAY['SQLI'], 4862, 4820, 42, now() - interval '6 hours', now() - interval '6 minutes',
  '[{"type": "shared_ja4", "label": "Shared TLS fingerprint", "value": "t13d1516h2_8daaf6152771_b186095e22b6", "detail": "18 distinct IPs in 24h"}, {"type": "asn_spread", "label": "ASNs", "value": "4", "detail": "AS4224, AS9009, AS60729, AS200052"}, {"type": "block_rate", "label": "WAF block rate", "value": "99%", "detail": "4820/4862 requests"}, {"type": "visibility", "label": "Evidence source", "value": "FULL_LOG"}]',
  '18 IPs across 4 ASNs (RO, NL, DE) presented the same TLS fingerprint t13d1516h2_8daaf6152771_b186095e22b6. They sent 4862 requests to 2 accounts, probing 3 distinct URIs. WAF blocked 4820 (99%); 42 were allowed through the COUNT-mode Custom-Checkout-RateLimit rule. Techniques observed: SQLI. Evidence source: full WAF logs.',
  'Simulate blocking the campaign IPs (or a JA4-matching rule), then request approval.');

INSERT INTO detections (type, title, description, severity, confidence, status, entity_ids, campaign_id, accounts, requests_involved,
  allowed_requests, evidence, recommended_action, fingerprint, timestamp) VALUES
 ('MALICIOUS_ALLOWED', 'Malicious traffic allowed from 185.220.101.42', '42 requests from a high-risk entity reached /api/v2/checkout/validate.',
  'CRITICAL', 90, 'OPEN', ARRAY['c1000000-0000-0000-0000-000000000001'::uuid, 'c1000000-0000-0000-0000-000000000005'::uuid],
  'd1000000-0000-0000-0000-000000000001', ARRAY['111122223333'], 42, 42,
  '[{"type": "allowed", "label": "Requests passed", "value": "42"}, {"type": "count_rule", "label": "Matched a COUNT-mode rule", "value": "yes", "detail": "Custom-Checkout-RateLimit only counted"}, {"type": "visibility", "label": "Evidence source", "value": "FULL_LOG"}]',
  'Open the investigation: check why it was allowed, then simulate a block.', 'demo-1', now() - interval '6 minutes'),
 ('SCANNER', 'Scanner activity from 45.155.205.233', '41 distinct URIs in 30 min with 98% blocked/404 responses.',
  'HIGH', 65, 'OPEN', ARRAY['c1000000-0000-0000-0000-000000000002'::uuid], NULL, ARRAY['111122223333', '444455556666'], 610, 0,
  '[{"type": "uri_diversity", "label": "Distinct URIs", "value": "41"}, {"type": "visibility", "label": "Evidence source", "value": "SAMPLED", "detail": "Counts are lower bounds (GetSampledRequests)"}]',
  'Simulate a temporary block.', 'demo-2', now() - interval '20 minutes'),
 ('CREDENTIAL_ATTACK', 'Credential attack on /api/v2/login', '940 POSTs to authentication endpoints in 30 min sharing one JA4.',
  'HIGH', 95, 'INVESTIGATING', ARRAY['c1000000-0000-0000-0000-000000000003'::uuid], NULL, ARRAY['111122223333'], 940, 0,
  '[{"type": "login_posts", "label": "Auth POSTs (30 min)", "value": "940"}, {"type": "visibility", "label": "Evidence source", "value": "FULL_LOG"}]',
  'Simulate a rate-based rule on the login path; enable ATP if allowed volume is high.', 'demo-3', now() - interval '35 minutes');

-- Raw request evidence so the simulator, timelines and "why was it allowed?" work.
INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, country, asn, http_method, host, uri, user_agent, ja4,
  action, matched_rule_name, attack_techniques, classification, source, http_request)
SELECT md5('mal-' || g), now() - (g || ' minutes')::interval, '111122223333', 'a1000000-0000-0000-0000-000000000001'::uuid, '185.220.101.42'::inet,
  'RO', 'AS4224', 'POST', 'pay.example.com', '/api/v2/checkout/validate', 'python-requests/2.31', 't13d1516h2_8daaf6152771_b186095e22b6',
  CASE WHEN g % 6 = 0 THEN 'ALLOW' ELSE 'BLOCK' END,
  CASE WHEN g % 6 = 0 THEN 'Custom-Checkout-RateLimit' ELSE 'AWS-AWSManagedRulesSQLiRuleSet:SQLi_QUERYARGUMENTS' END,
  ARRAY['SQLI'], 'MALICIOUS', 'FULL_LOG', '{}'::jsonb
FROM generate_series(1, 120) g;
INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, country, asn, http_method, host, uri, user_agent, ja4,
  action, matched_rule_name, attack_techniques, classification, source, http_request)
SELECT md5('cred-' || g), now() - ((g % 30) || ' minutes')::interval - (g || ' seconds')::interval, '111122223333',
  'a1000000-0000-0000-0000-000000000001'::uuid, '103.75.190.12'::inet, 'DE', 'AS60729', 'POST', 'pay.example.com', '/api/v2/login', 'okhttp/4.9',
  't13d1715h2_5b57614c22b0_3d5424432f57', 'COUNT', 'Custom-Checkout-RateLimit', ARRAY['CREDENTIAL_STUFFING'], 'SUSPICIOUS', 'FULL_LOG', '{}'::jsonb
FROM generate_series(1, 80) g;
INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, country, asn, http_method, host, uri, user_agent,
  action, matched_rule_name, classification, source, http_request)
SELECT md5('psp-' || g), now() - (g * 3 || ' minutes')::interval, '111122223333', 'a1000000-0000-0000-0000-000000000001'::uuid, '203.0.113.25'::inet,
  'US', 'AS64500', 'POST', 'pay.example.com', '/api/v2/payments/callback', 'PSP-Callback/2.0', 'ALLOW', NULL, 'LEGITIMATE', 'FULL_LOG', '{}'::jsonb
FROM generate_series(1, 60) g;
INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, country, asn, http_method, host, uri, user_agent,
  action, matched_rule_name, classification, source, http_request)
SELECT md5('fp-' || g), now() - (g * 7 || ' minutes')::interval, '444455556666', 'a1000000-0000-0000-0000-000000000002'::uuid, ('198.51.100.' || (g % 50 + 1))::inet,
  'GB', 'AS2856', 'POST', 'bank.example.com', '/api/v1/statements/upload', 'Mozilla/5.0', 'BLOCK',
  'AWS-AWSManagedRulesKnownBadInputsRuleSet:Host_localhost_HEADER', 'UNKNOWN', 'SAMPLED', '{}'::jsonb
FROM generate_series(1, 25) g;

INSERT INTO drift_events (drift_code, account_id, account_name, webacl_id, webacl_name, drift_type, severity, expected_state, actual_state, detected_at) VALUES
 ('DRF-7C1E09A2B4', '111122223333', 'prod-payments-04', 'a1000000-0000-0000-0000-000000000001', 'prod-payments-waf', 'RULE_ACTION_CHANGED', 'CRITICAL',
  '{"rule": "Custom-Checkout-RateLimit", "action": "BLOCK"}', '{"rule": "Custom-Checkout-RateLimit", "action": "COUNT"}', now() - interval '4 hours'),
 ('DRF-1B90FF33C2', '111122223333', 'prod-payments-04', 'a1000000-0000-0000-0000-000000000001', 'prod-payments-waf', 'MANAGED_VERSION_OUTDATED', 'MEDIUM',
  '{"rule": "AWS-AWSManagedRulesSQLiRuleSet", "version_status": "CURRENT"}', '{"rule": "AWS-AWSManagedRulesSQLiRuleSet", "version_status": "OUTDATED"}', now() - interval '2 days'),
 ('DRF-55AE0D7713', '444455556666', 'prod-core-banking-01', 'a1000000-0000-0000-0000-000000000002', 'core-banking-waf', 'MANAGED_VERSION_OUTDATED', 'MEDIUM',
  '{"rule": "AWS-AWSManagedRulesKnownBadInputsRuleSet", "version_status": "CURRENT"}', '{"rule": "AWS-AWSManagedRulesKnownBadInputsRuleSet", "version_status": "OUTDATED"}', now() - interval '1 day');

INSERT INTO allow_list_entries (cidr_or_value, ip_network, entity_type, name, category, owner, reason, created_by) VALUES
 ('203.0.113.0/24', '203.0.113.0/24', 'IP_CIDR', 'Payment PSP callbacks', 'PAYMENT_GATEWAY', 'payments-platform', 'Card processor webhook egress range', 'seed-demo'),
 ('10.0.0.0/8', '10.0.0.0/8', 'IP_CIDR', 'Corporate NAT egress', 'INTERNAL_NETWORK', 'network-engineering', 'Internal networks must never be blocked', 'seed-demo');

INSERT INTO approvals (approval_code, action_type, title, target, account_id, account_name, webacl_id, webacl_name, application,
  requested_by, requested_by_role, requested_at, reason, risk_level, ttl_hours, allow_list_check, simulation_summary, impact_scope,
  required_approver_role, previous_state, proposed_state) VALUES
 ('APR-DEMO-000001', 'TEMP_BLOCK_IP', 'Temp Block Ip: 185.220.101.42/32', '185.220.101.42/32', '111122223333', 'prod-payments-04',
  'a1000000-0000-0000-0000-000000000001', 'prod-payments-waf', '', 'soc.analyst@sas.local', 'SOC Analyst', now() - interval '5 minutes',
  'Campaign CMP-8F3A21C4: SQLi probing allowed through COUNT rule', 'MEDIUM', 1, 'PASSED',
  '{"summary": "120 would block, 0 potential false positives (0.000%)", "affected_accounts": 1, "affected_webacls": 1, "potential_false_positives": 0, "risk_reduction": "HIGH", "legitimate_impact": "NONE"}',
  '1 account(s), 1 WebACL(s)', 'Security Analyst or Security Admin', '{"ip_set": "sas-platform-blocklist"}',
  '{"op": "ip_set_add", "add": ["185.220.101.42/32"], "ip_set": {"name": "sas-platform-blocklist", "id": "ips-1", "scope": "REGIONAL", "region": "eu-west-1"}}'),
 ('APR-DEMO-000002', 'MODIFY_RULE', 'Modify Rule: Custom-Checkout-RateLimit', 'Custom-Checkout-RateLimit', '111122223333', 'prod-payments-04',
  'a1000000-0000-0000-0000-000000000001', 'prod-payments-waf', '', 'security.analyst@sas.local', 'Security Analyst', now() - interval '40 minutes',
  'Restore BLOCK after drift DRF-7C1E09A2B4', 'MEDIUM', NULL, 'PASSED',
  '{"summary": "200 would block, 0 potential false positives (0.000%)", "affected_accounts": 1, "affected_webacls": 1, "potential_false_positives": 0, "risk_reduction": "HIGH", "legitimate_impact": "NONE"}',
  '1 account(s), 1 WebACL(s)', 'Security Admin + Application Owner', '{"rule": "Custom-Checkout-RateLimit", "action": "COUNT"}',
  '{"op": "set_rule_action", "rule_name": "Custom-Checkout-RateLimit", "action": "BLOCK"}');

INSERT INTO platform_health (component, account_id, status, detail, error, affected_modules, last_success) VALUES
 ('aws_api', NULL, 'HEALTHY', 'STS and WAFv2 reachable through VPC endpoints', NULL, '{}', now() - interval '18 minutes'),
 ('queue', NULL, 'HEALTHY', 'Step Functions: last execution succeeded', NULL, '{}', now() - interval '18 minutes'),
 ('workers', NULL, 'HEALTHY', '7 pipeline Lambdas reporting', NULL, '{}', now() - interval '18 minutes'),
 ('threat_intel', NULL, 'DEGRADED', 'Degraded: GreyNoise', 'GreyNoise: GreyNoise HTTP 429', ARRAY['threat_intelligence'], now() - interval '18 minutes'),
 ('collector', '111122223333', 'HEALTHY', 'telemetry sync: 1 WebACLs, 2 endpoints, 214 new events', NULL, '{}', now() - interval '18 minutes'),
 ('collector', '444455556666', 'HEALTHY', 'telemetry sync: 1 WebACLs, 1 endpoints, 37 new events', NULL, '{}', now() - interval '22 minutes'),
 ('collector', '777788889999', 'DEGRADED', 'full sync: 1 WebACLs, 2 endpoints, 9 new events', 'endpoint_discovery APIGW/us-east-1: AccessDenied',
  ARRAY['endpoint_discovery'], now() - interval '25 minutes');
