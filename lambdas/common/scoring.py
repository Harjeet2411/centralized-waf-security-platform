"""Scoring models (CLAUDE.md section 6). Pure functions: every engine stores the inputs next to the result.

WAF Security Score  S = 0.25 coverage + 0.20 blocking + 0.20 malicious_allowed + 0.10 count_exposure
                        + 0.10 drift + 0.10 managed_versions + 0.05 logging           (each dimension 0-100)
Entity              T = min(100, 0.35 T_TI + 0.25 T_WAF + 0.20 T_JA4 + 0.20 T_Campaign)
                    R = round(0.60 T + 0.40 B);  CRITICAL if R >= 85 or malicious-allowed > 0
"""

import math

WAF_WEIGHTS = {
    "coverage": 0.25, "blocking": 0.20, "malicious_allowed": 0.20, "count_exposure": 0.10,
    "drift": 0.10, "managed_versions": 0.10, "logging": 0.05,
}
COUNT_TUNING_DAYS = 14  # a rule may sit in COUNT this long for tuning before it costs score
CRITICAL_MANAGED_GROUPS = {
    "AWSManagedRulesCommonRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
}
TECHNIQUE_SEVERITY = {
    "RCE": 35, "LOG4J": 35, "SQLI": 30, "XSS": 30, "LFI": 30, "CREDENTIAL_STUFFING": 30, "KNOWN_BAD_INPUT": 25,
    "FAKE_ACCOUNT_CREATION": 20, "BAD_REPUTATION_IP": 15, "BOT": 15, "RATE_ABUSE": 15, "ANONYMOUS_IP": 10,
}
CAMPAIGN_RISK_SCORE = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
ENVIRONMENT_IMPACT = {"production": 70, "shared-services": 50, "security": 50, "staging": 40, "development": 20}
SENSITIVE_ALLOWED_IMPACT = 90  # PRD 4.2: ALLOW on a production payment/auth endpoint => B >= 90


# --- WAF Security Score dimensions -----------------------------------------------------------------

def d_coverage(protected: int, exposed: int) -> float:
    return 100.0 if exposed == 0 else 100.0 * protected / exposed


def d_blocking(blocked_malicious: int, total_malicious: int) -> float:
    """Share of MALICIOUS/SUSPICIOUS requests that were blocked. No such traffic -> nothing slipped through."""
    return 100.0 if total_malicious == 0 else 100.0 * blocked_malicious / total_malicious


def d_malicious_allowed(allowed_malicious: int) -> float:
    # 0 -> 100, 5 -> 50, 45 -> 10. Smooth, never negative, every allowed malicious request costs something.
    return 100.0 / (1 + allowed_malicious / 5)


def d_count_exposure(count_rules: list[dict]) -> float:
    """count_rules: [{"managed_group_name", "age_days"}] for rules currently in COUNT."""
    penalty = sum(
        40 if r.get("managed_group_name") in CRITICAL_MANAGED_GROUPS else 25
        for r in count_rules if r["age_days"] > COUNT_TUNING_DAYS
    )
    return max(0.0, 100.0 - penalty)


def d_drift(open_by_severity: dict[str, int]) -> float:
    penalty = (40 * open_by_severity.get("CRITICAL", 0) + 20 * open_by_severity.get("HIGH", 0)
               + 5 * (open_by_severity.get("MEDIUM", 0) + open_by_severity.get("LOW", 0)))
    return max(0.0, 100.0 - penalty)


def d_managed_versions(statuses: list[str]) -> float:
    """UNKNOWN versions are excluded (no evidence either way); no managed groups -> nothing outdated."""
    known = [s for s in statuses if s != "UNKNOWN"]
    return 100.0 if not known else 100.0 * known.count("CURRENT") / len(known)


def d_logging(enabled: bool) -> float:
    return 100.0 if enabled else 0.0


def waf_score(dims: dict[str, float], weights: dict[str, float] = WAF_WEIGHTS) -> float:
    return round(sum(weights[k] * dims[k] for k in weights), 2)


def webacl_confidence(visibility_level: str) -> str:
    """NONE also covers metrics-only WebACLs: without request samples the traffic dimensions are unverified."""
    return {"full": "FULL", "sampled": "SAMPLED"}.get(visibility_level, "NONE")


def account_confidence(levels: list[str]) -> str:
    if not levels:
        return "NONE"
    if all(level == "full" for level in levels):
        return "FULL"
    if "full" in levels:
        return "PARTIAL"  # some WebACLs fully logged, the rest sampled (PRD 4.1)
    if "sampled" in levels:
        return "SAMPLED"
    return "NONE"


# --- entity scores ---------------------------------------------------------------------------------

def t_ti(rows: list[dict]) -> float:
    """Confidence-weighted mean of provider scores. rows: [{"score", "confidence"}]."""
    weight = sum(float(r["confidence"]) for r in rows)
    return 0.0 if weight == 0 else sum(float(r["score"]) * float(r["confidence"]) for r in rows) / weight


def t_waf(blocked: int, total: int, techniques: list[str], uri_diversity: int) -> float:
    block_part = 50.0 * blocked / total if total else 0.0
    technique_part = max((TECHNIQUE_SEVERITY.get(t, 10) for t in techniques), default=0)
    probing_part = min(20.0, uri_diversity / 25 * 20)
    return min(100.0, block_part + technique_part + probing_part)


def t_ja4(blocked: int, total: int, distinct_ips: int) -> float:
    """Malice of a TLS fingerprint: its block ratio, raised when it is shared by many IPs."""
    if total == 0:
        return 0.0
    return min(100.0, 100.0 * blocked / total + (20.0 if distinct_ips >= 5 else 0.0))


def t_campaign(risk_level: str | None) -> float:
    return float(CAMPAIGN_RISK_SCORE.get(risk_level or "", 0))


def threat_score(ti: float, waf: float, ja4: float, campaign: float) -> float:
    return round(min(100.0, 0.35 * ti + 0.25 * waf + 0.20 * ja4 + 0.20 * campaign), 2)


def confidence(request_count: int, ti_providers: int, has_full_log: bool) -> float:
    # ponytail: weights not specified by the PRD (sample size <= 40, corroborating feeds 15 each <= 45,
    # full-log visibility 15). Revisit with SOC once real distributions are known.
    sample = min(40.0, 10.0 * math.log10(1 + request_count))
    return round(min(100.0, sample + 15.0 * min(ti_providers, 3) + (15.0 if has_full_log else 0.0)), 2)


def business_impact(environment: str | None, sensitive_allowed_in_prod: bool) -> float:
    base = float(ENVIRONMENT_IMPACT.get(environment or "", 30))
    return max(base, SENSITIVE_ALLOWED_IMPACT) if sensitive_allowed_in_prod else base


def final_risk(threat: float, impact: float) -> int:
    return round(0.60 * threat + 0.40 * impact)


def risk_level(risk: int, malicious_allowed: int) -> str:
    if risk >= 85 or malicious_allowed > 0:
        return "CRITICAL"
    if risk >= 70:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


def classification(threat: float, allow_listed: bool) -> str:
    if threat >= 75:
        return "MALICIOUS"  # allow-listing never hides malice; it only blocks automated response
    if allow_listed:
        return "LEGITIMATE"
    if threat >= 40:
        return "SUSPICIOUS"
    return "UNKNOWN"
