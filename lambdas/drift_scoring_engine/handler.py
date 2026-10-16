"""sas-drift-scoring-engine: configuration drift (baseline vs current WebACL JSON) and the WAF Security Score.

Drift findings are idempotent: drift_code = hash(webacl, type, subject). A finding that disappears is RESOLVED;
one that comes back is re-OPENED. Scores store per-dimension inputs in score_evidence (Rule #1).
"""

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta

from common import db, scoring

log = logging.getLogger()
log.setLevel(logging.INFO)

ENFORCING = {"BLOCK", "CAPTCHA", "CHALLENGE"}


def effective_action(rule: dict) -> str:
    if "Action" in rule:
        return next(iter(rule["Action"])).upper()
    return "COUNT" if "Count" in rule.get("OverrideAction", {}) else "BLOCK"


def _managed_group(rule: dict) -> str | None:
    return rule.get("Statement", {}).get("ManagedRuleGroupStatement", {}).get("Name")


def diff_webacl(baseline: dict, current: dict) -> list[dict]:
    """Baseline vs current WebACL documents -> drift findings {drift_type, severity, subject, expected, actual}."""
    findings = []
    base_rules = {r["Name"]: r for r in baseline.get("Rules", [])}
    cur_rules = {r["Name"]: r for r in current.get("Rules", [])}
    for name, rule in base_rules.items():
        expected = effective_action(rule)
        if name not in cur_rules:
            critical = expected in ENFORCING and (_managed_group(rule) in scoring.CRITICAL_MANAGED_GROUPS
                                                   or "Action" in rule)
            findings.append({"drift_type": "RULE_REMOVED", "severity": "CRITICAL" if critical else "HIGH",
                             "subject": name, "expected": {"rule": name, "action": expected, "present": True},
                             "actual": {"rule": name, "present": False}})
            continue
        actual = effective_action(cur_rules[name])
        if actual != expected:
            downgrade = expected in ENFORCING and actual not in ENFORCING
            findings.append({"drift_type": "RULE_ACTION_CHANGED", "severity": "CRITICAL" if downgrade else "MEDIUM",
                             "subject": name, "expected": {"rule": name, "action": expected},
                             "actual": {"rule": name, "action": actual}})
    base_default = next(iter(baseline.get("DefaultAction", {"Allow": {}}))).upper()
    cur_default = next(iter(current.get("DefaultAction", {"Allow": {}}))).upper()
    if base_default != cur_default:
        findings.append({"drift_type": "RULE_ACTION_CHANGED",
                         "severity": "CRITICAL" if base_default == "BLOCK" else "LOW", "subject": "DefaultAction",
                         "expected": {"rule": "DefaultAction", "action": base_default},
                         "actual": {"rule": "DefaultAction", "action": cur_default}})
    if baseline.get("_logging_destination") and not current.get("_logging_destination"):
        findings.append({"drift_type": "LOGGING_DISABLED", "severity": "HIGH", "subject": "logging",
                         "expected": {"logging_destination": baseline["_logging_destination"]},
                         "actual": {"logging_destination": None}})
    removed = set(baseline.get("_associated_resources", [])) - set(current.get("_associated_resources", []))
    for resource in sorted(removed):
        findings.append({"drift_type": "ASSOCIATION_REMOVED", "severity": "CRITICAL", "subject": resource,
                         "expected": {"resource_arn": resource, "associated": True},
                         "actual": {"resource_arn": resource, "associated": False}})
    return findings


def drift_code(webacl_id, drift_type: str, subject: str) -> str:
    return "DRF-" + hashlib.sha1(f"{webacl_id}|{drift_type}|{subject}".encode()).hexdigest()[:10].upper()  # noqa: S324


UPSERT_DRIFT = """
INSERT INTO drift_events (drift_code, account_id, account_name, webacl_id, webacl_name, drift_type, severity,
                          expected_state, actual_state)
VALUES (%(code)s, %(account_id)s, %(account_name)s, %(webacl_id)s, %(webacl_name)s, %(drift_type)s, %(severity)s,
        %(expected)s, %(actual)s)
ON CONFLICT (drift_code) DO UPDATE SET
    severity = EXCLUDED.severity, actual_state = EXCLUDED.actual_state,
    status = CASE WHEN drift_events.status = 'RESOLVED' THEN 'OPEN' ELSE drift_events.status END,
    detected_at = CASE WHEN drift_events.status = 'RESOLVED' THEN now() ELSE drift_events.detected_at END
"""


def run_drift(cur) -> dict:
    cur.execute(
        "SELECT w.id, w.account_id, w.name, w.baseline_config, w.current_config, a.name AS account_name"
        " FROM web_acls w JOIN accounts a ON a.account_id = w.account_id"
        " WHERE w.baseline_config <> '{}'::jsonb AND w.current_config <> '{}'::jsonb"
    )
    acls = cur.fetchall()
    cur.execute("SELECT webacl_id, name, version_status FROM rules WHERE version_status IN ('OUTDATED', 'DEPRECATED')")
    outdated: dict = {}
    for r in cur.fetchall():
        outdated.setdefault(r["webacl_id"], []).append(r)
    opened = 0
    for acl in acls:
        findings = diff_webacl(acl["baseline_config"], acl["current_config"])
        for r in outdated.get(acl["id"], []):
            findings.append({"drift_type": "MANAGED_VERSION_OUTDATED",
                             "severity": "HIGH" if r["version_status"] == "DEPRECATED" else "MEDIUM",
                             "subject": r["name"], "expected": {"rule": r["name"], "version_status": "CURRENT"},
                             "actual": {"rule": r["name"], "version_status": r["version_status"]}})
        codes = []
        for f in findings:
            code = drift_code(acl["id"], f["drift_type"], f["subject"])
            codes.append(code)
            cur.execute(UPSERT_DRIFT, {
                "code": code, "account_id": acl["account_id"], "account_name": acl["account_name"],
                "webacl_id": acl["id"], "webacl_name": acl["name"], "drift_type": f["drift_type"],
                "severity": f["severity"], "expected": json.dumps(f["expected"]), "actual": json.dumps(f["actual"]),
            })
        opened += len(findings)
        cur.execute(
            "UPDATE drift_events SET status = 'RESOLVED' WHERE webacl_id = %s AND status <> 'RESOLVED'"
            " AND NOT (drift_code = ANY(%s))",
            (acl["id"], codes),
        )
    return {"webacls_evaluated": len(acls), "open_findings": opened}


# --- scoring --------------------------------------------------------------------------------------

WEBACL_INPUTS = """
SELECT w.id, w.account_id, w.name, w.visibility_level, w.logging_enabled, w.requests_24h,
  (SELECT count(*) FROM endpoints e WHERE e.webacl_id = w.id AND e.internet_facing) AS protected_endpoints,
  (SELECT count(*) FILTER (WHERE ev.action = 'BLOCK') FROM waf_events ev
     WHERE ev.webacl_id = w.id AND ev.timestamp > %(since)s AND ev.classification IN ('MALICIOUS', 'SUSPICIOUS'))
     AS blocked_malicious,
  (SELECT count(*) FROM waf_events ev
     WHERE ev.webacl_id = w.id AND ev.timestamp > %(since)s AND ev.classification IN ('MALICIOUS', 'SUSPICIOUS'))
     AS total_malicious,
  (SELECT count(*) FROM waf_events ev
     WHERE ev.webacl_id = w.id AND ev.timestamp > %(since)s AND ev.classification = 'MALICIOUS'
       AND ev.action = 'ALLOW') AS allowed_malicious,
  (SELECT coalesce(jsonb_agg(jsonb_build_object('name', r.name, 'managed_group_name', r.managed_group_name,
       'age_days', extract(epoch FROM (%(now)s - r.updated_at)) / 86400)), '[]'::jsonb)
     FROM rules r WHERE r.webacl_id = w.id AND r.action = 'COUNT') AS count_rules,
  (SELECT coalesce(jsonb_object_agg(severity, n), '{}'::jsonb) FROM (
     SELECT d.severity, count(*) AS n FROM drift_events d WHERE d.webacl_id = w.id AND d.status <> 'RESOLVED'
     GROUP BY d.severity) s) AS open_drift,
  (SELECT coalesce(array_agg(coalesce(r.version_status, 'UNKNOWN')), '{}') FROM rules r
     WHERE r.webacl_id = w.id AND r.type = 'MANAGED') AS managed_statuses
FROM web_acls w
"""


def score_webacl(row: dict, now: datetime) -> tuple[float, str, dict]:
    dims = {
        "coverage": 100.0 if row["protected_endpoints"] else 0.0,
        "blocking": scoring.d_blocking(row["blocked_malicious"], row["total_malicious"]),
        "malicious_allowed": scoring.d_malicious_allowed(row["allowed_malicious"]),
        "count_exposure": scoring.d_count_exposure(row["count_rules"]),
        "drift": scoring.d_drift(row["open_drift"]),
        "managed_versions": scoring.d_managed_versions(list(row["managed_statuses"])),
        "logging": scoring.d_logging(row["logging_enabled"]),
    }
    inputs = {
        "coverage": {"internet_facing_endpoints_attached": row["protected_endpoints"]},
        "blocking": {"blocked_malicious_24h": row["blocked_malicious"], "malicious_or_suspicious_24h":
                     row["total_malicious"]},
        "malicious_allowed": {"allowed_malicious_24h": row["allowed_malicious"]},
        "count_exposure": {"count_rules": row["count_rules"], "tuning_window_days": scoring.COUNT_TUNING_DAYS},
        "drift": {"open_by_severity": row["open_drift"]},
        "managed_versions": {"statuses": list(row["managed_statuses"])},
        "logging": {"enabled": row["logging_enabled"]},
    }
    evidence = {
        "dimensions": {k: {"value": round(v, 2), "weight": scoring.WAF_WEIGHTS[k], "inputs": inputs[k]}
                       for k, v in dims.items()},
        "visibility_level": row["visibility_level"],
        "note": "Request-level dimensions use sampled requests" if row["visibility_level"] == "sampled" else None,
        "computed_at": now.isoformat(),
    }
    return scoring.waf_score(dims), scoring.webacl_confidence(row["visibility_level"]), evidence


def run_scoring(cur, now: datetime) -> dict:
    cur.execute(WEBACL_INPUTS, {"since": now - timedelta(hours=24), "now": now})
    rows = cur.fetchall()
    per_account: dict[str, list] = {}
    for row in rows:
        score, conf, evidence = score_webacl(row, now)
        cur.execute(
            "UPDATE web_acls SET security_score = %s, score_confidence = %s, score_evidence = %s,"
            " malicious_allowed_24h = %s WHERE id = %s",
            (score, conf, json.dumps(evidence), row["allowed_malicious"], row["id"]),
        )
        per_account.setdefault(row["account_id"], []).append((row, evidence))

    cur.execute(
        "SELECT a.account_id, a.status,"
        " count(e.id) FILTER (WHERE e.internet_facing) AS exposed,"
        " count(e.id) FILTER (WHERE e.internet_facing AND e.webacl_id IS NOT NULL) AS protected"
        " FROM accounts a LEFT JOIN endpoints e ON e.account_id = a.account_id GROUP BY a.account_id, a.status"
    )
    for acct in cur.fetchall():
        scored = per_account.get(acct["account_id"], [])
        dims = {"coverage": scoring.d_coverage(acct["protected"], acct["exposed"])}
        total_weight = sum(r["requests_24h"] + 1 for r, _ in scored)  # traffic-weighted; +1 keeps idle ACLs counted
        for dim in scoring.WAF_WEIGHTS:
            if dim == "coverage":
                continue
            dims[dim] = (sum((r["requests_24h"] + 1) * ev["dimensions"][dim]["value"] for r, ev in scored)
                         / total_weight) if scored else 0.0
        evidence = {
            "dimensions": {k: {"value": round(v, 2), "weight": scoring.WAF_WEIGHTS[k]} for k, v in dims.items()},
            "coverage": {"internet_facing_endpoints": acct["exposed"], "attached": acct["protected"]},
            "webacls": [r["name"] for r, _ in scored], "aggregation": "traffic-weighted mean of WebACL dimensions",
            "computed_at": now.isoformat(),
        }
        confidence = scoring.account_confidence([r["visibility_level"] for r, _ in scored])
        if acct["status"] == "UNAVAILABLE":
            confidence = "NONE"
        cur.execute(
            "UPDATE accounts SET security_score = %s, score_confidence = %s, score_evidence = %s WHERE account_id = %s",
            (scoring.waf_score(dims), confidence, json.dumps(evidence), acct["account_id"]),
        )
    return {"webacls_scored": len(rows)}


def lambda_handler(event: dict, _context, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    with db.transaction() as cur:
        drift = run_drift(cur)  # drift first: the drift dimension reads the findings it just wrote
        scores = run_scoring(cur, now)
    summary = {**drift, **scores}
    log.info("drift/scoring summary %s", summary)
    return summary
