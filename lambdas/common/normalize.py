"""Normalize WAF sampled requests and full S3 log records into `waf_events` rows (one shape for both sources).

Dedup hash (CLAUDE.md 5): SHA256(WebACL_ARN || ClientIP || Timestamp_ms || Method || URI || RuleName).
Classification is left UNKNOWN here; the detection engine (Milestone 3) classifies with TI + behaviour context.
"""

import hashlib
import json
from datetime import UTC, datetime

DEFAULT_ACTION_RULE = "Default_Action"

# TLS fingerprints only reach WAF sampled requests if something upstream injects them as headers (CloudFront
# viewer-request function / origin-request policy) or a custom rule adds a label. Full logs carry them natively.
JA3_HEADERS = ("cloudfront-viewer-ja3-fingerprint", "x-ja3-fingerprint", "x-ja3")
JA4_HEADERS = ("cloudfront-viewer-ja4-fingerprint", "x-ja4-fingerprint", "x-ja4")
JA3_LABEL_PREFIX = "sas:ja3:"
JA4_LABEL_PREFIX = "sas:ja4:"
COUNTRY_LABEL_PREFIX = "awswaf:clientip:geo:country:"

# Managed rule group (or rule name) substring -> attack technique. Evidence of what matched, not a verdict.
TECHNIQUES = (
    ("sqli", "SQLI"),
    ("sqlinjection", "SQLI"),
    ("crosssitescripting", "XSS"),
    ("xss", "XSS"),
    ("knownbadinputs", "KNOWN_BAD_INPUT"),
    ("log4j", "LOG4J"),
    ("linuxrule", "LFI"),
    ("unixrule", "LFI"),
    ("windowsrule", "RCE"),
    ("phprule", "RCE"),
    ("ipreputation", "BAD_REPUTATION_IP"),
    ("anonymousip", "ANONYMOUS_IP"),
    ("botcontrol", "BOT"),
    ("atp", "CREDENTIAL_STUFFING"),
    ("acfp", "FAKE_ACCOUNT_CREATION"),
    ("ratelimit", "RATE_ABUSE"),
    ("rate-limit", "RATE_ABUSE"),
)


def event_hash(webacl_arn: str, client_ip: str, timestamp_ms: int, method: str, uri: str, rule_name: str) -> str:
    raw = "||".join([webacl_arn, client_ip, str(timestamp_ms), method, uri, rule_name or ""])
    return hashlib.sha256(raw.encode()).hexdigest()


def techniques_for(*names: str | None) -> list[str]:
    found: list[str] = []
    for name in names:
        lowered = (name or "").lower().replace("_", "")
        for needle, technique in TECHNIQUES:
            if needle.replace("_", "") in lowered and technique not in found:
                found.append(technique)
    return found


def _header(headers: dict[str, str], names: tuple[str, ...]) -> str | None:
    return next((headers[n] for n in names if headers.get(n)), None)


def _label_value(labels: list[str], prefix: str) -> str | None:
    return next((label[len(prefix):] for label in labels if label.startswith(prefix)), None)


def _row(*, webacl_arn: str, webacl_db_id, account_id: str, ts_ms: int, client_ip: str, country: str | None,
         method: str, uri: str, headers: dict[str, str], labels: list[str], action: str, rule_name: str,
         rule_groups: list[str], ja3: str | None, ja4: str | None, source: str, http_request: dict) -> dict:
    return {
        "event_hash": event_hash(webacl_arn, client_ip, ts_ms, method, uri, rule_name),
        "timestamp": datetime.fromtimestamp(ts_ms / 1000, tz=UTC),
        "account_id": account_id,
        "webacl_id": webacl_db_id,
        "client_ip": client_ip,
        "country": country or _label_value(labels, COUNTRY_LABEL_PREFIX),
        "http_method": method,
        "host": headers.get("host"),
        "uri": uri,
        "user_agent": headers.get("user-agent"),
        "ja3": ja3 or _header(headers, JA3_HEADERS) or _label_value(labels, JA3_LABEL_PREFIX),
        "ja4": ja4 or _header(headers, JA4_HEADERS) or _label_value(labels, JA4_LABEL_PREFIX),
        "action": action.upper(),
        "matched_rule_name": rule_name,
        "rule_groups": rule_groups,
        "labels": labels,
        "attack_techniques": techniques_for(rule_name, *rule_groups, *labels),
        "source": source,
        "http_request": json.dumps(http_request),
    }


def from_sampled_request(sample: dict, *, webacl_arn: str, webacl_db_id, account_id: str, rule_name: str) -> dict:
    """wafv2:GetSampledRequests SampledHTTPRequest -> waf_events row (source SAMPLED)."""
    request = sample["Request"]
    headers = {h["Name"].lower(): h["Value"] for h in request.get("Headers", [])}
    labels = [label["Name"] for label in sample.get("Labels", [])]
    ts = sample["Timestamp"]
    ts_ms = int(ts.timestamp() * 1000) if isinstance(ts, datetime) else int(ts)
    action = sample.get("Action") or "ALLOW"
    group = sample.get("RuleNameWithinRuleGroup")
    return _row(
        webacl_arn=webacl_arn, webacl_db_id=webacl_db_id, account_id=account_id, ts_ms=ts_ms,
        client_ip=request["ClientIP"], country=request.get("Country"), method=request.get("Method", "GET"),
        uri=request.get("URI", "/"), headers=headers, labels=labels, action=action,
        rule_name=f"{rule_name}:{group}" if group else rule_name, rule_groups=[rule_name] if group else [],
        ja3=None, ja4=None, source="SAMPLED",
        http_request={
            "headers": request.get("Headers", []), "http_version": request.get("HTTPVersion"),
            "weight": sample.get("Weight"), "response_code_sent": sample.get("ResponseCodeSent"),
            "overridden_action": sample.get("OverriddenAction"),
        },
    )


def from_log_record(record: dict, *, webacl_db_id, account_id: str) -> dict:
    """WAF full log JSON line -> waf_events row (source FULL_LOG)."""
    request = record["httpRequest"]
    headers = {h["name"].lower(): h["value"] for h in request.get("headers", [])}
    labels = [label["name"] for label in record.get("labels") or []]
    groups = [g["ruleGroupId"].rsplit("/", 1)[-1] for g in record.get("ruleGroupList") or [] if g.get("ruleGroupId")]
    rule_name = record.get("terminatingRuleId") or DEFAULT_ACTION_RULE
    return _row(
        webacl_arn=record["webaclId"], webacl_db_id=webacl_db_id, account_id=account_id,
        ts_ms=int(record["timestamp"]), client_ip=request["clientIp"], country=request.get("country"),
        method=request.get("httpMethod", "GET"), uri=request.get("uri", "/"), headers=headers, labels=labels,
        action=record.get("action", "ALLOW"), rule_name=rule_name, rule_groups=groups,
        ja3=record.get("ja3Fingerprint"), ja4=record.get("ja4Fingerprint"), source="FULL_LOG",
        http_request={
            "headers": request.get("headers", []), "args": request.get("args"),
            "http_version": request.get("httpVersion"), "request_id": request.get("requestId"),
            "http_source": record.get("httpSourceName"), "http_source_id": record.get("httpSourceId"),
            "response_code_sent": record.get("responseCodeSent"),
            "terminating_rule_type": record.get("terminatingRuleType"),
        },
    )


INSERT_EVENT = """
INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, country, http_method, host, uri,
    user_agent, ja3, ja4, action, matched_rule_name, rule_groups, labels, attack_techniques, source, http_request)
VALUES (%(event_hash)s, %(timestamp)s, %(account_id)s, %(webacl_id)s, %(client_ip)s, %(country)s, %(http_method)s,
    %(host)s, %(uri)s, %(user_agent)s, %(ja3)s, %(ja4)s, %(action)s, %(matched_rule_name)s, %(rule_groups)s,
    %(labels)s, %(attack_techniques)s, %(source)s, %(http_request)s::jsonb)
ON CONFLICT (event_hash) DO NOTHING
"""


def insert_events(cur, rows: list[dict]) -> int:
    """Insert rows, skipping duplicates by event_hash. Returns rows actually inserted."""
    inserted = 0
    for row in rows:
        cur.execute(INSERT_EVENT, row)
        inserted += cur.rowcount
    return inserted
