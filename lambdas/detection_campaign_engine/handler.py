"""sas-detection-campaign-engine: entity intelligence, JA3/JA4 correlation, campaigns and behavioural detections.

Order per run (one transaction):
 1. fold newly *ingested* events (watermark on waf_events.ingested_at) into entities + relationships
 2. score entities (T, C, B, R) from 24h behaviour, cached TI, JA4 malice, allow-list
 3. JA4 campaigns over 24h -> rescore members with the campaign term
 4. classify the last 24h of events from entity verdicts (feeds the WAF score's blocking dimensions)
 5. behavioural detections over the last 30 minutes (SCANNER, CREDENTIAL_ATTACK, DISTRIBUTED_ATTACK,
    SLOW_DISTRIBUTED, MALICIOUS_ALLOWED) + one JA4_CORRELATION detection per campaign

Visibility honesty: WAF never sees origin 404s, so SCANNER's 404 term only counts WAF-generated responses; on
SAMPLED data every count is a lower bound. Detections carry the visibility they were computed from.
"""

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta

from common import db, scoring

log = logging.getLogger()
log.setLevel(logging.INFO)

ENGINE = "detection_campaign"
SENSITIVE_PATH = r"^/(login|signin|auth|oauth|token|payments?|checkout|api/v[0-9]+/(token|auth|payments?|checkout))"
CREDENTIAL_PATH = r"^/(login|auth|oauth/token|api/v1/token)"
RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# entity type -> key expression over waf_events alias b
ENTITY_KEYS = {"IP": "host(b.client_ip)", "JA4": "b.ja4", "JA3": "b.ja3", "ASN": "b.asn", "USER_AGENT": "b.user_agent"}
RELATIONSHIPS = [("JA4", "b.ja4", "USES_JA4"), ("JA3", "b.ja3", "USES_JA3"), ("ASN", "b.asn", "BELONGS_TO_ASN"),
                 ("USER_AGENT", "b.user_agent", "USES_UA")]

UPSERT_ENTITIES = """
WITH b AS (SELECT * FROM waf_events b WHERE b.ingested_at > %(wm)s AND b.ingested_at <= %(upto)s AND {key} IS NOT NULL),
agg AS (
  SELECT {key} AS value, max(b.asn) AS asn, max(b.organization) AS org, max(b.country) AS country,
         max(b.ja3) AS ja3, max(b.ja4) AS ja4, max(b.user_agent) AS ua, min(b.timestamp) AS first_seen,
         max(b.timestamp) AS last_seen, count(*) AS n, count(*) FILTER (WHERE b.action = 'BLOCK') AS blocked,
         count(*) FILTER (WHERE b.action = 'ALLOW') AS allowed, count(*) FILTER (WHERE b.action = 'COUNT') AS counted,
         array_agg(DISTINCT b.account_id) AS accts, (array_agg(DISTINCT b.uri))[1:200] AS uris,
         jsonb_agg(DISTINCT w.name) AS webacls
  FROM b JOIN web_acls w ON w.id = b.webacl_id GROUP BY 1),
tech AS (SELECT {key} AS value, array_agg(DISTINCT t) AS techs FROM b, unnest(b.attack_techniques) t GROUP BY 1)
INSERT INTO entities (type, value, asn, organization, country, ja3, ja4, user_agent, first_seen, last_seen,
                      request_count, blocked_count, allowed_count, counted_count, targeted_accounts, targeted_uris,
                      attack_techniques, metadata)
SELECT %(type)s, agg.value, agg.asn, agg.org, agg.country, agg.ja3, agg.ja4, agg.ua, agg.first_seen, agg.last_seen,
       agg.n, agg.blocked, agg.allowed, agg.counted, agg.accts, agg.uris, coalesce(tech.techs, '{{}}'),
       jsonb_build_object('webacls', agg.webacls)
FROM agg LEFT JOIN tech USING (value)
ON CONFLICT (type, value) DO UPDATE SET
  asn = coalesce(EXCLUDED.asn, entities.asn), organization = coalesce(EXCLUDED.organization, entities.organization),
  country = coalesce(EXCLUDED.country, entities.country), ja3 = coalesce(EXCLUDED.ja3, entities.ja3),
  ja4 = coalesce(EXCLUDED.ja4, entities.ja4), user_agent = coalesce(EXCLUDED.user_agent, entities.user_agent),
  first_seen = least(entities.first_seen, EXCLUDED.first_seen),
  last_seen = greatest(entities.last_seen, EXCLUDED.last_seen),
  request_count = entities.request_count + EXCLUDED.request_count,
  blocked_count = entities.blocked_count + EXCLUDED.blocked_count,
  allowed_count = entities.allowed_count + EXCLUDED.allowed_count,
  counted_count = entities.counted_count + EXCLUDED.counted_count,
  targeted_accounts = ARRAY(SELECT DISTINCT unnest(coalesce(entities.targeted_accounts, '{{}}')
                                                    || EXCLUDED.targeted_accounts)),
  targeted_uris = (ARRAY(SELECT DISTINCT unnest(coalesce(entities.targeted_uris, '{{}}')
                                                 || EXCLUDED.targeted_uris)))[1:200],
  attack_techniques = ARRAY(SELECT DISTINCT unnest(coalesce(entities.attack_techniques, '{{}}')
                                                    || EXCLUDED.attack_techniques)),
  metadata = entities.metadata || jsonb_build_object('webacls', (
    SELECT coalesce(jsonb_agg(DISTINCT x), '[]'::jsonb) FROM jsonb_array_elements_text(
      coalesce(entities.metadata->'webacls', '[]'::jsonb) || coalesce(EXCLUDED.metadata->'webacls', '[]'::jsonb)) x))
"""

UPSERT_RELATIONSHIPS = """
WITH b AS (SELECT * FROM waf_events b WHERE b.ingested_at > %(wm)s AND b.ingested_at <= %(upto)s AND {key} IS NOT NULL)
INSERT INTO entity_relationships (source_entity_id, target_entity_id, relationship_type, observation_count,
                                  first_observed, last_observed)
SELECT s.id, t.id, %(rel)s, count(*), min(b.timestamp), max(b.timestamp)
FROM b JOIN entities s ON s.type = 'IP' AND s.value = host(b.client_ip)
       JOIN entities t ON t.type = %(ttype)s AND t.value = {key}
GROUP BY s.id, t.id
ON CONFLICT (source_entity_id, target_entity_id, relationship_type) DO UPDATE SET
  observation_count = entity_relationships.observation_count + EXCLUDED.observation_count,
  first_observed = least(entity_relationships.first_observed, EXCLUDED.first_observed),
  last_observed = greatest(entity_relationships.last_observed, EXCLUDED.last_observed)
"""


def fold_events(cur, wm, upto) -> None:
    for etype, key in ENTITY_KEYS.items():
        cur.execute(UPSERT_ENTITIES.format(key=key), {"wm": wm, "upto": upto, "type": etype})
    for ttype, key, rel in RELATIONSHIPS:
        cur.execute(UPSERT_RELATIONSHIPS.format(key=key), {"wm": wm, "upto": upto, "rel": rel, "ttype": ttype})


# --- scoring ----------------------------------------------------------------------------------------

def _window_stats(cur, since) -> tuple[dict, dict]:
    cur.execute(
        """
        SELECT host(e.client_ip) AS value, count(*) AS total, count(*) FILTER (WHERE e.action = 'BLOCK') AS blocked,
               count(*) FILTER (WHERE e.action = 'ALLOW') AS allowed, count(DISTINCT e.uri) AS uri_diversity,
               count(*) FILTER (WHERE e.http_request->>'response_code_sent' = '404') AS not_found,
               bool_or(e.source = 'FULL_LOG') AS full_log,
               bool_or(e.action = 'ALLOW' AND a.environment = 'production' AND e.uri ~* %(sensitive)s)
                 AS sensitive_allowed,
               array_agg(DISTINCT a.environment) AS environments,
               coalesce(array_agg(DISTINCT e.ja4) FILTER (WHERE e.ja4 IS NOT NULL), '{}') AS ja4s
        FROM waf_events e JOIN accounts a ON a.account_id = e.account_id
        WHERE e.timestamp > %(since)s GROUP BY 1
        """,
        {"since": since, "sensitive": SENSITIVE_PATH},
    )
    ips = {r["value"]: r for r in cur.fetchall()}
    cur.execute(
        "SELECT ja4 AS value, count(*) AS total, count(*) FILTER (WHERE action = 'BLOCK') AS blocked,"
        " count(DISTINCT client_ip) AS ips FROM waf_events WHERE timestamp > %s AND ja4 IS NOT NULL GROUP BY ja4",
        (since,),
    )
    ja4s = {r["value"]: r for r in cur.fetchall()}
    return ips, ja4s


def _recommendation(level: str, malicious_allowed: int, protected: dict | None) -> str:
    if protected:
        return (f"Protected entity ({protected['name']}, {protected['category']}): investigate only - automated "
                "blocking is denied by allow-list guardrails.")
    if level == "CRITICAL":
        lead = "Malicious traffic was ALLOWED. " if malicious_allowed else ""
        return f"{lead}Simulate a temporary IP block, then request approval (Response > Simulation)."
    if level == "HIGH":
        return "Investigate; consider a rate limit or temporary block after simulation."
    if level == "MEDIUM":
        return "Monitor; review in the next triage cycle."
    return "No action required."


def score_entities(cur, now: datetime, campaign_risk: dict) -> dict:
    """Scores IP and JA4 entities active in the last 24h. Returns {entity_id: (final_risk, level)}."""
    since = now - timedelta(hours=24)
    ip_stats, ja4_stats = _window_stats(cur, since)
    cur.execute(
        "SELECT id, type, value, request_count, attack_techniques, targeted_uris FROM entities"
        " WHERE type IN ('IP', 'JA4') AND last_seen > %s",
        (since,),
    )
    entities = cur.fetchall()
    ids = [e["id"] for e in entities]
    cur.execute("SELECT entity_id, score, confidence FROM threat_intelligence WHERE entity_id = ANY(%s)", (ids,))
    ti: dict = {}
    for r in cur.fetchall():
        ti.setdefault(r["entity_id"], []).append(r)
    cur.execute(
        """
        SELECT DISTINCT ON (e.id) e.id, a.name, a.category
        FROM entities e JOIN allow_list_entries a ON a.is_active AND (
          (a.ip_network IS NOT NULL AND (CASE WHEN e.type = 'IP' THEN e.value::inet END) <<= a.ip_network)
          OR (a.entity_type = 'ASN' AND e.type = 'IP' AND e.asn = a.cidr_or_value))
        WHERE e.id = ANY(%s)
        """,
        (ids,),
    )
    protected = {r["id"]: r for r in cur.fetchall()}

    ja4_threat = {v: scoring.t_ja4(s["blocked"], s["total"], s["ips"]) for v, s in ja4_stats.items()}
    results, ja4_impact = {}, {}
    updates = []
    for e in sorted(entities, key=lambda x: x["type"] != "IP"):  # IPs first: JA4 impact derives from its IPs
        techniques = list(e["attack_techniques"] or [])
        if e["type"] == "IP":
            s = ip_stats.get(e["value"], {})
            total, blocked = s.get("total", 0), s.get("blocked", 0)
            t_waf = scoring.t_waf(blocked, total, techniques, s.get("uri_diversity", 0))
            t_ja4 = max((ja4_threat.get(j, 0.0) for j in s.get("ja4s", [])), default=0.0)
            env = max(s.get("environments") or [None], key=lambda x: scoring.ENVIRONMENT_IMPACT.get(x or "", 0))
            impact = scoring.business_impact(env, bool(s.get("sensitive_allowed")))
            for j in s.get("ja4s", []):
                ja4_impact[j] = max(ja4_impact.get(j, 0.0), impact)
            full_log = bool(s.get("full_log"))
            allowed_24h = s.get("allowed", 0)
            meta = {"uri_diversity_24h": s.get("uri_diversity", 0),
                    "not_found_ratio": round(s.get("not_found", 0) / total, 4) if total else 0.0}
        else:
            s = ja4_stats.get(e["value"], {})
            total, blocked = s.get("total", 0), s.get("blocked", 0)
            t_waf = scoring.t_waf(blocked, total, techniques, len(e["targeted_uris"] or []))
            t_ja4 = ja4_threat.get(e["value"], 0.0)
            impact = ja4_impact.get(e["value"], 30.0)
            full_log, allowed_24h = False, 0
            meta = {"distinct_ips_24h": s.get("ips", 0)}
        threat = scoring.threat_score(scoring.t_ti(ti.get(e["id"], [])), t_waf, t_ja4,
                                      scoring.t_campaign(campaign_risk.get(e["id"])))
        prot = protected.get(e["id"])
        malicious_allowed = allowed_24h if threat >= 75 and not prot else 0
        risk = scoring.final_risk(threat, impact)
        level = scoring.risk_level(risk, malicious_allowed)
        conf = scoring.confidence(e["request_count"], len(ti.get(e["id"], [])), full_log)
        meta["score_inputs"] = {"t_ti": round(scoring.t_ti(ti.get(e["id"], [])), 2), "t_waf": round(t_waf, 2),
                                "t_ja4": round(t_ja4, 2), "t_campaign": scoring.t_campaign(campaign_risk.get(e["id"])),
                                "malicious_allowed_24h": malicious_allowed}
        updates.append((threat, conf, impact, risk, level, scoring.classification(threat, bool(prot)), bool(prot),
                        f"{prot['name']} ({prot['category']})" if prot else None,
                        _recommendation(level, malicious_allowed, prot), json.dumps(meta), e["id"]))
        results[e["id"]] = (risk, level)
    cur.executemany(
        "UPDATE entities SET threat_score = %s, confidence = %s, business_impact = %s, final_risk = %s,"
        " risk_level = %s, classification = %s, is_allow_listed = %s, allow_list_reason = %s,"
        " recommended_action = %s, metadata = metadata || %s::jsonb WHERE id = %s",
        updates,
    )
    return results


# --- campaigns --------------------------------------------------------------------------------------

def campaign_code(ja4: str) -> str:
    return "CMP-" + hashlib.sha1(ja4.encode()).hexdigest()[:8].upper()  # noqa: S324


def attack_story(c: dict, top_uris: list[str]) -> str:
    rate = c["blocked"] / c["total"] if c["total"] else 0
    techniques = f" Techniques observed: {', '.join(c['techniques'])}." if c["techniques"] else ""
    visibility = "full WAF logs" if c["full_log"] else "sampled requests only (counts are lower bounds)"
    return (
        f"Between {c['start_time']:%Y-%m-%d %H:%M} and {c['last_active']:%Y-%m-%d %H:%M} UTC, {c['ips']} IPs across "
        f"{len(c['asns'])} ASN(s) ({', '.join(c['countries']) or 'unknown countries'}) presented the same TLS "
        f"fingerprint {c['ja4']}. They sent {c['total']} requests to {len(c['accounts'])} account(s), probing "
        f"{c['uri_count']} distinct URIs (top: {', '.join(top_uris) or 'n/a'}). WAF blocked {c['blocked']} "
        f"({rate:.0%}); {c['allowed']} were allowed.{techniques} Evidence source: {visibility}."
    )


UPSERT_CAMPAIGN = """
INSERT INTO campaigns (campaign_code, name, type, status, risk_level, confidence, shared_ja4, entity_ids, asns,
    countries, targeted_accounts, targeted_uris, techniques, total_requests, blocked_requests, allowed_requests,
    start_time, last_active, correlation_evidence, attack_story, recommended_action)
VALUES (%(code)s, %(name)s, 'JA4_CORRELATION', 'ACTIVE', %(risk)s, %(confidence)s, %(ja4)s, %(entity_ids)s,
    %(asns)s, %(countries)s, %(accounts)s, %(uris)s, %(techniques)s, %(total)s, %(blocked)s, %(allowed)s,
    %(start_time)s, %(last_active)s, %(evidence)s::jsonb, %(story)s, %(recommended)s)
ON CONFLICT (campaign_code) DO UPDATE SET
  name = EXCLUDED.name, risk_level = EXCLUDED.risk_level, confidence = EXCLUDED.confidence,
  status = CASE WHEN campaigns.status = 'RESOLVED' THEN 'ACTIVE' ELSE campaigns.status END,
  entity_ids = EXCLUDED.entity_ids, asns = EXCLUDED.asns, countries = EXCLUDED.countries,
  targeted_accounts = EXCLUDED.targeted_accounts, targeted_uris = EXCLUDED.targeted_uris,
  techniques = EXCLUDED.techniques, total_requests = EXCLUDED.total_requests,
  blocked_requests = EXCLUDED.blocked_requests, allowed_requests = EXCLUDED.allowed_requests,
  start_time = least(campaigns.start_time, EXCLUDED.start_time),
  last_active = greatest(campaigns.last_active, EXCLUDED.last_active),
  correlation_evidence = EXCLUDED.correlation_evidence, attack_story = EXCLUDED.attack_story,
  recommended_action = EXCLUDED.recommended_action
RETURNING id
"""


def run_campaigns(cur, now: datetime, risks: dict) -> tuple[dict, list[dict]]:
    """JA4 campaign rule (24h): distinct IPs >= 5 and (block rate >= 0.40 or >= 1 attack technique)."""
    since = now - timedelta(hours=24)
    cur.execute(
        """
        SELECT ja4, count(*) AS total, count(*) FILTER (WHERE action = 'BLOCK') AS blocked,
               count(*) FILTER (WHERE action = 'ALLOW') AS allowed, count(DISTINCT client_ip) AS ips,
               array_agg(DISTINCT host(client_ip)) AS ip_values,
               coalesce(array_agg(DISTINCT asn) FILTER (WHERE asn IS NOT NULL), '{}') AS asns,
               coalesce(array_agg(DISTINCT country) FILTER (WHERE country IS NOT NULL), '{}') AS countries,
               array_agg(DISTINCT account_id) AS accounts, min(timestamp) AS start_time,
               max(timestamp) AS last_active, bool_or(source = 'FULL_LOG') AS full_log,
               count(DISTINCT uri) AS uri_count,
               ARRAY(SELECT DISTINCT t FROM waf_events w2, unnest(w2.attack_techniques) t
                     WHERE w2.ja4 = waf_events.ja4 AND w2.timestamp > %(since)s) AS techniques
        FROM waf_events WHERE timestamp > %(since)s AND ja4 IS NOT NULL
        GROUP BY ja4 HAVING count(DISTINCT client_ip) >= 5
        """,
        {"since": since},
    )
    membership, created = {}, []
    for c in cur.fetchall():
        if not (c["blocked"] / c["total"] >= 0.40 or c["techniques"]):
            continue
        cur.execute(
            "SELECT uri FROM waf_events WHERE ja4 = %s AND timestamp > %s GROUP BY uri ORDER BY count(*) DESC LIMIT 5",
            (c["ja4"], since),
        )
        top_uris = [r["uri"] for r in cur.fetchall()]
        cur.execute(
            "SELECT id, type FROM entities WHERE (type = 'IP' AND value = ANY(%s)) OR (type = 'JA4' AND value = %s)"
            " OR (type = 'ASN' AND value = ANY(%s))",
            (c["ip_values"], c["ja4"], c["asns"]),
        )
        members = cur.fetchall()
        member_levels = [risks.get(m["id"], (0, "LOW"))[1] for m in members if m["type"] == "IP"]
        risk = max(member_levels or ["LOW"], key=RISK_ORDER.index)
        confidence = round(min(100.0, 50 + 5 * c["ips"]) * (1.0 if c["full_log"] else 0.85), 2)
        evidence = [
            {"type": "shared_ja4", "label": "Shared TLS fingerprint", "value": c["ja4"],
             "detail": f"{c['ips']} distinct IPs in 24h"},
            {"type": "asn_spread", "label": "ASNs", "value": str(len(c["asns"])), "detail": ", ".join(c["asns"][:10])},
            {"type": "block_rate", "label": "WAF block rate", "value": f"{c['blocked'] / c['total']:.0%}",
             "detail": f"{c['blocked']}/{c['total']} requests"},
            {"type": "visibility", "label": "Evidence source", "value": "FULL_LOG" if c["full_log"] else "SAMPLED"},
        ]
        cur.execute(UPSERT_CAMPAIGN, {
            "code": campaign_code(c["ja4"]), "ja4": c["ja4"],
            "name": f"JA4 campaign {c['ja4'][:18]}... ({c['ips']} IPs, {len(c['asns'])} ASNs)",
            "risk": risk, "confidence": confidence, "entity_ids": [m["id"] for m in members], "asns": c["asns"],
            "countries": c["countries"], "accounts": c["accounts"], "uris": top_uris, "techniques": c["techniques"],
            "total": c["total"], "blocked": c["blocked"], "allowed": c["allowed"], "start_time": c["start_time"],
            "last_active": c["last_active"], "evidence": json.dumps(evidence), "story": attack_story(c, top_uris),
            "recommended": ("Simulate blocking the campaign IPs (or a JA4-matching rule), then request approval."
                            if c["allowed"] else "Monitor: WAF is blocking this campaign; verify no allowed paths."),
        })
        campaign_id = cur.fetchone()["id"]
        for m in members:
            membership[m["id"]] = max(risk, membership.get(m["id"], "LOW"), key=RISK_ORDER.index)
        created.append({"id": campaign_id, "ja4": c["ja4"], "risk": risk, "confidence": confidence,
                        "entity_ids": [m["id"] for m in members], "accounts": c["accounts"], "total": c["total"],
                        "allowed": c["allowed"], "evidence": evidence, "ips": c["ips"]})
    cur.execute(
        "UPDATE campaigns SET status = 'RESOLVED' WHERE status IN ('ACTIVE', 'INVESTIGATING') AND last_active < %s",
        (now - timedelta(hours=48),),
    )
    return membership, created


# --- detections -------------------------------------------------------------------------------------

def upsert_detection(cur, *, dtype: str, subject: str, title: str, description: str, severity: str,
                     confidence: float, entity_ids: list, accounts: list, requests: int, allowed: int,
                     evidence: list, recommended: str, now: datetime, campaign_id=None) -> None:
    fingerprint = hashlib.sha1(f"{dtype}|{subject}".encode()).hexdigest()  # noqa: S324
    params = {"type": dtype, "title": title, "description": description, "severity": severity,
              "confidence": confidence, "entity_ids": entity_ids, "accounts": accounts, "requests": requests,
              "allowed": allowed, "evidence": json.dumps(evidence), "recommended": recommended, "fp": fingerprint,
              "now": now, "campaign_id": campaign_id}
    cur.execute(
        "SELECT id FROM detections WHERE fingerprint = %s AND status <> 'MITIGATED' AND timestamp > %s",
        (fingerprint, now - timedelta(hours=24)),
    )
    existing = cur.fetchone()
    if existing:
        cur.execute(
            "UPDATE detections SET title = %(title)s, description = %(description)s, severity = %(severity)s,"
            " confidence = %(confidence)s, entity_ids = %(entity_ids)s, accounts = %(accounts)s,"
            " requests_involved = %(requests)s, allowed_requests = %(allowed)s, evidence = %(evidence)s::jsonb,"
            " recommended_action = %(recommended)s, timestamp = %(now)s,"
            " campaign_id = coalesce(%(campaign_id)s, campaign_id) WHERE id = %(id)s RETURNING id",
            {**params, "id": existing["id"]},
        )
    else:
        cur.execute(
            "INSERT INTO detections (type, title, description, severity, confidence, entity_ids, accounts,"
            " requests_involved, allowed_requests, evidence, recommended_action, fingerprint, timestamp, campaign_id)"
            " VALUES (%(type)s, %(title)s, %(description)s, %(severity)s, %(confidence)s, %(entity_ids)s,"
            " %(accounts)s, %(requests)s, %(allowed)s, %(evidence)s::jsonb, %(recommended)s, %(fp)s, %(now)s,"
            " %(campaign_id)s) RETURNING id",
            params,
        )
    detection_id = cur.fetchone()["id"]
    if campaign_id is None:
        cur.execute(
            "UPDATE detections d SET campaign_id = c.id FROM campaigns c WHERE d.id = %s AND c.status <> 'RESOLVED'"
            " AND c.entity_ids && d.entity_ids",
            (detection_id,),
        )


def _entity_ids(cur, ips: list[str], ja4: str | None = None) -> list:
    cur.execute("SELECT id FROM entities WHERE (type = 'IP' AND value = ANY(%s)) OR (type = 'JA4' AND value = %s)",
                (ips, ja4))
    return [r["id"] for r in cur.fetchall()]


def _visibility(full_log: bool) -> tuple[float, dict]:
    if full_log:
        return 90.0, {"type": "visibility", "label": "Evidence source", "value": "FULL_LOG"}
    return 65.0, {"type": "visibility", "label": "Evidence source", "value": "SAMPLED",
                  "detail": "Counts are lower bounds (GetSampledRequests)"}


def run_detections(cur, now: datetime, campaigns: list[dict]) -> int:
    window = now - timedelta(minutes=30)
    found = 0

    cur.execute(
        """
        SELECT host(client_ip) AS ip, count(*) AS total, count(DISTINCT uri) AS uris,
               count(*) FILTER (WHERE action = 'BLOCK') AS blocked,
               count(*) FILTER (WHERE http_request->>'response_code_sent' = '404') AS not_found,
               array_agg(DISTINCT account_id) AS accounts, bool_or(source = 'FULL_LOG') AS full_log
        FROM waf_events WHERE timestamp > %s GROUP BY 1
        HAVING count(DISTINCT uri) >= 25 AND (count(*) FILTER (WHERE action = 'BLOCK')
               + count(*) FILTER (WHERE http_request->>'response_code_sent' = '404'))::float / count(*) >= 0.60
        """,
        (window,),
    )
    for r in cur.fetchall():
        ratio = (r["blocked"] + r["not_found"]) / r["total"]
        conf, vis = _visibility(r["full_log"])
        upsert_detection(
            cur, dtype="SCANNER", subject=r["ip"], title=f"Scanner activity from {r['ip']}",
            description=f"{r['uris']} distinct URIs in 30 min with {ratio:.0%} blocked/404 responses.",
            severity="HIGH" if ratio >= 0.8 or r["uris"] >= 100 else "MEDIUM", confidence=conf,
            entity_ids=_entity_ids(cur, [r["ip"]]), accounts=r["accounts"], requests=r["total"], allowed=0,
            evidence=[{"type": "uri_diversity", "label": "Distinct URIs", "value": str(r["uris"])},
                      {"type": "block_404_ratio", "label": "Blocked + 404 ratio", "value": f"{ratio:.0%}",
                       "detail": f"{r['blocked']} blocked, {r['not_found']} WAF-visible 404s of {r['total']}"}, vis],
            recommended="Simulate a temporary block; scanners rarely need investigation beyond this.", now=now,
        )
        found += 1

    cur.execute(
        """
        SELECT coalesce(ja4, host(client_ip)) AS subject, max(ja4) AS ja4, count(*) AS total,
               count(*) FILTER (WHERE action = 'ALLOW') AS allowed, array_agg(DISTINCT host(client_ip)) AS ips,
               array_agg(DISTINCT account_id) AS accounts, bool_or(source = 'FULL_LOG') AS full_log,
               (array_agg(DISTINCT uri))[1:5] AS uris
        FROM waf_events WHERE timestamp > %s AND http_method = 'POST' AND uri ~* %s
        GROUP BY 1 HAVING count(*) >= 50
        """,
        (window, CREDENTIAL_PATH),
    )
    for r in cur.fetchall():
        conf, vis = _visibility(r["full_log"])
        upsert_detection(
            cur, dtype="CREDENTIAL_ATTACK", subject=r["subject"],
            title=f"Credential attack on {', '.join(r['uris'])}",
            description=f"{r['total']} POSTs to authentication endpoints in 30 min from {len(r['ips'])} IP(s)"
                        + (f" sharing JA4 {r['ja4']}." if r["ja4"] else "."),
            severity="HIGH", confidence=conf + (5 if r["ja4"] else 0), entity_ids=_entity_ids(cur, r["ips"], r["ja4"]),
            accounts=r["accounts"], requests=r["total"], allowed=r["allowed"],
            evidence=[{"type": "login_posts", "label": "Auth POSTs (30 min)", "value": str(r["total"])},
                      {"type": "allowed", "label": "Allowed", "value": str(r["allowed"])}, vis],
            recommended="Simulate a rate-based rule on the login path; enable ATP if allowed volume is high.",
            now=now,
        )
        found += 1

    cur.execute(
        """
        SELECT ja4, substring(uri from '^(/[^/?]*(/[^/?]*)?)') AS prefix, count(*) AS total,
               count(*) FILTER (WHERE action = 'ALLOW') AS allowed, count(DISTINCT client_ip) AS ip_count,
               array_agg(DISTINCT host(client_ip)) AS ips, array_agg(DISTINCT account_id) AS accounts,
               bool_or(source = 'FULL_LOG') AS full_log
        FROM waf_events WHERE timestamp > %s AND ja4 IS NOT NULL GROUP BY 1, 2 HAVING count(DISTINCT client_ip) >= 15
        """,
        (window,),
    )
    for r in cur.fetchall():
        conf, vis = _visibility(r["full_log"])
        upsert_detection(
            cur, dtype="DISTRIBUTED_ATTACK", subject=f"{r['ja4']}|{r['prefix']}",
            title=f"Distributed attack on {r['prefix']} ({r['ip_count']} IPs)",
            description=f"{r['ip_count']} IPs sharing JA4 {r['ja4']} targeted {r['prefix']} in 30 min.",
            severity="CRITICAL", confidence=conf, entity_ids=_entity_ids(cur, r["ips"], r["ja4"]),
            accounts=r["accounts"], requests=r["total"], allowed=r["allowed"],
            evidence=[{"type": "shared_ja4", "label": "Shared JA4", "value": r["ja4"]},
                      {"type": "distinct_ips", "label": "Distinct IPs", "value": str(r["ip_count"])},
                      {"type": "uri_prefix", "label": "Target", "value": r["prefix"]}, vis],
            recommended="Simulate a JA4-scoped block or rate limit on the targeted path.", now=now,
        )
        found += 1

    cur.execute(
        """
        WITH per AS (SELECT ja4, client_ip, count(*) AS n, count(*) FILTER (WHERE action = 'ALLOW') AS allowed,
                            array_agg(DISTINCT account_id) AS accounts, bool_or(source = 'FULL_LOG') AS full_log
                     FROM waf_events WHERE timestamp > %s AND ja4 IS NOT NULL GROUP BY 1, 2)
        SELECT ja4, max(n) AS max_per_ip, sum(n) AS total, sum(allowed) AS allowed, count(*) AS ip_count,
               array_agg(host(client_ip)) AS ips, bool_or(full_log) AS full_log,
               ARRAY(SELECT DISTINCT unnest(array_agg(a)) FROM unnest(array_agg(accounts)) a) AS accounts
        FROM per GROUP BY ja4 HAVING max(n) <= 300 AND sum(n) >= 300 AND count(*) >= 2
        """,
        (window,),
    )
    for r in cur.fetchall():
        conf, vis = _visibility(r["full_log"])
        upsert_detection(
            cur, dtype="SLOW_DISTRIBUTED", subject=r["ja4"],
            title=f"Slow distributed attack (JA4 {r['ja4'][:18]}...)",
            description=f"{r['ip_count']} IPs each under 10 req/min (max {r['max_per_ip']} in 30 min) totalling "
                        f"{r['total']} requests - below per-IP rate limits.",
            severity="HIGH", confidence=conf, entity_ids=_entity_ids(cur, r["ips"], r["ja4"]),
            accounts=list(r["accounts"]), requests=int(r["total"]), allowed=int(r["allowed"]),
            evidence=[{"type": "max_per_ip", "label": "Max requests per IP (30 min)", "value": str(r["max_per_ip"])},
                      {"type": "aggregate", "label": "Aggregate requests", "value": str(r["total"])}, vis],
            recommended="Per-IP rate limits cannot catch this; simulate a JA4-scoped rule.", now=now,
        )
        found += 1

    cur.execute(
        """
        SELECT host(e.client_ip) AS ip, count(*) AS total, bool_or(e.action = 'COUNT') AS via_count,
               max(en.threat_score) AS threat, array_agg(DISTINCT e.account_id) AS accounts,
               (array_agg(DISTINCT e.uri))[1:5] AS uris, bool_or(e.source = 'FULL_LOG') AS full_log
        FROM waf_events e JOIN entities en ON en.type = 'IP' AND en.value = host(e.client_ip)
        WHERE e.timestamp > %s AND NOT en.is_allow_listed
          AND ((e.action = 'ALLOW' AND en.threat_score >= 75) OR (e.action = 'COUNT' AND e.attack_techniques <> '{}'))
        GROUP BY 1
        """,
        (window,),
    )
    for r in cur.fetchall():
        conf, vis = _visibility(r["full_log"])
        evidence = [{"type": "allowed", "label": "Requests passed", "value": str(r["total"])},
                    {"type": "threat_score", "label": "Entity threat score", "value": f"{float(r['threat']):.0f}"},
                    {"type": "uris", "label": "URIs reached", "value": ", ".join(r["uris"])}, vis]
        if r["via_count"]:
            evidence.append({"type": "count_rule", "label": "Matched a COUNT-mode rule",
                             "value": "yes", "detail": "Attack signature matched but the rule only counted"})
        upsert_detection(
            cur, dtype="MALICIOUS_ALLOWED", subject=r["ip"], title=f"Malicious traffic allowed from {r['ip']}",
            description=f"{r['total']} requests from a high-risk entity reached {', '.join(r['uris'])}.",
            severity="CRITICAL", confidence=conf, entity_ids=_entity_ids(cur, [r["ip"]]), accounts=r["accounts"],
            requests=r["total"], allowed=r["total"], evidence=evidence,
            recommended="Open the investigation: check 'Why was it allowed?' (COUNT rule / drift / unprotected path), "
                        "then simulate a block.", now=now,
        )
        found += 1

    for c in campaigns:
        upsert_detection(
            cur, dtype="JA4_CORRELATION", subject=c["ja4"], title=f"JA4 correlated campaign ({c['ips']} IPs)",
            description=f"Campaign across {len(c['accounts'])} account(s); {c['allowed']} of {c['total']} requests "
                        "allowed in 24h.",
            severity=c["risk"] if c["risk"] != "LOW" else "MEDIUM", confidence=c["confidence"],
            entity_ids=c["entity_ids"], accounts=c["accounts"], requests=c["total"], allowed=c["allowed"],
            evidence=c["evidence"], recommended="Review the campaign and simulate a coordinated block.", now=now,
            campaign_id=c["id"],
        )
        found += 1
    return found


def lambda_handler(event: dict, _context, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    with db.transaction() as cur:
        wm, upto = db.get_watermark(cur, ENGINE), db.db_now(cur)
        fold_events(cur, wm, upto)
        risks = score_entities(cur, now, {})
        membership, campaigns = run_campaigns(cur, now, risks)
        if membership:
            score_entities(cur, now, membership)
        cur.execute(
            "UPDATE waf_events e SET classification = en.classification FROM entities en"
            " WHERE en.type = 'IP' AND en.value = host(e.client_ip) AND e.timestamp > %s"
            " AND e.classification IS DISTINCT FROM en.classification",
            (now - timedelta(hours=24),),
        )
        detections = run_detections(cur, now, campaigns)
        summary = {"entities_scored": len(risks), "campaigns": len(campaigns), "detections": detections}
        db.set_watermark(cur, ENGINE, upto, summary)
    log.info("detection summary %s", summary)
    return summary
