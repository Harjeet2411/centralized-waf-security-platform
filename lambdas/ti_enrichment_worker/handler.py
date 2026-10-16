"""sas-ti-enrichment-worker: AbuseIPDB / GreyNoise / VirusTotal lookups for new client IPs.

* Candidates: client IPs ingested since the last run, most suspicious first (attack techniques, blocks, volume);
  private/reserved and allow-listed IPs are never sent to third parties.
* Redis `ti:ip:{ip}` caches combined provider results for 24h; DB `threat_intelligence` keeps history.
* Per-provider daily budgets (Redis counters) keep the free/paid quotas and the $350 ceiling intact.
* Provider failure -> that provider is skipped and platform_health.threat_intel degrades; never raises.
"""

import ipaddress
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import redis

from common import db
from common.aws import get_secret
from ti_enrichment_worker.providers import PROVIDERS, ProviderUnavailable, http_fetch

log = logging.getLogger()
log.setLevel(logging.INFO)

ENGINE = "ti_enrichment"
CACHE_TTL = 86_400
DAILY_BUDGET = {"abuseipdb": 1000, "greynoise": 1000, "virustotal": 500}
PROVIDER_NAME = {"abuseipdb": "AbuseIPDB", "greynoise": "GreyNoise", "virustotal": "VirusTotal"}
DEFAULT_MAX_LOOKUPS = 25  # per run; 48 telemetry runs/day stays inside the smallest daily budget


def provider_keys() -> dict[str, str]:
    raw = os.environ.get("SAS_TI_KEYS_JSON") or (
        get_secret(os.environ["SAS_TI_SECRET_ARN"]) if os.environ.get("SAS_TI_SECRET_ARN") else "{}"
    )
    return {k: v for k, v in json.loads(raw).items() if k in PROVIDERS and v}


def redis_client() -> redis.Redis:
    return redis.Redis.from_url(os.environ.get("SAS_REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)


def candidates(cur, wm, upto, limit: int) -> list[str]:
    # ponytail: candidates beyond `limit` in one batch are not carried over; recurring IPs reappear in later
    # batches. Add a backlog table if one-off IPs must all be enriched.
    cur.execute(
        """
        SELECT host(e.client_ip) AS ip FROM waf_events e
        WHERE e.ingested_at > %(wm)s AND e.ingested_at <= %(upto)s
          AND NOT EXISTS (SELECT 1 FROM allow_list_entries a WHERE a.is_active AND a.ip_network IS NOT NULL
                          AND e.client_ip <<= a.ip_network)
        GROUP BY e.client_ip
        ORDER BY bool_or(e.attack_techniques <> '{}') DESC, bool_or(e.action = 'BLOCK') DESC, count(*) DESC
        LIMIT %(scan)s
        """,
        {"wm": wm, "upto": upto, "scan": limit * 4},
    )
    ips = [r["ip"] for r in cur.fetchall() if ipaddress.ip_address(r["ip"]).is_global]
    if not ips:
        return []
    cur.execute(  # skip IPs whose DB intel is still fresh
        "SELECT e.value FROM entities e JOIN threat_intelligence t ON t.entity_id = e.id"
        " WHERE e.type = 'IP' AND e.value = ANY(%s) GROUP BY e.value HAVING min(t.expires_at) > now()",
        (ips,),
    )
    fresh = {r["value"] for r in cur.fetchall()}
    return [ip for ip in ips if ip not in fresh][:limit]


def within_budget(cache: redis.Redis, provider: str, today: str) -> bool:
    key = f"ti:budget:{provider}:{today}"
    used = cache.incr(key)
    if used == 1:
        cache.expire(key, 2 * CACHE_TTL)
    return used <= DAILY_BUDGET[provider]


def lookup(ip: str, keys: dict, cache: redis.Redis, today: str, fetch, failures: dict) -> list[dict]:
    cached = cache.get(f"ti:ip:{ip}")
    if cached is not None:
        return json.loads(cached)

    def call(provider: str):
        if not within_budget(cache, provider, today):
            failures.setdefault(provider, []).append("daily budget exhausted")
            return None
        try:
            return PROVIDERS[provider](ip, keys[provider], fetch)
        except ProviderUnavailable as exc:
            failures.setdefault(provider, []).append(str(exc))
            return None

    with ThreadPoolExecutor(max_workers=len(keys) or 1) as pool:
        results = [r for r in pool.map(call, keys) if r]
    if results:
        cache.set(f"ti:ip:{ip}", json.dumps(results), ex=CACHE_TTL)
    return results


UPSERT_TI = """
INSERT INTO threat_intelligence (entity_id, provider, score, classification, confidence, tags, raw_response,
                                 last_checked, expires_at)
VALUES (%(entity_id)s, %(provider)s, %(score)s, %(classification)s, %(confidence)s, %(tags)s, %(raw)s::jsonb, now(),
        %(expires_at)s)
ON CONFLICT (entity_id, provider) DO UPDATE SET score = EXCLUDED.score, classification = EXCLUDED.classification,
  confidence = EXCLUDED.confidence, tags = EXCLUDED.tags, raw_response = EXCLUDED.raw_response,
  last_checked = now(), expires_at = EXCLUDED.expires_at
"""


def lambda_handler(event: dict, _context, fetch=http_fetch, cache: redis.Redis | None = None,
                   now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    keys = provider_keys()
    cache = cache or redis_client()
    max_lookups = int(os.environ.get("SAS_TI_MAX_LOOKUPS", DEFAULT_MAX_LOOKUPS))
    failures: dict[str, list[str]] = {}
    enriched = 0
    with db.transaction() as cur:
        wm, upto = db.get_watermark(cur, ENGINE), db.db_now(cur)
        ips = candidates(cur, wm, upto, max_lookups) if keys else []
        for ip in ips:
            results = lookup(ip, keys, cache, now.strftime("%Y%m%d"), fetch, failures)
            if not results:
                continue
            cur.execute(
                "INSERT INTO entities (type, value) VALUES ('IP', %s) ON CONFLICT (type, value)"
                " DO UPDATE SET value = EXCLUDED.value RETURNING id",
                (ip,),
            )
            entity_id = cur.fetchone()["id"]
            for r in results:
                cur.execute(UPSERT_TI, {**r, "entity_id": entity_id, "raw": json.dumps(r["raw"]),
                                        "expires_at": now + timedelta(seconds=CACHE_TTL)})
            enriched += 1

        if not keys:
            status, detail = "UNAVAILABLE", "No threat-intel provider keys configured"
        elif failures and len(failures) == len(keys) and enriched == 0 and ips:
            status, detail = "UNAVAILABLE", "All providers failing"
        elif failures:
            status, detail = "DEGRADED", "Degraded: " + ", ".join(PROVIDER_NAME[p] for p in sorted(failures))
        else:
            status, detail = "HEALTHY", f"{enriched} IPs enriched via {', '.join(PROVIDER_NAME[p] for p in keys)}"
        db.upsert_health(
            cur, component="threat_intel", account_id=None, status=status, detail=detail,
            error="; ".join(f"{PROVIDER_NAME[p]}: {msgs[-1]}" for p, msgs in sorted(failures.items())) or None,
            affected_modules=["threat_intelligence"] if failures else [], success=status != "UNAVAILABLE",
        )
        summary = {"candidates": len(ips), "enriched": enriched, "status": status,
                   "failures": {p: len(m) for p, m in failures.items()}}
        db.set_watermark(cur, ENGINE, upto, summary)
    log.info("ti summary %s", summary)
    return summary
