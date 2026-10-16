import json
from datetime import UTC, datetime

import pytest
import redis

from common import db
from tests.conftest import query
from ti_enrichment_worker import handler as ti
from ti_enrichment_worker import providers

KEYS = {"abuseipdb": "a-key", "greynoise": "g-key", "virustotal": "v-key"}


@pytest.fixture
def cache():
    client = redis.Redis.from_url("redis://localhost:6379/14", decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()


class FakeIdP:
    """Records every outbound URL; GreyNoise is rate-limited to prove graceful degradation."""

    def __init__(self):
        self.urls = []

    def __call__(self, url, headers):
        self.urls.append(url)
        if "abuseipdb" in url:
            return 200, {"data": {"abuseConfidenceScore": 97, "totalReports": 40, "isTor": True}}
        if "greynoise" in url:
            return 429, {}
        return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 14, "suspicious": 1,
                                                                      "harmless": 60, "undetected": 15}}}}


def seed_events(account):
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action)"
            " VALUES ('r-1', 'arn:w', 'w', %s, 'eu-west-1', 'REGIONAL', 'ALLOW') RETURNING id",
            (account["account_id"],),
        )
        webacl = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by)"
            " VALUES ('203.0.113.0/24', '203.0.113.0/24', 'PSP', 'PAYMENT_GATEWAY', 'pay', 'psp', 't')"
        )
        for i, ip in enumerate(["185.220.101.42", "45.155.205.233", "10.0.0.7", "203.0.113.5"]):
            cur.execute(
                "INSERT INTO waf_events (event_hash, timestamp, account_id, webacl_id, client_ip, http_method, uri,"
                " action, source) VALUES (%s, now(), %s, %s, %s, 'GET', '/', 'BLOCK', 'SAMPLED')",
                (f"h{i}", account["account_id"], webacl, ip),
            )


def test_enriches_public_ips_only_and_degrades_gracefully(account, cache, monkeypatch):
    monkeypatch.setenv("SAS_TI_KEYS_JSON", json.dumps(KEYS))
    seed_events(account)
    fake = FakeIdP()
    out = ti.lambda_handler({}, None, fetch=fake, cache=cache)

    looked_up = {u.split("ipAddress=")[1].split("&")[0] for u in fake.urls if "abuseipdb" in u}
    assert looked_up == {"185.220.101.42", "45.155.205.233"}  # private + allow-listed never leave the platform
    assert out["enriched"] == 2 and out["status"] == "DEGRADED" and out["failures"] == {"greynoise": 2}

    rows = query("SELECT e.value, t.provider, t.score, t.classification FROM threat_intelligence t"
                 " JOIN entities e ON e.id = t.entity_id ORDER BY e.value, t.provider")
    assert {(r["provider"], r["classification"]) for r in rows} == {("AbuseIPDB", "malicious"),
                                                                    ("VirusTotal", "malicious")}
    [health] = query("SELECT * FROM platform_health WHERE component = 'threat_intel'")
    assert health["status"] == "DEGRADED" and "GreyNoise" in health["detail"] and "429" in health["error"]
    assert cache.ttl("ti:ip:185.220.101.42") > 86_000


def test_cache_hit_skips_providers(cache):
    fake = FakeIdP()
    today = datetime.now(UTC).strftime("%Y%m%d")
    first = ti.lookup("185.220.101.42", KEYS, cache, today, fake, {})
    calls = len(fake.urls)
    assert ti.lookup("185.220.101.42", KEYS, cache, today, fake, {}) == first
    assert len(fake.urls) == calls


def test_daily_budget_enforced(cache, monkeypatch):
    monkeypatch.setitem(ti.DAILY_BUDGET, "virustotal", 1)
    failures = {}
    today = datetime.now(UTC).strftime("%Y%m%d")
    ti.lookup("1.1.1.1", {"virustotal": "v"}, cache, today, FakeIdP(), failures)
    ti.lookup("8.8.8.8", {"virustotal": "v"}, cache, today, FakeIdP(), failures)
    assert failures == {"virustotal": ["daily budget exhausted"]}


def test_no_keys_reports_unavailable(account, cache, monkeypatch):
    monkeypatch.setenv("SAS_TI_KEYS_JSON", "{}")
    out = ti.lambda_handler({}, None, fetch=FakeIdP(), cache=cache)
    assert out["status"] == "UNAVAILABLE"


def test_provider_normalization():
    assert providers.virustotal("1.1.1.1", "k", lambda u, h: (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}}}))["classification"] == "benign"
    gn = providers.greynoise("1.1.1.1", "k", lambda u, h: (404, {"message": "IP not observed"}))
    assert gn["classification"] == "unknown" and gn["score"] == 0.0
    with pytest.raises(providers.ProviderUnavailable):
        providers.abuseipdb("1.1.1.1", "k", lambda u, h: (503, {}))
