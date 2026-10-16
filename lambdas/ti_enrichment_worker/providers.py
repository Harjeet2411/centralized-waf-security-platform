"""Threat-intel provider adapters. Each returns a normalized result or raises ProviderUnavailable (429, 5xx,
timeout, bad payload) so the worker can degrade gracefully (Rule #8).

Licensing: VirusTotal's public API forbids commercial use and AbuseIPDB/GreyNoise free tiers have their own
terms - production in a financial institution needs the paid tiers. Daily budgets are enforced by the worker.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Callable

Fetch = Callable[[str, dict], tuple[int, dict]]  # (url, headers) -> (status, json body)
TIMEOUT_SECONDS = 5


class ProviderUnavailable(Exception):  # noqa: N818
    pass


def http_fetch(url: str, headers: dict) -> tuple[int, dict]:
    request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as resp:  # noqa: S310 - fixed https URLs
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body or b"{}")
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ProviderUnavailable(f"network error: {exc}") from exc


def _check(provider: str, status: int, ok: tuple[int, ...] = (200,)) -> None:
    if status == 429 or status >= 500:
        raise ProviderUnavailable(f"{provider} HTTP {status}")
    if status not in ok:
        raise ProviderUnavailable(f"{provider} unexpected HTTP {status}")


def abuseipdb(ip: str, key: str, fetch: Fetch = http_fetch) -> dict:
    status, body = fetch(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", {"Key": key})
    _check("AbuseIPDB", status)
    data = body.get("data") or {}
    score, reports = float(data.get("abuseConfidenceScore", 0)), int(data.get("totalReports", 0))
    if score >= 75:
        cls = "malicious"
    elif score >= 25:
        cls = "suspicious"
    else:
        cls = "benign" if reports == 0 and data.get("isWhitelisted") else "unknown"
    tags = [t for t in (data.get("usageType"), "tor" if data.get("isTor") else None) if t]
    return {"provider": "AbuseIPDB", "score": score, "classification": cls,
            "confidence": float(min(100, 40 + 2 * reports)), "tags": tags, "raw": data}


def greynoise(ip: str, key: str, fetch: Fetch = http_fetch) -> dict:
    status, body = fetch(f"https://api.greynoise.io/v3/community/{ip}", {"key": key})
    _check("GreyNoise", status, ok=(200, 404))  # 404 = never observed scanning the internet (a real answer)
    cls = body.get("classification", "unknown") if status == 200 else "unknown"
    cls = cls if cls in ("malicious", "benign") else "unknown"
    score = {"malicious": 90.0, "benign": 0.0}.get(cls, 0.0)
    tags = [t for t in ("noise" if body.get("noise") else None, "riot" if body.get("riot") else None,
                        body.get("name")) if t]
    return {"provider": "GreyNoise", "score": score, "classification": cls,
            "confidence": 80.0 if cls != "unknown" else 30.0, "tags": tags, "raw": body}


def virustotal(ip: str, key: str, fetch: Fetch = http_fetch) -> dict:
    status, body = fetch(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", {"x-apikey": key})
    _check("VirusTotal", status)
    stats = (body.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    engines = sum(int(v) for v in stats.values()) or 1
    if malicious >= 5:
        cls = "malicious"
    elif malicious or suspicious:
        cls = "suspicious"
    else:
        cls = "benign" if stats.get("harmless") else "unknown"
    return {"provider": "VirusTotal", "score": float(min(100, 10 * (malicious + 0.5 * suspicious))),
            "classification": cls, "confidence": float(min(100, 50 + engines / 2)),
            "tags": [f"{malicious}/{engines} engines"], "raw": stats}


PROVIDERS = {"abuseipdb": abuseipdb, "greynoise": greynoise, "virustotal": virustotal}
