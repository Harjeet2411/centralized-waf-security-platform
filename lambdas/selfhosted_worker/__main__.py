"""Self-hosted pipeline (staging): runs the same handlers as the Step Functions sync machine, in one process.

    python -m selfhosted_worker

Schedules match EventBridge: telemetry every 30 min, full discovery every 6 h. Manual refreshes arrive on the Redis
list `sync:requests` (pushed by POST /api/v1/refresh when SAS_SYNC_BACKEND=worker). Order per run, as in the ASL:
fetch_accounts -> account_collector per account (20 in parallel, throttling retried 4x: 2 s, x2.5) or
mark_account_degraded -> ti_enrichment_worker -> detection_campaign_engine -> drift_scoring_engine.
S3 full-log ingestion is not part of the self-hosted setup (all accounts are SAMPLED).
"""

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import redis

from account_collector import handler as account_collector
from common.aws import ThrottlingException, WAFLimitsExceededException
from detection_campaign_engine import handler as detection_engine
from drift_scoring_engine import handler as drift_engine
from fetch_accounts import handler as fetch_accounts
from mark_account_degraded import handler as mark_degraded
from ti_enrichment_worker import handler as ti_worker

log = logging.getLogger("selfhosted_worker")

TELEMETRY_SECONDS = int(os.environ.get("SAS_TELEMETRY_INTERVAL_SECONDS", "1800"))
FULL_SECONDS = int(os.environ.get("SAS_FULL_INTERVAL_SECONDS", "21600"))
MAX_CONCURRENCY = 20
RETRIES, RETRY_INTERVAL, BACKOFF = 4, 2.0, 2.5
REQUESTS_KEY, STATUS_KEY, LOCK_KEY = "sync:requests", "sync:global:status", "sync:global:lock"
CHANNEL = "pubsub:platform_events"
BLPOP_SECONDS = 60
THROTTLED = (WAFLimitsExceededException, ThrottlingException)


def collect(account: dict, mode: str, sleep=time.sleep) -> None:
    """One Map iteration: collector with the ASL retry policy; any final failure -> mark_account_degraded."""
    event = {"account": account, "mode": mode}
    for attempt in range(RETRIES + 1):
        try:
            account_collector.lambda_handler(event, None)
            return
        except THROTTLED as exc:
            error = exc
            if attempt == RETRIES:
                break
            sleep(RETRY_INTERVAL * BACKOFF ** attempt)
        except Exception as exc:  # one account's failure must not stop the others (Rule #8)
            error = exc
            break
    log.warning("account %s failed: %s", account["account_id"], error)
    mark_degraded.lambda_handler({**event, "error": {
        "Error": type(error).__name__, "Cause": json.dumps({"errorMessage": str(error)}),
    }}, None)


def run_sync(mode: str) -> None:
    accounts = fetch_accounts.lambda_handler({"mode": mode}, None)["accounts"]
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
        list(pool.map(lambda account: collect(account, mode), accounts))
    for engine in (ti_worker, detection_engine, drift_engine):
        engine.lambda_handler({"mode": mode}, None)


def publish(r: redis.Redis, event_type: str, payload: dict) -> None:
    r.publish(CHANNEL, json.dumps({"type": event_type, "payload": payload, "at": datetime.now(UTC).isoformat()}))


def run_locked(r: redis.Redis, mode: str, requested_by: str) -> None:
    """Same lock and status keys as the API. A manual request arrives with the lock already taken by the API;
    a scheduled run takes it itself and is skipped while another sync holds it."""
    if requested_by == "schedule" and not r.set(LOCK_KEY, f"worker:{mode}", nx=True, ex=7200):
        log.info("skipping scheduled %s sync: another sync holds the lock", mode)
        return
    started = datetime.now(UTC).isoformat()
    status = {"status": "syncing", "mode": mode, "started_at": started, "requested_by": requested_by}
    r.set(STATUS_KEY, json.dumps(status), ex=21_600)
    if requested_by == "schedule":
        publish(r, "SYNC_STARTED", status)
    outcome = "SUCCEEDED"
    try:
        run_sync(mode)
    except Exception:
        log.exception("%s sync failed", mode)
        outcome = "FAILED"
    finished = {"status": outcome, "mode": mode, "started_at": started, "finished_at": datetime.now(UTC).isoformat()}
    r.set(STATUS_KEY, json.dumps(finished), ex=21_600)
    r.delete(LOCK_KEY)
    publish(r, "SYNC_COMPLETED", finished)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # socket_timeout must exceed the BLPOP wait below, or the read times out while Redis is still blocking.
    r = redis.Redis.from_url(os.environ.get("SAS_REDIS_URL", "redis://localhost:6379/0"), decode_responses=True,
                             socket_timeout=BLPOP_SECONDS + 30, health_check_interval=30)
    next_full = time.monotonic()  # full discovery right after start, so a fresh install fills up immediately
    next_telemetry = next_full + TELEMETRY_SECONDS
    log.info("self-hosted worker started: telemetry every %ss, full every %ss", TELEMETRY_SECONDS, FULL_SECONDS)
    while True:
        now = time.monotonic()
        if now >= next_full:
            run_locked(r, "full", "schedule")
            next_full, next_telemetry = now + FULL_SECONDS, now + TELEMETRY_SECONDS
            continue
        if now >= next_telemetry:
            run_locked(r, "telemetry", "schedule")
            next_telemetry = now + TELEMETRY_SECONDS
            continue
        wait = max(1, int(min(next_full, next_telemetry) - now))
        try:
            item = r.blpop(REQUESTS_KEY, timeout=min(wait, BLPOP_SECONDS))
        except redis.RedisError as exc:  # Redis restart or network blip: wait and retry, keep the schedule
            log.warning("redis unavailable (%s); retrying in 5 s", exc)
            time.sleep(5)
            continue
        if item:
            request = json.loads(item[1])
            run_locked(r, request.get("mode", "full"), request.get("requested_by", "api"))


if __name__ == "__main__":
    main()
