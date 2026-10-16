"""sas-s3-log-ingestor: full WAF logs for the 6 logging-enabled accounts -> waf_events (source FULL_LOG).

Trigger: s3:ObjectCreated:* on the central WAF-log staging bucket (logging accounts deliver or replicate their
`aws-waf-logs-*` objects there). Objects are gzip'd JSON lines; streamed, never loaded whole into memory.
Records whose WebACL hasn't been discovered yet are counted and skipped (the next 6h discovery adds it; the
log object can be re-driven). Duplicate deliveries are no-ops via event_hash.
"""

import gzip
import io
import json
import logging
from urllib.parse import unquote_plus

import boto3

from common import db
from common.aws import BOTO_CONFIG
from common.normalize import from_log_record, insert_events

log = logging.getLogger()
log.setLevel(logging.INFO)
BATCH = 500


def ingest_stream(stream, webacl_lookup: dict[str, tuple]) -> dict:
    """Parse one gzip JSON-lines stream. webacl_lookup: WebACL ARN -> (db id, account_id)."""
    stats = {"lines": 0, "inserted": 0, "unknown_webacl": 0, "malformed": 0}
    batch: list[dict] = []

    def flush():
        if batch:
            with db.transaction() as cur:
                stats["inserted"] += insert_events(cur, batch)
            batch.clear()

    with gzip.GzipFile(fileobj=stream) as lines:
        for raw in io.TextIOWrapper(lines, encoding="utf-8"):
            if not raw.strip():
                continue
            stats["lines"] += 1
            try:
                record = json.loads(raw)
                target = webacl_lookup.get(record["webaclId"])
                if target is None:
                    stats["unknown_webacl"] += 1
                    continue
                batch.append(from_log_record(record, webacl_db_id=target[0], account_id=target[1]))
            except (ValueError, KeyError, TypeError):
                stats["malformed"] += 1
                continue
            if len(batch) >= BATCH:
                flush()
    flush()
    return stats


def load_webacl_lookup() -> dict[str, tuple]:
    with db.transaction() as cur:
        cur.execute("SELECT arn, id, account_id FROM web_acls")
        return {r["arn"]: (r["id"], r["account_id"]) for r in cur.fetchall()}


def lambda_handler(event: dict, _context, s3=None) -> dict:
    s3 = s3 or boto3.client("s3", config=BOTO_CONFIG)
    lookup = load_webacl_lookup()
    results = []
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        body = s3.get_object(Bucket=bucket, Key=key)["Body"]
        stats = ingest_stream(body, lookup)
        log.info("ingested s3://%s/%s %s", bucket, key, stats)
        results.append({"key": key, **stats})
    return {"objects": results}
