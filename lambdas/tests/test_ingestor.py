import copy
import gzip
import io
import json

from s3_log_ingestor.handler import lambda_handler
from tests.conftest import query
from tests.fakes import JA4, REGIONAL_ARN
from tests.test_normalize import LOG_RECORD


class FakeS3:
    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects

    def get_object(self, Bucket, Key):  # noqa: N803
        return {"Body": io.BytesIO(self.objects[Key])}


def gz_lines(records: list) -> bytes:
    return gzip.compress("\n".join(r if isinstance(r, str) else json.dumps(r) for r in records).encode())


def s3_event(key: str) -> dict:
    return {"Records": [{"s3": {"bucket": {"name": "sas-waf-logs-staging"}, "object": {"key": key}}}]}


def seed_webacl(account):
    from common import db
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO web_acls (webacl_id, arn, name, account_id, region, scope, default_action)"
            " VALUES ('r-1', %s, 'prod-payments-waf', %s, 'eu-west-1', 'REGIONAL', 'ALLOW')",
            (REGIONAL_ARN, account["account_id"]),
        )


def test_ingests_full_logs_and_dedups_redelivery(account):
    seed_webacl(account)
    second = copy.deepcopy(LOG_RECORD)
    second["timestamp"] += 1000
    second["action"] = "ALLOW"
    unknown = copy.deepcopy(LOG_RECORD)
    unknown["webaclId"] = "arn:aws:wafv2:eu-west-1:999999999999:regional/webacl/not-discovered/x"
    key = "AWSLogs/123456789012/WAFLogs/eu-west-1/prod-payments-waf/2026/10/17/12/00/log%201.gz"
    s3 = FakeS3({key.replace("%20", " "): gz_lines([LOG_RECORD, second, unknown, "{not json", ""])})

    out = lambda_handler(s3_event(key), None, s3=s3)
    assert out["objects"][0] | {"key": None} == {"key": None, "lines": 4, "inserted": 2, "unknown_webacl": 1,
                                                 "malformed": 1}
    rows = query("SELECT * FROM waf_events ORDER BY timestamp")
    assert [r["action"] for r in rows] == ["BLOCK", "ALLOW"]
    assert all(r["source"] == "FULL_LOG" and r["ja4"] == JA4 for r in rows)
    assert rows[0]["account_id"] == "123456789012"

    again = lambda_handler(s3_event(key), None, s3=s3)  # S3 at-least-once redelivery
    assert again["objects"][0]["inserted"] == 0
    assert len(query("SELECT id FROM waf_events")) == 2
