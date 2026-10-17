"""Self-hosted worker: ASL retry policy, degraded marking, engine order, lock handling."""

import json

import selfhosted_worker.__main__ as worker
from common.aws import ThrottlingException
from tests.conftest import query


def test_throttling_is_retried_then_succeeds(monkeypatch, account):
    calls, sleeps = [], []

    def collector(event, _ctx):
        calls.append(event)
        if len(calls) < 3:
            raise ThrottlingException("slow down")

    monkeypatch.setattr(worker.account_collector, "lambda_handler", collector)
    worker.collect(account, "telemetry", sleep=sleeps.append)
    assert len(calls) == 3
    assert sleeps == [2.0, 5.0]
    assert query("SELECT status FROM accounts")[0]["status"] != "UNAVAILABLE"


def test_access_failure_marks_account_unavailable(monkeypatch, account):
    class AccountAccessError(Exception):  # same class name the ASL Catch would report
        pass

    def collector(event, _ctx):
        raise AccountAccessError("AccessDenied on sts:AssumeRole")

    monkeypatch.setattr(worker.account_collector, "lambda_handler", collector)
    worker.collect(account, "full", sleep=lambda _s: None)
    row = query("SELECT status, last_error FROM accounts WHERE account_id = %s", (account["account_id"],))[0]
    assert row["status"] == "UNAVAILABLE"
    assert "AccessDenied" in row["last_error"]


def test_run_sync_runs_engines_in_asl_order(monkeypatch, account):
    order = []
    monkeypatch.setattr(worker, "collect", lambda acct, mode: order.append(("collect", acct["account_id"], mode)))
    for name, module in [("ti", worker.ti_worker), ("detect", worker.detection_engine), ("drift", worker.drift_engine)]:
        monkeypatch.setattr(module, "lambda_handler", lambda e, c, name=name: order.append((name, e["mode"])))
    worker.run_sync("full")
    assert order == [("collect", account["account_id"], "full"), ("ti", "full"), ("detect", "full"), ("drift", "full")]


class FakeRedis:
    def __init__(self, locked=False):
        self.store, self.published = ({worker.LOCK_KEY: "api"} if locked else {}), []

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    def delete(self, key):
        self.store.pop(key, None)

    def publish(self, channel, message):
        self.published.append(json.loads(message)["type"])


def test_scheduled_run_skips_while_locked_but_manual_request_runs(monkeypatch):
    runs = []
    monkeypatch.setattr(worker, "run_sync", runs.append)
    worker.run_locked(FakeRedis(locked=True), "telemetry", "schedule")
    assert runs == []
    r = FakeRedis(locked=True)  # the API took the lock before queueing the request
    worker.run_locked(r, "full", "admin@example.com")
    assert runs == ["full"]
    assert worker.LOCK_KEY not in r.store
    assert r.published == ["SYNC_COMPLETED"]
    assert json.loads(r.store[worker.STATUS_KEY])["status"] == "SUCCEEDED"
