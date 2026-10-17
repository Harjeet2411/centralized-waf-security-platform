"""Smart refresh: freshness short-circuit, single Step Functions start under the lock, completion broadcast."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.api.v1 import sync
from app.config import get_settings
from app.database import redis_client
from app.main import app
from tests.conftest import login_as


class FakeSfn:
    def __init__(self, statuses=("SUCCEEDED",)):
        self.started: list[dict] = []
        self.statuses = list(statuses)

    def start_execution(self, stateMachineArn, input):  # noqa: N803, A002
        self.started.append({"arn": stateMachineArn, "input": json.loads(input)})
        return {"executionArn": f"arn:aws:states:us-east-1:111111111111:execution:sync:{len(self.started)}"}

    def describe_execution(self, executionArn):  # noqa: N803
        return {"status": self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]}


@pytest.fixture
def sfn(monkeypatch):
    fake = FakeSfn(statuses=("RUNNING",))
    app.dependency_overrides[sync.get_sfn_client] = lambda: fake
    arn = "arn:aws:states:us-east-1:111111111111:stateMachine:s"
    monkeypatch.setattr(get_settings(), "sync_state_machine_arn", arn)
    yield fake
    app.dependency_overrides.clear()


async def seed_account(db, last_discovered):
    await db.execute(text(
        "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn,"
        " last_discovered) VALUES ('123456789012', 'a', 'production', 'o', 'arn:d', 'arn:r', :ts)"),
        {"ts": last_discovered})
    await db.commit()


async def test_fresh_data_returns_ready_without_starting(client, db, sfn):
    await seed_account(db, datetime.now(UTC) - timedelta(minutes=10))
    client.cookies.update(await login_as("Read Only"))
    resp = await client.post("/api/v1/refresh")
    assert resp.status_code == 200 and resp.json()["status"] == "ready" and sfn.started == []


async def test_stale_data_starts_exactly_one_sync(client, db, sfn):
    await seed_account(db, datetime.now(UTC) - timedelta(hours=3))
    client.cookies.update(await login_as("SOC Analyst"))
    first = await client.post("/api/v1/refresh")
    assert first.status_code == 202 and first.json()["status"] == "syncing"
    assert sfn.started == [{"arn": "arn:aws:states:us-east-1:111111111111:stateMachine:s", "input": {"mode": "full"}}]
    second = await client.post("/api/v1/refresh", params={"force": True})
    assert second.status_code == 202 and second.json()["execution_arn"] == first.json()["execution_arn"]
    assert len(sfn.started) == 1  # concurrent clicks never fan out duplicate 39-account syncs
    for task in list(sync._watchers):  # noqa: SLF001
        task.cancel()


async def test_unconfigured_state_machine(client, db, monkeypatch):
    monkeypatch.setattr(get_settings(), "sync_state_machine_arn", "")
    client.cookies.update(await login_as("Read Only"))
    assert (await client.post("/api/v1/refresh", params={"force": True})).status_code == 503


async def test_watcher_broadcasts_completion():
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("pubsub:platform_events")
    await pubsub.get_message(timeout=1)  # subscribe confirmation
    await redis_client.set("sync:global:lock", "x")
    outcome = await sync.watch_execution(FakeSfn(statuses=("RUNNING", "SUCCEEDED")), redis_client, "arn:exec:1",
                                         poll_seconds=0)
    assert outcome == "SUCCEEDED"
    message = None
    for _ in range(10):
        message = await pubsub.get_message(timeout=1)
        if message and message["type"] == "message":
            break
    event = json.loads(message["data"])
    assert event["type"] == "SYNC_COMPLETED" and event["payload"]["status"] == "SUCCEEDED"
    assert not await redis_client.exists("sync:global:lock")
    assert json.loads(await redis_client.get("sync:global:status"))["status"] == "SUCCEEDED"
    await pubsub.aclose()
