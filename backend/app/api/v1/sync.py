"""Smart manual refresh (APP_FLOW section 2) and the live event WebSocket.

POST /api/v1/refresh
  data < SAS_REFRESH_FRESHNESS_SECONDS old and not force -> 200 {"status": "ready"}
  a sync already running                                 -> 202 {"status": "syncing", ...}
  otherwise: Redis lock sync:global:lock, StartExecution  -> 202 {"status": "syncing", "execution_arn"}
  A background watcher polls DescribeExecution and publishes SYNC_COMPLETED when the execution ends.
  SAS_SYNC_BACKEND=worker (self-hosted): the request is queued on sync:requests; the worker runs it, then clears
  the lock and publishes SYNC_COMPLETED itself.
WS /ws/events: authenticated by the same session cookie, Origin-checked, relays pubsub:platform_events.
"""

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta

import boto3
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import events
from app.config import get_settings
from app.database import SessionLocal, get_db, get_redis, redis_client
from app.models import Account
from app.security import Principal, principal_from_session, require

log = logging.getLogger(__name__)
router = APIRouter(tags=["sync"])
ws_router = APIRouter()

STATUS_KEY, LOCK_KEY, REQUESTS_KEY = "sync:global:status", "sync:global:lock", "sync:requests"
STALE_SYNC = timedelta(hours=2)  # a "syncing" status older than this is from a crashed watcher
POLL_SECONDS = 15
_watchers: set[asyncio.Task] = set()


def get_sfn_client():
    """Overridden in tests."""
    return boto3.client("stepfunctions", region_name=get_settings().aws_region)


async def watch_execution(sfn, redis: Redis, execution_arn: str, poll_seconds: float = POLL_SECONDS) -> str:
    deadline = datetime.now(UTC) + STALE_SYNC
    outcome = "TIMED_OUT"
    while datetime.now(UTC) < deadline:
        described = await asyncio.to_thread(sfn.describe_execution, executionArn=execution_arn)
        if described["status"] != "RUNNING":
            outcome = described["status"]
            break
        await asyncio.sleep(poll_seconds)
    finished = {"status": outcome, "execution_arn": execution_arn, "finished_at": datetime.now(UTC).isoformat()}
    await redis.set(STATUS_KEY, json.dumps(finished), ex=21_600)
    await redis.delete(LOCK_KEY)
    await events.publish(redis, "SYNC_COMPLETED", finished)
    return outcome


@router.post("/refresh")
async def refresh(force: bool = False, principal: Principal = Depends(require("VIEW")),
                  db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
                  sfn=Depends(get_sfn_client)):
    settings = get_settings()
    now = datetime.now(UTC)
    current = json.loads(await redis.get(STATUS_KEY) or "{}")
    if current.get("status") == "syncing" and now - datetime.fromisoformat(current["started_at"]) < STALE_SYNC:
        return JSONResponse(current, status_code=status.HTTP_202_ACCEPTED)

    last_sync = await db.scalar(select(func.max(Account.last_discovered)))
    if not force and last_sync and now - last_sync < timedelta(seconds=settings.refresh_freshness_seconds):
        return {"status": "ready", "last_sync": last_sync.isoformat()}
    if settings.sync_backend == "worker":
        return await queue_worker_sync(redis, principal, now)
    if not settings.sync_state_machine_arn:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Sync state machine is not configured")
    if not await redis.set(LOCK_KEY, "starting", nx=True, ex=300):
        return JSONResponse({"status": "syncing", "detail": "A sync is being started"},
                            status_code=status.HTTP_202_ACCEPTED)
    try:
        started = await asyncio.to_thread(sfn.start_execution, stateMachineArn=settings.sync_state_machine_arn,
                                          input=json.dumps({"mode": "full"}))
    except Exception:
        await redis.delete(LOCK_KEY)
        raise
    syncing = {"status": "syncing", "execution_arn": started["executionArn"], "started_at": now.isoformat(),
               "requested_by": principal.email}
    await redis.set(LOCK_KEY, started["executionArn"], ex=int(STALE_SYNC.total_seconds()))
    await redis.set(STATUS_KEY, json.dumps(syncing), ex=21_600)
    await events.publish(redis, "SYNC_STARTED", syncing)
    task = asyncio.create_task(watch_execution(sfn, redis, started["executionArn"]))
    _watchers.add(task)  # keep a reference so the task isn't garbage-collected mid-flight
    task.add_done_callback(_watchers.discard)
    return JSONResponse(syncing, status_code=status.HTTP_202_ACCEPTED)


async def queue_worker_sync(redis: Redis, principal: Principal, now: datetime) -> JSONResponse:
    if not await redis.set(LOCK_KEY, "api", nx=True, ex=int(STALE_SYNC.total_seconds())):
        return JSONResponse({"status": "syncing", "detail": "A sync is already running"},
                            status_code=status.HTTP_202_ACCEPTED)
    syncing = {"status": "syncing", "started_at": now.isoformat(), "requested_by": principal.email}
    await redis.set(STATUS_KEY, json.dumps(syncing), ex=21_600)
    await redis.rpush(REQUESTS_KEY, json.dumps({"mode": "full", "requested_by": principal.email}))
    await events.publish(redis, "SYNC_STARTED", syncing)
    return JSONResponse(syncing, status_code=status.HTTP_202_ACCEPTED)


@ws_router.websocket("/ws/events")
async def event_stream(websocket: WebSocket):
    settings = get_settings()
    origin = websocket.headers.get("origin")
    if origin and origin not in settings.cors_origins:  # cross-site WebSocket hijacking guard
        await websocket.close(code=1008)
        return
    try:
        async with SessionLocal() as db:
            principal = await principal_from_session(websocket.cookies.get(settings.session_cookie_name), db,
                                                     redis_client)
    except HTTPException:
        await websocket.close(code=1008)
        return
    if not principal.has("VIEW"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(events.CHANNEL)

    async def relay():
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])

    relay_task = asyncio.create_task(relay())
    try:
        while True:  # client messages are ignored; receive() surfaces the disconnect
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        relay_task.cancel()
        await pubsub.unsubscribe(events.CHANNEL)
        await pubsub.aclose()
