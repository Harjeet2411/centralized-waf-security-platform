"""TTL auto-expiry for temporary IP blocks (FR-21). Run every few minutes (EventBridge -> ECS scheduled task):

    python -m app.workers.ttl_expiry

ACTIVE blocks within the expiring window -> EXPIRING (UI badge); past expires_at -> the platform removes exactly the
IPs it added (inverse rollback, verified, audited as TTL_EXPIRY) -> ttl_status REMOVED, approval EXPIRED.
A Redis lock keeps concurrent runs from double-removing.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal, redis_client
from app.models import Change
from app.security import Principal
from app.services.approval_service import ExecutorFactory, default_executor_factory, rollback

log = logging.getLogger(__name__)
LOCK_KEY = "ttl:expiry:lock"
SYSTEM = Principal(user_id=uuid.UUID(int=0), email="ttl-expiry@sas-platform.internal", full_name="TTL expiry worker",
                   role="System", permissions=("ROLLBACK",), scoped_account_ids=(), mfa=False)


async def run_once(executor_factory: ExecutorFactory = default_executor_factory, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    if not await redis_client.set(LOCK_KEY, "1", nx=True, ex=300):
        return {"skipped": "another expiry run holds the lock"}
    stats = {"expiring": 0, "removed": 0, "failed": 0}
    try:
        window = now + timedelta(minutes=get_settings().ttl_expiring_window_minutes)
        async with SessionLocal() as db:
            for change in (await db.scalars(select(Change).where(
                    Change.ttl_status == "ACTIVE", Change.expires_at > now, Change.expires_at <= window))).all():
                change.ttl_status = "EXPIRING"
                stats["expiring"] += 1
            await db.commit()
            due = (await db.scalars(select(Change.id).where(
                Change.ttl_status.in_(("ACTIVE", "EXPIRING")), Change.expires_at <= now,
                Change.execution_status == "EXECUTED"))).all()
        for change_id in due:
            async with SessionLocal() as db:
                try:
                    await rollback(db, change_id, SYSTEM, executor_factory, reason="Temporary block TTL elapsed",
                                   system=True)
                    stats["removed"] += 1
                except HTTPException as exc:
                    stats["failed"] += 1
                    log.error("TTL expiry failed for change %s: %s", change_id, exc.detail)
    finally:
        await redis_client.delete(LOCK_KEY)
    return stats


if __name__ == "__main__":
    print(asyncio.run(run_once()))  # noqa: T201
