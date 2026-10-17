"""Real-time platform events over Redis pub/sub (`pubsub:platform_events`), fanned out to browsers by /ws/events.

Every API worker subscribes, so an event published by any worker (or any process) reaches every connected client.
Event types: SYNC_STARTED, SYNC_COMPLETED, APPROVAL_REQUESTED, APPROVAL_UPDATED.
"""

import json
from datetime import UTC, datetime

from redis.asyncio import Redis

CHANNEL = "pubsub:platform_events"


async def publish(redis: Redis, event_type: str, payload: dict) -> None:
    message = {"type": event_type, "payload": payload, "at": datetime.now(UTC).isoformat()}
    await redis.publish(CHANNEL, json.dumps(message, default=str))
