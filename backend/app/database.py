from collections.abc import AsyncIterator

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

_settings = get_settings()

engine = create_async_engine(_settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

redis_client: Redis = Redis.from_url(_settings.redis_url, decode_responses=True)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


async def get_redis() -> Redis:
    return redis_client
