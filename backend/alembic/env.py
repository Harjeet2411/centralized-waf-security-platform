import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context
from app.config import get_settings
from app.models import Base

target_metadata = Base.metadata


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    url = context.config.attributes.get("database_url") or get_settings().database_url
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        await conn.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=get_settings().database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_run_online())
