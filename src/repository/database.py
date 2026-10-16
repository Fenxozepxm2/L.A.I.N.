import json
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import load_config

config = load_config()


def custom_json_serializer(*args, **kwargs):
    kwargs["ensure_ascii"] = False
    return json.dumps(*args, **kwargs)


engine = create_async_engine(
    config.database_url.url,
    echo=True,
    future=True,
    json_serializer=custom_json_serializer,
)

Async_fabric_make = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_session() -> AsyncGenerator:
    async with Async_fabric_make() as session:
        yield session
