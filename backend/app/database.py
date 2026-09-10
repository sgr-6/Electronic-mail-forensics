"""
Async SQLAlchemy database engine and session management.

Defaults to SQLite for zero-config local development.
Seamlessly switches to PostgreSQL when DATABASE_URL is set in .env.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

import logging

logger = logging.getLogger(__name__)

# Create async engine with appropriate settings for the backend
connect_args = {}
if settings.is_sqlite:
    connect_args["check_same_thread"] = False

engine = create_async_engine(
    settings.database_url,
    echo=settings.app_debug,
    connect_args=connect_args,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def init_db() -> None:
    """Create all tables. Called on application startup with SQLite fallback if remote DB is unreachable."""
    global engine, async_session_factory
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        if not settings.is_sqlite:
            logger.warning("Remote database connection failed (%s). Falling back to local SQLite database.", e)
            sqlite_url = "sqlite+aiosqlite:///./data.db"
            engine = create_async_engine(sqlite_url, echo=settings.app_debug, connect_args={"check_same_thread": False})
            async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        else:
            raise


async def get_session() -> AsyncSession:
    """Dependency: yield an async database session."""
    async with async_session_factory() as session:
        yield session
