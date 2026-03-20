"""
Async database engine, session factory, and lifecycle helpers.

Uses SQLAlchemy 2.0 with the asyncpg driver for PostgreSQL.
All application code should obtain sessions via `get_db_session()` or
the `get_db()` FastAPI dependency, never instantiate sessions directly.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from config.settings import db_settings

logger = logging.getLogger(__name__)


# ─── Declarative base shared by all ORM models ────────────────────────────────


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# ─── Engine & Session factory ─────────────────────────────────────────────────


def _create_engine() -> AsyncEngine:
    """Build and configure the async SQLAlchemy engine.

    SQLite (aiosqlite) uses a NullPool and does not support pool_size /
    max_overflow — those kwargs are only passed for PostgreSQL.
    """
    url = db_settings.async_url
    if db_settings.is_sqlite:
        from sqlalchemy.pool import StaticPool
        return create_async_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )
    return create_async_engine(
        url,
        pool_size=db_settings.pool_size,
        max_overflow=db_settings.max_overflow,
        pool_pre_ping=True,
        echo=False,
    )


# Lazily-initialised module-level singletons
engine: AsyncEngine = _create_engine()

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ─── Session helpers ──────────────────────────────────────────────────────────


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that yields a database session.

    Commits on success; rolls back and re-raises on any exception.
    Always closes the session in the finally block.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that injects a database session into route handlers.

    Usage::

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with get_db_session() as session:
        yield session


# ─── Lifecycle helpers ────────────────────────────────────────────────────────


async def init_database() -> None:
    """
    Create all database tables from ORM metadata.

    Suitable for development / testing.  In production use Alembic migrations.
    """
    async with engine.begin() as conn:
        # Import models so SQLAlchemy registers their metadata before creation
        import database.models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialised.")


async def close_database() -> None:
    """Dispose the engine's connection pool on application shutdown."""
    await engine.dispose()
    logger.info("Database connection pool closed.")
