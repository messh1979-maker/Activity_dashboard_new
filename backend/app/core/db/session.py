import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine, 
    AsyncSession, 
    create_async_engine,
    async_sessionmaker,
    AsyncAttrs
)
from sqlalchemy.orm import DeclarativeBase
from contextlib import asynccontextmanager

from app.core.config import settings


# Engine creation
#
# NOTE (dev, no-Docker): ORM models in app/modules/*/db/Models.py declare
# unqualified table names while alembic DDL creates one schema per module
# (auth, rbac, groups, planning, chat, inbox, ...). The search_path below
# makes those unqualified names resolve to the right schema without
# rewriting every model. Table names are unique across schemas, so this
# is unambiguous. Long-term (per Architecture v2.0 ADR-04) each model
# should declare its own __table_args__ = {"schema": ...}.
engine: AsyncEngine = create_async_engine(
    # PostgresDsn validates to a URL object; the engine needs a plain string.
    str(settings.SQLALCHEMY_DATABASE_URI),
    echo=settings.SQL_ECHO,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "server_settings": {
            "search_path": (
                "public,auth,rbac,groups,planning,calendar,chat,files,"
                "inbox,notification,reporting,sharing,ssoldap,audit"
            )
        }
    },
)

# Session factory
async_session_factory = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# Context manager for getting a session
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session."""
    async with async_session_factory() as session:
        yield session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: one session per request, one transaction.

    Commits when the handler returns, rolls back on any exception. Business
    data and the outbox/audit rows written through the same session are
    therefore atomic (architecture 2.3 / 12.3).
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Close pooled connections (called from the app lifespan on shutdown)."""
    await engine.dispose()


# Unit of Work pattern
class UnitOfWork:
    """Unit of Work pattern for managing database transactions."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def commit(self):
        """Commit the current transaction."""
        await self.session.commit()
    
    async def rollback(self):
        """Rollback the current transaction."""
        await self.session.rollback()
    
    async def refresh(self, obj):
        """Refresh an object from the database."""
        await self.session.refresh(obj)
    
    async def add(self, obj) -> None:
        """Add an object to the session."""
        self.session.add(obj)
    
    async def delete(self, obj) -> None:
        """Delete an object from the session."""
        await self.session.delete(obj)
    
    async def get(self, model, id):
        """Get a model by ID."""
        from sqlalchemy import select
        result = await self.session.execute(select(model).where(model.id == id))
        return result.scalar_one_or_none()
    
    async def execute(self, *args, **kwargs):
        """Execute a raw SQL statement."""
        return await self.session.execute(*args, **kwargs)


# Transaction decorator/context manager
class Transaction:
    """Transaction manager for handling database transactions."""
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.uow.rollback()
            return False
        await self.uow.commit()
        return None


# Export
__all__ = [
    "engine", "async_session_factory", "get_session", "get_db",
    "dispose_engine", "UnitOfWork", "Transaction",
]