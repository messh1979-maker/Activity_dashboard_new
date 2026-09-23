"""Database access compatibility layer.

Re-exports the async engine/session from ``app.core.db.session`` under the
names the rest of the codebase imports (``get_session``, ``engine``,
``async_session_context``, ``get_async_session``).
"""
from app.core.db.session import (
    async_session_factory,
    dispose_engine,
    engine,
    get_db,
    get_session,
)

# Alias used as ``async with async_session_context() as session:``.
async_session_context = get_session

# Alias used as a FastAPI dependency / factory.
get_async_session = get_session

__all__ = [
    "engine",
    "get_session",
    "async_session_factory",
    "async_session_context",
    "get_async_session",
    "get_db",
    "dispose_engine",
]
