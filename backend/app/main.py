"""
Planner Enterprise API - Main Application Entry Point

Architecture: Modular Monolith with Defense in Depth
Version: 2.0
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import dispose_engine, engine
from app.core.errors import register_exception_handlers
from app.core.events import event_bus
from app.core.middleware import register_middlewares
from app.modules import auth, rbac, groups, goals, sharing, chat, inbox, \
                        reporting, notification, audit, ssoldap, files

logging.basicConfig(level=settings.LOG_LEVEL, format=settings.LOG_FORMAT)

# Module order matters for initialization
MODULES = [auth, rbac, groups, goals, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Event bus subscriptions (modules without handlers are skipped)
    for m in MODULES:
        register = getattr(m, "register_event_handlers", None)
        if callable(register):
            register(event_bus)

    yield

    # Graceful shutdown: return pooled connections to PostgreSQL
    await shutdown_gracefully()


_docs_enabled = not settings.is_production

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    root_path=settings.ROOT_PATH,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# --- Middleware chain (single place; order documented in core/middleware) ---
register_middlewares(app)

# --- Exception handlers ---
register_exception_handlers(app)

# --- Include Module Routers ---
# All modules use /api/v1 prefix.
# Empty/stub modules (audit, files, notification, ssoldap) expose no router
# yet and are skipped until their routes land.
for m in MODULES:
    router = getattr(m, "router", None)
    if router is not None:
        app.include_router(router, prefix="/api/v1")

async def shutdown_gracefully():
    """Graceful shutdown routine."""
    await dispose_engine()


# Liveness: process is up (no dependencies touched)
@app.get("/health", include_in_schema=False)
async def health_check():
    return {
        "status": "healthy",
        "service": "planner-enterprise-api",
        "version": settings.APP_VERSION,
        "modules": [m.__name__ for m in MODULES],
    }


# Readiness: dependencies reachable (used by the load balancer)
@app.get("/ready", include_in_schema=False)
async def readiness_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger("app.health").exception("readiness: database unreachable")
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "down"})
    return {"status": "ready", "database": "up"}


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    return {
        "message": "Planner Enterprise API",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.ENV != "production" else "disabled",
        "endpoints": "/api/v1/auth, /api/v1/goals, /api/v1/groups, etc."
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        access_log=False
    )