"""Shared test setup. Environment is fixed *before* ``app`` is imported."""
import os

os.environ.setdefault("ENV", "testing")
os.environ.setdefault("DEBUG", "false")  # a local .env must not leak into tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+asyncpg://admin:admin123@localhost:5432/planner_db",
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
