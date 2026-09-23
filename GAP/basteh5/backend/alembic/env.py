import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Ensure `backend/` (project root for `app.*`) is on sys.path when
# alembic runs from D:\Projects\Activity_dashboard\backend.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _load_dotenv(path):
    """Minimal .env loader (avoids a python-dotenv dependency)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(_BACKEND_DIR, ".env"))

# Alembic runs in sync mode, but the app .env uses the async driver
# (postgresql+asyncpg://...). Convert it to the sync psycopg2 driver,
# which is what requirements.txt ships (psycopg2-binary).
_db_url = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    config.get_main_option("sqlalchemy.url"),
)
if _db_url and "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "+psycopg2")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

try:
    from app.core.db.base import Base  # noqa: E402

    target_metadata = Base.metadata
except Exception:
    from sqlalchemy import MetaData  # noqa: E402

    target_metadata = MetaData()

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    
    This configures the context with just a URL
    and gives us the ability to emit SQL script without
    needing a DBAPI.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    
    In this mode we need to connect to the database and run migrations
    against a live connection.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()