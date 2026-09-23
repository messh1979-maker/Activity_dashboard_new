from datetime import datetime
from alembic import context
from sqlalchemy import engine_from_config, pool, MetaData, Table, Column, String, DateTime
import os

# Add models here so they are registered before head generates
import sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/../../../../..')

from backend.app.core.db.base import Base

# Get target metadata from Base
target_metadata = Base.metadata

# Get URL from config
config = context.config
url = config.get_main_option("sqlalchemy.url")

engine = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix="sqlalchemy.",
    poolclass=pool.NullPool,
)

# Run a simple query to check connection
with engine.connect() as connection:
    connection.execute("SELECT 1")

# Set the revision to the latest base
opts = {}
if context.is_offline_mode():
    opts['input_file'] = 'offline.sql'
else:
    # Set head to the latest migration
    opts['sqlalchemy.url'] = url

# Set target_metadata
target_metadata.bind = engine