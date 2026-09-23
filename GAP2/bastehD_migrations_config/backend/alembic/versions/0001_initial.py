"""Initial schema: 13 module SQL files in FK-safe order.

Applied manually on 2026-09-19 with several PG-validity fixes
(inline INDEX -> CREATE INDEX, expression PKs -> partial unique indexes,
missing CREATE SCHEMA, partitioned PK including partition key).
`alembic stamp head` was used on the dev database; fresh databases can run
`alembic upgrade head` to execute everything below.
"""
import os

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = [
    "auth", "rbac", "groups", "planning", "calendar", "chat", "files",
    "inbox", "notification", "reporting", "sharing", "ssoldap", "audit",
]

# FK-safe order: auth first (referenced everywhere), chat before files
# (chat creates files.uploads), audit last.
SQL_FILES = [
    "auth_schema.sql",
    "rbac_schema.sql",
    "groups_schema.sql",
    "planning_schema.sql",
    "calendar_schema.sql",
    "chat_schema.sql",
    "files_schema.sql",
    "inbox_schema.sql",
    "notification_schema.sql",
    "reporting_schema.sql",
    "sharing_schema.sql",
    "ssoldap_schema.sql",
    "audit_schema.sql",
]


def _sql_dir():
    return os.path.dirname(os.path.realpath(__file__))


def upgrade():
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    for name in SQL_FILES:
        path = os.path.join(_sql_dir(), name)
        with open(path, encoding="utf-8") as fh:
            op.execute(fh.read())


def downgrade():
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
