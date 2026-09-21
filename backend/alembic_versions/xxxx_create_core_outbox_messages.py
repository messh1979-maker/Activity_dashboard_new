"""create core.outbox_messages

سند معماری v2.0، بخش ۲.۳.

⚠️ این فایل را در ``backend/alembic/versions/`` کپی کنید و نام آن را
طبق قرارداد Alembic خودتان (پیشوند ``down_revision``/hash) اصلاح کنید؛
من به تاریخچه‌ی Migration واقعی شما دسترسی ندارم، پس ``revision`` و
``down_revision`` را باید دستی تنظیم کنید (معمولاً ``alembic revision``
این را خودکار می‌سازد — کافی است بدنه‌ی ``upgrade``/``downgrade`` را از
اینجا کپی کنید).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# TODO: مقداردهی توسط شما یا ابزار alembic
revision = "REPLACE_ME"
down_revision = "REPLACE_ME_WITH_CURRENT_HEAD"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS core")

    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        schema="core",
    )

    op.create_index(
        "ix_outbox_pending",
        "outbox_messages",
        ["created_at"],
        schema="core",
        postgresql_where=sa.text("dispatched_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_pending", table_name="outbox_messages", schema="core")
    op.drop_table("outbox_messages", schema="core")
