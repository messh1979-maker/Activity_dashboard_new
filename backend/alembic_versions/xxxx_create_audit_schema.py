"""create audit schema (audit_logs, login_audit_logs)

سند معماری v2.0، بخش ۴.۸. مثل migration outbox، revision/down_revision
را خودتان طبق تاریخچه‌ی واقعی alembic تنظیم کنید.

⚠️ پارتیشن‌بندی (`PARTITION BY RANGE`) عمداً در این migration نیست —
برای MVP جدول ساده کافی است؛ بعداً یک migration جدا برای تبدیل به
جدول پارتیشن‌بندی‌شده اضافه کنید (این تبدیل در PostgreSQL نیازمند
بازسازی جدول است، پس بهتر است زودتر، قبل از انباشت داده‌ی واقعی
تصمیم‌گیری شود).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "REPLACE_ME"
down_revision = "REPLACE_ME_WITH_CURRENT_HEAD"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS audit")

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=True),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("mac_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("device_fingerprint", sa.String(length=255), nullable=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("result", sa.String(length=20), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("old_value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("new_value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("geo_location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("prev_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("row_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="audit",
    )
    op.create_index("idx_audit_user_time", "audit_logs", ["user_id", "timestamp"], schema="audit")
    op.create_index("idx_audit_mac", "audit_logs", ["mac_address"], schema="audit",
                     postgresql_where=sa.text("mac_address IS NOT NULL"))
    op.create_index("idx_audit_ip", "audit_logs", ["ip_address"], schema="audit")
    op.create_index("idx_audit_action", "audit_logs", ["action", "timestamp"], schema="audit")
    op.create_index("idx_audit_fingerprint", "audit_logs", ["device_fingerprint"], schema="audit")
    op.create_index("idx_audit_entity", "audit_logs", ["entity_type", "entity_id", "timestamp"], schema="audit")

    op.create_table(
        "login_audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("username", sa.String(length=100), nullable=True),
        sa.Column("national_id_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("auth_method", sa.String(length=20), nullable=False),
        sa.Column("mfa_used", sa.String(length=16), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("mac_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("device_fingerprint", sa.String(length=255), nullable=True),
        sa.Column("device_is_trusted", sa.Boolean(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.String(length=255), nullable=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("geo_location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("risk_score", sa.SmallInteger(), nullable=True),
        sa.Column("prev_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("row_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="audit",
    )
    op.create_index("idx_login_audit_user", "login_audit_logs", ["user_id", "timestamp"], schema="audit")
    op.create_index("idx_login_audit_mac", "login_audit_logs", ["mac_address"], schema="audit")
    op.create_index("idx_login_audit_ip", "login_audit_logs", ["ip_address", "timestamp"], schema="audit")
    op.create_index("idx_login_failed", "login_audit_logs", ["username", "timestamp"], schema="audit",
                     postgresql_where=sa.text("success = FALSE"))

    # طبق سند: «کاربر برنامه فقط اجازه‌ی درج دارد» — UPDATE/DELETE را حتی
    # از app_user هم می‌گیریم تا حذف/تغییر لاگ از مسیر اپلیکیشن ممکن نباشد.
    # ⚠️ اگر نام نقش دیتابیس شما «app_user» نیست، این را اصلاح کنید.
    op.execute("REVOKE UPDATE, DELETE ON ALL TABLES IN SCHEMA audit FROM app_user")
    op.execute("GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA audit TO app_user")


def downgrade() -> None:
    op.drop_table("login_audit_logs", schema="audit")
    op.drop_table("audit_logs", schema="audit")
