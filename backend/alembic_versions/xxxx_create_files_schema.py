"""create files schema (uploads)

سند معماری v2.0. revision/down_revision را طبق تاریخچه‌ی واقعی خودتان تنظیم کنید.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "REPLACE_ME"
down_revision = "REPLACE_ME_WITH_CURRENT_HEAD"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS files")

    op.create_table(
        "uploads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("uploader_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("context_type", sa.String(length=32), nullable=False),
        sa.Column("context_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("original_name", sa.String(length=255), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False, unique=True),
        sa.Column("mime_declared", sa.String(length=128), nullable=True),
        sa.Column("mime_detected", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("scan_status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("scan_engine", sa.String(length=32), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_available", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("size_bytes > 0 AND size_bytes <= 52428800", name="ck_uploads_size"),
        sa.CheckConstraint("scan_status IN ('pending','clean','infected','error')", name="ck_uploads_scan_status"),
        schema="files",
    )
    op.create_index(
        "ix_uploads_scan", "uploads", ["scan_status"], schema="files",
        postgresql_where=sa.text("scan_status = 'pending'"),
    )
    op.create_index("ix_uploads_context", "uploads", ["context_type", "context_id"], schema="files")
    op.create_index("ix_uploads_uploader", "uploads", ["uploader_id"], schema="files")


def downgrade() -> None:
    op.drop_table("uploads", schema="files")
