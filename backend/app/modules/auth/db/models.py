"""Auth DB models matching ``alembic/versions/auth_schema.sql``.

Column types mirror the SQL schema exactly (PostgreSQL UUID/ENUM/INET/JSONB)
so INSERTs succeed. Columns that the database fills via defaults
(created_at, failed counters, ...) are omitted from the model.
"""
import uuid as uuid_lib
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, INET, JSONB, UUID as PGUUID

from app.core.db.base import Base

auth_mode_enum = ENUM(
    "local", "sso", "both",
    name="auth_mode", schema="auth", create_type=False,
)
login_method_enum = ENUM(
    "local", "sso", "ldap", "kerberos", "recovery",
    name="login_method", schema="auth", create_type=False,
)


class Users(Base):
    """Application users (table ``auth.users``)."""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    username = Column(String(64), nullable=False)
    national_id_enc = Column(LargeBinary, nullable=False)
    national_id_nonce = Column(LargeBinary, nullable=False)
    national_id_hash = Column(String(64), nullable=False)
    national_id_last4 = Column(String(4), nullable=False)
    display_name = Column(String(128), nullable=False)
    auth_mode = Column(auth_mode_enum, nullable=False, default="local")
    password_hash = Column(Text, nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    token_version = Column(Integer, nullable=False, default=1)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_method = Column(String(16), nullable=True)
    mfa_secret_enc = Column(LargeBinary, nullable=True)
    mfa_secret_nonce = Column(LargeBinary, nullable=True)
    mfa_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class UserDevices(Base):
    """Registered user devices (table ``auth.user_devices``)."""

    __tablename__ = "user_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint",
                         name="uq_device_user_fingerprint"),
        {"schema": "auth", "extend_existing": True},
    )

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_fingerprint = Column(String(255), nullable=False)
    mac_address = Column(String(17), nullable=True)
    mac_source = Column(String(16), nullable=True)
    platform = Column(String(16), nullable=False)
    device_label = Column(String(128), nullable=True)
    os_info = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
    hmac_key_enc = Column(LargeBinary, nullable=True)
    is_trusted = Column(Boolean, nullable=False, default=False)
    trusted_at = Column(DateTime(timezone=True), nullable=True)
    trusted_by_mfa = Column(Boolean, nullable=False, default=False)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_ip = Column(INET, nullable=True)
    is_blocked = Column(Boolean, nullable=False, default=False)
    blocked_reason = Column(String(255), nullable=True)


class Sessions(Base):
    """Login sessions / refresh families (table ``auth.sessions``)."""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.user_devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    refresh_hash = Column(String(64), nullable=False, unique=True)
    family_id = Column(PGUUID(as_uuid=True), nullable=False)
    auth_method = Column(login_method_enum, nullable=False)
    mfa_satisfied = Column(Boolean, nullable=False, default=False)
    ip_address = Column(INET, nullable=True)
    geo_location = Column(JSONB, nullable=True)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_active_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(64), nullable=True)


Index("ix_auth_users_hash", Users.national_id_hash)


class MFARecoveryCodes(Base):
    """MFA recovery codes (table ``auth.mfa_recovery_codes``)."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash = Column(String(64), nullable=False, unique=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["Users", "UserDevices", "Sessions", "MFARecoveryCodes"]
