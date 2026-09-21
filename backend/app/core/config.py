"""Application configuration (Pydantic Settings, loaded from ENV / .env).

Architecture v2.0: section 3.1 (core/config.py) and 13.5 (deployment hardening).

Validation happens *inside* the model. (The previous version declared the
``@field_validator`` functions at module level, so they were never applied and
a weak ``SECRET_KEY`` / empty password was silently accepted.)
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRETS = {
    "change-me-to-a-random-string-at-least-32-chars-long",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application
    APP_NAME: str = "Planner Enterprise API"
    APP_VERSION: str = "2.0.0"
    ENV: str = "development"  # development | testing | production
    DEBUG: bool = False
    SQL_ECHO: bool = False  # log every SQL statement (was tied to ENV before)

    # ── Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Security
    SECRET_KEY: str = Field(..., min_length=32)
    # HS256 (shared secret) by default; set both JWT_*_KEY for RS256 (ADR / 3.1).
    ALGORITHM: str = "HS256"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 1440
    # Separate keys per purpose (section 4.9). When unset they are derived from
    # SECRET_KEY, which is acceptable for dev only (enforced in production).
    DATA_ENCRYPTION_KEY: str | None = None   # base64, 32 bytes (AES-256-GCM)
    NATIONAL_ID_PEPPER: str | None = None    # HMAC key for searchable hash

    # ── Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    SQLALCHEMY_DATABASE_URI: PostgresDsn = Field(
        ...,
        validation_alias=AliasChoices("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"),
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30

    # ── Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str | None = None  # overrides host/port/db when set

    # ── HTTP hardening
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    # WebSocket Origin allow-list (WebSocket is not covered by CORS, 12.8).
    # Empty -> falls back to CORS_ORIGINS.
    ALLOWED_ORIGINS: List[str] = []
    TRUSTED_PROXIES: List[str] = []  # only these may set X-Forwarded-For
    IP_ALLOW_LIST: List[str] = []
    IP_DENY_LIST: List[str] = []
    MAX_BODY_SIZE: int = 1_048_576  # 1 MiB for JSON endpoints

    # ── Feature flags
    ENABLE_MFA: bool = True
    ENABLE_SSO: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ALLOW_SELF_REGISTRATION: bool = False
    DEVICE_BINDING_MODE: str = "observe"  # off | observe | enforce (ADR-08)

    # ── Rate limiting (limits are "N/period", period: second|minute|hour)
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_ENABLED: bool = True

    # ── Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    ROOT_PATH: str = ""

    # ── File storage
    MAX_UPLOAD_SIZE: int = 52_428_800  # 50MB
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/gif"]
    ALLOWED_DOCUMENT_TYPES: List[str] = [
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]

    # ── Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s "
        "[%(filename)s:%(lineno)d]"
    )

    # ── Key rotation (key_version is stored beside encrypted data, 4.9)
    KEY_ROTATION_INTERVAL_DAYS: int = 365
    KEY_VERSION: int = 1

    # ------------------------------------------------------------------ #
    @field_validator("SECRET_KEY")
    @classmethod
    def _secret_key_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("ALGORITHM")
    @classmethod
    def _algorithm_allowed(cls, v: str) -> str:
        if v not in {"HS256", "RS256"}:
            raise ValueError("ALGORITHM must be HS256 or RS256 ('none' is never allowed)")
        return v

    @field_validator("DEVICE_BINDING_MODE")
    @classmethod
    def _device_mode(cls, v: str) -> str:
        if v not in {"off", "observe", "enforce"}:
            raise ValueError("DEVICE_BINDING_MODE must be off | observe | enforce")
        return v

    @model_validator(mode="after")
    def _cross_field_checks(self) -> "Settings":
        if self.ALGORITHM == "RS256" and not (self.JWT_PRIVATE_KEY and self.JWT_PUBLIC_KEY):
            raise ValueError("ALGORITHM=RS256 requires JWT_PRIVATE_KEY and JWT_PUBLIC_KEY")
        if self.ENV == "production":
            problems = []
            if self.SECRET_KEY in _INSECURE_SECRETS:
                problems.append("SECRET_KEY is a placeholder value")
            if "*" in self.ALLOWED_HOSTS:
                problems.append("ALLOWED_HOSTS must not contain '*'")
            if self.DEBUG:
                problems.append("DEBUG must be false")
            if not self.DATA_ENCRYPTION_KEY:
                problems.append("DATA_ENCRYPTION_KEY must be set (section 4.9)")
            if not self.NATIONAL_ID_PEPPER:
                problems.append("NATIONAL_ID_PEPPER must be set (ADR-06)")
            if self.DEVICE_BINDING_MODE == "off":
                problems.append("DEVICE_BINDING_MODE must not be 'off'")
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    # ------------------------------------------------------------------ #
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL or f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def ws_allowed_origins(self) -> List[str]:
        return self.ALLOWED_ORIGINS or self.CORS_ORIGINS


settings = Settings()


def get_db_url() -> str:
    """Async SQLAlchemy URL (single source of truth: SQLALCHEMY_DATABASE_URI)."""
    return str(settings.SQLALCHEMY_DATABASE_URI)
