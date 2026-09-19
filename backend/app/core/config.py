import os
from pathlib import Path
from pydantic import AliasChoices, Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        # Use .env file if it exists
        env_file=".env",
        env_file_encoding="utf-8",
        # Case-insensitive env var names
        case_sensitive=False,
    )
    
    # Application
    APP_NAME: str = "Planner Enterprise API"
    APP_VERSION: str = "1.0.0"
    ENV: str = Field(default="development", env="ENV")
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Security
    SECRET_KEY: str = Field(..., env="SECRET_KEY")  # 32+ bytes
    # HS256 with the shared SECRET_KEY (RS256 would need an RSA keypair)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 1440
    
    # Database
    POSTGRES_SERVER: str = Field(..., env="POSTGRES_SERVER")
    POSTGRES_PORT: int = Field(default=5432, env="POSTGRES_PORT")
    POSTGRES_USER: str = Field(..., env="POSTGRES_USER")
    POSTGRES_PASSWORD: str = Field(..., env="POSTGRES_PASSWORD")
    POSTGRES_DB: str = Field(..., env="POSTGRES_DB")
    # Accept both names: .env/app use SQLALCHEMY_DATABASE_URI,
    # some tooling expects DATABASE_URL.
    SQLALCHEMY_DATABASE_URI: PostgresDsn = Field(
        ...,
        validation_alias=AliasChoices("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"),
    )
    
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    
    # Security headers
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    # Feature flags
    ENABLE_MFA: bool = True
    ENABLE_SSO: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    ROOT_PATH: str = ""  # For reverse proxy setups
    
    # Rate limiting
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    
    # File storage
    MAX_UPLOAD_SIZE: int = 52428800  # 50MB
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/gif"]
    ALLOWED_DOCUMENT_TYPES: List[str] = [
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ]
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(level)s - %(message)s [%(filename)s:%(lineno)d]"

    # Migration: key_version fields should already exist in DB schema
    # Key rotation settings
    KEY_ROTATION_INTERVAL_DAYS: int = 365
    KEY_VERSION: int = 1


# Singleton instance
settings = Settings()


# Convenience accessors
def get_db_url() -> str:
    """Get the full database connection URL."""
    return f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@" \
           f"{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"


# Validation helpers
@field_validator("POSTGRES_PASSWORD")
@classmethod
def password_not_empty(cls, v):
    if not v or v == "change_me":
        raise ValueError("POSTGRES_PASSWORD must be set in environment")
    return v


@field_validator("SECRET_KEY")
@classmethod
def secret_key_not_empty(cls, v):
    if not v or len(v) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters")
    return v