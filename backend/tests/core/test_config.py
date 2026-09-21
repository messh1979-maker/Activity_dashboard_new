import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE = dict(
    SECRET_KEY="x" * 40,
    SQLALCHEMY_DATABASE_URI="postgresql+asyncpg://u:p@localhost/db",
)


def make(**kw):
    return Settings(_env_file=None, **{**BASE, **kw})


def test_short_secret_key_rejected():
    with pytest.raises(ValidationError):
        make(SECRET_KEY="short")


def test_unknown_algorithm_rejected():
    with pytest.raises(ValidationError):
        make(ALGORITHM="none")


def test_rs256_requires_keys():
    with pytest.raises(ValidationError):
        make(ALGORITHM="RS256")


def test_production_rejects_insecure_defaults():
    with pytest.raises(ValidationError) as e:
        make(ENV="production")  # ALLOWED_HOSTS '*', no DEK/pepper
    msg = str(e.value)
    assert "ALLOWED_HOSTS" in msg and "DATA_ENCRYPTION_KEY" in msg and "NATIONAL_ID_PEPPER" in msg


def test_production_ok_when_hardened():
    s = make(ENV="production", ALLOWED_HOSTS=["api.corp.local"],
             DATA_ENCRYPTION_KEY="a" * 44, NATIONAL_ID_PEPPER="p" * 32)
    assert s.is_production


def test_log_format_is_valid():
    import logging
    s = make()
    rec = logging.LogRecord("n", logging.INFO, "f.py", 1, "hello", None, None)
    assert "INFO" in logging.Formatter(s.LOG_FORMAT).format(rec)


def test_redis_url_and_ws_origins_fallback():
    s = make(REDIS_HOST="r", REDIS_PORT=1, REDIS_DB=2)
    assert s.redis_url == "redis://r:1/2"
    assert s.ws_allowed_origins == s.CORS_ORIGINS
