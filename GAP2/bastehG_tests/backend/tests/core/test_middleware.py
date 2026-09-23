import httpx
import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_context
from app.core.errors import (APIError, NotFoundError, PermissionDeniedError,
                             register_exception_handlers)
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import (MemoryLimiter, RateLimitMiddleware,
                                            parse_limit)
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


class Body(BaseModel):
    n: int


def make_app(*, rate="3/minute", auth="2/minute", deny=None, allow=None):
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/ctx")
    async def ctx():
        c = get_context()
        return {"rid": c.request_id, "ip": c.ip, "ua": c.user_agent, "mac": c.mac_address,
                "fp": c.device_fingerprint}

    @app.get("/api/v1/auth/login")
    async def login():
        return {}

    @app.post("/echo")
    async def echo(b: Body):
        return b.model_dump()

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internals")

    @app.get("/nf")
    async def nf():
        raise NotFoundError("گروه")

    @app.get("/deny")
    async def deny_():
        raise PermissionDeniedError("CANNOT_SELF_ASSIGN")

    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=MemoryLimiter(), default=rate, auth=auth)
    app.add_middleware(IPFilterMiddleware, allow_ips=allow, deny_ips=deny)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    return app


def client(app, **kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                                           client=("10.1.1.1", 5000)),
                             base_url="http://t", **kw)


async def test_request_id_and_security_headers():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "abcdefgh-1234"})
    assert r.headers["x-request-id"] == "abcdefgh-1234"
    assert r.json()["rid"] == "abcdefgh-1234"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


async def test_unsafe_request_id_is_replaced():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "bad id\r\nX: y"})
    assert " " not in r.headers["x-request-id"]


async def test_audit_context_from_headers_and_socket():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"User-Agent": "PlannerDesktop/2.0",
                                          "X-Device-MAC": "00-1a-2b-3c-4d-5e",
                                          "X-Device-Fingerprint": "a" * 32})
    j = r.json()
    assert j["ip"] == "10.1.1.1" and j["ua"] == "PlannerDesktop/2.0"
    assert j["mac"] == "00:1A:2B:3C:4D:5E" and j["fp"] == "a" * 32


async def test_invalid_mac_is_dropped():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Device-MAC": "not-a-mac"})
    assert r.json()["mac"] is None


async def test_x_forwarded_for_ignored_from_untrusted_peer():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Forwarded-For": "6.6.6.6"})
    assert r.json()["ip"] == "10.1.1.1"


async def test_rate_limit_default_bucket_and_retry_after():
    async with client(make_app(rate="3/minute")) as c:
        codes = [(await c.get("/ctx")).status_code for _ in range(5)]
        blocked = await c.get("/ctx")
    assert codes == [200, 200, 200, 429, 429]
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json()["error"] == "RATE_LIMIT_EXCEEDED"
    assert "x-request-id" in blocked.headers  # outer middlewares still apply


async def test_rate_limit_auth_bucket_is_separate_and_stricter():
    async with client(make_app(rate="100/minute", auth="2/minute")) as c:
        codes = [(await c.get("/api/v1/auth/login")).status_code for _ in range(3)]
        other = (await c.get("/ctx")).status_code
    assert codes == [200, 200, 429] and other == 200


async def test_rate_limit_not_bypassed_by_changing_path():
    async with client(make_app(rate="2/minute")) as c:
        codes = [(await c.get(f"/ctx?x={i}")).status_code for i in range(4)]
        codes.append((await c.get("/nf")).status_code)
    assert codes[2:] == [429, 429, 429]


async def test_ip_deny_cidr_returns_real_response_not_tuple():
    async with client(make_app(deny=["10.1.0.0/16"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_DENIED"


async def test_ip_allow_list():
    async with client(make_app(allow=["192.168.0.0/24"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_NOT_ALLOWED"


async def test_body_guard_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)
    async with client(make_app()) as c:
        r = await c.post("/echo", content=b"x" * 200, headers={"Content-Type": "application/json"})
        ok = await c.post("/echo", json={"n": 1})
    assert r.status_code == 413 and r.json()["error"] == "PAYLOAD_TOO_LARGE"
    assert ok.status_code == 200


async def test_body_guard_streamed_without_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)

    async def gen():
        for _ in range(10):
            yield b'{"n": 1,' + b" " * 20

    async with client(make_app()) as c:
        r = await c.post("/echo", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


async def test_error_formats():
    async with client(make_app(rate="1000/minute")) as c:
        nf = await c.get("/nf")
        deny = await c.get("/deny")
        route404 = await c.get("/nope")
        validation = await c.post("/echo", json={"n": "abc"})
        boom = await c.get("/boom")
    assert nf.status_code == 404 and nf.json()["error"] == "NOT_FOUND"
    assert deny.status_code == 403 and deny.json()["error"] == "CANNOT_SELF_ASSIGN"
    assert route404.status_code == 404 and route404.json()["error"] == "NOT_FOUND"  # Starlette 404
    assert validation.status_code == 422 and validation.json()["error"] == "VALIDATION_ERROR"
    assert isinstance(validation.json()["details"], list)
    assert boom.status_code == 500 and "secret internals" not in boom.text
    assert boom.json()["request_id"]


def test_parse_limit():
    assert parse_limit("100/minute") == (100, 60)
    assert parse_limit("5/second") == (5, 1)
    with pytest.raises(ValueError):
        parse_limit("lots")
