"""Pure-ASGI middleware contracts, especially the no-response disconnect path."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient
from starlette.responses import PlainTextResponse

from treg.api import (
    _BodyDecodeMiddleware,
    _LegacyHostRedirectMiddleware,
    _SecurityHeadersMiddleware,
)


def _production_middleware(inner):
    return _BodyDecodeMiddleware(
        _SecurityHeadersMiddleware(_LegacyHostRedirectMiddleware(inner))
    )


async def test_disconnected_downstream_may_end_without_a_response() -> None:
    """A disconnected request is not a server 500 and must not acquire a synthetic response."""
    received = False

    async def disconnected(scope, receive, send):
        nonlocal received
        message = await receive()
        assert message["type"] == "http.disconnect"
        received = True

    app = _production_middleware(disconnected)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp/",
        "raw_path": b"/mcp/",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        return {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    assert received is True
    assert sent == []


async def test_security_headers_are_setdefault_case_insensitively() -> None:
    async def response(scope, receive, send):
        await PlainTextResponse(
            "ok",
            headers={"x-frame-options": "SAMEORIGIN", "x-content-type-options": "strict"},
        )(scope, receive, send)

    app = _SecurityHeadersMiddleware(response)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        result = await client.get("/")

    assert result.headers.get_list("x-frame-options") == ["SAMEORIGIN"]
    assert result.headers.get_list("x-content-type-options") == ["strict"]
    assert result.headers["referrer-policy"] == "no-referrer"
    assert result.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
