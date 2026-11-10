"""Pure ASGI middleware: request context/logging/metrics/headers, and body size limit.

Written against raw ASGI instead of Starlette's BaseHTTPMiddleware so the
body limit can count streamed (chunked) bodies and nothing buffers a whole
request just to inspect it.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Iterable
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kevgate.metrics import Metrics

logger = logging.getLogger("kevgate.access")

REQUEST_ID_HEADER = "x-request-id"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", ()):
        if key == name:
            return bytes(value).decode("latin-1")
    return None


def _route_label(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "unmatched"


class RequestContextMiddleware:
    """Request id, security headers, one JSON access log line, and HTTP metrics.

    The access log records method, path (no query string), status, latency,
    request id and key_id. It never records headers or bodies.
    """

    def __init__(self, app: ASGIApp, *, metrics: Metrics, csp_exempt: Iterable[str] = ()) -> None:
        self.app = app
        self.metrics = metrics
        self.csp_exempt = frozenset(csp_exempt)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        incoming = _header(scope, REQUEST_ID_HEADER.encode())
        request_id = (
            incoming if incoming and _REQUEST_ID_RE.fullmatch(incoming) else uuid.uuid4().hex
        )
        state: dict[str, Any] = scope.setdefault("state", {})
        state["request_id"] = request_id
        path: str = scope.get("path", "")
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                for name, value in SECURITY_HEADERS.items():
                    if name == "Content-Security-Policy" and path in self.csp_exempt:
                        continue
                    headers[name] = value
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            status = 500
            logger.exception(
                "unhandled exception",
                extra={"fields": {"request_id": request_id, "path": path}},
            )
            raise
        finally:
            elapsed = time.perf_counter() - start
            method = str(scope.get("method", ""))
            route = _route_label(scope)
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.latency.labels(method, route).observe(elapsed)
            logger.info(
                "request",
                extra={
                    "fields": {
                        "method": method,
                        "path": path,
                        "route": route,
                        "status": status,
                        "latency_ms": round(elapsed * 1000, 2),
                        "request_id": request_id,
                        "key_id": state.get("key_id"),
                    }
                },
            )


class BodyTooLargeError(HTTPException):
    def __init__(self, limit: int) -> None:
        super().__init__(status_code=413, detail=f"request body exceeds {limit} bytes")


class BodySizeLimitMiddleware:
    """Reject bodies over ``max_bytes`` with 413.

    Declared Content-Length is checked before the app runs. Chunked bodies
    are counted as they stream; crossing the limit raises an HTTPException
    from ``receive``, which FastAPI turns into the same 413.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _header(scope, b"content-length")
        if declared is not None:
            if not declared.isdigit():
                await JSONResponse({"detail": "invalid Content-Length"}, status_code=400)(
                    scope, receive, send
                )
                return
            if int(declared) > self.max_bytes:
                await JSONResponse(
                    {"detail": f"request body exceeds {self.max_bytes} bytes"}, status_code=413
                )(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLargeError(self.max_bytes)
            return message

        await self.app(scope, limited_receive, send)
