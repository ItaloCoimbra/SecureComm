"""Small HTTP boundary for capability-scoped, opaque browser delivery.

No cookie authentication, identity directory, access log, request-body logging,
or server-side conversation encryption. TLS and E2EE are distinct properties.
"""

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
import ipaddress
import json
import logging
import math
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit

from aiohttp import web

from core.transport import validate_server_transport
from server.web_store import StoreError, WebStore


MAX_BODY_BYTES = 100000
_ROUTES = {
    "/v1/queues": "create_queue", "/v1/send": "send", "/v1/read": "read",
    "/v1/ack": "ack", "/v1/delete": "delete_queue",
    "/v1/blobs/put": "put_blob", "/v1/blobs/get": "get_blob",
    "/v1/blobs/delete": "delete_blob",
}
_MIME = {".js": "application/javascript", ".css": "text/css",
         ".wasm": "application/wasm", ".png": "image/png", ".svg": "image/svg+xml",
         ".ico": "image/x-icon", ".webp": "image/webp"}
_CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
        "img-src 'self' blob: data:; media-src 'self' blob:; font-src 'self'; "
        "connect-src 'self' https: http://127.0.0.1:* http://localhost:*; "
        "worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'")


def _origin(value):
    """Validate exact origins; no wildcards, credentials, paths or CRLF."""
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("invalid frontend origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if (parsed.scheme not in ("https", "http") or not host or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                or "*" in value or parsed.netloc.endswith(":")):
            raise ValueError
        if parsed.scheme == "http":
            if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("invalid frontend origin") from None
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _bad_constant(_):
    raise ValueError("nonfinite number")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite number")
    return result


class AdmissionBudget:
    """Single process-wide bucket: no persistent or per-IP tracking."""

    def __init__(self, rate, burst):
        if not math.isfinite(rate) or rate <= 0 or type(burst) is not int or burst <= 0:
            raise ValueError("invalid admission budget")
        self.rate, self.burst = rate, burst
        self.tokens, self.updated = float(burst), time.monotonic()

    def admit(self):
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


@dataclass
class _State:
    store: WebStore | None = None
    active: int = 0
    header_deadlines: dict = field(default_factory=dict)


_STATE = web.AppKey("web_state", _State)


def create_app(database, *, static_dir=None, allowed_origins=(), store_options=None,
               cleanup_interval=30.0, body_timeout=5.0, max_inflight=32,
               admission_rate=100.0, admission_burst=200):
    """Application factory, also usable by an explicitly configured runner.

    The supported WebRelay/CLI runner enforces TLS outside loopback and disables
    access logs. Custom runners must preserve those deployment requirements.
    """
    origins = frozenset(_origin(value) for value in allowed_origins)
    if (not math.isfinite(body_timeout) or body_timeout <= 0 or
            not math.isfinite(cleanup_interval) or cleanup_interval <= 0 or
            type(max_inflight) is not int or max_inflight <= 0):
        raise ValueError("invalid HTTP resource bounds")
    budget = AdmissionBudget(admission_rate, admission_burst)
    state = _State()
    static_root = Path(static_dir).resolve() if static_dir is not None else None

    @web.middleware
    async def boundary(request, handler):
        deadline = state.header_deadlines.pop(request.protocol, None)
        if deadline is not None:
            deadline.cancel()
        origin = request.headers.get("Origin")
        same_origin = f"{request.scheme}://{request.host}"
        origin_allowed = origin is not None and (origin in origins or origin == same_origin)
        admitted = False
        try:
            if not budget.admit() or state.active >= max_inflight:
                raise StoreError("capacity", 429)
            if origin is not None and not origin_allowed:
                raise StoreError("forbidden", 403)
            if request.query_string:
                raise StoreError("invalid_request", 400)
            state.active += 1
            admitted = True
            if request.method == "OPTIONS":
                headers = {part.strip().lower() for part in request.headers.get("Access-Control-Request-Headers", "").split(",") if part.strip()}
                if (not origin_allowed or request.path not in _ROUTES or
                        request.headers.get("Access-Control-Request-Method") != "POST" or
                        headers - {"content-type"}):
                    raise StoreError("forbidden", 403)
                response = web.Response(status=204)
                response.headers["Access-Control-Allow-Methods"] = "POST"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            else:
                response = await handler(request)
        except StoreError as exc:
            response = web.json_response({"error": exc.code}, status=exc.status)
        except web.HTTPException as exc:
            code = {404: "not_found", 405: "method_not_allowed", 413: "too_large"}.get(exc.status, "invalid_request")
            response = web.json_response({"error": code}, status=exc.status)
        except (sqlite3.Error, OSError):
            response = web.json_response({"error": "server_unavailable"}, status=503)
        finally:
            if admitted:
                state.active -= 1
        response.headers.update({
            "Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Content-Security-Policy": _CSP, "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(self), geolocation=(), payment=()",
        })
        if request.secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if origin_allowed:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        if response.status in (408, 413):
            response.force_close()
        return response

    async def operation(request):
        if request.content_type != "application/json":
            raise StoreError("unsupported_media_type", 415)
        if request.headers.get("Content-Encoding", "identity") != "identity":
            raise StoreError("unsupported_media_type", 415)
        try:
            raw = await asyncio.wait_for(request.read(), body_timeout)
        except asyncio.TimeoutError:
            raise StoreError("request_timeout", 408) from None
        try:
            packet = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                                parse_constant=_bad_constant, parse_float=_finite_float)
            if type(packet) is not dict:
                raise ValueError("object required")
        except (ValueError, UnicodeError, RecursionError):
            raise StoreError("invalid_request") from None
        return web.json_response(getattr(state.store, _ROUTES[request.path])(packet))

    async def health(_request):
        return web.json_response({"ok": True, "protocol": "securecomm-web-v1"})

    async def static(request):
        if static_root is None:
            raise web.HTTPNotFound()
        relative = request.match_info.get("path", "") or "index.html"
        if "\\" in relative or any(part.startswith(".") for part in relative.split("/")):
            raise web.HTTPNotFound()
        try:
            path = (static_root / relative).resolve()
            if not path.is_relative_to(static_root) or not path.is_file():
                raise web.HTTPNotFound()
            if relative == "index.html":
                content_type = "text/html"
            elif relative.startswith("assets/") and path.suffix in _MIME:
                content_type = _MIME[path.suffix]
            elif relative == "favicon.ico":
                content_type = "image/x-icon"
            else:
                raise web.HTTPNotFound()
            if path.stat().st_size > 16 * 1024 * 1024:
                raise web.HTTPNotFound()
        except (ValueError, OSError):
            raise web.HTTPNotFound() from None
        response = web.FileResponse(path)
        response.content_type = content_type
        return response

    async def lifecycle(_app):
        state.store = WebStore(database, **(store_options or {}))

        async def periodic_cleanup():
            while True:
                await asyncio.sleep(cleanup_interval)
                try:
                    state.store.cleanup()
                except sqlite3.Error:
                    # Retry next tick; no exception data, paths or request data logged.
                    pass

        cleanup_task = asyncio.create_task(periodic_cleanup())
        try:
            yield
        finally:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
            state.store.close()
            state.store = None

    app = web.Application(middlewares=[boundary], client_max_size=MAX_BODY_BYTES)
    app[_STATE] = state
    app.cleanup_ctx.append(lifecycle)
    for route in _ROUTES:
        app.router.add_post(route, operation)
    app.router.add_get("/v1/health", health)
    app.router.add_get("/", static)
    app.router.add_get("/{path:.*}", static)
    return app


class _BoundedRunner(web.AppRunner):
    """Pinned aiohttp adapter for admission before a request reaches middleware.

    The two Server connection callbacks are deliberately the only adapted
    internals. Their behavior is covered using real sockets, including incomplete
    headers; upgrades of the pinned aiohttp version must retain those tests.
    TLS handshakes still need OS/proxy resource limits before HTTP admission.
    """

    def __init__(self, app, *, max_connections, header_timeout, **kwargs):
        super().__init__(app, **kwargs)
        self._connection_limit = max_connections
        self._header_timeout = header_timeout

    async def _make_server(self):
        server = await super()._make_server()
        state = self.app[_STATE]
        made, lost = server.connection_made, server.connection_lost
        loop = asyncio.get_running_loop()

        def connection_made(handler, transport):
            if len(server.connections) >= self._connection_limit:
                transport.close()
                return
            made(handler, transport)
            state.header_deadlines[handler] = loop.call_later(self._header_timeout, transport.close)

        def connection_lost(handler, exc=None):
            deadline = state.header_deadlines.pop(handler, None)
            if deadline is not None:
                deadline.cancel()
            lost(handler, exc)

        server.connection_made = connection_made
        server.connection_lost = connection_lost
        return server


class WebRelay:
    """Managed listener with no request logging and cancellation-safe cleanup."""

    def __init__(self, database, *, host="127.0.0.1", port=0, ssl_context=None,
                 max_connections=128, header_timeout=5.0, **app_options):
        if (type(max_connections) is not int or max_connections <= 0 or
                not math.isfinite(header_timeout) or header_timeout <= 0):
            raise ValueError("invalid connection bounds")
        self.host, self.port, self.ssl_context = host, port, ssl_context
        self.max_connections, self.header_timeout = max_connections, header_timeout
        self.app = create_app(database, **app_options)
        self._runner = None
        self._site = None

    @property
    def address(self):
        if self._site is None or self._site._server is None or not self._site._server.sockets:
            raise RuntimeError("web relay is not running")
        return self._site._server.sockets[0].getsockname()[:2]

    @property
    def base_url(self):
        host, port = self.address
        if ":" in host:
            host = f"[{host}]"
        return f"{'https' if self.ssl_context else 'http'}://{host}:{port}"

    async def start(self):
        if self._runner is not None:
            raise RuntimeError("web relay is already running")
        host = validate_server_transport(self.host, self.ssl_context)
        # A dedicated sink prevents parser exceptions echoing attacker-controlled
        # request lines. There is deliberately no access log in this runner.
        logger = logging.Logger("securecomm.web.protocol")
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
        self._runner = _BoundedRunner(self.app, max_connections=self.max_connections,
                                    header_timeout=self.header_timeout, access_log=None, logger=logger,
                                    keepalive_timeout=5, shutdown_timeout=2,
                                    max_line_size=4096, max_field_size=4096, max_headers=32,
                                    read_bufsize=16384, auto_decompress=False, lingering_time=0.1)
        try:
            await self._runner.setup()
            self._site = web.TCPSite(self._runner, host, self.port, ssl_context=self.ssl_context, backlog=64)
            await self._site.start()
        except BaseException:
            await self.close()
            raise
        return self

    async def close(self):
        runner, self._runner = self._runner, None
        self._site = None
        if runner is not None:
            await runner.cleanup()
