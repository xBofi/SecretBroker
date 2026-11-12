"""HTTP glue: route registry, JSON bodies, authentication, errors and security headers.

Handlers are plain synchronous functions `handler(ctx) -> body | (status, body)` that run in the thread pool,
inside a database transaction (write transaction for anything but GET), so they stay short and easy to read.
"""

import json
import logging
import uuid
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import config, security
from .db import Database, now_epoch, now_iso
from .validate import ApiError

log = logging.getLogger("secretbroker_server")

PREFIX = "/api/v1"
ROUTES = []
SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-origin"),
]


VERSION_HEADER = "x-secretbroker-version"


def route(method, path, auth=True, tx=None, any_client=False):
    """Register a handler. `tx`: None = automatic, False = the handler opens its own transactions.
    `any_client`: answered even to apps older than SB_MIN_CLIENT (/info, so they can tell the user; /health)."""
    def register(handler):
        ROUTES.append((method, path, auth, tx, any_client, handler))
        return handler
    return register


class Server:
    """Shared state of one running server."""

    def __init__(self, settings):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings = settings
        self.db = Database(settings.db_path)
        self.secret = config.server_secret(settings.data_dir)
        self.email_throttle = security.Throttle(free=5)
        self.ip_throttle = security.Throttle(free=20)
        self.signup_throttle = security.Throttle(free=30)  # a whole team may join from one office
        self.delete_window = security.Window(settings.max_deletes_per_hour, 3600)  # item deletions per account
        self.invite_window = security.Window(settings.max_invites_per_hour, 3600)  # per organization and per account
        self.oldest_client = config.parse_version(settings.oldest_client)


class Ctx:
    def __init__(self, server, body, params, query, ip):
        self.server, self.settings, self.db = server, server.settings, server.db
        self.body, self.params, self.query, self.ip = body, params, query, ip
        self.conn = None
        self.user = None
        self.session_id = None

    @property
    def uid(self):
        return self.user["id"]


def unauthorized():
    return ApiError(401, "unauthorized", "Inicia sesión de nuevo.")


def authenticate(server, header):
    """Find the session behind a bearer token; each use pushes its expiry forward (sliding sessions)."""
    scheme, _, token = (header or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > 200:
        raise unauthorized()
    row = server.db.conn().execute(
        "SELECT s.id AS session_id, s.touched, s.expires, u.id, u.email, u.name, u.is_admin, u.verified, "
        "u.invited_to, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (security.token_hash(token),)).fetchone()
    now = now_epoch()
    if row is None or row["expires"] <= now or row["disabled"]:
        raise unauthorized()
    if now - row["touched"] >= 60:  # at most one write a minute per session
        with server.db.tx(write=True) as conn:
            conn.execute("UPDATE sessions SET touched = ?, last_seen = ?, expires = ? WHERE id = ?",
                         (now, now_iso(), now + server.settings.session_days * 86400, row["session_id"]))
    return row


def is_server_admin(settings, user):
    return bool(user["is_admin"]) or user["email"] in settings.admin_emails


async def _read_json(request, limit):
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > limit):
        raise ApiError(413, "too_large", "La petición es demasiado grande.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ApiError(413, "too_large", "La petición es demasiado grande.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw.strip():
        return {}
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise ApiError(400, "invalid", "El cuerpo debe ser JSON.")
    try:
        return json.loads(raw, parse_constant=_reject_constant)
    except ValueError:
        raise ApiError(400, "invalid", "JSON no válido.") from None


def _reject_constant(name):
    raise ValueError(name)


def client_ip(request, trust_proxy):
    """Behind the bundled Caddy the real address is the last X-Forwarded-For hop (the one Caddy added)."""
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded.strip():
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def check_client(server, request):
    """426 for an app older than this server serves. An app that does not say its version (before 0.17) or says
    something unreadable is served as before: nothing proves it is too old."""
    version = config.parse_version(request.headers.get(VERSION_HEADER, "")[:40])
    if version is not None and version < server.oldest_client:
        raise ApiError(426, "client_too_old", "Esta versión de SecretBroker es demasiado antigua para este servidor: "
                       "actualiza la app.", min_client=server.settings.oldest_client)


def error_response(exc):
    headers = {"Retry-After": str(exc.extra["retry_after"])} if "retry_after" in exc.extra else None
    return JSONResponse(exc.body(), status_code=exc.status, headers=headers)


def _run(server, handler, ctx, auth, tx, method, authorization):
    if auth:
        user = authenticate(server, authorization)
        ctx.user, ctx.session_id = user, user["session_id"]
    if tx is False:
        return handler(ctx)
    with server.db.tx(write=method != "GET" if tx is None else tx == "write") as conn:
        ctx.conn = conn
        return handler(ctx)


def _endpoint(server, handler, auth, tx, any_client, method):
    async def endpoint(request):
        try:
            if not any_client:
                check_client(server, request)
            body = await _read_json(request, server.settings.max_body)
            ctx = Ctx(server, body, dict(request.path_params), request.query_params,
                      client_ip(request, server.settings.trust_proxy))
            result = await run_in_threadpool(_run, server, handler, ctx, auth, tx, method,
                                             request.headers.get("authorization"))
        except ApiError as exc:
            return error_response(exc)
        except Exception:  # noqa: BLE001 - never leak internals to the client
            log.exception("Unhandled error in %s %s", method, request.url.path)
            return JSONResponse({"error": "Error interno del servidor.", "code": "internal"}, status_code=500)
        status, payload = result if isinstance(result, tuple) else (200, result)
        return JSONResponse(payload, status_code=status)
    return endpoint


async def _http_error(request, exc):
    codes = {404: ("not_found", "No existe."), 405: ("method_not_allowed", "Método no permitido.")}
    code, message = codes.get(exc.status_code, ("error", "Petición no válida."))
    return JSONResponse({"error": message, "code": code}, status_code=exc.status_code)


async def _server_error(request, exc):
    return JSONResponse({"error": "Error interno del servidor.", "code": "internal"}, status_code=500)


class SecurityHeaders:
    """Pure ASGI middleware: adds the same hardening headers to every response, errors included."""

    def __init__(self, app, hsts):
        self.app = app
        self.headers = SECURITY_HEADERS + ([(b"strict-transport-security", b"max-age=31536000")] if hsts else [])

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + self.headers
            await send(message)
        await self.app(scope, receive, send_with_headers)


def create_app(settings):
    from . import accounts, orgs, sharing  # noqa: F401 - importing registers their routes

    settings.check()
    server = Server(settings)
    routes = [Route(PREFIX + path, _endpoint(server, handler, auth, tx, any_client, method), methods=[method])
              for method, path, auth, tx, any_client, handler in ROUTES]

    @asynccontextmanager
    async def lifespan(app):
        yield
        server.db.close()

    app = Starlette(routes=routes, exception_handlers={HTTPException: _http_error, 500: _server_error},
                    lifespan=lifespan)
    app.state.server = server
    return SecurityHeaders(app, hsts=settings.https)


def new_id():
    return str(uuid.uuid4())
