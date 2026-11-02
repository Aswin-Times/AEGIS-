import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.exceptions import HTTPException

from aegis.api import routes_events, routes_incidents, routes_registry, routes_runtime
from aegis.api.dependencies import Container
from aegis.config import Settings
from aegis.correlation.worker import CorrelationWorker
from aegis.db.session import Database
from aegis.errors import AegisError, Forbidden, NotFound, ServiceUnavailable
from aegis.events.limiter import FailureLimiter
from aegis.gateway.tools import ToolRegistry, default_registry
from aegis.logging_config import configure_logging
from aegis.security.access_events import record_access_failure
from aegis.security.tokens import TokenService

logger = logging.getLogger("aegis.api")


class UnsafeDatabaseRole(RuntimeError):
    pass


def assert_runtime_role_is_restricted(db: Database) -> None:
    """Refuse to start with a role that RLS or the append-only grants would not constrain."""
    with db.engine.connect() as connection:
        superuser, bypass = connection.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        owned = connection.execute(
            text("SELECT count(*) FROM pg_tables WHERE tableowner = current_user "
                 "AND schemaname = 'public'")
        ).scalar_one()
    if superuser or bypass or owned:
        raise UnsafeDatabaseRole("AEGIS_DATABASE_URL must use the restricted aegis_app role")


def _error_response(request: Request, status: int, code: str, message: str, **extra):
    request_id = getattr(request.state, "request_id", None) or str(uuid4())
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id, **extra}},
        headers={"X-Request-Id": request_id},
    )


def _last_uuid_in_path(request: Request) -> UUID | None:
    found = None
    for value in request.path_params.values():
        try:
            found = UUID(str(value))
        except ValueError:
            continue
    return found


def _record_failed_access(request: Request, error: AegisError) -> None:
    principal = getattr(request.state, "principal", None)
    if principal is None or not isinstance(error, Forbidden | NotFound):
        return
    container = request.app.state.container
    record_access_failure(
        container.db,
        container.failure_limiter,
        principal,
        event_type="authz.denied" if isinstance(error, Forbidden) else "access.not_visible",
        requested_id=_last_uuid_in_path(request),
        now=container.clock(),
    )


def _register_error_handlers(app: FastAPI) -> None:
    # Not async: it writes to the database, so Starlette runs it in the thread pool.
    @app.exception_handler(AegisError)
    def handle_aegis_error(request: Request, error: AegisError):
        _record_failed_access(request, error)
        return _error_response(request, error.status_code, error.code, error.message)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, error: RequestValidationError):
        # Field locations only. The default response echoes the rejected input.
        fields = [".".join(str(part) for part in item["loc"]) for item in error.errors()]
        return _error_response(
            request, 422, "VALIDATION_ERROR", "The request is not valid.", fields=fields
        )

    @app.exception_handler(HTTPException)
    async def handle_http(request: Request, error: HTTPException):
        codes = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return _error_response(
            request, error.status_code, codes.get(error.status_code, "HTTP_ERROR"),
            "The request could not be completed.",
        )

    @app.exception_handler(IntegrityError)
    async def handle_integrity(request: Request, error: IntegrityError):
        return _error_response(
            request, 409, "ALREADY_EXISTS", "This conflicts with an existing record."
        )

    @app.exception_handler(OperationalError)
    async def handle_operational(request: Request, error: OperationalError):
        logger.error("database unavailable")
        return _error_response(request, 503, ServiceUnavailable.code, ServiceUnavailable.message)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, error: Exception):
        logger.exception("unhandled error", exc_info=error)
        return _error_response(request, 500, "INTERNAL_ERROR", "An internal error occurred.")


def create_app(settings: Settings | None = None, *, tools: ToolRegistry | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging()
    db = Database(settings.database_url)
    container = Container(
        settings=settings,
        db=db,
        tokens=TokenService(settings),
        tools=tools or default_registry(),
        failure_limiter=FailureLimiter(settings.failure_events_per_minute),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        assert_runtime_role_is_restricted(db)
        worker = None
        if settings.correlation_worker_enabled:
            # Read the clock through the container, so a test can move it.
            worker = CorrelationWorker(
                db, lambda: container.clock(), settings.correlation_poll_seconds
            )
            worker.start()
        yield
        if worker is not None:
            worker.stop()
        db.dispose()

    docs_enabled = settings.environment == "development"
    app = FastAPI(
        title="AEGIS",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.container = container
    _register_error_handlers(app)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = str(uuid4())
        started = time.perf_counter()

        declared = request.headers.get("Content-Length")
        if request.headers.get("Transfer-Encoding"):
            # Chunked bodies cannot be size-checked up front, so they are refused.
            response = _error_response(
                request, 411, "LENGTH_REQUIRED", "A Content-Length header is required."
            )
        elif declared and (not declared.isdigit() or int(declared) > settings.max_body_bytes):
            response = _error_response(
                request, 413, "PAYLOAD_TOO_LARGE", "The request body is too large."
            )
        else:
            response = await call_next(request)

        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info(
            "request",
            extra={
                "request_id": request.state.request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )
        return response

    app.include_router(routes_registry.router, prefix="/api/v1")
    app.include_router(routes_runtime.router, prefix="/api/v1")
    app.include_router(routes_events.router, prefix="/api/v1")
    app.include_router(routes_incidents.router, prefix="/api/v1")

    @app.get("/healthz", include_in_schema=True)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
