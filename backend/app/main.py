"""Sentinel FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from http import HTTPMethod
from importlib.metadata import version as get_version
from typing import Any, Final

import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match

from app.api import health, interactive_docs
from app.api.dependencies import drain_ticket_convergence_after_commit
from app.api.openapi import API_V1_RESPONSES, SentinelAPI
from app.api.v1 import (
    api_keys,
    auth,
    cves,
    fetchers,
    ibs_consumer,
    identity_audit,
    maintainer,
    products,
    ticket_audit,
    ticket_ibs_requests,
    ticket_packages,
    ticket_references,
    tickets,
    users,
)
from app.api.v1 import settings as settings_api
from app.config import settings
from app.core.cross_origin import CrossOriginProtectionMiddleware
from app.core.errors import AppError, ErrorCode
from app.core.logging import configure_logging
from app.core.middleware import RequestIDMiddleware
from app.core.query_limits import enforce_query_parameter_length_limit
from app.core.request_admissibility import reject_inadmissible_request_input
from app.database import async_session_factory
from app.services import fetcher_discovery  # noqa: F401
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.settings import bootstrap_system_settings

configure_logging(settings)
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application startup/shutdown lifecycle.

    Runs the system-settings bootstrap (self-healing, defense-in-depth
    — the primary mechanism is the Alembic seed migration) and the
    fetcher config bootstrap (`docs/features/platform/fetcher-infrastructure.md`,
    FetcherConfig) in the same transaction before the API begins
    serving requests. A database connection, schema, bootstrap, flush,
    or commit failure in either step rolls back the shared transaction
    and lets the exception escape, which aborts FastAPI startup. The
    process MUST NOT begin serving requests in that case — there is no
    degraded startup mode and no fallback setting value.
    """
    async with async_session_factory() as session:
        try:
            await bootstrap_system_settings(session)
            await bootstrap_fetcher_configs(session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    yield


# `SentinelAPI` documents the dependency-derived global responses in the
# OpenAPI document (`app/api/openapi.py`).
app = SentinelAPI(
    title="Sentinel",
    description="Security update management platform for SUSE/openSUSE distributions",
    version=get_version("sentinel"),
    debug=settings.debug,
    lifespan=lifespan,
    # Every path the API serves starts with `/api/`, except the probes, so a
    # host that also serves the web UI routes only `/api` to the API
    # (docs/api-spec.md, Base URL).
    openapi_url="/api/openapi.json",
    # FastAPI's own pages load the latest viewer release from a CDN; the
    # pinned Swagger UI page is registered below
    # (`app/api/interactive_docs.py`), and no other viewer is served.
    docs_url=None,
    redoc_url=None,
    # Applies the shared query-parameter length limit
    # (docs/api-spec.md, Query Parameter Length Limit) and the
    # inadmissible-character rejection (docs/api-spec.md, Inadmissible
    # Characters in Request Input) to every current and future endpoint
    # automatically, before any route-level dependency such as
    # authentication — see docs/conventions.md (FastAPI Conventions,
    # "Cross-cutting request input constraints").
    dependencies=[
        Depends(enforce_query_parameter_length_limit),
        Depends(reject_inadmissible_request_input),
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
)
# The last middleware added runs first. Cross-origin request protection
# (docs/features/identity/authentication.md, Cross-Origin Request
# Protection) runs inside `RequestIDMiddleware`, so its rejection carries
# `X-Request-ID` and its log record `request_id`, and before CORS, routing,
# and every dependency (docs/api-spec.md, Cross-Origin Request Protection).
app.add_middleware(
    CrossOriginProtectionMiddleware, trusted_origins=settings.cors_origins
)
app.add_middleware(RequestIDMiddleware)


@app.exception_handler(AppError)
async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Render `AppError` as the standard `{"code": ..., "detail": ...}`
    envelope — see `docs/api-spec.md` (Response Format). Propagates
    `exc.headers` (e.g. `Retry-After` for `AUTH_ACCOUNT_LOCKED`) onto
    the response verbatim, and merges any contract-defined top-level
    fields (`AppError.extra`, e.g. `existing_ticket_id`)."""
    return JSONResponse(
        status_code=exc.status_code,
        content={**exc.extra, "code": exc.code.value, "detail": exc.detail},
        headers=exc.headers,
    )


def _validation_error_response(errors: Sequence[Any]) -> JSONResponse:
    """Render the standard `422 VALIDATION_ERROR` envelope for Pydantic-
    shaped `errors` — see `docs/api-spec.md` (Response Format, Global
    Responses).

    Only `loc`, `msg`, and `type` are projected from each error dict, and
    before encoding. Pydantic v2's `errors()` also includes an `input` key
    with the raw offending value (and sometimes `ctx`), which is not part
    of the documented `errors` element schema, could echo sensitive
    request data (e.g. a password field) back to the client, and may nest
    deeper than the interpreter recursion limit, which encoding it would
    exceed (a `500` instead of this `422`).
    """
    return JSONResponse(
        status_code=422,
        content={
            "code": ErrorCode.VALIDATION_ERROR.value,
            "detail": "Request validation failed",
            "errors": jsonable_encoder(
                [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in errors]
            ),
        },
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Render Pydantic/FastAPI request validation failures, including a
    JSON body with a syntax error (`json_invalid`), as the standard
    `422 VALIDATION_ERROR` envelope (`_validation_error_response`)."""
    return _validation_error_response(exc.errors())


@app.exception_handler(Exception)
async def _unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Render any unhandled exception as the generic `500 INTERNAL_ERROR`
    envelope — see `docs/api-spec.md` (Global Responses). Logged at
    ERROR with the full traceback for operator diagnosis."""
    logger.error("unhandled_exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "code": ErrorCode.INTERNAL_ERROR.value,
            "detail": "An unexpected error occurred.",
        },
    )


# The single `errors` entry for a JSON body that FastAPI could not read or
# decode: the `type` and `msg` FastAPI itself reports for a JSON syntax error
# (`docs/api-spec.md`, JSON Request Body Decoding).
_UNDECODABLE_BODY_ERROR: Final = {
    "loc": ("body",),
    "msg": "JSON decode error",
    "type": "json_invalid",
}


def _allowed_methods(request: Request) -> list[str]:
    """The methods that have an endpoint for the request path, for the
    `Allow` header of `405 ROUTE_METHOD_NOT_ALLOWED` (`docs/api-spec.md`,
    Routing Responses).

    Starlette's own header names only the methods of the first route whose
    path matches, so a path served by several routes (`GET` and `POST
    /api/v1/tickets`) would advertise one. Instead, the router is asked,
    as Starlette does for its trailing-slash redirect, whether a copy of
    the request scope with each standard method fully matches a route.
    """
    routes = request.app.router.routes
    allowed: list[str] = []
    for method in HTTPMethod:
        probe = dict(request.scope)
        probe["method"] = method.value
        if any(route.matches(probe)[0] is Match.FULL for route in routes):
            allowed.append(method.value)
    return allowed


@app.exception_handler(StarletteHTTPException)
async def _http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Render the errors the framework raises itself as the standard
    envelope, on every path — see `docs/api-spec.md` (Response Format).

    Sentinel code raises `AppError`, never `HTTPException`, so these come
    only from routing and from reading the request body:

    - 404: no endpoint path matches the request path → `404
      ROUTE_NOT_FOUND` (Routing Responses).
    - 405: endpoint paths match, but none for the method → `405
      ROUTE_METHOD_NOT_ALLOWED`, with an `Allow` header naming every
      method that has an endpoint for the path (`_allowed_methods`).
    - 400: FastAPI could not read or decode the request body — bytes that
      are not validly encoded text, nesting or an integer beyond the
      parser's limits, or a client that disconnected mid-body; a JSON
      syntax error arrives as `RequestValidationError` instead → the
      global `422 VALIDATION_ERROR` with one `json_invalid` entry at
      `["body"]` (JSON Request Body Decoding), whatever the cause, so the
      outcome never depends on the decoder's environment-dependent depth
      limit.

    Any other status is unexpected and is rendered and logged as an
    unhandled exception (`_unhandled_exception_handler`).
    """
    if exc.status_code == 404:
        return JSONResponse(
            status_code=404,
            content={
                "code": ErrorCode.ROUTE_NOT_FOUND.value,
                "detail": "No endpoint matches the request path.",
            },
        )
    if exc.status_code == 405:
        return JSONResponse(
            status_code=405,
            content={
                "code": ErrorCode.ROUTE_METHOD_NOT_ALLOWED.value,
                "detail": "No endpoint at the request path accepts this method.",
            },
            headers={"Allow": ", ".join(_allowed_methods(request))},
        )
    if exc.status_code == 400:
        return _validation_error_response([_UNDECODABLE_BODY_ERROR])
    return await _unhandled_exception_handler(request, exc)


app.include_router(health.router)
app.add_route("/api/docs", interactive_docs.swagger_ui_html, include_in_schema=False)

# Every `/api/v1` route drains the Ticket convergence effects registered in
# its request transaction after `get_db()` commits
# (`drain_ticket_convergence_after_commit`; enforced for every route using
# `get_db` by `tests/test_api_conventions.py`), and documents the global
# `422` and `500` responses (`API_V1_RESPONSES`).
_API_V1_DEPENDENCIES = [Depends(drain_ticket_convergence_after_commit)]
for _router in (
    auth.router,
    api_keys.router,
    users.router,
    identity_audit.router,
    settings_api.router,
    fetchers.router,
    ibs_consumer.router,
    ticket_audit.router,
    tickets.router,
    ticket_packages.router,
    ticket_references.router,
    ticket_ibs_requests.router,
    cves.router,
    products.router,
    maintainer.router,
):
    app.include_router(
        _router, dependencies=_API_V1_DEPENDENCIES, responses=API_V1_RESPONSES
    )
