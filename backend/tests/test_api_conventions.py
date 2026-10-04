"""Structural tests over FastAPI route-level API conventions.

Verifies invariants declared in `docs/api-spec.md` across every
registered route. See `docs/features/platform/testing-strategy.md`
(Structural Tests) for scope and governing principle.

This module intentionally does not defer to "until the first real
endpoint exists": every check below iterates the app's registered
routes, so it started out passing vacuously (zero `APIRoute` instances
registered) and began enforcing automatically the moment the first
endpoint was added (`/health`, `/ready`) — no further action was
required from whoever added it. The same holds for every endpoint
added since.

Route discovery does not read `app.routes` directly: FastAPI represents
a router included via `include_router()` internally as a lazy
`_IncludedRouter` node, not as a flat list of `APIRoute` instances —
`app.routes` alone does not expose included routes. `_api_routes()`
flattens this via `fastapi.routing.iter_route_contexts()`, the same
mechanism FastAPI's own OpenAPI generation uses internally, and pairs
each route's *effective* path (accounting for any router-level prefix)
with the underlying `APIRoute` object for its FastAPI-specific
attributes (`response_model`, `status_code`, `summary`, `description`).

Out of scope: the RBAC Endpoint Permission Map cross-reference (see
`docs/features/identity/rbac.md`) is not verified here — it would
require parsing a Markdown table, which the governing principle
forbids. That cross-reference remains with `@docs-reviewer` /
`@api-parity-reviewer`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import UnionType
from typing import Annotated, Any, Literal, Union, get_args, get_origin

import pytest
from fastapi import routing as fastapi_routing
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, Strict
from pydantic.fields import FieldInfo

from app.api.dependencies import drain_ticket_convergence_after_commit
from app.database import get_db
from app.main import app

# Endpoints intentionally outside the `/api/v1/` prefix — public,
# non-versioned operational endpoints. See
# `docs/features/platform/health-endpoints.md`. Their responses are
# also exempt from the `{"data": ...}` envelope (e.g. `/health` returns
# `{"status": "ok"}` directly) — see docs/api-spec.md Response Format,
# which scopes the envelope to API endpoints.
_PREFIX_EXEMPT_PATHS = {"/health", "/ready"}

# The only HTTP methods used across the documented API surface — see
# `docs/api-spec.md` (Mutation Patterns: PATCH/POST) and the CORS
# `allow_methods` configuration in `app/main.py`. A route using any
# other method (e.g. PUT, HEAD) would be unreachable by the CORS
# configuration the application itself declares.
_ALLOWED_METHODS = {"GET", "POST", "PATCH", "DELETE"}

# Routes with this status code return no body — see docs/api-spec.md
# Response Format. They are exempt from both the response_model
# presence and the envelope-format checks below.
_NO_BODY_STATUS_CODE = 204


@dataclass(frozen=True)
class _RouteInfo:
    """A flattened view of one registered route.

    `path` is the *effective* path — resolved through any router-level
    prefix applied via `include_router()` — which is what every
    convention check below needs. `route` is the underlying `APIRoute`
    object, used for attributes that are intrinsic to the route
    definition itself and unaffected by inclusion context
    (`response_model`, `status_code`, `summary`, `description`).
    `dependant` is the *effective* dependency graph — it includes any
    dependency added at `include_router()` time, unlike `route.dependant`
    which reflects only the route's own declaration.
    """

    path: str
    methods: frozenset[str]
    route: APIRoute
    dependant: Dependant


def _api_routes() -> list[_RouteInfo]:
    infos: list[_RouteInfo] = []
    for context in fastapi_routing.iter_route_contexts(app.routes):
        if isinstance(context.original_route, APIRoute) and context.path is not None:
            infos.append(
                _RouteInfo(
                    path=context.path,
                    methods=frozenset(context.methods or ()),
                    route=context.original_route,
                    dependant=context.dependant,
                )
            )
    return infos


def _resolve_schema_ref(
    openapi_schema: dict[str, Any], node: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a `$ref` pointer (e.g. `#/components/schemas/TicketDetail`)
    to the schema object it points to. Returns `node` unchanged if it is
    not a `$ref`.
    """
    ref = node.get("$ref")
    if not ref:
        return node
    target: Any = openapi_schema
    for part in ref.removeprefix("#/").split("/"):
        target = target[part]
    return target  # type: ignore[no-any-return]


def _response_schema(
    openapi_schema: dict[str, Any], info: _RouteInfo
) -> dict[str, Any] | None:
    """The resolved JSON schema for `info`'s primary success response
    (`info.route.status_code`, default 200), or `None` if the OpenAPI
    document does not describe a JSON body for it (e.g. no
    `response_model` was declared and FastAPI could not infer one).
    """
    method = next(iter(info.methods), "").lower()
    operation = openapi_schema.get("paths", {}).get(info.path, {}).get(method, {})
    status_code = str(info.route.status_code or 200)
    response = operation.get("responses", {}).get(status_code, {})
    schema = response.get("content", {}).get("application/json", {}).get("schema")
    if schema is None:
        return None
    return _resolve_schema_ref(openapi_schema, schema)


@pytest.mark.unit
class TestRoutePrefixConvention:
    """Every route is prefixed with `/api/v1/`, except the documented
    health-endpoint exemption.

    See `docs/api-spec.md` (Base URL): "All API endpoints are prefixed
    with `/api/v1/`."
    """

    def test_every_route_has_api_v1_prefix_or_is_exempt(self) -> None:
        violations = [
            f"Route '{info.path}' is missing the required '/api/v1/' prefix"
            for info in _api_routes()
            if info.path not in _PREFIX_EXEMPT_PATHS
            and not info.path.startswith("/api/v1/")
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestRouteHttpMethods:
    """No route uses an HTTP method outside the documented set.

    See `docs/api-spec.md` (Mutation Patterns): only PATCH and POST are
    used for modification, GET for reads, DELETE for removal. `PUT` and
    `HEAD` are never used.
    """

    def test_every_route_uses_only_allowed_methods(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            disallowed = info.methods - _ALLOWED_METHODS
            if disallowed:
                violations.append(
                    f"Route '{info.path}' uses disallowed HTTP method(s) "
                    f"{disallowed} (allowed: {_ALLOWED_METHODS})"
                )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestRouteDocumentation:
    """Every route has OpenAPI documentation.

    See `docs/conventions.md` (FastAPI Conventions): "All endpoints
    must have OpenAPI documentation (summary, description)." FastAPI
    derives `description` from the endpoint's docstring when not set
    explicitly, so a docstring alone satisfies this.
    """

    def test_every_route_has_summary_or_description(self) -> None:
        violations = [
            f"Route '{info.path}' has no OpenAPI summary or description "
            "(add a docstring or explicit summary/description)"
            for info in _api_routes()
            if not (info.route.summary or info.route.description)
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestAuditLogEndpointNaming:
    """Every audit trail retrieval endpoint uses the `/audit-log`
    suffix.

    See `docs/api-spec.md` (Audit Trail Endpoint Naming): "Every audit
    trail retrieval endpoint MUST use the `/audit-log` suffix."
    """

    def test_audit_related_routes_end_with_audit_log_suffix(self) -> None:
        violations = [
            f"Route '{info.path}' references audit trails but does not "
            "end with the required '/audit-log' suffix"
            for info in _api_routes()
            if "audit" in info.path.lower() and not info.path.endswith("/audit-log")
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestResponseModelPresence:
    """Every route that returns a body declares a `response_model`.

    See `docs/conventions.md` (FastAPI Conventions): "Use appropriate
    HTTP status codes and response models." A route with status code
    204 (No Content) is exempt — it has no body to model.
    """

    def test_every_body_returning_route_has_a_response_model(self) -> None:
        violations = [
            f"Route '{info.path}' has no response_model (and status "
            f"code {info.route.status_code} is not 204 No Content)"
            for info in _api_routes()
            if info.route.status_code != _NO_BODY_STATUS_CODE
            and info.route.response_model is None
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestResponseEnvelopeFormat:
    """Every route that returns a body wraps it in the standard
    `{"data": ...}` envelope.

    See `docs/api-spec.md` (Response Format): paginated list endpoints
    return `{"data": [...], "meta": {...}}`; single-resource and
    unpaginated list endpoints return `{"data": {...}}`. A route with
    status code 204 (No Content) is exempt — it has no body. The
    `/health` and `/ready` exemption (see `TestRoutePrefixConvention`)
    also applies here — those endpoints are outside the API envelope
    contract by design.
    """

    def test_every_body_returning_route_has_a_data_property(self) -> None:
        openapi_schema = app.openapi()
        violations: list[str] = []
        for info in _api_routes():
            if info.route.status_code == _NO_BODY_STATUS_CODE:
                continue
            if info.path in _PREFIX_EXEMPT_PATHS:
                continue
            schema = _response_schema(openapi_schema, info)
            if schema is None or "data" not in schema.get("properties", {}):
                violations.append(
                    f"Route '{info.path}' response schema does not have "
                    "a top-level 'data' property (required by the "
                    "standard response envelope)"
                )
        assert not violations, "\n".join(violations)


_JSON_SCALAR_TYPES = (bool, int, float)


def _declares_strict(metadata: Iterable[Any]) -> bool:
    return any(isinstance(item, Strict) and item.strict for item in metadata)


def _has_lax_json_scalar(annotation: Any, strict: bool) -> bool:
    """Whether `annotation` contains a `bool`, `int`, or `float` that is
    not validated strictly. `strict` is the strictness inherited from the
    enclosing level: field-level `Field(strict=True)` covers the field's
    own type and its union members, but not collection items, so a
    container resets it and only an item-level `Strict()` annotation
    covers the items. JSON object keys are strings by transport, so only
    mapping values are inspected. `Literal` values are not types and enum
    subclasses are distinct classes, so neither matches.
    """
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is Annotated:
        return _has_lax_json_scalar(args[0], strict or _declares_strict(args[1:]))
    if annotation in _JSON_SCALAR_TYPES:
        return not strict
    if origin is Literal:
        return False
    if origin in (Union, UnionType):
        return any(_has_lax_json_scalar(arg, strict) for arg in args)
    if isinstance(origin, type) and issubclass(origin, Mapping):
        args = args[1:]
    return any(_has_lax_json_scalar(arg, False) for arg in args)


def _nested_models(annotation: Any) -> list[type[BaseModel]]:
    """Every `BaseModel` subclass referenced by `annotation`, at any depth."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return [model for arg in get_args(annotation) for model in _nested_models(arg)]


def _lax_scalar_fields(
    owner: str, field_info: FieldInfo, seen: set[type[BaseModel]]
) -> list[str]:
    """Dotted names of every field reachable from `field_info` whose type
    contains a non-strict JSON scalar, descending into nested request
    models."""
    violations: list[str] = []
    annotation = field_info.annotation
    if _has_lax_json_scalar(annotation, _declares_strict(field_info.metadata)):
        violations.append(owner)
    for model in _nested_models(annotation):
        if model in seen:
            continue
        seen.add(model)
        for name, nested in model.model_fields.items():
            violations.extend(
                _lax_scalar_fields(f"{model.__name__}.{name}", nested, seen)
            )
    return violations


@pytest.mark.unit
class TestStrictJsonBodyScalars:
    """Every `bool`, `int`, or `float` in a JSON request body is strict
    at every nesting level: `Field(strict=True)` on the field, or a
    `Strict()` item annotation inside a collection.

    See `docs/api-spec.md` (JSON Request Body Scalar Types) and
    `docs/conventions.md` (Pydantic Conventions, Strict JSON body
    scalars). Body parameters are collected from every route's
    effective dependency graph, so a body declared by a dependency is
    covered too.
    """

    def test_every_json_body_scalar_field_is_strict(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            for node in _iter_dependants(info.dependant):
                for param in node.body_params:
                    violations.extend(
                        f"Route '{info.path}': body field '{name}' has a "
                        "non-strict bool/int/float (use Field(strict=True), or "
                        "Annotated[<type>, Strict()] for collection items)"
                        for name in _lax_scalar_fields(
                            param.name, param.field_info, set()
                        )
                    )
        assert not violations, "\n".join(violations)

    def test_detection_covers_optional_collection_and_nested_fields(self) -> None:
        """Guards the checker itself against passing vacuously."""

        class _Inner(BaseModel):
            lax: float
            strict: float = Field(strict=True)

        class _Body(BaseModel):
            flag: bool | None = None
            counts: list[int] = []
            field_strict_counts: list[int] = Field(default=[], strict=True)
            item_strict_counts: list[Annotated[int, Strict()]] = []
            ratios: dict[str, float] = {}
            item_strict_ratios: dict[int, Annotated[float, Strict()]] = {}
            ok: int | None = Field(default=None, strict=True)
            label: str = ""
            choice: Literal[1, 2] = 1
            inner: _Inner | None = None

        violations = _lax_scalar_fields("body", FieldInfo(annotation=_Body), set())

        # `field_strict_counts` is a violation: field-level strictness
        # does not reach collection items.
        assert violations == [
            "_Body.flag",
            "_Body.counts",
            "_Body.field_strict_counts",
            "_Body.ratios",
            "_Inner.lax",
        ]


def _iter_dependants(dependant: Dependant) -> list[Dependant]:
    """Every `Dependant` node in `dependant`'s tree, including itself.

    Walks nested dependencies (e.g. an authentication dependency that
    itself depends on the database session) so a `get_db` occurrence
    hidden behind another dependency is not missed.
    """
    nodes = [dependant]
    for sub_dependant in dependant.dependencies:
        nodes.extend(_iter_dependants(sub_dependant))
    return nodes


@pytest.mark.unit
class TestTransactionDependencyScope:
    """Every route dependency graph that uses the API transaction
    session (`get_db`) declares it with `scope="function"`, at any
    depth (including a `get_db` occurrence nested under another
    dependency, e.g. authentication).

    See `docs/conventions.md` (API Transaction Dependency Scope):
    FastAPI defaults an unscoped `yield` dependency to
    `scope="request"`, whose post-yield code (commit, rollback,
    post-commit callbacks in `get_db()`) runs *after* the response has
    already been transmitted to the client — breaking the "commits
    before the caller can observe success" guarantee (Caller-Owned
    Service Transactions). `scope="function"` runs that same post-yield
    code before the response is sent, so a commit failure surfaces as a
    real error response instead of an already-decided success one. The
    shared `DatabaseSession` alias (`app/database.py`) pins this scope
    — this test guards against a future endpoint bypassing it via a raw
    `Depends(get_db)`.

    `use_cache` is also checked: a `get_db` occurrence declared with
    `use_cache=False` would open a second, independent session and
    transaction for the same request even if correctly function-scoped,
    splitting the caller-owned transaction the same guarantee requires
    to be singular.
    """

    def test_every_get_db_dependency_is_function_scoped_and_cached(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            for node in _iter_dependants(info.dependant):
                if node.call is not get_db:
                    continue
                if node.scope != "function":
                    violations.append(
                        f"Route '{info.path}' uses 'get_db' with scope "
                        f"'{node.scope}' (must be 'function' — use the "
                        "'DatabaseSession' alias from 'app.database' "
                        "instead of 'Depends(get_db)')"
                    )
                if not node.use_cache:
                    violations.append(
                        f"Route '{info.path}' uses 'get_db' with "
                        "use_cache=False, which opens a second, "
                        "independent transaction for the same request"
                    )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestTicketConvergenceDrain:
    """Every route that uses the API transaction session also drains its
    Ticket convergence effects after commit.

    See `docs/features/tickets/ticket-service.md` (Ticket Convergence >
    Publication policies): the API transaction dependency is an automatic
    transaction owner, so every request transaction that can register a
    convergence effect must detach and attempt it after `get_db()`
    commits. The drain is mounted on every `/api/v1` router in
    `app/main.py`; this test guards against a router added without it.
    """

    def test_every_get_db_route_has_the_drain_dependency(self) -> None:
        missing = [
            info.path
            for info in _api_routes()
            if any(n.call is get_db for n in _iter_dependants(info.dependant))
            and not any(
                n.call is drain_ticket_convergence_after_commit
                for n in _iter_dependants(info.dependant)
            )
        ]
        assert not missing, (
            "Routes using 'get_db' without 'drain_ticket_convergence_after_commit': "
            f"{missing}"
        )

    def test_drain_is_present_on_the_rerun_and_mutation_routes(self) -> None:
        paths = {
            info.path
            for info in _api_routes()
            if any(
                n.call is drain_ticket_convergence_after_commit
                for n in _iter_dependants(info.dependant)
            )
        }
        assert "/api/v1/tickets/{ticket_id}/reopen" in paths
        assert "/api/v1/tickets/{ticket_id}/revert-duplicate" in paths
