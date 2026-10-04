"""Cross-cutting query parameter length limit, shared by every endpoint.

See `docs/api-spec.md` (Query Parameter Length Limit) for the
authoritative contract: every declared string query parameter has an
individual maximum length of 500 characters; a value exceeding the
limit returns the standard `422 VALIDATION_ERROR` envelope. See
`docs/api-spec.md` (Undeclared Query Parameters) for the complementary
rule this dependency respects: a parameter name not declared by the
matched route is never inspected, regardless of its value's length.

See `docs/conventions.md` (FastAPI Conventions, "Cross-cutting request
input constraints") for why this is a single shared dependency
rather than a per-schema `Field(max_length=500)` repeated on every
string query field: a shared dependency, registered once at the app
level (`app.main`), applies automatically to every current and future
endpoint — eliminating the risk that a new endpoint forgets to declare
the constraint on one of its fields.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError

from app.core.route_params import declared_string_param_names

# docs/api-spec.md (Query Parameter Length Limit).
_MAX_QUERY_STRING_LENGTH = 500


async def enforce_query_parameter_length_limit(request: Request) -> None:
    """Reject any declared string query parameter value over 500 characters.

    Q1: `request` is the current request. The matched route (and its
    declared query parameters, at any dependency nesting depth) is read
    from `request.scope["route"]`, populated by Starlette's router
    after route matching and before any dependency executes.

    Q3: for every string-shaped query parameter declared by the matched
    route, checks every raw occurrence of that name in the request's
    query string (`request.query_params.getlist(name)` — a repeated
    parameter is checked individually per occurrence). A route with no
    declared string query parameters, or a request that supplies none
    of them, is a no-op. A query parameter name the route does not
    declare is never inspected, regardless of its value's length, per
    `docs/api-spec.md` (Undeclared Query Parameters).

    Q6: raises `RequestValidationError` — rendered as the standard `422
    VALIDATION_ERROR` envelope by the handler registered in `app.main`
    — carrying one Pydantic-shaped error entry per over-limit
    occurrence, using the same `type`/`msg` pair Pydantic itself
    produces for a `max_length` violation. Otherwise infallible.
    """
    route = request.scope.get("route")
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return

    errors: list[dict[str, Any]] = []
    for name in declared_string_param_names(dependant, "query"):
        for value in request.query_params.getlist(name):
            if len(value) > _MAX_QUERY_STRING_LENGTH:
                errors.append(
                    {
                        "loc": ["query", name],
                        "msg": (
                            "String should have at most "
                            f"{_MAX_QUERY_STRING_LENGTH} characters"
                        ),
                        "type": "string_too_long",
                    }
                )
    if errors:
        raise RequestValidationError(errors)
