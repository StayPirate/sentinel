"""App-wide rejection of inadmissible characters in consumer-supplied
request input.

See `docs/api-spec.md` (Inadmissible Characters in Request Input) for the
authoritative contract: no string supplied in a declared path or query
parameter, or anywhere in a JSON request body, may contain U+0000 or a
surrogate code point; a violation returns the standard `422
VALIDATION_ERROR` envelope before authentication and every
endpoint-specific outcome.

See `docs/conventions.md` (FastAPI Conventions, "Cross-cutting request
input constraints") for why this is a single dependency registered once at
the app level (`app.main`) rather than a per-field `AdmissibleStr`: it
applies automatically to every current and future endpoint.
"""

from __future__ import annotations

import email.message
from collections.abc import Iterator
from typing import Any

from fastapi import Request, params
from fastapi.datastructures import DefaultPlaceholder
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from app.core.external_strings import (
    INADMISSIBLE_CHARACTER_MESSAGE,
    contains_inadmissible_character,
)
from app.core.route_params import declared_string_param_names

# The `msg`/`type` pair Pydantic produces for an `AdmissibleStr` field
# (`app.core.external_strings.reject_inadmissible_characters`), so both
# mechanisms report an inadmissible character identically.
_ERROR_MESSAGE = f"Value error, {INADMISSIBLE_CHARACTER_MESSAGE}"
_ERROR_TYPE = "value_error"


def _error(loc: tuple[str | int, ...]) -> dict[str, Any]:
    return {"loc": loc, "msg": _ERROR_MESSAGE, "type": _ERROR_TYPE}


def _body_is_decoded_json(request: Request, route: APIRoute) -> bool:
    """Whether FastAPI decoded this request's body as JSON.

    Mirrors the body-reading decision in `fastapi.routing` (the request
    handler built by `get_request_handler()`), which completes before any
    dependency runs: a route without a body field, or with a form body,
    never decodes JSON; otherwise a non-empty body is decoded when its
    content type is `application/json` or `application/*+json`, or when it
    has no content type and the route does not enforce a strict content
    type. A body FastAPI kept as raw bytes is never decoded here, so this
    dependency cannot turn a non-JSON body into a decoding error.
    """
    body_field = route.body_field
    if body_field is None or isinstance(body_field.field_info, params.Form):
        return False
    content_type = request.headers.get("content-type")
    if not content_type:
        strict = route.strict_content_type
        if isinstance(strict, DefaultPlaceholder):
            strict = strict.value
        return not strict
    message = email.message.Message()
    message["content-type"] = content_type
    if message.get_content_maintype() != "application":
        return False
    subtype = message.get_content_subtype()
    return subtype == "json" or subtype.endswith("+json")


def _first_body_violation(body: Any) -> tuple[str | int, ...] | None:
    """The location of the first JSON string, in document order, that
    contains an inadmissible character; `None` when there is none.

    An object member name precedes its value. One containing an
    inadmissible character is located at its containing object: the name
    itself is never echoed in a `loc`, which could not even be rendered
    for a surrogate code point.

    Walks depth-first without recursion, so a deeply nested body that the
    JSON decoder accepted cannot exhaust the interpreter recursion limit
    here. Only the open containers' iterators and the current path are
    kept, and a location is built only for the violation found, so time
    is linear in the size of the body and extra memory in its depth.
    """
    # `path[i + 1]` is the segment of the member of `members[i]` being
    # inspected; `path[0]` locates the body itself.
    path: list[str | int] = ["body"]
    members: list[Iterator[tuple[str | int, Any]]] = []
    value = body
    while True:
        if isinstance(value, str):
            if contains_inadmissible_character(value):
                return tuple(path)
        elif isinstance(value, dict):
            members.append(iter(value.items()))
            path.append("")
        elif isinstance(value, list):
            members.append(enumerate(value))
            path.append(0)
        while members:
            member = next(members[-1], None)
            if member is not None:
                break
            members.pop()
            path.pop()
        else:
            return None
        segment, value = member
        if isinstance(segment, str) and contains_inadmissible_character(segment):
            return tuple(path[:-1])
        path[-1] = segment


async def reject_inadmissible_request_input(request: Request) -> None:
    """Reject any consumer-supplied request string containing an
    inadmissible character.

    Q1: `request` is the current request. The matched route is read from
    `request.scope["route"]`, populated by Starlette's router after route
    matching and before any dependency executes; FastAPI has already read
    and decoded a JSON body by then, so `request.json()` returns the cached
    document without reading or decoding it again.

    Q3: checks, in this order, every declared string-shaped path parameter
    (already percent-decoded by Starlette), every raw occurrence of every
    declared string-shaped query parameter at any dependency nesting depth,
    and the string values and object member names of a decoded JSON body,
    in document order up to the first violation. Undeclared query
    parameters, non-string parameters, headers, cookies, and non-JSON
    bodies are never inspected. A request with no violation is a no-op.

    Q6: raises `RequestValidationError` — rendered as the standard `422
    VALIDATION_ERROR` envelope by the handler registered in `app.main` —
    carrying one Pydantic-shaped error per offending path parameter and
    query parameter occurrence, then at most one for the body's first
    offending string, each located at its value. The value is never
    included in the error. Otherwise infallible.
    """
    route = request.scope.get("route")
    if not isinstance(route, APIRoute):
        return

    errors: list[dict[str, Any]] = []
    for name in declared_string_param_names(route.dependant, "path"):
        value = request.path_params.get(name)
        if isinstance(value, str) and contains_inadmissible_character(value):
            errors.append(_error(("path", name)))
    for name in declared_string_param_names(route.dependant, "query"):
        for value in request.query_params.getlist(name):
            if contains_inadmissible_character(value):
                errors.append(_error(("query", name)))
    if _body_is_decoded_json(request, route) and await request.body():
        location = _first_body_violation(await request.json())
        if location is not None:
            errors.append(_error(location))
    if errors:
        raise RequestValidationError(errors)
