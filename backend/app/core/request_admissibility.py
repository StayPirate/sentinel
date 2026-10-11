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

# Stack marker for an object member name containing an inadmissible
# character, so its error is emitted in document order relative to its
# siblings' values.
_INADMISSIBLE_MEMBER_NAME = object()


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


def _body_errors(body: Any) -> list[dict[str, Any]]:
    """One error per JSON string containing an inadmissible character, at
    any depth.

    Walks iteratively so a deeply nested body that the JSON decoder
    accepted cannot exhaust the interpreter recursion limit here. An object
    member name containing an inadmissible character is reported at its
    containing object (the name itself is never echoed in a `loc`, which
    could not even be rendered for a surrogate code point), and that
    member's value is not inspected further. Errors are in document order.
    """
    errors: list[dict[str, Any]] = []
    stack: list[tuple[tuple[str | int, ...], Any]] = [(("body",), body)]
    while stack:
        loc, value = stack.pop()
        if value is _INADMISSIBLE_MEMBER_NAME:
            errors.append(_error(loc))
        elif isinstance(value, str):
            if contains_inadmissible_character(value):
                errors.append(_error(loc))
        elif isinstance(value, list):
            stack.extend(
                ((*loc, index), item)
                for index, item in reversed(list(enumerate(value)))
            )
        elif isinstance(value, dict):
            members: list[tuple[tuple[str | int, ...], Any]] = []
            for key, item in value.items():
                if contains_inadmissible_character(key):
                    members.append((loc, _INADMISSIBLE_MEMBER_NAME))
                else:
                    members.append(((*loc, key), item))
            stack.extend(reversed(members))
    return errors


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
    and every string value and object member name of a decoded JSON body.
    Undeclared query parameters, non-string parameters, headers, cookies,
    and non-JSON bodies are never inspected. A request with no violation is
    a no-op.

    Q6: raises `RequestValidationError` — rendered as the standard `422
    VALIDATION_ERROR` envelope by the handler registered in `app.main` —
    carrying one Pydantic-shaped error per offending value, located at that
    value. The value is never included in the error. Otherwise infallible.
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
        errors.extend(_body_errors(await request.json()))
    if errors:
        raise RequestValidationError(errors)
