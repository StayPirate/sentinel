"""Discovery of the string-shaped parameters a matched route declares.

Shared by the app-wide request input dependencies (`app.core.query_limits`,
`app.core.request_nul`), which inspect only parameters the matched route
declares, per `docs/api-spec.md` (Undeclared Query Parameters).
"""

from __future__ import annotations

from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin

from fastapi.dependencies.models import Dependant


def is_string_like(annotation: Any) -> bool:
    """Whether `annotation` denotes a string-shaped parameter.

    Covers `str`, `str | None`, `StrEnum` subclasses (which are `str`
    subclasses), a `Literal` whose values are all strings, and
    `list[X]`/`list[X] | None` where `X` itself is string-shaped. A
    repeatable filter (e.g. `role: list[str]`,
    `event_type: list[IdentityAuditEventType]`) is declared as a
    `list[...]` annotation by FastAPI's `Query()` mechanism; callers check
    each raw occurrence individually via `request.query_params.getlist()`.
    Numeric, boolean, and UUID parameters are not string-shaped: an invalid
    value for those types already fails its own type validation with a
    more specific error.
    """
    origin = get_origin(annotation)
    if origin in (Union, UnionType):
        return any(
            is_string_like(arg) for arg in get_args(annotation) if arg is not type(None)
        )
    if origin is list:
        args = get_args(annotation)
        return bool(args) and is_string_like(args[0])
    if origin is Literal:
        values = get_args(annotation)
        return bool(values) and all(isinstance(value, str) for value in values)
    return isinstance(annotation, type) and issubclass(annotation, str)


def declared_string_param_names(
    dependant: Dependant, location: Literal["path", "query"]
) -> list[str]:
    """Every string-shaped `location` parameter name declared anywhere in
    `dependant`'s tree, including nested dependencies, in declaration
    order and without duplicates.

    A parameter declared inside a sub-dependency (e.g. a shared query-model
    builder or a Ticket-locator dependency used via `Depends()`) is listed
    on that sub-dependency's own `query_params`/`path_params`, not on the
    route's top-level `Dependant`, so the walk recurses into
    `dependant.dependencies`. Mirrors the recursive walk in
    `tests/test_api_conventions.py` (`_iter_dependants()`).

    Uses `field.alias` (the wire name), not `field.name` (the Python
    parameter name); the two differ whenever the endpoint declares an
    explicit alias (e.g. `Query(alias="status")` to avoid shadowing the
    `fastapi.status` module import).
    """
    fields = dependant.path_params if location == "path" else dependant.query_params
    names = [
        field.alias for field in fields if is_string_like(field.field_info.annotation)
    ]
    for sub_dependant in dependant.dependencies:
        names.extend(declared_string_param_names(sub_dependant, location))
    return list(dict.fromkeys(names))
