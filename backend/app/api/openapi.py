"""OpenAPI documentation of the global and shared responses.

`docs/api-spec.md` (Global Responses, Response Applicability Derivation)
derives these responses from an endpoint's access level and query shape, so
endpoint error tables never repeat them. The OpenAPI document, the contract
API clients are generated from, documents them for every operation
(`docs/api-spec.md`, Derived Responses in the OpenAPI Document), from what
produces them (`docs/conventions.md`, FastAPI Conventions):

- `422 VALIDATION_ERROR` and `500 INTERNAL_ERROR` apply to every `/api/v1`
  operation whatever its access level. `API_V1_RESPONSES` declares them once,
  for every router `app.main` includes under `/api/v1`. This also stops
  FastAPI from documenting its own validation-error body, which is not the
  body the application returns (`app.main`, `_validation_error_response`).
- `401 AUTH_NOT_AUTHENTICATED`, `403 AUTH_INSUFFICIENT_PERMISSION`, and the
  shared `400 DATE_RANGE_INVERTED` apply when an operation's dependency graph
  contains the dependency that produces them: authentication, a capability
  check, or both date-range query parameters. `SentinelAPI` adds them to the
  generated document (`document_dependency_responses`), so a new endpoint
  documents them without declaring them.

A route that declares a status itself keeps its declaration, because it
describes endpoint-specific codes for that status. For `422`, its schema
must therefore also admit `ValidationErrorResponse`
(`backend/tests/test_api_conventions.py`); for a dependency-derived status,
the derived condition is appended to its description.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final

from fastapi import FastAPI
from fastapi import routing as fastapi_routing
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from app.api.dependencies import (
    get_current_user,
    get_optional_current_user,
    require_any_capability,
    require_capability,
)
from app.schemas.errors import ErrorResponse, ValidationErrorResponse

API_V1_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    422: {
        "model": ValidationErrorResponse,
        "description": (
            "`VALIDATION_ERROR`: the request fails validation; `errors` lists "
            "each invalid input."
        ),
    },
    500: {
        "model": ErrorResponse,
        "description": "`INTERNAL_ERROR`: unhandled server error.",
    },
}
"""The responses of every `/api/v1` operation (`docs/api-spec.md`, Global
Response Derivation), passed to `include_router()` by `app.main`."""

_ERROR_RESPONSE_REF: Final = f"#/components/schemas/{ErrorResponse.__name__}"

# The closures `require_capability()` and `require_any_capability()` return
# for each endpoint share these qualified names.
_CAPABILITY_CHECKS: Final = frozenset(
    f"{factory.__qualname__}.<locals>._dependency"
    for factory in (require_capability, require_any_capability)
)


@dataclass(frozen=True)
class DerivedResponse:
    """A dependency-derived response: its status, error code, and the
    condition its OpenAPI description states."""

    status: str
    code: str
    condition: str

    @property
    def description(self) -> str:
        return f"`{self.code}`: {self.condition}"


_REQUIRED_AUTHENTICATION: Final = DerivedResponse(
    "401",
    "AUTH_NOT_AUTHENTICATED",
    "no credential was sent, or the credential is invalid.",
)
_OPTIONAL_AUTHENTICATION: Final = DerivedResponse(
    "401", "AUTH_NOT_AUTHENTICATED", "a credential was sent and is invalid."
)
_CAPABILITY: Final = DerivedResponse(
    "403",
    "AUTH_INSUFFICIENT_PERMISSION",
    "the caller lacks the required capability.",
)
_DATE_RANGE: Final = DerivedResponse(
    "400", "DATE_RANGE_INVERTED", "`from_date` is after `to_date`."
)
_DATE_RANGE_PARAMETERS: Final = frozenset({"from_date", "to_date"})


def _dependants(dependant: Dependant) -> Iterator[Dependant]:
    """`dependant` and every dependency nested below it."""
    yield dependant
    for sub_dependant in dependant.dependencies:
        yield from _dependants(sub_dependant)


def dependency_responses(dependant: Dependant) -> list[DerivedResponse]:
    """The global and shared responses an operation with the effective
    dependency graph `dependant` can return, beyond `API_V1_RESPONSES`
    (`docs/api-spec.md`, Global Response Derivation and Query-Shape
    Response Derivation)."""
    nodes = list(_dependants(dependant))
    calls = {node.call for node in nodes}
    responses: list[DerivedResponse] = []
    if get_current_user in calls:
        responses.append(_REQUIRED_AUTHENTICATION)
    elif get_optional_current_user in calls:
        responses.append(_OPTIONAL_AUTHENTICATION)
    if any(getattr(call, "__qualname__", None) in _CAPABILITY_CHECKS for call in calls):
        responses.append(_CAPABILITY)
    query_names = {param.alias for node in nodes for param in node.query_params}
    if query_names >= _DATE_RANGE_PARAMETERS:
        responses.append(_DATE_RANGE)
    return responses


def document_dependency_responses(
    openapi_schema: dict[str, Any], routes: Sequence[BaseRoute]
) -> None:
    """Add to `openapi_schema`, in place, the `dependency_responses()` of
    every documented operation of `routes`.

    An operation that already documents the status keeps its schema; the
    derived condition is appended to its description unless the
    description already names the code. Responses are ordered by status.
    """
    paths: dict[str, Any] = openapi_schema.get("paths", {})
    referenced = False
    for context in fastapi_routing.iter_route_contexts(routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        if not context.include_in_schema or context.path_format is None:
            continue
        derived = dependency_responses(context.dependant)
        if not derived:
            continue
        for method in context.methods or ():
            operation = paths.get(context.path_format, {}).get(method.lower())
            if operation is None:
                continue
            responses: dict[str, Any] = operation.setdefault("responses", {})
            for response in derived:
                existing = responses.get(response.status)
                if existing is None:
                    referenced = True
                    responses[response.status] = {
                        "description": response.description,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": _ERROR_RESPONSE_REF}
                            }
                        },
                    }
                elif f"`{response.code}`" not in existing.get("description", ""):
                    existing["description"] = (
                        f"{existing.get('description', '')} {response.description}"
                    ).strip()
            operation["responses"] = dict(sorted(responses.items()))
    if referenced:
        # Present whenever an `/api/v1` router is included (the `500` of
        # `API_V1_RESPONSES`); added otherwise so the reference resolves.
        openapi_schema.setdefault("components", {}).setdefault(
            "schemas", {}
        ).setdefault(ErrorResponse.__name__, ErrorResponse.model_json_schema())


class SentinelAPI(FastAPI):
    """FastAPI, whose generated OpenAPI document also describes the
    dependency-derived responses (`document_dependency_responses`)."""

    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is None:
            openapi_schema = super().openapi()
            document_dependency_responses(openapi_schema, self.routes)
            return openapi_schema
        return self.openapi_schema
