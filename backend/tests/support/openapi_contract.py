"""Runtime check of the application's responses against its OpenAPI document.

The OpenAPI document is the contract the separately developed frontend is
built against (`docs/architecture.md`, System Boundary). Success bodies are
generated from the same response models that document them, but an error
response is documented by a declaration that nothing ties to the code that
raises it. `response_contract_check()` wraps an application so that every
response it returns to a test request for a documented operation is compared
with the document, whichever client sent the request
(`docs/features/platform/testing-strategy.md`, OpenAPI Response Contract
Check):

- the status code must be documented for the operation;
- the body must match the documented media type and JSON schema, every
  object being closed: a member the schema does not declare is a mismatch.
  Pydantic omits `additionalProperties`, which JSON Schema reads as "any
  other member is allowed", so a body carrying an undocumented member would
  otherwise pass; and
- the description of the documented response must name the error `code` of
  the body, written as `` `CODE` `` (`docs/api-spec.md`, Derived Responses
  in the OpenAPI Document): the schema types `code` as a string, so the
  description is where a client learns which codes a status carries.

A request that selects no documented operation, such as a routing response
(`docs/api-spec.md`, Routing Responses) or `/openapi.json`, is not checked,
and neither is the diagnostic `500` that replaces `INTERNAL_ERROR` when
`DEBUG` is enabled (`docs/api-spec.md`, Response Format). Formats that
`jsonschema` cannot check without optional packages, such as `date-time`,
are not checked.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final

import pytest
from fastapi import FastAPI
from fastapi import routing as fastapi_routing
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_DOCUMENT_URI: Final = "urn:sentinel:openapi"

# JSON Schema keywords whose value is a schema, a list of schemas, or a map
# of names to schemas.
_SCHEMA_KEYWORDS: Final = (
    "items",
    "additionalProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "propertyNames",
)
_SCHEMA_LIST_KEYWORDS: Final = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_MAP_KEYWORDS: Final = ("properties", "patternProperties", "$defs")


def _close_objects(schema: Any) -> None:
    """Forbid, in place and at every level of `schema`, the members of an
    object schema that declares `properties` but leaves
    `additionalProperties` unset."""
    if not isinstance(schema, dict):
        return
    if "properties" in schema and "additionalProperties" not in schema:
        schema["additionalProperties"] = False
    for keyword in _SCHEMA_KEYWORDS:
        _close_objects(schema.get(keyword))
    for keyword in _SCHEMA_LIST_KEYWORDS:
        for subschema in schema.get(keyword, ()):
            _close_objects(subschema)
    for keyword in _SCHEMA_MAP_KEYWORDS:
        for subschema in schema.get(keyword, {}).values():
            _close_objects(subschema)


def _closed_document(document: dict[str, Any]) -> dict[str, Any]:
    """A copy of `document` whose component and response schemas are
    closed (`_close_objects`)."""
    closed = copy.deepcopy(document)
    for schema in closed.get("components", {}).get("schemas", {}).values():
        _close_objects(schema)
    for path_item in closed.get("paths", {}).values():
        for operation in path_item.values():
            for response in operation.get("responses", {}).values():
                for media in response.get("content", {}).values():
                    _close_objects(media.get("schema"))
    return closed


def _pointer(*tokens: str) -> str:
    """The JSON Pointer (RFC 6901) made of `tokens`."""
    return "".join(
        "/" + token.replace("~", "~0").replace("/", "~1") for token in tokens
    )


@dataclass
class _CapturedResponse:
    """The status, media type, and body of one HTTP response, as sent."""

    status: int | None = None
    media_type: str | None = None
    body: bytearray = field(default_factory=bytearray)
    complete: bool = False

    def record(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
            for name, value in message.get("headers", ()):
                if name.lower() == b"content-type":
                    self.media_type = value.decode("latin-1").split(";")[0].strip()
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")
            self.complete = not message.get("more_body", False)


@dataclass
class ResponseContractCheck:
    """Compares the responses of `app` with `app.openapi()` and records
    every mismatch in `violations`."""

    app: FastAPI
    violations: list[str] = field(default_factory=list)
    _registry: Registry[Any] | None = field(default=None, repr=False)
    _validators: dict[str, Draft202012Validator] = field(
        default_factory=dict, repr=False
    )

    def wrap(self, inner: ASGIApp) -> ASGIApp:
        """`inner`, with every HTTP response it sends checked. Placed
        outside Starlette's `ServerErrorMiddleware`, so it also sees the
        `500` rendered for an unhandled exception, which that middleware
        sends before re-raising the exception."""

        async def checked(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                await inner(scope, receive, send)
                return
            method: str = scope["method"]
            path: str = scope["path"]
            response = _CapturedResponse()

            async def capture(message: Message) -> None:
                response.record(message)
                await send(message)

            try:
                await inner(scope, receive, capture)
            finally:
                if response.complete and response.status is not None:
                    self.check(method, path, response)

        return checked

    def check(self, method: str, path: str, response: _CapturedResponse) -> None:
        """Record why `response`, returned to `method path`, is not the
        documented response of the operation the request selects, if it is
        not."""
        assert response.status is not None
        if self.app.debug and response.status == 500:
            return
        operation = self._operation(method, path)
        if operation is None:
            return
        template, operation_doc = operation
        where = f"{method} {path} (operation {method} {template}) returned"
        responses: dict[str, Any] = operation_doc.get("responses", {})
        status = response.status
        key = next(
            (
                candidate
                for candidate in (str(status), f"{status // 100}XX", "default")
                if candidate in responses
            ),
            None,
        )
        if key is None:
            self.violations.append(
                f"{where} {status}, which is not documented "
                f"(documented: {', '.join(sorted(responses)) or 'none'})"
            )
            return
        content: dict[str, Any] = responses[key].get("content", {})
        if not content:
            if response.body:
                self.violations.append(
                    f"{where} {status} with a body, but the response is "
                    "documented without content"
                )
            return
        if response.media_type not in content:
            self.violations.append(
                f"{where} {status} as {response.media_type!r}, but it is "
                f"documented as {', '.join(sorted(content))}"
            )
            return
        if "schema" not in content[response.media_type]:
            return
        try:
            body = json.loads(response.body)
        except ValueError:
            self.violations.append(f"{where} {status} with a body that is not JSON")
            return
        validator = self._validator(
            _pointer(
                "paths",
                template,
                method.lower(),
                "responses",
                key,
                "content",
                response.media_type,
                "schema",
            )
        )
        error = best_match(validator.iter_errors(body))
        if error is not None:
            self.violations.append(
                f"{where} {status} with a body that does not match the "
                f"documented schema at {error.json_path}: {error.message}"
            )
            return
        code = body.get("code") if isinstance(body, dict) else None
        description: str = responses[key].get("description", "")
        if isinstance(code, str) and f"`{code}`" not in description:
            self.violations.append(
                f"{where} {status} {code}, which the description of the "
                f"documented response does not name: {description!r}"
            )

    def _operation(self, method: str, path: str) -> tuple[str, dict[str, Any]] | None:
        """The path template and OpenAPI operation of the route the router
        selects for `method path` — the first route, in routing order, whose
        path and method both match — or `None` when no route matches both
        or the selected route is not documented."""
        for context in fastapi_routing.iter_route_contexts(self.app.routes):
            regex = getattr(context, "path_regex", None)
            if regex is None or not regex.match(path):
                continue
            if method not in (context.methods or ()):
                continue
            template = context.path_format
            if template is None:
                return None
            operation = (
                self.app.openapi()
                .get("paths", {})
                .get(template, {})
                .get(method.lower())
            )
            return None if operation is None else (template, operation)
        return None

    def _validator(self, pointer: str) -> Draft202012Validator:
        """A validator for the schema at `pointer` in the closed document,
        resolving its `$ref`s against that document."""
        if self._registry is None:
            resource = Resource.from_contents(
                _closed_document(self.app.openapi()),
                default_specification=DRAFT202012,
            )
            self._registry = Registry().with_resource(_DOCUMENT_URI, resource)
        validator = self._validators.get(pointer)
        if validator is None:
            validator = Draft202012Validator(
                {"$ref": f"{_DOCUMENT_URI}#{pointer}"},
                registry=self._registry,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )
            self._validators[pointer] = validator
        return validator


@contextmanager
def response_contract_check(app: FastAPI) -> Iterator[ResponseContractCheck]:
    """Check every response `app` returns while the context is active.

    The check wraps the middleware stack Starlette builds on the first
    request. Replacing `build_middleware_stack` keeps it in place when a
    test resets `middleware_stack` to have the stack rebuilt (for example
    after changing `app.debug`).
    """
    check = ResponseContractCheck(app)
    build: Callable[[], ASGIApp] = app.build_middleware_stack
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(app, "build_middleware_stack", lambda: check.wrap(build()))
        patch.setattr(app, "middleware_stack", None)
        yield check
