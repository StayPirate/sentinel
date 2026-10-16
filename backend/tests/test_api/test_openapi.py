"""Tests for the OpenAPI documentation of the global and shared responses
(`app/api/openapi.py`).

See `docs/api-spec.md` (Global Responses, Response Applicability
Derivation). Every case builds a standalone `SentinelAPI` whose routes use
the real authentication and capability dependencies; only the generated
document is inspected, so no request runs. The registered application is
covered by the structural tests in `tests/test_api_conventions.py` and by
the OpenAPI response contract check over every test request
(`tests/support/openapi_contract.py`).
"""

from __future__ import annotations

from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    AuthenticatedPrincipal,
    CurrentUser,
    OptionalCurrentUser,
    require_any_capability,
    require_capability,
)
from app.api.openapi import API_V1_RESPONSES, SentinelAPI
from app.core.enums import Capability
from app.schemas.errors import ErrorResponse

_ERROR_REF = {"$ref": "#/components/schemas/ErrorResponse"}
_REQUIRED_401 = (
    "`AUTH_NOT_AUTHENTICATED`: no credential was sent, or the credential is invalid."
)
_OPTIONAL_401 = "`AUTH_NOT_AUTHENTICATED`: a credential was sent and is invalid."
_403 = "`AUTH_INSUFFICIENT_PERMISSION`: the caller lacks the required capability."
_400 = "`DATE_RANGE_INVERTED`: `from_date` is after `to_date`."


def _date_range(
    from_date: Annotated[str | None, Query()] = None,
    to_date: Annotated[str | None, Query()] = None,
) -> None:
    """A query dependency declaring both date-range parameters, as the
    audit-log and list endpoints do."""


def _lower_bound(from_date: Annotated[str | None, Query()] = None) -> None:
    """A query dependency declaring only one of them."""


def _build_app(*, include_v1_responses: bool = True) -> SentinelAPI:
    router = APIRouter(prefix="/api/v1")

    @router.get("/public")
    async def public() -> None:
        """No credential processing."""

    @router.get("/optional")
    async def optional(principal: OptionalCurrentUser) -> None:
        """`Authentication: Optional`."""

    @router.get("/authenticated")
    async def authenticated(principal: CurrentUser) -> None:
        """`Access: Authenticated`."""

    @router.post("/capability")
    async def capability(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_FETCHERS)),
        ],
    ) -> None:
        """`Capability: manage_fetchers`."""

    @router.post("/any-capability")
    async def any_capability(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(
                require_any_capability(
                    Capability.TRIAGE_TICKET, Capability.MANAGE_FETCHERS
                )
            ),
        ],
    ) -> None:
        """`Capability: triage_ticket OR manage_fetchers`."""

    @router.get("/date-range", dependencies=[Depends(_date_range)])
    async def date_range() -> None:
        """Both date-range parameters, declared by a dependency."""

    @router.get("/lower-bound", dependencies=[Depends(_lower_bound)])
    async def lower_bound() -> None:
        """Only `from_date`."""

    @router.get("/hidden", include_in_schema=False)
    async def hidden(principal: CurrentUser) -> None:
        """Derives a 401, but has no operation to document it on."""

    @router.get(
        "/own-403",
        responses={
            403: {"model": ErrorResponse, "description": "`AUTH_SESSION_REQUIRED`."}
        },
    )
    async def own_403(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_USERS)),
        ],
    ) -> None:
        """A route-level 403 that does not name the derived code."""

    @router.get(
        "/own-400",
        dependencies=[Depends(_date_range)],
        responses={
            400: {
                "model": ErrorResponse,
                "description": "`DATE_RANGE_INVERTED` or `DATE_RANGE_TOO_WIDE`.",
            }
        },
    )
    async def own_400() -> None:
        """A route-level 400 that already names the derived code."""

    test_app = SentinelAPI()
    test_app.include_router(
        router, responses=API_V1_RESPONSES if include_v1_responses else None
    )
    return test_app


def _responses(test_app: SentinelAPI, method: str, path: str) -> dict[str, Any]:
    responses: dict[str, Any] = test_app.openapi()["paths"][f"/api/v1{path}"][method][
        "responses"
    ]
    return responses


def _derived(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {"application/json": {"schema": _ERROR_REF}},
    }


@pytest.mark.unit
class TestDependencyDerivedResponses:
    @pytest.mark.parametrize(
        ("method", "path", "expected"),
        [
            pytest.param("get", "/public", {}, id="public"),
            pytest.param("get", "/optional", {"401": _OPTIONAL_401}, id="optional"),
            pytest.param(
                "get", "/authenticated", {"401": _REQUIRED_401}, id="authenticated"
            ),
            pytest.param(
                "post",
                "/capability",
                {"401": _REQUIRED_401, "403": _403},
                id="capability",
            ),
            pytest.param(
                "post",
                "/any-capability",
                {"401": _REQUIRED_401, "403": _403},
                id="any-capability",
            ),
            pytest.param("get", "/date-range", {"400": _400}, id="date-range"),
            pytest.param("get", "/lower-bound", {}, id="one-date-parameter"),
        ],
    )
    def test_documents_the_responses_of_the_dependency_graph(
        self, method: str, path: str, expected: dict[str, str]
    ) -> None:
        responses = _responses(_build_app(), method, path)

        derived = {
            status: response
            for status, response in responses.items()
            if status not in {"200", "422", "500"}
        }
        assert derived == {
            status: _derived(description) for status, description in expected.items()
        }

    def test_responses_are_ordered_by_status(self) -> None:
        responses = _responses(_build_app(), "post", "/capability")

        assert list(responses) == ["200", "401", "403", "422", "500"]

    def test_route_level_status_keeps_its_schema_and_gains_the_condition(
        self,
    ) -> None:
        responses = _responses(_build_app(), "get", "/own-403")

        assert responses["403"] == {
            "description": f"`AUTH_SESSION_REQUIRED`. {_403}",
            "content": {"application/json": {"schema": _ERROR_REF}},
        }

    def test_route_level_description_naming_the_code_is_unchanged(self) -> None:
        responses = _responses(_build_app(), "get", "/own-400")

        assert responses["400"]["description"] == (
            "`DATE_RANGE_INVERTED` or `DATE_RANGE_TOO_WIDE`."
        )

    def test_error_schema_is_added_when_nothing_else_references_it(self) -> None:
        schemas = _build_app(include_v1_responses=False).openapi()["components"][
            "schemas"
        ]

        assert schemas["ErrorResponse"]["required"] == ["code", "detail"]

    def test_route_excluded_from_the_schema_is_skipped(self) -> None:
        """Its derived 401 has no operation to go on; generation does not
        fail and adds nothing for it."""
        assert "/api/v1/hidden" not in _build_app().openapi()["paths"]

    def test_error_schema_is_not_added_when_nothing_is_derived(self) -> None:
        router = APIRouter(prefix="/api/v1")

        @router.get("/public")
        async def public() -> None:
            """No credential processing."""

        test_app = SentinelAPI()
        test_app.include_router(router)

        schemas = test_app.openapi().get("components", {}).get("schemas", {})
        assert "ErrorResponse" not in schemas


@pytest.mark.unit
class TestApiV1Responses:
    def test_documents_the_validation_body_and_the_internal_error(self) -> None:
        openapi_schema = _build_app().openapi()
        responses = openapi_schema["paths"]["/api/v1/public"]["get"]["responses"]
        schemas = openapi_schema["components"]["schemas"]

        assert responses["422"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ValidationErrorResponse"
        }
        assert responses["500"]["content"]["application/json"]["schema"] == _ERROR_REF
        assert "HTTPValidationError" not in schemas
        validation = schemas["ValidationErrorResponse"]
        assert validation["required"] == ["code", "detail", "errors"]
        assert validation["properties"]["errors"]["items"] == {
            "$ref": "#/components/schemas/ValidationErrorItem"
        }
        assert schemas["ValidationErrorItem"]["required"] == ["loc", "msg", "type"]
