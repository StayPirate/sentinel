"""Tests for the declared route parameter discovery
(`backend/app/core/route_params.py`)."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

import pytest
from fastapi import Depends, FastAPI, Path, Query
from fastapi.routing import APIRoute

from app.core.route_params import declared_string_param_names, is_string_like


class _Choice(StrEnum):
    ONE = "one"
    TWO = "two"


@pytest.mark.unit
class TestIsStringLike:
    """Pure classification used to select which declared parameters the
    shared request input dependencies inspect."""

    def test_str_is_string_like(self) -> None:
        assert is_string_like(str) is True

    def test_optional_str_is_string_like(self) -> None:
        assert is_string_like(str | None) is True

    def test_str_enum_is_string_like(self) -> None:
        assert is_string_like(_Choice) is True

    def test_optional_str_enum_is_string_like(self) -> None:
        assert is_string_like(_Choice | None) is True

    def test_int_is_not_string_like(self) -> None:
        assert is_string_like(int) is False

    def test_optional_int_is_not_string_like(self) -> None:
        assert is_string_like(int | None) is False

    def test_bool_is_not_string_like(self) -> None:
        assert is_string_like(bool) is False

    def test_uuid_is_not_string_like(self) -> None:
        assert is_string_like(UUID) is False

    def test_list_str_is_string_like(self) -> None:
        assert is_string_like(list[str]) is True

    def test_optional_list_str_is_string_like(self) -> None:
        assert is_string_like(list[str] | None) is True

    def test_list_str_enum_is_string_like(self) -> None:
        assert is_string_like(list[_Choice]) is True

    def test_list_int_is_not_string_like(self) -> None:
        assert is_string_like(list[int]) is False

    def test_string_literal_is_string_like(self) -> None:
        """A `Literal` of strings (for example the preview's
        `proposed_version`) is inspected like `str`, so the shared NUL and
        length checks run before authentication and endpoint validation."""
        assert is_string_like(Literal["3.1", "4.0"]) is True
        assert is_string_like(Literal["3.1", "4.0"] | None) is True

    def test_non_string_literal_is_not_string_like(self) -> None:
        assert is_string_like(Literal[1, 2]) is False
        assert is_string_like(Literal["one", 2]) is False

    def test_bare_list_is_not_string_like(self) -> None:
        """A bare, unparameterized `list` has no element type to
        inspect — treated as not string-shaped rather than raising."""
        assert is_string_like(list) is False


def _locator(ticket_id: Annotated[str, Path()]) -> str:
    return ticket_id


def _filters(
    owner: Annotated[str | None, Query()] = None,
    state: Annotated[_Choice | None, Query(alias="status")] = None,
    page: Annotated[int, Query()] = 1,
) -> None:
    return None


def _route(app: FastAPI, path: str) -> APIRoute:
    route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == path)
    return route


@pytest.mark.unit
class TestDeclaredStringParamNames:
    def _app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/items/{ticket_id}/{item_id}")
        async def read(
            ticket_id: Annotated[str, Depends(_locator)],
            item_id: UUID,
            _filters: Annotated[None, Depends(_filters)],
            tag: Annotated[list[str] | None, Query()] = None,
            owner: Annotated[str | None, Query()] = None,
        ) -> None:
            return None

        return app

    def test_path_params_include_nested_string_params_only(self) -> None:
        route = _route(self._app(), "/items/{ticket_id}/{item_id}")

        assert declared_string_param_names(route.dependant, "path") == ["ticket_id"]

    def test_query_params_use_aliases_in_order_without_duplicates(self) -> None:
        """`owner` is declared both by the nested dependency and by the
        endpoint; it is listed once. `page` is not string-shaped."""
        route = _route(self._app(), "/items/{ticket_id}/{item_id}")

        assert declared_string_param_names(route.dependant, "query") == [
            "tag",
            "owner",
            "status",
        ]
