"""End-to-end tests for the Product catalog list endpoint
(`GET /api/v1/products`, `backend/app/api/v1/products.py`).

See docs/features/packages/product-catalog.md (API Endpoints > List
Products: query parameters, response, Product list item, Product Query
Service, Test Requirements; Catalog Readiness and Freshness; Security),
docs/api-spec.md (Optional Authentication on Public Endpoints; Query
Parameter Length Limit; Undeclared Query Parameters; Pagination; Enum
Filter Validation; Sort Parameter Validation; Response Format; Global
Responses; Product Identifier Resolution), and
docs/features/platform/testing-strategy.md (API Endpoints; Tier
Responsibility and Proportionality).

These tests cover the HTTP contract: the envelope and wire format,
repeatable-filter parsing (defaults, invalid values, all-invalid),
the one handler-captured UTC evaluation date, request validation,
undeclared parameters, optional authentication, handler delegation, and
OpenAPI. Search, filter composition, lifecycle parity, sorting, tie-breaking,
read-only, and independent-session snapshot-race coverage lives in
`tests/test_services/test_product_list.py`.

Every test starts from an empty Product table (per-test transaction
rollback) and passes explicit `catalog_last_seen_at` values.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import products as route
from app.core.enums import (
    CatalogPresence,
    LifecyclePhase,
    LifecyclePhaseFilter,
    ProductSortField,
    SortOrder,
)
from app.main import app
from app.models.api_key import ApiKey
from app.models.product import Product
from app.models.user import User
from app.services import product_service
from app.services.product_service import ProductListItemProjection, ProductPage
from tests.support.ticket_api import UNAUTHENTICATED, Clock

ProductFactory = Callable[..., Awaitable[Product]]

_PATH: Final = "/api/v1/products"
_NOW: Final = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
_SNAPSHOT: Final = datetime(2026, 9, 1, 2, 0, tzinfo=UTC)
_EARLIER: Final = datetime(2026, 8, 1, 2, 0, tzinfo=UTC)
_CREATED_AT: Final = datetime(2026, 5, 10, 8, 0, tzinfo=UTC)
_UPDATED_AT: Final = datetime(2026, 6, 11, 9, 30, 15, 250000, tzinfo=UTC)
_EMPTY_PAGE: Final = {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}

_ITEM_FIELDS: Final = {
    "name",
    "version",
    "display_name",
    "cpe",
    "catalog_presence",
    "catalog_last_seen_at",
    "first_customer_ship_date",
    "general_support_end_date",
    "extended_support_end_date",
    "reactive_support_end_date",
    "lifecycle_phase",
    "cvss_threshold",
    "created_at",
    "updated_at",
}
"""product-catalog.md, List Products > Product list item."""

_QUERY_PARAMETERS: Final = {
    "search",
    "cpe",
    "catalog_presence",
    "lifecycle_phase",
    "page",
    "per_page",
    "sort_by",
    "sort_order",
}
"""product-catalog.md, List Products > Query parameters."""

_TOO_LONG_MSG: Final = "String should have at most 500 characters"


async def _cpes(client: AsyncClient, **params: Any) -> list[str]:
    """CPEs of one complete page; the total must equal the page."""
    response = await client.get(_PATH, params={"per_page": 100, **params})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["meta"]["total"] == len(body["data"])
    return [item["cpe"] for item in body["data"]]


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Replaces the endpoint's single evaluation-instant capture."""
    clock = Clock(_NOW)
    monkeypatch.setattr(route, "_utc_now", clock.now)
    return clock


def _spy(monkeypatch: pytest.MonkeyPatch, page: ProductPage | None = None) -> AsyncMock:
    """Replace `product_service.list_products` with a spy returning `page`
    (an empty default page when omitted)."""
    spy = AsyncMock(
        return_value=page or ProductPage(items=(), total=0, page=1, per_page=20)
    )
    monkeypatch.setattr(product_service, "list_products", spy)
    return spy


# ---------------------------------------------------------------------------
# Envelope and wire format
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestProductList:
    async def test_paginated_envelope_and_wire_format(
        self, client: AsyncClient, fixed_clock: Clock, product_factory: ProductFactory
    ) -> None:
        supported = await product_factory(
            name="Example Linux Enterprise Server",
            version="15 SP6",
            display_name="ELES 15 SP6",
            cpe="cpe:/o:example:eles:15:sp6",
            catalog_last_seen_at=_SNAPSHOT,
            first_customer_ship_date=date(2024, 10, 1),
            general_support_end_date=date(2031, 10, 31),
            extended_support_end_date=date(2034, 10, 31),
            reactive_support_end_date=date(2036, 10, 31),
            cvss_threshold=Decimal("7.5"),
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        unknown = await product_factory(
            name="Example Micro",
            version="6.1",
            display_name="EM 6.1",
            cpe="cpe:/o:example:em:6.1",
            catalog_last_seen_at=_SNAPSHOT,
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )

        response = await client.get(_PATH)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data", "meta"}
        assert body["meta"] == {"total": 2, "page": 1, "per_page": 20}
        assert body["data"] == [
            {
                "name": "Example Linux Enterprise Server",
                "version": "15 SP6",
                "display_name": "ELES 15 SP6",
                "cpe": "cpe:/o:example:eles:15:sp6",
                "catalog_presence": "current",
                "catalog_last_seen_at": "2026-09-01T02:00:00Z",
                "first_customer_ship_date": "2024-10-01",
                "general_support_end_date": "2031-10-31",
                "extended_support_end_date": "2034-10-31",
                "reactive_support_end_date": "2036-10-31",
                "lifecycle_phase": "general_support",
                "cvss_threshold": 7.5,
                "created_at": "2026-05-10T08:00:00Z",
                "updated_at": "2026-06-11T09:30:15.250000Z",
            },
            {
                "name": "Example Micro",
                "version": "6.1",
                "display_name": "EM 6.1",
                "cpe": "cpe:/o:example:em:6.1",
                "catalog_presence": "current",
                "catalog_last_seen_at": "2026-09-01T02:00:00Z",
                "first_customer_ship_date": None,
                "general_support_end_date": None,
                "extended_support_end_date": None,
                "reactive_support_end_date": None,
                "lifecycle_phase": None,
                "cvss_threshold": None,
                "created_at": "2026-05-10T08:00:00Z",
                "updated_at": "2026-06-11T09:30:15.250000Z",
            },
        ]
        for item in body["data"]:
            assert set(item) == _ITEM_FIELDS
        for product in (supported, unknown):
            assert str(product.id) not in response.text
            assert product.id.hex not in response.text
        assert fixed_clock.calls == 1

    @pytest.mark.parametrize(
        ("threshold", "wire"),
        [(Decimal("7.0"), "7.0"), (Decimal("0.1"), "0.1"), (Decimal("10.0"), "10.0")],
    )
    async def test_cvss_threshold_is_a_json_number(
        self,
        client: AsyncClient,
        product_factory: ProductFactory,
        threshold: Decimal,
        wire: str,
    ) -> None:
        await product_factory(catalog_last_seen_at=_SNAPSHOT, cvss_threshold=threshold)

        response = await client.get(_PATH)

        assert response.status_code == 200
        (item,) = response.json()["data"]
        assert isinstance(item["cvss_threshold"], float)
        assert item["cvss_threshold"] == float(threshold)
        assert f'"cvss_threshold":{wire}' in response.text

    @pytest.mark.parametrize(
        "params",
        [
            {},
            {"catalog_presence": ["current", "historical"]},
            {"lifecycle_phase": "unavailable"},
            {"search": ""},
        ],
        ids=["default", "both", "unavailable", "empty-search"],
    )
    async def test_empty_catalog_returns_an_empty_page(
        self, client: AsyncClient, params: dict[str, Any]
    ) -> None:
        """Before the first complete snapshot: `200` and an empty page,
        never `PRODUCT_CATALOG_NOT_READY`."""
        response = await client.get(_PATH, params=params)

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, client: AsyncClient, product_factory: ProductFactory
    ) -> None:
        for _ in range(3):
            await product_factory(catalog_last_seen_at=_SNAPSHOT)

        response = await client.get(_PATH, params={"page": 3, "per_page": 2})

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 3, "page": 3, "per_page": 2},
        }


# ---------------------------------------------------------------------------
# Repeatable enum filters at the wire
# ---------------------------------------------------------------------------


@pytest.fixture
async def presence_world(product_factory: ProductFactory) -> None:
    await product_factory(
        cpe="cpe:/o:example:current-a", catalog_last_seen_at=_SNAPSHOT
    )
    await product_factory(
        cpe="cpe:/o:example:historical", catalog_last_seen_at=_EARLIER
    )
    await product_factory(
        cpe="cpe:/o:example:current-b", catalog_last_seen_at=_SNAPSHOT
    )


_CURRENT: Final = ["cpe:/o:example:current-a", "cpe:/o:example:current-b"]
_HISTORICAL: Final = ["cpe:/o:example:historical"]


@pytest.fixture
async def phase_world(product_factory: ProductFactory) -> None:
    """Current Products in each lifecycle situation on the date of
    `fixed_clock` (2026-09-27)."""
    for label, dates in (
        ("pre", {"first_customer_ship_date": date(2027, 1, 1)}),
        ("gs", {"general_support_end_date": date(2030, 1, 1)}),
        ("eol", {"general_support_end_date": date(2020, 1, 1)}),
        ("unknown", {}),
    ):
        await product_factory(
            cpe=f"cpe:/o:example:{label}", catalog_last_seen_at=_SNAPSHOT, **dates
        )


@pytest.mark.e2e
class TestRepeatableFilters:
    @pytest.mark.parametrize(
        ("presence", "expected"),
        [
            pytest.param(None, _CURRENT, id="absent-defaults-to-current"),
            pytest.param(["current"], _CURRENT, id="current"),
            pytest.param(["historical"], _HISTORICAL, id="historical"),
            pytest.param(
                ["current", "historical"],
                sorted(_CURRENT + _HISTORICAL),
                id="both",
            ),
            pytest.param(["current", "current"], _CURRENT, id="repeated"),
            pytest.param(["bogus", "historical"], _HISTORICAL, id="invalid-ignored"),
            pytest.param(["bogus"], [], id="only-invalid"),
            pytest.param(["current,historical"], [], id="comma-literal"),
            pytest.param(["CURRENT", "Historical"], [], id="case-sensitive"),
            pytest.param([""], [], id="empty-value"),
            pytest.param(
                ["current,historical", "historical"],
                _HISTORICAL,
                id="comma-literal-ignored",
            ),
        ],
    )
    async def test_catalog_presence_is_parsed_from_wire_values(
        self,
        client: AsyncClient,
        presence_world: None,
        presence: list[str] | None,
        expected: list[str],
    ) -> None:
        params = {} if presence is None else {"catalog_presence": presence}

        assert await _cpes(client, **params, sort_by="cpe") == sorted(expected)

    async def test_catalog_presence_is_serialized_per_item(
        self, client: AsyncClient, presence_world: None
    ) -> None:
        response = await client.get(
            _PATH, params={"catalog_presence": ["historical", "current"]}
        )

        assert response.status_code == 200
        assert {
            item["cpe"]: item["catalog_presence"] for item in response.json()["data"]
        } == {
            "cpe:/o:example:current-a": "current",
            "cpe:/o:example:current-b": "current",
            "cpe:/o:example:historical": "historical",
        }

    @pytest.mark.parametrize(
        ("phases", "expected"),
        [
            pytest.param(None, ["eol", "gs", "pre", "unknown"], id="absent-no-filter"),
            pytest.param(["general_support"], ["gs"], id="real-phase"),
            pytest.param(["unavailable"], ["unknown"], id="unavailable"),
            pytest.param(
                ["unavailable", "eol"], ["eol", "unknown"], id="unavailable-or"
            ),
            pytest.param(["pre_release", "eol"], ["eol", "pre"], id="or"),
            pytest.param(["bogus", "eol"], ["eol"], id="invalid-ignored"),
            pytest.param(["bogus"], [], id="only-invalid"),
            pytest.param(["eol,general_support"], [], id="comma-literal"),
            pytest.param(["EOL", "Unavailable"], [], id="case-sensitive"),
            pytest.param(["null"], [], id="null-is-not-a-value"),
        ],
    )
    async def test_lifecycle_phase_is_parsed_from_wire_values(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        phase_world: None,
        phases: list[str] | None,
        expected: list[str],
    ) -> None:
        params = {} if phases is None else {"lifecycle_phase": phases}

        assert await _cpes(client, **params, sort_by="cpe") == [
            f"cpe:/o:example:{label}" for label in expected
        ]

    async def test_unavailable_items_keep_a_null_lifecycle_phase(
        self, client: AsyncClient, fixed_clock: Clock, phase_world: None
    ) -> None:
        response = await client.get(
            _PATH,
            params={"lifecycle_phase": ["unavailable", "general_support"]},
        )

        assert response.status_code == 200
        assert {
            item["cpe"]: item["lifecycle_phase"] for item in response.json()["data"]
        } == {"cpe:/o:example:gs": "general_support", "cpe:/o:example:unknown": None}
        assert "unavailable" not in response.text


# ---------------------------------------------------------------------------
# One UTC evaluation date per request
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationDate:
    @pytest.mark.parametrize(
        ("now", "phase"),
        [
            pytest.param(
                datetime(2026, 9, 27, 23, 59, 59, 999999, tzinfo=UTC),
                "general_support",
                id="last-instant-of-gs-end",
            ),
            pytest.param(datetime(2026, 9, 28, tzinfo=UTC), "eol", id="next-utc-day"),
            pytest.param(
                datetime(2026, 9, 28, 1, 0, tzinfo=timezone(timedelta(hours=2))),
                "general_support",
                id="offset-instant-on-the-utc-gs-end",
            ),
            pytest.param(
                datetime(2026, 9, 27, 20, 0, tzinfo=timezone(timedelta(hours=-5))),
                "eol",
                id="offset-instant-on-the-next-utc-day",
            ),
        ],
    )
    async def test_rows_filters_and_phases_use_the_captured_utc_date(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        product_factory: ProductFactory,
        now: datetime,
        phase: str,
    ) -> None:
        """General Support ends on 2026-09-27 inclusive: the request's one
        UTC calendar date decides the serialized phase and the filter."""
        await product_factory(
            cpe="cpe:/o:example:boundary",
            catalog_last_seen_at=_SNAPSHOT,
            general_support_end_date=date(2026, 9, 27),
        )
        other = "eol" if phase == "general_support" else "general_support"
        clock = Clock(now)
        monkeypatch.setattr(route, "_utc_now", clock.now)

        listed = await client.get(_PATH)
        selected = await client.get(_PATH, params={"lifecycle_phase": phase})
        excluded = await client.get(_PATH, params={"lifecycle_phase": other})

        assert [item["lifecycle_phase"] for item in listed.json()["data"]] == [phase]
        assert [item["lifecycle_phase"] for item in selected.json()["data"]] == [phase]
        assert excluded.json() == _EMPTY_PAGE
        assert clock.calls == 3


# ---------------------------------------------------------------------------
# Request validation and undeclared parameters
# ---------------------------------------------------------------------------


_INVALID_CASES: Final = [
    pytest.param({"sort_by": "id"}, "sort_by", id="sort-by-id"),
    pytest.param({"sort_by": "Name"}, "sort_by", id="sort-by-case"),
    pytest.param({"sort_by": "lifecycle_phase"}, "sort_by", id="sort-by-derived"),
    pytest.param({"sort_by": ""}, "sort_by", id="sort-by-empty"),
    pytest.param({"sort_order": "up"}, "sort_order", id="sort-order"),
    pytest.param({"sort_order": "ASC"}, "sort_order", id="sort-order-case"),
    pytest.param({"page": 0}, "page", id="page-0"),
    pytest.param({"page": -1}, "page", id="page-negative"),
    pytest.param({"page": "first"}, "page", id="page-not-int"),
    pytest.param({"page": 2_147_483_648}, "page", id="page-overflow"),
    pytest.param({"per_page": 0}, "per_page", id="per-page-0"),
    pytest.param({"per_page": 101}, "per_page", id="per-page-101"),
    pytest.param({"per_page": "x"}, "per_page", id="per-page-not-int"),
]

_STRING_PARAMETERS: Final = ["search", "cpe", "catalog_presence", "lifecycle_phase"]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("params", "field"), _INVALID_CASES)
    async def test_invalid_parameter_returns_422_before_the_service(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, Any],
        field: str,
    ) -> None:
        spy = _spy(monkeypatch)

        response = await client.get(_PATH, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert body["detail"] == "Request validation failed"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spy.assert_not_awaited()

    @pytest.mark.parametrize("field", _STRING_PARAMETERS)
    async def test_a_501_character_value_is_a_422(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch, field: str
    ) -> None:
        """The global limit applies to each raw value, including one
        occurrence of a repeatable filter beside a valid one."""
        spy = _spy(monkeypatch)
        value: str | list[str] = "x" * 501
        if field in {"catalog_presence", "lifecycle_phase"}:
            value = ["current" if field == "catalog_presence" else "eol", "x" * 501]

        response = await client.get(_PATH, params={field: value})

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [
                {
                    "loc": ["query", field],
                    "msg": _TOO_LONG_MSG,
                    "type": "string_too_long",
                }
            ],
        }
        spy.assert_not_awaited()

    @pytest.mark.parametrize("field", _STRING_PARAMETERS)
    async def test_a_500_character_value_is_accepted(
        self, client: AsyncClient, product_factory: ProductFactory, field: str
    ) -> None:
        await product_factory(catalog_last_seen_at=_SNAPSHOT)

        response = await client.get(_PATH, params={field: "x" * 500})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_boundary_page_values_are_accepted(
        self, client: AsyncClient, product_factory: ProductFactory
    ) -> None:
        for _ in range(2):
            await product_factory(catalog_last_seen_at=_SNAPSHOT)

        for params, meta, size in (
            ({"per_page": 1}, {"total": 2, "page": 1, "per_page": 1}, 1),
            ({"per_page": 100}, {"total": 2, "page": 1, "per_page": 100}, 2),
            (
                {"page": 2_147_483_647, "per_page": 100},
                {"total": 2, "page": 2_147_483_647, "per_page": 100},
                0,
            ),
        ):
            response = await client.get(_PATH, params=params)
            assert response.status_code == 200, (params, response.text)
            assert response.json()["meta"] == meta
            assert len(response.json()["data"]) == size

    async def test_every_sort_field_and_order_is_accepted(
        self, client: AsyncClient, product_factory: ProductFactory
    ) -> None:
        """Ordering semantics are proven by the service tests; the wire
        accepts every documented value."""
        await product_factory(catalog_last_seen_at=_SNAPSHOT)

        for sort_by in ProductSortField:
            for sort_order in SortOrder:
                response = await client.get(
                    _PATH, params={"sort_by": sort_by, "sort_order": sort_order}
                )
                assert response.status_code == 200, (sort_by, sort_order)
                assert response.json()["meta"]["total"] == 1

    async def test_undeclared_query_parameters_are_ignored(
        self, client: AsyncClient, presence_world: None
    ) -> None:
        plain = await client.get(_PATH)
        with_params = await client.get(
            _PATH,
            params={
                "foo": "bar",
                "status": "x",
                "id": "00000000-0000-7000-8000-000000000000",
                "q": "y" * 600,
                "name": "Nothing",
                "sort": "cpe",
                "from_date": "not-a-date",
            },
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json()
        assert [item["cpe"] for item in plain.json()["data"]] == _CURRENT


# ---------------------------------------------------------------------------
# Optional authentication
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOptionalAuthentication:
    async def test_anonymous_request_is_accepted(
        self, client: AsyncClient, presence_world: None
    ) -> None:
        assert await _cpes(client) == _CURRENT

    async def test_valid_session_cookie_is_accepted_with_the_same_listing(
        self, authenticated_client: AsyncClient, presence_world: None
    ) -> None:
        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert [item["cpe"] for item in response.json()["data"]] == _CURRENT

    async def test_valid_api_key_is_accepted_and_processed(
        self,
        client: AsyncClient,
        presence_world: None,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid selected API key authenticates the caller and runs the
        API-key operational effect (`last_used_at` debouncing)."""
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch)

        response = await client.get(_PATH, headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        assert [item["cpe"] for item in response.json()["data"]] == _CURRENT
        touch.assert_awaited_once()
        assert touch.await_args is not None
        assert touch.await_args.args[0] == key.id

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"headers": {"Authorization": "Bearer stl_ak_" + "0" * 32}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "unknown-api-key", "cookie"],
    )
    async def test_invalid_selected_credential_returns_401_before_the_service(
        self,
        client: AsyncClient,
        presence_world: None,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        spy = _spy(monkeypatch)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_PATH, headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_invalid_bearer_never_falls_back_to_a_valid_cookie(
        self,
        authenticated_client: AsyncClient,
        presence_world: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(monkeypatch)

        response = await authenticated_client.get(
            _PATH, headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# The handler delegates parsed input to the service and runs no query
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_defaults_reach_the_service(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(monkeypatch)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE
        assert recorder.statements == []
        assert fixed_clock.calls == 1
        spy.assert_awaited_once()
        assert spy.await_args is not None
        assert spy.await_args.args == (db_session,)
        kwargs = spy.await_args.kwargs
        assert kwargs == {
            "evaluation_date": date(2026, 9, 27),
            "search": None,
            "cpe": None,
            "catalog_presence": (CatalogPresence.CURRENT,),
            "lifecycle_phase": None,
            "sort_by": ProductSortField.NAME,
            "sort_order": SortOrder.ASC,
            "page": 1,
            "per_page": 20,
        }
        assert type(kwargs["evaluation_date"]) is date
        assert type(kwargs["catalog_presence"][0]) is CatalogPresence
        assert type(kwargs["sort_by"]) is ProductSortField
        assert type(kwargs["sort_order"]) is SortOrder

    async def test_parsed_arguments_reach_the_service_and_are_serialized(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        projection = ProductListItemProjection(
            name="Example Server",
            version="15 SP7",
            display_name="ES 15 SP7",
            cpe="cpe:/o:example:es:15:sp7",
            catalog_presence=CatalogPresence.HISTORICAL,
            catalog_last_seen_at=_SNAPSHOT,
            first_customer_ship_date=date(2025, 6, 1),
            general_support_end_date=None,
            extended_support_end_date=None,
            reactive_support_end_date=None,
            lifecycle_phase=LifecyclePhase.REACTIVE_SUPPORT,
            cvss_threshold=Decimal("7.0"),
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        spy = _spy(
            monkeypatch,
            ProductPage(items=(projection,), total=15, page=3, per_page=7),
        )
        clock = Clock(datetime(2026, 9, 28, 1, 30, tzinfo=timezone(timedelta(hours=3))))
        monkeypatch.setattr(route, "_utc_now", clock.now)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(
                _PATH,
                params={
                    "search": "  Fictional%_\\  ",
                    "cpe": "cpe:/o:example:es:15:sp7",
                    "catalog_presence": [
                        "historical",
                        "bogus",
                        "current",
                        "historical",
                    ],
                    "lifecycle_phase": [
                        "unavailable",
                        "eol,general_support",
                        "general_support",
                        "unavailable",
                    ],
                    "page": 3,
                    "per_page": 7,
                    "sort_by": "cpe",
                    "sort_order": "desc",
                },
            )

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "name": "Example Server",
                    "version": "15 SP7",
                    "display_name": "ES 15 SP7",
                    "cpe": "cpe:/o:example:es:15:sp7",
                    "catalog_presence": "historical",
                    "catalog_last_seen_at": "2026-09-01T02:00:00Z",
                    "first_customer_ship_date": "2025-06-01",
                    "general_support_end_date": None,
                    "extended_support_end_date": None,
                    "reactive_support_end_date": None,
                    "lifecycle_phase": "reactive_support",
                    "cvss_threshold": 7.0,
                    "created_at": "2026-05-10T08:00:00Z",
                    "updated_at": "2026-06-11T09:30:15.250000Z",
                }
            ],
            "meta": {"total": 15, "page": 3, "per_page": 7},
        }
        assert '"cvss_threshold":7.0' in response.text
        assert recorder.statements == []
        assert clock.calls == 1
        spy.assert_awaited_once()
        assert spy.await_args is not None
        assert spy.await_args.args == (db_session,)
        assert spy.await_args.kwargs == {
            "evaluation_date": date(2026, 9, 27),
            "search": "  Fictional%_\\  ",
            "cpe": "cpe:/o:example:es:15:sp7",
            "catalog_presence": (CatalogPresence.HISTORICAL, CatalogPresence.CURRENT),
            "lifecycle_phase": (
                LifecyclePhaseFilter.UNAVAILABLE,
                LifecyclePhaseFilter.GENERAL_SUPPORT,
            ),
            "sort_by": ProductSortField.CPE,
            "sort_order": SortOrder.DESC,
            "page": 3,
            "per_page": 7,
        }

    async def test_only_invalid_filter_values_reach_the_service_as_empty_tuples(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(monkeypatch)

        response = await client.get(
            _PATH,
            params={
                "catalog_presence": ["bogus", "current,historical"],
                "lifecycle_phase": "Unavailable",
            },
        )

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE
        assert spy.await_args is not None
        assert spy.await_args.kwargs["catalog_presence"] == ()
        assert spy.await_args.kwargs["lifecycle_phase"] == ()


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


def _schemas() -> dict[str, Any]:
    schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
    return schemas


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


def _parameters() -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in _operation().get("parameters", [])}


def _branches(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """The schema itself plus its `anyOf`/`allOf` alternatives."""
    nested = [*schema.get("anyOf", []), *schema.get("allOf", [])]
    return [schema, *nested]


def _enum_values(schema: dict[str, Any]) -> set[str]:
    for branch in _branches(schema):
        if "$ref" in branch:
            return set(_schemas()[branch["$ref"].rsplit("/", 1)[1]]["enum"])
        if "enum" in branch:
            return set(branch["enum"])
    raise AssertionError(f"no enum in {schema}")


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_has_summary_description_and_tag(self) -> None:
        assert set(app.openapi()["paths"][_PATH]) == {"get"}
        operation = _operation()

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["Products"]

    def test_declares_exactly_the_specified_query_parameters(self) -> None:
        parameters = _parameters()

        assert set(parameters) == _QUERY_PARAMETERS
        assert all(p["in"] == "query" for p in parameters.values())
        assert not any(p.get("required", False) for p in parameters.values())
        for repeatable in ("catalog_presence", "lifecycle_phase"):
            assert parameters[repeatable]["schema"]["type"] == "array"
        assert _enum_values(parameters["sort_by"]["schema"]) == {
            field.value for field in ProductSortField
        }
        assert _enum_values(parameters["sort_by"]["schema"]) == {
            "name",
            "display_name",
            "version",
            "cpe",
            "catalog_last_seen_at",
            "created_at",
        }
        assert parameters["sort_by"]["schema"].get("default") == "name"
        assert _enum_values(parameters["sort_order"]["schema"]) == {"asc", "desc"}
        assert parameters["sort_order"]["schema"].get("default") == "asc"
        per_page = parameters["per_page"]["schema"]
        assert (per_page["minimum"], per_page["maximum"], per_page["default"]) == (
            1,
            100,
            20,
        )
        page = parameters["page"]["schema"]
        assert (page["minimum"], page["default"]) == (1, 1)

    def test_response_schema_exposes_exactly_the_specified_fields(self) -> None:
        schemas = _schemas()
        response = _operation()["responses"]["200"]["content"]["application/json"]

        assert response["schema"]["$ref"].endswith("/ProductListResponse")
        assert set(schemas["ProductListResponse"]["properties"]) == {"data", "meta"}
        assert schemas["ProductListResponse"]["properties"]["data"]["items"][
            "$ref"
        ].endswith("/ProductListItem")
        item = schemas["ProductListItem"]
        assert set(item["properties"]) == _ITEM_FIELDS
        assert set(item["required"]) == _ITEM_FIELDS
        assert "id" not in item["properties"]
        assert _enum_values(item["properties"]["catalog_presence"]) == {
            "current",
            "historical",
        }
        assert _enum_values(item["properties"]["lifecycle_phase"]) == {
            phase.value for phase in LifecyclePhase
        }
        assert {
            branch.get("type")
            for branch in _branches(item["properties"]["cvss_threshold"])
        } >= {"number", "null"}
