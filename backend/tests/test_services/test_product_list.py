"""Tests for `product_service.list_products()`.

Owning specifications: docs/features/packages/product-catalog.md (Product
Lifecycle Phases, Lifecycle Evaluator; SMELT Integration > Product Sync,
applied-snapshot identity `MAX(Product.catalog_last_seen_at)`; Catalog
Readiness and Freshness; API Endpoints > List Products, Product Query
Service, Test Requirements); docs/api-spec.md (Pagination; Filtering; Enum
Filter Validation; Sorting, Deterministic Pagination Ordering; Product
Identifier Resolution); docs/features/platform/testing-strategy.md
(Service Functions; Concurrency Testing; Parallel Execution).

Every `db_session` test starts from an empty Product table (per-test
rollback) and passes explicit `catalog_last_seen_at` values, so the
selected snapshot is exactly the one the test builds. The
independent-session races scope their lists by a unique token, place their
committed snapshots after every existing one, and delete their committed
rows explicitly.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from app.core.enums import (
    CatalogPresence,
    LifecyclePhase,
    LifecyclePhaseFilter,
    ProductSortField,
    SortOrder,
)
from app.models.product import Product
from app.services.product_lifecycle import evaluate_product_lifecycle_phase
from app.services.product_service import (
    MAX_PER_PAGE,
    ProductListItemProjection,
    ProductPage,
    list_products,
)
from tests.support.lifecycle_matrix import LIFECYCLE_CASES, LifecycleCase

ProductFactory = Callable[..., Awaitable[Product]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

CURRENT: Final = CatalogPresence.CURRENT
HISTORICAL: Final = CatalogPresence.HISTORICAL
BOTH: Final = (CURRENT, HISTORICAL)
UNAVAILABLE: Final = LifecyclePhaseFilter.UNAVAILABLE

EVALUATION_DATE: Final = date(2027, 1, 15)
SNAPSHOT: Final = datetime(2026, 9, 1, 2, 0, tzinfo=UTC)
"""The latest complete snapshot of the `db_session` tests."""
EARLIER: Final = datetime(2026, 8, 1, 2, 0, tzinfo=UTC)
"""An earlier snapshot: Products last seen here are historical."""
CREATED_AT: Final = datetime(2026, 5, 10, 8, 0, tzinfo=UTC)
UPDATED_AT: Final = datetime(2026, 6, 11, 9, 30, tzinfo=UTC)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")

# Lifecycle dates relative to EVALUATION_DATE.
PAST: Final = date(2020, 1, 31)
FUTURE: Final = date(2030, 1, 31)

_PROJECTION_FIELDS: Final = {
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


async def _list(db: AsyncSession, **overrides: Any) -> ProductPage:
    arguments: dict[str, Any] = {
        "evaluation_date": EVALUATION_DATE,
        "per_page": MAX_PER_PAGE,
        **overrides,
    }
    return await list_products(db, **arguments)


async def _cpes(db: AsyncSession, **overrides: Any) -> list[str]:
    """CPEs of one complete page; the total must equal the page."""
    result = await _list(db, **overrides)
    assert result.total == len(result.items)
    return [item.cpe for item in result.items]


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


# ---------------------------------------------------------------------------
# Snapshot identity and catalog presence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEmptyResults:
    @pytest.mark.parametrize(
        "overrides",
        [
            {},
            {"catalog_presence": BOTH},
            {"catalog_presence": (HISTORICAL,)},
            {"lifecycle_phase": (UNAVAILABLE,)},
            {"search": ""},
        ],
        ids=["default", "both", "historical", "unavailable", "empty-search"],
    )
    async def test_no_products_returns_an_empty_page(
        self, db_session: AsyncSession, overrides: dict[str, Any]
    ) -> None:
        """Before the first complete snapshot there is no snapshot identity:
        an empty successful page, never a readiness error."""
        assert await _list(db_session, page=3, per_page=7, **overrides) == ProductPage(
            items=(), total=0, page=3, per_page=7
        )

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        for _ in range(3):
            await product_factory(catalog_last_seen_at=SNAPSHOT)

        assert await _list(db_session, page=4, per_page=1) == ProductPage(
            items=(), total=3, page=4, per_page=1
        )
        assert await _list(db_session, page=2, per_page=3) == ProductPage(
            items=(), total=3, page=2, per_page=3
        )
        assert await _list(db_session, search="no-such-product") == ProductPage(
            items=(), total=0, page=1, per_page=MAX_PER_PAGE
        )


@pytest.fixture
async def presence_world(product_factory: ProductFactory) -> dict[str, Product]:
    """Two current Products of the latest snapshot and two retained
    historical Products last seen in earlier snapshots."""
    return {
        "current-a": await product_factory(
            cpe="cpe:/o:example:current-a", catalog_last_seen_at=SNAPSHOT
        ),
        "historical-a": await product_factory(
            cpe="cpe:/o:example:historical-a", catalog_last_seen_at=EARLIER
        ),
        "current-b": await product_factory(
            cpe="cpe:/o:example:current-b", catalog_last_seen_at=SNAPSHOT
        ),
        "historical-b": await product_factory(
            cpe="cpe:/o:example:historical-b",
            catalog_last_seen_at=EARLIER - timedelta(days=30),
        ),
    }


@pytest.mark.integration
class TestCatalogPresence:
    async def test_default_selects_only_the_current_snapshot(
        self, db_session: AsyncSession, presence_world: dict[str, Product]
    ) -> None:
        result = await list_products(db_session, evaluation_date=EVALUATION_DATE)

        assert [item.cpe for item in result.items] == [
            "cpe:/o:example:current-a",
            "cpe:/o:example:current-b",
        ]
        assert result.total == 2
        assert {item.catalog_presence for item in result.items} == {CURRENT}

    async def test_historical_selects_every_retained_product_not_in_the_snapshot(
        self, db_session: AsyncSession, presence_world: dict[str, Product]
    ) -> None:
        result = await _list(db_session, catalog_presence=(HISTORICAL,))

        assert [item.cpe for item in result.items] == [
            "cpe:/o:example:historical-a",
            "cpe:/o:example:historical-b",
        ]
        assert result.total == 2
        assert {item.catalog_presence for item in result.items} == {HISTORICAL}

    @pytest.mark.parametrize(
        "presence", [BOTH, (HISTORICAL, CURRENT)], ids=["current-first", "reversed"]
    )
    async def test_both_values_select_the_union(
        self,
        db_session: AsyncSession,
        presence_world: dict[str, Product],
        presence: tuple[CatalogPresence, ...],
    ) -> None:
        result = await _list(db_session, catalog_presence=presence)

        assert {item.cpe: item.catalog_presence for item in result.items} == {
            "cpe:/o:example:current-a": CURRENT,
            "cpe:/o:example:current-b": CURRENT,
            "cpe:/o:example:historical-a": HISTORICAL,
            "cpe:/o:example:historical-b": HISTORICAL,
        }
        assert result.total == 4

    async def test_empty_presence_tuple_matches_nothing(
        self, db_session: AsyncSession, presence_world: dict[str, Product]
    ) -> None:
        """Every supplied value was invalid: the API passes an empty tuple."""
        assert await _list(db_session, catalog_presence=()) == ProductPage(
            items=(), total=0, page=1, per_page=MAX_PER_PAGE
        )

    async def test_snapshot_is_the_maximum_last_seen_instant_only(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        """One microsecond older is already a different (historical)
        snapshot; a lone latest Product is the complete current snapshot."""
        latest = await product_factory(
            cpe="cpe:/o:example:latest", catalog_last_seen_at=SNAPSHOT
        )
        await product_factory(
            cpe="cpe:/o:example:older",
            catalog_last_seen_at=SNAPSHOT - timedelta(microseconds=1),
        )

        assert await _cpes(db_session) == [latest.cpe]
        assert await _cpes(db_session, catalog_presence=(HISTORICAL,)) == [
            "cpe:/o:example:older"
        ]


# ---------------------------------------------------------------------------
# Search and exact CPE
# ---------------------------------------------------------------------------


@pytest.fixture
async def search_world(product_factory: ProductFactory) -> None:
    """One Product per searched field, each carrying its token only in that
    field, plus literal-metacharacter pairs."""
    for overrides in (
        {"name": "Fictional Alpha Server", "cpe": "cpe:/o:example:by-name"},
        {"display_name": "Example Beta Desktop", "cpe": "cpe:/o:example:by-display"},
        {"version": "15 SP7 Gamma", "cpe": "cpe:/o:example:by-version"},
        {"cpe": "cpe:/o:example:Delta:15"},
        {"name": "Coverage 100% Edition", "cpe": "cpe:/o:example:percent"},
        {"name": "Coverage 1000 Edition", "cpe": "cpe:/o:example:no-percent"},
        {"name": "snake_case Product", "cpe": "cpe:/o:example:underscore"},
        {"name": "snakeXcase Product", "cpe": "cpe:/o:example:no-underscore"},
        {"name": "Back\\slash Product", "cpe": "cpe:/o:example:backslash"},
        {"name": "Backslash Product", "cpe": "cpe:/o:example:no-backslash"},
    ):
        await product_factory(catalog_last_seen_at=SNAPSHOT, **overrides)


@pytest.mark.integration
@pytest.mark.usefixtures("search_world")
class TestSearch:
    @pytest.mark.parametrize(
        ("search", "expected"),
        [
            ("alpha", "cpe:/o:example:by-name"),
            ("ALPHA SERVER", "cpe:/o:example:by-name"),
            ("bEtA dEsKtOp", "cpe:/o:example:by-display"),
            ("sp7 gamma", "cpe:/o:example:by-version"),
            ("delta:15", "cpe:/o:example:Delta:15"),
            ("DELTA", "cpe:/o:example:Delta:15"),
        ],
        ids=["name", "name-upper", "display-name", "version", "cpe", "cpe-upper"],
    )
    async def test_case_insensitive_substring_of_each_declared_field(
        self, db_session: AsyncSession, search: str, expected: str
    ) -> None:
        assert await _cpes(db_session, search=search) == [expected]

    @pytest.mark.parametrize(
        ("search", "expected"),
        [
            ("100%", ["cpe:/o:example:percent"]),
            ("%", ["cpe:/o:example:percent"]),
            ("e_c", ["cpe:/o:example:underscore"]),
            ("_", ["cpe:/o:example:underscore"]),
            ("k\\s", ["cpe:/o:example:backslash"]),
            ("\\", ["cpe:/o:example:backslash"]),
        ],
        ids=["percent", "percent-only", "underscore", "underscore-only", "bs", "bs1"],
    )
    async def test_pattern_metacharacters_match_literally(
        self, db_session: AsyncSession, search: str, expected: list[str]
    ) -> None:
        """Unescaped, `100%` would also match `1000`, `e_c` would match
        `eXc`, and `k\\s` would match `ks`."""
        assert await _cpes(db_session, search=search) == expected

    async def test_empty_search_matches_every_product(
        self, db_session: AsyncSession
    ) -> None:
        assert (await _list(db_session, search="")).total == 10
        assert (await _list(db_session)).total == 10

    async def test_cpe_is_an_exact_case_sensitive_match(
        self, db_session: AsyncSession
    ) -> None:
        assert await _cpes(db_session, cpe="cpe:/o:example:Delta:15") == [
            "cpe:/o:example:Delta:15"
        ]
        for near_miss in (
            "cpe:/o:example:delta:15",
            "cpe:/o:example:DELTA:15",
            "cpe:/o:example:Delta",
            "Delta:15",
            "cpe:/o:example:Delta:15 ",
            "cpe:/o:example:%",
            "cpe:/o:example:Delta:1_",
        ):
            assert await _cpes(db_session, cpe=near_miss) == [], near_miss


# ---------------------------------------------------------------------------
# Filter composition and lifecycle filtering
# ---------------------------------------------------------------------------


@pytest.fixture
async def composition_world(product_factory: ProductFactory) -> None:
    """Products whose presence, lifecycle phase on EVALUATION_DATE, and
    search token vary independently."""
    worlds: list[dict[str, Any]] = [
        {"cpe": "cpe:/o:example:a", "name": "Fictional A"},
        {
            "cpe": "cpe:/o:example:b",
            "name": "Fictional B",
            "general_support_end_date": PAST,
        },
        {"cpe": "cpe:/o:example:c", "name": "Fictional C", "historical": True},
        {"cpe": "cpe:/o:example:d", "name": "Other D"},
        {"cpe": "cpe:/o:example:e", "name": "Fictional E", "unavailable": True},
        {"cpe": "cpe:/o:example:f", "name": "Other F", "unavailable": True},
    ]
    for world in worlds:
        historical = world.pop("historical", False)
        unavailable = world.pop("unavailable", False)
        world.setdefault("general_support_end_date", None if unavailable else FUTURE)
        await product_factory(
            catalog_last_seen_at=EARLIER if historical else SNAPSHOT, **world
        )


GS: Final = LifecyclePhaseFilter.GENERAL_SUPPORT
EOL: Final = LifecyclePhaseFilter.EOL


@pytest.mark.integration
@pytest.mark.usefixtures("composition_world")
class TestFilterComposition:
    """`a`: current, general_support, token; `b`: current, eol, token;
    `c`: historical, general_support, token; `d`: current,
    general_support; `e`: current, unavailable, token; `f`: current,
    unavailable."""

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"search": "fictional"}, "abe"),
            ({"lifecycle_phase": (GS,)}, "ad"),
            ({"search": "fictional", "lifecycle_phase": (GS,)}, "a"),
            ({"search": "fictional", "lifecycle_phase": (GS, EOL)}, "ab"),
            (
                {
                    "search": "fictional",
                    "lifecycle_phase": (GS,),
                    "catalog_presence": BOTH,
                },
                "ac",
            ),
            ({"lifecycle_phase": (GS,), "catalog_presence": (HISTORICAL,)}, "c"),
            ({"cpe": "cpe:/o:example:a", "lifecycle_phase": (EOL,)}, ""),
            ({"cpe": "cpe:/o:example:a", "search": "other"}, ""),
            ({"cpe": "cpe:/o:example:c"}, ""),
            ({"cpe": "cpe:/o:example:c", "catalog_presence": BOTH}, "c"),
            (
                {
                    "cpe": "cpe:/o:example:a",
                    "search": "FICTIONAL A",
                    "lifecycle_phase": (GS, UNAVAILABLE),
                    "catalog_presence": (CURRENT,),
                },
                "a",
            ),
        ],
        ids=[
            "search",
            "phase",
            "search-and-phase",
            "or-within-phase",
            "or-within-presence",
            "phase-and-historical",
            "cpe-and-phase-mismatch",
            "cpe-and-search-mismatch",
            "cpe-of-historical-default-presence",
            "cpe-of-historical-both",
            "all-four",
        ],
    )
    async def test_distinct_filters_and_or_within_repeatable_filters(
        self, db_session: AsyncSession, overrides: dict[str, Any], expected: str
    ) -> None:
        assert await _cpes(db_session, **overrides) == [
            f"cpe:/o:example:{letter}" for letter in expected
        ]

    async def test_unavailable_alone_selects_null_phases_and_keeps_them_null(
        self, db_session: AsyncSession
    ) -> None:
        result = await _list(db_session, lifecycle_phase=(UNAVAILABLE,))

        assert [(item.cpe, item.lifecycle_phase) for item in result.items] == [
            ("cpe:/o:example:e", None),
            ("cpe:/o:example:f", None),
        ]
        assert result.total == 2

    async def test_unavailable_combined_with_a_real_phase(
        self, db_session: AsyncSession
    ) -> None:
        result = await _list(db_session, lifecycle_phase=(UNAVAILABLE, EOL))

        assert [(item.cpe, item.lifecycle_phase) for item in result.items] == [
            ("cpe:/o:example:b", LifecyclePhase.EOL),
            ("cpe:/o:example:e", None),
            ("cpe:/o:example:f", None),
        ]
        assert result.total == 3

    async def test_empty_lifecycle_tuple_matches_nothing_and_none_is_no_filter(
        self, db_session: AsyncSession
    ) -> None:
        assert await _list(db_session, lifecycle_phase=()) == ProductPage(
            items=(), total=0, page=1, per_page=MAX_PER_PAGE
        )
        assert (await _list(db_session, lifecycle_phase=None)).total == 5
        assert (
            await _list(db_session, lifecycle_phase=tuple(LifecyclePhaseFilter))
        ).total == 5


@pytest.mark.integration
class TestLifecycleParity:
    """The projected phase and the lifecycle filter equal the pure
    evaluator on the supplied `evaluation_date` for every curated case,
    including incomplete, inconsistent, and boundary-date sets."""

    @pytest.mark.parametrize("case", LIFECYCLE_CASES, ids=lambda case: case.id)
    async def test_projection_and_filter_match_the_pure_evaluator(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        case: LifecycleCase,
    ) -> None:
        inputs = case.inputs
        product = await product_factory(
            catalog_last_seen_at=SNAPSHOT,
            first_customer_ship_date=inputs.first_customer_ship_date,
            general_support_end_date=inputs.general_support_end_date,
            extended_support_end_date=inputs.extended_support_end_date,
            reactive_support_end_date=inputs.reactive_support_end_date,
        )
        await product_factory(catalog_last_seen_at=SNAPSHOT)
        on_date = {"evaluation_date": inputs.evaluation_date, "cpe": product.cpe}
        pure = evaluate_product_lifecycle_phase(**case.evaluator_kwargs())
        selecting = (
            UNAVAILABLE
            if case.expected is None
            else LifecyclePhaseFilter(case.expected)
        )
        others = tuple(
            value for value in LifecyclePhaseFilter if value is not selecting
        )

        (item,) = (await _list(db_session, **on_date)).items
        selected = await _cpes(db_session, lifecycle_phase=(selecting,), **on_date)
        excluded = await _cpes(db_session, lifecycle_phase=others, **on_date)

        assert item.lifecycle_phase == case.expected == pure
        assert selected == [product.cpe]
        assert excluded == []


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProjection:
    async def test_every_public_field_is_projected_and_id_is_absent(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        await product_factory(
            name="Example Linux Enterprise Server",
            version="15 SP6",
            display_name="ELES 15 SP6",
            cpe="cpe:/o:example:eles:15:sp6",
            catalog_last_seen_at=SNAPSHOT,
            first_customer_ship_date=date(2024, 10, 1),
            general_support_end_date=date(2026, 10, 31),
            extended_support_end_date=date(2029, 10, 31),
            reactive_support_end_date=date(2031, 10, 31),
            cvss_threshold=Decimal("7.5"),
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )
        await product_factory(
            name="Example Retired Product",
            version="12",
            display_name="ERP 12",
            cpe="cpe:/o:example:erp:12",
            catalog_last_seen_at=EARLIER,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )

        first, second = (await _list(db_session, catalog_presence=BOTH)).items

        assert first == ProductListItemProjection(
            name="Example Linux Enterprise Server",
            version="15 SP6",
            display_name="ELES 15 SP6",
            cpe="cpe:/o:example:eles:15:sp6",
            catalog_presence=CURRENT,
            catalog_last_seen_at=SNAPSHOT,
            first_customer_ship_date=date(2024, 10, 1),
            general_support_end_date=date(2026, 10, 31),
            extended_support_end_date=date(2029, 10, 31),
            reactive_support_end_date=date(2031, 10, 31),
            lifecycle_phase=LifecyclePhase.EXTENDED_SUPPORT,
            cvss_threshold=Decimal("7.5"),
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )
        assert second == ProductListItemProjection(
            name="Example Retired Product",
            version="12",
            display_name="ERP 12",
            cpe="cpe:/o:example:erp:12",
            catalog_presence=HISTORICAL,
            catalog_last_seen_at=EARLIER,
            first_customer_ship_date=None,
            general_support_end_date=None,
            extended_support_end_date=None,
            reactive_support_end_date=None,
            lifecycle_phase=None,
            cvss_threshold=None,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )
        assert type(first.catalog_presence) is CatalogPresence
        assert type(first.lifecycle_phase) is LifecyclePhase
        assert first.catalog_last_seen_at.utcoffset() == timedelta(0)
        for item in (first, second):
            assert {f.name for f in dataclasses.fields(item)} == _PROJECTION_FIELDS
            assert not hasattr(item, "id")
            for field in dataclasses.fields(item):
                assert not isinstance(getattr(item, field.name), uuid.UUID)

    async def test_server_default_timestamps_are_projected(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        product = await product_factory(catalog_last_seen_at=SNAPSHOT)
        stamps = (
            await db_session.execute(
                select(Product.created_at, Product.updated_at).where(
                    Product.id == product.id
                )
            )
        ).one()

        (item,) = (await _list(db_session)).items

        assert (item.created_at, item.updated_at) == tuple(stamps)


# ---------------------------------------------------------------------------
# Sorting and deterministic pagination
# ---------------------------------------------------------------------------

_STRING_VALUES: Final = ("beta", "Zeta", "Éclair", "alpha")
"""Code-point order is `Zeta` < `alpha` < `beta` < `Éclair`; a linguistic
collation would put `Zeta` last and `Éclair` before `Zeta`."""
_INSTANT_OFFSETS: Final = (2, 0, 3, 1)
_ASCENDING: Final = (1, 3, 0, 2)
"""Insertion indexes in ascending order of both value sequences above;
neither the insertion (and `Product.id`) order nor its reverse."""


def _sort_values(sort_by: ProductSortField, index: int) -> dict[str, Any]:
    """The overrides giving Product `index` its primary sort value."""
    value = _STRING_VALUES[index]
    instant = SNAPSHOT + timedelta(hours=_INSTANT_OFFSETS[index])
    by_field: dict[ProductSortField, dict[str, Any]] = {
        ProductSortField.NAME: {"name": value},
        ProductSortField.DISPLAY_NAME: {"display_name": value},
        ProductSortField.VERSION: {"version": value},
        ProductSortField.CPE: {"cpe": f"cpe:/o:example:{value}"},
        ProductSortField.CATALOG_LAST_SEEN_AT: {"catalog_last_seen_at": instant},
        ProductSortField.CREATED_AT: {"created_at": instant},
    }
    return {"catalog_last_seen_at": SNAPSHOT, **by_field[sort_by]}


_TIED: Final[dict[ProductSortField, dict[str, Any]]] = {
    ProductSortField.NAME: {"name": "Example Tie"},
    ProductSortField.DISPLAY_NAME: {"display_name": "Example Tie"},
    ProductSortField.VERSION: {"version": "15"},
    ProductSortField.CATALOG_LAST_SEEN_AT: {},
    ProductSortField.CREATED_AT: {"created_at": CREATED_AT},
}
"""`cpe` is unique and cannot tie."""


@pytest.mark.integration
class TestSorting:
    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize("sort_by", list(ProductSortField))
    async def test_every_sort_field_in_both_directions(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        sort_by: ProductSortField,
        sort_order: SortOrder,
    ) -> None:
        products = [
            await product_factory(**_sort_values(sort_by, index)) for index in range(4)
        ]
        ascending = [products[index].cpe for index in _ASCENDING]

        result = await _list(
            db_session, sort_by=sort_by, sort_order=sort_order, catalog_presence=BOTH
        )

        assert [item.cpe for item in result.items] == (
            ascending if sort_order is SortOrder.ASC else ascending[::-1]
        )
        assert result.total == 4

    async def test_default_order_is_name_ascending(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        products = [
            await product_factory(**_sort_values(ProductSortField.NAME, index))
            for index in range(4)
        ]

        result = await list_products(db_session, evaluation_date=EVALUATION_DATE)

        assert [item.cpe for item in result.items] == [
            products[index].cpe for index in _ASCENDING
        ]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize("sort_by", list(_TIED))
    async def test_ties_are_broken_by_internal_id_in_the_same_direction(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        sort_by: ProductSortField,
        sort_order: SortOrder,
    ) -> None:
        """Five tied Products are inserted against their id order, with
        every other field ascending in insertion order, so neither
        insertion order nor another column could produce the expected
        pages. Paging two at a time neither repeats nor skips."""
        ids = sorted(uuid.uuid7() for _ in range(5))
        by_id = {
            pk: await product_factory(
                **{
                    "id": pk,
                    "name": f"Example Tied {n}",
                    "display_name": f"Example Tied {n}",
                    "version": f"{n}",
                    "cpe": f"cpe:/o:example:tied:{n}",
                    "catalog_last_seen_at": SNAPSHOT,
                    "created_at": CREATED_AT + timedelta(minutes=n),
                    **_TIED[sort_by],
                }
            )
            for n, pk in enumerate(reversed(ids))
        }
        descending = sort_order is SortOrder.DESC
        expected = [by_id[pk].cpe for pk in sorted(ids, reverse=descending)]

        pages = [
            await _list(
                db_session, sort_by=sort_by, sort_order=sort_order, page=n, per_page=2
            )
            for n in range(1, 5)
        ]

        paged = [item.cpe for page in pages for item in page.items]
        assert [len(page.items) for page in pages] == [2, 2, 1, 0]
        assert paged == expected
        assert len(set(paged)) == 5
        assert {page.total for page in pages} == {5}


# ---------------------------------------------------------------------------
# Read-only, one statement, guards
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReadOnlyStatement:
    async def test_one_read_only_statement_without_lock_or_write(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        for index in range(6):
            await product_factory(
                catalog_last_seen_at=SNAPSHOT if index % 2 else EARLIER,
                general_support_end_date=PAST if index % 3 else None,
            )
        before = (
            await db_session.execute(
                select(func.count(), func.max(Product.updated_at)).select_from(Product)
            )
        ).one()

        counts = []
        for overrides in (
            {},
            {"per_page": 1, "page": 2},
            {
                "search": "example",
                "lifecycle_phase": (UNAVAILABLE, LifecyclePhaseFilter.EOL),
                "catalog_presence": BOTH,
                "sort_by": ProductSortField.CREATED_AT,
                "sort_order": SortOrder.DESC,
            },
        ):
            with _StatementRecorder(db_session) as recorder:
                await _list(db_session, **overrides)
            counts.append(len(recorder.statements))
            (statement,) = recorder.statements
            assert statement.lstrip().upper().startswith(("SELECT", "WITH"))
            for row_lock in ROW_LOCKS:
                assert row_lock not in statement.upper()

        assert counts == [1, 1, 1]
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()
        after = (
            await db_session.execute(
                select(func.count(), func.max(Product.updated_at)).select_from(Product)
            )
        ).one()
        assert tuple(after) == tuple(before)

    async def test_re_invocation_returns_the_same_page(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        for _ in range(3):
            await product_factory(catalog_last_seen_at=SNAPSHOT)

        assert await _list(db_session, per_page=2) == await _list(
            db_session, per_page=2
        )


@pytest.mark.unit
class TestGuardsAndPropagation:
    @pytest.mark.parametrize(
        ("page", "per_page"), [(0, 20), (-1, 20), (1, 0), (1, -1), (1, 101)]
    )
    async def test_out_of_range_pagination_raises_before_any_statement(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await list_products(
                db, evaluation_date=EVALUATION_DATE, page=page, per_page=per_page
            )

        db.execute.assert_not_awaited()

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await list_products(db, evaluation_date=EVALUATION_DATE)

        assert excinfo.value is failure


@pytest.mark.integration
class TestPaginationBoundaries:
    async def test_boundary_page_sizes_are_accepted(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        products = [
            await product_factory(catalog_last_seen_at=SNAPSHOT) for _ in range(101)
        ]

        smallest = await list_products(
            db_session, evaluation_date=EVALUATION_DATE, page=101, per_page=1
        )
        largest = await list_products(
            db_session, evaluation_date=EVALUATION_DATE, per_page=100
        )

        assert MAX_PER_PAGE == 100
        assert (smallest.total, smallest.page, smallest.per_page) == (101, 101, 1)
        assert len(smallest.items) == 1
        assert (largest.total, largest.page, largest.per_page) == (101, 1, 100)
        assert len(largest.items) == 100
        assert {item.cpe for item in largest.items} | {
            item.cpe for item in smallest.items
        } == {product.cpe for product in products}


# ---------------------------------------------------------------------------
# Independent-session races (one coherent snapshot observation)
# ---------------------------------------------------------------------------

_RACE_FLOOR: Final = datetime(2099, 1, 1, tzinfo=UTC)


class _CommittedCatalog:
    """Commits token-scoped Products through an independent session and
    deletes them at teardown (testing-strategy.md, Concurrency Testing:
    committed data is not rolled back by the fixture).

    The selected snapshot is the global `MAX(Product.catalog_last_seen_at)`
    of the worker database, so every instant is placed after any existing
    Product (and after 2099-01-01) to make this test's publications the
    latest ones."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.token = f"fictional-catalog-{uuid.uuid4().hex[:12]}"
        self.product_ids: list[uuid.UUID] = []
        self.base = _RACE_FLOOR

    async def start(self) -> None:
        latest = (
            await self.session.execute(select(func.max(Product.catalog_last_seen_at)))
        ).scalar_one()
        await self.session.rollback()
        if latest is not None and latest >= self.base:
            self.base = latest + timedelta(days=1)

    def at(self, hours: int) -> datetime:
        return self.base + timedelta(hours=hours)

    def cpe(self, label: str) -> str:
        return f"cpe:/o:example:{self.token}:{label}"

    def new_product(self, label: str, seen_at: datetime) -> Executable:
        """An insert of a token-scoped Product, registered for cleanup."""
        pk = uuid.uuid7()
        self.product_ids.append(pk)
        return insert(Product).values(
            id=pk,
            name=f"{self.token} {label}",
            version="1",
            display_name=f"Example {label}",
            cpe=self.cpe(label),
            catalog_last_seen_at=seen_at,
        )

    def seen(self, label: str, seen_at: datetime) -> Executable:
        return (
            update(Product)
            .where(Product.cpe == self.cpe(label))
            .values(catalog_last_seen_at=seen_at)
        )

    async def cleanup(self) -> None:
        await self.session.rollback()
        await self.session.execute(
            delete(Product).where(Product.id.in_(self.product_ids))
        )
        await self.session.commit()


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@pytest.fixture
async def committed_catalog(
    db_session_factory: SessionFactory,
) -> AsyncIterator[_CommittedCatalog]:
    catalog = _CommittedCatalog(await db_session_factory())
    try:
        await catalog.start()
        yield catalog
    finally:
        await catalog.cleanup()


Observation = tuple[dict[str, tuple[CatalogPresence, datetime]], int]


@dataclasses.dataclass(frozen=True)
class _Race:
    """The committed catalog, a reader session R, a writer session W, and
    the factory for a fresh session observing the committed state."""

    catalog: _CommittedCatalog
    reader: AsyncSession
    writer: AsyncSession
    sessions: SessionFactory

    async def observe(
        self, presence: tuple[CatalogPresence, ...], *, fresh: bool = False
    ) -> Observation:
        """The token-scoped list of R (or of a fresh session): each label's
        presence and last-seen instant, and the total."""
        db = await self.sessions() if fresh else self.reader
        result = await _list(db, search=self.catalog.token, catalog_presence=presence)
        return (
            {
                item.cpe.rsplit(":", 1)[1]: (
                    item.catalog_presence,
                    item.catalog_last_seen_at,
                )
                for item in result.items
            },
            result.total,
        )

    async def publish_first_snapshot(self) -> None:
        """S1: `a` and `b` current at T1; `h` retained from T0."""
        catalog = self.catalog
        await _commit(
            catalog.session,
            catalog.new_product("h", catalog.at(0)),
            catalog.new_product("a", catalog.at(1)),
            catalog.new_product("b", catalog.at(1)),
        )

    def second_snapshot(self) -> tuple[Executable, ...]:
        """S2 at T2: re-observes `a`, adds `n`, and no longer observes
        `b`, which becomes historical."""
        catalog = self.catalog
        return (
            catalog.seen("a", catalog.at(2)),
            catalog.new_product("n", catalog.at(2)),
        )

    def expected_first(self, presence: tuple[CatalogPresence, ...]) -> Observation:
        at = self.catalog.at
        rows = {
            "h": (HISTORICAL, at(0)),
            "a": (CURRENT, at(1)),
            "b": (CURRENT, at(1)),
        }
        selected = {k: v for k, v in rows.items() if v[0] in presence}
        return selected, len(selected)

    def expected_second(self, presence: tuple[CatalogPresence, ...]) -> Observation:
        at = self.catalog.at
        rows = {
            "h": (HISTORICAL, at(0)),
            "b": (HISTORICAL, at(1)),
            "a": (CURRENT, at(2)),
            "n": (CURRENT, at(2)),
        }
        selected = {k: v for k, v in rows.items() if v[0] in presence}
        return selected, len(selected)


@pytest.fixture
async def race(
    committed_catalog: _CommittedCatalog, db_session_factory: SessionFactory
) -> _Race:
    return _Race(
        committed_catalog,
        await db_session_factory(),
        await db_session_factory(),
        db_session_factory,
    )


def _commit_after_first_statement(
    monkeypatch: pytest.MonkeyPatch,
    reader: AsyncSession,
    change: Callable[[], Awaitable[None]],
) -> list[int]:
    """Commit `change` from another session right after the reader's first
    statement returns; returns a one-element call counter. A list split
    into several statements (snapshot, rows, count) would observe the
    change in a later one."""
    original = reader.execute
    calls = [0]

    async def _execute(*args: Any, **kwargs: Any) -> Any:
        result = await original(*args, **kwargs)
        calls[0] += 1
        if calls[0] == 1:
            await change()
        return result

    monkeypatch.setattr(reader, "execute", _execute)
    return calls


_PRESENCES: Final = [(CURRENT,), (HISTORICAL,), BOTH]
_PRESENCE_IDS: Final = ["current", "historical", "both"]


@pytest.mark.integration
class TestSnapshotRaces:
    """A complete SMELT publication (S2) committed by session W while
    session R lists: R's one-statement list describes S1 entirely (rows,
    `catalog_presence`, and total), and a later list describes S2
    entirely."""

    @pytest.mark.parametrize("presence", _PRESENCES, ids=_PRESENCE_IDS)
    async def test_publication_between_lists_is_observed_whole(
        self, race: _Race, presence: tuple[CatalogPresence, ...]
    ) -> None:
        await race.publish_first_snapshot()

        assert await race.observe(presence) == race.expected_first(presence)
        await _commit(race.writer, *race.second_snapshot())

        assert await race.observe(presence) == race.expected_second(presence)

    @pytest.mark.parametrize("presence", _PRESENCES, ids=_PRESENCE_IDS)
    async def test_publication_after_the_first_statement_is_not_mixed_in(
        self,
        race: _Race,
        monkeypatch: pytest.MonkeyPatch,
        presence: tuple[CatalogPresence, ...],
    ) -> None:
        await race.publish_first_snapshot()
        publication = race.second_snapshot()

        async def change() -> None:
            await _commit(race.writer, *publication)

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        observed = await race.observe(presence)

        assert calls == [1]
        assert observed == race.expected_first(presence)
        assert await race.observe(presence, fresh=True) == race.expected_second(
            presence
        )
