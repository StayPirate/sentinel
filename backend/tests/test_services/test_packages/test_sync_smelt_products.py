"""Tests for the `sync_smelt_products` fetcher.

Contract under test: docs/features/packages/product-catalog.md (SMELT
Integration > Product Sync, steps 1-5 and 7, retained rows, and failure
behavior; Catalog Readiness and Freshness; Fetcher: `sync_smelt_products`,
properties, Error Handling, and Metrics), docs/features/platform/
fetcher-infrastructure.md (BaseFetcher Base Class: execution-session
transaction contract, Finalization, Outcome and effect accounting; Error
Message Sanitization; Naming Convention; Registry), docs/features/platform/
testing-strategy.md (Mandatory Test Scenarios, Fetcher Outcome and Effect
Accounting), and docs/features/tickets/ticket-audit-log.md (Canonical
Mutation and No-Event Matrix row "Product catalog source mutation or
workflow-only dispatch/checkpoint outcome"; Testing Requirement 12).
Product Sync steps 6 and 8 (newly-current retention and the post-commit
backfill enqueue) are deferred and not covered here.

`validate_snapshot()` and the fetcher properties are unit tests. Publication
tests call `execute(db_session)`: its commit releases a savepoint of the
per-test outer transaction, so every row is rolled back at teardown. The
two `run()` lifecycle tests commit through `real_session_factory` and
delete every row they create. SMELT is the fake server of
`tests/support/smelt.py`, injected as the fetcher's HTTP client; the
snapshot clock is the `_utc_now` seam.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import String, delete, event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.config import settings
from app.core.enums import CatalogPresence
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.packages import smelt_product_listing
from app.services.packages import sync_smelt_products as sync_module
from app.services.packages.smelt_product_listing import (
    InvalidProductListingError,
    SmeltProductListing,
)
from app.services.packages.sync_smelt_products import (
    CatalogProduct,
    SnapshotValidationError,
    SyncSmeltProducts,
    validate_snapshot,
)
from app.services.product_service import list_products
from tests.support.smelt import (
    SMELT_TEST_API_URL,
    SmeltServer,
    make_rows,
    product_row,
)

VALIDATION_FAILED: Final = "SMELT Product catalog validation failed"
PUBLICATION_FAILED: Final = "Failed to publish SMELT Product catalog"
INVALID_RESPONSE: Final = "SMELT returned invalid Product catalog response"

T0: Final = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
T1: Final = datetime(2026, 9, 2, 1, 0, tzinfo=UTC)
T2: Final = datetime(2026, 9, 3, 1, 0, tzinfo=UTC)
T3: Final = datetime(2026, 9, 4, 1, 0, tzinfo=UTC)
MICROSECOND: Final = timedelta(microseconds=1)
EVALUATION_DATE: Final = date(2026, 9, 15)
MARKER: Final = "Example-Confidential-Source-Value"

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""


def _max_length(column: Any) -> int:
    column_type = column.type
    assert isinstance(column_type, String)
    assert column_type.length is not None
    return column_type.length


FIELD_LIMITS: Final = {
    "name": _max_length(Product.__table__.c.name),
    "version": _max_length(Product.__table__.c.version),
    "cpe": _max_length(Product.__table__.c.cpe),
    "friendly_name": _max_length(Product.__table__.c.display_name),
}
REPO_LIMIT: Final = _max_length(ProductRepository.__table__.c.repo_name)
FIELDS: Final = tuple(FIELD_LIMITS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _listing(*rows: dict[str, Any]) -> SmeltProductListing:
    return SmeltProductListing(count=len(rows), results=list(rows))


def _expected(row: dict[str, Any]) -> CatalogProduct:
    return CatalogProduct(
        cpe=row["cpe"],
        name=row["name"],
        version=row["version"],
        display_name=row["friendly_name"],
        repos=tuple(row["repos"]),
    )


def _rejected(listing: SmeltProductListing) -> SnapshotValidationError:
    with pytest.raises(SnapshotValidationError) as raised:
        validate_snapshot(listing)
    return raised.value


def _metrics(fetcher: SyncSmeltProducts) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


class Clock:
    """The controlled snapshot clock patched into `_utc_now`."""

    def __init__(self) -> None:
        self.now = T1

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    controlled = Clock()
    monkeypatch.setattr(sync_module, "_utc_now", controlled)
    return controlled


@pytest.fixture(autouse=True)
def _fictional_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the fetcher at the fictional SMELT origin."""
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


def _fetcher(server: SmeltServer) -> SyncSmeltProducts:
    fetcher = SyncSmeltProducts()
    fetcher._http_client = server.client()
    return fetcher


async def _execute(db: AsyncSession, server: SmeltServer) -> SyncSmeltProducts:
    fetcher = _fetcher(server)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _publish(db: AsyncSession, rows: list[dict[str, Any]]) -> Metrics:
    """Run one complete synchronization of `rows` and return its metrics."""
    return _metrics(await _execute(db, SmeltServer.for_rows(rows)))


async def _execute_failing(
    db: AsyncSession, server: SmeltServer
) -> tuple[FetcherError, SyncSmeltProducts]:
    fetcher = _fetcher(server)
    try:
        with pytest.raises(FetcherError) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


ProductState = dict[str, tuple[str, str, str, datetime]]
AssociationState = dict[tuple[str, str], datetime]


async def _products(db: AsyncSession) -> ProductState:
    """Every persisted Product: CPE -> (name, version, display, last seen)."""
    rows = await db.execute(
        select(
            Product.cpe,
            Product.name,
            Product.version,
            Product.display_name,
            Product.catalog_last_seen_at,
        )
    )
    return {
        row.cpe: (row.name, row.version, row.display_name, row.catalog_last_seen_at)
        for row in rows
    }


async def _associations(db: AsyncSession) -> AssociationState:
    """Every persisted association: (CPE, repository) -> last seen."""
    rows = await db.execute(
        select(
            Product.cpe,
            ProductRepository.repo_name,
            ProductRepository.catalog_last_seen_at,
        ).join(Product, Product.id == ProductRepository.product_id)
    )
    return {(row.cpe, row.repo_name): row.catalog_last_seen_at for row in rows}


async def _applied_snapshot(db: AsyncSession) -> datetime | None:
    return (
        await db.execute(select(func.max(Product.catalog_last_seen_at)))
    ).scalar_one()


# ---------------------------------------------------------------------------
# Complete-snapshot validation (Product Sync step 2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSnapshotValidation:
    def test_valid_snapshot_returns_every_product_in_order(self) -> None:
        rows = make_rows(3)

        assert validate_snapshot(_listing(*rows)) == [_expected(row) for row in rows]

    def test_zero_count_is_rejected(self) -> None:
        error = _rejected(SmeltProductListing(count=0, results=[]))

        assert str(error) == "count must be greater than zero"

    @pytest.mark.parametrize("field", FIELDS)
    def test_missing_required_field_is_rejected(self, field: str) -> None:
        row = product_row(2)
        del row[field]

        _rejected(_listing(product_row(1), row))

    @pytest.mark.parametrize("field", FIELDS)
    @pytest.mark.parametrize(
        "value",
        ["", 7, None, ["text"], True],
        ids=["empty", "int", "null", "list", "bool"],
    )
    def test_empty_or_non_string_required_field_is_rejected(
        self, field: str, value: Any
    ) -> None:
        _rejected(_listing(product_row(1, **{field: value})))

    @pytest.mark.parametrize("field", FIELDS)
    def test_required_field_at_column_length_is_accepted(self, field: str) -> None:
        value = "x" * FIELD_LIMITS[field]
        row = product_row(1, **{field: value})

        (product,) = validate_snapshot(_listing(row))

        assert _expected(row) == product

    @pytest.mark.parametrize("field", FIELDS)
    def test_required_field_over_column_length_is_rejected(self, field: str) -> None:
        value = "x" * (FIELD_LIMITS[field] + 1)

        _rejected(_listing(product_row(1, **{field: value})))

    @pytest.mark.parametrize(
        "repos",
        [None, [], "EXAMPLE:Updates:ProductA:1:x86_64", {"repo": "x"}],
        ids=["null", "empty", "string", "object"],
    )
    def test_missing_empty_or_non_array_repos_is_rejected(self, repos: Any) -> None:
        _rejected(_listing(product_row(1, repos=repos)))

    def test_absent_repos_is_rejected(self) -> None:
        row = product_row(1)
        del row["repos"]

        _rejected(_listing(row))

    @pytest.mark.parametrize(
        "element", ["", 3, None, ["nested"]], ids=["empty", "int", "null", "list"]
    )
    def test_empty_or_non_string_repository_is_rejected(self, element: Any) -> None:
        row = product_row(1, repos=["EXAMPLE:Updates:ProductA:1:x86_64", element])

        _rejected(_listing(row))

    def test_repository_at_column_length_is_accepted(self) -> None:
        row = product_row(1, repos=["r" * REPO_LIMIT])

        assert validate_snapshot(_listing(row)) == [_expected(row)]

    def test_repository_over_column_length_is_rejected(self) -> None:
        _rejected(_listing(product_row(1, repos=["r" * (REPO_LIMIT + 1)])))

    def test_duplicate_cpe_is_rejected(self) -> None:
        duplicate = product_row(2, cpe=product_row(1)["cpe"])

        error = _rejected(_listing(product_row(1), duplicate))

        assert str(error) == "row 1: duplicate cpe"

    def test_repeated_repository_within_one_product_is_rejected(self) -> None:
        repo = "EXAMPLE:Updates:ProductA:1:x86_64"

        error = _rejected(_listing(product_row(1, repos=[repo, repo])))

        assert str(error) == "row 0: repeated repository"

    def test_duplicate_cpe_repository_association_is_rejected(self) -> None:
        """The same `(CPE, repository)` association on two rows is a
        duplicate CPE row."""
        row = product_row(1)

        _rejected(_listing(row, product_row(2, cpe=row["cpe"], repos=row["repos"])))

    def test_repository_shared_by_different_products_is_accepted(self) -> None:
        shared = "EXAMPLE:Updates:Shared:1:x86_64"
        rows = [product_row(1, repos=[shared]), product_row(2, repos=[shared, "b"])]

        assert validate_snapshot(_listing(*rows)) == [_expected(row) for row in rows]

    def test_values_are_preserved_without_trimming_or_case_normalization(
        self,
    ) -> None:
        rows = [
            product_row(
                1,
                name="  Example Mixed Name ",
                version=" 15-SP7 ",
                cpe="CPE:/o:Example:Product-A:1 ",
                friendly_name="\tExample Friendly\t",
                repos=[
                    " EXAMPLE:Updates:ProductA:1:x86_64",
                    "example:updates:producta:1:x86_64",
                ],
            ),
            product_row(2, cpe="cpe:/o:example:product-a:1"),
        ]

        products = validate_snapshot(_listing(*rows))

        assert products == [_expected(row) for row in rows]
        assert products[0].repos == (
            " EXAMPLE:Updates:ProductA:1:x86_64",
            "example:updates:producta:1:x86_64",
        )

    def test_ignored_and_unknown_fields_do_not_affect_validation(self) -> None:
        base = product_row(1)
        noisy = {
            **base,
            "id": "not-an-integer",
            "end_of_life": "2020-01-31",
            "changed": None,
            "details": "malformed",
            "unknown_field": {"nested": [1, None, {"value": MARKER}]},
        }
        minimal = {
            key: base[key]
            for key in ("name", "version", "cpe", "friendly_name", "repos")
        }

        assert validate_snapshot(_listing(noisy)) == [_expected(base)]
        assert validate_snapshot(_listing(minimal)) == [_expected(base)]

    def test_any_invalid_row_rejects_the_complete_snapshot(self) -> None:
        rows = [*make_rows(5), product_row(6, name=""), *make_rows(3, start=7)]

        error = _rejected(_listing(*rows))

        assert str(error).startswith("row 5: ")

    @pytest.mark.parametrize(
        "row",
        [
            product_row(1, name=MARKER * 10),
            product_row(1, cpe=MARKER * 20),
            product_row(1, repos=[MARKER, MARKER]),
            product_row(1, repos=[MARKER * 20]),
            product_row(1, name="", friendly_name=MARKER),
            product_row(1, version=[MARKER]),
        ],
        ids=["long-name", "long-cpe", "repeated-repo", "long-repo", "empty", "list"],
    )
    def test_validation_error_message_contains_no_source_value(
        self, row: dict[str, Any]
    ) -> None:
        error = _rejected(_listing(row))

        assert MARKER not in str(error)

    def test_duplicate_cpe_message_contains_no_source_value(self) -> None:
        rows = [product_row(1, cpe=MARKER), product_row(2, cpe=MARKER)]

        assert MARKER not in str(_rejected(_listing(*rows)))


# ---------------------------------------------------------------------------
# Publication and metrics (steps 3-5 and 7; Metrics)
# ---------------------------------------------------------------------------


def _repos(product: str, *suffixes: str) -> list[str]:
    return [f"EXAMPLE:Updates:{product}:1:{suffix}" for suffix in suffixes]


def _first_snapshot() -> list[dict[str, Any]]:
    """A: unchanged; B: descriptive change; C: repository-set change;
    D: repository order only; E: descriptive and repository change; F: dropped.
    """
    return [
        product_row(1, cpe="cpe:/o:example:a:1", repos=_repos("A", "x86_64", "s390x")),
        product_row(2, cpe="cpe:/o:example:b:1", repos=_repos("B", "x86_64")),
        product_row(3, cpe="cpe:/o:example:c:1", repos=_repos("C", "c1", "c2")),
        product_row(4, cpe="cpe:/o:example:d:1", repos=_repos("D", "d1", "d2")),
        product_row(5, cpe="cpe:/o:example:e:1", repos=_repos("E", "e1")),
        product_row(6, cpe="cpe:/o:example:f:1", repos=_repos("F", "f1", "f2")),
    ]


def _second_snapshot() -> list[dict[str, Any]]:
    """The first snapshot changed as documented there, F dropped, G new."""
    return [
        product_row(1, cpe="cpe:/o:example:a:1", repos=_repos("A", "x86_64", "s390x")),
        product_row(
            2,
            cpe="cpe:/o:example:b:1",
            name="Example-Product-B-Renamed",
            version="2",
            friendly_name="Example Product B Renamed",
            repos=_repos("B", "x86_64"),
        ),
        product_row(3, cpe="cpe:/o:example:c:1", repos=_repos("C", "c2", "c3")),
        product_row(4, cpe="cpe:/o:example:d:1", repos=_repos("D", "d2", "d1")),
        product_row(
            5,
            cpe="cpe:/o:example:e:1",
            friendly_name="Example Product E Renamed",
            repos=_repos("E", "e1", "e2"),
        ),
        product_row(7, cpe="cpe:/o:example:g:1", repos=_repos("G", "g1")),
    ]


@pytest.mark.integration
class TestPublication:
    async def test_first_snapshot_creates_products_and_associations(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        rows = _first_snapshot()

        metrics = await _publish(db_session, rows)

        assert metrics == (6, 6, 0, 0)
        assert await _products(db_session) == {
            row["cpe"]: (row["name"], row["version"], row["friendly_name"], T1)
            for row in rows
        }
        assert await _associations(db_session) == {
            (row["cpe"], repo): T1 for row in rows for repo in row["repos"]
        }
        assert await _applied_snapshot(db_session) == T1

    async def test_second_snapshot_counts_each_product_once(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        await _publish(db_session, _first_snapshot())
        clock.now = T2

        metrics = await _publish(db_session, _second_snapshot())

        # Selected: A-G (7). Created: G. Updated: B (descriptive), C (repo
        # set), E (both, once), F (left current). A and D (order only)
        # succeed unchanged.
        assert metrics == (7, 1, 4, 0)

    async def test_second_snapshot_publishes_observed_and_retains_dropped_rows(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        first, second = _first_snapshot(), _second_snapshot()
        await _publish(db_session, first)
        clock.now = T2

        await _publish(db_session, second)

        expected_products = {
            row["cpe"]: (row["name"], row["version"], row["friendly_name"], T2)
            for row in second
        }
        dropped = first[5]
        expected_products[dropped["cpe"]] = (
            dropped["name"],
            dropped["version"],
            dropped["friendly_name"],
            T1,
        )
        assert await _products(db_session) == expected_products
        expected_associations = {
            (row["cpe"], repo): T1 for row in first for repo in row["repos"]
        }
        expected_associations.update(
            {(row["cpe"], repo): T2 for row in second for repo in row["repos"]}
        )
        assert await _associations(db_session) == expected_associations
        assert expected_associations[("cpe:/o:example:c:1", _repos("C", "c1")[0])] == T1
        assert await _applied_snapshot(db_session) == T2

    async def test_reappearing_product_and_association_become_current(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        await _publish(db_session, _first_snapshot())
        clock.now = T2
        await _publish(db_session, _second_snapshot())
        clock.now = T3
        third = [
            product_row(
                1, cpe="cpe:/o:example:a:1", repos=_repos("A", "x86_64", "s390x")
            ),
            product_row(
                3, cpe="cpe:/o:example:c:1", repos=_repos("C", "c1", "c2", "c3")
            ),
            product_row(6, cpe="cpe:/o:example:f:1", repos=_repos("F", "f1", "f2")),
        ]

        metrics = await _publish(db_session, third)

        # Selected: A-G (7). Updated: B, D, E, G (left current), C (the
        # historical c1 association re-entered), F (re-entered). A unchanged.
        assert metrics == (7, 0, 6, 0)
        products = await _products(db_session)
        assert products["cpe:/o:example:f:1"][3] == T3
        assert products["cpe:/o:example:b:1"][3] == T2
        associations = await _associations(db_session)
        assert associations[("cpe:/o:example:c:1", _repos("C", "c1")[0])] == T3
        assert associations[("cpe:/o:example:f:1", _repos("F", "f1")[0])] == T3
        assert associations[("cpe:/o:example:e:1", _repos("E", "e2")[0])] == T2
        assert len(products) == 7
        assert await _applied_snapshot(db_session) == T3

    async def test_identical_snapshot_is_an_empty_diff_publication(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        rows = _first_snapshot()
        await _publish(db_session, rows)
        clock.now = T2

        metrics = await _publish(db_session, rows)

        assert metrics == (6, 0, 0, 0)
        assert set((await _products(db_session)).values()) == {
            (row["name"], row["version"], row["friendly_name"], T2) for row in rows
        }
        assert set((await _associations(db_session)).values()) == {T2}

    async def test_decreased_snapshot_is_published_without_count_regression_check(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        await _publish(db_session, make_rows(150))
        clock.now = T2

        metrics = await _publish(db_session, make_rows(1))

        assert metrics == (150, 0, 149, 0)
        assert await _applied_snapshot(db_session) == T2

    @pytest.mark.parametrize(
        "clock_value", [T1, T1 - timedelta(days=3)], ids=["equal", "earlier"]
    )
    async def test_snapshot_not_after_the_applied_one_advances_by_one_microsecond(
        self, db_session: AsyncSession, clock: Clock, clock_value: datetime
    ) -> None:
        rows = _first_snapshot()
        await _publish(db_session, rows[:3])
        clock.now = clock_value

        metrics = await _publish(db_session, rows[1:])

        advanced = T1 + MICROSECOND
        assert await _applied_snapshot(db_session) == advanced
        products = await _products(db_session)
        assert {cpe: state[3] for cpe, state in products.items()} == {
            rows[0]["cpe"]: T1,
            **{row["cpe"]: advanced for row in rows[1:]},
        }
        assert set((await _associations(db_session)).values()) == {T1, advanced}
        # Selected: rows 1-6; created: rows 4-6; updated: row 1 (left).
        assert metrics == (6, 3, 1, 0)

    async def test_aimaas_owned_columns_are_never_cleared_or_overwritten(
        self,
        db_session: AsyncSession,
        clock: Clock,
        product_factory: Callable[..., Awaitable[Product]],
    ) -> None:
        row = product_row(1)
        lifecycle = {
            "cvss_threshold": Decimal("7.5"),
            "first_customer_ship_date": date(2024, 6, 1),
            "general_support_end_date": date(2031, 7, 31),
            "extended_support_end_date": date(2034, 7, 31),
            "reactive_support_end_date": date(2037, 7, 31),
        }
        await product_factory(
            cpe=row["cpe"],
            name="Old Name",
            version="0",
            display_name="Old Display",
            catalog_last_seen_at=T0,
            **lifecycle,
        )

        metrics = await _publish(db_session, [{**row, "end_of_life": "2020-01-31"}])

        stored = (
            await db_session.execute(
                select(
                    Product.name,
                    Product.display_name,
                    Product.cvss_threshold,
                    Product.first_customer_ship_date,
                    Product.general_support_end_date,
                    Product.extended_support_end_date,
                    Product.reactive_support_end_date,
                ).where(Product.cpe == row["cpe"])
            )
        ).one()
        assert (stored.name, stored.display_name) == (row["name"], row["friendly_name"])
        assert {key: getattr(stored, key) for key in lifecycle} == lifecycle
        assert metrics == (1, 0, 1, 0)

    async def test_ignored_fields_do_not_reach_persistence(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        row = product_row(
            1, end_of_life="2020-01-31", id=9999, details=[{"cpe": "cpe:/o:other:1"}]
        )

        await _publish(db_session, [row])

        stored = (
            await db_session.execute(
                select(
                    Product.general_support_end_date,
                    Product.extended_support_end_date,
                    Product.reactive_support_end_date,
                    Product.cvss_threshold,
                )
            )
        ).one()
        assert tuple(stored) == (None, None, None, None)
        assert set(await _products(db_session)) == {row["cpe"]}

    async def test_source_values_are_persisted_exactly(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        rows = [
            product_row(
                1,
                name=" Example Mixed ",
                cpe="CPE:/o:Example:Product-A:1",
                friendly_name="Example\tFriendly ",
                repos=["EXAMPLE:Updates:A:1:x86_64 ", "example:updates:a:1:x86_64"],
            ),
            product_row(2, cpe="cpe:/o:example:product-a:1"),
        ]

        await _publish(db_session, rows)

        assert await _products(db_session) == {
            row["cpe"]: (row["name"], row["version"], row["friendly_name"], T1)
            for row in rows
        }
        assert set(await _associations(db_session)) == {
            (row["cpe"], repo) for row in rows for repo in row["repos"]
        }

    async def test_shared_repository_is_persisted_for_each_product(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        shared = "EXAMPLE:Updates:Shared:1:x86_64"
        rows = [product_row(1, repos=[shared]), product_row(2, repos=[shared])]

        await _publish(db_session, rows)

        assert set(await _associations(db_session)) == {
            (rows[0]["cpe"], shared),
            (rows[1]["cpe"], shared),
        }

    async def test_snapshot_larger_than_one_upsert_chunk_is_published(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        rows = make_rows(1100)

        metrics = await _publish(db_session, rows)

        assert metrics == (1100, 1100, 0, 0)
        assert len(await _products(db_session)) == 1100
        assert len(await _associations(db_session)) == 2200

    async def test_configured_request_delay_is_applied_between_pages(
        self,
        db_session: AsyncSession,
        clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(
            smelt_product_listing, "asyncio", SimpleNamespace(sleep=sleep)
        )
        fetcher = _fetcher(SmeltServer.for_rows(make_rows(250)))
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.25, custom_settings={}
        )
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert sleeps == [0.25, 0.25]


# ---------------------------------------------------------------------------
# Transaction boundaries and failures (steps 1 and 7; Error Handling)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionBoundaries:
    async def test_every_request_completes_before_any_database_statement(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        await _publish(db_session, make_rows(2))
        clock.now = T2
        events: list[tuple[str, str]] = []
        engine = db_session.get_bind().engine

        def record(*args: Any) -> None:
            events.append(("sql", args[2]))

        event.listen(engine, "before_cursor_execute", record)
        try:
            await _execute(
                db_session, SmeltServer.for_rows(make_rows(250), events=events)
            )
        finally:
            event.remove(engine, "before_cursor_execute", record)

        kinds = [kind for kind, _ in events]
        assert kinds.count("http") == 3
        assert "sql" in kinds
        assert kinds == sorted(kinds)  # every "http" precedes every "sql"

    @pytest.mark.parametrize("stage", ["associations", "commit"])
    async def test_database_failure_rolls_back_the_complete_publication(
        self,
        db_session: AsyncSession,
        clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
    ) -> None:
        await _publish(db_session, _first_snapshot())
        before = (await _products(db_session), await _associations(db_session))
        clock.now = T2
        failure = OperationalError("INSERT", {}, Exception("connection lost"))
        original = sync_module._upsert_associations

        async def failing_upsert(*args: Any, **kwargs: Any) -> None:
            await original(*args, **kwargs)
            raise failure

        async def failing_commit() -> None:
            raise failure

        if stage == "associations":
            monkeypatch.setattr(sync_module, "_upsert_associations", failing_upsert)
        else:
            monkeypatch.setattr(db_session, "commit", failing_commit)

        error, fetcher = await _execute_failing(
            db_session, SmeltServer.for_rows(_second_snapshot())
        )
        await db_session.rollback()

        assert str(error) == PUBLICATION_FAILED
        assert error.__cause__ is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert (await _products(db_session), await _associations(db_session)) == before
        assert await _applied_snapshot(db_session) == T1

    async def test_publication_failure_log_contains_no_payload(
        self,
        db_session: AsyncSession,
        clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def failing_upsert(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("INSERT", {}, Exception(MARKER))

        monkeypatch.setattr(sync_module, "_upsert_associations", failing_upsert)

        with capture_logs() as logs:
            await _execute_failing(
                db_session, SmeltServer.for_rows([product_row(1, name=MARKER)])
            )
        await db_session.rollback()

        assert logs == [
            {
                "event": "smelt_product_catalog_publication_failed",
                "log_level": "warning",
            }
        ]


def _http_500(server: SmeltServer) -> None:
    server.responses[2] = lambda request: httpx.Response(500)


def _connect_error(server: SmeltServer) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("example connection failure", request=request)

    server.responses[1] = respond


def _read_timeout(server: SmeltServer) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("example timeout", request=request)

    server.responses[1] = respond


def _invalid_metadata(server: SmeltServer) -> None:
    server.pages[2]["previous"] = None


def _invalid_row(server: SmeltServer) -> None:
    server.pages[3]["results"][0]["repos"] = []


def _duplicate_cpe(server: SmeltServer) -> None:
    server.pages[3]["results"][0]["cpe"] = server.pages[1]["results"][0]["cpe"]


def _zero_count(server: SmeltServer) -> None:
    server.pages.clear()
    server.pages[1] = {
        "count": 0,
        "total_pages": 1,
        "next": None,
        "previous": None,
        "results": [],
    }


FailureCase = tuple[str, Callable[[SmeltServer], None], str, type[BaseException]]

_RUN_FAILURES: Final[list[FailureCase]] = [
    ("http-status", _http_500, "SMELT returned HTTP 500", httpx.HTTPStatusError),
    ("connection", _connect_error, "Failed to connect to SMELT", httpx.ConnectError),
    ("timeout", _read_timeout, "SMELT request timed out", httpx.ReadTimeout),
    ("pagination", _invalid_metadata, INVALID_RESPONSE, InvalidProductListingError),
    ("row", _invalid_row, VALIDATION_FAILED, SnapshotValidationError),
    ("duplicate-cpe", _duplicate_cpe, VALIDATION_FAILED, SnapshotValidationError),
    ("zero-count", _zero_count, VALIDATION_FAILED, SnapshotValidationError),
]


@pytest.mark.integration
class TestWholeRunFailureBeforePublication:
    @pytest.mark.parametrize(
        ("break_server", "message", "cause"),
        [case[1:] for case in _RUN_FAILURES],
        ids=[case[0] for case in _RUN_FAILURES],
    )
    async def test_failure_publishes_nothing_and_records_no_metric(
        self,
        db_session: AsyncSession,
        clock: Clock,
        break_server: Callable[[SmeltServer], None],
        message: str,
        cause: type[BaseException],
    ) -> None:
        await _publish(db_session, _first_snapshot())
        before = (await _products(db_session), await _associations(db_session))
        clock.now = T2
        server = SmeltServer.for_rows(make_rows(250))
        break_server(server)
        events: list[tuple[str, str]] = []
        engine = db_session.get_bind().engine

        def record(*args: Any) -> None:
            events.append(("sql", args[2]))

        event.listen(engine, "before_cursor_execute", record)
        try:
            error, fetcher = await _execute_failing(db_session, server)
        finally:
            event.remove(engine, "before_cursor_execute", record)

        assert str(error) == message
        assert isinstance(error.__cause__, cause)
        assert "smelt.example.test" not in str(error)
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert events == []
        assert (await _products(db_session), await _associations(db_session)) == before

    async def test_validation_failure_log_names_category_without_payload(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        rows = make_rows(3)
        rows[1]["name"] = MARKER * 10

        with capture_logs() as logs:
            await _execute_failing(db_session, SmeltServer.for_rows(rows))

        assert logs == [
            {
                "event": "smelt_product_catalog_validation_failed",
                "log_level": "warning",
                "category": f"row 1: name exceeds {FIELD_LIMITS['name']} characters",
            }
        ]


# ---------------------------------------------------------------------------
# No Ticket audit event (ticket-audit-log.md matrix row; TR 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoTicketAuditEvent:
    async def test_effective_and_no_op_publications_create_no_ticket_event(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    ) -> None:
        first = make_rows(3)
        await _publish(db_session, first)
        result = await db_session.execute(select(Product.cpe, Product.id))
        product_ids = dict(result.all())
        ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        for row in first:
            await ticket_package_product_factory(
                ticket_package_track_id=track.id, product_id=product_ids[row["cpe"]]
            )
        await ticket_factory()  # a Ticket without a package tree

        async def tree_state() -> list[tuple[Any, ...]]:
            rows = await db_session.execute(
                select(
                    TicketPackageProduct.id,
                    TicketPackageProduct.product_id,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.released_at,
                    TicketPackageProduct.deleted_at,
                    TicketPackageProduct.updated_at,
                ).order_by(TicketPackageProduct.id)
            )
            return [tuple(row) for row in rows]

        async def event_count() -> int:
            return (
                await db_session.execute(select(func.count(TicketAuditEvent.id)))
            ).scalar_one()

        tree_before = await tree_state()
        assert await event_count() == 0

        # Row 1 updated, row 2 left current, row 3 unchanged, row 4 created.
        second = [
            {**first[0], "friendly_name": "Example Product 1 Renamed"},
            first[2],
            product_row(4),
        ]
        clock.now = T2
        effective = await _publish(db_session, second)
        clock.now = T3
        no_op = await _publish(db_session, second)

        assert effective == (4, 1, 2, 0)
        assert no_op == (3, 0, 0, 0)
        assert await event_count() == 0
        assert await tree_state() == tree_before


# ---------------------------------------------------------------------------
# Catalog readiness and coherence with the Product query service
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCatalogReadiness:
    async def test_published_snapshot_is_the_current_catalog(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        both = (CatalogPresence.CURRENT, CatalogPresence.HISTORICAL)

        async def presence() -> dict[str, tuple[CatalogPresence, datetime]]:
            page = await list_products(
                db_session,
                evaluation_date=EVALUATION_DATE,
                catalog_presence=both,
                per_page=100,
            )
            return {
                item.cpe: (item.catalog_presence, item.catalog_last_seen_at)
                for item in page.items
            }

        rows = make_rows(3)
        assert await _applied_snapshot(db_session) is None
        assert await presence() == {}

        await _publish(db_session, rows)

        assert await presence() == {
            row["cpe"]: (CatalogPresence.CURRENT, T1) for row in rows
        }

        clock.now = T2
        await _publish(db_session, rows[:2])

        assert await presence() == {
            rows[0]["cpe"]: (CatalogPresence.CURRENT, T2),
            rows[1]["cpe"]: (CatalogPresence.CURRENT, T2),
            rows[2]["cpe"]: (CatalogPresence.HISTORICAL, T1),
        }
        current_only = await list_products(db_session, evaluation_date=EVALUATION_DATE)
        assert current_only.total == 2
        assert {item.cpe for item in current_only.items} == {
            rows[0]["cpe"],
            rows[1]["cpe"],
        }


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------

RunSetup = Callable[[SmeltServer], Awaitable[uuid.UUID]]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RunSetup]:
    """Commit a `running` FetcherRun and route `run()` to the test database.

    `run()` opens its own sessions through `base_fetcher`'s
    `async_session_factory` and creates its HTTP client through
    `create_http_client`; both are redirected here. Every committed row
    (FetcherConfig, FetcherRun, and the Products and associations the
    publication commits) is deleted at teardown.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    fetcher_name = f"test_smelt_run_{uuid.uuid4().hex[:12]}"
    servers: list[SmeltServer] = []

    async def setup(server: SmeltServer) -> uuid.UUID:
        servers.append(server)
        monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: server.client(),
        )
        async with real_session_factory() as session:
            session.add(
                FetcherConfig(
                    fetcher_name=fetcher_name,
                    enabled=True,
                    run_timeout=3600,
                    request_delay=0,
                    custom_settings={},
                )
            )
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    try:
        yield setup
    finally:
        cpes = {
            row["cpe"]
            for server in servers
            for body in server.pages.values()
            for row in body["results"]
        }
        async with real_session_factory() as session:
            product_ids = select(Product.id).where(Product.cpe.in_(cpes))
            await session.execute(
                delete(ProductRepository).where(
                    ProductRepository.product_id.in_(product_ids)
                )
            )
            await session.execute(delete(Product).where(Product.cpe.in_(cpes)))
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


async def _finalized(
    real_session_factory: async_sessionmaker[AsyncSession], run_id: uuid.UUID
) -> FetcherRun:
    async with real_session_factory() as session:
        run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run


@pytest.mark.integration
class TestRunLifecycle:
    async def test_successful_run_is_finalized_with_exact_counters(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        clock: Clock,
    ) -> None:
        rows = make_rows(3, start=9001)
        run_id = await committed_run(SmeltServer.for_rows(rows))

        await SyncSmeltProducts().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (3, 3, 0, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        async with real_session_factory() as session:
            assert await _products(session) == {
                row["cpe"]: (row["name"], row["version"], row["friendly_name"], T1)
                for row in rows
            }

    async def test_failed_run_is_finalized_with_sanitized_message(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        clock: Clock,
    ) -> None:
        server = SmeltServer.for_rows(make_rows(250, start=9101))
        server.responses[2] = lambda request: httpx.Response(503)
        run_id = await committed_run(server)

        with pytest.raises(FetcherError, match=r"^SMELT returned HTTP 503$"):
            await SyncSmeltProducts().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "SMELT returned HTTP 503"
        assert run.error_detail is not None
        assert run.error_traceback is not None
        assert "smelt.example.test" not in run.error_message
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (0, 0, 0, 0)
        async with real_session_factory() as session:
            assert await _products(session) == {}


# ---------------------------------------------------------------------------
# Registration and properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY["sync_smelt_products"] is SyncSmeltProducts

    def test_properties_match_the_specification(self) -> None:
        assert SyncSmeltProducts.name == "sync_smelt_products"
        assert SyncSmeltProducts.description == (
            "Synchronize the complete SMELT Product catalog and repository associations"
        )
        assert SyncSmeltProducts.default_schedule == "0 1 * * *"
        assert SyncSmeltProducts.participates_in_catch_up is False
        assert SyncSmeltProducts.Settings is None
        assert SyncSmeltProducts.queue is None

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(
            part.capitalize() for part in SyncSmeltProducts.name.split("_")
        )

        assert derived == SyncSmeltProducts.__name__ == "SyncSmeltProducts"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert "sync_smelt_products" not in get_catch_up_fetchers()


@pytest.mark.unit
class TestSeams:
    def test_snapshot_clock_returns_the_current_utc_instant(self) -> None:
        before = datetime.now(UTC)

        now = sync_module._utc_now()

        assert now.tzinfo is UTC
        assert before <= now <= datetime.now(UTC)

    @pytest.mark.parametrize(
        "column",
        [Product.__table__.c.cvss_threshold, Product.__table__.c.created_at],
        ids=["numeric", "timestamp"],
    )
    def test_validation_bound_requires_a_bounded_string_column(
        self, column: Any
    ) -> None:
        with pytest.raises(TypeError, match="is not a bounded string column"):
            sync_module._column_length(column)


@pytest.mark.integration
class TestBootstrap:
    async def test_bootstrap_creates_the_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, "sync_smelt_products") is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, "sync_smelt_products")
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.custom_settings == {}
