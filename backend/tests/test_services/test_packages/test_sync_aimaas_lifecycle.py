"""Tests for the `sync_aimaas_lifecycle` fetcher.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Deleted Flag Semantics and Product Lifecycle Sync, steps 1-8,
inconsistency warnings, and the four-column write scope; Fetcher:
`sync_aimaas_lifecycle`, properties, Error Handling, and Metrics),
docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base Class:
execution-session transaction contract, Finalization, Outcome and effect
accounting; Error Message Sanitization; Registry), docs/features/platform/
testing-strategy.md (Fetcher Outcome and Effect Accounting), and
docs/features/tickets/ticket-audit-log.md (Canonical Mutation and No-Event
Matrix row "Product catalog source mutation or workflow-only
dispatch/checkpoint outcome"; Testing Requirement 12).

`parse_lifecycle_entries()`, `validate_lifecycle_entries()`, and the
fetcher properties are unit tests. Publication tests call
`execute(db_session)` against Products seeded directly: the fetcher's
commit releases a savepoint of the per-test outer transaction, so every
row is rolled back at teardown. The two `run()` lifecycle tests commit
through `real_session_factory` and delete every row they create. AIMAAS is
the fake server of `tests/support/aimaas.py`, injected as the fetcher's
HTTP client.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import Update, delete, event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.config import settings
from app.core.enums import LifecyclePhase
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
from app.services.packages import aimaas_listing
from app.services.packages.aimaas_listing import InvalidAimaasListingError
from app.services.packages.sync_aimaas_lifecycle import (
    INVALID_RESPONSE_MESSAGE,
    PUBLICATION_FAILED_MESSAGE,
    VALIDATION_FAILED_MESSAGE,
    LifecycleDates,
    LifecycleEntry,
    LifecycleResponseError,
    LifecycleValidationError,
    SyncAimaasLifecycle,
    parse_lifecycle_entries,
    validate_lifecycle_entries,
)
from app.services.product_lifecycle import (
    LifecycleDateViolation,
    evaluate_product_lifecycle_phase,
)
from tests.support.aimaas import (
    AIMAAS_TEST_API_URL,
    AIMAAS_TEST_PRODUCTS_ENDPOINT,
    AimaasServer,
    make_items,
    product_item,
)

MARKER: Final = "Example-Confidential-Aimaas-Value"
T0: Final = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
OLD_UPDATED_AT: Final = datetime(2020, 1, 1, tzinfo=UTC)
WARNING_EVENT: Final = "product_lifecycle_dates_inconsistent"

DATE_FIELDS: Final = ("fcs", "end_of_gs", "end_of_ltss", "end_of_espos")
ALL_DATE_FIELDS: Final = (*DATE_FIELDS, "end_of_reactive_ltss")

Dates = tuple[date | None, date | None, date | None, date | None]
"""`(first_customer_ship, general_support_end, extended_end, reactive_end)`."""

NO_DATES: Final[Dates] = (None, None, None, None)
# The projection of `product_item()`'s default dates.
DEFAULT_DATES: Final[Dates] = (
    date(2024, 1, 15),
    date(2027, 6, 30),
    date(2030, 6, 30),
    date(2032, 6, 30),
)

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lifecycle(dates: Dates) -> LifecycleDates:
    return LifecycleDates(
        first_customer_ship_date=dates[0],
        general_support_end_date=dates[1],
        extended_support_end_date=dates[2],
        reactive_support_end_date=dates[3],
    )


def _date_columns(dates: Dates) -> dict[str, date | None]:
    return {
        "first_customer_ship_date": dates[0],
        "general_support_end_date": dates[1],
        "extended_support_end_date": dates[2],
        "reactive_support_end_date": dates[3],
    }


def _item(cpe: Any, **overrides: Any) -> dict[str, Any]:
    """One fictional AIMAAS entry for `cpe` (default dates unless overridden)."""
    return product_item(1, cpe=cpe, **overrides)


def _parsed(item: dict[str, Any]) -> LifecycleEntry:
    (entry,) = parse_lifecycle_entries([item])
    return entry


def _response_error(items: list[dict[str, Any]]) -> LifecycleResponseError:
    with pytest.raises(LifecycleResponseError) as raised:
        parse_lifecycle_entries(items)
    return raised.value


def _metrics(fetcher: SyncAimaasLifecycle) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


@pytest.fixture(autouse=True)
def _fictional_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the fetcher at the fictional AIMAAS origin."""
    monkeypatch.setattr(settings, "aimaas_api_url", AIMAAS_TEST_API_URL)


def _fetcher(server: AimaasServer) -> SyncAimaasLifecycle:
    fetcher = SyncAimaasLifecycle()
    fetcher._http_client = server.client()
    return fetcher


async def _execute(db: AsyncSession, server: AimaasServer) -> SyncAimaasLifecycle:
    fetcher = _fetcher(server)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _publish(db: AsyncSession, items: list[dict[str, Any]]) -> Metrics:
    """Run one complete synchronization of `items` and return its metrics."""
    return _metrics(await _execute(db, AimaasServer.for_items(items)))


async def _execute_failing(
    db: AsyncSession, server: AimaasServer
) -> tuple[FetcherError, SyncAimaasLifecycle]:
    fetcher = _fetcher(server)
    try:
        with pytest.raises(FetcherError) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


SeedProduct = Callable[..., Awaitable[Product]]


@pytest.fixture
def seed(product_factory: Callable[..., Awaitable[Product]]) -> SeedProduct:
    """Seed one local Product with lifecycle dates and an old `updated_at`."""

    async def _seed(cpe: str, dates: Dates = NO_DATES, **overrides: Any) -> Product:
        return await product_factory(
            cpe=cpe,
            catalog_last_seen_at=T0,
            updated_at=OLD_UPDATED_AT,
            **_date_columns(dates),
            **overrides,
        )

    return _seed


async def _dates(db: AsyncSession) -> dict[str, Dates]:
    """Every persisted Product: CPE -> its four lifecycle dates."""
    rows = await db.execute(
        select(
            Product.cpe,
            Product.first_customer_ship_date,
            Product.general_support_end_date,
            Product.extended_support_end_date,
            Product.reactive_support_end_date,
        )
    )
    return {
        row.cpe: (
            row.first_customer_ship_date,
            row.general_support_end_date,
            row.extended_support_end_date,
            row.reactive_support_end_date,
        )
        for row in rows
    }


async def _updated_at(db: AsyncSession) -> dict[str, datetime]:
    rows = await db.execute(select(Product.cpe, Product.updated_at))
    return {row.cpe: row.updated_at for row in rows}


async def _product_rows(db: AsyncSession) -> dict[str, tuple[Any, ...]]:
    """Every persisted Product: CPE -> every column (complete state)."""
    columns = list(Product.__table__.columns)
    rows = await db.execute(select(*columns))
    return {row.cpe: tuple(row) for row in rows}


class SqlRecorder:
    """Records every SQL statement the engine executes while attached."""

    def __init__(self, db: AsyncSession, events: list[tuple[str, str]]) -> None:
        self.engine = db.get_bind().engine
        self.events = events

    def _record(self, *args: Any) -> None:
        self.events.append(("sql", args[2]))

    def __enter__(self) -> SqlRecorder:
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self.engine, "before_cursor_execute", self._record)


def _warnings(logs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == WARNING_EVENT]


def _warning(cpe: str, reason: LifecycleDateViolation) -> dict[str, Any]:
    return {
        "event": WARNING_EVENT,
        "log_level": "warning",
        "product_cpe": cpe,
        "reason": reason.value,
    }


# ---------------------------------------------------------------------------
# Response parsing (consumed fields; field projection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseLifecycleEntries:
    def test_fields_are_projected_onto_the_four_columns(self) -> None:
        item = _item(
            "cpe:/o:example:product-a:1",
            fcs="2021-03-04",
            end_of_gs="2025-05-06",
            end_of_ltss="2028-07-08",
            end_of_espos=None,
            end_of_reactive_ltss="2030-09-10",
        )

        assert parse_lifecycle_entries([item]) == [
            LifecycleEntry(
                cpe="cpe:/o:example:product-a:1",
                dates=LifecycleDates(
                    first_customer_ship_date=date(2021, 3, 4),
                    general_support_end_date=date(2025, 5, 6),
                    extended_support_end_date=date(2028, 7, 8),
                    reactive_support_end_date=date(2030, 9, 10),
                ),
            )
        ]

    @pytest.mark.parametrize(
        ("ltss", "espos", "expected"),
        [
            ("2029-01-31", None, date(2029, 1, 31)),
            (None, "2029-02-28", date(2029, 2, 28)),
            ("2029-01-31", "2030-01-31", date(2030, 1, 31)),
            ("2030-01-31", "2029-01-31", date(2030, 1, 31)),
            ("2029-01-31", "2029-01-31", date(2029, 1, 31)),
            (None, None, None),
        ],
        ids=[
            "ltss-only",
            "espos-only",
            "espos-later",
            "ltss-later",
            "equal",
            "neither",
        ],
    )
    def test_extended_end_is_the_later_of_ltss_and_espos(
        self, ltss: str | None, espos: str | None, expected: date | None
    ) -> None:
        entry = _parsed(
            _item("cpe:/o:example:a:1", end_of_ltss=ltss, end_of_espos=espos)
        )

        assert entry.dates.extended_support_end_date == expected

    def test_all_null_dates_project_to_all_null_columns(self) -> None:
        item = _item("cpe:/o:example:a:1", **dict.fromkeys(ALL_DATE_FIELDS))

        assert _parsed(item).dates == _lifecycle(NO_DATES)

    @pytest.mark.parametrize("cpe", [None, ""], ids=["null", "empty"])
    def test_null_or_empty_cpe_yields_an_unmatchable_entry(
        self, cpe: str | None
    ) -> None:
        entry = _parsed(_item(cpe))

        assert entry.cpe is None
        assert entry.dates == _lifecycle(DEFAULT_DATES)

    @pytest.mark.parametrize(
        "cpe",
        [
            "cpe:/o:example:product-a:1 ",
            " cpe:/o:example:product-a:1",
            "CPE:/O:EXAMPLE:PRODUCT-A:1",
            "cpe:/o:Example:Product-A:1\t",
        ],
        ids=["trailing-space", "leading-space", "upper-case", "mixed-tab"],
    )
    def test_cpe_is_preserved_exactly(self, cpe: str) -> None:
        assert _parsed(_item(cpe)).cpe == cpe

    def test_missing_cpe_key_is_a_response_error(self) -> None:
        item = _item("cpe:/o:example:a:1")
        del item["cpe"]

        error = _response_error([_item("cpe:/o:example:b:1"), item])

        assert str(error) == "item 1: cpe is missing"

    @pytest.mark.parametrize(
        "cpe", [7, ["cpe:/o:example:a:1"], True, {"cpe": "x"}, 1.5]
    )
    def test_non_string_cpe_is_a_response_error(self, cpe: Any) -> None:
        error = _response_error([_item(cpe)])

        assert str(error) == "item 0: cpe must be a string"

    @pytest.mark.parametrize(
        "cpe",
        ["\x00", "\x00cpe:/o:example:a:1", "cpe:/o:\x00example:a:1", "cpe:/o:a:1\x00"],
        ids=["only", "start", "middle", "end"],
    )
    def test_cpe_containing_nul_is_a_response_error(self, cpe: str) -> None:
        """External String Admissibility: not unmatchable, not stripped."""
        error = _response_error([_item("cpe:/o:example:b:1"), _item(cpe)])

        assert str(error) == "item 1: cpe contains U+0000"

    @pytest.mark.parametrize("field", ALL_DATE_FIELDS)
    def test_missing_date_key_is_a_response_error(self, field: str) -> None:
        item = _item("cpe:/o:example:a:1")
        del item[field]

        error = _response_error([_item("cpe:/o:example:b:1"), _item(None), item])

        assert str(error) == f"item 2: {field} is missing"

    @pytest.mark.parametrize("field", ALL_DATE_FIELDS)
    @pytest.mark.parametrize(
        "value",
        [
            "2026-13-01",
            "2026-02-30",
            "2026-00-10",
            "2026-1-5",
            "20260105",
            "2026-01-05T00:00:00",
            "2026-01-05 ",
            "2026-W01-1",
            "",
            123,
            20260105,
            True,
            [],
            {"date": "2026-01-05"},
        ],
        ids=[
            "month-13",
            "february-30",
            "month-00",
            "unpadded",
            "basic-format",
            "date-time",
            "trailing-space",
            "iso-week",
            "empty",
            "int",
            "int-basic",
            "bool",
            "list",
            "object",
        ],
    )
    def test_invalid_date_value_is_a_response_error(
        self, field: str, value: Any
    ) -> None:
        error = _response_error([_item("cpe:/o:example:a:1", **{field: value})])

        assert str(error) == f"item 0: {field} is not a date"

    def test_ignored_and_unknown_fields_do_not_affect_parsing(self) -> None:
        base = _item("cpe:/o:example:a:1")
        noisy = {
            **base,
            "slug": None,
            "name": 5,
            "id": "not-an-integer",
            "deleted": "yes",
            "version": ["x"],
            "tracked_in_bz": {"nested": True},
            "beta_release": "not-a-date",
            "end_of_lts_core": "2026-13-45",
            "unknown_field": {"nested": [1, None, {"value": MARKER}]},
        }
        minimal = {key: base[key] for key in ("cpe", *ALL_DATE_FIELDS)}

        assert parse_lifecycle_entries([noisy]) == parse_lifecycle_entries([base])
        assert parse_lifecycle_entries([minimal]) == parse_lifecycle_entries([base])

    def test_entries_are_returned_in_response_order(self) -> None:
        items = make_items(5)

        entries = parse_lifecycle_entries(items)

        assert [entry.cpe for entry in entries] == [item["cpe"] for item in items]

    def test_empty_response_yields_no_entries(self) -> None:
        assert parse_lifecycle_entries([]) == []

    @pytest.mark.parametrize(
        "item",
        [
            _item([MARKER]),
            _item(MARKER, fcs=MARKER),
            _item(MARKER, end_of_gs=f"2026-{MARKER}"),
            _item(MARKER, end_of_reactive_ltss=[MARKER]),
            {"cpe": MARKER, MARKER: MARKER},
        ],
        ids=["cpe-list", "fcs", "end-of-gs", "reactive-list", "missing-dates"],
    )
    def test_response_error_message_contains_no_source_value(
        self, item: dict[str, Any]
    ) -> None:
        error = _response_error([item])

        assert MARKER not in str(error)


@pytest.mark.unit
class TestValidateLifecycleEntries:
    def test_returns_the_cpe_to_projection_map(self) -> None:
        items = [
            _item("cpe:/o:example:a:1"),
            _item("cpe:/o:example:b:1", end_of_reactive_ltss=None),
        ]

        projections = validate_lifecycle_entries(parse_lifecycle_entries(items))

        assert projections == {
            "cpe:/o:example:a:1": _lifecycle(DEFAULT_DATES),
            "cpe:/o:example:b:1": _lifecycle((*DEFAULT_DATES[:3], None)),
        }

    def test_duplicate_non_empty_cpe_is_rejected(self) -> None:
        entries = parse_lifecycle_entries(
            [
                _item(MARKER),
                _item("cpe:/o:example:b:1"),
                _item(None),
                _item(MARKER, fcs=None),
            ]
        )

        with pytest.raises(LifecycleValidationError) as raised:
            validate_lifecycle_entries(entries)

        assert str(raised.value) == "item 3: duplicate cpe"
        assert MARKER not in str(raised.value)

    def test_several_null_or_empty_cpes_are_allowed_and_excluded(self) -> None:
        entries = parse_lifecycle_entries(
            [_item(None), _item(""), _item("cpe:/o:example:a:1"), _item(None)]
        )

        assert validate_lifecycle_entries(entries) == {
            "cpe:/o:example:a:1": _lifecycle(DEFAULT_DATES)
        }

    def test_cpes_differing_only_in_case_or_whitespace_are_distinct(self) -> None:
        cpes = ["cpe:/o:example:a:1", "CPE:/O:EXAMPLE:A:1", "cpe:/o:example:a:1 "]
        entries = parse_lifecycle_entries([_item(cpe) for cpe in cpes])

        assert list(validate_lifecycle_entries(entries)) == cpes

    def test_empty_response_yields_an_empty_map(self) -> None:
        assert validate_lifecycle_entries([]) == {}


@pytest.mark.unit
class TestLifecycleDates:
    def test_violations_apply_the_lifecycle_evaluator_rules(self) -> None:
        reversed_chain = _lifecycle(
            (date(2030, 1, 1), date(2029, 1, 1), date(2028, 1, 1), date(2027, 1, 1))
        )

        assert reversed_chain.violations() == (
            LifecycleDateViolation.FIRST_CUSTOMER_SHIP_AFTER_GENERAL_SUPPORT_END,
            LifecycleDateViolation.GENERAL_SUPPORT_END_AFTER_EXTENDED_SUPPORT_END,
            LifecycleDateViolation.EXTENDED_SUPPORT_END_AFTER_REACTIVE_SUPPORT_END,
        )
        assert _lifecycle(DEFAULT_DATES).violations() == ()
        assert _lifecycle(NO_DATES).violations() == ()


# ---------------------------------------------------------------------------
# Publication (steps 3-8; write scope; matching)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPublication:
    async def test_matched_product_receives_the_projection(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe)

        metrics = await _publish(
            db_session,
            [
                _item(
                    cpe,
                    fcs="2021-03-04",
                    end_of_gs="2025-05-06",
                    end_of_ltss="2028-07-08",
                    end_of_espos="2028-12-31",
                    end_of_reactive_ltss="2030-09-10",
                )
            ],
        )

        assert metrics == (1, 0, 1, 0)
        assert await _dates(db_session) == {
            cpe: (
                date(2021, 3, 4),
                date(2025, 5, 6),
                date(2028, 12, 31),
                date(2030, 9, 10),
            )
        }

    @pytest.mark.parametrize(
        ("ltss", "espos", "expected"),
        [
            ("2029-01-31", "2030-01-31", date(2030, 1, 31)),
            ("2030-01-31", "2029-01-31", date(2030, 1, 31)),
            (None, "2029-02-28", date(2029, 2, 28)),
        ],
        ids=["espos-later", "ltss-later", "espos-only"],
    )
    async def test_later_of_ltss_and_espos_is_persisted(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        ltss: str | None,
        espos: str | None,
        expected: date,
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe)

        await _publish(db_session, [_item(cpe, end_of_ltss=ltss, end_of_espos=espos)])

        assert (await _dates(db_session))[cpe][2] == expected

    async def test_changed_dates_are_written_and_advance_updated_at(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, (date(2024, 1, 15), date(2027, 6, 30), None, None))

        metrics = await _publish(db_session, [_item(cpe)])

        assert metrics == (1, 0, 1, 0)
        assert (await _dates(db_session))[cpe] == DEFAULT_DATES
        assert (await _updated_at(db_session))[cpe] > OLD_UPDATED_AT

    async def test_unchanged_dates_are_not_written(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, DEFAULT_DATES)
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, [_item(cpe)])

        assert metrics == (1, 0, 0, 0)
        assert await _product_rows(db_session) == before
        assert (await _updated_at(db_session))[cpe] == OLD_UPDATED_AT

    @pytest.mark.parametrize(
        ("field", "column"),
        [
            ("fcs", 0),
            ("end_of_gs", 1),
            ("end_of_ltss", 2),
            ("end_of_reactive_ltss", 3),
        ],
    )
    async def test_source_date_becoming_null_clears_the_column(
        self, db_session: AsyncSession, seed: SeedProduct, field: str, column: int
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, DEFAULT_DATES)

        metrics = await _publish(db_session, [_item(cpe, **{field: None})])

        expected = list(DEFAULT_DATES)
        expected[column] = None
        assert (await _dates(db_session))[cpe] == tuple(expected)
        assert metrics == (1, 0, 1, 0)
        assert (await _updated_at(db_session))[cpe] > OLD_UPDATED_AT

    async def test_extended_end_clears_only_when_ltss_and_espos_are_null(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        kept, cleared = "cpe:/o:example:kept:1", "cpe:/o:example:cleared:1"
        await seed(kept, DEFAULT_DATES)
        await seed(cleared, DEFAULT_DATES)

        metrics = await _publish(
            db_session,
            [
                _item(kept, end_of_ltss=None, end_of_espos="2030-06-30"),
                _item(cleared, end_of_ltss=None, end_of_espos=None),
            ],
        )

        dates = await _dates(db_session)
        assert dates[kept] == DEFAULT_DATES
        assert dates[cleared][2] is None
        assert metrics == (2, 0, 1, 0)

    async def test_products_absent_from_aimaas_keep_their_dates(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        present, absent = "cpe:/o:example:present:1", "cpe:/o:example:absent:1"
        await seed(present)
        await seed(absent, DEFAULT_DATES)
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, [_item(present)])

        after = await _product_rows(db_session)
        assert after[absent] == before[absent]
        assert metrics == (1, 0, 1, 0)

    async def test_unmatched_and_unmatchable_entries_create_and_change_nothing(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        local = "cpe:/o:example:local:1"
        await seed(local)
        before = await _product_rows(db_session)
        items = [
            _item("cpe:/o:example:unknown:1"),
            _item(None),
            _item(""),
            _item(None, end_of_gs=None),
        ]

        metrics = await _publish(db_session, items)

        assert metrics == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before

    async def test_no_heuristic_matching_by_name_or_version(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        item = product_item(1)
        await seed(
            "cpe:/o:example:local-only:1",
            name=item["name"],
            version=item["version"],
            display_name=item["name"],
        )
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, [item])

        assert metrics == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before

    @pytest.mark.parametrize(
        "upstream",
        [
            "CPE:/O:EXAMPLE:PRODUCT-A:1",
            "cpe:/o:example:product-a:1 ",
            " cpe:/o:example:product-a:1",
            "cpe:/o:example:product-a",
        ],
        ids=["upper-case", "trailing-space", "leading-space", "prefix"],
    )
    async def test_cpe_matching_is_exact_and_case_sensitive(
        self, db_session: AsyncSession, seed: SeedProduct, upstream: str
    ) -> None:
        await seed("cpe:/o:example:product-a:1")
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, [_item(upstream)])

        assert metrics == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before

    async def test_only_the_four_lifecycle_columns_and_updated_at_change(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        product_repository_factory: Callable[..., Awaitable[ProductRepository]],
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        product = await seed(
            cpe,
            name="Example-Product-A",
            version="15-SP7",
            display_name="Example Product A",
            cvss_threshold=Decimal("7.5"),
        )
        await product_repository_factory(
            product_id=product.id,
            repo_name="EXAMPLE:Updates:A:1:x86_64",
            catalog_last_seen_at=T0,
        )
        await db_session.commit()
        columns = [
            column.name
            for column in Product.__table__.columns
            if column.name not in _date_columns(NO_DATES)
            and column.name != "updated_at"
        ]

        async def untouched() -> dict[str, Any]:
            row = (
                await db_session.execute(
                    select(*(Product.__table__.c[name] for name in columns))
                )
            ).one()
            return dict(zip(columns, row, strict=True))

        async def repositories() -> list[tuple[Any, ...]]:
            rows = await db_session.execute(
                select(*ProductRepository.__table__.columns)
            )
            return [tuple(row) for row in rows]

        before = (await untouched(), await repositories())
        assert before[0]["cvss_threshold"] == Decimal("7.5")
        assert before[0]["catalog_last_seen_at"] == T0

        metrics = await _publish(db_session, [_item(cpe, cvss_threshold=1.0)])

        assert metrics == (1, 0, 1, 0)
        assert (await untouched(), await repositories()) == before
        assert (await _dates(db_session))[cpe] == DEFAULT_DATES

    async def test_response_larger_than_one_select_chunk_matches_every_product(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        items = make_items(1100)
        cpes = sorted(item["cpe"] for item in items)
        first, last = cpes[0], cpes[-1]
        await seed(first)
        await seed(last)

        metrics = await _publish(db_session, items)

        assert metrics == (2, 0, 2, 0)
        dates = await _dates(db_session)
        assert dates == {first: DEFAULT_DATES, last: DEFAULT_DATES}

    async def test_requests_use_the_documented_query_without_deleted_records(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        server = AimaasServer.for_items(make_items(150))

        await _execute(db_session, server)

        assert server.requested_urls == [
            f"{AIMAAS_TEST_PRODUCTS_ENDPOINT}?all_fields=true&size=100&page={page}"
            for page in (1, 2)
        ]
        for request in server.requests:
            assert "all" not in request.url.params
            assert "deleted_only" not in request.url.params

    async def test_configured_request_delay_is_applied_between_pages(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(aimaas_listing, "asyncio", SimpleNamespace(sleep=sleep))
        fetcher = _fetcher(AimaasServer.for_items(make_items(250)))
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.25, custom_settings={}
        )
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert sleeps == [0.25, 0.25]

    async def test_without_run_config_no_delay_is_applied(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(aimaas_listing, "asyncio", SimpleNamespace(sleep=sleep))

        await _publish(db_session, make_items(250))

        assert sleeps == []


# ---------------------------------------------------------------------------
# Metrics (exact outcome and effect counters)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMetrics:
    async def test_changed_product_succeeds_and_is_updated(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:a:1")

        metrics = await _publish(db_session, [_item("cpe:/o:example:a:1")])

        assert metrics == (1, 0, 1, 0)

    async def test_unchanged_product_succeeds_without_update(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:a:1", DEFAULT_DATES)

        metrics = await _publish(db_session, [_item("cpe:/o:example:a:1")])

        assert metrics == (1, 0, 0, 0)

    async def test_incomplete_date_set_succeeds(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:a:1"
        await seed(cpe)
        item = _item(cpe, **{**dict.fromkeys(ALL_DATE_FIELDS), "fcs": "2024-01-15"})

        assert await _publish(db_session, [item]) == (1, 0, 1, 0)
        assert (await _dates(db_session))[cpe] == (date(2024, 1, 15), None, None, None)

    async def test_inconsistent_date_set_succeeds_and_is_persisted(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:a:1"
        await seed(cpe)

        metrics = await _publish(db_session, [_item(cpe, end_of_gs=None)])

        assert metrics == (1, 0, 1, 0)
        assert (await _dates(db_session))[cpe] == (
            DEFAULT_DATES[0],
            None,
            DEFAULT_DATES[2],
            DEFAULT_DATES[3],
        )

    async def test_unmatched_cpe_records_no_metric(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:local:1")

        metrics = await _publish(db_session, [_item("cpe:/o:example:other:1")])

        assert metrics == (0, 0, 0, 0)

    async def test_mixed_run_counts_each_matched_product_once(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:changed:1")
        await seed("cpe:/o:example:unchanged:1", DEFAULT_DATES)
        await seed("cpe:/o:example:incomplete:1", DEFAULT_DATES)
        await seed("cpe:/o:example:inconsistent:1")
        await seed("cpe:/o:example:absent:1")
        items = [
            _item("cpe:/o:example:changed:1"),
            _item("cpe:/o:example:unchanged:1"),
            _item(
                "cpe:/o:example:incomplete:1",
                end_of_ltss=None,
                end_of_reactive_ltss=None,
            ),
            _item("cpe:/o:example:inconsistent:1", end_of_ltss=None),
            _item("cpe:/o:example:unmatched:1", end_of_gs=None),
            _item(None),
            _item(""),
        ]

        with capture_logs() as logs:
            metrics = await _publish(db_session, items)

        assert metrics == (4, 0, 3, 0)
        assert _warnings(logs) == [
            _warning(
                "cpe:/o:example:inconsistent:1",
                LifecycleDateViolation.MISSING_EXTENDED_SUPPORT_END_DATE,
            )
        ]
        (summary,) = [
            log for log in logs if log["event"] == "aimaas_product_lifecycle_published"
        ]
        assert summary == {
            "event": "aimaas_product_lifecycle_published",
            "log_level": "info",
            "aimaas_products": 7,
            "selected": 4,
            "updated": 3,
            "inconsistent": 1,
        }

    async def test_empty_collection_records_nothing_and_changes_nothing(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:a:1", DEFAULT_DATES)
        before = await _product_rows(db_session)
        server = AimaasServer.for_items([])
        assert server.pages[1]["pages"] == 0

        metrics = _metrics(await _execute(db_session, server))

        assert metrics == (0, 0, 0, 0)
        assert server.requested_pages == [1]
        assert await _product_rows(db_session) == before

    async def test_second_identical_run_succeeds_without_updates(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        for cpe in ("cpe:/o:example:a:1", "cpe:/o:example:b:1"):
            await seed(cpe)
        items = [_item("cpe:/o:example:a:1"), _item("cpe:/o:example:b:1")]

        first = await _publish(db_session, items)
        second = await _publish(db_session, items)

        assert (first, second) == ((2, 0, 2, 0), (2, 0, 0, 0))


# ---------------------------------------------------------------------------
# Inconsistency warnings
# ---------------------------------------------------------------------------

_V = LifecycleDateViolation

# (reason, overrides of `product_item()`'s default dates, persisted dates)
_SINGLE_REASONS: Final[list[tuple[LifecycleDateViolation, dict[str, Any], Dates]]] = [
    (
        _V.MISSING_GENERAL_SUPPORT_END_DATE,
        {"end_of_gs": None},
        (date(2024, 1, 15), None, date(2030, 6, 30), date(2032, 6, 30)),
    ),
    (
        _V.MISSING_EXTENDED_SUPPORT_END_DATE,
        {"end_of_ltss": None},
        (date(2024, 1, 15), date(2027, 6, 30), None, date(2032, 6, 30)),
    ),
    (
        _V.FIRST_CUSTOMER_SHIP_AFTER_GENERAL_SUPPORT_END,
        {"fcs": "2027-07-01"},
        (date(2027, 7, 1), date(2027, 6, 30), date(2030, 6, 30), date(2032, 6, 30)),
    ),
    (
        _V.GENERAL_SUPPORT_END_AFTER_EXTENDED_SUPPORT_END,
        {"end_of_gs": "2030-07-01"},
        (date(2024, 1, 15), date(2030, 7, 1), date(2030, 6, 30), date(2032, 6, 30)),
    ),
    (
        _V.EXTENDED_SUPPORT_END_AFTER_REACTIVE_SUPPORT_END,
        {"end_of_espos": "2032-07-01"},
        (date(2024, 1, 15), date(2027, 6, 30), date(2032, 7, 1), date(2032, 6, 30)),
    ),
]


@pytest.mark.integration
class TestInconsistencyWarnings:
    @pytest.mark.parametrize(
        ("reason", "overrides", "persisted"),
        _SINGLE_REASONS,
        ids=[case[0].value for case in _SINGLE_REASONS],
    )
    async def test_each_violated_rule_alone_emits_exactly_one_warning(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        reason: LifecycleDateViolation,
        overrides: dict[str, Any],
        persisted: Dates,
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe)
        item = _item(cpe, **overrides, name=MARKER, slug=MARKER)

        with capture_logs() as logs:
            fetcher = await _execute(db_session, AimaasServer.for_items([item]))

        assert _warnings(logs) == [_warning(cpe, reason)]
        assert MARKER not in repr(logs)
        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert (await _dates(db_session))[cpe] == persisted

    async def test_combination_emits_one_warning_per_violated_rule(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe)
        item = _item(
            cpe,
            fcs="2034-01-01",
            end_of_gs="2033-01-01",
            end_of_ltss="2032-01-01",
            end_of_espos=None,
            end_of_reactive_ltss="2031-01-01",
        )

        with capture_logs() as logs:
            metrics = await _publish(db_session, [item])

        assert _warnings(logs) == [
            _warning(cpe, _V.FIRST_CUSTOMER_SHIP_AFTER_GENERAL_SUPPORT_END),
            _warning(cpe, _V.GENERAL_SUPPORT_END_AFTER_EXTENDED_SUPPORT_END),
            _warning(cpe, _V.EXTENDED_SUPPORT_END_AFTER_REACTIVE_SUPPORT_END),
        ]
        assert metrics == (1, 0, 1, 0)

    async def test_missing_rule_combined_with_an_order_rule(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe)
        item = _item(cpe, end_of_gs=None, end_of_ltss="2033-01-01")

        with capture_logs() as logs:
            await _publish(db_session, [item])

        assert _warnings(logs) == [
            _warning(cpe, _V.MISSING_GENERAL_SUPPORT_END_DATE),
            _warning(cpe, _V.EXTENDED_SUPPORT_END_AFTER_REACTIVE_SUPPORT_END),
        ]

    async def test_unchanged_inconsistent_product_still_warns(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, (DEFAULT_DATES[0], None, DEFAULT_DATES[2], DEFAULT_DATES[3]))

        with capture_logs() as logs:
            metrics = await _publish(db_session, [_item(cpe, end_of_gs=None)])

        assert metrics == (1, 0, 0, 0)
        assert _warnings(logs) == [_warning(cpe, _V.MISSING_GENERAL_SUPPORT_END_DATE)]

    @pytest.mark.parametrize(
        "overrides",
        [
            dict.fromkeys(ALL_DATE_FIELDS),
            {**dict.fromkeys(ALL_DATE_FIELDS), "fcs": "2024-01-15"},
            {**dict.fromkeys(ALL_DATE_FIELDS), "end_of_gs": "2027-06-30"},
            {"end_of_reactive_ltss": None},
            {"fcs": None},
            {"fcs": "2027-06-30", "end_of_ltss": "2027-06-30"},
        ],
        ids=[
            "nothing",
            "fcs-only",
            "gs-only",
            "no-reactive",
            "no-fcs",
            "equal-boundaries",
        ],
    )
    async def test_consistent_or_incomplete_dates_emit_no_warning(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        overrides: dict[str, Any],
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, DEFAULT_DATES)

        with capture_logs() as logs:
            metrics = await _publish(db_session, [_item(cpe, **overrides)])

        assert _warnings(logs) == []
        assert metrics == (1, 0, 1, 0)

    async def test_unmatched_inconsistent_entries_emit_no_warning(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:local:1", DEFAULT_DATES)
        items = [
            _item("cpe:/o:example:unmatched:1", end_of_gs=None),
            _item(None, fcs="2040-01-01"),
            _item("", end_of_ltss=None),
        ]

        with capture_logs() as logs:
            metrics = await _publish(db_session, items)

        assert _warnings(logs) == []
        assert metrics == (0, 0, 0, 0)

    async def test_warnings_are_emitted_after_the_single_commit(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cpes = ["cpe:/o:example:a:1", "cpe:/o:example:b:1"]
        for cpe in cpes:
            await seed(cpe)
        original_commit = db_session.commit
        commits: list[int] = []

        with capture_logs() as logs:

            async def recording_commit() -> None:
                await original_commit()
                commits.append(len(logs))

            monkeypatch.setattr(db_session, "commit", recording_commit)
            await _publish(db_session, [_item(cpe, end_of_gs=None) for cpe in cpes])

        (committed_at,) = commits
        positions = [
            index for index, entry in enumerate(logs) if entry["event"] == WARNING_EVENT
        ]
        assert len(positions) == 2
        assert min(positions) >= committed_at


# ---------------------------------------------------------------------------
# Transaction boundaries and failures (steps 1, 2, and 8; Error Handling)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionBoundaries:
    async def test_every_request_completes_before_any_database_statement(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        items = make_items(250)
        await seed(items[0]["cpe"])
        await seed(items[-1]["cpe"], DEFAULT_DATES)
        await db_session.commit()
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            fetcher = await _execute(
                db_session, AimaasServer.for_items(items, events=events)
            )

        kinds = [kind for kind, _ in events]
        assert kinds.count("http") == 3
        assert "sql" in kinds
        assert kinds == sorted(kinds)  # every "http" precedes every "sql"
        assert _metrics(fetcher) == (2, 0, 1, 0)

    @pytest.mark.parametrize("stage", ["update", "commit"])
    async def test_database_failure_rolls_back_the_complete_publication(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
    ) -> None:
        cpes = [f"cpe:/o:example:product-{index}:1" for index in range(3)]
        for cpe in cpes:
            await seed(cpe)
        await db_session.commit()
        before = await _product_rows(db_session)
        failure = OperationalError("UPDATE", {}, Exception(MARKER))
        original_execute = db_session.execute

        async def failing_execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            result = await original_execute(statement, *args, **kwargs)
            if isinstance(statement, Update):
                raise failure
            return result

        async def failing_commit() -> None:
            raise failure

        if stage == "update":
            monkeypatch.setattr(db_session, "execute", failing_execute)
        else:
            monkeypatch.setattr(db_session, "commit", failing_commit)
        items = [_item(cpe, end_of_gs=None, name=MARKER) for cpe in cpes]

        with capture_logs() as logs:
            error, fetcher = await _execute_failing(
                db_session, AimaasServer.for_items(items)
            )
        await db_session.rollback()

        assert str(error) == PUBLICATION_FAILED_MESSAGE
        assert error.__cause__ is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before
        assert logs == [
            {
                "event": "aimaas_product_lifecycle_publication_failed",
                "log_level": "warning",
            }
        ]


def _http_500(server: AimaasServer) -> None:
    server.responses[2] = lambda request: httpx.Response(500)


def _connect_error(server: AimaasServer) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("example connection failure", request=request)

    server.responses[1] = respond


def _read_timeout(server: AimaasServer) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("example timeout", request=request)

    server.responses[3] = respond


def _invalid_pagination(server: AimaasServer) -> None:
    server.pages[2]["total"] = 251


def _missing_cpe(server: AimaasServer) -> None:
    del server.pages[3]["items"][0]["cpe"]


def _nul_cpe(server: AimaasServer) -> None:
    server.pages[2]["items"][7]["cpe"] = "cpe:/o:example:nul\x00:1"


def _invalid_date(server: AimaasServer) -> None:
    server.pages[2]["items"][5]["end_of_gs"] = "2026-02-30"


def _missing_date(server: AimaasServer) -> None:
    del server.pages[1]["items"][0]["end_of_reactive_ltss"]


def _duplicate_cpe(server: AimaasServer) -> None:
    server.pages[3]["items"][0]["cpe"] = server.pages[1]["items"][0]["cpe"]


FailureCase = tuple[str, Callable[[AimaasServer], None], str, type[BaseException]]

_RUN_FAILURES: Final[list[FailureCase]] = [
    ("http-status", _http_500, "AIMAAS returned HTTP 500", httpx.HTTPStatusError),
    ("connection", _connect_error, "Failed to connect to AIMAAS", httpx.ConnectError),
    ("timeout", _read_timeout, "AIMAAS request timed out", httpx.ReadTimeout),
    (
        "pagination",
        _invalid_pagination,
        INVALID_RESPONSE_MESSAGE,
        InvalidAimaasListingError,
    ),
    ("missing-cpe", _missing_cpe, INVALID_RESPONSE_MESSAGE, LifecycleResponseError),
    ("nul-cpe", _nul_cpe, INVALID_RESPONSE_MESSAGE, LifecycleResponseError),
    ("invalid-date", _invalid_date, INVALID_RESPONSE_MESSAGE, LifecycleResponseError),
    ("missing-date", _missing_date, INVALID_RESPONSE_MESSAGE, LifecycleResponseError),
    (
        "duplicate-cpe",
        _duplicate_cpe,
        VALIDATION_FAILED_MESSAGE,
        LifecycleValidationError,
    ),
]


@pytest.mark.integration
class TestWholeRunFailureBeforePublication:
    @pytest.mark.parametrize(
        ("break_server", "message", "cause"),
        [case[1:] for case in _RUN_FAILURES],
        ids=[case[0] for case in _RUN_FAILURES],
    )
    async def test_failure_publishes_nothing_and_executes_no_sql(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        break_server: Callable[[AimaasServer], None],
        message: str,
        cause: type[BaseException],
    ) -> None:
        items = make_items(250)
        for item in (items[0], items[120], items[249]):
            await seed(item["cpe"])
        await db_session.commit()
        before = await _product_rows(db_session)
        server = AimaasServer.for_items(items)
        break_server(server)
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events), capture_logs() as logs:
            error, fetcher = await _execute_failing(db_session, server)

        assert str(error) == message
        assert isinstance(error.__cause__, cause)
        assert "aimaas.example.test" not in str(error)
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert events == []
        assert _warnings(logs) == []
        assert await _product_rows(db_session) == before

    def test_failure_messages_are_the_specified_values(self) -> None:
        assert INVALID_RESPONSE_MESSAGE == (
            "AIMAAS returned invalid Product lifecycle response"
        )
        assert VALIDATION_FAILED_MESSAGE == "AIMAAS Product lifecycle validation failed"
        assert PUBLICATION_FAILED_MESSAGE == (
            "Failed to synchronize AIMAAS lifecycle dates"
        )

    async def test_duplicate_cpe_log_names_category_without_payload(
        self, db_session: AsyncSession
    ) -> None:
        items = [_item(MARKER), _item("cpe:/o:example:b:1"), _item(MARKER)]

        with capture_logs() as logs:
            error, _ = await _execute_failing(db_session, AimaasServer.for_items(items))

        assert logs == [
            {
                "event": "aimaas_product_lifecycle_validation_failed",
                "log_level": "warning",
                "category": "item 2: duplicate cpe",
            }
        ]
        assert MARKER not in str(error)

    async def test_schema_failure_log_names_category_without_payload(
        self, db_session: AsyncSession
    ) -> None:
        items = [_item("cpe:/o:example:a:1"), _item(MARKER, fcs=MARKER)]

        with capture_logs() as logs:
            error, _ = await _execute_failing(db_session, AimaasServer.for_items(items))

        assert logs == [
            {
                "event": "aimaas_product_lifecycle_response_invalid",
                "log_level": "warning",
                "category": "item 1: fcs is not a date",
            }
        ]
        assert MARKER not in str(error)
        assert MARKER not in str(error.__cause__)


# ---------------------------------------------------------------------------
# No Ticket audit event (ticket-audit-log.md matrix row; TR 12)
# ---------------------------------------------------------------------------

# Date-stable projections relative to any plausible current UTC date.
_EOL_ITEM_DATES: Final = {
    "fcs": "2000-01-03",
    "end_of_gs": "2001-01-31",
    "end_of_ltss": "2002-01-31",
    "end_of_espos": None,
    "end_of_reactive_ltss": "2003-01-31",
}
_REACTIVE_ITEM_DATES: Final = {
    "fcs": "2000-01-03",
    "end_of_gs": "2001-01-31",
    "end_of_ltss": "2002-01-31",
    "end_of_espos": None,
    "end_of_reactive_ltss": "2099-12-31",
}


@pytest.mark.integration
class TestNoTicketAuditEvent:
    async def test_effective_and_no_op_publications_create_no_ticket_event(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    ) -> None:
        eol_cpe = "cpe:/o:example:eol:1"
        reactive_cpe = "cpe:/o:example:reactive:1"
        unchanged_cpe = "cpe:/o:example:unchanged:1"
        products = [
            await seed(eol_cpe, DEFAULT_DATES),
            await seed(reactive_cpe, DEFAULT_DATES),
            await seed(unchanged_cpe, DEFAULT_DATES),
        ]
        ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        for product in products:
            await ticket_package_product_factory(
                ticket_package_track_id=track.id, product_id=product.id
            )
        await ticket_factory()  # a Ticket without a package tree
        await db_session.commit()

        async def tree_state() -> list[tuple[Any, ...]]:
            tickets = await db_session.execute(
                select(Ticket.id, Ticket.status, Ticket.updated_at).order_by(Ticket.id)
            )
            packages = await db_session.execute(
                select(TicketPackage.id, TicketPackage.deleted_at)
            )
            tracks = await db_session.execute(
                select(
                    TicketPackageTrack.id,
                    TicketPackageTrack.status,
                    TicketPackageTrack.delivery_status,
                    TicketPackageTrack.deleted_at,
                )
            )
            occurrences = await db_session.execute(
                select(
                    TicketPackageProduct.id,
                    TicketPackageProduct.product_id,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                    TicketPackageProduct.released_at,
                    TicketPackageProduct.deleted_at,
                    TicketPackageProduct.updated_at,
                ).order_by(TicketPackageProduct.id)
            )
            return [
                tuple(row)
                for result in (tickets, packages, tracks, occurrences)
                for row in result
            ]

        async def event_count() -> int:
            return (
                await db_session.execute(select(func.count(TicketAuditEvent.id)))
            ).scalar_one()

        tree_before = await tree_state()
        assert await event_count() == 0
        items = [
            _item(eol_cpe, **_EOL_ITEM_DATES),
            _item(reactive_cpe, **_REACTIVE_ITEM_DATES),
            _item(unchanged_cpe),
        ]

        effective = await _publish(db_session, items)
        no_op = await _publish(db_session, items)

        assert (effective, no_op) == ((3, 0, 2, 0), (3, 0, 0, 0))
        today = datetime.now(UTC).date()
        dates = await _dates(db_session)
        phases = {
            cpe: evaluate_product_lifecycle_phase(
                evaluation_date=today,
                first_customer_ship_date=dates[cpe][0],
                general_support_end_date=dates[cpe][1],
                extended_support_end_date=dates[cpe][2],
                reactive_support_end_date=dates[cpe][3],
            )
            for cpe in (eol_cpe, reactive_cpe)
        }
        assert phases == {
            eol_cpe: LifecyclePhase.EOL,
            reactive_cpe: LifecyclePhase.REACTIVE_SUPPORT,
        }
        assert await event_count() == 0
        assert await tree_state() == tree_before


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------

RunSetup = Callable[[AimaasServer, dict[str, Dates]], Awaitable[uuid.UUID]]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RunSetup]:
    """Commit seeded Products and a `running` FetcherRun; route `run()`.

    `run()` opens its own sessions through `base_fetcher`'s
    `async_session_factory` and creates its HTTP client through
    `create_http_client`; both are redirected here. Every committed row
    (the seeded Products, FetcherConfig, and FetcherRun) is deleted at
    teardown.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    fetcher_name = f"test_aimaas_run_{uuid.uuid4().hex[:12]}"
    seeded: list[str] = []

    async def setup(server: AimaasServer, products: dict[str, Dates]) -> uuid.UUID:
        monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: server.client(),
        )
        async with real_session_factory() as session:
            for index, (cpe, dates) in enumerate(products.items()):
                seeded.append(cpe)
                session.add(
                    Product(
                        cpe=cpe,
                        name=f"Example Run Product {index}",
                        version=str(index),
                        display_name=f"Example Run Product {index}",
                        catalog_last_seen_at=T0,
                        **_date_columns(dates),
                    )
                )
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
        async with real_session_factory() as session:
            await session.execute(delete(Product).where(Product.cpe.in_(seeded)))
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


async def _committed_dates(
    real_session_factory: async_sessionmaker[AsyncSession], cpes: list[str]
) -> dict[str, Dates]:
    async with real_session_factory() as session:
        dates = await _dates(session)
    return {cpe: dates[cpe] for cpe in cpes}


@pytest.mark.integration
class TestRunLifecycle:
    async def test_successful_run_is_finalized_with_exact_counters(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        suffix = uuid.uuid4().hex[:12]
        changed = f"cpe:/o:example:run-{suffix}:changed"
        unchanged = f"cpe:/o:example:run-{suffix}:unchanged"
        items = [
            _item(changed),
            _item(unchanged),
            _item(f"cpe:/o:example:run-{suffix}:unmatched"),
        ]
        run_id = await committed_run(
            AimaasServer.for_items(items),
            {changed: NO_DATES, unchanged: DEFAULT_DATES},
        )

        await SyncAimaasLifecycle().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (2, 0, 1, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        assert await _committed_dates(real_session_factory, [changed, unchanged]) == {
            changed: DEFAULT_DATES,
            unchanged: DEFAULT_DATES,
        }

    async def test_failed_run_is_finalized_with_sanitized_message(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        suffix = uuid.uuid4().hex[:12]
        items = [_item(f"cpe:/o:example:run-{suffix}:{index}") for index in range(250)]
        server = AimaasServer.for_items(items)
        server.responses[2] = lambda request: httpx.Response(503)
        seeded = {items[0]["cpe"]: NO_DATES}
        run_id = await committed_run(server, seeded)

        with pytest.raises(FetcherError, match=r"^AIMAAS returned HTTP 503$"):
            await SyncAimaasLifecycle().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "AIMAAS returned HTTP 503"
        assert run.error_detail is not None
        assert run.error_traceback is not None
        assert "aimaas.example.test" not in run.error_message
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (0, 0, 0, 0)
        assert await _committed_dates(real_session_factory, list(seeded)) == seeded


# ---------------------------------------------------------------------------
# Registration and properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY["sync_aimaas_lifecycle"] is SyncAimaasLifecycle

    def test_properties_match_the_specification(self) -> None:
        assert SyncAimaasLifecycle.name == "sync_aimaas_lifecycle"
        assert SyncAimaasLifecycle.description == (
            "Synchronize AIMAAS Product lifecycle dates"
        )
        assert SyncAimaasLifecycle.default_schedule == "15 2 * * *"
        assert SyncAimaasLifecycle.participates_in_catch_up is False
        assert SyncAimaasLifecycle.Settings is None
        assert SyncAimaasLifecycle.queue is None

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(
            part.capitalize() for part in SyncAimaasLifecycle.name.split("_")
        )

        assert derived == SyncAimaasLifecycle.__name__ == "SyncAimaasLifecycle"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert "sync_aimaas_lifecycle" not in get_catch_up_fetchers()


@pytest.mark.integration
class TestBootstrap:
    async def test_bootstrap_creates_the_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, "sync_aimaas_lifecycle") is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, "sync_aimaas_lifecycle")
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == 0
        assert config.custom_settings == {}
