"""Tests for the `sync_aimaas_thresholds` fetcher.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Origin, Authentication, and Pagination; Deleted Flag
Semantics; CVSS Threshold Sync, consumed-field schema and steps 1-10;
SMELT Decoupling; Fetcher: `sync_aimaas_thresholds`, properties, Error
Handling, and Metrics), docs/features/packages/
product-lifecycle-transitions.md (Integration with AIMAAS Synchronization),
docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base Class:
execution-session transaction contract, Finalization, Outcome and effect
accounting; Error Message Sanitization; Registry; Fetcher Discovery),
docs/conventions.md (Transaction Hygiene Rules: no broker I/O inside a
transaction), docs/features/platform/testing-strategy.md (Fetcher Outcome
and Effect Accounting), and docs/features/tickets/ticket-audit-log.md
(Canonical Mutation and No-Event Matrix row "Product catalog source
mutation or workflow-only dispatch/checkpoint outcome"; Testing
Requirement 12).

The parsers, `threshold_value()`, `validate_response()`,
`resolve_thresholds()`, and the fetcher properties are unit tests.
Publication tests call `execute(db_session)` against Products seeded
directly: the fetcher's commits release savepoints of the per-test outer
transaction, so every row is rolled back at teardown. The `run()`
lifecycle tests commit through `real_session_factory` and delete every row
they create. AIMAAS is the fake router of `tests/support/aimaas.py`,
injected as the fetcher's HTTP client. The post-commit dispatch is
substituted by an autouse recorder; the end-to-end test instead substitutes
the broker call `celery_app.send_task`. The fetcher clock is fixed to `EVAL`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import Mock

import httpx
import pytest
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import Select, Update, delete, event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.celery_app import celery_app
from app.config import settings
from app.core.enums import TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import fetcher_discovery
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.packages import aimaas_listing
from app.services.packages import sync_aimaas_thresholds as sync_module
from app.services.packages.aimaas_listing import (
    PRODUCTS_ENDPOINT_PATH,
    InvalidAimaasListingError,
)
from app.services.packages.product_eligibility_mismatch import (
    find_product_eligibility_mismatches,
)
from app.services.packages.product_eligibility_recalculation import (
    dispatch_product_eligibility_recalculation,
)
from app.services.packages.sync_aimaas_thresholds import (
    INVALID_PRODUCT_LIST_MESSAGE,
    INVALID_THRESHOLD_LIST_MESSAGE,
    PUBLICATION_FAILED_MESSAGE,
    THRESHOLDS_ENDPOINT_PATH,
    VALIDATION_FAILED_MESSAGE,
    AimaasProductRef,
    SyncAimaasThresholds,
    ThresholdEntry,
    ThresholdResponseError,
    ThresholdValidationError,
    ValidatedResponse,
    parse_product_refs,
    parse_threshold_entries,
    resolve_thresholds,
    threshold_value,
    validate_response,
)
from tests.support.aimaas import AIMAAS_TEST_API_URL as API_URL
from tests.support.aimaas import (
    AIMAAS_TEST_PRODUCTS_ENDPOINT,
    AIMAAS_TEST_THRESHOLDS_ENDPOINT,
    PRODUCT_LIST_PAGES,
    THRESHOLD_FIXTURE_PAGES,
    AimaasRouter,
    AimaasServer,
    load_products_page,
    load_thresholds_page,
    product_item,
    threshold_item,
    threshold_sync_router,
)
from tests.support.ticket_mutations import EVAL

MARKER: Final = "Example-Confidential-Aimaas-Value"
T0: Final = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
OLD_UPDATED_AT: Final = datetime(2020, 1, 1, tzinfo=UTC)
DEFAULT_VERSION: Final = "3.1"
UNRESOLVED_EVENT: Final = "aimaas_cvss_threshold_product_unresolved"
DISPATCH_FAILED_EVENT: Final = "aimaas_cvss_threshold_dispatch_failed"
SUMMARY_EVENT: Final = "aimaas_cvss_thresholds_published"

_REAL_UTC_TODAY = sync_module._utc_today

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class DispatchRecorder:
    """Substitute for `dispatch_product_eligibility_recalculation()`.

    Records each `(catalog_product_id, reason)`; raises the configured
    exception for a Product in `failures`; when `session` is set, records
    whether that session had an open transaction at dispatch time; when
    `events` is set, appends `"dispatch"` to it.
    """

    calls: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    failures: dict[uuid.UUID, BaseException] = field(default_factory=dict)
    session: AsyncSession | None = None
    in_transaction: list[bool] = field(default_factory=list)
    events: list[str] | None = None

    async def __call__(self, catalog_product_id: uuid.UUID, reason: str) -> None:
        self.calls.append((catalog_product_id, reason))
        if self.events is not None:
            self.events.append("dispatch")
        if self.session is not None:
            self.in_transaction.append(self.session.in_transaction())
        error = self.failures.get(catalog_product_id)
        if error is not None:
            raise error

    @property
    def product_ids(self) -> list[uuid.UUID]:
        return [product_id for product_id, _ in self.calls]


@pytest.fixture(autouse=True)
def _fictional_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the fetcher at the fictional AIMAAS origin."""
    monkeypatch.setattr(settings, "aimaas_api_url", API_URL)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """The fetcher's UTC clock, fixed to `EVAL`."""
    today = Mock(return_value=EVAL)
    monkeypatch.setattr(sync_module, "_utc_today", today)
    return today


@pytest.fixture(autouse=True)
def dispatcher(monkeypatch: pytest.MonkeyPatch) -> DispatchRecorder:
    """Substitute the post-commit dispatch: no test reaches a broker."""
    recorder = DispatchRecorder()
    monkeypatch.setattr(
        sync_module, "dispatch_product_eligibility_recalculation", recorder
    )
    return recorder


@pytest.fixture
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


def _router(
    products: Mapping[int, str | None],
    thresholds: Mapping[int, Any],
    *,
    events: list[tuple[str, str]] | None = None,
) -> AimaasRouter:
    """AIMAAS Product IDs → `cpe`, and AIMAAS Product IDs → `threshold`."""
    return threshold_sync_router(
        [product_item(pid, cpe=cpe) for pid, cpe in products.items()],
        [
            threshold_item(pid, product=pid, threshold=v)
            for pid, v in thresholds.items()
        ],
        events=events,
    )


def _metrics(fetcher: SyncAimaasThresholds) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def _fetcher(router: AimaasRouter) -> SyncAimaasThresholds:
    fetcher = SyncAimaasThresholds()
    fetcher._http_client = router.client()
    return fetcher


async def _execute(db: AsyncSession, router: AimaasRouter) -> SyncAimaasThresholds:
    fetcher = _fetcher(router)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _publish(
    db: AsyncSession,
    products: Mapping[int, str | None],
    thresholds: Mapping[int, Any],
) -> Metrics:
    """Run one complete synchronization and return its metrics."""
    return _metrics(await _execute(db, _router(products, thresholds)))


async def _execute_failing(
    db: AsyncSession, router: AimaasRouter, error: type[BaseException] = FetcherError
) -> tuple[BaseException, SyncAimaasThresholds]:
    fetcher = _fetcher(router)
    try:
        with pytest.raises(error) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


SeedProduct = Callable[..., Awaitable[Product]]


@pytest.fixture
def seed(product_factory: Callable[..., Awaitable[Product]]) -> SeedProduct:
    """Seed one local Product with a threshold and an old `updated_at`."""

    async def _seed(
        cpe: str, threshold: str | None = None, **overrides: Any
    ) -> Product:
        return await product_factory(
            cpe=cpe,
            cvss_threshold=None if threshold is None else Decimal(threshold),
            catalog_last_seen_at=T0,
            updated_at=OLD_UPDATED_AT,
            **overrides,
        )

    return _seed


async def _thresholds(db: AsyncSession) -> dict[str, Decimal | None]:
    """Every persisted Product: CPE → `cvss_threshold`."""
    rows = await db.execute(select(Product.cpe, Product.cvss_threshold))
    return {row.cpe: row.cvss_threshold for row in rows}


async def _updated_at(db: AsyncSession) -> dict[str, datetime]:
    rows = await db.execute(select(Product.cpe, Product.updated_at))
    return {row.cpe: row.updated_at for row in rows}


async def _product_rows(db: AsyncSession) -> dict[str, tuple[Any, ...]]:
    """Every persisted Product: CPE → every column (complete state)."""
    rows = await db.execute(select(*Product.__table__.columns))
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


def _logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _unresolved(aimaas_product_id: int) -> dict[str, Any]:
    return {
        "event": UNRESOLVED_EVENT,
        "log_level": "warning",
        "aimaas_product_id": aimaas_product_id,
    }


Placer = Callable[..., Awaitable[TicketPackageProduct]]


@pytest.fixture
def place(
    ticket_factory: Callable[..., Awaitable[Ticket]],
    ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
    ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
    ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
) -> Placer:
    """One occurrence of `product` with the stored `eligible` in a fresh
    `Analysis` Ticket (CVE-less unless `cve_id` is given)."""

    async def _place(
        product: Product, *, eligible: bool, cve_id: uuid.UUID | None = None
    ) -> TicketPackageProduct:
        ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve_id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        return await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=eligible
        )

    return _place


# ---------------------------------------------------------------------------
# Response parsing (consumed-field schema)
# ---------------------------------------------------------------------------


def _product_error(items: list[dict[str, Any]]) -> ThresholdResponseError:
    with pytest.raises(ThresholdResponseError) as raised:
        parse_product_refs(items)
    return raised.value


def _threshold_error(items: list[dict[str, Any]]) -> ThresholdResponseError:
    with pytest.raises(ThresholdResponseError) as raised:
        parse_threshold_entries(items)
    return raised.value


@pytest.mark.unit
class TestParseProductRefs:
    def test_id_and_cpe_are_projected_in_response_order(self) -> None:
        items = [
            product_item(7, cpe="cpe:/o:example:a:1"),
            product_item(3, cpe="cpe:/o:example:b:1"),
        ]

        assert parse_product_refs(items) == [
            AimaasProductRef(id=7, cpe="cpe:/o:example:a:1"),
            AimaasProductRef(id=3, cpe="cpe:/o:example:b:1"),
        ]

    @pytest.mark.parametrize("cpe", [None, ""], ids=["null", "empty"])
    def test_null_or_empty_cpe_is_unmatchable(self, cpe: str | None) -> None:
        assert parse_product_refs([product_item(4, cpe=cpe)]) == [
            AimaasProductRef(id=4, cpe=None)
        ]

    def test_cpe_is_preserved_exactly(self) -> None:
        cpe = " CPE:/O:Example:A:1\t"

        assert parse_product_refs([product_item(1, cpe=cpe)])[0].cpe == cpe

    def test_ignored_and_unknown_fields_do_not_affect_parsing(self) -> None:
        noisy = {
            **product_item(1, cpe="cpe:/o:example:a:1"),
            "fcs": "not-a-date",
            "deleted": "yes",
            "unknown_field": {"nested": [MARKER]},
        }

        assert parse_product_refs([noisy]) == parse_product_refs(
            [{"id": 1, "cpe": "cpe:/o:example:a:1"}]
        )

    @pytest.mark.parametrize("field", ["id", "cpe"])
    def test_missing_key_is_a_response_error(self, field: str) -> None:
        item = product_item(2, cpe="cpe:/o:example:b:1")
        del item[field]

        error = _product_error([product_item(1, cpe="cpe:/o:example:a:1"), item])

        assert str(error) == f"item 1: {field} is missing"

    @pytest.mark.parametrize(
        "value",
        ["7", 7.0, None, True, False, [7], MARKER],
        ids=["string", "float", "null", "true", "false", "list", "marker"],
    )
    def test_non_integer_id_is_a_response_error(self, value: Any) -> None:
        error = _product_error([product_item(1, id=value)])

        assert str(error) == "item 0: id must be an integer"
        assert MARKER not in str(error)

    @pytest.mark.parametrize(
        "value", [7, True, ["cpe:/o:example:a:1"], {"cpe": MARKER}, 1.5]
    )
    def test_non_string_cpe_is_a_response_error(self, value: Any) -> None:
        error = _product_error([product_item(1, cpe=value)])

        assert str(error) == "item 0: cpe must be a string"
        assert MARKER not in str(error)

    @pytest.mark.parametrize(
        "value",
        ["\x00", f"\x00{MARKER}", f"{MARKER}\x00{MARKER}", f"{MARKER}\x00"],
        ids=["only", "start", "middle", "end"],
    )
    def test_cpe_containing_nul_is_a_response_error(self, value: str) -> None:
        """External String Admissibility: not unmatchable, not stripped."""
        error = _product_error([product_item(1, cpe=value)])

        assert str(error) == "item 0: cpe contains U+0000"
        assert MARKER not in str(error)

    def test_empty_response_yields_no_refs(self) -> None:
        assert parse_product_refs([]) == []


@pytest.mark.unit
class TestParseThresholdEntries:
    def test_product_and_threshold_are_projected_in_response_order(self) -> None:
        items = [
            threshold_item(1, product=9, threshold=7.0),
            threshold_item(2, product=4, threshold=4),
        ]

        assert parse_threshold_entries(items) == [
            ThresholdEntry(product=9, threshold=7.0),
            ThresholdEntry(product=4, threshold=4),
        ]

    def test_threshold_value_is_not_checked_by_parsing(self) -> None:
        """The value is validated by the complete-response validation."""
        items = [threshold_item(1, product=1, threshold=MARKER)]

        assert parse_threshold_entries(items) == [
            ThresholdEntry(product=1, threshold=MARKER)
        ]

    def test_ignored_and_unknown_fields_do_not_affect_parsing(self) -> None:
        noisy = {
            **threshold_item(1, product=5, threshold=9.0),
            "id": "not-an-integer",
            "deleted": "yes",
            "slug": None,
            "unknown_field": [MARKER],
        }

        assert parse_threshold_entries([noisy]) == parse_threshold_entries(
            [{"product": 5, "threshold": 9.0}]
        )

    @pytest.mark.parametrize("field", ["product", "threshold"])
    def test_missing_key_is_a_response_error(self, field: str) -> None:
        item = threshold_item(2, product=2)
        del item[field]

        error = _threshold_error([threshold_item(1, product=1), item])

        assert str(error) == f"item 1: {field} is missing"

    def test_explicit_null_threshold_is_not_a_missing_key(self) -> None:
        assert parse_threshold_entries([threshold_item(1, product=1, threshold=None)])

    @pytest.mark.parametrize(
        "value",
        ["7", 7.0, None, True, False, [7], MARKER],
        ids=["string", "float", "null", "true", "false", "list", "marker"],
    )
    def test_non_integer_product_is_a_response_error(self, value: Any) -> None:
        error = _threshold_error([threshold_item(1, product=value)])

        assert str(error) == "item 0: product must be an integer"
        assert MARKER not in str(error)

    def test_empty_response_yields_no_entries(self) -> None:
        assert parse_threshold_entries([]) == []


# ---------------------------------------------------------------------------
# Threshold value and complete-response validation (step 2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestThresholdValue:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (7, "7.0"),
            (0, "0.0"),
            (10, "10.0"),
            (7.0, "7.0"),
            (0.0, "0.0"),
            (10.0, "10.0"),
            (4.5, "4.5"),
            (9.9, "9.9"),
            (0.1, "0.1"),
            (-0.0, "0.0"),
        ],
    )
    def test_valid_value_is_the_one_decimal_persisted_value(
        self, value: float, expected: str
    ) -> None:
        result = threshold_value(value)

        assert result == Decimal(expected)
        assert result is not None
        assert result.as_tuple().exponent == -1

    @pytest.mark.parametrize(
        "value",
        [
            7.05,
            4.55,
            1e-05,
            -0.1,
            -1,
            10.1,
            11,
            10**30,
            float("nan"),
            float("inf"),
            float("-inf"),
            True,
            False,
            "7.0",
            None,
            [7.0],
            {"value": 7.0},
        ],
        ids=[
            "two-decimals",
            "two-decimals-half",
            "tiny",
            "negative",
            "negative-int",
            "above-ten",
            "above-ten-int",
            "huge-int",
            "nan",
            "inf",
            "negative-inf",
            "true",
            "false",
            "string",
            "null",
            "list",
            "object",
        ],
    )
    def test_invalid_value_is_rejected(self, value: Any) -> None:
        assert threshold_value(value) is None


def _refs(*pairs: tuple[int, str | None]) -> list[AimaasProductRef]:
    return [AimaasProductRef(id=pid, cpe=cpe) for pid, cpe in pairs]


def _entries(*pairs: tuple[int, Any]) -> list[ThresholdEntry]:
    return [ThresholdEntry(product=pid, threshold=value) for pid, value in pairs]


def _validation_error(
    products: list[AimaasProductRef], thresholds: list[ThresholdEntry]
) -> ThresholdValidationError:
    with pytest.raises(ThresholdValidationError) as raised:
        validate_response(products, thresholds)
    return raised.value


@pytest.mark.unit
class TestValidateResponse:
    def test_returns_the_join_inputs(self) -> None:
        response = validate_response(
            _refs((1, "cpe:/o:example:a:1"), (2, None)),
            _entries((1, 7.0), (2, 4)),
        )

        assert response == ValidatedResponse(
            cpe_by_product_id={1: "cpe:/o:example:a:1", 2: None},
            thresholds=[(1, Decimal("7.0")), (2, Decimal("4.0"))],
        )

    def test_duplicate_id_is_rejected(self) -> None:
        error = _validation_error(
            _refs((1, "cpe:/o:example:a:1"), (2, "cpe:/o:example:b:1"), (1, MARKER)),
            [],
        )

        assert str(error) == "product 2: duplicate id"

    def test_duplicate_non_empty_cpe_is_rejected(self) -> None:
        error = _validation_error(_refs((1, MARKER), (2, None), (3, MARKER)), [])

        assert str(error) == "product 2: duplicate cpe"
        assert MARKER not in str(error)

    def test_several_unmatchable_cpes_are_allowed(self) -> None:
        response = validate_response(_refs((1, None), (2, None), (3, None)), [])

        assert response.cpe_by_product_id == {1: None, 2: None, 3: None}

    def test_duplicate_product_is_rejected(self) -> None:
        error = _validation_error([], _entries((5, 7.0), (6, 7.0), (5, 9.0)))

        assert str(error) == "threshold 2: duplicate product"

    @pytest.mark.parametrize("value", [7.05, 10.1, -0.1, None, True, MARKER])
    def test_invalid_threshold_is_rejected(self, value: Any) -> None:
        error = _validation_error([], _entries((1, 7.0), (2, value)))

        assert str(error) == "threshold 1: threshold out of range"
        assert MARKER not in str(error)

    def test_threshold_of_an_unlisted_product_is_valid(self) -> None:
        """Resolution, not validation, handles an unresolved Product."""
        response = validate_response(_refs((1, "cpe:/o:example:a:1")), _entries((9, 7)))

        assert response.thresholds == [(9, Decimal("7.0"))]

    def test_empty_response_is_valid(self) -> None:
        assert validate_response([], []) == ValidatedResponse({}, [])


@pytest.mark.unit
class TestResolveThresholds:
    def test_resolved_cpes_map_to_their_thresholds(self) -> None:
        response = ValidatedResponse(
            cpe_by_product_id={1: "cpe:/o:example:a:1", 2: "cpe:/o:example:b:1"},
            thresholds=[(2, Decimal("4.0")), (1, Decimal("7.0"))],
        )

        with capture_logs() as logs:
            resolved = resolve_thresholds(response)

        assert resolved == {
            "cpe:/o:example:a:1": Decimal("7.0"),
            "cpe:/o:example:b:1": Decimal("4.0"),
        }
        assert logs == []

    def test_unresolved_product_is_one_warning_and_skipped(self) -> None:
        response = ValidatedResponse(
            cpe_by_product_id={1: "cpe:/o:example:a:1"},
            thresholds=[(216, Decimal("7.0")), (1, Decimal("9.0")), (217, Decimal(4))],
        )

        with capture_logs() as logs:
            resolved = resolve_thresholds(response)

        assert resolved == {"cpe:/o:example:a:1": Decimal("9.0")}
        assert logs == [_unresolved(216), _unresolved(217)]

    def test_product_with_unmatchable_cpe_is_silently_skipped(self) -> None:
        response = ValidatedResponse(
            cpe_by_product_id={1: None}, thresholds=[(1, Decimal("7.0"))]
        )

        with capture_logs() as logs:
            resolved = resolve_thresholds(response)

        assert resolved == {}
        assert logs == []


@pytest.mark.unit
def test_utc_today_is_the_current_utc_date() -> None:
    before = datetime.now(UTC).date()
    today = _REAL_UTC_TODAY()
    after = datetime.now(UTC).date()

    assert type(today) is date
    assert today in {before, after}


# ---------------------------------------------------------------------------
# Publication (steps 3-8; write scope; matching; clearing)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPublication:
    @pytest.mark.parametrize(
        ("stored", "upstream", "persisted"),
        [
            (None, 7.0, "7.0"),
            ("7.0", 9, "9.0"),
            ("9.0", 4.5, "4.5"),
            ("7.0", 0, "0.0"),
            (None, 10.0, "10.0"),
        ],
        ids=["null-to-value", "value-to-int", "value-to-value", "to-zero", "to-ten"],
    )
    async def test_changed_threshold_is_written_and_advances_updated_at(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        stored: str | None,
        upstream: float,
        persisted: str,
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        product = await seed(cpe, stored)

        metrics = await _publish(db_session, {1: cpe}, {1: upstream})

        assert metrics == (1, 0, 1, 0)
        assert await _thresholds(db_session) == {cpe: Decimal(persisted)}
        assert (await _updated_at(db_session))[cpe] > OLD_UPDATED_AT
        assert dispatcher.calls == [(product.id, "threshold")]

    @pytest.mark.parametrize("upstream", [7.0, 7], ids=["float", "int"])
    async def test_unchanged_threshold_is_not_written(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        upstream: float,
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        await seed(cpe, "7.0")
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, {1: cpe}, {1: upstream})

        assert metrics == (1, 0, 0, 0)
        assert await _product_rows(db_session) == before
        assert (await _updated_at(db_session))[cpe] == OLD_UPDATED_AT
        assert dispatcher.calls == []

    async def test_absent_threshold_clears_the_stored_value(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        """A local non-null threshold whose CPE has no resolved AIMAAS
        threshold (listed Product without threshold, unlisted Product, and
        a threshold whose Product resolves to an unmatchable `cpe`) is
        cleared to NULL; a NULL threshold is not evaluated."""
        listed = await seed("cpe:/o:example:listed:1", "7.0")
        unlisted = await seed("cpe:/o:example:unlisted:1", "4.0")
        await seed("cpe:/o:example:untouched:1")
        before = await _product_rows(db_session)

        metrics = await _publish(
            db_session, {1: "cpe:/o:example:listed:1", 2: None}, {2: 9.0}
        )

        assert metrics == (2, 0, 2, 0)
        assert await _thresholds(db_session) == {
            "cpe:/o:example:listed:1": None,
            "cpe:/o:example:unlisted:1": None,
            "cpe:/o:example:untouched:1": None,
        }
        after = await _product_rows(db_session)
        assert (
            after["cpe:/o:example:untouched:1"] == before["cpe:/o:example:untouched:1"]
        )
        assert sorted(dispatcher.product_ids) == sorted([listed.id, unlisted.id])

    @pytest.mark.parametrize(
        "envelope",
        [
            pytest.param({"total": 0, "pages": 0}, id="pages-0"),
            pytest.param({"total": 0, "pages": 1}, id="pages-1-total-0"),
        ],
    )
    async def test_empty_complete_threshold_collection_clears_every_threshold(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        envelope: dict[str, int],
    ) -> None:
        first = await seed("cpe:/o:example:a:1", "7.0")
        second = await seed("cpe:/o:example:b:1", "9.0")
        await seed("cpe:/o:example:c:1")
        thresholds = AimaasServer(
            {1: {"items": [], "page": 1, "size": 100, **envelope}}
        )
        router = AimaasRouter(
            {
                AIMAAS_TEST_PRODUCTS_ENDPOINT: AimaasServer.for_items(
                    [product_item(1, cpe="cpe:/o:example:a:1")]
                ),
                AIMAAS_TEST_THRESHOLDS_ENDPOINT: thresholds,
            }
        )

        metrics = _metrics(await _execute(db_session, router))

        assert metrics == (2, 0, 2, 0)
        assert thresholds.requested_pages == [1]
        assert set((await _thresholds(db_session)).values()) == {None}
        assert dispatcher.product_ids == sorted([first.id, second.id])

    async def test_only_cvss_threshold_and_updated_at_change(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        product_repository_factory: Callable[..., Awaitable[ProductRepository]],
    ) -> None:
        cpe = "cpe:/o:example:product-a:1"
        product = await seed(
            cpe,
            "7.5",
            name="Example-Product-A",
            version="15-SP7",
            display_name="Example Product A",
            first_customer_ship_date=date(2024, 1, 15),
            general_support_end_date=date(2027, 6, 30),
            extended_support_end_date=date(2030, 6, 30),
            reactive_support_end_date=date(2032, 6, 30),
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
            if column.name not in ("cvss_threshold", "updated_at")
        ]

        async def untouched() -> tuple[dict[str, Any], list[tuple[Any, ...]]]:
            row = (
                await db_session.execute(
                    select(*(Product.__table__.c[name] for name in columns))
                )
            ).one()
            repositories = await db_session.execute(
                select(*ProductRepository.__table__.columns)
            )
            return dict(zip(columns, row, strict=True)), [
                tuple(r) for r in repositories
            ]

        before = await untouched()
        assert before[0]["catalog_last_seen_at"] == T0

        metrics = await _publish(db_session, {1: cpe}, {1: 9.0})

        assert metrics == (1, 0, 1, 0)
        assert await untouched() == before
        assert await _thresholds(db_session) == {cpe: Decimal("9.0")}

    async def test_unmatched_and_unmatchable_entries_create_and_change_nothing(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        await seed("cpe:/o:example:local:1")
        before = await _product_rows(db_session)

        with capture_logs() as logs:
            metrics = await _publish(
                db_session,
                {1: "cpe:/o:example:unknown:1", 2: None, 3: ""},
                {1: 7.0, 2: 9.0, 3: 4.0},
            )

        assert metrics == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before
        assert _logged(logs, UNRESOLVED_EVENT) == []
        assert dispatcher.calls == []

    @pytest.mark.parametrize(
        "upstream",
        [
            "CPE:/O:EXAMPLE:PRODUCT-A:1",
            "cpe:/o:example:product-a:1 ",
            "cpe:/o:example:product-a",
        ],
        ids=["upper-case", "trailing-space", "prefix"],
    )
    async def test_cpe_matching_is_exact_and_case_sensitive(
        self, db_session: AsyncSession, seed: SeedProduct, upstream: str
    ) -> None:
        await seed("cpe:/o:example:product-a:1")
        before = await _product_rows(db_session)

        metrics = await _publish(db_session, {1: upstream}, {1: 7.0})

        assert metrics == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before

    async def test_threshold_resolves_through_the_aimaas_product_id(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        """The threshold entry's own `id` is ignored; its `product` names
        the AIMAAS Product whose `cpe` is matched."""
        await seed("cpe:/o:example:a:1")
        await seed("cpe:/o:example:b:1")
        router = threshold_sync_router(
            [
                product_item(10, cpe="cpe:/o:example:a:1"),
                product_item(20, cpe="cpe:/o:example:b:1"),
            ],
            [
                threshold_item(1, product=20, threshold=4.0, id=10),
                threshold_item(2, product=10, threshold=9.0, id=20),
            ],
        )

        await _execute(db_session, router)

        assert await _thresholds(db_session) == {
            "cpe:/o:example:a:1": Decimal("9.0"),
            "cpe:/o:example:b:1": Decimal("4.0"),
        }

    async def test_unresolved_upstream_product_warns_once_and_continues(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        await seed("cpe:/o:example:a:1")

        with capture_logs() as logs:
            metrics = await _publish(
                db_session, {1: "cpe:/o:example:a:1"}, {216: 7.0, 1: 9.0}
            )

        assert metrics == (1, 0, 1, 0)
        assert _logged(logs, UNRESOLVED_EVENT) == [_unresolved(216)]
        assert await _thresholds(db_session) == {"cpe:/o:example:a:1": Decimal("9.0")}

    async def test_response_larger_than_one_select_chunk_matches_every_product(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        products = {pid: f"cpe:/o:example:chunk-{pid:04d}:1" for pid in range(1, 1101)}
        first, last = products[1], products[1100]
        await seed(first)
        await seed(last, "4.0")

        metrics = await _publish(db_session, products, dict.fromkeys(products, 7.0))

        assert metrics == (2, 0, 2, 0)
        assert await _thresholds(db_session) == {
            first: Decimal("7.0"),
            last: Decimal("7.0"),
        }

    async def test_requests_use_the_documented_queries(
        self, db_session: AsyncSession
    ) -> None:
        products = {pid: f"cpe:/o:example:p-{pid}:1" for pid in range(1, 151)}
        router = _router(products, dict.fromkeys(range(1, 102), 7.0))

        await _execute(db_session, router)

        assert router.requested_urls == [
            *(
                f"{AIMAAS_TEST_PRODUCTS_ENDPOINT}?all_fields=true&size=100&page={page}"
                for page in (1, 2)
            ),
            *(
                f"{AIMAAS_TEST_THRESHOLDS_ENDPOINT}?size=100&page={page}"
                for page in (1, 2)
            ),
        ]
        for request in router.requests:
            assert "all" not in request.url.params
            assert "deleted_only" not in request.url.params
        assert PRODUCTS_ENDPOINT_PATH == "entity/products"
        assert THRESHOLDS_ENDPOINT_PATH == "entity/cvss-threshold"

    async def test_configured_request_delay_is_applied_between_pages(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(aimaas_listing, "asyncio", SimpleNamespace(sleep=sleep))
        products = {pid: f"cpe:/o:example:p-{pid}:1" for pid in range(1, 251)}
        fetcher = _fetcher(_router(products, dict.fromkeys(range(1, 151), 7.0)))
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.25, custom_settings={}
        )
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert sleeps == [0.25, 0.25, 0.25]  # products pages 2-3, thresholds 2

    async def test_without_run_config_no_delay_is_applied(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(aimaas_listing, "asyncio", SimpleNamespace(sleep=sleep))
        products = {pid: f"cpe:/o:example:p-{pid}:1" for pid in range(1, 251)}

        await _publish(db_session, products, dict.fromkeys(range(1, 151), 7.0))

        assert sleeps == []


# ---------------------------------------------------------------------------
# Metrics (exact outcome and effect counters; every mandated case)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestMetrics:
    async def test_changed_only(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        """NULL → 7.0 with a converged CVE-less occurrence (10.0 >= 7.0)."""
        product = await seed("cpe:/o:example:a:1")
        await place(product, eligible=True)

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (1, 0, 1, 0)
        assert dispatcher.calls == [(product.id, "threshold")]

    async def test_unchanged_matched(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        """Also the unchanged absence evaluation: the stored non-null
        threshold is evaluated for absence clearing, is still present
        upstream with the same value, and is retained."""
        product = await seed("cpe:/o:example:a:1", "7.0")
        await place(product, eligible=True)

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (1, 0, 0, 0)
        assert dispatcher.calls == []

    async def test_absence_evaluation_always_changes_and_succeeds(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        """A stored non-null threshold absent from the resolved set is
        cleared: updated and, after its dispatch, succeeded. A NULL threshold
        is not evaluated for absence clearing."""
        product = await seed("cpe:/o:example:a:1", "7.0")
        await seed("cpe:/o:example:null:1")

        metrics = await _publish(db_session, {}, {})

        assert metrics == (1, 0, 1, 0)
        assert dispatcher.calls == [(product.id, "threshold")]

    async def test_mismatch_only_matched_product(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        """Unchanged 7.0, but a stale `false` (CVE-less 10.0 >= 7.0)."""
        product = await seed("cpe:/o:example:a:1", "7.0")
        await place(product, eligible=False)

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (1, 0, 0, 0)
        assert dispatcher.calls == [(product.id, "threshold")]

    async def test_mismatch_only_unevaluated_product(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        """A NULL-threshold Product outside both evaluation sets is selected
        through the mismatch set alone (recovery of a prior failure)."""
        product = await seed("cpe:/o:example:a:1")
        await place(product, eligible=False)

        metrics = await _publish(db_session, {}, {})

        assert metrics == (1, 0, 0, 0)
        assert dispatcher.calls == [(product.id, "threshold")]

    async def test_overlapping_changed_and_mismatch_counts_once(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        product = await seed("cpe:/o:example:a:1", "9.0")
        await place(product, eligible=False)
        await place(product, eligible=False)

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (1, 0, 1, 0)
        assert dispatcher.calls == [(product.id, "threshold")]

    async def test_successful_dispatches(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        products = [await seed(f"cpe:/o:example:{name}:1") for name in "abc"]

        metrics = await _publish(
            db_session,
            {1: "cpe:/o:example:a:1", 2: "cpe:/o:example:b:1", 3: "cpe:/o:example:c:1"},
            {1: 7.0, 2: 9.0, 3: 4.0},
        )

        assert metrics == (3, 0, 3, 0)
        assert dispatcher.calls == [
            (product.id, "threshold") for product in sorted(products, key=_id)
        ]

    async def test_failed_dispatch_after_committed_update(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        product = await seed("cpe:/o:example:a:1")
        dispatcher.failures[product.id] = KombuOperationalError("example failure")

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (0, 0, 1, 1)
        assert await _thresholds(db_session) == {"cpe:/o:example:a:1": Decimal("7.0")}

    async def test_failed_dispatch_of_a_mismatch_only_product(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        product = await seed("cpe:/o:example:a:1", "7.0")
        await place(product, eligible=False)
        dispatcher.failures[product.id] = RuntimeError("example failure")

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (0, 0, 0, 1)

    async def test_unresolved_upstream_product(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        await seed("cpe:/o:example:a:1")

        with capture_logs() as logs:
            metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {216: 7.0})

        assert metrics == (0, 0, 0, 0)
        assert _logged(logs, UNRESOLVED_EVENT) == [_unresolved(216)]
        assert dispatcher.calls == []

    async def test_unmatched_local_cpe(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        await seed("cpe:/o:example:local:1")

        with capture_logs() as logs:
            metrics = await _publish(
                db_session, {1: "cpe:/o:example:other:1"}, {1: 7.0}
            )

        assert metrics == (0, 0, 0, 0)
        assert _logged(logs, UNRESOLVED_EVENT) == []
        assert dispatcher.calls == []

    async def test_empty_selected_set(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        product = await seed("cpe:/o:example:a:1")
        await place(product, eligible=True)

        metrics = await _publish(db_session, {1: "cpe:/o:example:other:1"}, {})

        assert metrics == (0, 0, 0, 0)
        assert dispatcher.calls == []

    async def test_mixed_run_counts_each_selected_product_once(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
    ) -> None:
        changed = await seed("cpe:/o:example:changed:1")
        unchanged = await seed("cpe:/o:example:unchanged:1", "7.0")
        cleared = await seed("cpe:/o:example:cleared:1", "4.0")
        stale = await seed("cpe:/o:example:stale:1", "7.0")
        both = await seed("cpe:/o:example:both:1", "9.0")
        failing = await seed("cpe:/o:example:failing:1")
        await seed("cpe:/o:example:excluded:1")
        await place(unchanged, eligible=True)
        await place(stale, eligible=False)
        await place(both, eligible=False)
        dispatcher.failures[failing.id] = KombuOperationalError("example failure")
        products = {
            1: "cpe:/o:example:changed:1",
            2: "cpe:/o:example:unchanged:1",
            3: "cpe:/o:example:stale:1",
            4: "cpe:/o:example:both:1",
            5: "cpe:/o:example:failing:1",
            6: "cpe:/o:example:unmatched:1",
            7: None,
        }
        thresholds = {1: 7.0, 2: 7.0, 3: 7.0, 4: 4.0, 5: 7.0, 6: 9.0, 7: 9.0, 216: 7}

        with capture_logs() as logs:
            metrics = await _publish(db_session, products, thresholds)

        # changed, cleared, both, failing updated; unchanged and every
        # dispatched-successfully Product succeeded; failing failed.
        assert metrics == (5, 0, 4, 1)
        required = sorted([changed, cleared, stale, both, failing], key=_id)
        assert dispatcher.product_ids == [product.id for product in required]
        assert {reason for _, reason in dispatcher.calls} == {"threshold"}
        assert _logged(logs, UNRESOLVED_EVENT) == [_unresolved(216)]
        assert _logged(logs, SUMMARY_EVENT) == [
            {
                "event": SUMMARY_EVENT,
                "log_level": "info",
                "aimaas_products": 7,
                "aimaas_thresholds": 8,
                "resolved": 6,
                "evaluated": 6,
                "updated": 4,
                "mismatched": 2,
                "dispatched": 4,
                "dispatch_failed": 1,
            }
        ]

    async def test_second_identical_run_has_no_updates(
        self, db_session: AsyncSession, seed: SeedProduct, dispatcher: DispatchRecorder
    ) -> None:
        await seed("cpe:/o:example:a:1")
        await seed("cpe:/o:example:b:1", "4.0")
        products = {1: "cpe:/o:example:a:1", 2: "cpe:/o:example:b:1"}

        first = await _publish(db_session, products, {1: 7.0, 2: 9.0})
        second = await _publish(db_session, products, {1: 7.0, 2: 9.0})

        assert (first, second) == ((2, 0, 2, 0), (2, 0, 0, 0))
        assert len(dispatcher.calls) == 2


def _id(product: Product) -> uuid.UUID:
    return product.id


# ---------------------------------------------------------------------------
# Transaction boundaries and post-commit dispatch (steps 1, 8-10)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestTransactionBoundaries:
    async def test_both_retrieval_phases_complete_before_any_statement(
        self, db_session: AsyncSession, seed: SeedProduct
    ) -> None:
        products = {pid: f"cpe:/o:example:p-{pid}:1" for pid in range(1, 251)}
        await seed(products[100])
        await seed(products[250], "7.0")
        await db_session.commit()
        events: list[tuple[str, str]] = []
        router = _router(products, dict.fromkeys(range(100, 251), 7.0), events=events)

        with SqlRecorder(db_session, events):
            fetcher = await _execute(db_session, router)

        kinds = [kind for kind, _ in events]
        assert kinds.count("http") == 5  # three Product pages, two threshold pages
        assert "sql" in kinds
        assert kinds == sorted(kinds)  # every "http" precedes every "sql"
        assert _metrics(fetcher) == (2, 0, 1, 0)

    async def test_publication_commits_once_before_scan_and_dispatch(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
        monkeypatch: pytest.MonkeyPatch,
        clock: Mock,
    ) -> None:
        changed = await seed("cpe:/o:example:changed:1")
        stale = await seed("cpe:/o:example:stale:1", "7.0")
        await place(stale, eligible=False)
        await db_session.commit()
        sequence: list[str] = []
        scans: list[dict[str, Any]] = []
        original_commit = db_session.commit
        original_scan = find_product_eligibility_mismatches

        async def recording_commit() -> None:
            await original_commit()
            sequence.append("commit")

        async def recording_scan(
            session: AsyncSession, **kwargs: Any
        ) -> frozenset[uuid.UUID]:
            sequence.append("scan")
            scans.append({"session": session, **kwargs})
            return await original_scan(session, **kwargs)

        monkeypatch.setattr(db_session, "commit", recording_commit)
        monkeypatch.setattr(
            sync_module, "find_product_eligibility_mismatches", recording_scan
        )
        dispatcher.events = sequence
        dispatcher.session = db_session

        await _publish(
            db_session,
            {1: "cpe:/o:example:changed:1", 2: "cpe:/o:example:stale:1"},
            {1: 7.0, 2: 7.0},
        )

        assert sequence == ["commit", "scan", "commit", "dispatch", "dispatch"]
        assert dispatcher.in_transaction == [False, False]
        assert scans == [{"session": db_session, "evaluation_date": EVAL}]
        clock.assert_called_once_with()
        assert dispatcher.product_ids == sorted([changed.id, stale.id])

    async def test_scan_uses_the_utc_evaluation_date(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        place: Placer,
        dispatcher: DispatchRecorder,
        clock: Mock,
    ) -> None:
        """A Product in Reactive Support on `EVAL` with a stored `true` is a
        mismatch only when the scan evaluates on the clock's date."""
        product = await seed(
            "cpe:/o:example:a:1",
            first_customer_ship_date=date(2020, 1, 1),
            general_support_end_date=date(2022, 1, 1),
            extended_support_end_date=date(2024, 1, 1),
            reactive_support_end_date=date(2027, 1, 1),
        )
        await place(product, eligible=True)

        clock.return_value = date(2023, 1, 1)  # Extended Support: no mismatch
        assert await _publish(db_session, {}, {}) == (0, 0, 0, 0)
        clock.return_value = EVAL
        assert await _publish(db_session, {}, {}) == (1, 0, 0, 0)

        assert dispatcher.calls == [(product.id, "threshold")]

    @pytest.mark.parametrize("stage", ["select", "update", "commit"])
    async def test_database_failure_publishes_nothing_and_dispatches_nothing(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
    ) -> None:
        cpes = [f"cpe:/o:example:product-{index}:1" for index in range(3)]
        await seed(cpes[0])
        await seed(cpes[1], "4.0")
        await seed(cpes[2], "9.0")
        await db_session.commit()
        before = await _product_rows(db_session)
        failure = OperationalError("STATEMENT", {}, Exception(MARKER))
        original_execute = db_session.execute
        armed = [True]

        async def failing_execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            if armed[0] and stage == "select" and isinstance(statement, Select):
                raise failure
            result = await original_execute(statement, *args, **kwargs)
            if armed[0] and stage == "update" and isinstance(statement, Update):
                raise failure
            return result

        async def failing_commit() -> None:
            raise failure

        if stage == "commit":
            monkeypatch.setattr(db_session, "commit", failing_commit)
        else:
            monkeypatch.setattr(db_session, "execute", failing_execute)

        with capture_logs() as logs:
            error, fetcher = await _execute_failing(
                db_session,
                _router({1: cpes[0], 2: cpes[1]}, {1: 7.0, 2: 9.0}),
            )
        armed[0] = False
        await db_session.rollback()

        assert str(error) == PUBLICATION_FAILED_MESSAGE
        assert error.__cause__ is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert await _product_rows(db_session) == before
        assert dispatcher.calls == []
        assert logs == [
            {
                "event": "aimaas_cvss_threshold_publication_failed",
                "log_level": "warning",
            }
        ]

    async def test_dispatch_failure_is_logged_and_later_products_continue(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
    ) -> None:
        products = sorted(
            [await seed(f"cpe:/o:example:{name}:1") for name in "abc"], key=_id
        )
        dispatcher.failures[products[0].id] = KombuOperationalError(MARKER)
        dispatcher.failures[products[1].id] = TypeError(MARKER)

        with capture_logs() as logs:
            metrics = await _publish(
                db_session,
                {
                    1: "cpe:/o:example:a:1",
                    2: "cpe:/o:example:b:1",
                    3: "cpe:/o:example:c:1",
                },
                {1: 7.0, 2: 7.0, 3: 7.0},
            )

        assert metrics == (1, 0, 3, 2)
        assert dispatcher.product_ids == [product.id for product in products]
        assert _logged(logs, DISPATCH_FAILED_EVENT) == [
            {
                "event": DISPATCH_FAILED_EVENT,
                "log_level": "warning",
                "product_id": str(products[0].id),
                "error_type": "OperationalError",
            },
            {
                "event": DISPATCH_FAILED_EVENT,
                "log_level": "warning",
                "product_id": str(products[1].id),
                "error_type": "TypeError",
            },
        ]
        assert MARKER not in repr(logs)
        assert set((await _thresholds(db_session)).values()) == {Decimal("7.0")}

    @pytest.mark.parametrize(
        "signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_whole_run_signal_from_dispatch_propagates(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        signal: type[BaseException],
    ) -> None:
        products = sorted(
            [await seed(f"cpe:/o:example:{name}:1") for name in "ab"], key=_id
        )
        raised = signal()
        dispatcher.failures[products[0].id] = raised

        with capture_logs() as logs:
            error, fetcher = await _execute_failing(
                db_session,
                _router(
                    {1: "cpe:/o:example:a:1", 2: "cpe:/o:example:b:1"}, {1: 7, 2: 7}
                ),
                signal,
            )

        assert error is raised
        assert dispatcher.product_ids == [products[0].id]
        assert _metrics(fetcher) == (0, 0, 2, 0)
        assert _logged(logs, DISPATCH_FAILED_EVENT) == []
        assert set((await _thresholds(db_session)).values()) == {Decimal("7.0")}

    async def test_real_dispatch_publishes_through_the_broker_after_commit(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The production dispatch chain with only `send_task` substituted."""
        product = await seed("cpe:/o:example:a:1")
        states: list[bool] = []

        def send_task(*args: Any, **kwargs: Any) -> None:
            states.append(db_session.in_transaction())

        mock = Mock(side_effect=send_task)
        monkeypatch.setattr(
            sync_module,
            "dispatch_product_eligibility_recalculation",
            dispatch_product_eligibility_recalculation,
        )
        monkeypatch.setattr(celery_app, "send_task", mock)

        metrics = await _publish(db_session, {1: "cpe:/o:example:a:1"}, {1: 7.0})

        assert metrics == (1, 0, 1, 0)
        mock.assert_called_once_with(
            "re_evaluate_product_eligibility",
            kwargs={"catalog_product_id": str(product.id), "reason": "threshold"},
            ignore_result=True,
        )
        assert states == [False]


# ---------------------------------------------------------------------------
# Whole-run failures before publication (Error Handling)
# ---------------------------------------------------------------------------

_PHASES: Final = {
    "products": (AIMAAS_TEST_PRODUCTS_ENDPOINT, INVALID_PRODUCT_LIST_MESSAGE),
    "cvss_thresholds": (
        AIMAAS_TEST_THRESHOLDS_ENDPOINT,
        INVALID_THRESHOLD_LIST_MESSAGE,
    ),
}


def _failing_router(events: list[tuple[str, str]] | None = None) -> AimaasRouter:
    """250 Products (three pages) and 150 thresholds (two pages)."""
    products = {pid: f"cpe:/o:example:p-{pid}:1" for pid in range(1, 251)}
    return _router(products, dict.fromkeys(range(1, 151), 7.0), events=events)


def _http_500(server: AimaasServer) -> tuple[int, dict[str, Any]]:
    server.responses[2] = lambda request: httpx.Response(500)
    return 2, {"category": "http_status", "status_code": 500}


def _connect_error(server: AimaasServer) -> tuple[int, dict[str, Any]]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("example connection failure", request=request)

    server.responses[1] = respond
    return 1, {"category": "connection"}


def _read_timeout(server: AimaasServer) -> tuple[int, dict[str, Any]]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("example timeout", request=request)

    server.responses[2] = respond
    return 2, {"category": "timeout"}


def _invalid_pagination(server: AimaasServer) -> tuple[int, dict[str, Any]]:
    server.pages[2]["total"] += 1
    return 2, {"category": "page 2: total or pages changed during retrieval"}


RetrievalCase = tuple[
    str, Callable[[AimaasServer], tuple[int, dict[str, Any]]], str | None, type
]

_RETRIEVAL_FAILURES: Final[list[RetrievalCase]] = [
    ("http-status", _http_500, "AIMAAS returned HTTP 500", httpx.HTTPStatusError),
    ("connection", _connect_error, "Failed to connect to AIMAAS", httpx.ConnectError),
    ("timeout", _read_timeout, "AIMAAS request timed out", httpx.ReadTimeout),
    ("pagination", _invalid_pagination, None, InvalidAimaasListingError),
]


def _break_item(server: AimaasServer, field: str, value: Any) -> None:
    item = server.pages[2]["items"][5]
    if value is _DELETE:
        del item[field]
    else:
        item[field] = value


_DELETE: Final = object()

SchemaCase = tuple[str, str, str, Any, str]

_SCHEMA_FAILURES: Final[list[SchemaCase]] = [
    ("missing-id", "products", "id", _DELETE, "item 105: id is missing"),
    ("missing-cpe", "products", "cpe", _DELETE, "item 105: cpe is missing"),
    ("string-id", "products", "id", MARKER, "item 105: id must be an integer"),
    ("bool-id", "products", "id", True, "item 105: id must be an integer"),
    ("int-cpe", "products", "cpe", 7, "item 105: cpe must be a string"),
    (
        "nul-cpe",
        "products",
        "cpe",
        "cpe:/o:example:nul\x00:1",
        "item 105: cpe contains U+0000",
    ),
    (
        "missing-product",
        "cvss_thresholds",
        "product",
        _DELETE,
        "item 105: product is missing",
    ),
    (
        "missing-threshold",
        "cvss_thresholds",
        "threshold",
        _DELETE,
        "item 105: threshold is missing",
    ),
    (
        "string-product",
        "cvss_thresholds",
        "product",
        MARKER,
        "item 105: product must be an integer",
    ),
    (
        "bool-product",
        "cvss_thresholds",
        "product",
        False,
        "item 105: product must be an integer",
    ),
]


async def _seed_failure_world(seed: SeedProduct, db: AsyncSession) -> None:
    await seed("cpe:/o:example:p-1:1")
    await seed("cpe:/o:example:p-120:1", "4.0")
    await seed("cpe:/o:example:local-only:1", "9.0")
    await db.commit()


@pytest.mark.integration
class TestWholeRunFailureBeforePublication:
    @pytest.mark.parametrize("phase", list(_PHASES))
    @pytest.mark.parametrize(
        ("break_server", "message", "cause"),
        [case[1:] for case in _RETRIEVAL_FAILURES],
        ids=[case[0] for case in _RETRIEVAL_FAILURES],
    )
    async def test_retrieval_failure_publishes_nothing_and_executes_no_sql(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        phase: str,
        break_server: Callable[[AimaasServer], tuple[int, dict[str, Any]]],
        message: str | None,
        cause: type[BaseException],
    ) -> None:
        await _seed_failure_world(seed, db_session)
        before = await _product_rows(db_session)
        router = _failing_router()
        endpoint, invalid_message = _PHASES[phase]
        page, detail = break_server(router.routes[endpoint])
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events), capture_logs() as logs:
            error, fetcher = await _execute_failing(db_session, router)

        assert str(error) == (message or invalid_message)
        assert isinstance(error.__cause__, cause)
        assert "aimaas.example.test" not in str(error)
        event_name = (
            "aimaas_response_invalid"
            if cause is InvalidAimaasListingError
            else "aimaas_request_failed"
        )
        assert logs == [
            {
                "event": event_name,
                "log_level": "warning",
                "collection": phase,
                "page": page,
                **detail,
            }
        ]
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert events == []
        assert dispatcher.calls == []
        assert await _product_rows(db_session) == before

    @pytest.mark.parametrize(
        ("phase", "field", "value", "category"),
        [case[1:] for case in _SCHEMA_FAILURES],
        ids=[case[0] for case in _SCHEMA_FAILURES],
    )
    async def test_response_schema_failure_names_its_phase(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        phase: str,
        field: str,
        value: Any,
        category: str,
    ) -> None:
        await _seed_failure_world(seed, db_session)
        before = await _product_rows(db_session)
        router = _failing_router()
        endpoint, invalid_message = _PHASES[phase]
        _break_item(router.routes[endpoint], field, value)
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events), capture_logs() as logs:
            error, fetcher = await _execute_failing(db_session, router)

        assert str(error) == invalid_message
        assert isinstance(error.__cause__, ThresholdResponseError)
        assert logs == [
            {
                "event": "aimaas_cvss_threshold_response_invalid",
                "log_level": "warning",
                "collection": phase,
                "category": category,
            }
        ]
        assert MARKER not in repr(logs)
        assert MARKER not in str(error)
        assert MARKER not in str(error.__cause__)
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert events == []
        assert dispatcher.calls == []
        assert await _product_rows(db_session) == before

    @pytest.mark.parametrize(
        ("products", "thresholds", "category"),
        [
            (
                [(1, "cpe:/o:example:p-1:1"), (2, MARKER), (1, "cpe:/o:example:x:1")],
                [(1, 7.0)],
                "product 2: duplicate id",
            ),
            (
                [(1, MARKER), (2, None), (3, ""), (4, None), (5, MARKER)],
                [(1, 7.0)],
                "product 4: duplicate cpe",
            ),
            (
                [(1, "cpe:/o:example:p-1:1")],
                [(1, 7.0), (2, 9.0), (1, 4.0)],
                "threshold 2: duplicate product",
            ),
            (
                [(1, "cpe:/o:example:p-1:1")],
                [(1, 7.0), (2, 10.5)],
                "threshold 1: threshold out of range",
            ),
            (
                [(1, "cpe:/o:example:p-1:1")],
                [(1, 7.05)],
                "threshold 0: threshold out of range",
            ),
            (
                [(1, "cpe:/o:example:p-1:1")],
                [(1, None)],
                "threshold 0: threshold out of range",
            ),
        ],
        ids=[
            "duplicate-id",
            "duplicate-cpe",
            "duplicate-product",
            "above-range",
            "two-decimals",
            "null-threshold",
        ],
    )
    async def test_validation_failure_changes_no_threshold(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        dispatcher: DispatchRecorder,
        products: list[tuple[int, str | None]],
        thresholds: list[tuple[int, Any]],
        category: str,
    ) -> None:
        await _seed_failure_world(seed, db_session)
        before = await _product_rows(db_session)
        router = threshold_sync_router(
            [product_item(pid, cpe=cpe) for pid, cpe in products],
            [
                threshold_item(index, product=pid, threshold=value)
                for index, (pid, value) in enumerate(thresholds)
            ],
        )
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events), capture_logs() as logs:
            error, fetcher = await _execute_failing(db_session, router)

        assert str(error) == VALIDATION_FAILED_MESSAGE
        assert isinstance(error.__cause__, ThresholdValidationError)
        assert logs == [
            {
                "event": "aimaas_cvss_threshold_validation_failed",
                "log_level": "warning",
                "category": category,
            }
        ]
        assert MARKER not in repr(logs)
        assert MARKER not in str(error)
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert events == []
        assert dispatcher.calls == []
        assert await _product_rows(db_session) == before

    def test_failure_messages_are_the_specified_values(self) -> None:
        assert INVALID_PRODUCT_LIST_MESSAGE == (
            "AIMAAS returned invalid Product list response"
        )
        assert INVALID_THRESHOLD_LIST_MESSAGE == (
            "AIMAAS returned invalid CVSS threshold response"
        )
        assert VALIDATION_FAILED_MESSAGE == "AIMAAS CVSS threshold validation failed"
        assert PUBLICATION_FAILED_MESSAGE == (
            "Failed to synchronize AIMAAS CVSS thresholds"
        )


# ---------------------------------------------------------------------------
# No Ticket audit event (ticket-audit-log.md matrix row; TR 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestNoTicketAuditEvent:
    async def test_effective_and_no_op_publications_create_no_ticket_event(
        self,
        db_session: AsyncSession,
        seed: SeedProduct,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
        dispatcher: DispatchRecorder,
    ) -> None:
        """A 9.0 threshold makes the stored `true` of a SUSE 5.0 Ticket
        stale: the catalog side commits the threshold and dispatches, but
        changes no eligibility, Ticket status, or audit history."""
        raised = await seed("cpe:/o:example:raised:1")
        cleared = await seed("cpe:/o:example:cleared:1", "7.0")
        cve = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name="SUSE",
            cvss_version="3.1",
            score=Decimal("5.0"),
        )
        ticket = await ticket_factory(status=TicketStatus.ANALYZED.value, cve_id=cve.id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        for product, eligible in ((raised, True), (cleared, False)):
            await ticket_package_product_factory(
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=eligible,
            )
        await ticket_factory()  # a Ticket without a package tree
        await db_session.commit()

        async def tree_state() -> list[tuple[Any, ...]]:
            tickets = await db_session.execute(
                select(Ticket.id, Ticket.status, Ticket.updated_at).order_by(Ticket.id)
            )
            tracks = await db_session.execute(
                select(TicketPackageTrack.id, TicketPackageTrack.status)
            )
            occurrences = await db_session.execute(
                select(
                    TicketPackageProduct.id,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                    TicketPackageProduct.updated_at,
                ).order_by(TicketPackageProduct.id)
            )
            return [
                tuple(row)
                for result in (tickets, tracks, occurrences)
                for row in result
            ]

        async def event_count() -> int:
            return (
                await db_session.execute(select(func.count(TicketAuditEvent.id)))
            ).scalar_one()

        tree_before = await tree_state()
        assert await event_count() == 0

        effective = await _publish(db_session, {1: "cpe:/o:example:raised:1"}, {1: 9.0})
        no_op = await _publish(db_session, {1: "cpe:/o:example:raised:1"}, {1: 9.0})

        assert (effective, no_op) == ((2, 0, 2, 0), (2, 0, 0, 0))
        assert await _thresholds(db_session) == {
            "cpe:/o:example:raised:1": Decimal("9.0"),
            "cpe:/o:example:cleared:1": None,
        }
        assert sorted(dispatcher.product_ids) == sorted(
            [raised.id, cleared.id, raised.id, cleared.id]
        )
        assert await event_count() == 0
        assert await tree_state() == tree_before


# ---------------------------------------------------------------------------
# Parser-backed contract: the captured live pages through the fetcher path
# ---------------------------------------------------------------------------

# The 23 captured thresholds that resolve through the captured Product list,
# transcribed from `thresholds_page_1.json` joined with `products_page_*`.
_LIVE_RESOLVED: Final = {
    "cpe:suse:carwos:1": Decimal("9.0"),
    "cpe:/o:suse:ses:7.1": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-espos:15:sp4": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-espos:15:sp5": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-ltss:15:sp2": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-ltss:15:sp3": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-ltss:15:sp4": Decimal("7.0"),
    "cpe:/o:suse:sle_hpc-ltss:15:sp5": Decimal("7.0"),
    "cpe:/o:suse:suse_sles_ltss-extreme-core:11:sp4": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss:12:sp5": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss:15:sp2": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss:15:sp3": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss:15:sp4": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss:15:sp5": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss-extended-security:12:sp5": Decimal("4.0"),
    "cpe:/o:suse:sles_ltss_teradata:12:sp3": Decimal("7.0"),
    "cpe:/o:suse:sles-ltss-teradata:15:sp2": Decimal("7.0"),
    "cpe:/o:suse:sles_sap:15:sp2": Decimal("7.0"),
    "cpe:/o:suse:sles_sap:15:sp3": Decimal("7.0"),
    "cpe:/o:suse:sles_sap:15:sp4": Decimal("7.0"),
    "cpe:/o:suse:suse-manager-proxy:4.3": Decimal("7.0"),
    "cpe:/o:suse:suse-manager-retail-branch-server:4.3": Decimal("7.0"),
    "cpe:/o:suse:suse-manager-server:4.3": Decimal("7.0"),
}
_LIVE_UNRESOLVED_PRODUCT_ID: Final = 216
_LIVE_UNTHRESHOLDED_CPE: Final = "cpe:/o:suse:sle-module-basesystem:15"


def _live_router() -> AimaasRouter:
    """Serve every captured Product and threshold page verbatim."""
    return AimaasRouter(
        {
            AIMAAS_TEST_PRODUCTS_ENDPOINT: AimaasServer(
                {page: load_products_page(page) for page in PRODUCT_LIST_PAGES}
            ),
            AIMAAS_TEST_THRESHOLDS_ENDPOINT: AimaasServer(
                {page: load_thresholds_page(page) for page in THRESHOLD_FIXTURE_PAGES}
            ),
        }
    )


@pytest.mark.unit
class TestLiveSerializationAccepted:
    async def test_live_pages_resolve_through_the_join(self) -> None:
        router = _live_router()

        async with router.client() as client:
            products = await aimaas_listing.fetch_aimaas_products(
                client,
                api_url=API_URL,
                request_delay=0,
                invalid_message=INVALID_PRODUCT_LIST_MESSAGE,
            )
            thresholds = await aimaas_listing.fetch_aimaas_listing(
                client,
                api_url=API_URL,
                path=THRESHOLDS_ENDPOINT_PATH,
                query={},
                collection="cvss_thresholds",
                request_delay=0,
                invalid_message=INVALID_THRESHOLD_LIST_MESSAGE,
            )
        refs = parse_product_refs(products.items)
        entries = parse_threshold_entries(thresholds.items)
        response = validate_response(refs, entries)

        with capture_logs() as logs:
            resolved = resolve_thresholds(response)

        assert (products.total, len(refs)) == (475, 475)
        assert (thresholds.total, len(entries)) == (24, 24)
        assert resolved == _LIVE_RESOLVED
        assert logs == [_unresolved(_LIVE_UNRESOLVED_PRODUCT_ID)]
        assert router.requested_urls == [
            *(
                f"{AIMAAS_TEST_PRODUCTS_ENDPOINT}?all_fields=true&size=100&page={page}"
                for page in range(1, 6)
            ),
            f"{AIMAAS_TEST_THRESHOLDS_ENDPOINT}?size=100&page=1",
        ]

    def test_live_threshold_values_are_valid(self) -> None:
        for item in load_thresholds_page(1)["items"]:
            assert threshold_value(item["threshold"]) is not None

    def test_live_unthresholded_cpe_is_listed(self) -> None:
        refs = parse_product_refs(
            [
                item
                for page in PRODUCT_LIST_PAGES
                for item in load_products_page(page)["items"]
            ]
        )

        assert _LIVE_UNTHRESHOLDED_CPE in {ref.cpe for ref in refs}
        assert _LIVE_UNTHRESHOLDED_CPE not in _LIVE_RESOLVED


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------

RunSetup = Callable[[AimaasRouter, dict[str, str | None]], Awaitable[uuid.UUID]]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RunSetup]:
    """Commit seeded Products (CPE → threshold) and a `running` FetcherRun;
    route `run()`.

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

    async def setup(router: AimaasRouter, products: dict[str, str | None]) -> uuid.UUID:
        monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: router.client(),
        )
        async with real_session_factory() as session:
            for index, (cpe, threshold) in enumerate(products.items()):
                seeded.append(cpe)
                session.add(
                    Product(
                        cpe=cpe,
                        name=f"Example Run Product {index}",
                        version=str(index),
                        display_name=f"Example Run Product {index}",
                        catalog_last_seen_at=T0,
                        cvss_threshold=None
                        if threshold is None
                        else Decimal(threshold),
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


def _run_metrics(run: FetcherRun) -> Metrics:
    return (run.items_succeeded, run.items_created, run.items_updated, run.items_failed)


async def _committed(
    real_session_factory: async_sessionmaker[AsyncSession], cpes: list[str]
) -> dict[str, tuple[uuid.UUID, Decimal | None]]:
    async with real_session_factory() as session:
        rows = await session.execute(
            select(Product.cpe, Product.id, Product.cvss_threshold).where(
                Product.cpe.in_(cpes)
            )
        )
        return {row.cpe: (row.id, row.cvss_threshold) for row in rows}


@pytest.mark.integration
class TestRunLifecycle:
    async def test_live_fixtures_end_to_end_with_substituted_broker(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Captured live pages for both endpoints; the production dispatch
        chain down to a substituted `celery_app.send_task`."""
        suffix = uuid.uuid4().hex[:12]
        cleared = f"cpe:/o:example:run-{suffix}:cleared"
        local_only = f"cpe:/o:example:run-{suffix}:local-only"
        seeded: dict[str, str | None] = {
            "cpe:/o:suse:ses:7.1": None,  # NULL → 7.0
            "cpe:/o:suse:sles-ltss:15:sp5": "7.0",  # unchanged
            "cpe:/o:suse:sles-ltss-extended-security:12:sp5": "7.0",  # → 4.0
            _LIVE_UNTHRESHOLDED_CPE: None,  # listed, no threshold, NULL
            cleared: "5.0",  # absent → cleared
            local_only: None,  # not evaluated
        }
        run_id = await committed_run(_live_router(), seeded)
        send_task = Mock()
        monkeypatch.setattr(
            sync_module,
            "dispatch_product_eligibility_recalculation",
            dispatch_product_eligibility_recalculation,
        )
        monkeypatch.setattr(celery_app, "send_task", send_task)

        with capture_logs() as logs:
            await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (4, 0, 3, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        committed = await _committed(real_session_factory, list(seeded))
        assert {cpe: value for cpe, (_, value) in committed.items()} == {
            "cpe:/o:suse:ses:7.1": Decimal("7.0"),
            "cpe:/o:suse:sles-ltss:15:sp5": Decimal("7.0"),
            "cpe:/o:suse:sles-ltss-extended-security:12:sp5": Decimal("4.0"),
            _LIVE_UNTHRESHOLDED_CPE: None,
            cleared: None,
            local_only: None,
        }
        changed = sorted(
            committed[cpe][0]
            for cpe in (
                "cpe:/o:suse:ses:7.1",
                "cpe:/o:suse:sles-ltss-extended-security:12:sp5",
                cleared,
            )
        )
        assert [call.args for call in send_task.call_args_list] == [
            ("re_evaluate_product_eligibility",) for _ in changed
        ]
        assert [call.kwargs for call in send_task.call_args_list] == [
            {
                "kwargs": {"catalog_product_id": str(pid), "reason": "threshold"},
                "ignore_result": True,
            }
            for pid in changed
        ]
        assert _logged(logs, UNRESOLVED_EVENT) == [
            _unresolved(_LIVE_UNRESOLVED_PRODUCT_ID)
        ]

    async def test_failed_dispatch_after_update_is_a_normal_return_failure(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        dispatcher: DispatchRecorder,
    ) -> None:
        cpe = f"cpe:/o:example:run-{uuid.uuid4().hex[:12]}:a"
        run_id = await committed_run(_router({1: cpe}, {1: 7.0}), {cpe: None})
        (product_id, _) = (await _committed(real_session_factory, [cpe]))[cpe]
        dispatcher.failures[product_id] = KombuOperationalError("example failure")

        await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "All 1 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _run_metrics(run) == (0, 0, 1, 1)
        assert (await _committed(real_session_factory, [cpe]))[cpe][1] == Decimal("7.0")

    async def test_one_failed_dispatch_among_successes_is_partial(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        dispatcher: DispatchRecorder,
    ) -> None:
        suffix = uuid.uuid4().hex[:12]
        first, second = (
            f"cpe:/o:example:run-{suffix}:a",
            f"cpe:/o:example:run-{suffix}:b",
        )
        run_id = await committed_run(
            _router({1: first, 2: second}, {1: 7.0, 2: 7.0}),
            {first: None, second: None},
        )
        (product_id, _) = (await _committed(real_session_factory, [first]))[first]
        dispatcher.failures[product_id] = KombuOperationalError("example failure")

        await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "partial"
        assert _run_metrics(run) == (1, 0, 2, 1)

    async def test_escaping_post_commit_scan_failure_preserves_updates(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        dispatcher: DispatchRecorder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        suffix = uuid.uuid4().hex[:12]
        changed, unchanged = (
            f"cpe:/o:example:run-{suffix}:changed",
            f"cpe:/o:example:run-{suffix}:unchanged",
        )
        run_id = await committed_run(
            _router({1: changed, 2: unchanged}, {1: 7.0, 2: 7.0}),
            {changed: None, unchanged: "7.0"},
        )
        failure = OperationalError("SELECT", {}, Exception("example scan failure"))

        async def failing_scan(session: AsyncSession, **kwargs: Any) -> frozenset[Any]:
            raise failure

        monkeypatch.setattr(
            sync_module, "find_product_eligibility_mismatches", failing_scan
        )

        with pytest.raises(OperationalError) as raised:
            await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        assert raised.value is failure
        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (0, 0, 1, 0)
        committed = await _committed(real_session_factory, [changed, unchanged])
        assert {cpe: value for cpe, (_, value) in committed.items()} == {
            changed: Decimal("7.0"),
            unchanged: Decimal("7.0"),
        }
        assert dispatcher.calls == []

    async def test_empty_selected_set_is_a_success(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        dispatcher: DispatchRecorder,
    ) -> None:
        local = f"cpe:/o:example:run-{uuid.uuid4().hex[:12]}:local"
        run_id = await committed_run(
            _router({1: "cpe:/o:example:run-unmatched:1"}, {1: 7.0}), {local: None}
        )

        await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert dispatcher.calls == []

    async def test_retrieval_failure_is_finalized_with_sanitized_message(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        dispatcher: DispatchRecorder,
    ) -> None:
        cpe = f"cpe:/o:example:run-{uuid.uuid4().hex[:12]}:a"
        router = _router({1: cpe}, {1: 7.0})
        router.routes[AIMAAS_TEST_THRESHOLDS_ENDPOINT].responses[1] = lambda request: (
            httpx.Response(503)
        )
        run_id = await committed_run(router, {cpe: "4.0"})

        with pytest.raises(FetcherError, match=r"^AIMAAS returned HTTP 503$"):
            await SyncAimaasThresholds().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "AIMAAS returned HTTP 503"
        assert "aimaas.example.test" not in run.error_message
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert (await _committed(real_session_factory, [cpe]))[cpe][1] == Decimal("4.0")
        assert dispatcher.calls == []


# ---------------------------------------------------------------------------
# Registration and properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY["sync_aimaas_thresholds"] is SyncAimaasThresholds

    def test_properties_match_the_specification(self) -> None:
        assert SyncAimaasThresholds.name == "sync_aimaas_thresholds"
        assert SyncAimaasThresholds.description == (
            "Synchronize AIMAAS Product CVSS thresholds and trigger eligibility "
            "reconciliation"
        )
        assert SyncAimaasThresholds.default_schedule == "45 2 * * *"
        assert SyncAimaasThresholds.participates_in_catch_up is False
        assert SyncAimaasThresholds.Settings is None
        assert SyncAimaasThresholds.queue is None

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(
            part.capitalize() for part in SyncAimaasThresholds.name.split("_")
        )

        assert derived == SyncAimaasThresholds.__name__ == "SyncAimaasThresholds"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert "sync_aimaas_thresholds" not in get_catch_up_fetchers()

    def test_discovery_module_imports_the_fetcher_module(self) -> None:
        source = Path(fetcher_discovery.__file__).read_text(encoding="utf-8")

        assert "import app.services.packages.sync_aimaas_thresholds" in (
            source.splitlines()
        )


@pytest.mark.integration
class TestBootstrap:
    async def test_bootstrap_creates_the_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, "sync_aimaas_thresholds") is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, "sync_aimaas_thresholds")
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == 0
        assert config.custom_settings == {}
