"""Tests for `cve_service.list_cve_sources()` (global persisted-source listing).

Owning specifications: docs/features/tickets/cve-service.md (Service Read
Contracts; Global CVE Source Listing); docs/data-model.md (CVESource,
Derived predicate "stalled"); docs/api-spec.md (Nullable Sort Field
Ordering); docs/features/platform/testing-strategy.md (CVE and Source
Reads > Global persisted-source listing; Concurrency Testing).

Every `db_session` test starts from an empty `cve_source` table (per-test
rollback), so a listing observes exactly the rows the test creates. Rows
are written through `cve_source_factory`, which bypasses
`record_source_status()` so arbitrary statuses and timestamps can be set.
Each row gets a random `CVESource.id`, so the internal tie-breaker order is
independent of insertion order. The independent-session races scope their
listing by a unique source identifier and delete their committed rows.
"""

from __future__ import annotations

import dataclasses
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from app.core.enums import CVESourceFetchStatus, CVESourceSortField, SortOrder
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services.cve_service import (
    CVESourceListItemProjection,
    CVESourceListResult,
    list_cve_sources,
)

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

FEB = datetime(2099, 2, 1, 12, 0, tzinfo=UTC)
MAR = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
APR = datetime(2099, 4, 1, 12, 0, tzinfo=UTC)
MAY = datetime(2099, 5, 1, 12, 0, tzinfo=UTC)
ONE_US = timedelta(microseconds=1)
THIRTY_DAYS = timedelta(days=30)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")
FAILURE: Final = CVESourceFetchStatus.FAILURE.value

_DEFAULTS: Final[dict[str, Any]] = {
    "source": None,
    "status": None,
    "stalled": None,
    "from_date": None,
    "to_date": None,
    "page": 1,
    "per_page": 100,
    "sort_by": CVESourceSortField.FETCHED_AT,
    "sort_order": SortOrder.ASC,
}


async def _list(db: AsyncSession, **overrides: Any) -> CVESourceListResult:
    return await list_cve_sources(db, **{**_DEFAULTS, **overrides})


async def _keys(db: AsyncSession, **overrides: Any) -> set[tuple[str, str]]:
    """`(cve_id, source)` keys of one complete page; the total must equal
    the page and no key may repeat."""
    result = await _list(db, **overrides)
    keys = [(item.cve_id, item.source) for item in result.items]
    assert result.total == len(keys) == len(set(keys))
    return set(keys)


async def _db_now(db: AsyncSession) -> datetime:
    """`now()` of the session's transaction: the instant the service's own
    statement observes in the same transaction."""
    now: datetime = (await db.execute(select(func.now()))).scalar_one()
    return now


@dataclasses.dataclass(frozen=True)
class _Row:
    cve: CVE
    row: CVESource

    @property
    def key(self) -> tuple[str, str]:
        return (self.cve.cve_id, self.row.source)


MakeRow = Callable[..., Awaitable[_Row]]


@pytest.fixture
def make_row(cve_factory: Factory, cve_source_factory: Factory) -> MakeRow:
    """A `CVESource` row (source `nvd` unless overridden) with a random id,
    for `cve` or a fresh CVE."""

    async def _create(*, cve: CVE | None = None, **fields: Any) -> _Row:
        owner: CVE = cve if cve is not None else await cve_factory()
        fields.setdefault("source", "nvd")
        fields.setdefault("id", uuid.uuid4())
        return _Row(owner, await cve_source_factory(cve_id=owner.id, **fields))

    return _create


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


async def _persisted_state(db: AsyncSession) -> tuple[Any, ...]:
    """Row counts and latest modification instants of the related tables."""
    models = (CVE, CVESource, Ticket, TicketAuditEvent, FetcherRun)
    counts = [select(func.count()).select_from(m).scalar_subquery() for m in models]
    stamps = [
        select(func.max(model.updated_at)).scalar_subquery()
        for model in (CVE, CVESource, Ticket)
    ]
    return tuple((await db.execute(select(*counts, *stamps))).one())


# ---------------------------------------------------------------------------
# Identifier-only exception and projection
# ---------------------------------------------------------------------------

ITEM_FIELDS: Final = {
    "cve_id",
    "source",
    "status",
    "fetched_at",
    "first_failed_at",
    "created_at",
    "updated_at",
}
PARAMETERS: Final = [
    "db",
    "source",
    "status",
    "stalled",
    "from_date",
    "to_date",
    "page",
    "per_page",
    "sort_by",
    "sort_order",
]


@pytest.mark.integration
class TestIdentifierOnlyException:
    def test_no_caller_parameter_and_exact_projection_fields(self) -> None:
        assert list(inspect.signature(list_cve_sources).parameters) == PARAMETERS
        fields = dataclasses.fields
        assert {f.name for f in fields(CVESourceListItemProjection)} == ITEM_FIELDS
        assert {f.name for f in fields(CVESourceListResult)} == {
            "items",
            "total",
            "page",
            "per_page",
        }

    async def test_row_of_a_confidential_ticket_cve_exposes_only_the_cve_id(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        make_row: MakeRow,
    ) -> None:
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-71001",
            title="Fictional confidential title",
            description="Fictional confidential description",
        )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        source = await make_row(
            cve=cve, status=FAILURE, fetched_at=MAR, first_failed_at=FEB
        )
        created_at, updated_at = (
            await db_session.execute(
                select(CVESource.created_at, CVESource.updated_at).where(
                    CVESource.id == source.row.id
                )
            )
        ).one()

        result = await _list(db_session)

        assert result == CVESourceListResult(
            items=(
                CVESourceListItemProjection(
                    cve_id="CVE-2099-71001",
                    source="nvd",
                    status=CVESourceFetchStatus.FAILURE,
                    fetched_at=MAR,
                    first_failed_at=FEB,
                    created_at=created_at,
                    updated_at=updated_at,
                ),
            ),
            total=1,
            page=1,
            per_page=100,
        )
        (item,) = result.items
        assert type(item.status) is CVESourceFetchStatus
        assert not any(isinstance(getattr(item, n), uuid.UUID) for n in ITEM_FIELDS)
        secrets = (source.row.id, cve.id, ticket.id, f"SNTL-{ticket.sequence_id}")
        for secret in (*map(str, secrets), "Fictional confidential"):
            assert secret not in repr(item)


# ---------------------------------------------------------------------------
# source and status filters
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSourceAndStatusFilters:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            pytest.param(None, ["nvd-1", "nvd-2", "retired", "nvd_extra"], id="all"),
            pytest.param("nvd", ["nvd-1", "nvd-2"], id="current"),
            pytest.param("retired_source", ["retired"], id="historical"),
            pytest.param("nvd_extra", ["nvd_extra"], id="exact-not-prefix"),
            pytest.param("nv", [], id="prefix-of-existing"),
            pytest.param("absent_source", [], id="absent"),
        ],
    )
    async def test_source_is_an_exact_match(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        source: str | None,
        expected: list[str],
    ) -> None:
        """A deregistered identifier persisted on the same CVE as a current
        one is listed like any other row."""
        first = await make_row()
        rows = {
            "nvd-1": first,
            "nvd-2": await make_row(),
            "retired": await make_row(cve=first.cve, source="retired_source"),
            "nvd_extra": await make_row(source="nvd_extra"),
        }

        assert await _keys(db_session, source=source) == {
            rows[name].key for name in expected
        }

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            pytest.param(None, ["success", "failure", "missing"], id="omitted"),
            pytest.param("success", ["success"], id="success"),
            pytest.param("failure", ["failure"], id="failure"),
            pytest.param("missing", ["missing"], id="missing"),
            pytest.param("FAILURE", [], id="stored-casing"),
            pytest.param("pending", [], id="derived-pending"),
            pytest.param("not_attempted", [], id="derived-not-attempted"),
            pytest.param("bogus", [], id="bogus"),
            pytest.param("", [], id="empty"),
        ],
    )
    async def test_status_matches_only_persisted_values(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        status: str | None,
        expected: list[str],
    ) -> None:
        rows = {
            "success": await make_row(status="success"),
            "failure": await make_row(status=FAILURE, first_failed_at=FEB),
            "missing": await make_row(status="missing"),
        }

        assert await _keys(db_session, status=status) == {
            rows[name].key for name in expected
        }


# ---------------------------------------------------------------------------
# stalled: 30-day boundary at the statement's database instant
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _StalledWorld:
    now: datetime
    rows: dict[str, _Row]

    def keys(self, *names: str) -> set[tuple[str, str]]:
        return {self.rows[name].key for name in names}


STALLED: Final = ("over", "retired_over")
NOT_STALLED: Final = (
    "exact",
    "under",
    "null_streak",
    "success",
    "missing",
    "success_old_streak",
)


@pytest.fixture
async def stalled_world(db_session: AsyncSession, make_row: MakeRow) -> _StalledWorld:
    """`over` is 30 days + 1 us before `now()` (stalled), `exact` exactly 30
    days (not stalled: strict `<`), `under` 30 days - 1 us. A `success`
    row with an old streak timestamp proves the status gate."""
    now = await _db_now(db_session)
    threshold = now - THIRTY_DAYS
    specs: dict[str, dict[str, Any]] = {
        "over": {"status": FAILURE, "first_failed_at": threshold - ONE_US},
        "exact": {"status": FAILURE, "first_failed_at": threshold},
        "under": {"status": FAILURE, "first_failed_at": threshold + ONE_US},
        "null_streak": {"status": FAILURE, "first_failed_at": None},
        "success": {"status": "success"},
        "missing": {"status": "missing"},
        "success_old_streak": {
            "status": "success",
            "first_failed_at": threshold - timedelta(days=5),
        },
        "retired_over": {
            "status": FAILURE,
            "first_failed_at": threshold - timedelta(days=5),
            "source": "retired_source",
        },
    }
    rows = {
        name: await make_row(fetched_at=MAR + timedelta(minutes=index), **fields)
        for index, (name, fields) in enumerate(specs.items())
    }
    return _StalledWorld(now, rows)


@pytest.mark.integration
class TestStalledFilter:
    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            pytest.param({"stalled": True}, STALLED, id="only-stalled"),
            pytest.param({"stalled": False}, NOT_STALLED, id="all-but-stalled"),
            pytest.param({"stalled": None}, STALLED + NOT_STALLED, id="omitted"),
            pytest.param({"stalled": True, "status": "success"}, (), id="success"),
            pytest.param(
                {"stalled": True, "status": "failure"}, STALLED, id="stalled-failure"
            ),
            pytest.param(
                {"status": "failure", "stalled": False},
                ("exact", "under", "null_streak"),
                id="non-stalled-failures",
            ),
            pytest.param({"stalled": True, "source": "nvd"}, ("over",), id="nvd"),
            pytest.param(
                {"stalled": False, "source": "retired_source"}, (), id="retired"
            ),
        ],
    )
    async def test_boundary_and_combinations(
        self,
        db_session: AsyncSession,
        stalled_world: _StalledWorld,
        filters: dict[str, Any],
        expected: tuple[str, ...],
    ) -> None:
        assert await _db_now(db_session) == stalled_world.now
        assert await _keys(db_session, **filters) == stalled_world.keys(*expected)

    @pytest.mark.parametrize(
        ("stalled", "names", "per_page"),
        [(True, STALLED, 1), (False, NOT_STALLED, 4)],
        ids=["stalled", "not-stalled"],
    )
    async def test_page_and_total_use_the_same_boundary(
        self,
        db_session: AsyncSession,
        stalled_world: _StalledWorld,
        stalled: bool,
        names: tuple[str, ...],
        per_page: int,
    ) -> None:
        pages = [
            await _list(db_session, stalled=stalled, page=page, per_page=per_page)
            for page in (1, 2, 3)
        ]

        assert [page.total for page in pages] == [len(names)] * 3
        assert [len(page.items) for page in pages] == [
            per_page,
            len(names) - per_page,
            0,
        ]
        paged = [(item.cve_id, item.source) for page in pages for item in page.items]
        assert len(paged) == len(set(paged))
        assert set(paged) == stalled_world.keys(*names)


# ---------------------------------------------------------------------------
# Date bounds and AND across every filter
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDateBoundsAndConjunction:
    @pytest.mark.parametrize(
        ("bounds", "expected"),
        [
            pytest.param({"from_date": MAR}, ["mar", "after", "apr"], id="from"),
            pytest.param({"to_date": MAR}, ["feb", "before", "mar"], id="to"),
            pytest.param({"from_date": MAR, "to_date": MAR}, ["mar"], id="same"),
            pytest.param({"from_date": MAR + ONE_US}, ["after", "apr"], id="from+1"),
            pytest.param({"to_date": MAR - ONE_US}, ["feb", "before"], id="to-1"),
            pytest.param(
                {"from_date": MAR - ONE_US, "to_date": MAR + ONE_US},
                ["before", "mar", "after"],
                id="window",
            ),
        ],
    )
    async def test_fetched_at_bounds_are_inclusive(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        bounds: dict[str, datetime],
        expected: list[str],
    ) -> None:
        instants = {
            "feb": FEB,
            "before": MAR - ONE_US,
            "mar": MAR,
            "after": MAR + ONE_US,
            "apr": APR,
        }
        rows = {name: await make_row(fetched_at=at) for name, at in instants.items()}

        assert await _keys(db_session, **bounds) == {rows[n].key for n in expected}

    @pytest.mark.parametrize(
        "omitted", [None, "source", "status", "stalled", "from_date", "to_date"]
    )
    async def test_every_filter_is_and_combined(
        self, db_session: AsyncSession, make_row: MakeRow, omitted: str | None
    ) -> None:
        """Each `miss` row fails exactly one filter, so dropping that filter
        adds exactly that row."""
        stalled_streak = await _db_now(db_session) - THIRTY_DAYS - ONE_US
        failing = {"status": FAILURE, "first_failed_at": APR, "fetched_at": MAR}
        match = await make_row(**failing)
        misses = {
            "source": await make_row(**{**failing, "source": "retired_source"}),
            "status": await make_row(status="success", fetched_at=MAR),
            "stalled": await make_row(**{**failing, "first_failed_at": stalled_streak}),
            "from_date": await make_row(**{**failing, "fetched_at": MAR - ONE_US}),
            "to_date": await make_row(**{**failing, "fetched_at": APR + ONE_US}),
        }
        filters: dict[str, Any] = {
            "source": "nvd",
            "status": "failure",
            "stalled": False,
            "from_date": MAR,
            "to_date": APR,
        }
        expected = {match.key}
        if omitted is not None:
            del filters[omitted]
            expected.add(misses[omitted].key)

        assert await _keys(db_session, **filters) == expected


# ---------------------------------------------------------------------------
# Ordering and pagination
# ---------------------------------------------------------------------------


def _ordered_by_id(rows: list[_Row], sort_order: SortOrder) -> list[_Row]:
    return sorted(rows, key=lambda r: r.row.id, reverse=sort_order is SortOrder.DESC)


async def _sources(db: AsyncSession, **overrides: Any) -> list[tuple[str, str]]:
    result = await _list(db, **overrides)
    assert result.total == len(result.items)
    return [(item.cve_id, item.source) for item in result.items]


@pytest.mark.integration
class TestSorting:
    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_source_uses_code_point_order(
        self, db_session: AsyncSession, make_row: MakeRow, sort_order: SortOrder
    ) -> None:
        """Code point puts `a_z` before `ab` and `nvd2` before `nvd_2`; a
        linguistic collation that ignores `_` would not."""
        ascending = ["a_z", "ab", "nvd", "nvd2", "nvd_2", "retired_source"]
        assert sorted(ascending) == ascending
        rows = {
            name: await make_row(source=name)
            for name in ("nvd_2", "retired_source", "ab", "nvd", "a_z", "nvd2")
        }
        names = ascending if sort_order is SortOrder.ASC else ascending[::-1]

        assert await _sources(
            db_session, sort_by=CVESourceSortField.SOURCE, sort_order=sort_order
        ) == [rows[name].key for name in names]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_status_uses_code_point_order(
        self, db_session: AsyncSession, make_row: MakeRow, sort_order: SortOrder
    ) -> None:
        rows = {
            status: await make_row(status=status)
            for status in ("success", "missing", "failure")
        }
        names = ["failure", "missing", "success"]
        if sort_order is SortOrder.DESC:
            names.reverse()

        assert await _sources(
            db_session, sort_by=CVESourceSortField.STATUS, sort_order=sort_order
        ) == [rows[name].key for name in names]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize(
        ("sort_by", "column", "nullable"),
        [
            (CVESourceSortField.FETCHED_AT, "fetched_at", False),
            (CVESourceSortField.FIRST_FAILED_AT, "first_failed_at", True),
        ],
        ids=["fetched_at", "first_failed_at"],
    )
    async def test_timestamps_with_null_last_in_both_directions(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        sort_by: CVESourceSortField,
        column: str,
        nullable: bool,
        sort_order: SortOrder,
    ) -> None:
        """`fetched_at` is NOT NULL, so only `first_failed_at` has a `NULL`
        group; it is last in both directions, ordered by `CVESource.id`."""
        dated = {
            at: await make_row(status=FAILURE, **{column: at}) for at in (APR, FEB, MAY)
        }
        undated = (
            [await make_row(status="success") for _ in range(2)] if nullable else []
        )
        ordered = [dated[at] for at in (FEB, APR, MAY)]
        if sort_order is SortOrder.DESC:
            ordered.reverse()
        expected = [*ordered, *_ordered_by_id(undated, sort_order)]

        assert await _sources(db_session, sort_by=sort_by, sort_order=sort_order) == [
            row.key for row in expected
        ]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize(
        ("sort_by", "tied", "null"),
        [
            (CVESourceSortField.SOURCE, {}, {}),
            (CVESourceSortField.STATUS, {}, {}),
            (CVESourceSortField.FETCHED_AT, {}, {}),
            (
                CVESourceSortField.FIRST_FAILED_AT,
                {"first_failed_at": FEB},
                {"first_failed_at": None},
            ),
        ],
        ids=["source", "status", "fetched_at", "first_failed_at"],
    )
    async def test_equal_keys_page_stably_by_internal_id(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        sort_by: CVESourceSortField,
        tied: dict[str, Any],
        null: dict[str, Any],
        sort_order: SortOrder,
    ) -> None:
        """Every row shares `source`, `status`, and `fetched_at`; for
        `first_failed_at` five rows tie and two are `NULL`. Random ids make
        the id order differ from insertion and CVE-ID order. Two-row pages
        over five requests neither repeat nor skip."""
        common = {"status": FAILURE, "fetched_at": MAR}
        tied_rows = [await make_row(**common, **tied) for _ in range(5)]
        null_rows = [await make_row(**common, **null) for _ in range(2)]
        if sort_by is CVESourceSortField.FIRST_FAILED_AT:
            full = [
                *_ordered_by_id(tied_rows, sort_order),
                *_ordered_by_id(null_rows, sort_order),
            ]
        else:
            full = _ordered_by_id(tied_rows + null_rows, sort_order)

        pages = [
            await _list(
                db_session, sort_by=sort_by, sort_order=sort_order, page=n, per_page=2
            )
            for n in range(1, 6)
        ]

        assert [len(page.items) for page in pages] == [2, 2, 2, 1, 0]
        assert {page.total for page in pages} == {7}
        paged = [(i.cve_id, i.source) for page in pages for i in page.items]
        assert paged == [row.key for row in full]


@pytest.mark.integration
class TestPagination:
    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession, make_row: MakeRow
    ) -> None:
        for _ in range(3):
            await make_row()

        assert await _list(db_session, page=4, per_page=1) == CVESourceListResult(
            items=(), total=3, page=4, per_page=1
        )
        assert await _list(db_session, page=2, per_page=3) == CVESourceListResult(
            items=(), total=3, page=2, per_page=3
        )
        assert await _list(db_session, source="absent_source") == CVESourceListResult(
            items=(), total=0, page=1, per_page=100
        )

    @pytest.mark.parametrize(
        ("page", "per_page"), [(0, 20), (-1, 20), (1, 0), (1, 101)]
    )
    async def test_out_of_range_pagination_raises_before_any_statement(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await _list(db, page=page, per_page=per_page)

        db.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Bounded read-only statement and latest-state divergence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundedReadAndDivergence:
    async def test_one_read_only_statement_regardless_of_page_size(
        self, db_session: AsyncSession, make_row: MakeRow, ticket_factory: Factory
    ) -> None:
        for index in range(12):
            row = await make_row(status=FAILURE, first_failed_at=APR)
            if index % 2:
                await ticket_factory(cve_id=row.cve.id, is_confidential=index % 4 == 1)
        before = await _persisted_state(db_session)

        counts = []
        for per_page in (1, 5, 12):
            with _StatementRecorder(db_session) as recorder:
                result = await _list(
                    db_session,
                    stalled=False,
                    per_page=per_page,
                    sort_by=CVESourceSortField.FIRST_FAILED_AT,
                )
            assert result.total == 12
            assert len(result.items) == per_page
            counts.append(len(recorder.statements))
            statement = recorder.statements[0]
            assert statement.lstrip().upper().startswith("WITH")
            for row_lock in ROW_LOCKS:
                assert row_lock not in statement.upper()
            assert "ticket" not in statement.lower()

        assert counts == [1, 1, 1]
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()
        assert await _persisted_state(db_session) == before

    async def test_drill_down_count_diverges_from_the_run_aggregate(
        self, db_session: AsyncSession, make_row: MakeRow, fetcher_run_factory: Factory
    ) -> None:
        """The run failed three CVEs. One is still failing in the window, one
        was later retried to `success`, and one failed again after the
        window; an on-demand failure landed inside the window. The listing
        shows the latest state (two rows), not the run (three)."""
        finished = MAR + timedelta(hours=1)
        run: FetcherRun = await fetcher_run_factory(
            status="partial",
            started_at=MAR,
            finished_at=finished,
            items_succeeded=5,
            items_failed=3,
        )
        still_failing = await make_row(
            status=FAILURE, fetched_at=MAR + timedelta(minutes=10), first_failed_at=MAR
        )
        await make_row(status="success", fetched_at=APR)
        await make_row(status=FAILURE, fetched_at=APR, first_failed_at=MAR)
        on_demand = await make_row(
            status=FAILURE,
            fetched_at=MAR + timedelta(minutes=50),
            first_failed_at=MAR + timedelta(minutes=50),
        )
        run_row = select(*FetcherRun.__table__.columns).where(FetcherRun.id == run.id)
        before = (await db_session.execute(run_row)).one()

        result = await _list(
            db_session, source="nvd", status="failure", from_date=MAR, to_date=finished
        )

        assert {(i.cve_id, i.source) for i in result.items} == {
            still_failing.key,
            on_demand.key,
        }
        assert result.total == 2 != before.items_failed == 3
        assert (await db_session.execute(run_row)).one() == before


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------

DAY = timedelta(days=1)
OLD_STREAK = timedelta(days=31)


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@dataclasses.dataclass(frozen=True)
class _Committed:
    cve_pk: uuid.UUID
    key: tuple[str, str]
    inserts: tuple[Executable, ...]


@dataclasses.dataclass
class _Race:
    """Committed CVEs whose rows share one unique, grammar-valid source
    identifier (xdist-safe), a reader session R, a writer session W, and
    fresh sessions observing the committed state. Teardown deletes the
    CVEs; their rows go with the `ON DELETE CASCADE`."""

    owner: AsyncSession
    reader: AsyncSession
    writer: AsyncSession
    sessions: SessionFactory
    source: str = dataclasses.field(
        default_factory=lambda: f"fictional_race_{uuid.uuid4().hex[:12]}"
    )
    cve_pks: list[uuid.UUID] = dataclasses.field(default_factory=list)

    def new(self, status: str, streak_age: timedelta | None = None) -> _Committed:
        """Inserts of a fresh CVE and its row, registered for cleanup."""
        cve_pk, cve_id = uuid.uuid7(), f"CVE-2099-{uuid.uuid4().int % 10**9:09d}"
        self.cve_pks.append(cve_pk)
        streak = func.now() - streak_age if streak_age is not None else None
        return _Committed(
            cve_pk,
            (cve_id, self.source),
            (
                insert(CVE).values(id=cve_pk, cve_id=cve_id),
                insert(CVESource).values(
                    cve_id=cve_pk,
                    source=self.source,
                    status=status,
                    fetched_at=func.now(),
                    first_failed_at=streak,
                ),
            ),
        )

    async def row(self, status: str, streak_age: timedelta | None = None) -> _Committed:
        committed = self.new(status, streak_age)
        await _commit(self.owner, *committed.inserts)
        return committed

    def reclassify(self, row: _Committed, **values: Any) -> Executable:
        return (
            update(CVESource)
            .where(CVESource.cve_id == row.cve_pk, CVESource.source == self.source)
            .values(fetched_at=func.now(), **values)
        )

    async def keys(
        self, db: AsyncSession, **filters: Any
    ) -> tuple[set[tuple[str, str]], int]:
        return await _keys(db, source=self.source, **filters), (
            await _list(db, source=self.source, per_page=1, **filters)
        ).total

    async def cleanup(self) -> None:
        await self.owner.rollback()
        await _commit(self.owner, delete(CVE).where(CVE.id.in_(self.cve_pks)))


@pytest.fixture
async def race(db_session_factory: SessionFactory) -> AsyncIterator[_Race]:
    state = _Race(
        owner=await db_session_factory(),
        reader=await db_session_factory(),
        writer=await db_session_factory(),
        sessions=db_session_factory,
    )
    try:
        yield state
    finally:
        await state.cleanup()


@dataclasses.dataclass(frozen=True)
class _Scenario:
    filters: dict[str, Any]
    before: set[tuple[str, str]]
    change: tuple[Executable, ...]
    after: set[tuple[str, str]]


async def _scenario(race: _Race, kind: str) -> _Scenario:
    """`status`: one failure becomes `success`, one `success` becomes a
    failure, and a failure is added. `stalled`: the stalled row recovers,
    a recent streak is backdated past 30 days, and a stalled row is added.
    Each change moves the filtered set from one row to two others."""
    stalled = kind == "stalled"
    first = await race.row(FAILURE, OLD_STREAK if stalled else DAY)
    second = await race.row(FAILURE if stalled else "success", DAY if stalled else None)
    added = race.new(FAILURE, OLD_STREAK if stalled else DAY)
    moved = (
        {"first_failed_at": func.now() - OLD_STREAK}
        if stalled
        else {"status": FAILURE, "first_failed_at": func.now()}
    )
    return _Scenario(
        {"stalled": True} if stalled else {"status": "failure"},
        {first.key},
        (
            race.reclassify(first, status="success", first_failed_at=None),
            race.reclassify(second, **moved),
            *added.inserts,
        ),
        {second.key, added.key},
    )


def _commit_after_first_statement(
    monkeypatch: pytest.MonkeyPatch,
    reader: AsyncSession,
    change: Callable[[], Awaitable[None]],
) -> list[int]:
    """Commit `change` from another session right after the reader's first
    statement returns; returns a one-element call counter. A read split
    into several statements would observe the change in a later one."""
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


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["status", "stalled"])
class TestListingRaces:
    """W adds and reclassifies rows. Between two listings R observes the
    change (R holds no snapshot); committed right after R's first
    statement, the one-statement listing returns the coherent pre-change
    page and total, and a fresh session observes the change."""

    async def test_change_between_listings_is_observed(
        self, race: _Race, kind: str
    ) -> None:
        scenario = await _scenario(race, kind)

        assert await race.keys(race.reader, **scenario.filters) == (scenario.before, 1)
        await _commit(race.writer, *scenario.change)

        assert await race.keys(race.reader, **scenario.filters) == (scenario.after, 2)

    async def test_change_after_the_first_statement_is_not_observed(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch, kind: str
    ) -> None:
        scenario = await _scenario(race, kind)

        async def change() -> None:
            await _commit(race.writer, *scenario.change)

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        result = await _list(race.reader, source=race.source, **scenario.filters)

        assert calls == [1]
        assert result.total == 1
        assert {(i.cve_id, i.source) for i in result.items} == scenario.before
        fresh = await race.sessions()
        assert await race.keys(fresh, **scenario.filters) == (scenario.after, 2)
