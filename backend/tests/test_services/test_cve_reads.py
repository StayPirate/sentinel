"""Tests for `cve_service.list_cves()` and `cve_service.get_cve_detail()`.

Owning specifications: docs/features/tickets/cve-service.md (CVE Read and
Accessibility Boundary; Service Read Contracts > CVE List, CVE Detail);
docs/features/tickets/cve-tracking.md (List CVEs; Get CVE);
docs/features/tickets/tickets.md (Shared Sub-Schemas: `CVEDetail`);
docs/api-spec.md (Request Conventions; CVE Accessibility Check; CVE
Identifier Resolution); docs/features/platform/testing-strategy.md (CVE
and Source Reads; Ticket Accessibility; Concurrency Testing).

Every `db_session` test starts from an empty CVE table (per-test
rollback), so a list observes exactly the CVEs the test creates. The
independent-session races scope their lists by a unique title token and
delete their committed rows explicitly.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from app.core.enums import CVESortField, CveState, Role, Scope, Severity, SortOrder
from app.core.exceptions import CVENotFoundError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.models.user_role import UserRole
from app.services.cve_projection import (
    CVEDetailProjection,
    CVEEPSSProjection,
    CVEExternalIdentifierProjection,
    CVEKEVProjection,
    CVESSVCProjection,
    CVEWeaknessProjection,
)
from app.services.cve_service import (
    CVEDetailResult,
    CVEListItemProjection,
    CVEListResult,
    get_cve_detail,
    list_cves,
)
from app.services.ticket_service import get_ticket_detail
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
EXCLUDED_AT = datetime(2099, 1, 2, 9, 0, tzinfo=UTC)
FEB = datetime(2099, 2, 1, 12, 0, tzinfo=UTC)
MAR = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
APR = datetime(2099, 4, 1, 12, 0, tzinfo=UTC)
MAY = datetime(2099, 5, 1, 12, 0, tzinfo=UTC)
ONE_US = timedelta(microseconds=1)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")

_LIST_DEFAULTS: Final[dict[str, Any]] = {
    "search": None,
    "cve_state": None,
    "severity": None,
    "has_ticket": None,
    "from_date": None,
    "to_date": None,
    "page": 1,
    "per_page": 100,
    "sort_by": CVESortField.CVE_ID,
    "sort_order": SortOrder.ASC,
}


def _restricted(user: User | uuid.UUID) -> TicketCaller:
    user_id = user if isinstance(user, uuid.UUID) else user.id
    return TicketCaller.authenticated(user_id, Scope.NON_CONFIDENTIAL)


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


async def _list(
    db: AsyncSession, caller: TicketCaller = ALL_SCOPE, **overrides: Any
) -> CVEListResult:
    return await list_cves(db, caller, **{**_LIST_DEFAULTS, **overrides})


async def _ids(
    db: AsyncSession, caller: TicketCaller = ALL_SCOPE, **overrides: Any
) -> list[str]:
    """CVE-IDs of one complete page; the total must equal the page."""
    result = await _list(db, caller, **overrides)
    assert result.total == len(result.items)
    return [item.cve_id for item in result.items]


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


def _assert_read_only_statement(statement: str, prefix: str) -> None:
    assert statement.lstrip().upper().startswith(prefix)
    for row_lock in ROW_LOCKS:
        assert row_lock not in statement.upper()


async def _persisted_state(db: AsyncSession) -> tuple[Any, ...]:
    """Row counts and latest modification instants of the touched tables."""
    counts = [
        select(func.count()).select_from(table).scalar_subquery()
        for table in (CVE, Ticket, TicketAuditEvent)
    ]
    stamps = [
        select(func.max(model.updated_at)).scalar_subquery() for model in (CVE, Ticket)
    ]
    return tuple((await db.execute(select(*counts, *stamps))).one())


def _assert_untouched_session(db: AsyncSession) -> None:
    """No pending ORM change and the caller-owned transaction still open."""
    assert not db.new
    assert not db.dirty
    assert not db.deleted
    assert db.in_transaction()


def _assert_no_uuid(value: Any) -> None:
    for field in dataclasses.fields(value):
        assert not isinstance(getattr(value, field.name), uuid.UUID), field.name


@dataclasses.dataclass(frozen=True)
class _Make:
    """The `tests/conftest.py` model factories this module uses."""

    cve: Factory
    ticket: Factory
    user: Factory
    grant: Factory
    package: Factory
    maintainer: Factory
    cwe: Factory
    external_id: Factory
    kev: Factory
    epss: Factory
    ssvc: Factory
    source: Factory
    cvss: Factory

    async def maintained(
        self,
        ticket: Ticket,
        user: User | None = None,
        deleted_at: datetime | None = None,
    ) -> TicketPackage:
        """A package of `ticket` maintained by `user` (a fresh user when
        omitted), directly excluded when `deleted_at` is set."""
        package: TicketPackage = await self.package(
            ticket_id=ticket.id, deleted_at=deleted_at
        )
        owner = {} if user is None else {"user_id": user.id}
        await self.maintainer(ticket_package_id=package.id, **owner)
        return package


_FACTORY_FIXTURES: Final = {
    "cve": "cve_factory",
    "ticket": "ticket_factory",
    "user": "user_factory",
    "grant": "ticket_access_grant_factory",
    "package": "ticket_package_factory",
    "maintainer": "ticket_package_maintainer_factory",
    "cwe": "cve_cwe_factory",
    "external_id": "cve_external_identifier_factory",
    "kev": "cve_kev_entry_factory",
    "epss": "cve_epss_score_factory",
    "ssvc": "cve_ssvc_assessment_factory",
    "source": "cve_source_factory",
    "cvss": "cve_cvss_assessment_factory",
}


@pytest.fixture
def make(request: pytest.FixtureRequest) -> _Make:
    return _Make(
        **{
            name: request.getfixturevalue(fixture)
            for name, fixture in _FACTORY_FIXTURES.items()
        }
    )


# ---------------------------------------------------------------------------
# list_cves: canonical predicate (mixed visible and invisible rows)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _VisibilityWorld:
    """Seven CVEs covering every canonical-predicate branch, keyed by name,
    and the expected accessible names for each caller."""

    cves: dict[str, CVE]
    expectations: dict[TicketCaller, list[str]]


@pytest.fixture
async def visibility_world(make: _Make) -> _VisibilityWorld:
    user: User = await make.user()
    names = ("ticketless", "public", "hidden", "granted", "maintained")
    cves: dict[str, CVE] = {
        name: await make.cve(cve_id=f"CVE-2099-{40001 + index}")
        for index, name in enumerate((*names, "excluded", "multi"))
    }
    await make.ticket(cve_id=cves["public"].id, is_confidential=False)
    hidden = await make.ticket(cve_id=cves["hidden"].id, is_confidential=True)
    await make.grant(ticket_id=hidden.id)
    await make.maintained(hidden)
    granted = await make.ticket(cve_id=cves["granted"].id, is_confidential=True)
    await make.grant(ticket_id=granted.id, user_id=user.id)
    for name, deleted in (
        ("maintained", [None]),
        ("excluded", [EXCLUDED_AT]),
        ("multi", [EXCLUDED_AT, None]),
    ):
        ticket = await make.ticket(cve_id=cves[name].id, is_confidential=True)
        for deleted_at in deleted:
            await make.maintained(ticket, user, deleted_at)
    public = ["ticketless", "public"]
    return _VisibilityWorld(
        cves,
        {
            ANONYMOUS_CALLER: public,
            _restricted(uuid.uuid4()): public,
            _restricted(user): [*public, "granted", "maintained", "multi"],
            ALL_SCOPE: list(cves),
        },
    )


@pytest.mark.integration
class TestListVisibility:
    async def test_mixed_visibility_items_and_total(
        self, db_session: AsyncSession, visibility_world: _VisibilityWorld
    ) -> None:
        """`excluded` (only maintained package excluded) is invisible while
        `multi` (one excluded, one included maintained package) stays
        visible to its maintainer."""
        cves = visibility_world.cves
        for caller, visible in visibility_world.expectations.items():
            expected = sorted(cves[name].cve_id for name in visible)
            assert (await _list(db_session, caller, per_page=1)).total == len(visible)
            assert await _ids(db_session, caller) == expected, caller

    async def test_hidden_rows_never_match_a_filter_search_or_sort(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        hidden: CVE = await make.cve(
            title="secret fictional flaw",
            severity=Severity.CRITICAL.value,
            published_date=MAR,
        )
        await make.ticket(cve_id=hidden.id, is_confidential=True)

        for filters in (
            {"search": "secret"},
            {"search": hidden.cve_id},
            {"severity": ["critical"]},
            {"has_ticket": True},
            {"from_date": FEB},
            {"sort_by": CVESortField.SEVERITY},
        ):
            result = await _list(db_session, ANONYMOUS_CALLER, **filters)
            assert (result.items, result.total) == ((), 0), filters

    async def test_anonymous_statement_evaluates_no_grant_or_maintainer_branch(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        await make.cve()

        with _StatementRecorder(db_session) as recorder:
            await _list(db_session, ANONYMOUS_CALLER)

        (statement,) = recorder.statements
        assert "ticket_access_grant" not in statement
        assert "ticket_package_maintainer" not in statement


# ---------------------------------------------------------------------------
# list_cves: filters alone and combined
# ---------------------------------------------------------------------------


@pytest.fixture
async def filter_world(make: _Make) -> None:
    """Five accessible CVEs and one confidential associated CVE (hidden
    from the anonymous caller used by the filter matrix)."""
    rows = (
        ("alpha", CveState.PUBLISHED, Severity.HIGH, MAR, None),
        ("bravo", CveState.REJECTED, Severity.NONE, APR, False),
        ("charlie", CveState.PUBLISHED, None, None, False),
        ("delta", CveState.PUBLISHED, Severity.CRITICAL, MAY, None),
        ("echo", CveState.REJECTED, Severity.LOW, FEB, None),
        ("hidden", CveState.PUBLISHED, Severity.HIGH, MAR, True),
    )
    for index, (name, state, severity, published, confidential) in enumerate(rows):
        cve: CVE = await make.cve(
            cve_id=f"CVE-2099-{20001 + index}",
            title=f"{name} fictional flaw",
            cve_state=state.value,
            severity=severity.value if severity is not None else None,
            published_date=published,
        )
        if confidential is not None:
            await make.ticket(cve_id=cve.id, is_confidential=confidential)


_NAMES: Final = {
    "alpha": "CVE-2099-20001",
    "bravo": "CVE-2099-20002",
    "charlie": "CVE-2099-20003",
    "delta": "CVE-2099-20004",
    "echo": "CVE-2099-20005",
}
ALL_SEVERITIES: Final = ["critical", "high", "medium", "low", "none", "unresolved"]
FIVE: Final = ["alpha", "bravo", "charlie", "delta", "echo"]

FILTER_CASES: Final[list[tuple[str, dict[str, Any], list[str]]]] = [
    ("omitted", {}, FIVE),
    ("state-published", {"cve_state": "published"}, ["alpha", "charlie", "delta"]),
    ("state-rejected", {"cve_state": "rejected"}, ["bravo", "echo"]),
    ("state-stored-casing", {"cve_state": "PUBLISHED"}, []),
    ("state-bogus", {"cve_state": "bogus"}, []),
    ("state-empty", {"cve_state": ""}, []),
    ("severity-high", {"severity": ["high"]}, ["alpha"]),
    ("severity-none-label", {"severity": ["none"]}, ["bravo"]),
    ("severity-unresolved", {"severity": ["unresolved"]}, ["charlie"]),
    ("severity-or", {"severity": ["critical", "low"]}, ["delta", "echo"]),
    (
        "severity-none-or-null",
        {"severity": ["none", "unresolved"]},
        ["bravo", "charlie"],
    ),
    ("severity-invalid-dropped", {"severity": ["high", "bogus"]}, ["alpha"]),
    ("severity-empty", {"severity": []}, []),
    ("severity-only-invalid", {"severity": ["bogus", "critical,high"]}, []),
    ("severity-all", {"severity": ALL_SEVERITIES}, FIVE),
    ("has-ticket", {"has_ticket": True}, ["bravo", "charlie"]),
    ("no-ticket", {"has_ticket": False}, ["alpha", "delta", "echo"]),
    ("from-exact", {"from_date": MAR}, ["alpha", "bravo", "delta"]),
    ("to-exact", {"to_date": MAR}, ["alpha", "echo"]),
    ("from-to-same-instant", {"from_date": MAR, "to_date": MAR}, ["alpha"]),
    ("from-just-after", {"from_date": MAR + ONE_US}, ["bravo", "delta"]),
    ("to-just-before", {"to_date": MAR - ONE_US}, ["echo"]),
    (
        "state-severity-ticket",
        {
            "cve_state": "published",
            "severity": ["high", "critical"],
            "has_ticket": False,
        },
        ["alpha", "delta"],
    ),
    ("rejected-with-ticket", {"cve_state": "rejected", "has_ticket": True}, ["bravo"]),
    ("severity-and-from", {"severity": ["none", "low"], "from_date": MAR}, ["bravo"]),
    ("ticket-and-to", {"has_ticket": True, "to_date": APR}, ["bravo"]),
    (
        "search-and-state",
        {"search": "fictional", "cve_state": "rejected"},
        ["bravo", "echo"],
    ),
    ("unresolved-and-date", {"severity": ["unresolved"], "from_date": FEB}, []),
    ("valid-and-empty-state", {"severity": ["high"], "cve_state": "bogus"}, []),
]


@pytest.mark.integration
@pytest.mark.usefixtures("filter_world")
class TestListFilters:
    @pytest.mark.parametrize(
        ("filters", "expected"),
        [(filters, expected) for _, filters, expected in FILTER_CASES],
        ids=[name for name, _, _ in FILTER_CASES],
    )
    async def test_filter_matrix_for_the_anonymous_caller(
        self, db_session: AsyncSession, filters: dict[str, Any], expected: list[str]
    ) -> None:
        result = await _list(db_session, ANONYMOUS_CALLER, **filters)

        assert [item.cve_id for item in result.items] == [_NAMES[n] for n in expected]
        assert result.total == len(expected)

    async def test_has_ticket_includes_the_confidential_cve_only_when_accessible(
        self, db_session: AsyncSession
    ) -> None:
        assert await _ids(db_session, ALL_SCOPE, has_ticket=True) == [
            "CVE-2099-20002",
            "CVE-2099-20003",
            "CVE-2099-20006",
        ]
        assert await _ids(db_session, ANONYMOUS_CALLER, has_ticket=True) == [
            "CVE-2099-20002",
            "CVE-2099-20003",
        ]


# ---------------------------------------------------------------------------
# list_cves: search
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListSearch:
    @pytest.mark.parametrize(
        ("term", "expected"),
        [
            pytest.param(
                "cve-2099-3", ["30001", "30002", "31000"], id="id-prefix-lower"
            ),
            pytest.param("CVE-2099-30", ["30001", "30002"], id="id-prefix"),
            pytest.param("Cve-2099-31000", ["31000"], id="id-full-mixed-case"),
            pytest.param("2099-3000", [], id="id-mid-substring"),
            pytest.param("-30001", [], id="id-suffix"),
            pytest.param("fictional", ["30001", "30002"], id="title-or-description"),
            pytest.param("OVERFLOW", ["30001"], id="title-case-insensitive"),
            pytest.param("  overflow\t", ["30001"], id="trimmed-substring"),
            pytest.param(" cve-2099-31", ["31000"], id="trimmed-id-prefix"),
            pytest.param("after FREE", ["30002"], id="description-case-insensitive"),
        ],
    )
    async def test_id_prefix_and_text_substring(
        self, db_session: AsyncSession, make: _Make, term: str, expected: list[str]
    ) -> None:
        await make.cve(cve_id="CVE-2099-30001", title="Heap overflow in Fictional-Lib")
        await make.cve(
            cve_id="CVE-2099-30002", description="Use after free in the FICTIONAL tool"
        )
        await make.cve(
            cve_id="CVE-2099-31000", title="Integer issue", description="unrelated"
        )

        assert await _ids(db_session, search=term) == [
            f"CVE-2099-{n}" for n in expected
        ]

    @pytest.mark.parametrize("term", ["", " ", "\t \n"])
    async def test_whitespace_only_search_equals_omission(
        self, db_session: AsyncSession, make: _Make, term: str
    ) -> None:
        for index in range(3):
            await make.cve(cve_id=f"CVE-2099-3200{index}", title="fictional")

        assert await _list(db_session, search=term, per_page=2) == await _list(
            db_session, search=None, per_page=2
        )
        assert (await _list(db_session, search=term)).total == 3

    @pytest.mark.parametrize(
        ("term", "expected"),
        [
            pytest.param("100%", ["CVE-2099-33001"], id="percent-in-term"),
            pytest.param("%", ["CVE-2099-33001"], id="percent-alone"),
            pytest.param("snake_case", ["CVE-2099-33004"], id="underscore-in-term"),
            pytest.param("_", ["CVE-2099-33004"], id="underscore-alone"),
            pytest.param("CVE_2099", [], id="underscore-in-id-prefix"),
            pytest.param("\\", ["CVE-2099-33006"], id="backslash-alone"),
            pytest.param("C:\\fictional", ["CVE-2099-33006"], id="backslash-in-term"),
        ],
    )
    async def test_pattern_characters_match_literally(
        self, db_session: AsyncSession, make: _Make, term: str, expected: list[str]
    ) -> None:
        for suffix, title, description in (
            ("33001", "100% fictional coverage", None),
            ("33002", "1000 fictional coverage", None),
            ("33003", "100 fictional coverage", None),
            ("33004", None, "a snake_case fictional name"),
            ("33005", None, "a snakeXcase fictional name"),
            ("33006", "C:\\fictional\\path", None),
            ("33007", "C:fictional/path", None),
        ):
            await make.cve(
                cve_id=f"CVE-2099-{suffix}", title=title, description=description
            )

        assert await _ids(db_session, search=term) == expected


# ---------------------------------------------------------------------------
# list_cves: ordering and pagination
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListSorting:
    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_cve_id_uses_code_point_order(
        self, db_session: AsyncSession, make: _Make, sort_order: SortOrder
    ) -> None:
        """Code-point order puts `100000` before `10002` and `9999` after
        both; numeric order would not."""
        for cve_id in ("CVE-2099-9999", "CVE-2100-0001", "CVE-2099-10002"):
            await make.cve(cve_id=cve_id)
        await make.cve(cve_id="CVE-2099-100000")
        ascending = [
            "CVE-2099-100000",
            "CVE-2099-10002",
            "CVE-2099-9999",
            "CVE-2100-0001",
        ]

        assert await _ids(
            db_session, sort_by=CVESortField.CVE_ID, sort_order=sort_order
        ) == (ascending if sort_order is SortOrder.ASC else ascending[::-1])

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_severity_uses_semantic_rank_with_null_last(
        self, db_session: AsyncSession, make: _Make, sort_order: SortOrder
    ) -> None:
        stored = ["Medium", None, "Critical", "None", "Low", "High"]
        for index, severity in enumerate(stored):
            await make.cve(cve_id=f"CVE-2099-{50001 + index}", severity=severity)
        by_severity = {
            severity: f"CVE-2099-{50001 + i}" for i, severity in enumerate(stored)
        }
        ranked = ["None", "Low", "Medium", "High", "Critical"]
        if sort_order is SortOrder.DESC:
            ranked.reverse()

        result = await _list(
            db_session, sort_by=CVESortField.SEVERITY, sort_order=sort_order
        )

        assert [item.cve_id for item in result.items] == [
            *(by_severity[label] for label in ranked),
            by_severity[None],
        ]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize(
        ("sort_by", "column", "nullable"),
        [
            (CVESortField.PUBLISHED_DATE, "published_date", True),
            (CVESortField.CREATED_AT, "created_at", False),
        ],
        ids=["published_date", "created_at"],
    )
    async def test_timestamps_with_null_last(
        self,
        db_session: AsyncSession,
        make: _Make,
        sort_by: CVESortField,
        column: str,
        nullable: bool,
        sort_order: SortOrder,
    ) -> None:
        """`created_at` is NOT NULL, so only `published_date` has a `NULL`
        group; it is last in both directions, ordered by `CVE.id`."""
        dated = {
            instant: await make.cve(**{column: instant}) for instant in (APR, FEB, MAY)
        }
        undated = [await make.cve() for _ in range(2)] if nullable else []
        descending = sort_order is SortOrder.DESC
        ordered = [dated[instant] for instant in (FEB, APR, MAY)]
        expected = [
            *(ordered[::-1] if descending else ordered),
            *sorted(undated, key=lambda c: c.id, reverse=descending),
        ]

        assert await _ids(db_session, sort_by=sort_by, sort_order=sort_order) == [
            cve.cve_id for cve in expected
        ]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize(
        ("sort_by", "tied", "null"),
        [
            (CVESortField.SEVERITY, {"severity": "High"}, {"severity": None}),
            (
                CVESortField.PUBLISHED_DATE,
                {"published_date": MAR},
                {"published_date": None},
            ),
            (CVESortField.CREATED_AT, {"created_at": MAR}, {"created_at": MAR}),
            (CVESortField.CVE_ID, {}, {}),
        ],
        ids=["severity", "published_date", "created_at", "cve_id"],
    )
    async def test_pages_are_stable_and_disjoint_by_internal_id(
        self,
        db_session: AsyncSession,
        make: _Make,
        sort_by: CVESortField,
        tied: dict[str, Any],
        null: dict[str, Any],
        sort_order: SortOrder,
    ) -> None:
        """Equal (and equal `NULL`) primary keys are tie-broken by `CVE.id`
        in the requested direction; paging two rows at a time over four
        pages neither repeats nor skips. CVE-IDs are assigned against the
        id order so a CVE-ID tie-breaker would fail."""
        descending = sort_order is SortOrder.DESC
        tied_cves = [
            await make.cve(cve_id=f"CVE-2099-{60009 - n}", **tied) for n in range(5)
        ]
        null_cves = [
            await make.cve(cve_id=f"CVE-2099-{60002 - n}", **null) for n in range(2)
        ]
        if sort_by is CVESortField.CVE_ID:
            full = sorted(
                tied_cves + null_cves, key=lambda c: c.cve_id, reverse=descending
            )
        elif sort_by is CVESortField.CREATED_AT:
            full = sorted(tied_cves + null_cves, key=lambda c: c.id, reverse=descending)
        else:
            full = [
                *sorted(tied_cves, key=lambda c: c.id, reverse=descending),
                *sorted(null_cves, key=lambda c: c.id, reverse=descending),
            ]

        pages = [
            await _list(
                db_session, sort_by=sort_by, sort_order=sort_order, page=n, per_page=2
            )
            for n in range(1, 5)
        ]

        paged = [item.cve_id for page in pages for item in page.items]
        assert [len(page.items) for page in pages] == [2, 2, 2, 1]
        assert paged == [cve.cve_id for cve in full]
        assert len(set(paged)) == 7
        assert {page.total for page in pages} == {7}


@pytest.mark.integration
class TestListPagination:
    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        for _ in range(3):
            await make.cve()

        assert await _list(db_session, page=4, per_page=1) == CVEListResult(
            items=(), total=3, page=4, per_page=1
        )
        assert await _list(db_session, page=2, per_page=3) == CVEListResult(
            items=(), total=3, page=2, per_page=3
        )
        assert await _list(db_session, search="none-such") == CVEListResult(
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
# list_cves: row identity, bounded read, projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListRowIdentityAndBoundedRead:
    async def test_child_and_ticket_fan_out_yields_one_row(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        user: User = await make.user()
        rich: CVE = await make.cve(cve_id="CVE-2099-70001")
        plain: CVE = await make.cve(cve_id="CVE-2099-70002")
        for _ in range(3):
            await make.cwe(cve_id=rich.id)
            await make.source(cve_id=rich.id)
        for _ in range(2):
            await make.external_id(cve_id=rich.id)
            await make.cvss(cve_id=rich.id)
        await make.kev(cve_id=rich.id)
        await make.epss(cve_id=rich.id)
        await make.ssvc(cve_id=rich.id)
        ticket = await make.ticket(cve_id=rich.id, is_confidential=True)
        await make.grant(ticket_id=ticket.id, user_id=user.id)
        await make.grant(ticket_id=ticket.id)
        for _ in range(3):
            package = await make.package(ticket_id=ticket.id)
            await make.maintainer(ticket_package_id=package.id, user_id=user.id)
            await make.maintainer(ticket_package_id=package.id)

        for caller in (ALL_SCOPE, _restricted(user)):
            assert await _ids(db_session, caller) == [rich.cve_id, plain.cve_id]
            assert (await _list(db_session, caller, per_page=1)).total == 2
            assert (await _list(db_session, caller, has_ticket=True)).total == 1

    async def test_one_read_only_statement_regardless_of_page_size(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        user: User = await make.user()
        for index in range(12):
            cve = await make.cve(severity="High")
            await make.cwe(cve_id=cve.id)
            if index % 2:
                await make.ticket(cve_id=cve.id, is_confidential=index % 4 == 1)
        before = await _persisted_state(db_session)

        counts = []
        for per_page in (1, 5, 12):
            with _StatementRecorder(db_session) as recorder:
                result = await _list(
                    db_session,
                    _restricted(user),
                    per_page=per_page,
                    sort_by=CVESortField.SEVERITY,
                )
            assert result.total == 9
            assert len(result.items) == min(per_page, 9)
            counts.append(len(recorder.statements))
            _assert_read_only_statement(recorder.statements[0], "WITH")

        assert counts == [1, 1, 1]
        _assert_untouched_session(db_session)
        assert await _persisted_state(db_session) == before

    async def test_item_projection(self, db_session: AsyncSession, make: _Make) -> None:
        associated: CVE = await make.cve(
            cve_id="CVE-2099-80001",
            title="Fictional title",
            description="Fictional description",
            severity=Severity.NONE.value,
            cve_state=CveState.REJECTED.value,
            published_date=MAR,
        )
        ticket = await make.ticket(cve_id=associated.id)
        ticketless: CVE = await make.cve(cve_id="CVE-2099-80002")
        stamps = {
            row.id: (row.created_at, row.updated_at)
            for row in await db_session.execute(
                select(CVE.id, CVE.created_at, CVE.updated_at)
            )
        }

        first, second = (await _list(db_session, ANONYMOUS_CALLER)).items

        assert first == CVEListItemProjection(
            cve_id="CVE-2099-80001",
            title="Fictional title",
            description="Fictional description",
            severity=Severity.NONE,
            cve_state=CveState.REJECTED,
            published_date=MAR,
            ticket_id=_sntl(ticket),
            created_at=stamps[associated.id][0],
            updated_at=stamps[associated.id][1],
        )
        assert first.ticket_id == f"SNTL-{ticket.sequence_id}"
        assert type(first.severity) is Severity
        assert type(first.cve_state) is CveState
        assert second == CVEListItemProjection(
            cve_id="CVE-2099-80002",
            title=None,
            description=None,
            severity=None,
            cve_state=CveState.PUBLISHED,
            published_date=None,
            ticket_id=None,
            created_at=stamps[ticketless.id][0],
            updated_at=stamps[ticketless.id][1],
        )
        for item in (first, second):
            _assert_no_uuid(item)


# ---------------------------------------------------------------------------
# get_cve_detail: identifier resolution and accessibility
# ---------------------------------------------------------------------------

MALFORMED_CVE_IDS: Final = [
    "cve-2099-10001",
    " CVE-2099-10001",
    "CVE-2099-10001 ",
    "CVE-2099-" + "1" * 12,
    "018f0e2a-7b1c-7cde-8f00-000000000001",
    "<internal-uuid>",
    "<random-uuid>",
]


@pytest.mark.integration
class TestDetailAccess:
    @pytest.mark.parametrize("cve_id", MALFORMED_CVE_IDS)
    async def test_malformed_identifier_raises_without_any_statement(
        self, db_session: AsyncSession, make: _Make, cve_id: str
    ) -> None:
        cve: CVE = await make.cve(cve_id="CVE-2099-10001")
        cve_id = {
            "<internal-uuid>": str(cve.id),
            "<random-uuid>": str(uuid.uuid4()),
        }.get(cve_id, cve_id)

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await get_cve_detail(db_session, ALL_SCOPE, cve_id)

        assert recorder.statements == []

    async def test_canonical_predicate_decides_and_denial_equals_missing(
        self, db_session: AsyncSession, visibility_world: _VisibilityWorld
    ) -> None:
        cves = visibility_world.cves
        with pytest.raises(CVENotFoundError):
            await get_cve_detail(db_session, ALL_SCOPE, "CVE-2099-400010")
        with pytest.raises(CVENotFoundError) as missing:
            await get_cve_detail(db_session, ANONYMOUS_CALLER, "CVE-2099-99999")

        for caller, visible in visibility_world.expectations.items():
            for name, cve in cves.items():
                if name in visible:
                    result = await get_cve_detail(db_session, caller, cve.cve_id)
                    assert result.cve.cve_id == cve.cve_id
                    continue
                with pytest.raises(CVENotFoundError) as denied:
                    await get_cve_detail(db_session, caller, cve.cve_id)
                assert type(denied.value) is type(missing.value)
                assert str(denied.value) == str(missing.value)


# ---------------------------------------------------------------------------
# get_cve_detail: projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDetailProjection:
    async def test_full_projection_with_ordered_evidence(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        """Rows are inserted in neither order. Code-point order puts
        `CWE-1021` < `CWE-20` < `CWE-79`, `NVD` < `Red Hat` < `nvd`, and
        `GHSA-Zzzz` < `GHSA-aaaa`; a numeric or linguistic order would not.
        `NVD` and `nvd` are distinct exact values and both kept."""
        cve: CVE = await make.cve(
            cve_id="CVE-2099-90001",
            title="Fictional title",
            description="Fictional description",
            published_date=MAR,
            modified_date=APR,
            cve_state=CveState.REJECTED.value,
            date_rejected=MAY,
            severity=Severity.NONE.value,
        )
        ticket = await make.ticket(cve_id=cve.id, is_confidential=True)
        for cwe_id, source in (
            ("CWE-79", "nvd"),
            ("CWE-20", "NVD"),
            ("CWE-79", "Red Hat"),
            ("CWE-1021", "MITRE"),
            ("CWE-79", "NVD"),
            ("CWE-20", "MITRE"),
        ):
            await make.cwe(cve_id=cve.id, cwe_id=cwe_id, source=source)
        for source, identifier, url in (
            ("RUSTSEC", "RUSTSEC-2099-0001", None),
            ("GHSA", "GHSA-aaaa-fict-ional", "https://example.com/a"),
            ("PYSEC", "PYSEC-2099-1", None),
            ("GHSA", "GHSA-Zzzz-fict-ional", None),
        ):
            await make.external_id(
                cve_id=cve.id, source=source, identifier=identifier, url=url
            )
        await make.kev(
            cve_id=cve.id,
            date_added=date(2099, 1, 15),
            reference_url="https://example.com/kev",
        )
        await make.epss(
            cve_id=cve.id, score=0.25, percentile=0.75, assessed_at=date(2099, 1, 16)
        )
        await make.ssvc(
            cve_id=cve.id,
            exploitation="active",
            automatable="yes",
            technical_impact="total",
            version="2.0.3",
            assessed_at=FEB,
        )
        await make.cvss(cve_id=cve.id)
        before = await _persisted_state(db_session)

        with _StatementRecorder(db_session) as recorder:
            result = await get_cve_detail(db_session, ALL_SCOPE, cve.cve_id)

        assert result == CVEDetailResult(
            cve=CVEDetailProjection(
                cve_id="CVE-2099-90001",
                title="Fictional title",
                description="Fictional description",
                published_date=MAR,
                modified_date=APR,
                cve_state=CveState.REJECTED,
                date_rejected=MAY,
                severity=Severity.NONE,
                external_identifiers=(
                    CVEExternalIdentifierProjection(
                        "GHSA", "GHSA-Zzzz-fict-ional", None
                    ),
                    CVEExternalIdentifierProjection(
                        "GHSA", "GHSA-aaaa-fict-ional", "https://example.com/a"
                    ),
                    CVEExternalIdentifierProjection("PYSEC", "PYSEC-2099-1", None),
                    CVEExternalIdentifierProjection(
                        "RUSTSEC", "RUSTSEC-2099-0001", None
                    ),
                ),
                kev=CVEKEVProjection(date(2099, 1, 15), "https://example.com/kev"),
                epss=CVEEPSSProjection(0.25, 0.75, date(2099, 1, 16)),
                ssvc=CVESSVCProjection("active", "yes", "total", "2.0.3", FEB),
                cwes=(
                    CVEWeaknessProjection("CWE-1021", ("MITRE",)),
                    CVEWeaknessProjection("CWE-20", ("MITRE", "NVD")),
                    CVEWeaknessProjection("CWE-79", ("NVD", "Red Hat", "nvd")),
                ),
            ),
            ticket_id=_sntl(ticket),
        )
        assert result.cve.severity is Severity.NONE
        assert type(result.cve.cve_state) is CveState
        assert len(recorder.statements) == 1
        _assert_read_only_statement(recorder.statements[0], "SELECT")
        _assert_no_uuid(result)
        _assert_no_uuid(result.cve)
        _assert_untouched_session(db_session)
        assert await _persisted_state(db_session) == before

    async def test_absent_evidence_and_ticketless_cve(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        cve: CVE = await make.cve(cve_id="CVE-2099-90002")

        result = await get_cve_detail(db_session, ANONYMOUS_CALLER, cve.cve_id)

        assert result == CVEDetailResult(
            cve=CVEDetailProjection(
                cve_id="CVE-2099-90002",
                title=None,
                description=None,
                published_date=None,
                modified_date=None,
                cve_state=CveState.PUBLISHED,
                date_rejected=None,
                severity=None,
                external_identifiers=(),
                kev=None,
                epss=None,
                ssvc=None,
                cwes=(),
            ),
            ticket_id=None,
        )

    async def test_cve_projection_equals_the_ticket_detail_cve(
        self, db_session: AsyncSession, make: _Make
    ) -> None:
        cve: CVE = await make.cve(
            title="Fictional", severity=Severity.HIGH.value, published_date=MAR
        )
        ticket = await make.ticket(cve_id=cve.id)
        for cwe_id, source in (("CWE-79", "NVD"), ("CWE-20", "MITRE")):
            await make.cwe(cve_id=cve.id, cwe_id=cwe_id, source=source)
        await make.external_id(cve_id=cve.id)
        await make.kev(cve_id=cve.id)
        await make.epss(cve_id=cve.id)
        await make.ssvc(cve_id=cve.id)

        resource = await get_cve_detail(db_session, ALL_SCOPE, cve.cve_id)
        ticket_detail = await get_ticket_detail(
            db_session, ticket_id=_sntl(ticket), caller=ALL_SCOPE
        )

        assert ticket_detail.cve is not None
        assert resource.cve == ticket_detail.cve
        assert resource.ticket_id == ticket_detail.ticket_id


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (testing-strategy.md, Concurrency Testing:
    committed data is not rolled back by the fixture). CVE children (KEV)
    are removed by the `ON DELETE CASCADE` of their CVE."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.token = f"fictional-cve-read-{uuid.uuid4().hex[:12]}"
        self.user_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []

    async def user(self, role: Role | None = None) -> User:
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"fictional.cveread.{suffix}",
            email=f"cveread.{suffix}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    def new_cve(self, **fields: Any) -> Executable:
        """An insert of a token-titled CVE, registered for cleanup."""
        cve_pk = uuid.uuid7()
        self.cve_ids.append(cve_pk)
        values = {"title": self.token, **fields}
        return insert(CVE).values(id=cve_pk, cve_id=_random_cve_id(), **values)

    async def cve(self, **fields: Any) -> CVE:
        cve = CVE(cve_id=_random_cve_id(), title=self.token, **fields)
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        await self.session.commit()
        return cve

    async def ticket(
        self,
        cve: CVE | None,
        *,
        is_confidential: bool,
        maintainer: User | None = None,
        packages: int = 1,
    ) -> tuple[Ticket, list[TicketPackage]]:
        ticket = Ticket(is_confidential=is_confidential, cve_id=cve.id if cve else None)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        created = []
        for index in range(packages):
            package = TicketPackage(
                ticket_id=ticket.id, package_name=f"fictional-cve-read-{index}"
            )
            self.session.add(package)
            await self.session.flush()
            if maintainer is not None:
                self.session.add(
                    TicketPackageMaintainer(
                        ticket_package_id=package.id, user_id=maintainer.id
                    )
                )
            created.append(package)
        await self.session.commit()
        return ticket, created

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        for statement in (
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


def _random_cve_id() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10**9:09d}"


@pytest.fixture
async def committed_world(
    db_session_factory: SessionFactory,
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


@dataclasses.dataclass(frozen=True)
class _Race:
    """The committed world, a reader session R, a writer session W, and the
    factory for a fresh session observing the committed state."""

    world: _CommittedWorld
    reader: AsyncSession
    writer: AsyncSession
    sessions: SessionFactory

    async def ids(
        self, caller: TicketCaller, *, fresh: bool = False
    ) -> tuple[set[str], int]:
        """The token-scoped list of R (or of a fresh session): CVE-IDs and
        total."""
        db = await self.sessions() if fresh else self.reader
        result = await _list(db, caller, search=self.world.token)
        return {item.cve_id for item in result.items}, result.total

    async def detail(
        self, caller: TicketCaller, cve: CVE, *, fresh: bool = False
    ) -> CVEDetailResult:
        db = await self.sessions() if fresh else self.reader
        return await get_cve_detail(db, caller, cve.cve_id)


@pytest.fixture
async def race(
    committed_world: _CommittedWorld, db_session_factory: SessionFactory
) -> _Race:
    return _Race(
        committed_world,
        await db_session_factory(),
        await db_session_factory(),
        db_session_factory,
    )


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


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


@dataclasses.dataclass(frozen=True)
class _Loss:
    """A CVE accessible to `caller` and the committed change that removes
    that access."""

    cve: CVE
    caller: TicketCaller
    change: tuple[Executable, ...]


LOSS_CASES: Final = ["confidentiality", "grant", "last_package", "association"]


async def _prepare_loss(world: _CommittedWorld, case: str) -> _Loss:
    cve = await world.cve()
    if case == "confidentiality":
        user = await world.user()
        ticket, _ = await world.ticket(cve, is_confidential=False)
        change: Executable = (
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True)
        )
        return _Loss(cve, _restricted(user), (change,))
    if case == "grant":
        user, granter = await world.user(), await world.user()
        ticket, _ = await world.ticket(cve, is_confidential=True)
        await world.grant(ticket, user, granter)
        change = delete(TicketAccessGrant).where(
            TicketAccessGrant.ticket_id == ticket.id
        )
        return _Loss(cve, _restricted(user), (change,))
    if case == "last_package":
        user = await world.user()
        _, (first, last) = await world.ticket(
            cve, is_confidential=True, maintainer=user, packages=2
        )
        await _commit(
            world.session,
            update(TicketPackage)
            .where(TicketPackage.id == first.id)
            .values(deleted_at=EXCLUDED_AT),
        )
        change = (
            update(TicketPackage)
            .where(TicketPackage.id == last.id)
            .values(deleted_at=EXCLUDED_AT)
        )
        return _Loss(cve, _restricted(user), (change,))
    assert case == "association"
    ticket, _ = await world.ticket(None, is_confidential=True)
    change = update(Ticket).where(Ticket.id == ticket.id).values(cve_id=cve.id)
    return _Loss(cve, ANONYMOUS_CALLER, (change,))


def _add_kev(cve: CVE) -> Executable:
    return insert(CVEKEVEntry).values(cve_id=cve.id, date_added=date(2099, 1, 15))


async def _prepare_gain(world: _CommittedWorld) -> tuple[CVE, Ticket, User, Executable]:
    """A confidential associated CVE, its Ticket, a caller user without
    access, and the grant insert that gives that user access."""
    user, granter = await world.user(), await world.user()
    cve = await world.cve()
    ticket, _ = await world.ticket(cve, is_confidential=True)
    grant = insert(TicketAccessGrant).values(
        ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
    )
    return cve, ticket, user, grant


@pytest.mark.integration
class TestListRaces:
    """Session R lists, session W commits, and R lists again on the same
    connection: rows and total both reflect the committed change. When W
    commits right after R's first statement, the one-statement list
    returns the coherent pre-change rows and total, and a fresh session
    observes the change."""

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_between_lists(self, race: _Race, case: str) -> None:
        loss = await _prepare_loss(race.world, case)
        control = await race.world.cve()

        assert await race.ids(loss.caller) == ({loss.cve.cve_id, control.cve_id}, 2)
        await _commit(race.writer, *loss.change)

        assert await race.ids(loss.caller) == ({control.cve_id}, 1)

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_after_the_first_statement(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch, case: str
    ) -> None:
        loss = await _prepare_loss(race.world, case)
        control = await race.world.cve()
        added = (race.world.new_cve(), race.world.new_cve())

        async def change() -> None:
            await _commit(race.writer, *loss.change, *added)

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        result = await race.ids(loss.caller)

        assert calls == [1]
        assert result == ({loss.cve.cve_id, control.cve_id}, 2)
        fresh_ids, fresh_total = await race.ids(loss.caller, fresh=True)
        assert fresh_total == 3 == len(fresh_ids)
        assert loss.cve.cve_id not in fresh_ids
        assert control.cve_id in fresh_ids

    async def test_access_acquired_with_a_severity_change_is_observed_whole(
        self, race: _Race
    ) -> None:
        cve, ticket, user, grant = await _prepare_gain(race.world)

        assert await race.ids(_restricted(user)) == (set(), 0)
        await _commit(
            race.writer,
            grant,
            update(CVE).where(CVE.id == cve.id).values(severity="Critical"),
        )

        after = await _list(race.reader, _restricted(user), search=race.world.token)
        assert after.total == 1
        (item,) = after.items
        assert (item.cve_id, item.severity, item.ticket_id) == (
            cve.cve_id,
            Severity.CRITICAL,
            _sntl(ticket),
        )

    async def test_access_acquired_after_the_first_statement(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve, _, user, grant = await _prepare_gain(race.world)
        control = await race.world.cve()
        added = race.world.new_cve()

        async def change() -> None:
            await _commit(race.writer, grant, added)

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        result = await race.ids(_restricted(user))

        assert calls == [1]
        assert result == ({control.cve_id}, 1)
        fresh_ids, fresh_total = await race.ids(_restricted(user), fresh=True)
        assert fresh_total == 3 == len(fresh_ids)
        assert {cve.cve_id, control.cve_id} < fresh_ids


@pytest.mark.integration
class TestDetailRaces:
    """The same independent-session protocol for the CVE detail: a lost
    access raises `CVENotFoundError`, an acquired access is observed
    together with the evidence committed with it, and a change committed
    after the first statement never produces a mixed result."""

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_between_reads(self, race: _Race, case: str) -> None:
        loss = await _prepare_loss(race.world, case)

        assert (await race.detail(loss.caller, loss.cve)).cve.cve_id == loss.cve.cve_id
        await _commit(race.writer, *loss.change)

        with pytest.raises(CVENotFoundError):
            await race.detail(loss.caller, loss.cve)

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_after_the_first_statement(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch, case: str
    ) -> None:
        loss = await _prepare_loss(race.world, case)

        async def change() -> None:
            await _commit(race.writer, *loss.change, _add_kev(loss.cve))

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        result = await race.detail(loss.caller, loss.cve)

        assert calls == [1]
        assert result.cve.cve_id == loss.cve.cve_id
        assert result.cve.kev is None
        assert (result.ticket_id is None) is (case == "association")
        with pytest.raises(CVENotFoundError):
            await race.detail(loss.caller, loss.cve, fresh=True)

    async def test_access_acquired_with_a_kev_entry_is_observed_whole(
        self, race: _Race
    ) -> None:
        cve, ticket, user, grant = await _prepare_gain(race.world)

        with pytest.raises(CVENotFoundError):
            await race.detail(_restricted(user), cve)
        await _commit(race.writer, grant, _add_kev(cve))

        after = await race.detail(_restricted(user), cve)
        assert after.cve.kev == CVEKEVProjection(date(2099, 1, 15), None)
        assert after.ticket_id == _sntl(ticket)

    async def test_access_acquired_after_the_first_statement(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve, _, user, grant = await _prepare_gain(race.world)

        async def change() -> None:
            await _commit(race.writer, grant, _add_kev(cve))

        calls = _commit_after_first_statement(monkeypatch, race.reader, change)
        with pytest.raises(CVENotFoundError):
            await race.detail(_restricted(user), cve)

        assert calls == [1]
        after = await race.detail(_restricted(user), cve, fresh=True)
        assert after.cve.kev == CVEKEVProjection(date(2099, 1, 15), None)


@pytest.mark.integration
class TestResolvedCaller:
    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self, race: _Race
    ) -> None:
        """Both reads consume the request-resolved scope: a role removal
        committed during the request does not narrow the in-flight caller;
        the next request's newly resolved caller is narrowed."""
        user = await race.world.user(Role.VULNERABILITY_ANALYST)
        cve = await race.world.cve()
        ticket, _ = await race.world.ticket(cve, is_confidential=True)
        in_flight = TicketCaller.authenticated(user.id, Scope.ALL)

        await _commit(race.writer, delete(UserRole).where(UserRole.user_id == user.id))

        assert await race.ids(in_flight) == ({cve.cve_id}, 1)
        assert (await race.detail(in_flight, cve)).ticket_id == _sntl(ticket)
        next_request = _restricted(user)
        assert await race.ids(next_request) == (set(), 0)
        with pytest.raises(CVENotFoundError):
            await race.detail(next_request, cve)
