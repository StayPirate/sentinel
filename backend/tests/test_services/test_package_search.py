"""Tests for the cross-Ticket package search (`package_service.search_packages()`).

Owning specifications:

- docs/features/packages/package-service.md (Query Operations >
  `search_packages()`; Consumer caller context and Ticket accessibility;
  Architectural Test Requirement bullets "Atomic consumer accessibility"
  and "Derived actionability").
- docs/features/packages/package-model.md (Manual Exclusion Markers;
  Derived Actionability; API Endpoints > Search Packages Across Tickets,
  including Query Parameters and Response Schema `PackageListItem`).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility): the canonical visibility predicate.
- docs/features/tickets/tickets.md (Severity Resolution).
- docs/features/platform/testing-strategy.md (Ticket Accessibility >
  Canonical predicate, List and count reads, controlled-clock and package
  query bullets of Ticket identifier and read-contract coverage).

The independent-session races of the same query shape live in
`tests/test_services/test_package_search_atomicity.py`.

Expected values are transcribed from the specifications (for example the
`PackageListItem` example and the Product lifecycle rows of
`tests/support/lifecycle_matrix.py`), never computed by the module under
test. Every test starts from an empty database (per-test transaction
rollback), so a search observes exactly the rows the test creates.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageSortField,
    PackageStatus,
    Scope,
    Severity,
    SortOrder,
    TicketStatus,
)
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    MAX_PER_PAGE,
    PackageSearchItem,
    PackageSearchPage,
    TicketPackageRefProjection,
    TrackSummaryProjection,
    search_packages,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.lifecycle_matrix import FAR_PAST, GS_END, ONE_DAY

Factory = Callable[..., Awaitable[Any]]

EVAL = date(2026, 9, 27)
"""The evaluation date of every search unless a test states otherwise."""

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
EXCLUDED_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
BASE = datetime(2026, 5, 15, 10, 30, tzinfo=UTC)

EOL_GS_END = FAR_PAST
"""A General Support end alone, long before `EVAL`: the Product is `eol`
on `EVAL` (lifecycle_matrix.py, `gs_only_day_after_gs_end_eol`)."""

ALL_STATUSES = pytest.mark.parametrize("status", list(TicketStatus), ids=str)


@dataclass(frozen=True, slots=True)
class Occ:
    """One Product occurrence of a factory-built track.

    `gs_end` is the catalog Product's only lifecycle date: `None` leaves
    the lifecycle unavailable (`NULL` phase, actionable), `EOL_GS_END`
    makes it `eol` on `EVAL`. `excluded` seeds the occurrence's direct
    marker."""

    gs_end: date | None = None
    excluded: bool = False


SUPPORTED = Occ()
EOL = Occ(gs_end=EOL_GS_END)
EXCLUDED = Occ(excluded=True)


@dataclass(frozen=True, slots=True)
class Tree:
    """Builds package trees through the raw model factories."""

    package_factory: Factory
    track_factory: Factory
    occurrence_factory: Factory
    product_factory: Factory

    async def package(
        self,
        ticket: Ticket,
        name: str,
        statuses: Sequence[PackageStatus] = (PackageStatus.ANALYSIS,),
        **columns: Any,
    ) -> TicketPackage:
        """A package with one actionable track per status (each with one
        supported Product occurrence); `columns` override package columns
        such as `deleted_at`, `created_at`, and `updated_at`."""
        package: TicketPackage = await self.package_factory(
            ticket_id=ticket.id, package_name=name, **columns
        )
        for status in statuses:
            await self.track(package, status)
        return package

    async def track(
        self,
        package: TicketPackage,
        status: PackageStatus = PackageStatus.ANALYSIS,
        *occurrences: Occ,
        excluded: bool = False,
    ) -> TicketPackageTrack:
        """A track with the given occurrences (one `SUPPORTED` occurrence
        when none is given)."""
        track: TicketPackageTrack = await self.track_factory(
            ticket_package_id=package.id,
            status=status.value,
            deleted_at=EXCLUDED_AT if excluded else None,
        )
        for occurrence in occurrences or (SUPPORTED,):
            product = await self.product_factory(
                general_support_end_date=occurrence.gs_end
            )
            await self.occurrence_factory(
                ticket_package_track_id=track.id,
                product_id=product.id,
                deleted_at=EXCLUDED_AT if occurrence.excluded else None,
            )
        return track


@pytest.fixture
def tree(
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
    product_factory: Factory,
) -> Tree:
    return Tree(
        ticket_package_factory,
        ticket_package_track_factory,
        ticket_package_product_factory,
        product_factory,
    )


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


async def _search(
    db: AsyncSession,
    caller: TicketCaller = ALL_SCOPE,
    *,
    evaluation_date: date = EVAL,
    **filters: Any,
) -> PackageSearchPage:
    return await search_packages(
        db, caller=caller, evaluation_date=evaluation_date, **filters
    )


async def _names(
    db: AsyncSession, caller: TicketCaller = ALL_SCOPE, **filters: Any
) -> list[str]:
    """The package names of one complete page; the total must agree."""
    page = await _search(db, caller, per_page=MAX_PER_PAGE, **filters)
    assert page.total == len(page.items)
    return [item.package_name for item in page.items]


def _summary(**counts: int) -> TrackSummaryProjection:
    """A `TrackSummary` with the given status counts (others 0) and their
    sum as `total`."""
    fields = ("affected", "fixed", "not_affected", "wont_fix", "analysis")
    values = {field: counts.get(field, 0) for field in fields}
    return TrackSummaryProjection(total=sum(values.values()), **values)


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProjection:
    async def test_item_projects_every_field(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """The `PackageListItem` example of package-model.md: the
        `TicketPackage` UUID and timestamps, the canonical `SNTL-{n}`
        reference with status and resolved severity, and the actionable
        track counts by status."""
        ticket: Ticket = await ticket_factory(
            sequence_id=123,
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            created_at=datetime(2026, 1, 2, 3, 4, tzinfo=UTC),
            updated_at=datetime(2026, 1, 3, 3, 4, tzinfo=UTC),
        )
        package = await tree.package(
            ticket,
            "openssl-3",
            (
                PackageStatus.AFFECTED,
                PackageStatus.AFFECTED,
                PackageStatus.FIXED,
                PackageStatus.NOT_AFFECTED,
                PackageStatus.ANALYSIS,
            ),
            created_at=datetime(2026, 5, 15, 10, 30, tzinfo=UTC),
            updated_at=datetime(2026, 5, 16, 8, 0, tzinfo=UTC),
        )

        page = await _search(db_session)

        assert page == PackageSearchPage(
            items=(
                PackageSearchItem(
                    id=package.id,
                    package_name="openssl-3",
                    ticket=TicketPackageRefProjection(
                        ticket_id="SNTL-123",
                        status=TicketStatus.ANALYSIS,
                        severity=Severity.HIGH,
                    ),
                    track_summary=TrackSummaryProjection(
                        total=5,
                        affected=2,
                        fixed=1,
                        not_affected=1,
                        wont_fix=0,
                        analysis=1,
                    ),
                    created_at=datetime(2026, 5, 15, 10, 30, tzinfo=UTC),
                    updated_at=datetime(2026, 5, 16, 8, 0, tzinfo=UTC),
                ),
            ),
            total=1,
            page=1,
            per_page=20,
        )

    async def test_one_item_per_package_and_ticket_pair(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """The same package name in two Tickets appears once per Ticket;
        two packages of one Ticket are two items."""
        first: Ticket = await ticket_factory(sequence_id=701)
        second: Ticket = await ticket_factory(sequence_id=702)
        in_first = await tree.package(first, "example-lib")
        in_second = await tree.package(second, "example-lib")
        other = await tree.package(first, "example-other")

        page = await _search(db_session)

        assert page.total == 3
        assert {
            (item.id, item.package_name, item.ticket.ticket_id) for item in page.items
        } == {
            (in_first.id, "example-lib", "SNTL-701"),
            (in_second.id, "example-lib", "SNTL-702"),
            (other.id, "example-other", "SNTL-701"),
        }

    @pytest.mark.parametrize(
        ("has_cve", "cve_severity", "manual", "expected"),
        [
            pytest.param(
                True, Severity.CRITICAL, None, Severity.CRITICAL, id="cve-critical"
            ),
            pytest.param(True, Severity.NONE, None, Severity.NONE, id="cve-none-label"),
            pytest.param(True, None, None, None, id="cve-null-severity"),
            pytest.param(
                False, None, Severity.MEDIUM, Severity.MEDIUM, id="manual-medium"
            ),
            pytest.param(
                False, None, Severity.NONE, Severity.NONE, id="manual-none-label"
            ),
            pytest.param(False, None, None, None, id="neither"),
        ],
    )
    async def test_ticket_severity_is_the_resolved_severity(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        cve_factory: Factory,
        has_cve: bool,
        cve_severity: Severity | None,
        manual: Severity | None,
        expected: Severity | None,
    ) -> None:
        """tickets.md, Severity Resolution: a CVE-associated Ticket uses
        `CVE.severity` (possibly `NULL`), a CVE-less Ticket uses
        `severity_manual`, neither is `NULL`; the `None` label is distinct
        from `NULL`."""
        columns: dict[str, Any] = {}
        if has_cve:
            cve = await cve_factory(
                severity=cve_severity.value if cve_severity else None
            )
            columns["cve_id"] = cve.id
        if manual is not None:
            columns["severity_manual"] = manual.value
        ticket = await ticket_factory(**columns)
        await tree.package(ticket, "example-severity")

        (item,) = (await _search(db_session)).items

        assert item.ticket.severity is expected


@pytest.mark.unit
class TestProjectionShape:
    def test_ticket_reference_exposes_only_the_canonical_identity(self) -> None:
        assert set(TicketPackageRefProjection.__dataclass_fields__) == {
            "ticket_id",
            "status",
            "severity",
        }

    def test_item_exposes_no_tree_or_maintainer_field(self) -> None:
        assert set(PackageSearchItem.__dataclass_fields__) == {
            "id",
            "package_name",
            "ticket",
            "track_summary",
            "created_at",
            "updated_at",
        }
        assert set(TrackSummaryProjection.__dataclass_fields__) == {
            "total",
            "affected",
            "fixed",
            "not_affected",
            "wont_fix",
            "analysis",
        }


# ---------------------------------------------------------------------------
# Visibility (rbac.md canonical predicate; testing-strategy.md, Ticket
# Accessibility > Canonical predicate and List and count reads)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestVisibility:
    async def test_mixed_visibility_items_and_total(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        caller_user: User = await user_factory(
            username="fictional.maintainer", email="fictional.maintainer@example.com"
        )
        public = await ticket_factory()
        await tree.package(public, "example-public")
        granted = await ticket_factory(is_confidential=True)
        await tree.package(granted, "example-granted")
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=caller_user.id)
        maintained = await ticket_factory(is_confidential=True)
        own = await tree.package(maintained, "example-maintained")
        await ticket_package_maintainer_factory(
            ticket_package_id=own.id, user_id=caller_user.id
        )
        await tree.package(maintained, "example-maintained-sibling")
        excluded_maintained = await ticket_factory(is_confidential=True)
        excluded = await tree.package(
            excluded_maintained, "example-excluded-own", deleted_at=EXCLUDED_AT
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=caller_user.id
        )
        await tree.package(excluded_maintained, "example-excluded-sibling")
        hidden = await ticket_factory(is_confidential=True)
        await tree.package(hidden, "example-hidden")
        restricted = TicketCaller.authenticated(caller_user.id, Scope.NON_CONFIDENTIAL)
        no_path = TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL)

        expectations = {
            ANONYMOUS_CALLER: {"example-public"},
            no_path: {"example-public"},
            restricted: {
                "example-public",
                "example-granted",
                "example-maintained",
                "example-maintained-sibling",
            },
            ALL_SCOPE: {
                "example-public",
                "example-granted",
                "example-maintained",
                "example-maintained-sibling",
                "example-excluded-sibling",
                "example-hidden",
            },
        }
        for caller, visible in expectations.items():
            page = await _search(db_session, caller, per_page=1)
            assert page.total == len(visible), caller
            assert set(await _names(db_session, caller)) == visible, caller

    @pytest.mark.parametrize(
        "non_actionable", ["track-excluded", "product-excluded", "eol", "no-tracks"]
    )
    async def test_included_maintained_package_keeps_visibility_when_non_actionable(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        non_actionable: str,
    ) -> None:
        """Track or Product exclusion and Product EOL do not affect the
        package-wide maintainer branch: the confidential Ticket stays
        visible through its included maintained package, whose own item
        is absent because it is not actionable, while its other
        actionable package is returned."""
        caller_user: User = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        own = await tree.package(ticket, "example-own", ())
        if non_actionable == "track-excluded":
            await tree.track(own, PackageStatus.AFFECTED, excluded=True)
        elif non_actionable == "product-excluded":
            await tree.track(own, PackageStatus.AFFECTED, EXCLUDED)
        elif non_actionable == "eol":
            await tree.track(own, PackageStatus.AFFECTED, EOL, EOL)
        await ticket_package_maintainer_factory(
            ticket_package_id=own.id, user_id=caller_user.id
        )
        await tree.package(ticket, "example-sibling")
        caller = TicketCaller.authenticated(caller_user.id, Scope.NON_CONFIDENTIAL)

        assert await _names(db_session, caller) == ["example-sibling"]

    async def test_directly_excluded_maintained_package_grants_no_visibility(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        caller_user: User = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        own = await tree.package(ticket, "example-own", deleted_at=EXCLUDED_AT)
        await ticket_package_maintainer_factory(
            ticket_package_id=own.id, user_id=caller_user.id
        )
        await tree.package(ticket, "example-sibling")
        caller = TicketCaller.authenticated(caller_user.id, Scope.NON_CONFIDENTIAL)

        assert await _search(db_session, caller) == PackageSearchPage(
            items=(), total=0, page=1, per_page=20
        )
        assert await _names(db_session, ALL_SCOPE) == ["example-sibling"]

    async def test_multiple_qualifying_packages(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """Excluding one maintained package preserves visibility while
        another included maintained package remains; it is lost only when
        every maintained package is excluded."""
        caller_user: User = await user_factory()
        kept = await ticket_factory(is_confidential=True)
        lost = await ticket_factory(is_confidential=True)
        for ticket, prefix, excluded_flags in (
            (kept, "example-kept", (True, False)),
            (lost, "example-lost", (True, True)),
        ):
            for index, is_excluded in enumerate(excluded_flags):
                package = await tree.package(
                    ticket,
                    f"{prefix}-own-{index}",
                    deleted_at=EXCLUDED_AT if is_excluded else None,
                )
                await ticket_package_maintainer_factory(
                    ticket_package_id=package.id, user_id=caller_user.id
                )
            await tree.package(ticket, f"{prefix}-sibling")
        caller = TicketCaller.authenticated(caller_user.id, Scope.NON_CONFIDENTIAL)

        assert set(await _names(db_session, caller)) == {
            "example-kept-own-1",
            "example-kept-sibling",
        }

    async def test_invisible_rows_never_move_visible_rows_between_pages(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """Visibility is part of the selection before sorting and
        pagination: hidden packages interleaved in the order neither count
        nor shift the anonymous caller's pages."""
        public = await ticket_factory()
        hidden = await ticket_factory(is_confidential=True)
        for minute, (ticket, name) in enumerate(
            (
                (public, "example-v1"),
                (hidden, "example-h1"),
                (public, "example-v2"),
                (hidden, "example-h2"),
                (public, "example-v3"),
            )
        ):
            await tree.package(
                ticket, name, created_at=BASE + timedelta(minutes=minute)
            )

        pages = [
            await _search(db_session, ANONYMOUS_CALLER, page=n, per_page=1)
            for n in range(1, 5)
        ]

        assert [[i.package_name for i in page.items] for page in pages] == [
            ["example-v3"],
            ["example-v2"],
            ["example-v1"],
            [],
        ]
        assert {page.total for page in pages} == {3}

    async def test_filters_apply_only_to_visible_candidates(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        hidden = await ticket_factory(
            is_confidential=True, status=TicketStatus.ANALYSIS.value
        )
        await tree.package(hidden, "example-secret")

        for filters in (
            {"search": "secret"},
            {"name": "example-secret"},
            {"ticket_status": [TicketStatus.ANALYSIS]},
            {"sort_by": PackageSortField.PACKAGE_NAME},
        ):
            page = await _search(db_session, ANONYMOUS_CALLER, **filters)
            assert (page.items, page.total) == ((), 0), filters

    async def test_anonymous_search_evaluates_no_grant_or_maintainer_branch(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await tree.package(await ticket_factory(), "example-public")

        with _StatementRecorder(db_session) as recorder:
            await _search(db_session, ANONYMOUS_CALLER)

        (statement,) = recorder.statements
        assert "ticket_access_grant" not in statement
        assert "ticket_package_maintainer" not in statement


# ---------------------------------------------------------------------------
# Actionable-only items and track summary (package-model.md, Derived
# Actionability; Search Packages Across Tickets)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActionableOnly:
    async def test_only_actionable_packages_are_returned(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()
        await tree.package(ticket, "example-direct-excluded", deleted_at=EXCLUDED_AT)
        tracks_excluded = await tree.package(ticket, "example-tracks-excluded", ())
        await tree.track(tracks_excluded, PackageStatus.AFFECTED, excluded=True)
        await tree.track(tracks_excluded, PackageStatus.FIXED, excluded=True)
        all_eol = await tree.package(ticket, "example-all-eol", ())
        await tree.track(all_eol, PackageStatus.AFFECTED, EOL, EOL)
        await tree.track(all_eol, PackageStatus.FIXED, EOL)
        products_excluded = await tree.package(ticket, "example-products-excluded", ())
        await tree.track(products_excluded, PackageStatus.AFFECTED, EXCLUDED, EXCLUDED)
        await tree.package(ticket, "example-no-tracks", ())
        mixed_out = await tree.package(ticket, "example-excluded-and-eol", ())
        await tree.track(mixed_out, PackageStatus.AFFECTED, EXCLUDED, EOL)
        # A NULL lifecycle phase does not make a Product non-actionable.
        await tree.package(ticket, "example-lifecycle-unknown")
        partly = await tree.package(ticket, "example-partly-eol", ())
        await tree.track(
            partly, PackageStatus.NOT_AFFECTED, EOL, Occ(gs_end=date(2030, 1, 1))
        )

        assert sorted(await _names(db_session)) == [
            "example-lifecycle-unknown",
            "example-partly-eol",
        ]

    async def test_summary_counts_only_the_actionable_tracks(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """A package with one actionable track and excluded or EOL-only
        tracks is present; only the actionable track is counted."""
        ticket = await ticket_factory()
        package = await tree.package(ticket, "example-mixed", (PackageStatus.AFFECTED,))
        await tree.track(package, PackageStatus.FIXED, excluded=True)
        await tree.track(package, PackageStatus.NOT_AFFECTED, EOL)
        await tree.track(package, PackageStatus.WONT_FIX, EXCLUDED)

        page = await _search(db_session)

        assert page.total == 1
        (item,) = page.items
        assert item.track_summary == _summary(affected=1)

    @pytest.mark.parametrize("status", list(PackageStatus), ids=str)
    async def test_every_status_is_counted_in_its_own_field(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        status: PackageStatus,
    ) -> None:
        ticket = await ticket_factory()
        package = await tree.package(ticket, "example-status", (status, status))
        await tree.track(package, status, excluded=True)
        await tree.track(package, status, EOL)
        await tree.track(package, status, EXCLUDED)
        field = {
            PackageStatus.AFFECTED: "affected",
            PackageStatus.FIXED: "fixed",
            PackageStatus.NOT_AFFECTED: "not_affected",
            PackageStatus.WONT_FIX: "wont_fix",
            PackageStatus.ANALYSIS: "analysis",
        }[status]

        (item,) = (await _search(db_session)).items

        assert item.track_summary == _summary(**{field: 2})

    async def test_summary_belongs_to_its_own_package_occurrence(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """Same package name in two Tickets: each item counts only its own
        tracks."""
        first = await ticket_factory(sequence_id=801)
        second = await ticket_factory(sequence_id=802)
        await tree.package(first, "example-lib", (PackageStatus.AFFECTED,))
        await tree.package(
            second,
            "example-lib",
            (PackageStatus.FIXED, PackageStatus.FIXED, PackageStatus.WONT_FIX),
        )

        page = await _search(db_session)

        assert {item.ticket.ticket_id: item.track_summary for item in page.items} == {
            "SNTL-801": _summary(affected=1),
            "SNTL-802": _summary(fixed=2, wont_fix=1),
        }


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSearchFilter:
    NAMES = (
        "example%lib",
        "exampleXlib",
        "example_lib",
        "example\\lib",
        "Example-Lib",
        "fictional tool",
    )

    async def _seed(self, tree: Tree, ticket_factory: Factory) -> None:
        ticket = await ticket_factory()
        for name in self.NAMES:
            await tree.package(ticket, name)

    async def test_percent_underscore_and_backslash_are_literal(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await self._seed(tree, ticket_factory)

        assert await _names(db_session, search="%") == ["example%lib"]
        assert await _names(db_session, search="e%l") == ["example%lib"]
        assert await _names(db_session, search="_") == ["example_lib"]
        assert await _names(db_session, search="e_l") == ["example_lib"]
        assert await _names(db_session, search="\\") == ["example\\lib"]
        assert await _names(db_session, search="e\\l") == ["example\\lib"]
        assert await _names(db_session, search="x%") == []
        assert await _names(db_session, search="X_") == []

    async def test_substring_match_is_case_insensitive(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await self._seed(tree, ticket_factory)

        assert sorted(await _names(db_session, search="LIB")) == sorted(
            ["example%lib", "exampleXlib", "example_lib", "example\\lib", "Example-Lib"]
        )
        assert await _names(db_session, search="xampleX") == ["exampleXlib"]
        assert await _names(db_session, search="-lIb") == ["Example-Lib"]
        assert await _names(db_session, search="TOOL") == ["fictional tool"]

    async def test_outer_whitespace_is_trimmed_and_inner_whitespace_kept(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await self._seed(tree, ticket_factory)

        assert await _names(db_session, search="  fictional tool \t") == [
            "fictional tool"
        ]
        assert await _names(db_session, search=" EXAMPLE_ ") == ["example_lib"]
        assert await _names(db_session, search="fictional  tool") == []

    @pytest.mark.parametrize(
        "term",
        [
            pytest.param(None, id="omitted"),
            pytest.param("", id="empty"),
            pytest.param(" ", id="space"),
            pytest.param("   \t\n ", id="whitespace"),
        ],
    )
    async def test_empty_or_whitespace_only_search_applies_no_filter(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        term: str | None,
    ) -> None:
        await self._seed(tree, ticket_factory)

        assert sorted(await _names(db_session, search=term)) == sorted(self.NAMES)


@pytest.mark.integration
class TestNameFilter:
    async def test_name_is_an_exact_case_sensitive_match(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        first = await ticket_factory()
        second = await ticket_factory()
        await tree.package(first, "example-lib")
        await tree.package(second, "example-lib")
        await tree.package(first, "Example-Lib")
        await tree.package(first, "example-lib-extra")
        await tree.package(first, "example%lib")

        assert await _names(db_session, name="example-lib") == [
            "example-lib",
            "example-lib",
        ]
        assert await _names(db_session, name="Example-Lib") == ["Example-Lib"]
        assert await _names(db_session, name="EXAMPLE-LIB") == []
        assert await _names(db_session, name="example") == []
        assert await _names(db_session, name="lib") == []
        assert await _names(db_session, name="example%lib") == ["example%lib"]
        assert await _names(db_session, name="example_lib") == []


@pytest.mark.integration
class TestTicketStatusFilter:
    async def _seed(self, tree: Tree, ticket_factory: Factory) -> None:
        """One Ticket per status with packages `<status>-a` and `<status>-b`
        (the Duplicated factory target has no package)."""
        for status in TicketStatus:
            ticket = await ticket_factory(status=status.value)
            for suffix in ("a", "b"):
                await tree.package(ticket, f"{status.value.lower()}-{suffix}")

    @ALL_STATUSES
    async def test_each_status_selects_only_its_tickets(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        await self._seed(tree, ticket_factory)

        page = await _search(db_session, ticket_status=[status])

        assert page.total == 2
        assert sorted(i.package_name for i in page.items) == [
            f"{status.value.lower()}-a",
            f"{status.value.lower()}-b",
        ]
        assert {i.ticket.status for i in page.items} == {status}

    async def test_values_combine_with_or_and_other_filters_with_and(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await self._seed(tree, ticket_factory)
        new_or_resolved = [TicketStatus.NEW, TicketStatus.RESOLVED]

        assert sorted(await _names(db_session, ticket_status=new_or_resolved)) == [
            "new-a",
            "new-b",
            "resolved-a",
            "resolved-b",
        ]
        assert sorted(
            await _names(db_session, ticket_status=new_or_resolved, search="-A")
        ) == ["new-a", "resolved-a"]
        assert await _names(
            db_session, ticket_status=new_or_resolved, name="resolved-b"
        ) == ["resolved-b"]
        assert (
            await _names(db_session, ticket_status=new_or_resolved, name="analysis-a")
            == []
        )

    async def test_empty_collection_matches_nothing_and_none_matches_all(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        await self._seed(tree, ticket_factory)

        assert await _search(db_session, ticket_status=[]) == PackageSearchPage(
            items=(), total=0, page=1, per_page=20
        )
        assert len(await _names(db_session, ticket_status=None)) == 12
        assert len(await _names(db_session)) == 12


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSorting:
    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_package_name_uses_unicode_code_point_order(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        sort_order: SortOrder,
    ) -> None:
        """Code-point order puts uppercase before `_`, `_` before
        lowercase, and non-ASCII last, independent of collation."""
        ticket = await ticket_factory()
        for minute, name in enumerate(("beta", "ébène", "_under", "alpha", "Zeta")):
            await tree.package(
                ticket, name, created_at=BASE + timedelta(minutes=minute)
            )
        ascending = ["Zeta", "_under", "alpha", "beta", "ébène"]

        names = await _names(
            db_session, sort_by=PackageSortField.PACKAGE_NAME, sort_order=sort_order
        )

        assert names == (ascending if sort_order is SortOrder.ASC else ascending[::-1])

    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_created_at_is_the_package_timestamp(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        sort_order: SortOrder,
    ) -> None:
        """`TicketPackage.created_at`, not `Ticket.created_at`: the Tickets
        are created in the opposite order of their packages."""
        for index, name in enumerate(
            ("example-first", "example-second", "example-third")
        ):
            ticket = await ticket_factory(created_at=BASE - timedelta(days=index))
            await tree.package(ticket, name, created_at=BASE + timedelta(hours=index))
        ascending = ["example-first", "example-second", "example-third"]

        names = await _names(
            db_session, sort_by=PackageSortField.CREATED_AT, sort_order=sort_order
        )

        assert names == (ascending if sort_order is SortOrder.ASC else ascending[::-1])

    async def test_default_order_is_created_at_descending(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()
        for minute, name in enumerate(("example-b", "example-c", "example-a")):
            await tree.package(
                ticket, name, created_at=BASE + timedelta(minutes=minute)
            )

        assert await _names(db_session) == ["example-a", "example-c", "example-b"]

    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    @pytest.mark.parametrize("sort_by", list(PackageSortField), ids=str)
    async def test_equal_keys_page_deterministically_by_internal_id(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        sort_by: PackageSortField,
        sort_order: SortOrder,
    ) -> None:
        """Equal primary keys (one package name in five Tickets, all added
        at the same instant) are ordered by `TicketPackage.id` in the
        requested direction: paging one row at a time neither repeats nor
        skips."""
        packages = [
            await tree.package(await ticket_factory(), "example-tie", created_at=BASE)
            for _ in range(5)
        ]
        expected = sorted(
            (package.id for package in packages),
            reverse=sort_order is SortOrder.DESC,
        )

        pages = [
            await _search(
                db_session, sort_by=sort_by, sort_order=sort_order, page=n, per_page=1
            )
            for n in range(1, 6)
        ]

        assert [page.items[0].id for page in pages] == expected
        assert {page.total for page in pages} == {5}

    async def test_tie_breaker_applies_within_equal_keys_only(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """Across pages of two, distinct names keep their primary order and
        equal names are ordered by id within the group."""
        tied = [
            await tree.package(await ticket_factory(), "example-b") for _ in range(3)
        ]
        await tree.package(await ticket_factory(), "example-a")
        await tree.package(await ticket_factory(), "example-c")
        tied_ids = sorted(package.id for package in tied)

        pages = [
            await _search(
                db_session,
                sort_by=PackageSortField.PACKAGE_NAME,
                sort_order=SortOrder.ASC,
                page=n,
                per_page=2,
            )
            for n in (1, 2, 3)
        ]
        items = [item for page in pages for item in page.items]

        assert [item.package_name for item in items] == [
            "example-a",
            "example-b",
            "example-b",
            "example-b",
            "example-c",
        ]
        assert [item.id for item in items[1:4]] == tied_ids


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPagination:
    async def test_total_is_computed_before_slicing(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()
        for minute in range(5):
            await tree.package(
                ticket, f"example-{minute}", created_at=BASE + timedelta(minutes=minute)
            )

        page = await _search(db_session, page=2, per_page=2)

        assert (page.total, page.page, page.per_page) == (5, 2, 2)
        assert [item.package_name for item in page.items] == ["example-2", "example-1"]

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()
        for index in range(3):
            await tree.package(ticket, f"example-{index}")

        page = await _search(db_session, page=4, per_page=1)

        assert page == PackageSearchPage(items=(), total=3, page=4, per_page=1)

    async def test_empty_database_yields_an_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        assert await _search(db_session) == PackageSearchPage(
            items=(), total=0, page=1, per_page=20
        )

    @pytest.mark.parametrize(
        ("page", "per_page"),
        [
            pytest.param(0, 20, id="page-0"),
            pytest.param(-1, 20, id="page-negative"),
            pytest.param(1, 0, id="per-page-0"),
            pytest.param(1, 101, id="per-page-101"),
        ],
    )
    async def test_out_of_range_pagination_raises_before_any_query(
        self, db_session: AsyncSession, page: int, per_page: int
    ) -> None:
        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="page"),
        ):
            await _search(db_session, page=page, per_page=per_page)

        assert recorder.statements == []

    @pytest.mark.parametrize("per_page", [1, 100])
    async def test_per_page_bounds_are_accepted(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        per_page: int,
    ) -> None:
        ticket = await ticket_factory()
        for index in range(3):
            await tree.package(ticket, f"example-{index}")

        page = await _search(db_session, per_page=per_page)

        assert (page.total, page.per_page, len(page.items)) == (
            3,
            per_page,
            min(3, per_page),
        )


# ---------------------------------------------------------------------------
# Bounded database work and read-only behavior
# ---------------------------------------------------------------------------


async def _bulk_tree(
    db: AsyncSession, ticket_factory: Factory, *, packages: int, tracks: int
) -> None:
    """`packages` actionable packages over five Tickets, each with `tracks`
    tracks of two shared supported Products (bulk flushes, no per-row
    round trip)."""
    tickets = [await ticket_factory() for _ in range(5)]
    products = [
        Product(
            name=f"Example Product bulk {index}",
            version="1",
            display_name=f"EP bulk {index}",
            cpe=f"cpe:/o:example:bulk:{index}",
            catalog_last_seen_at=BASE,
        )
        for index in range(2)
    ]
    created = [
        TicketPackage(
            ticket_id=tickets[index % 5].id, package_name=f"example-bulk-{index}"
        )
        for index in range(packages)
    ]
    db.add_all([*products, *created])
    await db.flush()
    statuses = list(PackageStatus)
    track_rows = [
        TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{index}:Update",
            status=statuses[index % len(statuses)].value,
        )
        for package in created
        for index in range(tracks)
    ]
    db.add_all(track_rows)
    await db.flush()
    db.add_all(
        [
            TicketPackageProduct(ticket_package_track_id=track.id, product_id=p.id)
            for track in track_rows
            for p in products
        ]
    )
    await db.flush()


@pytest.mark.integration
class TestBoundedRead:
    @pytest.mark.parametrize(
        ("packages", "tracks"),
        [
            pytest.param(0, 0, id="no-result"),
            pytest.param(1, 1, id="one-result"),
            pytest.param(40, 6, id="many-results-many-tracks"),
        ],
    )
    async def test_statement_count_is_independent_of_page_size_and_cardinality(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        packages: int,
        tracks: int,
    ) -> None:
        """No per-item or per-track loading: every page size and result
        cardinality executes the same single statement, so an N+1
        regression fails."""
        await _bulk_tree(db_session, ticket_factory, packages=packages, tracks=tracks)

        counts = []
        for per_page in (1, 100):
            with _StatementRecorder(db_session) as recorder:
                page = await _search(db_session, per_page=per_page)
            assert page.total == packages
            assert len(page.items) == min(packages, per_page)
            assert all(item.track_summary.total == tracks for item in page.items)
            counts.append(len(recorder.statements))

        assert counts == [1, 1]

    async def test_search_writes_nothing_locks_nothing_and_ends_no_transaction(
        self,
        db_session: AsyncSession,
        tree: Tree,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, severity_manual=Severity.LOW.value
        )
        await tree.package(ticket, "example-read-only", (PackageStatus.AFFECTED,))
        await ticket_audit_event_factory(ticket_id=ticket.id)
        snapshot = select(
            Ticket.status,
            Ticket.updated_at,
            Ticket.assignee_id,
            Ticket.priority_auto,
            TicketPackage.updated_at,
            TicketPackage.deleted_at,
        ).join(TicketPackage, TicketPackage.ticket_id == Ticket.id)
        events = select(func.count()).select_from(TicketAuditEvent)
        before = (
            (await db_session.execute(snapshot)).all(),
            await db_session.scalar(events),
        )
        transaction_ends: list[object] = []

        def _record_end(*args: object) -> None:
            transaction_ends.append(args)

        event.listen(db_session.sync_session, "after_transaction_end", _record_end)
        try:
            with _StatementRecorder(db_session) as recorder:
                await _search(
                    db_session,
                    search="read",
                    ticket_status=[TicketStatus.ANALYSIS],
                    sort_by=PackageSortField.PACKAGE_NAME,
                )
        finally:
            event.remove(db_session.sync_session, "after_transaction_end", _record_end)

        after = (
            (await db_session.execute(snapshot)).all(),
            await db_session.scalar(events),
        )
        assert after == before
        assert transaction_ends == []
        assert db_session.in_transaction()
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        (statement,) = recorder.statements
        upper = statement.upper()
        assert upper.split(None, 1)[0] in {"SELECT", "WITH"}
        assert not re.search(
            r"\b(INSERT|UPDATE|DELETE|SAVEPOINT|COMMIT|ROLLBACK)\b", upper
        )
        assert not re.search(
            r"\bFOR\s+(NO\s+KEY\s+)?(UPDATE|SHARE|KEY\s+SHARE)\b", upper
        )

    async def test_database_error_propagates_unchanged(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await search_packages(db, caller=ALL_SCOPE, evaluation_date=EVAL)

        assert excinfo.value is failure
        db.commit.assert_not_awaited()
        db.rollback.assert_not_awaited()


# ---------------------------------------------------------------------------
# One supplied evaluation date (package-model.md, Derived Actionability;
# testing-strategy.md, controlled-clock bullet)
# ---------------------------------------------------------------------------

LAST_SUPPORTED_DAY = GS_END
"""A Product whose only lifecycle date is this General Support end is in
General Support on this date and `eol` on the next day
(lifecycle_matrix.py, `gs_only_at_gs_end_general_support` and
`gs_only_day_after_gs_end_eol`)."""

FIRST_EOL_DAY = GS_END + ONE_DAY


@pytest.mark.integration
class TestEvaluationDate:
    async def test_candidate_selection_uses_the_supplied_date(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()
        package = await tree.package(ticket, "example-eol-tomorrow", ())
        await tree.track(package, PackageStatus.AFFECTED, Occ(gs_end=GS_END))

        before = await _search(db_session, evaluation_date=LAST_SUPPORTED_DAY)
        after = await _search(db_session, evaluation_date=FIRST_EOL_DAY)

        assert before.total == 1
        (item,) = before.items
        assert item.track_summary == _summary(affected=1)
        assert after == PackageSearchPage(items=(), total=0, page=1, per_page=20)

    async def test_track_summary_uses_the_same_supplied_date(
        self, db_session: AsyncSession, tree: Tree, ticket_factory: Factory
    ) -> None:
        """One track turns `eol` on the next day while another stays
        actionable: the item remains and its summary drops that track, on
        whichever date the caller supplies (independent of the real
        current date)."""
        ticket = await ticket_factory()
        package = await tree.package(ticket, "example-partly", ())
        await tree.track(package, PackageStatus.AFFECTED, Occ(gs_end=GS_END))
        await tree.track(package, PackageStatus.FIXED, SUPPORTED)

        on_last_day = await _search(db_session, evaluation_date=LAST_SUPPORTED_DAY)
        on_first_eol_day = await _search(db_session, evaluation_date=FIRST_EOL_DAY)

        assert [i.track_summary for i in on_last_day.items] == [
            _summary(affected=1, fixed=1)
        ]
        assert [i.track_summary for i in on_first_eol_day.items] == [_summary(fixed=1)]
        assert (on_last_day.total, on_first_eol_day.total) == (1, 1)
