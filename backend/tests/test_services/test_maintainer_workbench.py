"""Tests for the maintainer workbench queries of `package_service`.

Owning specifications:

- docs/features/packages/maintainer.md (User Identification and
  Ownership; Workbench Row and Privacy Contract; Classification; Shared
  Global-List Query Contract; Package Details for Ticket; Consistency,
  Side Effects, and Performance).
- docs/features/packages/package-service.md (Maintainer workbench
  queries; Architectural Test Requirement "Maintainer workbench
  queries").
- docs/features/tickets/ticket-deadlines.md (Evaluation Instant; Track
  Milestones; Sorting; Testing Requirements 7 and 12).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility): the canonical visibility predicate, consumed unchanged.
- docs/features/platform/testing-strategy.md (Maintainer Workbench;
  Ticket Accessibility > List and count reads, Single, nested, and
  assembled reads).

The independent-session races live in
`tests/test_services/test_maintainer_workbench_races.py`.

Expected values are transcribed from the specifications; the deadline
parity tests compare with `get_ticket_packages()`, the owning projection
of `TrackDetail`. Every test starts from an empty database (per-test
transaction rollback), so each read observes exactly the rows the test
creates.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    MaintainerWorkSortField,
    MilestoneStatus,
    PackageStatus,
    Scope,
    Severity,
    SortOrder,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    MAX_PER_PAGE,
    get_maintainer_ticket_work,
    get_ticket_packages,
    list_maintainer_completed_work,
    list_maintainer_in_progress_work,
    list_maintainer_pending_work,
)
from app.services.packages.maintainer_workbench import (
    MaintainerTicketWork,
    MaintainerWorkItem,
    MaintainerWorkPage,
)
from app.services.ticket_convergence_registry import pending_ticket_convergence_effects
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.maintainer_workbench import (
    ELIGIBLE,
    EOL,
    EVAL,
    EXCLUDED,
    INELIGIBLE,
    INSTANT,
    OLD,
    RECENT,
    SUBMISSION_OFFSET_30,
    Prod,
    WorkbenchSeed,
    owner_caller,
)
from tests.support.no_outbound import OutboundGuard
from tests.support.ticket_mutations import StatementRecorder

pytest_plugins = ["tests.support.no_outbound_fixtures"]

ListOperation = Callable[..., Awaitable[MaintainerWorkPage]]

LISTS: Final[Mapping[str, ListOperation]] = {
    "pending": list_maintainer_pending_work,
    "in_progress": list_maintainer_in_progress_work,
    "completed": list_maintainer_completed_work,
}
CLASSIFICATIONS: Final = tuple(LISTS)
ALL_LISTS = pytest.mark.parametrize("classification", CLASSIFICATIONS)


@pytest.fixture
def seed(db_session: AsyncSession) -> WorkbenchSeed:
    return WorkbenchSeed(db_session)


@pytest.fixture
async def owner(seed: WorkbenchSeed) -> User:
    return await seed.user()


async def _list(
    db: AsyncSession,
    classification: str,
    caller: TicketCaller,
    **arguments: Any,
) -> MaintainerWorkPage:
    arguments.setdefault("evaluation_date", EVAL)
    arguments.setdefault("evaluation_instant", INSTANT)
    arguments.setdefault("per_page", MAX_PER_PAGE)
    return await LISTS[classification](db, caller=caller, **arguments)


async def _ticket_work(
    db: AsyncSession,
    ticket: Ticket | str,
    caller: TicketCaller,
    **arguments: Any,
) -> MaintainerTicketWork:
    locator = (
        ticket if isinstance(ticket, str) else format_ticket_id(ticket.sequence_id)
    )
    arguments.setdefault("evaluation_date", EVAL)
    arguments.setdefault("evaluation_instant", INSTANT)
    return await get_maintainer_ticket_work(
        db, ticket_id=locator, caller=caller, **arguments
    )


def _references(items: tuple[MaintainerWorkItem, ...]) -> list[str]:
    return [item.reference for item in items]


async def _listed(
    db: AsyncSession, caller: TicketCaller, **arguments: Any
) -> dict[str, list[str]]:
    """The references of every global list; each total agrees with its
    complete page."""
    listed = {}
    for classification in CLASSIFICATIONS:
        page = await _list(db, classification, caller, **arguments)
        assert page.total == len(page.items)
        listed[classification] = _references(page.items)
    return listed


async def _classify(
    db: AsyncSession, ticket: Ticket, caller: TicketCaller, **arguments: Any
) -> set[str]:
    """The classifications in which the caller's tracks of `ticket` appear,
    asserting that the per-Ticket aggregate partitions them identically to
    the three global lists."""
    listed = await _listed(db, caller, **arguments)
    work = await _ticket_work(db, ticket, caller, **arguments)
    assert {c: _references(getattr(work, c)) for c in CLASSIFICATIONS} == listed
    return {classification for classification, refs in listed.items() if refs}


# ---------------------------------------------------------------------------
# Projection (maintainer.md, Workbench Row and Privacy Contract)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProjection:
    async def test_item_projects_exactly_the_ten_fields(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket(severity=Severity.HIGH, created_at=RECENT)
        cve_identifier = await db_session.scalar(
            select(CVE.cve_id).where(CVE.id == ticket.cve_id)
        )
        await seed.work(
            owner,
            ticket=ticket,
            name="fictional-kernel",
            reference="SUSE:SLE-15-SP6:Update",
        )

        page = await _list(db_session, "pending", owner_caller(owner), per_page=20)

        assert page == MaintainerWorkPage(
            items=(
                MaintainerWorkItem(
                    package_name="fictional-kernel",
                    ticket_id=format_ticket_id(ticket.sequence_id),
                    cve_id=cve_identifier,
                    severity=Severity.HIGH,
                    workflow_type=WorkflowType.IBS,
                    reference="SUSE:SLE-15-SP6:Update",
                    status=PackageStatus.AFFECTED,
                    delivery_status=DeliveryStatus.PENDING,
                    submission_due_at=RECENT + SUBMISSION_OFFSET_30,
                    submission_milestone=MilestoneStatus.PENDING,
                ),
            ),
            total=1,
            page=1,
            per_page=20,
        )

    async def test_cveless_ticket_projects_manual_severity_and_null_cve(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        await seed.work(owner, cve=False, severity=Severity.MEDIUM)

        (item,) = (await _list(db_session, "pending", owner_caller(owner))).items

        assert (item.cve_id, item.severity) == (None, Severity.MEDIUM)
        assert item.submission_due_at == RECENT + timedelta(days=54)

    async def test_unresolved_severity_projects_null_with_the_30_day_tier(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        await seed.work(owner, severity=None)

        (item,) = (await _list(db_session, "pending", owner_caller(owner))).items

        assert item.severity is None
        assert item.submission_due_at == RECENT + SUBMISSION_OFFSET_30

    async def test_none_label_is_distinct_from_unresolved_and_has_no_sla(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        await seed.work(owner, severity=Severity.NONE)

        (item,) = (await _list(db_session, "pending", owner_caller(owner))).items

        assert item.severity is Severity.NONE
        assert (item.submission_due_at, item.submission_milestone) == (None, None)


# ---------------------------------------------------------------------------
# Visibility and ownership (maintainer.md, User Identification and
# Ownership; testing-strategy.md, Maintainer Workbench)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestVisibilityAndOwnership:
    async def test_non_confidential_ticket_without_association_returns_nothing(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket()
        await seed.work(other, ticket=ticket)

        assert await _listed(db_session, owner_caller(owner)) == {
            c: [] for c in CLASSIFICATIONS
        }
        assert await _ticket_work(db_session, ticket, owner_caller(owner)) == (
            MaintainerTicketWork(pending=(), in_progress=(), completed=())
        )

    async def test_scope_all_without_association_returns_nothing(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket(confidential=True)
        await seed.work(other, ticket=ticket)
        caller = owner_caller(owner, Scope.ALL)

        assert await _classify(db_session, ticket, caller) == set()

    async def test_explicit_grant_without_association_returns_nothing(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket(confidential=True)
        await seed.work(other, ticket=ticket)
        await seed.grant(ticket, owner, other)

        assert await _classify(db_session, ticket, owner_caller(owner)) == set()

    @pytest.mark.parametrize(
        "branch", ["non-confidential", "scope-all", "explicit-grant", "maintainer"]
    )
    async def test_every_visibility_branch_with_ownership_returns_the_row(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User, branch: str
    ) -> None:
        ticket = await seed.ticket(confidential=branch != "non-confidential")
        track = await seed.work(owner, ticket=ticket)
        caller = (
            owner_caller(owner, Scope.ALL)
            if branch == "scope-all"
            else owner_caller(owner)
        )
        if branch == "explicit-grant":
            await seed.grant(ticket, owner, await seed.user())

        assert await _classify(db_session, ticket, caller) == {"pending"}
        (item,) = (await _list(db_session, "pending", caller)).items
        assert item.reference == track.reference

    async def test_confidential_ticket_without_any_branch_is_invisible(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket(confidential=True)
        await seed.work(other, ticket=ticket)

        assert await _listed(db_session, owner_caller(owner)) == {
            c: [] for c in CLASSIFICATIONS
        }
        with pytest.raises(TicketNotFoundError):
            await _ticket_work(db_session, ticket, owner_caller(owner))

    async def test_another_users_association_is_not_ownership(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket()
        await seed.work(other, ticket=ticket, name="fictional-a")
        mine = await seed.work(owner, ticket=ticket, name="fictional-b")

        assert await _listed(db_session, owner_caller(owner)) == {
            "pending": [mine.reference],
            "in_progress": [],
            "completed": [],
        }

    async def test_same_named_package_on_another_ticket_does_not_qualify(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        maintained = await seed.ticket()
        unmaintained = await seed.ticket()
        await seed.work(owner, ticket=maintained, name="fictional-shared")
        package = await seed.package(unmaintained, "fictional-shared")
        await seed.track(package)

        page = await _list(db_session, "pending", owner_caller(owner))

        assert [item.ticket_id for item in page.items] == [
            format_ticket_id(maintained.sequence_id)
        ]

    @pytest.mark.parametrize(
        "confidential", [False, True], ids=["public", "confidential"]
    )
    async def test_excluded_package_is_not_owned_and_restore_reactivates_it(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        confidential: bool,
    ) -> None:
        """A direct package exclusion retains the association but removes
        ownership (and, for a confidential Ticket, the maintainer visibility
        branch); restoring the package reactivates both."""
        ticket = await seed.ticket(confidential=confidential)
        track = await seed.work(owner, ticket=ticket)
        caller = owner_caller(owner)
        await db_session.execute(
            update(TicketPackage)
            .where(TicketPackage.id == track.ticket_package_id)
            .values(deleted_at=INSTANT - timedelta(days=1))
        )

        assert await _listed(db_session, caller) == {c: [] for c in CLASSIFICATIONS}
        if confidential:
            with pytest.raises(TicketNotFoundError):
                await _ticket_work(db_session, ticket, caller)
        else:
            assert await _classify(db_session, ticket, caller) == set()
        associations = await db_session.scalar(
            select(func.count()).select_from(TicketPackageMaintainer)
        )
        assert associations == 1

        await db_session.execute(
            update(TicketPackage)
            .where(TicketPackage.id == track.ticket_package_id)
            .values(deleted_at=None)
        )
        assert await _classify(db_session, ticket, caller) == {"pending"}

    async def test_another_included_maintained_package_preserves_visibility(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket(confidential=True)
        excluded = await seed.package(ticket, "fictional-a", maintainers=(owner,))
        await seed.track(excluded)
        await db_session.execute(
            update(TicketPackage)
            .where(TicketPackage.id == excluded.id)
            .values(deleted_at=INSTANT - timedelta(days=1))
        )
        kept = await seed.work(owner, ticket=ticket, name="fictional-b")

        work = await _ticket_work(db_session, ticket, owner_caller(owner))

        assert _references(work.pending) == [kept.reference]

    async def test_track_and_product_exclusion_affect_only_actionability(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """Excluding one track or the only Product of another track removes
        those rows only; the package-wide association keeps owning (and making
        visible) the remaining track."""
        ticket = await seed.ticket(confidential=True)
        package = await seed.package(ticket, maintainers=(owner,))
        kept = await seed.track(package, reference="Example:Kept:Update")
        await seed.track(package, reference="Example:Track:Update", excluded=True)
        await seed.track(
            package, reference="Example:Product:Update", products=(EXCLUDED,)
        )

        assert await _listed(db_session, owner_caller(owner)) == {
            "pending": [kept.reference],
            "in_progress": [],
            "completed": [],
        }

    async def test_anonymous_caller_is_a_contract_violation(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket()
        with StatementRecorder(db_session) as recorder:
            for classification in CLASSIFICATIONS:
                with pytest.raises(ValueError, match="authenticated caller"):
                    await _list(db_session, classification, ANONYMOUS_CALLER)
            with pytest.raises(ValueError, match="authenticated caller"):
                await _ticket_work(db_session, ticket, ANONYMOUS_CALLER)
        assert recorder.statements == []


# ---------------------------------------------------------------------------
# Classification (maintainer.md, Classification)
# ---------------------------------------------------------------------------

_STATUS_EXPECTATIONS: Final = {
    TicketStatus.NEW: set(),
    TicketStatus.ANALYSIS: {"pending", "in_progress", "completed"},
    TicketStatus.ANALYZED: {"pending", "in_progress", "completed"},
    TicketStatus.RESOLVED: {"completed"},
    TicketStatus.IGNORED: set(),
    TicketStatus.DUPLICATED: set(),
}


@pytest.mark.integration
class TestTicketStatusBoundaries:
    @pytest.mark.parametrize("status", list(TicketStatus), ids=str)
    async def test_ticket_status_admits_exactly_its_classifications(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        status: TicketStatus,
    ) -> None:
        """One pending-shaped, one in-progress-shaped, and one
        completed-shaped track on a Ticket in each status."""
        ticket = await seed.ticket(status=status)
        package = await seed.package(ticket, maintainers=(owner,))
        for reference, delivery in (
            ("pending", DeliveryStatus.PENDING),
            ("in_progress", DeliveryStatus.IN_PROGRESS),
            ("completed", DeliveryStatus.RELEASED),
        ):
            await seed.track(package, reference=reference, delivery=delivery)

        listed = await _listed(db_session, owner_caller(owner))
        work = await _ticket_work(db_session, ticket, owner_caller(owner))

        expected = _STATUS_EXPECTATIONS[status]
        assert listed == {c: [c] if c in expected else [] for c in CLASSIFICATIONS}
        assert {c: _references(getattr(work, c)) for c in CLASSIFICATIONS} == listed


_P = PackageStatus
_D = DeliveryStatus

# (track status, delivery, Products) -> expected classifications. Transcribed
# from maintainer.md (Pending, In Progress, Completed).
_SHAPES: Final = [
    pytest.param(_P.AFFECTED, _D.PENDING, (ELIGIBLE,), {"pending"}, id="pending"),
    pytest.param(_P.ANALYSIS, _D.PENDING, (ELIGIBLE,), set(), id="analysis-pending"),
    pytest.param(_P.FIXED, _D.PENDING, (ELIGIBLE,), set(), id="fixed-pending"),
    pytest.param(_P.NOT_AFFECTED, _D.PENDING, (ELIGIBLE,), set(), id="na-pending"),
    pytest.param(_P.WONT_FIX, _D.PENDING, (ELIGIBLE,), set(), id="wontfix-pending"),
    pytest.param(
        _P.AFFECTED, _D.IN_PROGRESS, (ELIGIBLE,), {"in_progress"}, id="affected-ip"
    ),
    pytest.param(_P.FIXED, _D.IN_PROGRESS, (ELIGIBLE,), {"in_progress"}, id="fixed-ip"),
    pytest.param(_P.ANALYSIS, _D.IN_PROGRESS, (ELIGIBLE,), set(), id="analysis-ip"),
    pytest.param(_P.NOT_AFFECTED, _D.IN_PROGRESS, (ELIGIBLE,), set(), id="na-ip"),
    pytest.param(_P.WONT_FIX, _D.IN_PROGRESS, (ELIGIBLE,), set(), id="wontfix-ip"),
    *(
        pytest.param(
            status, _D.RELEASED, products, {"completed"}, id=f"{status}-released-{tag}"
        )
        for status in PackageStatus
        for tag, products in (("eligible", (ELIGIBLE,)), ("ineligible", (INELIGIBLE,)))
    ),
    *(
        pytest.param(_P.AFFECTED, delivery, products, set(), id=f"{delivery}-{tag}")
        for delivery in (_D.PENDING, _D.IN_PROGRESS)
        for tag, products in (
            ("all-ineligible", (INELIGIBLE, INELIGIBLE)),
            ("eligible-only-excluded", (Prod(excluded=True), INELIGIBLE)),
            ("eligible-only-eol", (EOL, INELIGIBLE)),
        )
    ),
    *(
        pytest.param(_P.AFFECTED, delivery, products, set(), id=f"{delivery}-{tag}")
        for delivery in DeliveryStatus
        for tag, products in (
            ("no-product", ()),
            ("all-excluded", (EXCLUDED, EXCLUDED)),
            ("all-eol", (EOL, EOL)),
        )
    ),
    pytest.param(
        _P.AFFECTED,
        _D.PENDING,
        (EOL, INELIGIBLE, ELIGIBLE),
        {"pending"},
        id="pending-mixed-one-actionable-eligible",
    ),
    pytest.param(
        _P.FIXED,
        _D.IN_PROGRESS,
        (EXCLUDED, ELIGIBLE),
        {"in_progress"},
        id="in-progress-mixed-one-actionable-eligible",
    ),
    pytest.param(
        _P.WONT_FIX,
        _D.RELEASED,
        (EOL, INELIGIBLE),
        {"completed"},
        id="completed-mixed-actionable-ineligible",
    ),
]


@pytest.mark.integration
class TestClassificationShapes:
    @pytest.mark.parametrize("workflow", [WorkflowType.IBS, WorkflowType.GIT], ids=str)
    @pytest.mark.parametrize(
        ("track_status", "delivery", "products", "expected"), _SHAPES
    )
    async def test_shape_is_classified_exactly(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        workflow: WorkflowType,
        track_status: PackageStatus,
        delivery: DeliveryStatus,
        products: tuple[Prod, ...],
        expected: set[str],
    ) -> None:
        """`ibs` and `git` tracks with the same persisted facts classify
        identically, and `workflow_type` is projected accurately."""
        ticket = await seed.ticket()
        await seed.work(
            owner,
            ticket=ticket,
            track_status=track_status,
            delivery=delivery,
            workflow=workflow,
            products=products,
        )

        assert await _classify(db_session, ticket, owner_caller(owner)) == expected
        for classification in expected:
            (item,) = (
                await _list(db_session, classification, owner_caller(owner))
            ).items
            assert item.workflow_type is workflow

    @pytest.mark.parametrize("level", ["package", "track", "product"])
    @pytest.mark.parametrize("delivery", list(DeliveryStatus), ids=str)
    async def test_direct_and_ancestor_exclusion_removes_every_classification(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        level: str,
        delivery: DeliveryStatus,
    ) -> None:
        """A marker at any level makes the track non-actionable; a package or
        track marker is also the ancestor-effective exclusion of every
        Product below it."""
        ticket = await seed.ticket()
        package = await seed.package(
            ticket, maintainers=(owner,), excluded=level == "package"
        )
        await seed.track(
            package,
            delivery=delivery,
            excluded=level == "track",
            products=(EXCLUDED, EXCLUDED) if level == "product" else (ELIGIBLE,),
        )

        assert await _listed(db_session, owner_caller(owner)) == {
            c: [] for c in CLASSIFICATIONS
        }

    async def test_classification_changes_no_persisted_value(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket()
        package = await seed.package(ticket, maintainers=(owner,))
        for delivery in DeliveryStatus:
            await seed.track(package, delivery=delivery, products=(ELIGIBLE, EOL))
        snapshot = (
            select(
                Ticket.status,
                Ticket.updated_at,
                Ticket.assignee_id,
                TicketPackage.deleted_at,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
                TicketPackageProduct.eligible,
                TicketPackageProduct.deleted_at,
                TicketPackageProduct.released_at,
            )
            .select_from(Ticket)
            .join(TicketPackage)
            .join(TicketPackageTrack)
            .join(TicketPackageProduct)
            .order_by(TicketPackageProduct.id)
        )
        before = (await db_session.execute(snapshot)).all()

        await _classify(db_session, ticket, owner_caller(owner))

        assert (await db_session.execute(snapshot)).all() == before


# ---------------------------------------------------------------------------
# Filtering, ordering, and pagination (maintainer.md, Shared Global-List
# Query Contract; docs/api-spec.md, Sorting)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPackageFilter:
    @pytest.mark.parametrize(
        ("value", "matches"),
        [
            pytest.param("fictional-kernel", True, id="exact"),
            pytest.param("Fictional-Kernel", False, id="case-variant"),
            pytest.param("fictional", False, id="prefix"),
            pytest.param("kernel", False, id="substring"),
            pytest.param("fictional_kernel", False, id="alias-like"),
            pytest.param("fictional-kernel%", False, id="pattern-syntax"),
            pytest.param(" fictional-kernel", False, id="leading-whitespace"),
            pytest.param("fictional-kernel ", False, id="trailing-whitespace"),
        ],
    )
    async def test_package_is_a_case_sensitive_exact_match(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        value: str,
        matches: bool,
    ) -> None:
        ticket = await seed.ticket()
        exact = await seed.work(owner, ticket=ticket, name="fictional-kernel")
        for name in ("fictional-kernel-source", "libfictional-kernel-x"):
            await seed.work(owner, ticket=ticket, name=name)

        page = await _list(db_session, "pending", owner_caller(owner), package=value)

        assert _references(page.items) == ([exact.reference] if matches else [])
        assert page.total == (1 if matches else 0)

    async def test_package_composes_with_the_mandatory_predicates_using_and(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """Same-named packages that are invisible, not owned, or not pending
        never match the filter."""
        other = await seed.user()
        name = "fictional-kernel"
        mine = await seed.work(owner, name=name)
        await seed.work(other, name=name, confidential=True)
        await seed.work(other, name=name)
        await seed.work(owner, name=name, delivery=DeliveryStatus.IN_PROGRESS)
        await seed.work(owner, name=name, status=TicketStatus.NEW)
        await seed.work(owner, name="fictional-other")

        page = await _list(db_session, "pending", owner_caller(owner), package=name)

        assert (page.total, _references(page.items)) == (1, [mine.reference])


async def _sorted(
    db: AsyncSession,
    caller: TicketCaller,
    sort_by: MaintainerWorkSortField,
    sort_order: SortOrder,
) -> list[str]:
    page = await _list(db, "pending", caller, sort_by=sort_by, sort_order=sort_order)
    return _references(page.items)


@pytest.mark.integration
class TestOrdering:
    async def test_default_is_severity_descending(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        low = await seed.work(owner, severity=Severity.LOW)
        critical = await seed.work(owner, severity=Severity.CRITICAL)
        unresolved = await seed.work(owner, severity=None)

        page = await list_maintainer_pending_work(
            db_session,
            caller=owner_caller(owner),
            evaluation_date=EVAL,
            evaluation_instant=INSTANT,
        )

        assert _references(page.items) == [
            critical.reference,
            low.reference,
            unresolved.reference,
        ]
        assert (page.page, page.per_page) == (1, 20)

    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_severity_uses_the_semantic_rank_with_null_last(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        sort_order: SortOrder,
    ) -> None:
        by_label = {}
        for severity in (
            Severity.MEDIUM,
            Severity.NONE,
            Severity.CRITICAL,
            Severity.LOW,
            Severity.HIGH,
        ):
            by_label[severity] = (await seed.work(owner, severity=severity)).reference
        unresolved = (await seed.work(owner, severity=None)).reference
        ascending = [
            by_label[s]
            for s in (
                Severity.NONE,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            )
        ]
        expected = ascending if sort_order is SortOrder.ASC else ascending[::-1]

        assert await _sorted(
            db_session,
            owner_caller(owner),
            MaintainerWorkSortField.SEVERITY,
            sort_order,
        ) == [*expected, unresolved]

    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_package_uses_unicode_code_point_order(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        sort_order: SortOrder,
    ) -> None:
        """Code-point order puts uppercase before lowercase and `ä` after
        every ASCII letter, unlike a linguistic collation."""
        ticket = await seed.ticket()
        by_name = {
            name: (await seed.work(owner, ticket=ticket, name=name)).reference
            for name in ("b-pkg", "ä-pkg", "B-pkg", "a-pkg")
        }
        ascending = [by_name[n] for n in ("B-pkg", "a-pkg", "b-pkg", "ä-pkg")]
        expected = ascending if sort_order is SortOrder.ASC else ascending[::-1]

        assert (
            await _sorted(
                db_session,
                owner_caller(owner),
                MaintainerWorkSortField.PACKAGE,
                sort_order,
            )
            == expected
        )

    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_submission_due_at_orders_by_date_with_null_last(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        sort_order: SortOrder,
    ) -> None:
        """Due dates differ by tier and start; the `None` severity label has
        no SLA and therefore a null due date, which stays last."""
        earliest = await seed.work(owner, created_at=OLD)
        middle = await seed.work(owner, created_at=RECENT)
        latest = await seed.work(owner, severity=Severity.LOW, created_at=OLD)
        no_sla = await seed.work(owner, severity=Severity.NONE)
        ascending = [earliest.reference, middle.reference, latest.reference]
        expected = ascending if sort_order is SortOrder.ASC else ascending[::-1]

        assert await _sorted(
            db_session,
            owner_caller(owner),
            MaintainerWorkSortField.SUBMISSION_DUE_AT,
            sort_order,
        ) == [*expected, no_sla.reference]

    @pytest.mark.parametrize("sort_by", list(MaintainerWorkSortField), ids=str)
    @pytest.mark.parametrize("sort_order", list(SortOrder), ids=str)
    async def test_equal_keys_page_stably_by_internal_track_id(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        sort_by: MaintainerWorkSortField,
        sort_order: SortOrder,
    ) -> None:
        """Five rows with equal severity, package name, and due date: paging
        one at a time yields every row exactly once, in track-UUID order in
        the requested direction."""
        ticket = await seed.ticket()
        package = await seed.package(ticket, "fictional-same", maintainers=(owner,))
        tracks = [await seed.track(package) for _ in range(5)]
        ids = sorted(track.id for track in tracks)
        expected_ids = ids if sort_order is SortOrder.ASC else ids[::-1]
        by_reference = {track.reference: track.id for track in tracks}

        observed: list[uuid.UUID] = []
        for page_number in range(1, 7):
            page = await _list(
                db_session,
                "pending",
                owner_caller(owner),
                sort_by=sort_by,
                sort_order=sort_order,
                page=page_number,
                per_page=1,
            )
            assert page.total == 5
            observed.extend(by_reference[item.reference] for item in page.items)

        assert observed == expected_ids


@pytest.mark.integration
class TestPagination:
    async def test_pages_slice_one_candidate_set_with_its_total(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket()
        names = [f"fictional-{n:02d}" for n in range(5)]
        by_name = {
            name: (await seed.work(owner, ticket=ticket, name=name)).reference
            for name in names
        }

        pages = [
            await _list(
                db_session,
                "pending",
                owner_caller(owner),
                sort_by=MaintainerWorkSortField.PACKAGE,
                sort_order=SortOrder.ASC,
                page=number,
                per_page=2,
            )
            for number in (1, 2, 3, 4)
        ]

        assert [_references(page.items) for page in pages] == [
            [by_name[names[0]], by_name[names[1]]],
            [by_name[names[2]], by_name[names[3]]],
            [by_name[names[4]]],
            [],
        ]
        assert [(p.total, p.page, p.per_page) for p in pages] == [
            (5, 1, 2),
            (5, 2, 2),
            (5, 3, 2),
            (5, 4, 2),
        ]

    @ALL_LISTS
    async def test_empty_candidate_set_is_an_ordinary_empty_page(
        self, db_session: AsyncSession, owner: User, classification: str
    ) -> None:
        page = await _list(db_session, classification, owner_caller(owner), page=3)

        assert page == MaintainerWorkPage(items=(), total=0, page=3, per_page=100)

    async def test_minimum_and_maximum_page_sizes(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket()
        package = await seed.package(ticket, maintainers=(owner,))
        for _ in range(3):
            await seed.track(package)

        smallest = await _list(db_session, "pending", owner_caller(owner), per_page=1)
        largest = await _list(db_session, "pending", owner_caller(owner), per_page=100)

        assert (len(smallest.items), smallest.total) == (1, 3)
        assert (len(largest.items), largest.total) == (3, 3)

    @ALL_LISTS
    @pytest.mark.parametrize(
        ("page", "per_page", "message"),
        [
            pytest.param(0, 20, "page must be at least 1", id="page-zero"),
            pytest.param(1, 0, "per_page must be between", id="per-page-zero"),
            pytest.param(1, 101, "per_page must be between", id="per-page-101"),
        ],
    )
    async def test_invalid_pagination_raises_before_any_query(
        self,
        db_session: AsyncSession,
        owner: User,
        classification: str,
        page: int,
        per_page: int,
        message: str,
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=message),
        ):
            await _list(
                db_session,
                classification,
                owner_caller(owner),
                page=page,
                per_page=per_page,
            )
        assert recorder.statements == []

    async def test_naive_instant_raises_before_any_query(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        ticket = await seed.ticket()
        naive = INSTANT.replace(tzinfo=None)
        with StatementRecorder(db_session) as recorder:
            for classification in CLASSIFICATIONS:
                with pytest.raises(ValueError, match="timezone-aware"):
                    await _list(
                        db_session,
                        classification,
                        owner_caller(owner),
                        evaluation_instant=naive,
                    )
            with pytest.raises(ValueError, match="timezone-aware"):
                await _ticket_work(
                    db_session, ticket, owner_caller(owner), evaluation_instant=naive
                )
        assert recorder.statements == []


# ---------------------------------------------------------------------------
# Submission deadline projection (ticket-deadlines.md; carried-in line 5)
# ---------------------------------------------------------------------------

_DEADLINE_CASES: Final = [
    pytest.param(
        {},
        RECENT + SUBMISSION_OFFSET_30,
        MilestoneStatus.PENDING,
        id="pending-row-pending",
    ),
    pytest.param(
        {"created_at": OLD},
        OLD + SUBMISSION_OFFSET_30,
        MilestoneStatus.OVERDUE,
        id="pending-row-overdue",
    ),
    pytest.param(
        {"created_at": OLD, "products": (Prod(released=True),)},
        OLD + SUBMISSION_OFFSET_30,
        MilestoneStatus.DONE,
        id="pending-row-done-by-later-qa-evidence",
    ),
    pytest.param(
        {"created_at": OLD, "delivery": DeliveryStatus.IN_PROGRESS},
        OLD + SUBMISSION_OFFSET_30,
        MilestoneStatus.DONE,
        id="in-progress-row-done",
    ),
    pytest.param(
        {"created_at": OLD, "delivery": DeliveryStatus.RELEASED},
        OLD + SUBMISSION_OFFSET_30,
        MilestoneStatus.DONE,
        id="completed-row-done",
    ),
    pytest.param(
        {"created_at": OLD, "workflow": WorkflowType.GIT},
        OLD + SUBMISSION_OFFSET_30,
        None,
        id="git-track-null",
    ),
    pytest.param(
        {"created_at": OLD, "cve": False},
        OLD + SUBMISSION_OFFSET_30,
        None,
        id="cveless-ticket-null",
    ),
    *(
        pytest.param(
            {
                "created_at": OLD,
                "track_status": status,
                "delivery": DeliveryStatus.RELEASED,
            },
            OLD + SUBMISSION_OFFSET_30,
            MilestoneStatus.NOT_APPLICABLE,
            id=f"completed-{status}-not-applicable",
        )
        for status in (PackageStatus.NOT_AFFECTED, PackageStatus.WONT_FIX)
    ),
    pytest.param(
        {
            "created_at": OLD,
            "delivery": DeliveryStatus.RELEASED,
            "products": (INELIGIBLE,),
        },
        OLD + SUBMISSION_OFFSET_30,
        MilestoneStatus.NOT_APPLICABLE,
        id="completed-without-actionable-eligible-product-not-applicable",
    ),
    pytest.param({"severity": Severity.NONE}, None, None, id="none-label-no-sla"),
    pytest.param(
        {"severity": Severity.LOW, "created_at": OLD},
        OLD + timedelta(days=108),
        MilestoneStatus.PENDING,
        id="low-tier",
    ),
]


@pytest.mark.integration
class TestDeadlineProjection:
    @pytest.mark.parametrize(("work", "due_at", "milestone"), _DEADLINE_CASES)
    async def test_submission_fields_equal_the_track_detail_projection(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        work: dict[str, Any],
        due_at: datetime | None,
        milestone: MilestoneStatus | None,
    ) -> None:
        """Every classified row projects the transcribed submission due date
        and milestone status, equal to the same track's `TrackDetail` values
        from `get_ticket_packages()` for the same instant, in both the global
        list and the per-Ticket aggregate."""
        ticket_columns = {
            key: work.pop(key)
            for key in ("created_at", "cve", "severity")
            if key in work
        }
        ticket = await seed.ticket(**ticket_columns)
        await seed.work(owner, ticket=ticket, **work)
        caller = owner_caller(owner)

        aggregate = await _ticket_work(db_session, ticket, caller)
        (item,) = aggregate.pending + aggregate.in_progress + aggregate.completed
        listed = [
            listed_item
            for classification in CLASSIFICATIONS
            for listed_item in (await _list(db_session, classification, caller)).items
        ]
        (tree_package,) = await get_ticket_packages(
            db_session,
            ticket_id=format_ticket_id(ticket.sequence_id),
            caller=caller,
            evaluation_date=EVAL,
            evaluation_instant=INSTANT,
        )
        (tree_track,) = tree_package.tracks
        tree_due = tree_track.due_dates

        assert listed == [item]
        assert (item.submission_due_at, item.submission_milestone) == (
            due_at,
            milestone,
        )
        assert item.submission_due_at == (
            tree_due.submission if tree_due is not None else None
        )
        assert item.submission_milestone == tree_track.milestones.submission

    async def test_due_boundary_equal_instant_is_pending(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """`due_at < evaluation_instant` is past; an equal instant is not."""
        await seed.work(owner, created_at=OLD)
        due = OLD + SUBMISSION_OFFSET_30

        at_due = await _list(
            db_session, "pending", owner_caller(owner), evaluation_instant=due
        )
        after_due = await _list(
            db_session,
            "pending",
            owner_caller(owner),
            evaluation_instant=due + timedelta(microseconds=1),
        )

        assert at_due.items[0].submission_milestone is MilestoneStatus.PENDING
        assert after_due.items[0].submission_milestone is MilestoneStatus.OVERDUE

    async def test_one_supplied_date_classifies_rows_and_total_across_midnight(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """A Product whose General Support ends on `EVAL` is actionable on
        `EVAL` and `eol` on the next day: the supplied date alone decides
        participation for rows and total alike."""
        ticket = await seed.ticket()
        await seed.work(owner, ticket=ticket, products=(Prod(gs_end=EVAL),))
        before = datetime(EVAL.year, EVAL.month, EVAL.day, 23, 59, 59, 999999, UTC)
        after = before + timedelta(microseconds=1)

        on_eval = await _list(
            db_session,
            "pending",
            owner_caller(owner),
            evaluation_date=before.date(),
            evaluation_instant=before,
        )
        next_day = await _list(
            db_session,
            "pending",
            owner_caller(owner),
            evaluation_date=after.date(),
            evaluation_instant=after,
        )

        assert (on_eval.total, len(on_eval.items)) == (1, 1)
        assert (next_day.total, next_day.items) == (0, ())


# ---------------------------------------------------------------------------
# No fan-out and bounded queries
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoFanOut:
    @ALL_LISTS
    async def test_products_and_associations_never_multiply_a_track(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        classification: str,
    ) -> None:
        delivery = {
            "pending": DeliveryStatus.PENDING,
            "in_progress": DeliveryStatus.IN_PROGRESS,
            "completed": DeliveryStatus.RELEASED,
        }[classification]
        ticket = await seed.ticket(confidential=True)
        package = await seed.package(
            ticket, maintainers=(owner, await seed.user(), await seed.user())
        )
        first = await seed.track(
            package, delivery=delivery, products=(ELIGIBLE, ELIGIBLE, ELIGIBLE, EOL)
        )
        second = await seed.track(package, delivery=delivery)
        unrelated = await seed.package(ticket, "fictional-unrelated")
        await seed.track(unrelated, delivery=delivery, products=(ELIGIBLE, ELIGIBLE))
        await seed.grant(ticket, owner, await seed.user())

        page = await _list(db_session, classification, owner_caller(owner))
        work = await _ticket_work(db_session, ticket, owner_caller(owner))

        expected = sorted([first.reference, second.reference])
        assert page.total == 2
        assert sorted(_references(page.items)) == expected
        assert sorted(_references(getattr(work, classification))) == expected


async def _bulk(seed: WorkbenchSeed, owner: User, *, tickets: int, tracks: int) -> None:
    for _ in range(tickets):
        ticket = await seed.ticket()
        package = await seed.package(ticket, maintainers=(owner,))
        for _ in range(tracks):
            await seed.track(package, products=(ELIGIBLE, ELIGIBLE))


@pytest.mark.integration
class TestBoundedQueries:
    @ALL_LISTS
    @pytest.mark.parametrize(
        ("tickets", "tracks"),
        [
            pytest.param(0, 0, id="no-result"),
            pytest.param(1, 1, id="one-result"),
            pytest.param(12, 10, id="many-results"),
        ],
    )
    async def test_list_is_one_statement_for_every_page_size_and_cardinality(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        classification: str,
        tickets: int,
        tracks: int,
    ) -> None:
        await _bulk(seed, owner, tickets=tickets, tracks=tracks)
        expected_total = tickets * tracks if classification == "pending" else 0

        counts = []
        for per_page in (1, 100):
            with StatementRecorder(db_session) as recorder:
                page = await _list(
                    db_session, classification, owner_caller(owner), per_page=per_page
                )
            assert page.total == expected_total
            assert len(page.items) == min(expected_total, per_page)
            counts.append(len(recorder.statements))

        assert counts == [1, 1]

    @pytest.mark.parametrize("tracks", [0, 1, 40])
    async def test_per_ticket_aggregate_is_one_statement(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User, tracks: int
    ) -> None:
        ticket = await seed.ticket()
        package = await seed.package(ticket, maintainers=(owner,))
        for _ in range(tracks):
            await seed.track(package, products=(ELIGIBLE, ELIGIBLE))

        with StatementRecorder(db_session) as recorder:
            work = await _ticket_work(db_session, ticket, owner_caller(owner))

        assert len(work.pending) == tracks
        assert len(recorder.statements) == 1


# ---------------------------------------------------------------------------
# Per-Ticket aggregate (maintainer.md, Package Details for Ticket)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketWork:
    async def test_collections_partition_and_use_the_fixed_order(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """Ascending code-point `package_name`, then `reference`, then track
        UUID; each track appears in exactly one collection."""
        ticket = await seed.ticket()
        b_package = await seed.package(ticket, "b-pkg", maintainers=(owner,))
        upper_package = await seed.package(ticket, "B-pkg", maintainers=(owner,))
        a_package = await seed.package(ticket, "a-pkg", maintainers=(owner,))
        b_second = await seed.track(b_package, reference="b-ref")
        b_first = await seed.track(b_package, reference="B-ref")
        upper = await seed.track(upper_package, reference="z-ref")
        a_track = await seed.track(a_package, reference="a-ref")
        a_progress = await seed.track(
            a_package, reference="m-ref", delivery=DeliveryStatus.IN_PROGRESS
        )
        b_done = await seed.track(
            b_package, reference="c-ref", delivery=DeliveryStatus.RELEASED
        )
        a_done = await seed.track(
            a_package, reference="x-ref", delivery=DeliveryStatus.RELEASED
        )

        work = await _ticket_work(db_session, ticket, owner_caller(owner))

        assert _references(work.pending) == [
            upper.reference,
            a_track.reference,
            b_first.reference,
            b_second.reference,
        ]
        assert _references(work.in_progress) == [a_progress.reference]
        assert _references(work.completed) == [a_done.reference, b_done.reference]
        assert {item.ticket_id for item in work.pending} == {
            format_ticket_id(ticket.sequence_id)
        }

    @pytest.mark.parametrize(
        "cause",
        [
            "status-new",
            "status-ignored",
            "status-duplicated",
            "no-association",
            "excluded-package",
            "no-package",
            "ineligible",
            "not-affected-pending",
        ],
    )
    async def test_accessible_ticket_without_work_returns_three_empty_collections(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User, cause: str
    ) -> None:
        status = {
            "status-new": TicketStatus.NEW,
            "status-ignored": TicketStatus.IGNORED,
            "status-duplicated": TicketStatus.DUPLICATED,
        }.get(cause, TicketStatus.ANALYSIS)
        ticket = await seed.ticket(status=status)
        if cause != "no-package":
            package = await seed.package(
                ticket,
                maintainers=() if cause == "no-association" else (owner,),
                excluded=cause == "excluded-package",
            )
            await seed.track(
                package,
                status=PackageStatus.NOT_AFFECTED
                if cause == "not-affected-pending"
                else PackageStatus.AFFECTED,
                products=(INELIGIBLE,) if cause == "ineligible" else (ELIGIBLE,),
            )

        work = await _ticket_work(db_session, ticket, owner_caller(owner))

        assert work == MaintainerTicketWork(pending=(), in_progress=(), completed=())

    @pytest.mark.parametrize(
        "locator",
        [
            pytest.param(lambda t: f"sntl-{t.sequence_id}", id="lowercase-prefix"),
            pytest.param(lambda t: f"SNTL-0{t.sequence_id}", id="zero-padded"),
            pytest.param(lambda t: f" SNTL-{t.sequence_id}", id="leading-space"),
            pytest.param(lambda t: "SNTL-0", id="zero"),
            pytest.param(lambda t: "not-a-ticket", id="malformed"),
            pytest.param(lambda t: str(t.id), id="ticket-uuid"),
        ],
    )
    async def test_malformed_locator_raises_before_any_query(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        locator: Callable[[Ticket], str],
    ) -> None:
        ticket = await seed.ticket()
        await seed.work(owner, ticket=ticket)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _ticket_work(db_session, locator(ticket), owner_caller(owner))

        assert recorder.statements == []

    async def test_missing_and_inaccessible_tickets_are_indistinguishable(
        self, db_session: AsyncSession, seed: WorkbenchSeed, owner: User
    ) -> None:
        """Both raise the same no-argument `TicketNotFoundError`; the
        inaccessible Ticket has caller-owned-looking work for another user
        that is never projected."""
        other = await seed.user()
        inaccessible = await seed.ticket(confidential=True)
        await seed.work(other, ticket=inaccessible)

        errors = []
        for locator in ("SNTL-2147483647", format_ticket_id(inaccessible.sequence_id)):
            with pytest.raises(TicketNotFoundError) as excinfo:
                await _ticket_work(db_session, locator, owner_caller(owner))
            errors.append((type(excinfo.value), excinfo.value.args))

        assert errors[0] == errors[1]


# ---------------------------------------------------------------------------
# Read-only service (maintainer.md, Consistency, Side Effects, and
# Performance)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReadOnly:
    async def test_queries_write_lock_dispatch_and_end_nothing(
        self,
        db_session: AsyncSession,
        seed: WorkbenchSeed,
        owner: User,
        no_outbound: OutboundGuard,
    ) -> None:
        ticket = await seed.ticket()
        package = await seed.package(ticket, maintainers=(owner,))
        for delivery in DeliveryStatus:
            await seed.track(package, delivery=delivery)
        db_session.add(
            TicketAuditEvent(ticket_id=ticket.id, event_type="ticket_created")
        )
        await db_session.flush()
        snapshot = (
            select(
                Ticket.status,
                Ticket.updated_at,
                Ticket.assignee_id,
                Ticket.priority_auto,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.updated_at,
            )
            .join(TicketPackage, TicketPackage.ticket_id == Ticket.id)
            .join(TicketPackageTrack)
            .order_by(TicketPackageTrack.id)
        )
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
            with StatementRecorder(db_session) as recorder:
                for classification in CLASSIFICATIONS:
                    await _list(
                        db_session,
                        classification,
                        owner_caller(owner),
                        package="fictional-pkg",
                        sort_by=MaintainerWorkSortField.SUBMISSION_DUE_AT,
                    )
                await _ticket_work(db_session, ticket, owner_caller(owner))
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
        assert not db_session.info.get("post_commit_callbacks")
        assert pending_ticket_convergence_effects(db_session) == ()
        assert no_outbound.attempts == []
        assert len(recorder.statements) == 4
        for statement in recorder.statements:
            upper = statement.upper()
            assert upper.split(None, 1)[0] in {"SELECT", "WITH"}
            assert not re.search(
                r"\b(INSERT|UPDATE|DELETE|SAVEPOINT|COMMIT|ROLLBACK)\b", upper
            )
            assert not re.search(
                r"\bFOR\s+(NO\s+KEY\s+)?(UPDATE|SHARE|KEY\s+SHARE)\b", upper
            )

    @pytest.mark.parametrize("operation", [*CLASSIFICATIONS, "ticket"])
    async def test_database_error_propagates_unchanged(self, operation: str) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure
        caller = TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL)

        call = (
            _ticket_work(db, "SNTL-1", caller)
            if operation == "ticket"
            else _list(db, operation, caller)
        )
        with pytest.raises(OperationalError) as excinfo:
            await call

        assert excinfo.value is failure
        db.commit.assert_not_awaited()
        db.rollback.assert_not_awaited()
