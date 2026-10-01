"""Tests for the package-tree query (`package_service.get_ticket_packages()`
and its composed mode).

Owning specifications:

- `docs/features/packages/package-service.md` (Query Operations >
  `get_ticket_packages()`): SNTL-only resolution under the canonical
  visibility predicate in one coherent observation, the complete tree
  including excluded records, canonical code-point ordering, no
  maintainer identities, no N+1 loading.
- `docs/features/packages/package-model.md` (Derived Actionability,
  Delivery Relevance Indicator, List Ticket Packages).
- `docs/features/tickets/ticket-deadlines.md` (Due Dates, Evaluation
  Instant, Track Milestones, Testing Requirements 4-7, 11, 12 track
  parts): per-track due dates, milestones, and `current_phase` over
  persisted Ticket, track, Product, and IBS request evidence rows, driven
  by the shared matrix `tests/support/deadline_matrix.py` (also consumed
  by the pure-function and SQL parity tests).
- `docs/features/platform/testing-strategy.md` (Ticket Accessibility >
  Single, nested, and assembled reads; Ticket identifier and read-contract
  coverage; package query N+1 checks).

Expected milestone results are transcribed independently from the
specification, never computed by the module under test.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CurrentPhase,
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    LifecyclePhase,
    MilestoneStatus,
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import package_service
from app.services.package_service import (
    PackageProjection,
    ProductProjection,
    TicketTreeContext,
    TrackProjection,
    assemble_ticket_packages,
    get_ticket_packages,
    ticket_package_tree_column,
    ticket_tree_context_columns,
    ticket_tree_context_from_row,
)
from app.services.ticket_deadlines import (
    ACTIVE_RELEASE_REQUEST_STATES,
    DueDates,
    TrackMilestones,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.deadline_matrix import (
    ACTIVE_RELEASE_REQUEST_STATES as MATRIX_ACTIVE_STATES,
)
from tests.support.deadline_matrix import (
    AFTER_ALL_DUE,
    AT_TRIAGE_DUE,
    BEFORE_ANY_DUE,
    CREATED_AT,
    DEADLINE_CASES,
    RELEASE,
    TIER_30_OFFSETS_DAYS,
    DeadlineCase,
    ProductEvidence,
    RequestEvidence,
)
from tests.support.deadline_persistence import (
    EXCLUDED_AT,
    GS_FUTURE,
    GS_PAST,
    RELEASED_AT,
    DeadlineWorld,
)
from tests.support.module_imports import APP_ROOT, imported_modules

Factory = Callable[..., Awaitable[Any]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)

D = MilestoneStatus.DONE
P = MilestoneStatus.PENDING
O = MilestoneStatus.OVERDUE  # noqa: E741 - mirrors the specification value
NA = MilestoneStatus.NOT_APPLICABLE
N = None
R = NonActionableReason


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _due_dates(offsets: tuple[int, ...] = TIER_30_OFFSETS_DAYS) -> DueDates:
    triage, submission, um, qa, release = (
        CREATED_AT + timedelta(days=days) for days in offsets
    )
    return DueDates(triage=triage, submission=submission, um=um, qa=qa, release=release)


async def _read(
    db: AsyncSession,
    ticket: Ticket,
    *,
    caller: TicketCaller = ALL_SCOPE,
    instant: datetime = BEFORE_ANY_DUE,
    evaluation_date: date | None = None,
) -> tuple[PackageProjection, ...]:
    return await get_ticket_packages(
        db,
        ticket_id=_sntl(ticket),
        caller=caller,
        evaluation_date=evaluation_date or instant.date(),
        evaluation_instant=instant,
    )


class _StatementRecorder:
    """Records every SQL statement executed through the test engine."""

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
# Complete projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTreeProjection:
    async def test_projects_every_level_including_excluded_and_eol_records(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.HIGH.value)
        ticket: Ticket = await ticket_factory(cve_id=cve.id, created_at=CREATED_AT)
        supported = await product_factory(
            cpe="cpe:/o:example:alpha:1",
            display_name="Example Alpha 1",
            general_support_end_date=GS_FUTURE,
        )
        eol = await product_factory(
            cpe="cpe:/o:example:beta:1",
            display_name="Example Beta 1",
            general_support_end_date=GS_PAST,
        )
        unknown = await product_factory(cpe="cpe:/o:example:gamma:1")
        included = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-lib"
        )
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-tool", deleted_at=EXCLUDED_AT
        )
        track = await ticket_package_track_factory(
            ticket_package_id=included.id,
            reference="Example:Codestream:1:Update",
            status=PackageStatus.AFFECTED.value,
            delivery_status=DeliveryStatus.IN_PROGRESS.value,
        )
        alpha = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=supported.id,
            released_at=RELEASED_AT,
        )
        beta = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=eol.id,
            eligible=False,
            is_eligible_override=True,
        )
        gamma = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=unknown.id,
            deleted_at=EXCLUDED_AT,
        )
        excluded_track = await ticket_package_track_factory(
            ticket_package_id=excluded.id,
            reference="Example:Codestream:2:Update",
            workflow_type=WorkflowType.GIT.value,
            status=PackageStatus.NOT_AFFECTED.value,
        )
        delta = await ticket_package_product_factory(
            ticket_package_track_id=excluded_track.id, product_id=supported.id
        )

        packages = await _read(db_session, ticket)

        due = _due_dates()
        assert packages == (
            PackageProjection(
                id=included.id,
                package_name="example-lib",
                deleted_at=None,
                actionable=True,
                non_actionable_reason=None,
                tracks=(
                    TrackProjection(
                        id=track.id,
                        workflow_type=WorkflowType.IBS,
                        reference="Example:Codestream:1:Update",
                        status=PackageStatus.AFFECTED,
                        delivery_status=DeliveryStatus.IN_PROGRESS,
                        delivery_relevant=True,
                        deleted_at=None,
                        actionable=True,
                        non_actionable_reason=None,
                        due_dates=due,
                        milestones=TrackMilestones(
                            triage=D,
                            submission=D,
                            um=D,
                            qa=D,
                            current_phase=CurrentPhase.DONE,
                        ),
                        products=(
                            ProductProjection(
                                id=alpha.id,
                                product_cpe="cpe:/o:example:alpha:1",
                                product_name="Example Alpha 1",
                                eligible=True,
                                is_eligible_override=False,
                                released_at=RELEASED_AT,
                                lifecycle_phase=LifecyclePhase.GENERAL_SUPPORT,
                                deleted_at=None,
                                actionable=True,
                                non_actionable_reason=None,
                            ),
                            ProductProjection(
                                id=beta.id,
                                product_cpe="cpe:/o:example:beta:1",
                                product_name="Example Beta 1",
                                eligible=False,
                                is_eligible_override=True,
                                released_at=None,
                                lifecycle_phase=LifecyclePhase.EOL,
                                deleted_at=None,
                                actionable=False,
                                non_actionable_reason=R.EOL,
                            ),
                            ProductProjection(
                                id=gamma.id,
                                product_cpe="cpe:/o:example:gamma:1",
                                product_name=unknown.display_name,
                                eligible=True,
                                is_eligible_override=False,
                                released_at=None,
                                lifecycle_phase=None,
                                deleted_at=EXCLUDED_AT,
                                actionable=False,
                                non_actionable_reason=R.PRODUCT_EXCLUDED,
                            ),
                        ),
                    ),
                ),
            ),
            PackageProjection(
                id=excluded.id,
                package_name="example-tool",
                deleted_at=EXCLUDED_AT,
                actionable=False,
                non_actionable_reason=R.PACKAGE_EXCLUDED,
                tracks=(
                    TrackProjection(
                        id=excluded_track.id,
                        workflow_type=WorkflowType.GIT,
                        reference="Example:Codestream:2:Update",
                        status=PackageStatus.NOT_AFFECTED,
                        delivery_status=DeliveryStatus.PENDING,
                        delivery_relevant=False,
                        deleted_at=None,
                        actionable=False,
                        non_actionable_reason=R.PACKAGE_EXCLUDED,
                        due_dates=due,
                        milestones=TrackMilestones(
                            triage=NA,
                            submission=NA,
                            um=NA,
                            qa=NA,
                            current_phase=CurrentPhase.DONE,
                        ),
                        products=(
                            ProductProjection(
                                id=delta.id,
                                product_cpe="cpe:/o:example:alpha:1",
                                product_name="Example Alpha 1",
                                eligible=True,
                                is_eligible_override=False,
                                released_at=None,
                                lifecycle_phase=LifecyclePhase.GENERAL_SUPPORT,
                                deleted_at=None,
                                actionable=False,
                                non_actionable_reason=R.PACKAGE_EXCLUDED,
                            ),
                        ),
                    ),
                ),
            ),
        )

    async def test_timestamps_are_aware_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=EXCLUDED_AT
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, deleted_at=EXCLUDED_AT
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            released_at=RELEASED_AT,
            deleted_at=EXCLUDED_AT,
        )

        (projected,) = await _read(db_session, ticket, instant=datetime.now(UTC))
        (projected_track,) = projected.tracks
        (projected_product,) = projected_track.products

        for value in (
            projected.deleted_at,
            projected_track.deleted_at,
            projected_product.deleted_at,
            projected_product.released_at,
        ):
            assert value is not None
            assert value.utcoffset() == timedelta(0)
        assert projected_product.released_at == RELEASED_AT

    async def test_ticket_without_packages_returns_an_empty_tree(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        assert await _read(db_session, ticket) == ()

    async def test_track_and_package_without_children_are_present(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(created_at=CREATED_AT)
        empty_package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="a-empty"
        )
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="b-with-track"
        )
        await ticket_package_track_factory(ticket_package_id=package.id)

        first, second = await _read(db_session, ticket)

        assert (first.id, first.tracks, first.non_actionable_reason) == (
            empty_package.id,
            (),
            R.NO_ACTIONABLE_TRACKS,
        )
        (track,) = second.tracks
        assert (track.products, track.actionable, track.non_actionable_reason) == (
            (),
            False,
            R.NO_ACTIONABLE_PRODUCTS,
        )
        assert second.non_actionable_reason is R.NO_ACTIONABLE_TRACKS

    async def test_track_excluded_reason_precedes_no_actionable_products(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, deleted_at=EXCLUDED_AT
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, deleted_at=EXCLUDED_AT
        )

        (projected,) = await _read(db_session, ticket)
        (projected_track,) = projected.tracks
        (projected_product,) = projected_track.products

        assert projected.non_actionable_reason is R.NO_ACTIONABLE_TRACKS
        assert projected_track.non_actionable_reason is R.TRACK_EXCLUDED
        assert projected_product.non_actionable_reason is R.TRACK_EXCLUDED

    async def test_projection_exposes_no_maintainer_identity(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(ticket_package_id=package.id)

        with _StatementRecorder(db_session) as recorder:
            (projected,) = await _read(db_session, ticket)

        assert "maintainer" not in PackageProjection.__dataclass_fields__
        assert projected.id == package.id
        (statement,) = recorder.statements
        assert "ticket_package_maintainer" not in statement
        assert '"user"' not in statement


# ---------------------------------------------------------------------------
# Resolution, accessibility, and caller-contract errors
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResolutionAndAccessibility:
    @pytest.mark.parametrize(
        "locator",
        ["sntl-1", "SNTL-01", "SNTL-0", " SNTL-1", "SNTL-2147483648", "", "abc"],
    )
    async def test_malformed_locator_raises_before_any_query(
        self, db_session: AsyncSession, locator: str
    ) -> None:
        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await get_ticket_packages(
                db_session,
                ticket_id=locator,
                caller=ALL_SCOPE,
                evaluation_date=BEFORE_ANY_DUE.date(),
                evaluation_instant=BEFORE_ANY_DUE,
            )

        assert recorder.statements == []

    async def test_uuid_missing_and_inaccessible_raise_the_same_error(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        confidential: Ticket = await ticket_factory(is_confidential=True)

        for locator, caller in (
            (str(confidential.id), ALL_SCOPE),
            ("SNTL-2147483647", ALL_SCOPE),
            (_sntl(confidential), ANONYMOUS_CALLER),
            (
                _sntl(confidential),
                TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL),
            ),
        ):
            with pytest.raises(TicketNotFoundError) as raised:
                await get_ticket_packages(
                    db_session,
                    ticket_id=locator,
                    caller=caller,
                    evaluation_date=BEFORE_ANY_DUE.date(),
                    evaluation_instant=BEFORE_ANY_DUE,
                )
            assert str(raised.value) == str(TicketNotFoundError())

    async def test_naive_instant_raises_before_any_query(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="evaluation_instant"),
        ):
            await _read(db_session, ticket, instant=BEFORE_ANY_DUE.replace(tzinfo=None))

        assert recorder.statements == []

    @pytest.mark.parametrize("branch", ["scope_all", "grant", "maintainer"])
    async def test_each_visibility_branch_returns_the_confidential_tree(
        self,
        branch: str,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=ticket.id)
        user: User = await user_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        if branch == "scope_all":
            caller = TicketCaller.authenticated(user.id, Scope.ALL)
        elif branch == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        else:
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )

        (projected,) = await _read(db_session, ticket, caller=caller)

        assert projected.id == package.id

    async def test_non_confidential_tree_is_visible_to_anonymous(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)

        (projected,) = await _read(db_session, ticket, caller=ANONYMOUS_CALLER)

        assert projected.id == package.id

    async def test_excluded_maintained_package_grants_no_access_but_stays_in_tree(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, package_name="a", deleted_at=EXCLUDED_AT
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=user.id
        )
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        with pytest.raises(TicketNotFoundError):
            await _read(db_session, ticket, caller=caller)

        included = await ticket_package_factory(ticket_id=ticket.id, package_name="b")
        await ticket_package_maintainer_factory(
            ticket_package_id=included.id, user_id=user.id
        )
        projected = await _read(db_session, ticket, caller=caller)

        assert [p.id for p in projected] == [excluded.id, included.id]

    async def test_database_errors_propagate(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failure = RuntimeError("fictional database failure")
        monkeypatch.setattr(db_session, "execute", AsyncMock(side_effect=failure))

        with pytest.raises(RuntimeError) as raised:
            await get_ticket_packages(
                db_session,
                ticket_id="SNTL-1",
                caller=ALL_SCOPE,
                evaluation_date=BEFORE_ANY_DUE.date(),
                evaluation_instant=BEFORE_ANY_DUE,
            )

        assert raised.value is failure


# ---------------------------------------------------------------------------
# Per-track milestones over persisted rows
# ---------------------------------------------------------------------------


@pytest.fixture
def deadline_world(request: pytest.FixtureRequest) -> DeadlineWorld:
    return DeadlineWorld.from_request(request)


@pytest.mark.integration
class TestTrackMilestones:
    @pytest.mark.parametrize("case", DEADLINE_CASES, ids=lambda case: case.id)
    async def test_milestones_current_phase_and_due_dates(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
        case: DeadlineCase,
    ) -> None:
        """Shared matrix over persisted rows: the tree derives actionability,
        actionable eligible Products, and RR evidence from the rows."""
        persisted = await deadline_world.build(case)

        (package,) = await _read(
            db_session, persisted.ticket, instant=case.evaluation_instant
        )
        (track,) = package.tracks

        assert (
            track.milestones.triage,
            track.milestones.submission,
            track.milestones.um,
            track.milestones.qa,
        ) == case.expected_statuses
        assert track.milestones.current_phase == case.expected_current_phase
        assert track.actionable is case.track_actionable
        due = track.due_dates
        assert (
            None
            if due is None
            else (due.triage, due.submission, due.um, due.qa, due.release)
        ) == case.expected_due_dates()

    def test_every_request_state_is_covered(self) -> None:
        covered = {
            evidence.state
            for case in DEADLINE_CASES
            for evidence in case.requests
            if evidence.action_type is IBSRequestActionType.MAINTENANCE_RELEASE
            and evidence.correlated
        }

        assert covered == set(IBSRequestState)
        assert MATRIX_ACTIVE_STATES == ACTIVE_RELEASE_REQUEST_STATES

    async def test_release_request_evidence_is_scoped_to_its_own_track(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        """An active RR correlated to one track of a package is not `um`
        evidence for a sibling track of the same package."""
        f = deadline_world.factory
        cve = await f("cve_factory")(severity=Severity.HIGH.value)
        ticket: Ticket = await f("ticket_factory")(cve_id=cve.id, created_at=CREATED_AT)
        package = await f("ticket_package_factory")(ticket_id=ticket.id)
        with_rr = await f("ticket_package_track_factory")(
            ticket_package_id=package.id,
            reference="Example:A",
            status=PackageStatus.AFFECTED.value,
        )
        without_rr = await f("ticket_package_track_factory")(
            ticket_package_id=package.id,
            reference="Example:B",
            status=PackageStatus.AFFECTED.value,
        )
        for track in (with_rr, without_rr):
            await f("ticket_package_product_factory")(ticket_package_track_id=track.id)
        request = await f("ibs_request_factory")(state=IBSRequestState.NEW.value)
        action = await f("ibs_request_action_factory")(
            ibs_request_id=request.id, action_type=RELEASE.value
        )
        await f("ibs_request_action_track_factory")(
            ibs_request_action_id=action.id, ticket_package_track_id=with_rr.id
        )

        (projected,) = await _read(db_session, ticket)
        first, second = projected.tracks

        assert first.id == with_rr.id
        assert (first.milestones.um, first.milestones.current_phase) == (
            D,
            CurrentPhase.QA,
        )
        assert (second.milestones.um, second.milestones.current_phase) == (
            P,
            CurrentPhase.SUBMISSION,
        )

    async def test_track_due_dates_equal_for_every_track_including_non_actionable(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.MEDIUM.value, created_at=CREATED_AT
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        actionable = await ticket_package_track_factory(ticket_package_id=package.id)
        await ticket_package_product_factory(ticket_package_track_id=actionable.id)
        await ticket_package_track_factory(
            ticket_package_id=package.id, deleted_at=EXCLUDED_AT
        )

        (projected,) = await _read(db_session, ticket)

        assert [track.due_dates for track in projected.tracks] == [
            _due_dates((9, 54, 63, 90, 90))
        ] * 2

    async def test_one_instant_is_used_for_every_track(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """Every track of one response compares against the one supplied
        instant: exactly at the triage due date, all are `pending`."""
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.HIGH.value, created_at=CREATED_AT
        )
        for name in ("a", "b", "c"):
            package = await ticket_package_factory(
                ticket_id=ticket.id, package_name=name
            )
            track = await ticket_package_track_factory(ticket_package_id=package.id)
            await ticket_package_product_factory(ticket_package_track_id=track.id)

        projected = await _read(db_session, ticket, instant=AT_TRIAGE_DUE)

        assert [p.tracks[0].milestones.triage for p in projected] == [P, P, P]


# ---------------------------------------------------------------------------
# Evaluation date and instant
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvaluationDateAndInstant:
    async def test_actionability_and_lifecycle_use_the_supplied_date(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """The evaluation date alone drives lifecycle and actionability; the
        instant (a later day here, as in a mutation projection crossing
        midnight) drives only milestone comparisons."""
        gs_end = date(2026, 3, 11)
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.HIGH.value, created_at=CREATED_AT
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.ANALYSIS.value
        )
        product = await product_factory(general_support_end_date=gs_end)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        instant = datetime(2026, 3, 14, 0, 0, 1, tzinfo=UTC)

        (on_gs_end,) = await _read(
            db_session, ticket, instant=instant, evaluation_date=gs_end
        )
        (after_gs_end,) = await _read(
            db_session, ticket, instant=instant, evaluation_date=date(2026, 3, 12)
        )

        supported_track = on_gs_end.tracks[0]
        eol_track = after_gs_end.tracks[0]
        assert supported_track.products[0].lifecycle_phase is (
            LifecyclePhase.GENERAL_SUPPORT
        )
        assert (supported_track.actionable, supported_track.milestones.triage) == (
            True,
            O,
        )
        assert eol_track.products[0].lifecycle_phase is LifecyclePhase.EOL
        assert eol_track.products[0].non_actionable_reason is R.EOL
        assert (eol_track.actionable, eol_track.milestones.triage) == (False, NA)


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCanonicalOrdering:
    async def test_every_level_uses_unicode_code_point_order(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """Names are inserted out of order and include case and non-ASCII
        differences that a linguistic collation would order differently."""
        names = ["b-pkg", "é-pkg", "B-pkg", "a-pkg", "Z-pkg", "_pkg"]
        references = ["Example:b", "Example:B", "Example:a", "Example:é", "Example:Z"]
        cpes = [
            "cpe:/o:example:b",
            "cpe:/o:example:B",
            "cpe:/o:example:a",
            "cpe:/o:example:é",
            "cpe:/o:example:Z",
        ]
        ticket: Ticket = await ticket_factory()
        first_package = None
        for name in names:
            package = await ticket_package_factory(
                ticket_id=ticket.id, package_name=name
            )
            first_package = first_package or package
        assert first_package is not None
        first_track = None
        for reference in references:
            track = await ticket_package_track_factory(
                ticket_package_id=first_package.id, reference=reference
            )
            first_track = first_track or track
        assert first_track is not None
        for cpe in cpes:
            product = await product_factory(cpe=cpe)
            await ticket_package_product_factory(
                ticket_package_track_id=first_track.id, product_id=product.id
            )

        projected = await _read(db_session, ticket)

        assert [p.package_name for p in projected] == sorted(names)
        (with_tracks,) = [p for p in projected if p.id == first_package.id]
        assert [t.reference for t in with_tracks.tracks] == sorted(references)
        (with_products,) = [t for t in with_tracks.tracks if t.id == first_track.id]
        assert [p.product_cpe for p in with_products.products] == sorted(cpes)

    def test_each_level_orders_by_c_collation_then_occurrence_uuid(self) -> None:
        """Equal persisted sort keys cannot be created at any level (each is
        unique within its parent), so the UUID tie-breaker is asserted on
        the compiled statement."""
        compiled = str(
            select(ticket_package_tree_column(Ticket.id, date(2026, 3, 11))).compile(
                dialect=postgresql.dialect()  # type: ignore[no-untyped-call]
            )
        )

        for clause in (
            'ORDER BY ticket_package.package_name COLLATE "C", ticket_package.id)',
            'ORDER BY ticket_package_track.reference COLLATE "C", '
            "ticket_package_track.id)",
            'ORDER BY product.cpe COLLATE "C", ticket_package_product.id)',
        ):
            assert clause in compiled


# ---------------------------------------------------------------------------
# Bounded database work
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundedQueries:
    async def _tree(
        self,
        world: DeadlineWorld,
        *,
        packages: int,
        tracks: int,
        products: int,
    ) -> Ticket:
        f = world.factory
        cve = await f("cve_factory")(severity=Severity.HIGH.value)
        ticket: Ticket = await f("ticket_factory")(cve_id=cve.id)
        for p in range(packages):
            package = await f("ticket_package_factory")(
                ticket_id=ticket.id, package_name=f"pkg-{p}"
            )
            for _ in range(tracks):
                track = await f("ticket_package_track_factory")(
                    ticket_package_id=package.id
                )
                request = await f("ibs_request_factory")()
                action = await f("ibs_request_action_factory")(
                    ibs_request_id=request.id, action_type=RELEASE.value
                )
                await f("ibs_request_action_track_factory")(
                    ibs_request_action_id=action.id, ticket_package_track_id=track.id
                )
                for _ in range(products):
                    await f("ticket_package_product_factory")(
                        ticket_package_track_id=track.id
                    )
        return ticket

    async def test_query_count_is_independent_of_tree_cardinality(
        self, db_session: AsyncSession, deadline_world: DeadlineWorld
    ) -> None:
        small = await self._tree(deadline_world, packages=1, tracks=1, products=1)
        large = await self._tree(deadline_world, packages=4, tracks=3, products=3)

        with _StatementRecorder(db_session) as small_recorder:
            small_tree = await _read(db_session, small)
        with _StatementRecorder(db_session) as large_recorder:
            large_tree = await _read(db_session, large)

        assert len(small_recorder.statements) == 1
        assert len(large_recorder.statements) == 1
        assert sum(len(t.products) for p in large_tree for t in p.tracks) == 36
        assert sum(len(t.products) for p in small_tree for t in p.tracks) == 1


# ---------------------------------------------------------------------------
# Composed mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestComposedMode:
    async def test_tree_column_composes_into_a_caller_owned_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """A composing read selects the Ticket by internal UUID with its own
        (here: none) visibility decision; the column adds exactly one value
        per Ticket row and applies no visibility of its own."""
        confidential: Ticket = await ticket_factory(
            is_confidential=True,
            severity_manual=Severity.LOW.value,
            created_at=CREATED_AT,
        )
        other: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=confidential.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        for _ in range(3):
            await ticket_package_product_factory(ticket_package_track_id=track.id)
        await ticket_package_factory(ticket_id=other.id)
        evaluation_date = BEFORE_ANY_DUE.date()

        with _StatementRecorder(db_session) as recorder:
            rows = (
                await db_session.execute(
                    select(
                        Ticket.id,
                        *ticket_tree_context_columns(),
                        ticket_package_tree_column(Ticket.id, evaluation_date).label(
                            "packages"
                        ),
                    ).where(Ticket.id == confidential.id)
                )
            ).all()

        assert len(recorder.statements) == 1
        (row,) = rows
        context = ticket_tree_context_from_row(row)
        assert context == TicketTreeContext(
            created_at=CREATED_AT,
            status=TicketStatus.NEW,
            has_cve=False,
            severity=Severity.LOW,
        )
        projected = assemble_ticket_packages(
            row.packages, ticket=context, evaluation_instant=BEFORE_ANY_DUE
        )
        assert [p.id for p in projected] == [package.id]
        assert len(projected[0].tracks[0].products) == 3
        assert projected[0].tracks[0].due_dates == _due_dates((18, 108, 126, 180, 180))
        assert projected == await _read(db_session, confidential)

    async def test_context_columns_resolve_cve_severity_and_unresolved(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.CRITICAL.value)
        with_cve: Ticket = await ticket_factory(cve_id=cve.id)
        unresolved: Ticket = await ticket_factory()

        rows = (
            await db_session.execute(
                select(Ticket.id, *ticket_tree_context_columns()).where(
                    Ticket.id.in_([with_cve.id, unresolved.id])
                )
            )
        ).all()

        contexts = {row.id: ticket_tree_context_from_row(row) for row in rows}
        assert (contexts[with_cve.id].has_cve, contexts[with_cve.id].severity) == (
            True,
            Severity.CRITICAL,
        )
        assert (
            contexts[unresolved.id].has_cve,
            contexts[unresolved.id].severity,
        ) == (False, None)

    def test_assembly_rejects_naive_instant(self) -> None:
        context = TicketTreeContext(
            created_at=CREATED_AT,
            status=TicketStatus.NEW,
            has_cve=False,
            severity=None,
        )

        with pytest.raises(ValueError, match="evaluation_instant"):
            assemble_ticket_packages(
                [],
                ticket=context,
                evaluation_instant=BEFORE_ANY_DUE.replace(tzinfo=None),
            )


# ---------------------------------------------------------------------------
# Informational only: the read writes nothing
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReadIsSideEffectFree:
    async def test_read_writes_no_row_and_creates_no_event(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        persisted = await deadline_world.build(
            DeadlineCase(
                id="side_effects",
                expected_offsets_days=TIER_30_OFFSETS_DAYS,
                expected_statuses=(D, D, D, O),
                expected_current_phase=CurrentPhase.QA,
                products=(ProductEvidence(eol=True), ProductEvidence()),
                requests=(RequestEvidence(),),
                evaluation_instant=AFTER_ALL_DUE,
            )
        )
        ticket = persisted.ticket
        snapshot = select(
            Ticket.status, Ticket.updated_at, Ticket.priority_auto, Ticket.assignee_id
        ).where(Ticket.id == ticket.id)
        tree_snapshot = (
            select(
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.updated_at,
                TicketPackageProduct.eligible,
                TicketPackageProduct.updated_at,
                TicketPackageProduct.deleted_at,
            )
            .join(
                TicketPackageProduct,
                TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackage.ticket_id == ticket.id)
            .order_by(TicketPackageProduct.id)
        )
        before = (
            (await db_session.execute(snapshot)).one(),
            (await db_session.execute(tree_snapshot)).all(),
        )

        with _StatementRecorder(db_session) as recorder:
            await _read(db_session, ticket, instant=AFTER_ALL_DUE)

        after = (
            (await db_session.execute(snapshot)).one(),
            (await db_session.execute(tree_snapshot)).all(),
        )
        events = await db_session.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        )
        assert after == before
        assert events == 0
        assert not db_session.new
        assert not db_session.dirty
        assert all(s.lstrip().upper().startswith("SELECT") for s in recorder.statements)


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (testing-strategy.md, Concurrency Testing:
    committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.product_ids: list[uuid.UUID] = []

    async def user(self, *, role: Role | None = None) -> User:
        user = User(
            username=f"fictional.tree.{uuid.uuid4().hex[:10]}",
            email=f"tree.{uuid.uuid4().hex[:10]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket_with_tree(
        self, *, is_confidential: bool, maintainer: User | None = None
    ) -> tuple[Ticket, TicketPackage, TicketPackageTrack]:
        ticket = Ticket(is_confidential=is_confidential)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-race")
        self.session.add(package)
        await self.session.flush()
        if maintainer is not None:
            self.session.add(
                TicketPackageMaintainer(
                    ticket_package_id=package.id, user_id=maintainer.id
                )
            )
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type=WorkflowType.IBS.value,
            reference="Example:Codestream:Race:Update",
        )
        self.session.add(track)
        await self.session.flush()
        await self.product_occurrence(track)
        await self.session.commit()
        return ticket, package, track

    async def product_occurrence(self, track: TicketPackageTrack) -> None:
        product = Product(
            name="Race Product",
            version="1",
            display_name="Race Product 1",
            cpe=f"cpe:/o:example:race:{uuid.uuid4().hex}",
            catalog_last_seen_at=datetime.now(UTC),
        )
        self.session.add(product)
        await self.session.flush()
        self.product_ids.append(product.id)
        self.session.add(
            TicketPackageProduct(
                ticket_package_track_id=track.id, product_id=product.id
            )
        )
        await self.session.flush()

    async def cleanup(self) -> None:
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        for statement in (
            delete(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(tracks)
            ),
            delete(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(Product).where(Product.id.in_(self.product_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


async def _tree_read(
    session: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> tuple[PackageProjection, ...]:
    return await get_ticket_packages(
        session,
        ticket_id=_sntl(ticket),
        caller=caller,
        evaluation_date=BEFORE_ANY_DUE.date(),
        evaluation_instant=BEFORE_ANY_DUE,
    )


@pytest.mark.integration
class TestTreeReadRaces:
    """Session R performs a preliminary SNTL resolution and a first tree
    read, session W then commits a change, and R reads again. The steps run
    in a fixed order on independent connections, so the interleaving is
    deterministic. The read is one statement, so R observes either the
    complete post-change tree or 404, never a tree assembled from a stale
    access decision or from mixed views."""

    async def test_confidentiality_set_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket, _, _ = await committed_world.ticket_with_tree(is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert len(await _tree_read(reader, ticket, caller)) == 1
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )

        with pytest.raises(TicketNotFoundError):
            await _tree_read(reader, ticket, caller)

    async def test_grant_revoked_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, _ = await committed_world.ticket_with_tree(is_confidential=True)
        committed_world.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await committed_world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert len(await _tree_read(reader, ticket, caller)) == 1
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        with pytest.raises(TicketNotFoundError):
            await _tree_read(reader, ticket, caller)

    async def test_last_maintained_package_excluded_together_with_tree_change(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """W atomically excludes the caller's last maintained package and
        changes the track: R must not return the post-change tree."""
        user = await committed_world.user()
        ticket, package, track = await committed_world.ticket_with_tree(
            is_confidential=True, maintainer=user
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        (before,) = await _tree_read(reader, ticket, caller)
        assert before.deleted_at is None
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(status=PackageStatus.NOT_AFFECTED.value),
        )

        with pytest.raises(TicketNotFoundError):
            await _tree_read(reader, ticket, caller)

    async def test_visibility_acquired_with_tree_change_is_observed_whole(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, track = await committed_world.ticket_with_tree(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        with pytest.raises(TicketNotFoundError):
            await _tree_read(reader, ticket, caller)
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await writer.execute(
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=DeliveryStatus.IN_PROGRESS.value)
        )
        await writer.commit()

        (package,) = await _tree_read(reader, ticket, caller)
        assert package.tracks[0].delivery_status is DeliveryStatus.IN_PROGRESS

    async def test_committed_tree_changes_are_observed_entirely(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """A multi-level change committed between reads is observed at
        every level at once."""
        ticket, package, track = await committed_world.ticket_with_tree(
            is_confidential=False
        )
        reader = await db_session_factory()
        writer = await db_session_factory()

        (before,) = await _tree_read(reader, ticket, ANONYMOUS_CALLER)
        excluded_at = datetime.now(UTC)
        await _commit(
            writer,
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(deleted_at=excluded_at, status=PackageStatus.FIXED.value),
            update(TicketPackageProduct)
            .where(TicketPackageProduct.ticket_package_track_id == track.id)
            .values(released_at=excluded_at),
        )
        (after,) = await _tree_read(reader, ticket, ANONYMOUS_CALLER)

        assert (before.tracks[0].actionable, before.tracks[0].status) == (
            True,
            PackageStatus.ANALYSIS,
        )
        assert before.tracks[0].products[0].released_at is None
        assert (after.tracks[0].actionable, after.tracks[0].status) == (
            False,
            PackageStatus.FIXED,
        )
        assert after.tracks[0].products[0].released_at is not None
        assert after.actionable is False
        assert package.id == after.id

    async def test_role_removed_after_caller_resolution_does_not_change_the_read(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """The service consumes the request-resolved caller and never reloads
        roles: a committed role removal applies only to the next caller
        resolution."""
        user = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, _, _ = await committed_world.ticket_with_tree(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        in_flight = TicketCaller.authenticated(user.id, Scope.ALL)

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))

        assert len(await _tree_read(reader, ticket, in_flight)) == 1
        with pytest.raises(TicketNotFoundError):
            await _tree_read(
                reader,
                ticket,
                TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            )


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPackageServiceModuleBoundary:
    def test_imports_no_higher_level_ticket_service(self) -> None:
        """`package_service` never imports `ticket_service`
        (package-service.md, Relationship with other modules)."""
        modules = imported_modules(
            APP_ROOT / "services" / "package_service.py", "app.services"
        )

        assert "app.services.ticket_service" not in modules
        assert "app.models.ticket_package_maintainer" not in modules
        assert "app.models.user" not in modules

    def test_implemented_coroutines(self) -> None:
        """The public operations implemented so far; private helpers are
        implementation details and are not part of the inventory."""
        coroutines = {
            name
            for name, member in inspect.getmembers(package_service, inspect.isfunction)
            if member.__module__ == package_service.__name__
            and inspect.iscoroutinefunction(member)
            and not name.startswith("_")
        }

        assert coroutines == {
            "get_ticket_packages",
            "search_packages",
            "converge_manual_zone_exit_eligibility",
            "set_track_status",
            "set_product_eligibility",
            "soft_delete_ticket_package",
            "soft_delete_ticket_package_track",
            "soft_delete_ticket_package_product",
            "restore_ticket_package",
            "restore_ticket_package_track",
            "restore_ticket_package_product",
        }

    def test_uses_no_private_ticket_mutations_helper(self) -> None:
        """The manual-zone-exit convergence is package-owned; it neither
        calls the CVSS chain's inline propagation helper nor imports any
        private `ticket_mutations` name (ticket-service.md, Manual-Zone
        Exit Operations; package-service.md, Synchronous manual-zone-exit
        eligibility convergence)."""
        tree = _package_service_tree()
        referenced = {
            node.attr if isinstance(node, ast.Attribute) else node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute | ast.Name)
        }
        private_imports = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "app.services.ticket_mutations"
            for alias in node.names
            if alias.name.startswith("_")
        ]
        private_attributes = [
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "ticket_mutations"
            and node.attr.startswith("_")
        ]

        assert "_propagate_automatic_product_eligibility" not in referenced
        assert (private_imports, private_attributes) == ([], [])

    def test_calls_the_shared_evaluator_with_exactly_its_four_inputs(self) -> None:
        """package-model.md, Axis 2: Eligibility: one shared pure evaluator,
        fed only the override marker, lifecycle phase, Product threshold,
        and Eligibility Score Resolution."""
        calls = [
            node
            for node in ast.walk(_package_service_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "evaluate_product_eligibility"
        ]

        assert len(calls) >= 1
        for call in calls:
            assert call.args == []
            assert {k.arg for k in call.keywords} == {
                "is_eligible_override",
                "lifecycle_phase",
                "cvss_threshold",
                "eligibility_score",
            }


def _package_service_tree() -> ast.Module:
    path = APP_ROOT / "services" / "package_service.py"
    return ast.parse(path.read_text(encoding="utf-8"))
