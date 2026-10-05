"""Independent-session races between the real `deactivate_user()`
(backend/app/services/user_service.py) and the assignment-capable Ticket,
CVSS, and package paths.

Owning specifications:

- docs/features/identity/user-service.md (`deactivate_user()`, including
  Concurrency: deactivation / Ticket assignment; Private Helpers:
  `_unassign_active_tickets()`; Concurrency Considerations: Assignment
  concurrent with deactivation or active manual role loss).
- docs/features/identity/rbac.md (Business Rules 10-12: assignment target
  constraint, auto-assignment, and embedded assignment skip an inactive
  actor).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary: `user deactivated`; Canonical Mutation and No-Event Matrix:
  "User deactivation, final VA-role loss, or assignment-eligibility
  sanitation"; Testing Requirements 19 and 23).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: every assignment-capable path acquires User `FOR SHARE`
  before CVE/Ticket locks, in assignment-first and deactivation-first
  commit orders; Deactivation concurrency; Concurrency Testing, Lock-Wait
  Observation).
- The counterparts' owning contracts: docs/features/tickets/ticket-service.md
  (Concurrency control; `create_ticket`; `assign_ticket`;
  `set_priority_override`; `reopen_from_ignored()`),
  docs/features/tickets/ticket-mutations.md (`set_severity_manual()`;
  Auto-Assignment Rule; `auto_assign_actor()`), and
  docs/features/packages/package-service.md (Auto-Assignment Rule;
  `set_track_status()`).

The matrix takes one representative per assignment category and owning
service, each in both commit orders (twelve cases), as the final VA-origin
loss matrix of `test_va_role_loss_assignment_races.py`:

| Category | Representative | Owner |
|---|---|---|
| explicit | `assign_ticket()` (target is deactivated) | `ticket_service` |
| creation | manual `create_ticket()` | `ticket_service` |
| auto-assignment | `set_priority_override()` | `ticket_service` |
| auto-assignment | `set_severity_manual()` | `ticket_mutations` |
| auto-assignment | `set_track_status()` | `package_service` |
| embedded | `reopen_from_ignored()` (`force=True`) | `ticket_service` |

The lifecycle writer is always the real `deactivate_user()` of the target by
an administrator, never a simulated lock. In the assignment-first order the
assignment path holds its uncommitted assignment and the User `FOR SHARE` in
session A; the deactivation in session B is proven to wait on A with the
User `FOR NO KEY UPDATE` as its only statement, and after both commit the
deactivation has cleared the assignment with exactly one system
`assignment` event whose fixed reason is `user deactivated` (the
caller-supplied reason is never copied into it). In the deactivation-first
order B's uncommitted deactivation, which finds nothing to clear, holds the
User lock; A is proven to wait on B at its User `FOR SHARE` before touching
any CVE or Ticket row, and after B commits A decides from the committed
inactive User: explicit assignment raises `AssigneeInactiveError`
(`TICKET_ASSIGNEE_INACTIVE`) with no write, and every other path, whose
acting user is the deactivated User, skips the assignment without an
`assignment` event while keeping its ordinary effects. That acting user
authenticated before the deactivation committed; the services decide from
the locked-current User (`auto_assign_actor()` step 3; `create_ticket`
assigns only an active VA creator).

Every case also asserts the committed deactivation: `User.active` is
false, the VA origin is retained, and the Identity trail holds exactly one
`user_deactivated` attributed to the administrator with the reason.

Committed state is always read through a fresh independent session.
Committed rows, including service-created Tickets, the Identity events, and
the committed `default_cvss_version` setting, are deleted explicitly at
teardown (testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, TicketStatus
from app.services.ticket_service import AssigneeInactiveError
from app.services.user_service import DeactivationResult
from tests.support.assignment_lifecycle_races import (
    GATE,
    PROMOTION,
    REOPENED,
    Actors,
    CommittedRace,
    Factory,
    Path,
    RaceWorld,
    assign_path,
    assignment_event,
    assignment_first,
    committed_track_status,
    create_path,
    lifecycle_first,
    open_track_ticket,
    other_va,
    override_path,
    override_set_event,
    race_actors,
    race_world,
    read_committed,
    reopen_path,
    severity_path,
    severity_set_event,
    track_changed_event,
    track_status_path,
)
from tests.support.cvss_chain import priority_event
from tests.support.identity_lifecycle_races import (
    MANUAL,
    USER_DEACTIVATED,
    deactivate,
    user_deactivated,
)
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import EventRow, unassigned_event

REASON = "fictional offboarding"
"""The caller-supplied deactivation reason (Identity context only)."""
VA_STORED = "Vulnerability Analyst"
"""The stored `UserRole.role` value of `vulnerability_analyst`
(data-model.md, UserRole; conventions.md, Enum Storage Strategy)."""


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RaceWorld]:
    async with race_world(db_session_factory) as created:
        yield created


# ---------------------------------------------------------------------------
# The lifecycle writer: deactivate_user()
# ---------------------------------------------------------------------------


def _deactivation(
    actors: Actors,
) -> Callable[[AsyncSession], Awaitable[DeactivationResult]]:
    """The real `deactivate_user()` of the target by the admin."""

    def run(session: AsyncSession) -> Awaitable[DeactivationResult]:
        return deactivate(session, actors.target, REASON, actors.admin)

    return run


async def _assignment_first(world: RaceWorld, actors: Actors, path: Path) -> uuid.UUID:
    """`assignment_first()` with the real deactivation as B, which performs
    the transition. Returns the Ticket UUID of `path`."""
    ticket_id, result = await assignment_first(world, path, _deactivation(actors))
    assert result.deactivated is True
    return ticket_id


async def _deactivation_first(
    world: RaceWorld,
    actors: Actors,
    path: Path,
    *,
    error: type[Exception] | None = None,
) -> uuid.UUID | None:
    """`lifecycle_first()` with the real deactivation as B, which performs
    the transition. Returns the Ticket UUID of `path`, or `None` when it
    raised `error`."""
    ticket_id, result = await lifecycle_first(
        world, path, _deactivation(actors), error=error
    )
    assert result.deactivated is True
    return ticket_id


def _assert_deactivated(committed: CommittedRace, actors: Actors) -> None:
    """The committed deactivation: the target is inactive, keeps its VA
    origin, and its Identity trail holds exactly one `user_deactivated`
    attributed to the admin, with the reason and no `source`."""
    assert committed.active is False
    assert committed.origins == {(VA_STORED, MANUAL)}
    assert committed.identity == [user_deactivated(actors.admin, actors.target, REASON)]


def _cleared(actors: Actors) -> EventRow:
    """The deactivation's system unassignment of the target."""
    return unassigned_event(actors.target.username, USER_DEACTIVATED)


# ---------------------------------------------------------------------------
# Explicit assignment: assign_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitAssignment:
    """Another VA assigns an unassigned CVE-less `New` Ticket to the User
    who is deactivated (ticket-service.md, `assign_ticket`: target User
    `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(
            world, actors, assign_path(ticket, actors.target, assigner)
        )

        committed = await read_committed(world, actors, ticket.id)
        # The clear leaves the status unchanged.
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            assignment_event(assigner, None, actors.target),
            PROMOTION,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_raises_the_inactive_target_error(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _deactivation_first(
            world,
            actors,
            assign_path(ticket, actors.target, assigner),
            error=AssigneeInactiveError,
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == []
        assert committed.unassignments == []
        _assert_deactivated(committed, actors)


# ---------------------------------------------------------------------------
# Creation assignment: manual create_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreationAssignment:
    """The User who is deactivated manually creates a CVE-less Ticket
    without severity (ticket-service.md, `create_ticket` steps 1 and 4-6:
    creator `FOR SHARE`, then INSERT; `Analysis` assigned only to an active
    VA creator; no automatic priority)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)

        ticket_id = await _assignment_first(world, actors, create_path(actors.target))

        committed = await read_committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            *creation_events(
                creator_id=actors.target.id, assignee_username=actors.target.username
            ),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket_id]
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_creates_new_and_unassigned(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)

        ticket_id = await _deactivation_first(world, actors, create_path(actors.target))

        assert ticket_id is not None
        committed = await read_committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == creation_events(creator_id=actors.target.id)
        assert committed.unassignments == []
        _assert_deactivated(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_service): set_priority_override()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPriorityOverrideAutoAssignment:
    """The User who is deactivated sets a `P1` override on an unassigned
    CVE-less `New` Ticket without severity (ticket-priority.md,
    `set_priority_override()`: acting User `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(world, actors, override_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, "P1", None)
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            PROMOTION,
            override_set_event(actors.target),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_sets_the_override_without_assignment(
        self, world: RaceWorld
    ) -> None:
        """No assignment, hence no promotion: the Ticket stays `New`
        (reconciliation never leaves `New`)."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _deactivation_first(world, actors, override_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, "P1", None)
        assert committed.events == [override_set_event(actors.target)]
        assert committed.unassignments == []
        _assert_deactivated(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_mutations): set_severity_manual()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSeverityAutoAssignment:
    """The User who is deactivated sets `High` on an unassigned CVE-less
    `Analysis` Ticket without severity or packages (ticket-mutations.md,
    `set_severity_manual()`: acting User `FOR SHARE`, then Ticket; the
    refresh moves `priority_auto` to `P3`; no gate change)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None)

        await _assignment_first(world, actors, severity_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            severity_set_event(actors.target),
            priority_event(None, "P3"),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_sets_the_severity_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None)

        await _deactivation_first(world, actors, severity_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            severity_set_event(actors.target),
            priority_event(None, "P3"),
        ]
        assert committed.unassignments == []
        _assert_deactivated(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (package_service): set_track_status()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTrackStatusAutoAssignment:
    """The User who is deactivated sets the only track `AFFECTED`
    (package-service.md, `set_track_status()`: acting User `FOR SHARE`,
    then Ticket; the gate result becomes `Analyzed`)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _assignment_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        # The deactivation clears the assignee only: `Analyzed` remains.
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            track_changed_event(track, actors.target),
            GATE,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_changes_the_track_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _deactivation_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [track_changed_event(track, actors.target), GATE]
        assert committed.unassignments == []
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_deactivated(committed, actors)


# ---------------------------------------------------------------------------
# Embedded assignment: reopen_from_ignored()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReopenEmbeddedAssignment:
    """The User who is deactivated reopens a CVE-less `Ignored` Ticket
    without severity or packages that is assigned to another active VA
    (ticket-service.md, `reopen_from_ignored()`: acting User `FOR SHARE`,
    then Ticket; `auto_assign_actor(force=True)` takes ownership only for an
    eligible actor, so a skip keeps the other assignee, whom sanitation
    retains as an active VA)."""

    async def test_assignment_first_is_cleared_by_the_deactivation(
        self, world: RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await race_actors(world)
        previous = await other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _assignment_first(world, actors, reopen_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            assignment_event(actors.target, previous, actors.target),
            REOPENED,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_deactivated(committed, actors)

    async def test_deactivation_first_reopens_and_keeps_the_previous_assignee(
        self, world: RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await race_actors(world)
        previous = await other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _deactivation_first(world, actors, reopen_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (
            TicketStatus.ANALYSIS,
            previous.id,
            None,
            None,
            None,
        )
        assert committed.events == [REOPENED]
        assert committed.unassignments == []
        _assert_deactivated(committed, actors)
