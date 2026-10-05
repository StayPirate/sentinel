"""Independent-session races between the real final manual
`vulnerability_analyst` origin loss (`update_roles()`,
backend/app/services/user_service.py) and the assignment-capable Ticket,
CVSS, and package paths.

Owning specifications:

- docs/features/identity/user-service.md (Concurrency Considerations:
  Assignment concurrent with deactivation or active manual role loss;
  `update_roles()`; Private Helpers).
- docs/features/identity/rbac.md (Business Rule 10, Assignment target
  constraint: prospective and retroactive enforcement).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary; Canonical Mutation and No-Event Matrix; Cross-Event Ordering,
  Locking, and Rollback; Testing Requirements 19 and 23).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: every assignment-capable path acquires User `FOR SHARE`
  before CVE/Ticket locks; final VA-origin removal concurrent with
  assignment; Concurrency Testing, Lock-Wait Observation).
- The counterparts' owning contracts: docs/features/tickets/ticket-service.md
  (Concurrency control; `create_ticket`; `assign_ticket`;
  `set_priority_override`; `reopen_from_ignored()`),
  docs/features/tickets/ticket-priority.md (`set_priority_override()`),
  docs/features/tickets/ticket-mutations.md (`set_severity_manual()`;
  Auto-Assignment Rule; `auto_assign_actor()`), and
  docs/features/packages/package-service.md (Auto-Assignment Rule;
  `set_track_status()`).

The matrix takes one representative per assignment category and owning
service, each in both commit orders (twelve cases):

| Category | Representative | Owner |
|---|---|---|
| explicit | `assign_ticket()` (target loses VA) | `ticket_service` |
| creation | manual `create_ticket()` | `ticket_service` |
| auto-assignment | `set_priority_override()` | `ticket_service` |
| auto-assignment | `set_severity_manual()` | `ticket_mutations` |
| auto-assignment | `set_track_status()` | `package_service` |
| embedded | `reopen_from_ignored()` (`force=True`) | `ticket_service` |

The lifecycle writer is always the real `update_roles()` removing the
User's only (`_manual`) VA origin, never a simulated lock. In the
assignment-first order the assignment path holds its uncommitted
assignment and the User `FOR SHARE` in session A; the role loss in session
B is proven to wait on A with the User lock as its only statement, and
after both commit the lifecycle batch has cleared the assignment with
exactly one system event. In the role-loss-first order B's uncommitted
role loss, which finds nothing to clear, holds the User
`FOR NO KEY UPDATE`; A is proven to wait on B at its User `FOR SHARE`
before touching any CVE or Ticket row, and after B commits A decides from
the committed ineligible User: explicit assignment raises its existing
target error with no write, and every other path skips the assignment
without an `assignment` event while keeping its ordinary effects.

Committed state is always read through a fresh independent session.
Committed rows, including service-created Tickets and the committed
`default_cvss_version` setting, are deleted explicitly at teardown
(testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketPriority,
    TicketStatus,
)
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.ticket_mutations import set_severity_manual
from app.services.ticket_service import (
    AssigneeNotVAError,
    TicketCreationSource,
    assign_ticket,
    create_ticket,
    reopen_from_ignored,
    set_priority_override,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import priority_event, ticket_state
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    VA_ROLE_REMOVED,
    IdentityEventRow,
    IdentityWorld,
    identity_events,
    origins,
    remove_roles,
    role_removed,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
    unassigned_event,
)
from tests.support.track_status import set_status

Factory = Callable[[], Awaitable[AsyncSession]]
Path = Callable[[AsyncSession], Awaitable[uuid.UUID]]
"""One assignment-capable call in a racing session, returning the UUID of
the Ticket it acted on (or created)."""

ROOT_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) (?:ticket|cve)\b")
DEFAULT_VERSION = "3.1"
PACKAGE_NAME = "fictional-role-loss-race"
VA_WIRE = "vulnerability_analyst"
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class _RaceWorld(IdentityWorld):
    """An `IdentityWorld` that also deletes the Tickets created by the code
    under test (found by assignee and by acting-user event, so that a
    failing assertion cannot leak rows) and owns the committed
    `default_cvss_version` setting when it had to create it."""

    def __init__(self, factory: Factory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self._owns_setting = False

    async def ensure_default_setting(self) -> None:
        """The committed setting read by the manual-zone-exit eligibility
        boundary (the test schema has none)."""
        setting = await self.session.get(SystemSetting, "default_cvss_version")
        if setting is None:
            self.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            self._owns_setting = True
        else:
            assert setting.value == DEFAULT_VERSION
        await self.session.commit()

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        created = (
            await self.session.scalars(
                select(Ticket.id).where(
                    or_(
                        Ticket.assignee_id.in_(self.user_ids),
                        Ticket.id.in_(
                            select(TicketAuditEvent.ticket_id).where(
                                TicketAuditEvent.user_id.in_(self.user_ids)
                            )
                        ),
                    )
                )
            )
        ).all()
        self.ticket_ids.extend(set(created) - set(self.ticket_ids))
        await self.session.rollback()
        try:
            await super().cleanup()
        finally:
            if self._owns_setting:
                await self.session.execute(
                    delete(SystemSetting).where(
                        SystemSetting.key == "default_cvss_version"
                    )
                )
                await self.session.commit()


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[_RaceWorld]:
    created = _RaceWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass(frozen=True, slots=True)
class _Actors:
    admin: User
    """The administrator removing the role (the `role_removed` actor)."""
    target: User
    """The User whose only VA origin is `_manual`, and who loses it."""


async def _actors(world: _RaceWorld) -> _Actors:
    return _Actors(
        admin=await world.identity_user(manual=[Role.ADMIN], prefix="alice.admin"),
        target=await world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST], prefix="bob.va"
        ),
    )


async def _other_va(world: _RaceWorld, prefix: str) -> User:
    return await world.identity_user(manual=[Role.VULNERABILITY_ANALYST], prefix=prefix)


# ---------------------------------------------------------------------------
# Race drivers
# ---------------------------------------------------------------------------


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _is_user_lock(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR NO KEY UPDATE" in statement


def _ticket_writes(writes: list[str]) -> list[str]:
    """The writes to `ticket` or `ticket_audit_event`."""
    return [w for w in writes if "ticket" in w]


async def _assignment_first(
    world: _RaceWorld, actors: _Actors, path: Path
) -> uuid.UUID:
    """A runs `path` and keeps it uncommitted (holding the User `FOR SHARE`);
    B's real final VA-origin removal is proven to wait on A with the User
    lock as its first and only statement; A commits, then B completes and
    commits. Returns the Ticket UUID of `path`."""
    a = await world.open_session()
    b = await world.open_session()

    ticket_id = await path(a)
    world.ticket_ids.append(ticket_id)
    with SessionStatementRecorder(b) as recorder:
        task = world.start(
            b,
            remove_roles(b, actors.target, [Role.VULNERABILITY_ANALYST], actors.admin),
        )
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        waiting = list(recorder.statements)
        assert len(waiting) == 1
        assert _is_user_lock(waiting[0])
        await a.commit()
        removal = await asyncio.wait_for(task, timeout=WAIT)
    await b.commit()

    assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
    # The batch cleared exactly the one committed assignment.
    assert len([w for w in recorder.writes() if "UPDATE ticket " in w]) == 1
    return ticket_id


async def _role_loss_first(
    world: _RaceWorld,
    actors: _Actors,
    path: Path,
    *,
    error: type[Exception] | None = None,
) -> uuid.UUID | None:
    """B's real final VA-origin removal runs first and stays uncommitted
    (holding the User `FOR NO KEY UPDATE`); it finds nothing to clear. A
    runs `path` and is proven to wait on B at its User `FOR SHARE`, before
    any CVE or Ticket statement; B commits, then A completes and commits.
    With `error`, A must raise it with no write and roll back. Returns the
    Ticket UUID of `path`, or `None` when it raised."""
    a = await world.open_session()
    b = await world.open_session()

    with SessionStatementRecorder(b) as removal_recorder:
        removal = await remove_roles(
            b, actors.target, [Role.VULNERABILITY_ANALYST], actors.admin
        )
    assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
    assert _ticket_writes(removal_recorder.writes()) == []

    with SessionStatementRecorder(a) as recorder:
        task = world.start(a, path(a))
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        waiting = list(recorder.statements)
        assert _is_user_share(waiting[-1])
        assert [s for s in waiting if ROOT_STATEMENT.search(s)] == []
        await b.commit()
        if error is not None:
            with pytest.raises(error):
                await asyncio.wait_for(task, timeout=WAIT)
            assert recorder.writes() == []
            await a.rollback()
            return None
        ticket_id: uuid.UUID = await asyncio.wait_for(task, timeout=WAIT)

    world.ticket_ids.append(ticket_id)
    await a.commit()
    return ticket_id


# ---------------------------------------------------------------------------
# Committed observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Committed:
    ticket: tuple[Any, ...]
    """`(status, assignee_id, priority_auto, priority_override,
    severity_manual)`."""
    events: list[EventRow]
    unassignments: list[uuid.UUID]
    """The Tickets of every committed system unassignment of the target."""
    origins: set[tuple[str, str]]
    identity: list[IdentityEventRow]


async def _committed(
    world: _RaceWorld, actors: _Actors, ticket_id: uuid.UUID
) -> _Committed:
    """The committed Ticket state and history, every system unassignment
    event of the target on any Ticket, and the target's role origins and
    Identity trail, read through a fresh independent session."""
    probe = await world.open_session()
    target = actors.target
    unassignments = (
        await probe.scalars(
            select(TicketAuditEvent.ticket_id)
            .where(
                TicketAuditEvent.event_type == "assignment",
                TicketAuditEvent.user_id.is_(None),
                TicketAuditEvent.old_value == target.username,
            )
            .order_by(TicketAuditEvent.id)
        )
    ).all()
    committed = _Committed(
        ticket=await ticket_state(probe, ticket_id),
        events=await ticket_events_by_id(probe, ticket_id),
        unassignments=list(unassignments),
        origins=await origins(probe, target.id),
        identity=await identity_events(probe, target.id),
    )
    await probe.rollback()
    return committed


def _assert_role_lost(committed: _Committed, actors: _Actors) -> None:
    """The committed final manual VA-origin loss: no origin remains and the
    Identity trail holds exactly one `role_removed`."""
    assert committed.origins == set()
    assert committed.identity == [role_removed(actors.admin, actors.target, VA_WIRE)]


def _cleared(actors: _Actors) -> EventRow:
    """The lifecycle batch's system unassignment of the target."""
    return unassigned_event(actors.target.username, VA_ROLE_REMOVED)


def _assignment(actor: User, old: User | None, new: User) -> EventRow:
    """An acting-user `assignment` event."""
    return EventRow(
        "assignment",
        actor.id,
        old.username if old is not None else None,
        new.username,
        None,
        None,
    )


def _caller(actor: User) -> TicketCaller:
    return TicketCaller.authenticated(actor.id, Scope.ALL)


PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of an assignment."""


# ---------------------------------------------------------------------------
# Explicit assignment: assign_ticket()
# ---------------------------------------------------------------------------


def _assign(ticket: Ticket, target: User, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await assign_ticket(
            session,
            ticket_id=ticket.id,
            assignee=str(target.id),
            acting_user_id=actor.id,
            caller=_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


@pytest.mark.integration
class TestExplicitAssignment:
    """Another VA assigns an unassigned CVE-less `New` Ticket to the User
    who loses the role (ticket-service.md, `assign_ticket`: target User
    `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        assigner = await _other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(world, actors, _assign(ticket, actors.target, assigner))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            _assignment(assigner, None, actors.target),
            PROMOTION,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_raises_the_target_error_without_effect(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        assigner = await _other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _role_loss_first(
            world,
            actors,
            _assign(ticket, actors.target, assigner),
            error=AssigneeNotVAError,
        )

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == []
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Creation assignment: manual create_ticket()
# ---------------------------------------------------------------------------


def _create(creator: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        ticket = await create_ticket(
            session,
            acting_user_id=creator.id,
            source=TicketCreationSource.MANUAL,
        )
        return ticket.id

    return run


@pytest.mark.integration
class TestCreationAssignment:
    """The User who loses the role manually creates a CVE-less Ticket
    without severity (ticket-service.md, `create_ticket` steps 1 and 4-6:
    creator `FOR SHARE`, then INSERT; no automatic priority)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)

        ticket_id = await _assignment_first(world, actors, _create(actors.target))

        committed = await _committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            *creation_events(
                creator_id=actors.target.id, assignee_username=actors.target.username
            ),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket_id]
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_creates_new_and_unassigned(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)

        ticket_id = await _role_loss_first(world, actors, _create(actors.target))

        assert ticket_id is not None
        committed = await _committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == creation_events(creator_id=actors.target.id)
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_service): set_priority_override()
# ---------------------------------------------------------------------------


def _override(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_priority_override(
            session,
            ticket_id=ticket.id,
            priority=TicketPriority.P1,
            acting_user_id=actor.id,
            caller=_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


def _override_set(actor: User) -> EventRow:
    """The acting-user `priority_changed` of setting `P1` without a prior
    override or automatic priority."""
    return EventRow(
        "priority_changed", actor.id, None, "P1", None, {"override_action": "set"}
    )


@pytest.mark.integration
class TestPriorityOverrideAutoAssignment:
    """The User who loses the role sets a `P1` override on an unassigned
    CVE-less `New` Ticket without severity (ticket-priority.md,
    `set_priority_override()`: acting User `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(world, actors, _override(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, "P1", None)
        assert committed.events == [
            _assignment(actors.target, None, actors.target),
            PROMOTION,
            _override_set(actors.target),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_sets_the_override_without_assignment(
        self, world: _RaceWorld
    ) -> None:
        """No assignment, hence no promotion: the Ticket stays `New`
        (reconciliation never leaves `New`)."""
        actors = await _actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _role_loss_first(world, actors, _override(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, "P1", None)
        assert committed.events == [_override_set(actors.target)]
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_mutations): set_severity_manual()
# ---------------------------------------------------------------------------


def _severity(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_severity_manual(
            session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=actor.id,
            caller=_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


def _severity_set(actor: User) -> EventRow:
    """The acting-user `severity_changed` from SQL `NULL` to `High`."""
    return EventRow("severity_changed", actor.id, None, "High", None, None)


@pytest.mark.integration
class TestSeverityAutoAssignment:
    """The User who loses the role sets `High` on an unassigned CVE-less
    `Analysis` Ticket without severity or packages (ticket-mutations.md,
    `set_severity_manual()`: acting User `FOR SHARE`, then Ticket; the
    refresh moves `priority_auto` to `P3`; no gate change)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        ticket = await world.ticket(cve_id=None)

        await _assignment_first(world, actors, _severity(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            _assignment(actors.target, None, actors.target),
            _severity_set(actors.target),
            priority_event(None, "P3"),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_sets_the_severity_without_assignment(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        ticket = await world.ticket(cve_id=None)

        await _role_loss_first(world, actors, _severity(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            _severity_set(actors.target),
            priority_event(None, "P3"),
        ]
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (package_service): set_track_status()
# ---------------------------------------------------------------------------


async def _open_ticket(world: _RaceWorld) -> tuple[Ticket, TicketPackageTrack]:
    """A committed unassigned CVE-less `High` `Analysis` Ticket with one
    `ANALYSIS` track and one eligible in-support Product: `AFFECTED` makes
    its gate result `Analyzed` (tickets.md gates)."""
    ticket = await world.ticket(cve_id=None, severity_manual=Severity.HIGH)
    session = world.session
    package = TicketPackage(ticket_id=ticket.id, package_name=PACKAGE_NAME)
    session.add(package)
    await session.flush()
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=AFTER_EVAL,
    )
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=PackageStatus.ANALYSIS.value,
    )
    session.add_all([product, track])
    await session.flush()
    world.product_ids.append(product.id)
    session.add(
        TicketPackageProduct(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
    )
    await session.commit()
    return ticket, track


def _track_status(ticket: Ticket, track: TicketPackageTrack, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_status(
            session, track, PackageStatus.AFFECTED, actor, ticket_id=ticket.id
        )
        return ticket.id

    return run


def _track_changed(track: TicketPackageTrack, actor: User) -> EventRow:
    """The acting-user `track_status_changed` `ANALYSIS -> AFFECTED`."""
    return EventRow(
        "track_status_changed",
        actor.id,
        PackageStatus.ANALYSIS.value,
        PackageStatus.AFFECTED.value,
        None,
        {"track": track.reference, "package": PACKAGE_NAME},
    )


async def _committed_track_status(world: _RaceWorld, track: TicketPackageTrack) -> str:
    probe = await world.open_session()
    status = (
        await probe.execute(
            select(TicketPackageTrack.status).where(TicketPackageTrack.id == track.id)
        )
    ).scalar_one()
    await probe.rollback()
    return status


GATE = status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value)
"""The final system gate event `Analysis -> Analyzed`."""


@pytest.mark.integration
class TestTrackStatusAutoAssignment:
    """The User who loses the role sets the only track `AFFECTED`
    (package-service.md, `set_track_status()`: acting User `FOR SHARE`,
    then Ticket; the gate result becomes `Analyzed`)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        ticket, track = await _open_ticket(world)

        await _assignment_first(
            world, actors, _track_status(ticket, track, actors.target)
        )

        committed = await _committed(world, actors, ticket.id)
        # The lifecycle batch clears the assignee only: `Analyzed` remains.
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [
            _assignment(actors.target, None, actors.target),
            _track_changed(track, actors.target),
            GATE,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        assert await _committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_changes_the_track_without_assignment(
        self, world: _RaceWorld
    ) -> None:
        actors = await _actors(world)
        ticket, track = await _open_ticket(world)

        await _role_loss_first(
            world, actors, _track_status(ticket, track, actors.target)
        )

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [_track_changed(track, actors.target), GATE]
        assert committed.unassignments == []
        assert await _committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Embedded assignment: reopen_from_ignored()
# ---------------------------------------------------------------------------


def _reopen(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await reopen_from_ignored(
            session,
            ticket_id=ticket.id,
            acting_user_id=actor.id,
            caller=_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


REOPENED = status_event(TicketStatus.IGNORED.value, TicketStatus.ANALYSIS.value)
"""The final system `status_change` of the reopen: a CVE-less Ticket
without severity or packages evaluates to the `Analysis` floor."""


@pytest.mark.integration
class TestReopenEmbeddedAssignment:
    """The User who loses the role reopens a CVE-less `Ignored` Ticket
    without severity or packages that is assigned to another active VA
    (ticket-service.md, `reopen_from_ignored()`: acting User `FOR SHARE`,
    then Ticket; `auto_assign_actor(force=True)` takes ownership only for an
    eligible actor, so a skip keeps the other assignee)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: _RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await _actors(world)
        previous = await _other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _assignment_first(world, actors, _reopen(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            _assignment(actors.target, previous, actors.target),
            REOPENED,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_reopens_and_keeps_the_previous_assignee(
        self, world: _RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await _actors(world)
        previous = await _other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _role_loss_first(world, actors, _reopen(ticket, actors.target))

        committed = await _committed(world, actors, ticket.id)
        assert committed.ticket == (
            TicketStatus.ANALYSIS,
            previous.id,
            None,
            None,
            None,
        )
        assert committed.events == [REOPENED]
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)
