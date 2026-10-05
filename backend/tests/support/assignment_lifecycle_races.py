"""Shared independent-session scaffolding for the assignment-category race
matrices against a real identity lifecycle writer.

Consumers:

- `tests/test_services/test_va_role_loss_assignment_races.py` (the real
  final manual VA-origin loss, `update_roles()`);
- `tests/test_services/test_deactivation_assignment_races.py` (the real
  `deactivate_user()`).

Owning specifications: docs/features/identity/user-service.md
(Concurrency Considerations: Assignment concurrent with deactivation or
active manual role loss) and docs/features/platform/testing-strategy.md
(User Lifecycle and Management: every assignment-capable path acquires User
`FOR SHARE` before CVE/Ticket locks; Concurrency Testing, Lock-Wait
Observation).

Everything here is independent of the lifecycle writer:

- `RaceWorld` and `race_world()`: the committed world, which also deletes
  the Tickets created by the code under test and the committed
  `default_cvss_version` setting it had to create; each consumer defines its
  own `world` fixture around `race_world()`;
- `Actors`, `race_actors()`, and `other_va()`: the administrator running the
  lifecycle writer, the active VA target it makes ineligible, and further
  active VAs;
- `assignment_first()` and `lifecycle_first()`: the two commit-order
  drivers, parameterized by a `LifecycleWriter` (the real writer for the
  target, left uncommitted) and by the predicate of its first statement,
  the User lock it waits on (`is_user_lock` by default);
- `read_committed()`: the committed Ticket state and history, the target's
  system unassignments, role origins, active flag, and Identity trail;
- the six representative `Path` builders of the matrix (`assign_path`,
  `create_path`, `override_path`, `severity_path`, `track_status_path`,
  `reopen_path`), their setup helpers, and the event rows they create.

Writer-specific expectations (the writer call and its result, the
unassignment reason, and the committed identity outcome) stay in each
consumer. Expected values in the consumers are transcribed from the
specifications; nothing here computes an expectation with the module under
test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
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
    TicketCreationSource,
    assign_ticket,
    create_ticket,
    reopen_from_ignored,
    set_priority_override,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import ticket_state
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    IdentityEventRow,
    IdentityWorld,
    identity_events,
    origins,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)
from tests.support.track_status import set_status

Factory = Callable[[], Awaitable[AsyncSession]]
Path = Callable[[AsyncSession], Awaitable[uuid.UUID]]
"""One assignment-capable call in a racing session, returning the UUID of
the Ticket it acted on (or created)."""
LifecycleWriter = Callable[[AsyncSession], Awaitable[Any]]
"""The real lifecycle writer for the target in a racing session, left
uncommitted, returning its result."""

ROOT_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) (?:ticket|cve)\b")
DEFAULT_VERSION = "3.1"
PACKAGE_NAME = "fictional-lifecycle-race"
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class RaceWorld(IdentityWorld):
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


@asynccontextmanager
async def race_world(factory: Factory) -> AsyncIterator[RaceWorld]:
    """A `RaceWorld` on a fresh session of `factory`, cleaned up on exit;
    the body of a consumer's `world` fixture."""
    created = RaceWorld(factory, await factory())
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass(frozen=True, slots=True)
class Actors:
    admin: User
    """The administrator running the lifecycle writer (its audit actor)."""
    target: User
    """The active User whose only VA origin is `_manual`, made ineligible
    by the lifecycle writer."""


async def race_actors(world: RaceWorld) -> Actors:
    return Actors(
        admin=await world.identity_user(manual=[Role.ADMIN], prefix="alice.admin"),
        target=await world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST], prefix="bob.va"
        ),
    )


async def other_va(world: RaceWorld, prefix: str) -> User:
    """Another committed active User with a `_manual` VA origin."""
    return await world.identity_user(manual=[Role.VULNERABILITY_ANALYST], prefix=prefix)


# ---------------------------------------------------------------------------
# Race drivers
# ---------------------------------------------------------------------------


def is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def is_user_lock(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR NO KEY UPDATE" in statement


def ticket_writes(writes: list[str]) -> list[str]:
    """The writes to `ticket` or `ticket_audit_event`."""
    return [w for w in writes if "ticket" in w]


async def assignment_first[R](
    world: RaceWorld,
    path: Path,
    writer: Callable[[AsyncSession], Awaitable[R]],
    *,
    waits_at: Callable[[str], bool] = is_user_lock,
) -> tuple[uuid.UUID, R]:
    """A runs `path` and keeps it uncommitted (holding the User `FOR SHARE`);
    B's real lifecycle `writer` is proven to wait on A with the User lock
    (`waits_at`) as its first and only statement; A commits, then B
    completes and commits. B's batch must have cleared exactly the one
    committed assignment. Returns the Ticket UUID of `path` and the writer's
    result."""
    a = await world.open_session()
    b = await world.open_session()

    ticket_id = await path(a)
    world.ticket_ids.append(ticket_id)
    with SessionStatementRecorder(b) as recorder:
        task = world.start(b, writer(b))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        waiting = list(recorder.statements)
        assert len(waiting) == 1
        assert waits_at(waiting[0])
        await a.commit()
        result: R = await asyncio.wait_for(task, timeout=WAIT)
    await b.commit()

    # The batch cleared exactly the one committed assignment.
    assert len([w for w in recorder.writes() if "UPDATE ticket " in w]) == 1
    return ticket_id, result


async def lifecycle_first[R](
    world: RaceWorld,
    path: Path,
    writer: Callable[[AsyncSession], Awaitable[R]],
    *,
    error: type[Exception] | None = None,
) -> tuple[uuid.UUID | None, R]:
    """B's real lifecycle `writer` runs first and stays uncommitted (holding
    the User `FOR NO KEY UPDATE`); it finds nothing to clear. A runs `path`
    and is proven to wait on B at its User `FOR SHARE`, before any CVE or
    Ticket statement; B commits, then A completes and commits. With
    `error`, A must raise it with no write and roll back. Returns the Ticket
    UUID of `path` (`None` when it raised) and the writer's result."""
    a = await world.open_session()
    b = await world.open_session()

    with SessionStatementRecorder(b) as writer_recorder:
        result = await writer(b)
    assert ticket_writes(writer_recorder.writes()) == []

    with SessionStatementRecorder(a) as recorder:
        task = world.start(a, path(a))
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        waiting = list(recorder.statements)
        assert is_user_share(waiting[-1])
        assert [s for s in waiting if ROOT_STATEMENT.search(s)] == []
        await b.commit()
        if error is not None:
            with pytest.raises(error):
                await asyncio.wait_for(task, timeout=WAIT)
            assert recorder.writes() == []
            await a.rollback()
            return None, result
        ticket_id: uuid.UUID = await asyncio.wait_for(task, timeout=WAIT)

    world.ticket_ids.append(ticket_id)
    await a.commit()
    return ticket_id, result


# ---------------------------------------------------------------------------
# Committed observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommittedRace:
    ticket: tuple[Any, ...]
    """`(status, assignee_id, priority_auto, priority_override,
    severity_manual)`."""
    events: list[EventRow]
    unassignments: list[uuid.UUID]
    """The Tickets of every committed system unassignment of the target."""
    origins: set[tuple[str, str]]
    active: bool
    """The committed `User.active` of the target."""
    identity: list[IdentityEventRow]


async def read_committed(
    world: RaceWorld, actors: Actors, ticket_id: uuid.UUID
) -> CommittedRace:
    """The committed Ticket state and history, every system unassignment
    event of the target on any Ticket, and the target's role origins,
    active flag, and Identity trail, read through a fresh independent
    session."""
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
    active = (
        await probe.execute(select(User.active).where(User.id == target.id))
    ).scalar_one()
    committed = CommittedRace(
        ticket=await ticket_state(probe, ticket_id),
        events=await ticket_events_by_id(probe, ticket_id),
        unassignments=list(unassignments),
        origins=await origins(probe, target.id),
        active=active,
        identity=await identity_events(probe, target.id),
    )
    await probe.rollback()
    return committed


def assignment_event(actor: User, old: User | None, new: User) -> EventRow:
    """An acting-user `assignment` event."""
    return EventRow(
        "assignment",
        actor.id,
        old.username if old is not None else None,
        new.username,
        None,
        None,
    )


def consumer_caller(actor: User) -> TicketCaller:
    return TicketCaller.authenticated(actor.id, Scope.ALL)


PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of an assignment."""


# ---------------------------------------------------------------------------
# Explicit assignment: assign_ticket()
# ---------------------------------------------------------------------------


def assign_path(ticket: Ticket, target: User, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await assign_ticket(
            session,
            ticket_id=ticket.id,
            assignee=str(target.id),
            acting_user_id=actor.id,
            caller=consumer_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


# ---------------------------------------------------------------------------
# Creation assignment: manual create_ticket()
# ---------------------------------------------------------------------------


def create_path(creator: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        ticket = await create_ticket(
            session,
            acting_user_id=creator.id,
            source=TicketCreationSource.MANUAL,
        )
        return ticket.id

    return run


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_service): set_priority_override()
# ---------------------------------------------------------------------------


def override_path(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_priority_override(
            session,
            ticket_id=ticket.id,
            priority=TicketPriority.P1,
            acting_user_id=actor.id,
            caller=consumer_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


def override_set_event(actor: User) -> EventRow:
    """The acting-user `priority_changed` of setting `P1` without a prior
    override or automatic priority."""
    return EventRow(
        "priority_changed", actor.id, None, "P1", None, {"override_action": "set"}
    )


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_mutations): set_severity_manual()
# ---------------------------------------------------------------------------


def severity_path(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_severity_manual(
            session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=actor.id,
            caller=consumer_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


def severity_set_event(actor: User) -> EventRow:
    """The acting-user `severity_changed` from SQL `NULL` to `High`."""
    return EventRow("severity_changed", actor.id, None, "High", None, None)


# ---------------------------------------------------------------------------
# Auto-assignment (package_service): set_track_status()
# ---------------------------------------------------------------------------


async def open_track_ticket(world: RaceWorld) -> tuple[Ticket, TicketPackageTrack]:
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


def track_status_path(ticket: Ticket, track: TicketPackageTrack, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await set_status(
            session, track, PackageStatus.AFFECTED, actor, ticket_id=ticket.id
        )
        return ticket.id

    return run


def track_changed_event(track: TicketPackageTrack, actor: User) -> EventRow:
    """The acting-user `track_status_changed` `ANALYSIS -> AFFECTED`."""
    return EventRow(
        "track_status_changed",
        actor.id,
        PackageStatus.ANALYSIS.value,
        PackageStatus.AFFECTED.value,
        None,
        {"track": track.reference, "package": PACKAGE_NAME},
    )


async def committed_track_status(world: RaceWorld, track: TicketPackageTrack) -> str:
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


# ---------------------------------------------------------------------------
# Embedded assignment: reopen_from_ignored()
# ---------------------------------------------------------------------------


def reopen_path(ticket: Ticket, actor: User) -> Path:
    async def run(session: AsyncSession) -> uuid.UUID:
        await reopen_from_ignored(
            session,
            ticket_id=ticket.id,
            acting_user_id=actor.id,
            caller=consumer_caller(actor),
            evaluation_date=EVAL,
        )
        return ticket.id

    return run


REOPENED = status_event(TicketStatus.IGNORED.value, TicketStatus.ANALYSIS.value)
"""The final system `status_change` of the reopen: a CVE-less Ticket
without severity or packages evaluates to the `Analysis` floor."""
