"""Shared helpers for the `set_track_status()` service tests.

Consumers:

- `tests/test_services/test_set_track_status.py` (part A: authority matrix,
  no-op, gate transitions, auto-assignment, audit payload, nested
  ownership);
- `tests/test_services/test_set_track_status_scope.py` (part B:
  accessibility, manual zone, excluded and EOL tracks, dimension
  independence, result projection, shared evaluation date, rollback, and
  audit-history independence);
- the `set_product_eligibility()` tests (`Spy`, `ticket_state`), see
  `tests/support/product_eligibility.py`, and
  `tests/test_services/test_set_product_eligibility_atomicity.py` (`Spy`).

The helpers observe persisted state and record calls; nothing here computes
an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import date
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Scope
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    SYSTEM_INVOCATION,
    TrackStatusResult,
    set_track_status,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    ticket_events,
)


async def track_event(
    db: AsyncSession,
    track: TicketPackageTrack,
    actor: User | None,
    old: PackageStatus,
    new: PackageStatus,
) -> EventRow:
    """The `track_status_changed` event: acting user or `NULL`, enum names,
    `comment` `NULL`, and `{track, package}` detail."""
    package_name = (
        await db.execute(
            select(TicketPackage.package_name).where(
                TicketPackage.id == track.ticket_package_id
            )
        )
    ).scalar_one()
    return EventRow(
        "track_status_changed",
        actor.id if actor else None,
        old.value,
        new.value,
        None,
        {"track": track.reference, "package": package_name},
    )


async def set_status(
    db: AsyncSession,
    track: TicketPackageTrack,
    status: PackageStatus,
    actor: User | None,
    *,
    ticket_id: uuid.UUID | None = None,
    package_id: uuid.UUID | None = None,
    force: bool = False,
    scope: Scope = Scope.ALL,
    evaluation_date: date = EVAL,
) -> TrackStatusResult:
    """Call the service as the API (`actor`, with effective `scope`) or a
    system workflow (`None`) would, for `track`'s own path unless a locator
    level is overridden."""
    if package_id is None:
        package_id = track.ticket_package_id
    if ticket_id is None:
        ticket_id = (
            await db.execute(
                select(TicketPackage.ticket_id).where(TicketPackage.id == package_id)
            )
        ).scalar_one()
    return await set_track_status(
        db,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track.id,
        status=status,
        acting_user_id=actor.id if actor else None,
        caller=(
            TicketCaller.authenticated(actor.id, scope) if actor else SYSTEM_INVOCATION
        ),
        force=force,
        evaluation_date=evaluation_date,
    )


async def ticket_state(
    db: AsyncSession, ticket: Ticket
) -> tuple[str, uuid.UUID | None]:
    """The persisted `(status, assignee_id)` of a Ticket."""
    row = (
        await db.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    return row.status, row.assignee_id


async def persisted_track_status(db: AsyncSession, track: TicketPackageTrack) -> str:
    """The persisted affectedness status of a track."""
    return (
        await db.execute(
            select(TicketPackageTrack.status).where(TicketPackageTrack.id == track.id)
        )
    ).scalar_one()


class Spy:
    """Wraps an async `package_service` attribute (a name imported from
    `ticket_mutations`), recording each call's arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(package_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(package_service, name, _wrapper)


async def assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[TrackStatusResult]],
    *,
    tickets: tuple[Ticket, ...],
    tracks: tuple[TicketPackageTrack, ...],
    error: type[Exception] | None = None,
) -> TrackStatusResult | None:
    """Run the call and assert the zero-side-effect contract: no write, no
    assignment, no reconciliation, no registered convergence effect, and
    unchanged Ticket status, assignee, events, and track statuses for every
    given Ticket and track. Returns the result of a non-raising call."""
    before = (
        [await ticket_state(db, t) for t in tickets],
        [await ticket_events(db, t) for t in tickets],
        [await persisted_track_status(db, t) for t in tracks],
    )
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: TrackStatusResult | None = None

    with StatementRecorder(db) as recorder:
        if error is None:
            result = await run()
        else:
            with pytest.raises(error):
                await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert (
        [await ticket_state(db, t) for t in tickets],
        [await ticket_events(db, t) for t in tickets],
        [await persisted_track_status(db, t) for t in tracks],
    ) == before
    return result
