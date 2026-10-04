"""Shared helpers for the package-tree exclusion and restoration tests.

The six direct-marker operations of `package_service`
(`soft_delete_ticket_package[_track|_product]()` and
`restore_ticket_package[_track|_product]()`) share one contract
(package-service.md, Exclusion and restoration operations). These helpers
address them by `Level` and `Direction`, observe persisted markers and the
derived package-tree actionability, and build the exact direct audit event.

Consumers:

- `tests/test_services/test_package_exclusion.py` (independent exclusion
  scopes, guards, gate transitions, auto-assignment, audit payload);
- `tests/test_services/test_package_exclusion_scope.py` (caller
  validation, nested ownership, manual zone, shared evaluation date,
  rollback, and audit-history independence);
- `tests/test_services/test_package_exclusion_visibility.py` (consumer
  accessibility branches and the canonical predicate rows, including the
  committed self-loss case, with `CommittedPath`);
- `tests/test_services/test_package_exclusion_atomicity.py` (the
  independent-session races, with `CommittedPath`, `committed_path()`,
  `add_maintainer()`, `path_call()`, `path_event()`, and
  `markers_by_id()`);
- `tests/test_services/test_add_package_records_atomicity.py`,
  `tests/test_services/test_add_package_to_ticket_races.py`, and
  `tests/support/package_records_races.py` (public add racing with
  exclusion or restore, with `committed_path()`, `path_call()`,
  `path_event()`, `markers_by_id()`, and `with_target()`);
- `tests/test_api/test_ticket_package_exclusion.py` (the endpoint e2e
  tier, with `Level`, `Direction`, `markers()`, `with_target()`, and
  `marker_event()`);
- `tests/test_services/test_new_to_analysis_promotion.py` (the six paths
  of Architectural Test Requirement 4, with `gate_world()` and `change()`).

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test. The
derived-state observation reads the package tree through the independent
query `get_ticket_packages()`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from enum import StrEnum
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import NonActionableReason, PackageStatus, Scope
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    MarkerChangeResult,
    get_ticket_packages,
    restore_ticket_package,
    restore_ticket_package_product,
    restore_ticket_package_track,
    soft_delete_ticket_package,
    soft_delete_ticket_package_product,
    soft_delete_ticket_package_track,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.product_eligibility import (
    occurrence_path,
    product_subject,
    track_occurrences,
)
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TreeBuilder,
    ticket_events,
)
from tests.support.track_status import Spy, ticket_state

MARKER_NOW = datetime(2026, 9, 27, 10, 30, 15, 123456, tzinfo=UTC)
"""The controlled current UTC instant patched into `_marker_now()`."""

SEEDED_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
"""The direct marker seeded on a committed record before a restore."""


class Level(StrEnum):
    """The package-tree level whose direct `deleted_at` marker changes."""

    PACKAGE = "package"
    TRACK = "track"
    PRODUCT = "product"


class Direction(StrEnum):
    """Exclusion sets the direct marker; restoration clears it."""

    EXCLUDE = "exclude"
    RESTORE = "restore"


LEVELS = pytest.mark.parametrize("level", list(Level), ids=str)
DIRECTIONS = pytest.mark.parametrize("direction", list(Direction), ids=str)

_OPERATIONS: dict[
    tuple[Level, Direction], Callable[..., Awaitable[MarkerChangeResult[Any]]]
] = {
    (Level.PACKAGE, Direction.EXCLUDE): soft_delete_ticket_package,
    (Level.TRACK, Direction.EXCLUDE): soft_delete_ticket_package_track,
    (Level.PRODUCT, Direction.EXCLUDE): soft_delete_ticket_package_product,
    (Level.PACKAGE, Direction.RESTORE): restore_ticket_package,
    (Level.TRACK, Direction.RESTORE): restore_ticket_package_track,
    (Level.PRODUCT, Direction.RESTORE): restore_ticket_package_product,
}

Markers = tuple[datetime | None, datetime | None, datetime | None]
"""The direct `(package, track, Product)` markers of one occurrence path."""

State = tuple[bool, NonActionableReason | None]
"""One record's derived `(actionable, non_actionable_reason)`."""


def patch_marker_now(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every exclusion set its marker to `MARKER_NOW`."""
    monkeypatch.setattr(package_service, "_marker_now", lambda: MARKER_NOW)


async def call_operation(
    db: AsyncSession,
    level: Level,
    direction: Direction,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    occurrence_id: uuid.UUID,
    acting_user_id: Any,
    caller: Any,
    evaluation_date: date | None = EVAL,
) -> MarkerChangeResult[Any]:
    """Invoke the operation of `level`/`direction` with an explicit locator;
    the levels above the target ignore the deeper locator parts."""
    kwargs: dict[str, Any] = {
        "ticket_id": ticket_id,
        "package_id": package_id,
        "acting_user_id": acting_user_id,
        "caller": caller,
        "evaluation_date": evaluation_date,
    }
    if level is not Level.PACKAGE:
        kwargs["track_id"] = track_id
    if level is Level.PRODUCT:
        kwargs["ticket_package_product_id"] = occurrence_id
    return await _OPERATIONS[level, direction](db, **kwargs)


async def change(
    db: AsyncSession,
    level: Level,
    direction: Direction,
    occurrence: TicketPackageProduct,
    actor: User,
    *,
    ticket_id: uuid.UUID | None = None,
    package_id: uuid.UUID | None = None,
    track_id: uuid.UUID | None = None,
    occurrence_id: uuid.UUID | None = None,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> MarkerChangeResult[Any]:
    """Call the operation as the API would (`actor` with effective `scope`)
    for the path of `occurrence` (its package, track, or itself by `level`)
    unless a locator part is overridden."""
    own_ticket, own_package, own_track = await occurrence_path(db, occurrence)
    return await call_operation(
        db,
        level,
        direction,
        ticket_id=own_ticket if ticket_id is None else ticket_id,
        package_id=own_package if package_id is None else package_id,
        track_id=own_track if track_id is None else track_id,
        occurrence_id=occurrence.id if occurrence_id is None else occurrence_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def markers(db: AsyncSession, occurrence: TicketPackageProduct) -> Markers:
    """The persisted direct markers of an occurrence's package, track, and
    itself."""
    return await markers_by_id(db, occurrence.id)


async def markers_by_id(db: AsyncSession, occurrence_id: uuid.UUID) -> Markers:
    """`markers()` for an occurrence identified only by its UUID."""
    row = (
        await db.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.deleted_at,
                TicketPackageProduct.deleted_at,
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageProduct.id == occurrence_id)
        )
    ).one()
    return row[0], row[1], row[2]


def with_target(before: Markers, level: Level, value: datetime | None) -> Markers:
    """`before` with only the `level` marker replaced by `value`."""
    replaced = list(before)
    replaced[list(Level).index(level)] = value
    return replaced[0], replaced[1], replaced[2]


async def observed(
    db: AsyncSession, occurrence: TicketPackageProduct, evaluation_date: date = EVAL
) -> tuple[State, State, State]:
    """The derived `(package, track, Product)` state of an occurrence path,
    read through the independent package-tree query for `evaluation_date`."""
    ticket_id, package_id, track_id = await occurrence_path(db, occurrence)
    sequence_id = (
        await db.execute(select(Ticket.sequence_id).where(Ticket.id == ticket_id))
    ).scalar_one()
    packages = await get_ticket_packages(
        db,
        ticket_id=format_ticket_id(sequence_id),
        caller=TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
        evaluation_date=evaluation_date,
        evaluation_instant=datetime.combine(evaluation_date, time(12), UTC),
    )
    (package,) = [p for p in packages if p.id == package_id]
    (track,) = [t for t in package.tracks if t.id == track_id]
    (product,) = [p for p in track.products if p.id == occurrence.id]
    return (
        (package.actionable, package.non_actionable_reason),
        (track.actionable, track.non_actionable_reason),
        (product.actionable, product.non_actionable_reason),
    )


async def marker_event(
    db: AsyncSession,
    level: Level,
    direction: Direction,
    occurrence: TicketPackageProduct,
    actor: User,
) -> EventRow:
    """The direct event of an effective change (ticket-audit-log.md, Event
    Type Contract and detail JSONB Schema Contract): the acting user, the
    package name / track reference / Product display name as `old_value`
    (exclusion) or `new_value` (restore), `comment` `NULL`, and `detail`
    `NULL` / `{track, package}` / the event-time Product subject."""
    subject = await product_subject(db, occurrence)
    value, detail = {
        Level.PACKAGE: (subject["package"], None),
        Level.TRACK: (
            subject["track"],
            {"track": subject["track"], "package": subject["package"]},
        ),
        Level.PRODUCT: (subject["product_name"], subject),
    }[level]
    suffix = "excluded" if direction is Direction.EXCLUDE else "restored"
    old, new = (value, None) if direction is Direction.EXCLUDE else (None, value)
    return EventRow(f"{level}_{suffix}", actor.id, old, new, None, detail)


async def gate_world(
    db: AsyncSession,
    tree: TreeBuilder,
    ticket: Ticket,
    level: Level,
    direction: Direction,
    *,
    other: PackageStatus = PackageStatus.NOT_AFFECTED,
    target: PackageStatus = PackageStatus.ANALYSIS,
) -> TicketPackageProduct:
    """Two packages with one track and one eligible in-support Product each.

    The first track (`other`) is never touched. The second track
    (`target`) is the operation's path: for a restore, only its `level`
    marker is seeded; for an exclusion every marker is clear. Returns the
    target Product occurrence."""
    await tree(ticket, status=other)
    seeded = direction is Direction.RESTORE
    track = await tree(
        ticket,
        status=target,
        products=(Prod(excluded=seeded and level is Level.PRODUCT),),
        package_excluded=seeded and level is Level.PACKAGE,
        track_excluded=seeded and level is Level.TRACK,
    )
    (occurrence,) = await track_occurrences(db, track)
    return occurrence


async def assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[MarkerChangeResult[Any]]],
    *,
    tickets: tuple[Ticket, ...],
    occurrences: tuple[TicketPackageProduct, ...],
    error: type[Exception],
) -> None:
    """Run the raising call and assert the zero-side-effect contract: no
    write, no assignment, no reconciliation, no registered convergence
    effect, and unchanged Ticket status, assignee, events, and package,
    track, and Product markers for every given Ticket and occurrence."""

    async def snapshot() -> tuple[Any, ...]:
        return (
            [await ticket_state(db, t) for t in tickets],
            [await ticket_events(db, t) for t in tickets],
            [await markers(db, o) for o in occurrences],
        )

    before = await snapshot()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")

    with StatementRecorder(db) as recorder, pytest.raises(error):
        await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await snapshot() == before


# ---------------------------------------------------------------------------
# Committed worlds for independent-session tests
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommittedPath:
    """One committed package/track/Product occurrence path with its declared
    locator and its event-time subject (`track`, `package`, `product_name`,
    `product_cpe`)."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    id: uuid.UUID
    subject: dict[str, str]


async def committed_path(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    package_id: uuid.UUID | None = None,
    status: PackageStatus = PackageStatus.ANALYSIS,
    package_excluded: bool = False,
    track_excluded: bool = False,
    product_excluded: bool = False,
) -> CommittedPath:
    """Commit one track with one eligible in-support Product occurrence
    under `package_id`, or under a new uniquely named package; each `*_excluded`
    seeds that direct marker with `SEEDED_AT` (`package_excluded` only for a
    new package). Rows are owned by the world and deleted at its teardown."""
    session = world.session
    suffix = uuid.uuid4().hex[:10]
    if package_id is None:
        package = TicketPackage(
            ticket_id=ticket.id,
            package_name=f"example-libexcl-{suffix}",
            deleted_at=SEEDED_AT if package_excluded else None,
        )
        session.add(package)
        await session.flush()
        package_id = package.id
    package_name = (
        await session.execute(
            select(TicketPackage.package_name).where(TicketPackage.id == package_id)
        )
    ).scalar_one()
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=AFTER_EVAL,
    )
    track = TicketPackageTrack(
        ticket_package_id=package_id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=status.value,
        deleted_at=SEEDED_AT if track_excluded else None,
    )
    session.add_all([product, track])
    await session.flush()
    world.product_ids.append(product.id)
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=True,
        deleted_at=SEEDED_AT if product_excluded else None,
    )
    session.add(occurrence)
    await session.commit()
    return CommittedPath(
        ticket.id,
        package_id,
        track.id,
        occurrence.id,
        {
            "track": track.reference,
            "package": package_name,
            "product_name": product.display_name,
            "product_cpe": product.cpe,
        },
    )


async def add_maintainer(
    world: CommittedWorld, package_id: uuid.UUID, user: User
) -> None:
    """Commit a `TicketPackageMaintainer` association of `user` under the
    package (deleted at teardown with the world's packages)."""
    world.session.add(
        TicketPackageMaintainer(ticket_package_id=package_id, user_id=user.id)
    )
    await world.session.commit()


def path_call(
    session: AsyncSession,
    level: Level,
    direction: Direction,
    path: CommittedPath,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    package_id: uuid.UUID | None = None,
    track_id: uuid.UUID | None = None,
    occurrence_id: uuid.UUID | None = None,
) -> Coroutine[Any, Any, MarkerChangeResult[Any]]:
    """The operation of `level`/`direction` on a committed path as the API
    makes it, with the explicit declared locator, so the call issues no
    statement before its own locks; a locator part may be overridden."""
    return call_operation(
        session,
        level,
        direction,
        ticket_id=path.ticket_id,
        package_id=path.package_id if package_id is None else package_id,
        track_id=path.track_id if track_id is None else track_id,
        occurrence_id=path.id if occurrence_id is None else occurrence_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


def path_event(
    level: Level, direction: Direction, path: CommittedPath, actor: User
) -> EventRow:
    """`marker_event()` for a committed path, from its recorded subject."""
    subject = path.subject
    value, detail = {
        Level.PACKAGE: (subject["package"], None),
        Level.TRACK: (
            subject["track"],
            {"track": subject["track"], "package": subject["package"]},
        ),
        Level.PRODUCT: (subject["product_name"], dict(subject)),
    }[level]
    suffix = "excluded" if direction is Direction.EXCLUDE else "restored"
    old, new = (value, None) if direction is Direction.EXCLUDE else (None, value)
    return EventRow(f"{level}_{suffix}", actor.id, old, new, None, detail)
