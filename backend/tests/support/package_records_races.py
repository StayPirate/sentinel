"""Shared committed-world helpers for the package-record race tests.

The Ticket-locked boundary `package_service.add_package_records()` and its
I/O-then-Lock orchestrator `add_package_to_ticket()` are raced with
independent `db_session_factory` sessions (testing-strategy.md,
Concurrency Testing; Ticket Accessibility: Locked mutations, External I/O
and post-commit effects). These helpers build their committed worlds on
`tests/support/suse_cvss_races.py` `CommittedWorld` and observe the
committed state through fresh independent sessions:

- `committed_world()`, a `CommittedWorld` that also owns the committed
  `default_cvss_version` setting the test schema lacks;
- `pinned_ticket()`, the unassigned CVE-less `Analysis` Ticket with
  `severity_manual = High` and an untouched actionable `ANALYSIS` "pin"
  package, so a package-tree change keeps it in `Analysis` and creates no
  gate event; `world_product()`, a committed catalog Product in General
  Support on `EVAL` with a `NULL` threshold (a created occurrence is
  eligible, the `10.0` fallback score);
- the marker world of the public-add races (`marker_world()`, `KINDS`,
  `tree_events()`, `with_new_rows()`, `EXPECTED_OUTCOME`);
- the locked-current accessibility losses (`LOSSES`, `existing_package()`,
  `protected_state()`, `assert_denied_without_effects()`);
- `committed_state()`, the committed Ticket, events, one package tree,
  and maintainer associations.

Committed rows are owned by the world and deleted at its teardown.

Consumers:

- `tests/test_services/test_add_package_records_atomicity.py` (the races of
  the locked boundary);
- `tests/test_services/test_add_package_to_ticket_races.py` (the races of
  the orchestrator across its external SMELT phase).

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Severity, TicketStatus, WorkflowType
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services.package_service import PackageAddedComment, PackageRecordsOutcome
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.package_exclusion import CommittedPath, Level, committed_path
from tests.support.package_records import (
    NEW_TRACK,
    OccurrenceState,
    TrackState,
    Tree,
    catalog_product,
    changed,
    maintainer_event,
    maintainers,
    new_occurrence,
    package_added_event,
    package_tree,
    ticket_row,
    tree_rows,
)
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

ANALYSIS = TicketStatus.ANALYSIS.value
IBS_REF = "Fictional:Product:15-SP7:Update"
GIT_REF = "fictional/slfo-1.1"
CVE_RESOLUTION: PackageAddedComment = "CVE package resolution"


@asynccontextmanager
async def committed_world(factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every creation reads."""
    created = CommittedWorld(factory, await factory())
    owns_setting = False
    try:
        if await created.session.get(SystemSetting, "default_cvss_version") is None:
            created.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            owns_setting = True
        await created.session.commit()
        yield created
    finally:
        await created.cleanup()
        if owns_setting:
            await created.session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await created.session.commit()


# ---------------------------------------------------------------------------
# Committed rows
# ---------------------------------------------------------------------------


async def pinned_ticket(world: CommittedWorld) -> Ticket:
    """The committed unassigned pinned Ticket of the module docstring."""
    ticket = await world.ticket(cve_id=None, severity_manual=Severity.HIGH)
    await committed_path(world, ticket)
    return ticket


async def world_product(world: CommittedWorld) -> Product:
    """A committed catalog Product owned by the world."""
    product = await catalog_product(world.session)
    world.product_ids.append(product.id)
    await world.session.commit()
    return product


async def product_of(world: CommittedWorld, path: CommittedPath) -> uuid.UUID:
    """The catalog Product of a committed path's occurrence."""
    product_id = (
        await world.session.execute(
            select(TicketPackageProduct.product_id).where(
                TicketPackageProduct.id == path.id
            )
        )
    ).scalar_one()
    await world.session.commit()
    return product_id


def path_tree(
    path: CommittedPath,
    *,
    package: datetime | None,
    track: datetime | None,
    product: datetime | None,
    product_id: uuid.UUID,
) -> Tree:
    """The tree of a committed path (an `ibs` `ANALYSIS`/`PENDING` track
    with one eligible unreleased occurrence) with the given direct
    markers."""
    reference = path.subject["track"]
    return Tree(
        package,
        {reference: TrackState("ibs", "ANALYSIS", "PENDING", track)},
        {(reference, product_id): OccurrenceState(True, False, None, product)},
    )


def sessions_of(spy: Spy, position: int) -> list[Any]:
    """The session argument of each recorded call."""
    return [args[position] for args, _kwargs in spy.calls]


# ---------------------------------------------------------------------------
# Committed state
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class CommittedState:
    """The committed Ticket `(status, assignee_id)`, its audit events, the
    tree of one package, and every maintainer association of the Ticket."""

    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]
    tree: Tree | None
    maintainers: list[tuple[str, uuid.UUID]]


async def committed_state(
    world: CommittedWorld, ticket_id: uuid.UUID, package_name: str
) -> CommittedState:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    state = CommittedState(
        await ticket_row(probe, ticket_id),
        await ticket_events_by_id(probe, ticket_id),
        await package_tree(probe, ticket_id, package_name),
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


# ---------------------------------------------------------------------------
# Public add racing with exclusion or restore (package-service.md,
# Concurrency Control)
# ---------------------------------------------------------------------------

KINDS = ["no-op", "maintainer-only", "tree"]
"""The adding call's input on the committed path `T1: {P1}`. `no-op`: the
same tree, no email. `maintainer-only`: the same tree with maintainer M.
`tree`: `T1: {P1, P2}` plus a new Git track `GIT_REF: {P3}`, with M."""


@dataclasses.dataclass(frozen=True, slots=True)
class MarkerWorld:
    """A pinned unassigned Ticket with the target path, its exclusion or
    restoration actor A, the adding actor B (`None` for a system call),
    the maintainer M, and the extra catalog Products."""

    ticket: Ticket
    path: CommittedPath
    p1: uuid.UUID
    p2: Product
    p3: Product
    actor_a: User
    actor_b: User | None
    m: User


async def marker_world(
    world: CommittedWorld, *, seeded: Level | None = None, system: bool = False
) -> MarkerWorld:
    """A `MarkerWorld` whose path carries the `seeded` direct marker."""
    actor_a = await world.user(role=Role.VULNERABILITY_ANALYST)
    actor_b = None if system else await world.user(role=Role.VULNERABILITY_ANALYST)
    m = await world.user(role=Role.RESTRICTED_ANALYST)
    ticket = await pinned_ticket(world)
    path = await committed_path(
        world,
        ticket,
        package_excluded=seeded is Level.PACKAGE,
        track_excluded=seeded is Level.TRACK,
        product_excluded=seeded is Level.PRODUCT,
    )
    return MarkerWorld(
        ticket,
        path,
        await product_of(world, path),
        await world_product(world),
        await world_product(world),
        actor_a,
        actor_b,
        m,
    )


def tree_events(
    kind: str, w: MarkerWorld, comment: PackageAddedComment = CVE_RESOLUTION
) -> list[EventRow]:
    """The adding call's own events (no assignment: A already assigned)."""
    pkg = w.path.subject["package"]
    return {
        "no-op": [],
        "maintainer-only": [maintainer_event(pkg, w.m)],
        "tree": [
            maintainer_event(pkg, w.m),
            package_added_event(pkg, w.actor_b, comment),
        ],
    }[kind]


def with_new_rows(tree: Tree, kind: str, w: MarkerWorld) -> Tree:
    """`tree` plus the rows that the `tree` input creates."""
    if kind != "tree":
        return tree
    reference = w.path.subject["track"]
    return Tree(
        tree.deleted_at,
        tree.tracks | {GIT_REF: NEW_TRACK[WorkflowType.GIT]},
        tree.occurrences
        | {
            (reference, w.p2.id): new_occurrence(True),
            (GIT_REF, w.p3.id): new_occurrence(True),
        },
    )


EXPECTED_OUTCOME = {
    "no-op": (PackageRecordsOutcome.PACKAGE_TREE_NO_OP, 0, 1, 0, 1),
    "maintainer-only": (PackageRecordsOutcome.MAINTAINER_ONLY, 0, 1, 0, 1),
    "tree": changed(1, 1, 2, 1),
}


# ---------------------------------------------------------------------------
# Atomic consumer accessibility: locked-current state (testing-strategy.md,
# Ticket Accessibility: Locked mutations)
# ---------------------------------------------------------------------------

LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-scoped visibility losses of testing-strategy.md, Locked
mutations (`association-changed` is a CVE-scoped loss)."""

UNDECIDED = (
    "ticket_package.package_name =",
    "FROM ticket_package_track",
    "FROM ticket_package_product",
    '"user".email IN',
)
"""Statement fragments of the package lookup (excluded-package guard), the
locked tree reload (no-op and idempotency classification), and the
maintainer match: none may precede a locked accessibility denial."""


async def existing_package(world: CommittedWorld, ticket: Ticket) -> uuid.UUID | None:
    """The Ticket's maintained package created by `prepare_loss()`, if any."""
    package_id = (
        await world.session.execute(
            select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
        )
    ).scalar_one_or_none()
    await world.session.commit()
    return package_id


async def protected_state(
    world: CommittedWorld, ticket_id: uuid.UUID
) -> tuple[Any, ...]:
    """The committed assignee, events, maintainer associations, and every
    package-tree row with the package markers left out (the
    `last-package-excluded` loss sets one)."""
    probe = await world.open_session()
    _status, assignee = await ticket_row(probe, ticket_id)
    rows = [
        r[:3] if r[0] == "package" else r for r in await tree_rows(probe, ticket_id)
    ]
    state = (
        assignee,
        await ticket_events_by_id(probe, ticket_id),
        rows,
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


def assert_denied_without_effects(
    recorder: StatementRecorder,
    session: AsyncSession,
    assign: Spy,
    reconcile: Spy,
) -> None:
    """Zero domain write, assignment, reconciliation, and convergence
    registration, and no excluded-package, no-op, idempotency, or
    maintainer-match read before the denial."""
    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(session) == ()
    assert [s for s in recorder.statements if any(p in s for p in UNDECIDED)] == []
