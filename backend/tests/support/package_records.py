"""Shared helpers for the `add_package_records()` service tests.

`package_service.add_package_records()` is the Ticket-locked package-tree
creation and maintainer-association boundary (package-service.md,
`add_package_records()`; package-maintainership.md, Acquisition Workflow >
Locked mutation). These helpers build its typed input, seed catalog
Products, Users, and package trees, call it as a user-attributed consumer
or a system workflow would, observe the persisted tree, associations, and
Ticket state, and build the exact expected audit events.

Every helper takes an explicit `AsyncSession` and only adds and flushes,
so it works on the shared `db_session` and on an independent
`db_session_factory` session whose owner commits and cleans up (for
example with `tests/support/suse_cvss_races.py` `CommittedWorld`, whose
`product_ids` and `user_ids` the caller extends with the seeded rows).
Seeded identifiers carry a random suffix, so they never collide with
committed rows of a concurrent world.

Consumers:

- `tests/test_services/test_add_package_records.py` (record creation,
  idempotency, creation eligibility, maintainers, audit, gates,
  re-resolution mode, no unspecified work);
- `tests/test_services/test_add_package_records_scope.py` (caller
  contract, guards and their order, whole-invocation rollback);
- `tests/test_services/test_add_package_records_atomicity.py` (the
  independent-session races);
- `tests/test_services/test_new_to_analysis_promotion.py` (the
  `add_package_records()` path of Architectural Test Requirement 4, with
  `add_records()`, `catalog_product()`, and `target()`).

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, PackageStatus, Role, Scope, WorkflowType
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services.package_service import (
    SYSTEM_INVOCATION,
    PackageAddedComment,
    PackageRecordsOutcome,
    PackageRecordsResult,
    ResolvedTrackData,
    add_package_records,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
    RELEASED_AT,
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

SYSTEM_COMMENTS: tuple[PackageAddedComment, ...] = (
    "CVE package resolution",
    "Product catalog backfill",
    "Ticket convergence",
)
"""The closed `package_added` comments of the automatic contexts
(ticket-audit-log.md, Canonical Automatic Comment Vocabulary)."""

SEEDED_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
"""The direct `deleted_at` marker of a seeded excluded record."""

LIFECYCLES: dict[str, dict[str, date]] = {
    "general": {"general_support_end_date": AFTER_EVAL},
    "eol": {"general_support_end_date": BEFORE_EVAL},
    "reactive": {
        "general_support_end_date": REACTIVE_GS_END,
        "extended_support_end_date": REACTIVE_EXTENDED_END,
        "reactive_support_end_date": REACTIVE_END,
    },
    "none": {},
    "extended-ends-on-eval": {
        "general_support_end_date": BEFORE_EVAL,
        "extended_support_end_date": EVAL,
        "reactive_support_end_date": AFTER_EVAL,
    },
}
"""Catalog lifecycle dates (product-catalog.md, Lifecycle Evaluator, with
inclusive phase ends). `general`: General Support on `EVAL`. `eol`: EOL on
`EVAL`. `reactive`: Reactive Support on `EVAL`. `none`: no dates (phase
unavailable). `extended-ends-on-eval`: Extended Support on `EVAL`, Reactive
Support on the next day."""


def _suffix() -> str:
    return uuid.uuid4().hex[:10]


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


def target(
    reference: str,
    *products: Product | uuid.UUID,
    workflow: WorkflowType = WorkflowType.IBS,
) -> ResolvedTrackData:
    """One resolved track: its codestream `reference`, `workflow`, and the
    catalog Products (or raw catalog IDs) in the given order."""
    return ResolvedTrackData(
        reference=reference,
        workflow_type=workflow,
        catalog_product_ids=tuple(
            p.id if isinstance(p, Product) else p for p in products
        ),
    )


# ---------------------------------------------------------------------------
# Seeding (any session; flush only)
# ---------------------------------------------------------------------------


async def catalog_product(
    db: AsyncSession,
    *,
    threshold: Decimal | str | None = None,
    lifecycle: str = "general",
) -> Product:
    """A catalog Product with a `cvss_threshold` (`None` is SQL `NULL`) and
    the `LIFECYCLES` entry `lifecycle`."""
    suffix = _suffix()
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        cvss_threshold=Decimal(threshold) if threshold is not None else None,
        **LIFECYCLES[lifecycle],
    )
    db.add(product)
    await db.flush()
    return product


async def seed_user(
    db: AsyncSession,
    *,
    email: str | None = None,
    username: str | None = None,
    active: bool = True,
    roles: tuple[Role, ...] = (Role.VULNERABILITY_ANALYST,),
    user_id: uuid.UUID | None = None,
) -> User:
    """A local User with fictional identifiers and the given role origins."""
    suffix = _suffix()
    user = User(
        username=username or f"fictional.user.{suffix}",
        email=email or f"fictional.user.{suffix}@example.com",
        password_hash="$2b$12$" + "r" * 53,
        active=active,
    )
    if user_id is not None:
        user.id = user_id
    db.add(user)
    await db.flush()
    for index, role in enumerate(roles):
        db.add(UserRole(user_id=user.id, role=role.value, group_name=f"_o{index}"))
    await db.flush()
    return user


async def seed_package(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    name: str,
    *,
    excluded: bool = False,
) -> TicketPackage:
    """A package occurrence, directly excluded at `SEEDED_AT` when asked."""
    package = TicketPackage(
        ticket_id=ticket_id,
        package_name=name,
        deleted_at=SEEDED_AT if excluded else None,
    )
    db.add(package)
    await db.flush()
    return package


async def seed_track(
    db: AsyncSession,
    package: TicketPackage,
    reference: str,
    *,
    status: PackageStatus = PackageStatus.ANALYSIS,
    delivery: DeliveryStatus = DeliveryStatus.PENDING,
    workflow: WorkflowType = WorkflowType.IBS,
    excluded: bool = False,
) -> TicketPackageTrack:
    """A track of `package` with the given affectedness and delivery."""
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type=workflow.value,
        reference=reference,
        status=status.value,
        delivery_status=delivery.value,
        deleted_at=SEEDED_AT if excluded else None,
    )
    db.add(track)
    await db.flush()
    return track


async def seed_occurrence(
    db: AsyncSession,
    track: TicketPackageTrack,
    product: Product,
    *,
    eligible: bool = True,
    override: bool = False,
    released: bool = False,
    excluded: bool = False,
) -> TicketPackageProduct:
    """A Product occurrence of `product` under `track`."""
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=eligible,
        is_eligible_override=override,
        released_at=RELEASED_AT if released else None,
        deleted_at=SEEDED_AT if excluded else None,
    )
    db.add(occurrence)
    await db.flush()
    return occurrence


async def seed_maintainer(
    db: AsyncSession, package: TicketPackage, user: User
) -> TicketPackageMaintainer:
    """An existing `TicketPackageMaintainer` association."""
    association = TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
    db.add(association)
    await db.flush()
    return association


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


async def add_records(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    package_name: str,
    tracks: Iterable[ResolvedTrackData],
    *,
    actor: User | None = None,
    emails: Iterable[str] = (),
    scope: Scope = Scope.ALL,
    comment: PackageAddedComment = "CVE package resolution",
    active_ticket_only: bool = False,
    reresolution: bool = False,
) -> PackageRecordsResult:
    """Call the service as the user-facing package addition (`actor`, with
    effective `scope`, and a `NULL` comment) or a system workflow (`None`,
    with the canonical `comment`) would. The call issues no statement before
    its own locks."""
    return await add_package_records(
        db,
        ticket_id=ticket_id,
        package_name=package_name,
        tracks=list(tracks),
        maintainer_emails=frozenset(emails),
        acting_user_id=actor.id if actor else None,
        caller=(
            TicketCaller.authenticated(actor.id, scope) if actor else SYSTEM_INVOCATION
        ),
        audit_comment=None if actor else comment,
        active_ticket_only=active_ticket_only,
        allow_excluded_reresolution=reresolution,
    )


def changed(
    tracks_created: int,
    tracks_skipped: int,
    products_created: int,
    products_skipped: int,
) -> tuple[PackageRecordsOutcome, int, int, int, int]:
    """The expected `(outcome, counts)` of a package-tree change."""
    return (
        PackageRecordsOutcome.PACKAGE_TREE_CHANGED,
        tracks_created,
        tracks_skipped,
        products_created,
        products_skipped,
    )


def outcome(
    result: PackageRecordsResult,
) -> tuple[PackageRecordsOutcome, int, int, int, int]:
    """The `(outcome, tracks_created, tracks_skipped, products_created,
    products_skipped)` of a result."""
    return (
        result.outcome,
        result.tracks_created,
        result.tracks_skipped,
        result.products_created,
        result.products_skipped,
    )


SKIPPED = PackageRecordsResult(
    outcome=PackageRecordsOutcome.ACTIVE_TICKET_ONLY_SKIPPED,
    tracks_created=0,
    tracks_skipped=0,
    products_created=0,
    products_skipped=0,
    created_tracks=(),
)
"""The `active_ticket_only` skip, which examines nothing."""


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrackState:
    """One persisted track: `(workflow_type, status, delivery_status,
    deleted_at)`."""

    workflow_type: str
    status: str
    delivery_status: str
    deleted_at: datetime | None


@dataclass(frozen=True, slots=True)
class OccurrenceState:
    """One persisted Product occurrence: `(eligible, is_eligible_override,
    released_at, deleted_at)`."""

    eligible: bool
    is_eligible_override: bool
    released_at: datetime | None
    deleted_at: datetime | None


NEW_TRACK = {
    WorkflowType.IBS: TrackState("ibs", "ANALYSIS", "PENDING", None),
    WorkflowType.GIT: TrackState("git", "ANALYSIS", "PENDING", None),
}
"""A newly created track (package-service.md, Record Creation Logic:
`ANALYSIS`/`PENDING`, `deleted_at = NULL`)."""


def new_occurrence(eligible: bool) -> OccurrenceState:
    """A newly created occurrence: the creation eligibility, no override,
    unreleased, and `deleted_at = NULL`."""
    return OccurrenceState(eligible, False, None, None)


@dataclass(frozen=True, slots=True)
class Tree:
    """The persisted tree of one package occurrence: its direct marker, its
    tracks by reference, and its occurrences by `(reference, Product.id)`."""

    deleted_at: datetime | None
    tracks: dict[str, TrackState]
    occurrences: dict[tuple[str, uuid.UUID], OccurrenceState]


async def package_tree(
    db: AsyncSession, ticket_id: uuid.UUID, package_name: str
) -> Tree | None:
    """The persisted tree of the Ticket's package `package_name`, if any."""
    package = (
        await db.execute(
            select(TicketPackage.id, TicketPackage.deleted_at).where(
                TicketPackage.ticket_id == ticket_id,
                TicketPackage.package_name == package_name,
            )
        )
    ).one_or_none()
    if package is None:
        return None
    tracks = (
        await db.execute(
            select(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id == package.id
            )
        )
    ).scalars()
    track_states: dict[str, TrackState] = {}
    references: dict[uuid.UUID, str] = {}
    for t in tracks:
        references[t.id] = t.reference
        track_states[t.reference] = TrackState(
            t.workflow_type, t.status, t.delivery_status, t.deleted_at
        )
    occurrences = (
        await db.execute(
            select(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(list(references))
            )
        )
    ).scalars()
    return Tree(
        package.deleted_at,
        track_states,
        {
            (references[o.ticket_package_track_id], o.product_id): OccurrenceState(
                o.eligible, o.is_eligible_override, o.released_at, o.deleted_at
            )
            for o in occurrences
        },
    )


async def track_ids(
    db: AsyncSession, ticket_id: uuid.UUID, package_name: str
) -> dict[str, uuid.UUID]:
    """The persisted track IDs of the package, by reference."""
    rows = await db.execute(
        select(TicketPackageTrack.reference, TicketPackageTrack.id)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            TicketPackage.ticket_id == ticket_id,
            TicketPackage.package_name == package_name,
        )
    )
    return {row.reference: row.id for row in rows}


async def tree_rows(db: AsyncSession, ticket_id: uuid.UUID) -> list[tuple[Any, ...]]:
    """Every persisted package, track, and occurrence row of the Ticket, with
    its identity and every mutable column, in a deterministic order."""
    packages = (
        await db.execute(
            select(
                TicketPackage.id, TicketPackage.package_name, TicketPackage.deleted_at
            ).where(TicketPackage.ticket_id == ticket_id)
        )
    ).all()
    package_ids = [p.id for p in packages]
    tracks = (
        await db.execute(
            select(
                TicketPackageTrack.id,
                TicketPackageTrack.ticket_package_id,
                TicketPackageTrack.workflow_type,
                TicketPackageTrack.reference,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
            ).where(TicketPackageTrack.ticket_package_id.in_(package_ids))
        )
    ).all()
    occurrences = (
        await db.execute(
            select(
                TicketPackageProduct.id,
                TicketPackageProduct.ticket_package_track_id,
                TicketPackageProduct.product_id,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackageProduct.deleted_at,
            ).where(
                TicketPackageProduct.ticket_package_track_id.in_([t.id for t in tracks])
            )
        )
    ).all()
    return sorted(
        [("package", *p) for p in packages]
        + [("track", *t) for t in tracks]
        + [("product", *o) for o in occurrences],
        key=repr,
    )


async def maintainers(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[str, uuid.UUID]]:
    """Every `(package_name, user_id)` association of the Ticket, sorted."""
    rows = await db.execute(
        select(TicketPackage.package_name, TicketPackageMaintainer.user_id)
        .join(
            TicketPackage,
            TicketPackage.id == TicketPackageMaintainer.ticket_package_id,
        )
        .where(TicketPackage.ticket_id == ticket_id)
    )
    return sorted((row.package_name, row.user_id) for row in rows)


async def ticket_row(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None]:
    """The persisted `(status, assignee_id)` of a Ticket."""
    row = (
        await db.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket_id)
        )
    ).one()
    return row.status, row.assignee_id


async def snapshot(db: AsyncSession, *ticket_ids: uuid.UUID) -> tuple[Any, ...]:
    """The complete observable state of the Tickets: status and assignee,
    audit events, package-tree rows, maintainer associations, plus the
    session's pending Ticket convergence effects."""
    return (
        [await ticket_row(db, t) for t in ticket_ids],
        [await ticket_events_by_id(db, t) for t in ticket_ids],
        [await tree_rows(db, t) for t in ticket_ids],
        [await maintainers(db, t) for t in ticket_ids],
        pending_ticket_convergence_effects(db),
    )


async def assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[PackageRecordsResult]],
    *,
    ticket_ids: tuple[uuid.UUID, ...],
    error: type[Exception] | None = None,
) -> PackageRecordsResult | None:
    """Run the call and assert the zero-side-effect contract: no write
    statement, no `auto_assign_actor()` or `reconcile_ticket_status()` call,
    no registered convergence effect, and an unchanged `snapshot()` for
    every given Ticket. Returns the result of a non-raising call."""
    before = await snapshot(db, *ticket_ids)
    assert before[-1] == ()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: PackageRecordsResult | None = None

    with StatementRecorder(db) as recorder:
        if error is None:
            result = await run()
        else:
            with pytest.raises(error):
                await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert await snapshot(db, *ticket_ids) == before
    return result


# ---------------------------------------------------------------------------
# Expected events (ticket-audit-log.md, Event Type Contract)
# ---------------------------------------------------------------------------


def package_added_event(
    package_name: str,
    actor: User | None = None,
    comment: PackageAddedComment | None = None,
) -> EventRow:
    """The invocation-level `package_added`: the acting user and `NULL`
    comment for a user-facing addition, `NULL` and the exact canonical
    comment for an automatic one; `new_value` the package name."""
    return EventRow(
        "package_added",
        actor.id if actor else None,
        None,
        package_name,
        None if actor else comment,
        None,
    )


def maintainer_event(package_name: str, user: User) -> EventRow:
    """The system `package_maintainer_added` of one new association:
    `new_value` the event-time username, `comment` `NULL`, and
    `detail = {"package": package_name}`."""
    return EventRow(
        "package_maintainer_added",
        None,
        None,
        user.username,
        None,
        {"package": package_name},
    )
