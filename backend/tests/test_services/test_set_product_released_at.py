"""Single-session service integration tests for `set_product_released_at()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (Transaction ownership;
  Semantic locators and locked ownership validation;
  `set_product_released_at()`; Concurrency Control (the Ticket lock is
  compatible when the caller already holds it); Service Exceptions;
  Excluded and Non-Actionable Records; Architectural Test Requirement:
  Forward transitions, Nested ownership validation, Human-readable Product
  audit subjects, Product release composition (repeated calls), Dimension
  independence (Product release part)).
- docs/features/packages/package-model.md (Product Release Confirmation;
  Ticket Lifecycle Integration).
- docs/features/tickets/tickets.md (Gate: Analyzed -> Resolved, clause
  (b)).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `product_released`; Rules (effective NULL-to-timestamp only; Product
  subject fields are event-time snapshots); detail JSONB Schema Contract;
  Testing Requirements 1-9).
- docs/features/platform/testing-strategy.md (Audit Trail Testing; Service
  Functions; Rollback Within a Test).
- docs/conventions.md (Timestamps & Timezones).

Independent-session behavior (committed atomicity and lock serialization)
is covered by `tests/test_services/test_set_product_released_at_atomicity.py`.

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High` and each factory-built track carries Products in
General Support on `EVAL`. The service captures its one UTC evaluation
date from `package_service._utc_today()`, which every test pins to `EVAL`.
Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from unittest.mock import Mock

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Scope,
    Severity,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service
from app.services.package_service import (
    MutationOutcome,
    PackageNotFoundError,
    ProductNotFoundError,
    ProductReleasedResult,
    TrackNotFoundError,
    set_product_released_at,
)
from app.services.ticket_audit_log import list_ticket_events
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.database import rollback_test_scope
from tests.support.product_eligibility import (
    occurrence_path,
    only_occurrence,
    persisted_occurrence,
    product_subject,
    track_occurrences,
)
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    RELEASED_AT,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
    status_event,
    ticket_events,
    tree_for,
)
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

Factory = Callable[..., Awaitable[Any]]

ADVISORY = "SUSE-SU-2024:0815-1"
"""A fictional validated advisory identifier."""

ISSUED = datetime(2024, 3, 1, 12, 0, tzinfo=UTC)
"""A retroactive advisory-issued instant (ticket-audit-log.md, Testing
Requirement 9: retroactive advisory dates)."""

ISSUED_Z = "2024-03-01T12:00:00Z"
"""`ISSUED` in UTC ISO 8601 with the `Z` suffix."""

NEXT_DAY = EVAL + timedelta(days=1)


@pytest.fixture(autouse=True)
def controlled_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the service's one UTC evaluation date to `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _release(
    db: AsyncSession,
    occurrence: TicketPackageProduct,
    released_at: datetime = ISSUED,
    *,
    ticket_id: uuid.UUID | None = None,
    package_id: uuid.UUID | None = None,
    track_id: uuid.UUID | None = None,
    occurrence_id: uuid.UUID | None = None,
    advisory_id: str = ADVISORY,
) -> ProductReleasedResult:
    """Call the service as the release detector would, for `occurrence`'s
    own path unless a locator level is overridden."""
    own_ticket, own_package, own_track = await occurrence_path(db, occurrence)
    return await set_product_released_at(
        db,
        ticket_id=own_ticket if ticket_id is None else ticket_id,
        package_id=own_package if package_id is None else package_id,
        track_id=own_track if track_id is None else track_id,
        ticket_package_product_id=(
            occurrence.id if occurrence_id is None else occurrence_id
        ),
        released_at=released_at,
        advisory_id=advisory_id,
    )


async def _released_at(
    db: AsyncSession, occurrence: TicketPackageProduct
) -> datetime | None:
    """The persisted `released_at` of an occurrence (a column read, never
    the identity-map copy)."""
    return (
        await db.execute(
            select(TicketPackageProduct.released_at).where(
                TicketPackageProduct.id == occurrence.id
            )
        )
    ).scalar_one()


async def _released_event(
    db: AsyncSession,
    occurrence: TicketPackageProduct,
    new_value: str = ISSUED_Z,
    advisory_id: str = ADVISORY,
) -> EventRow:
    """The system `product_released` event: `old_value` and `comment`
    `NULL`, the UTC `Z` instant, and the Product subject plus
    `advisory_id`."""
    return EventRow(
        "product_released",
        None,
        None,
        new_value,
        None,
        {**await product_subject(db, occurrence), "advisory_id": advisory_id},
    )


async def _assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[ProductReleasedResult]],
    *,
    tickets: tuple[Ticket, ...],
    occurrences: tuple[TicketPackageProduct, ...],
    error: type[Exception] | None = None,
) -> ProductReleasedResult | None:
    """Run the call and assert the zero-side-effect contract: no write, no
    assignment, no reconciliation, no registered convergence effect, and
    unchanged Ticket status, assignee, and events and occurrence
    `released_at`, eligibility, and override marker for every given
    Ticket and occurrence. Returns the result of a non-raising call."""

    async def snapshot() -> tuple[Any, ...]:
        return (
            [await ticket_state(db, t) for t in tickets],
            [await ticket_events(db, t) for t in tickets],
            [await _released_at(db, o) for o in occurrences],
            [await persisted_occurrence(db, o) for o in occurrences],
        )

    before = await snapshot()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: ProductReleasedResult | None = None

    with StatementRecorder(db) as recorder:
        if error is None:
            result = await run()
        else:
            with pytest.raises(error):
                await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await snapshot() == before
    return result


async def _cve_ticket(
    ticket_factory: TicketFactory,
    cve_with: CVEBuilder,
    *,
    status: TicketStatus = TicketStatus.ANALYZED,
    **overrides: Any,
) -> Ticket:
    """A CVE-associated Ticket satisfying the Analyzed gate inputs: CVE
    severity High and a SUSE assessment at the default version (tickets.md,
    Gate: Analysis -> Analyzed, conditions 3 and 4)."""
    cve = await cve_with(Assessment("9.8"), severity=Severity.HIGH)
    return await ticket_factory(status=status.value, cve_id=cve.id, **overrides)


# ---------------------------------------------------------------------------
# Effective release (package-service.md, `set_product_released_at()`
# steps 5-8; conventions.md, Timestamps & Timezones)
# ---------------------------------------------------------------------------

INSTANTS = [
    # (supplied aware instant, stored UTC instant, audit `new_value`)
    pytest.param(ISSUED, ISSUED, ISSUED_Z, id="utc"),
    pytest.param(
        datetime(2024, 3, 1, 14, 0, tzinfo=timezone(timedelta(hours=2))),
        ISSUED,
        ISSUED_Z,
        id="plus-0200",
    ),
    pytest.param(
        datetime(2024, 2, 29, 22, 30, tzinfo=timezone(-timedelta(hours=5, minutes=30))),
        datetime(2024, 3, 1, 4, 0, tzinfo=UTC),
        "2024-03-01T04:00:00Z",
        id="minus-0530-crossing-the-utc-date",
    ),
]


@pytest.mark.integration
class TestEffectiveRelease:
    """package-service.md, `set_product_released_at()` steps 5-8 and Q4;
    ticket-audit-log.md, Event Type Contract `product_released` and Testing
    Requirements 1-7 and 9 (`new_value` equals the actual persisted
    `released_at`, including retroactive advisory dates)."""

    @pytest.mark.parametrize(("supplied", "stored", "new_value"), INSTANTS)
    async def test_release_persists_the_utc_instant_with_one_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        supplied: datetime,
        stored: datetime,
        new_value: str,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        result = await _release(db_session, occurrence, supplied)

        assert (result.outcome, result.ticket_package_product_id) == (
            MutationOutcome.CHANGED,
            occurrence.id,
        )
        assert result.released_at == stored
        assert result.released_at.utcoffset() == timedelta(0)
        persisted = await _released_at(db_session, occurrence)
        assert persisted == stored
        assert persisted is not None
        assert persisted.utcoffset() == timedelta(0)
        db_session.expire(occurrence)
        await db_session.refresh(occurrence)
        assert occurrence.released_at == stored
        events = await ticket_events(db_session, ticket)
        assert events == [await _released_event(db_session, occurrence, new_value)]
        assert events[0].new_value is not None
        assert datetime.fromisoformat(events[0].new_value) == persisted

    async def test_function_flushes_and_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """package-service.md, Transaction ownership and step 8: the
        occurrence UPDATE and the event INSERT reach the database inside the
        call, nothing is left pending, and no commit is issued; the caller's
        rollback therefore removes the release and its event
        (ticket-audit-log.md, Testing Requirement 7)."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        commits: list[object] = []

        async with rollback_test_scope(db_session):
            original_commit = db_session.commit

            async def commit() -> None:
                commits.append(object())
                await original_commit()

            monkeypatch.setattr(db_session, "commit", commit)
            with StatementRecorder(db_session) as recorder:
                result = await _release(db_session, occurrence)

            writes = recorder.writes()
            assert any(
                s.lstrip().startswith("UPDATE ticket_package_product ") for s in writes
            )
            assert any(
                s.lstrip().startswith("INSERT INTO ticket_audit_event") for s in writes
            )
            assert (len(db_session.new), len(db_session.dirty)) == (0, 0)
            assert result.outcome is MutationOutcome.CHANGED
            assert commits == []
            monkeypatch.undo()
        await db_session.refresh(ticket)
        await db_session.refresh(occurrence)

        assert await _released_at(db_session, occurrence) is None
        assert await ticket_events(db_session, ticket) == []

    async def test_caller_already_holding_the_ticket_lock_is_compatible(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-service.md, `set_product_released_at()` Q2: the Ticket
        `FOR UPDATE` is compatible when the caller already holds it."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        await lock_ticket(db_session, ticket)

        result = await _release(db_session, occurrence)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _released_at(db_session, occurrence) == ISSUED


# ---------------------------------------------------------------------------
# Audit payload (ticket-audit-log.md, `product_released`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditPayload:
    """ticket-audit-log.md, Event Type Contract `product_released` (system
    `user_id`, `old_value` and `comment` `NULL`), detail JSONB Schema
    Contract (exactly `track`, `package`, `product_name`, `product_cpe`,
    `advisory_id`; `product_name` is `Product.display_name`, never
    `Product.name`; no internal UUID), the rule "Product subject fields are
    event-time snapshots", and Testing Requirements 6 and 8; package-service.md,
    Architectural Test Requirement: Human-readable Product audit subjects."""

    @staticmethod
    async def _occurrence(
        ticket: Ticket,
        *,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> tuple[Product, TicketPackageProduct]:
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-libwidget"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Distro:15-SP9:Update",
            status=PackageStatus.FIXED.value,
        )
        product = await product_factory(
            name="exwidget-server",
            display_name="Example Widget Server 15 SP9",
            cpe="cpe:/o:example:widget_server:15:sp9",
            general_support_end_date=AFTER_EVAL,
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        return product, occurrence

    async def test_event_has_exact_literal_payload(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        ticket = await cveless(ticket_factory)
        product, occurrence = await self._occurrence(
            ticket,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )

        await _release(db_session, occurrence, advisory_id="SUSE-SU-2024:4242-1")

        events = await ticket_events(db_session, ticket)
        released = [e for e in events if e.event_type == "product_released"]
        assert released == [
            EventRow(
                "product_released",
                None,
                None,
                ISSUED_Z,
                None,
                {
                    "track": "Example:Distro:15-SP9:Update",
                    "package": "example-libwidget",
                    "product_name": "Example Widget Server 15 SP9",
                    "product_cpe": "cpe:/o:example:widget_server:15:sp9",
                    "advisory_id": "SUSE-SU-2024:4242-1",
                },
            )
        ]
        serialized = json.dumps(released[0].detail)
        for internal in (occurrence.id, product.id, ticket.id):
            assert str(internal) not in serialized
        assert "exwidget-server" not in serialized

    async def test_subject_is_an_event_time_snapshot(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """A later catalog rename of the Product does not change the stored
        subject: audit reads never join current Product data."""
        ticket = await cveless(ticket_factory)
        product, occurrence = await self._occurrence(
            ticket,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        await _release(db_session, occurrence)
        before = await ticket_events(db_session, ticket)

        await db_session.execute(
            update(Product)
            .where(Product.id == product.id)
            .values(
                display_name="Example Widget Server 15 SP9 Renamed",
                cpe="cpe:/o:example:widget_server_renamed:15:sp9",
            )
        )

        after = await ticket_events(db_session, ticket)
        assert after == before
        assert [e.detail for e in after if e.event_type == "product_released"] == [
            {
                "track": "Example:Distro:15-SP9:Update",
                "package": "example-libwidget",
                "product_name": "Example Widget Server 15 SP9",
                "product_cpe": "cpe:/o:example:widget_server:15:sp9",
                "advisory_id": ADVISORY,
            }
        ]

    @pytest.mark.parametrize(
        "term", ["Widget Server 15 SP9", "cpe:/o:example:widget_server:15:sp9"]
    )
    async def test_event_is_searchable_by_product_name_and_cpe(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        term: str,
    ) -> None:
        """ticket-audit-log.md, Testing Requirement 8 (searchable by both
        event-time values). The reader is an unrelated VA with scope
        `all`."""
        reader = await va_user()
        ticket = await cveless(ticket_factory)
        await db_session.refresh(ticket, ["sequence_id"])
        _, occurrence = await self._occurrence(
            ticket,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        await _release(db_session, occurrence)

        page = await list_ticket_events(
            db_session,
            ticket_id=format_ticket_id(ticket.sequence_id),
            caller=TicketCaller.authenticated(reader.id, Scope.ALL),
            search=term,
        )

        assert [(e.event_type, e.new_value) for e in page.items] == [
            ("product_released", ISSUED_Z)
        ]


# ---------------------------------------------------------------------------
# Caller contract (package-service.md, `set_product_released_at()` Q6)
# ---------------------------------------------------------------------------


class _NoOffset(tzinfo):
    """A `tzinfo` whose offset is unknown: the datetime is naive."""

    def utcoffset(self, dt: datetime | None, /) -> timedelta | None:
        return None

    def dst(self, dt: datetime | None, /) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None, /) -> str | None:
        return None


@pytest.mark.integration
class TestNaiveInstant:
    """package-service.md, `set_product_released_at()` Q6: a naive
    `released_at` raises `ValueError` before any database operation;
    conventions.md, Timestamps & Timezones (naive timestamps are
    ambiguous)."""

    @pytest.mark.parametrize(
        "released_at",
        [
            pytest.param(
                datetime(2024, 3, 1, 12, 0),  # noqa: DTZ001 - naive input under test
                id="no-tzinfo",
            ),
            pytest.param(
                datetime(2024, 3, 1, 12, 0, tzinfo=_NoOffset()), id="unknown-offset"
            ),
        ],
    )
    async def test_naive_instant_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        released_at: datetime,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        ticket_id, package_id, track_id = await occurrence_path(db_session, occurrence)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="timezone-aware"),
        ):
            await set_product_released_at(
                db_session,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                ticket_package_product_id=occurrence.id,
                released_at=released_at,
                advisory_id=ADVISORY,
            )

        assert recorder.statements == []
        assert reconcile.calls == []
        assert await _released_at(db_session, occurrence) is None
        assert await ticket_events(db_session, ticket) == []
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)


# ---------------------------------------------------------------------------
# Irreversible no-op and no auto-assignment
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIrreversibleNoOp:
    """package-service.md, `set_product_released_at()` step 4,
    Idempotency, Irreversibility, and Callers (no auto-assignment);
    ticket-audit-log.md, Rules (idempotent no-op outcomes create no event)
    and Testing Requirement 12."""

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(RELEASED_AT - timedelta(days=30), id="earlier-instant"),
            pytest.param(RELEASED_AT + timedelta(days=30), id="later-instant"),
            pytest.param(RELEASED_AT, id="same-instant"),
        ],
    )
    async def test_released_occurrence_is_an_irreversible_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        requested: datetime,
    ) -> None:
        """The stale `Analyzed` status of an unassigned Ticket whose only
        track is in `ANALYSIS` would be corrected by any reconciliation."""
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)
        track = await tree(
            ticket, status=PackageStatus.ANALYSIS, products=(Prod(released=True),)
        )
        occurrence = await only_occurrence(db_session, track)

        result = await _assert_no_effects(
            db_session,
            monkeypatch,
            lambda: _release(db_session, occurrence, requested),
            tickets=(ticket,),
            occurrences=(occurrence,),
        )

        assert result is not None
        assert (result.outcome, result.ticket_package_product_id) == (
            MutationOutcome.NO_OP,
            occurrence.id,
        )
        assert result.released_at == RELEASED_AT
        assert await _released_at(db_session, occurrence) == RELEASED_AT
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYZED, None)
        assert await ticket_events(db_session, ticket) == []

    async def test_repeated_call_keeps_the_first_instant_and_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """package-service.md, Q5 and Architectural Test Requirement: Product
        release composition (a repeated call preserves the first timestamp
        without another event or reconciliation)."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _release(db_session, occurrence, ISSUED)
        second = await _release(
            db_session,
            occurrence,
            ISSUED + timedelta(days=2),
            advisory_id="SUSE-SU-2024:0816-1",
        )

        assert (first.outcome, second.outcome) == (
            MutationOutcome.CHANGED,
            MutationOutcome.NO_OP,
        )
        assert second.released_at == ISSUED
        assert await _released_at(db_session, occurrence) == ISSUED
        assert len(reconcile.calls) == 1
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, occurrence)
        ]

    @pytest.mark.parametrize("assigned", [False, True], ids=["unassigned", "assigned"])
    async def test_effective_release_never_assigns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        assigned: bool,
    ) -> None:
        """An unassigned Ticket stays unassigned and an assigned one keeps
        its active VA assignee: the system boundary has no actor."""
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory, assignee_id=assignee.id if assigned else None
        )
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        assign = Spy(monkeypatch, "auto_assign_actor")

        result = await _release(db_session, occurrence)

        assert result.outcome is MutationOutcome.CHANGED
        assert assign.calls == []
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            assignee.id if assigned else None,
        )
        assert [e.event_type for e in await ticket_events(db_session, ticket)] == [
            "product_released"
        ]


# ---------------------------------------------------------------------------
# Nested ownership validation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNestedOwnership:
    """package-service.md, Semantic locators and locked ownership
    validation, `set_product_released_at()` Preconditions and step 3,
    Service Exceptions, and Architectural Test Requirement: Nested
    ownership validation and Public Product identity
    (`ticket_package_product_id` is the package-tree occurrence, never the
    catalog `Product.id`). A mismatch never mutates or reveals the
    occurrence under the other path."""

    @staticmethod
    async def _world(
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        db: AsyncSession,
    ) -> dict[str, Any]:
        ticket = await cveless(ticket_factory)
        other_ticket = await cveless(ticket_factory)
        own_track = await tree(ticket, status=PackageStatus.ANALYSIS)
        own = await only_occurrence(db, own_track)
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=own_track.ticket_package_id,
            status=PackageStatus.ANALYSIS.value,
        )
        sibling_product = await product_factory(general_support_end_date=AFTER_EVAL)
        same_package = await ticket_package_product_factory(
            ticket_package_track_id=sibling_track.id, product_id=sibling_product.id
        )
        other_package_track = await tree(ticket, status=PackageStatus.ANALYSIS)
        other_package = await only_occurrence(db, other_package_track)
        foreign_track = await tree(other_ticket, status=PackageStatus.ANALYSIS)
        foreign = await only_occurrence(db, foreign_track)
        return {
            "ticket": ticket,
            "other_ticket": other_ticket,
            "own_track": own_track,
            "own": own,
            "same_package": same_package,
            "other_package_track": other_package_track,
            "other_package": other_package,
            "foreign_track": foreign_track,
            "foreign": foreign,
        }

    @pytest.mark.parametrize(
        ("case", "error"),
        [
            ("missing-package", PackageNotFoundError),
            ("package-of-other-ticket", PackageNotFoundError),
            ("missing-track", TrackNotFoundError),
            ("track-of-other-package", TrackNotFoundError),
            ("missing-occurrence", ProductNotFoundError),
            ("occurrence-of-sibling-track", ProductNotFoundError),
            ("occurrence-of-other-package", ProductNotFoundError),
            ("occurrence-of-other-ticket", ProductNotFoundError),
            ("catalog-product-id", ProductNotFoundError),
        ],
    )
    async def test_mismatched_path_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        error: type[Exception],
    ) -> None:
        w = await self._world(
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
            db_session,
        )
        own_track: TicketPackageTrack = w["own_track"]
        foreign_track: TicketPackageTrack = w["foreign_track"]
        other_track: TicketPackageTrack = w["other_package_track"]
        own = (own_track.ticket_package_id, own_track.id, w["own"].id)
        # (package_id, track_id, ticket_package_product_id) under the own
        # Ticket; a mismatched level names an existing record elsewhere.
        package_id, track_id, occurrence_id = {
            "missing-package": (uuid.uuid4(), own[1], own[2]),
            "package-of-other-ticket": (
                foreign_track.ticket_package_id,
                foreign_track.id,
                w["foreign"].id,
            ),
            "missing-track": (own[0], uuid.uuid4(), own[2]),
            "track-of-other-package": (own[0], other_track.id, w["other_package"].id),
            "missing-occurrence": (own[0], own[1], uuid.uuid4()),
            "occurrence-of-sibling-track": (own[0], own[1], w["same_package"].id),
            "occurrence-of-other-package": (own[0], own[1], w["other_package"].id),
            "occurrence-of-other-ticket": (own[0], own[1], w["foreign"].id),
            "catalog-product-id": (own[0], own[1], w["own"].product_id),
        }[case]

        await _assert_no_effects(
            db_session,
            monkeypatch,
            lambda: _release(
                db_session,
                w["own"],
                ticket_id=w["ticket"].id,
                package_id=package_id,
                track_id=track_id,
                occurrence_id=occurrence_id,
            ),
            tickets=(w["ticket"], w["other_ticket"]),
            occurrences=(w["own"], w["same_package"], w["other_package"], w["foreign"]),
            error=error,
        )

    async def test_correct_path_releases_only_the_declared_occurrence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        w = await self._world(
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
            db_session,
        )
        own: TicketPackageProduct = w["own"]

        result = await _release(db_session, own)

        assert (result.outcome, result.ticket_package_product_id) == (
            MutationOutcome.CHANGED,
            own.id,
        )
        assert [
            await _released_at(db_session, w[name])
            for name in ("own", "same_package", "other_package", "foreign")
        ] == [ISSUED, None, None, None]
        assert await ticket_events(db_session, w["ticket"]) == [
            await _released_event(db_session, own)
        ]
        assert await ticket_events(db_session, w["other_ticket"]) == []

    async def test_missing_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        await _assert_no_effects(
            db_session,
            monkeypatch,
            lambda: _release(db_session, occurrence, ticket_id=uuid.uuid4()),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotFoundError,
        )


# ---------------------------------------------------------------------------
# Ticket-level operability
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOperability:
    """package-service.md, `set_product_released_at()` Preconditions and
    step 2 and Ticket-level operability: release detection does not apply
    to `Ignored` or `Duplicated` Tickets, and operability precedes the
    locked path reload and the no-op classification; every operable status,
    `Resolved` included, is accepted."""

    @pytest.mark.parametrize(
        "zone", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    @pytest.mark.parametrize(
        "case", ["effective", "missing-occurrence", "already-released"]
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        case: str,
    ) -> None:
        """A missing occurrence raises `TicketNotMutableError`, not
        `ProductNotFoundError`; an already released occurrence is rejected
        rather than classified as a no-op."""
        ticket = await cveless(ticket_factory, status=zone)
        track = await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(released=case == "already-released"),),
        )
        occurrence = await only_occurrence(db_session, track)
        missing = case == "missing-occurrence"

        await _assert_no_effects(
            db_session,
            monkeypatch,
            lambda: _release(
                db_session,
                occurrence,
                occurrence_id=uuid.uuid4() if missing else None,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotMutableError,
        )

    @pytest.mark.parametrize(
        ("status", "track_status"),
        [
            (TicketStatus.NEW, PackageStatus.ANALYSIS),
            (TicketStatus.ANALYSIS, PackageStatus.ANALYSIS),
            (TicketStatus.ANALYZED, PackageStatus.AFFECTED),
            (TicketStatus.RESOLVED, PackageStatus.NOT_AFFECTED),
        ],
        ids=lambda value: str(value),
    )
    async def test_operable_ticket_is_released(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        track_status: PackageStatus,
    ) -> None:
        """Each tree keeps its seeded gate result: a `New` Ticket is outside
        the gate zone (ticket-mutations.md, `reconcile_ticket_status()` step
        1), and a released Product changes neither an `ANALYSIS`, an
        `AFFECTED` (clause (c)), nor a `NOT_AFFECTED` (clause (a)) track."""
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket, status=track_status)
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _release(db_session, occurrence)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _released_at(db_session, occurrence) == ISSUED
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket) == (status, None)
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, occurrence)
        ]


# ---------------------------------------------------------------------------
# Excluded, EOL, and ineligible occurrences are released
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNonActionableOccurrences:
    """package-service.md, `set_product_released_at()` Preconditions (no
    precondition on `deleted_at`; soft-deleted products are included) and
    Excluded and Non-Actionable Records (manually excluded and EOL records
    remain current with reality); package-model.md, Product Release
    Confirmation. Eligibility and overrides are not release inputs.

    A second actionable `ANALYSIS` track anchors the Ticket in `Analysis`,
    so no gate event follows the release."""

    @pytest.mark.parametrize(
        ("spec", "track_excluded", "package_excluded"),
        [
            pytest.param(Prod(excluded=True), False, False, id="product-excluded"),
            pytest.param(Prod(), True, False, id="track-excluded"),
            pytest.param(Prod(), False, True, id="package-excluded"),
            pytest.param(Prod(excluded=True), True, True, id="every-level-excluded"),
            pytest.param(Prod(eol=True), False, False, id="eol"),
            pytest.param(Prod(lifecycle=False), False, False, id="no-lifecycle-data"),
            pytest.param(Prod(eligible=False), False, False, id="ineligible"),
            pytest.param(
                Prod(eligible=False, override=True),
                False,
                False,
                id="overridden-ineligible",
            ),
            pytest.param(
                Prod(eligible=True, override=True),
                False,
                False,
                id="overridden-eligible",
            ),
        ],
    )
    async def test_non_actionable_occurrence_is_released_with_its_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        spec: Prod,
        track_excluded: bool,
        package_excluded: bool,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(spec,),
            track_excluded=track_excluded,
            package_excluded=package_excluded,
        )
        await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _release(db_session, occurrence)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _released_at(db_session, occurrence) == ISSUED
        assert await persisted_occurrence(db_session, occurrence) == (
            spec.eligible,
            spec.override,
        )
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, occurrence)
        ]


# ---------------------------------------------------------------------------
# Reconciliation with the one evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReconciliation:
    """package-service.md, `set_product_released_at()` step 7 (one
    `reconcile_ticket_status()` call for an effective release) and Derived
    actionability (one UTC evaluation date, captured once, including a
    workflow that crosses midnight UTC)."""

    @pytest.mark.parametrize(
        "clock",
        [
            pytest.param([EVAL], id="single-reading"),
            pytest.param([EVAL, NEXT_DAY], id="crossing-midnight"),
        ],
    )
    async def test_effective_release_reconciles_once_with_the_captured_date(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        clock: list[Any],
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await _release(db_session, occurrence)

        assert utc_today.call_count == 1
        assert [(args[0].id, args[1], kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, db_session, {"evaluation_date": EVAL})
        ]


# ---------------------------------------------------------------------------
# Forward transitions through reconciliation
# ---------------------------------------------------------------------------

SIBLINGS = [
    # (other occurrences of the released track, expected Ticket status)
    pytest.param((), TicketStatus.RESOLVED, id="only-product"),
    pytest.param((Prod(released=True),), TicketStatus.RESOLVED, id="sibling-released"),
    pytest.param(
        (Prod(eligible=False),), TicketStatus.RESOLVED, id="sibling-ineligible"
    ),
    pytest.param((Prod(eol=True),), TicketStatus.RESOLVED, id="sibling-eol"),
    pytest.param((Prod(excluded=True),), TicketStatus.RESOLVED, id="sibling-excluded"),
    pytest.param((Prod(),), TicketStatus.ANALYZED, id="sibling-unreleased-eligible"),
]
"""tickets.md, Gate: Analyzed -> Resolved clause (b): a `FIXED` track of a
CVE-associated Ticket is resolution-complete when every actionable eligible
Product is released. Ineligible, EOL, and excluded siblings are outside
`AEP(t)`; an actionable eligible unreleased sibling keeps the track
incomplete."""


@pytest.mark.integration
class TestForwardTransitions:
    """package-service.md, Architectural Test Requirement: Forward
    transitions; package-model.md, Ticket Lifecycle Integration (Analyzed ->
    Resolved, clause (b)); ticket-audit-log.md, Cross-Event Ordering (the
    final gate `status_change` is last). The Ticket is unassigned and stays
    unassigned."""

    @pytest.mark.parametrize(("siblings", "expected"), SIBLINGS)
    async def test_release_of_the_last_unreleased_product_resolves(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        siblings: tuple[Prod, ...],
        expected: TicketStatus,
    ) -> None:
        ticket = await _cve_ticket(ticket_factory, cve_with)
        track = await tree(
            ticket, status=PackageStatus.FIXED, products=(Prod(), *siblings)
        )
        # Occurrence ids are UUIDv7, so the first is the target `Prod()`.
        target = (await track_occurrences(db_session, track))[0]
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _release(db_session, target)

        assert result.outcome is MutationOutcome.CHANGED
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket) == (expected, None)
        gate = (
            [status_event(TicketStatus.ANALYZED, TicketStatus.RESOLVED)]
            if expected is TicketStatus.RESOLVED
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, target),
            *gate,
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unreleased_product_of_another_fixed_track_keeps_analyzed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        ticket = await _cve_ticket(ticket_factory, cve_with)
        track = await tree(ticket, status=PackageStatus.FIXED)
        await tree(ticket, status=PackageStatus.FIXED)
        occurrence = await only_occurrence(db_session, track)

        await _release(db_session, occurrence)

        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYZED, None)
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, occurrence)
        ]

    async def test_releasing_both_tracks_resolves_on_the_second(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        ticket = await _cve_ticket(ticket_factory, cve_with)
        first = await only_occurrence(
            db_session, await tree(ticket, status=PackageStatus.FIXED)
        )
        second = await only_occurrence(
            db_session, await tree(ticket, status=PackageStatus.FIXED)
        )

        await _release(db_session, first)
        await _release(db_session, second, ISSUED + timedelta(hours=1))

        assert await ticket_state(db_session, ticket) == (TicketStatus.RESOLVED, None)
        assert await ticket_events(db_session, ticket) == [
            await _released_event(db_session, first),
            await _released_event(db_session, second, "2024-03-01T13:00:00Z"),
            status_event(TicketStatus.ANALYZED, TicketStatus.RESOLVED),
        ]


# ---------------------------------------------------------------------------
# Dimension independence (Product release part)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDimensionIndependence:
    """package-service.md, Architectural Test Requirement: Dimension
    independence (a Product release observation does not mutate
    affectedness, eligibility, or track delivery); package-model.md, Three
    Orthogonal Dimensions and Product Release Confirmation."""

    @pytest.mark.parametrize(
        "delivery", [DeliveryStatus.PENDING, DeliveryStatus.IN_PROGRESS], ids=str
    )
    async def test_release_changes_only_the_release_timestamp(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        delivery: DeliveryStatus,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(
                Prod(),
                Prod(eligible=False),
                Prod(eligible=False, override=True),
                Prod(eligible=True, override=True),
            ),
        )
        await db_session.execute(
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=delivery.value)
        )
        occurrences = await track_occurrences(db_session, track)
        target = occurrences[0]
        eligibility_before = [
            await persisted_occurrence(db_session, o) for o in occurrences
        ]

        await _release(db_session, target)

        row = (
            await db_session.execute(
                select(
                    TicketPackageTrack.status, TicketPackageTrack.delivery_status
                ).where(TicketPackageTrack.id == track.id)
            )
        ).one()
        assert (row.status, row.delivery_status) == (
            PackageStatus.FIXED.value,
            delivery.value,
        )
        assert [
            await persisted_occurrence(db_session, o) for o in occurrences
        ] == eligibility_before
        assert [await _released_at(db_session, o) for o in occurrences] == [
            ISSUED,
            None,
            None,
            None,
        ]


# ---------------------------------------------------------------------------
# Audit-history independence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoAuditHistoryRead:
    """package-service.md, `set_product_released_at()` (never reads audit
    history); testing-strategy.md, Audit Trail Testing (audit history is
    never queried to determine current state or idempotency). An effective
    call only inserts into `ticket_audit_event`; a no-op never touches
    it."""

    @pytest.mark.parametrize(
        ("released", "outcome"),
        [(False, MutationOutcome.CHANGED), (True, MutationOutcome.NO_OP)],
        ids=["effective", "no-op"],
    )
    async def test_call_never_selects_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        released: bool,
        outcome: MutationOutcome,
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        track = await tree(
            ticket, status=PackageStatus.FIXED, products=(Prod(released=released),)
        )
        occurrence = await only_occurrence(db_session, track)
        ticket_id, package_id, track_id = await occurrence_path(db_session, occurrence)

        with StatementRecorder(db_session) as recorder:
            result = await set_product_released_at(
                db_session,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                ticket_package_product_id=occurrence.id,
                released_at=ISSUED,
                advisory_id=ADVISORY,
            )

        assert result.outcome is outcome
        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert recorder.selects_from("ticket_audit_event") == []
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []
        assert bool(audit) is (outcome is MutationOutcome.CHANGED)
