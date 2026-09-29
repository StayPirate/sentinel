"""Single-session service integration tests for `mark_as_duplicate()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; `mark_as_duplicate`; Service
  Exceptions; Architectural Test Requirement 4 (`mark_as_duplicate()`
  path, in `tests/test_services/test_new_to_analysis_promotion.py`), 5,
  and 15 (single-session part)).
- docs/features/tickets/tickets.md (Status Transitions, including the
  VA/non-VA note after the matrix; Auto-Assignment on Unassigned Tickets;
  Duplicate Handling; Identifier Disclosure Boundary).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`, `assignment`, `duplicate_set`,
  `duplicate_target_changed`; Canonical Mutation and No-Event Matrix:
  Ignore, mark duplicate, reopen, or revert duplicate; Cross-Event
  Ordering, Locking, and Rollback; Testing Requirements 1-7 and 22).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Audit Trail Testing, What to Assert).

Architectural Test Requirement 6 (the `NOWAIT` conflict with a dependent
locked by another transaction, mapped to
`DuplicateConcurrentModificationError`) and the independent-session races
(audit Testing Requirement 23, locked-current accessibility of both
ordered roots) need independent sessions and are owned by a separate
atomicity module; one shared session cannot hold a conflicting lock.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15. The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; `mark_as_duplicate()`
changes only statuses, duplicate links, and, through auto-assignment,
`assignee_id`, so it cannot remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketAuditEventType, TicketStatus
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    DuplicateTargetIsDuplicatedError,
    SelfDuplicateError,
    get_ticket_detail,
    mark_as_duplicate,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    status_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""

State = tuple[str, uuid.UUID | None, uuid.UUID | None]
"""The persisted `(status, duplicate_of_id, assignee_id)` of a Ticket."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sntl(ticket: Ticket) -> str:
    """The public `SNTL-{n}` identifier (tickets.md, SNTL-{n} Format)."""
    return f"SNTL-{ticket.sequence_id}"


def _duplicated(actor: User, old: TicketStatus) -> EventRow:
    """The acting-user `{current} -> Duplicated` `status_change`."""
    return EventRow(
        "status_change",
        actor.id,
        old.value,
        TicketStatus.DUPLICATED.value,
        None,
        None,
    )


def _duplicate_set(actor: User, target: Ticket) -> EventRow:
    """ticket-audit-log.md, Event Type Contract: `duplicate_set`."""
    return EventRow("duplicate_set", actor.id, None, _sntl(target), None, None)


def _retargeted(source: Ticket, target: Ticket) -> EventRow:
    """ticket-audit-log.md, Event Type Contract: the system
    `duplicate_target_changed` of one repointed dependent."""
    return EventRow(
        "duplicate_target_changed",
        None,
        _sntl(source),
        _sntl(target),
        None,
        {"triggered_by_ticket": _sntl(source)},
    )


def _assignment(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def _mark(
    db: AsyncSession,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call the service as an API handler would."""
    return await mark_as_duplicate(
        db,
        ticket_id=source_id,
        duplicate_of_id=target_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _states(
    db: AsyncSession, ticket_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, State]:
    """The persisted state of every existing Ticket among `ticket_ids`."""
    rows = await db.execute(
        select(
            Ticket.id, Ticket.status, Ticket.duplicate_of_id, Ticket.assignee_id
        ).where(Ticket.id.in_(list(ticket_ids)))
    )
    return {r.id: (r.status, r.duplicate_of_id, r.assignee_id) for r in rows}


async def _events(
    db: AsyncSession, ticket_ids: Iterable[uuid.UUID]
) -> list[tuple[uuid.UUID, EventRow]]:
    """The audit events of the given Tickets, each with its Ticket UUID,
    in global insertion (UUIDv7 `id`) order."""
    rows = (
        await db.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(list(ticket_ids)))
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    return [
        (
            r.ticket_id,
            EventRow(
                r.event_type, r.user_id, r.old_value, r.new_value, r.comment, r.detail
            ),
        )
        for r in rows
    ]


def _ordered_ids(count: int) -> list[uuid.UUID]:
    """`count` fresh Ticket UUIDs in ascending order."""
    return sorted(uuid.uuid4() for _ in range(count))


class _Spy:
    """Wraps an async `ticket_service` attribute (the name imported from
    `ticket_mutations`), recording each call's arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    actor: User,
    scope: Scope = Scope.ALL,
    others: Iterable[uuid.UUID] = (),
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error before Phase 2 (no dependent lock),
    no write, no assignment, no reconciliation, no registered convergence
    effect, every involved Ticket unchanged, and no event on any of them."""
    involved = [source_id, target_id, *others]
    assign = _Spy(monkeypatch, "auto_assign_actor")
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    before = await _states(db, involved)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _mark(db, source_id, target_id, actor, scope=scope)

    assert [s for s in recorder.statements if "NOWAIT" in s] == []
    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await _states(db, involved) == before
    assert await _events(db, involved) == []


# ---------------------------------------------------------------------------
# Effective mark-as-duplicate
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMarkAsDuplicate:
    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
        ],
        ids=str,
    )
    async def test_operable_source_becomes_a_duplicate_of_the_target(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """tickets.md, Mark-as-Duplicate Operation: every operable status
        is a valid source. A non-VA actor is never assigned, so a `New`
        source records the direct `New -> Duplicated` (Status Transitions,
        note after the matrix). The entry never reconciles, registers a
        post-commit effect, or reads audit history."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        source = await ticket_factory(status=status.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _mark(
                db_session, source.id, target.id, actor, scope=Scope.NON_CONFIDENTIAL
            )

        assert result.id == source.id
        assert (result.status, result.duplicate_of_id) == (
            TicketStatus.DUPLICATED,
            target.id,
        )
        await db_session.flush()
        assert await _states(db_session, [source.id, target.id]) == {
            source.id: (TicketStatus.DUPLICATED, target.id, None),
            target.id: (TicketStatus.ANALYSIS, None, None),
        }
        assert await _events(db_session, [source.id, target.id]) == [
            (source.id, _duplicated(actor, status)),
            (source.id, _duplicate_set(actor, target)),
        ]
        assert reconcile.calls == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert recorder.selects_from("ticket_audit_event") == []

    async def test_va_actor_claims_an_unassigned_new_source_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """tickets.md, Auto-Assignment on Unassigned Tickets: `assignment`
        and the system `New -> Analysis` precede the acting-user
        `Analysis -> Duplicated` and `duplicate_set`."""
        actor = await va_user()
        source = await ticket_factory(status=TicketStatus.NEW.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)

        await _mark(db_session, source.id, target.id, actor)

        assert await _states(db_session, [source.id]) == {
            source.id: (TicketStatus.DUPLICATED, target.id, actor.id)
        }
        assert await _events(db_session, [source.id, target.id]) == [
            (source.id, _assignment(actor)),
            (source.id, PROMOTION),
            (source.id, _duplicated(actor, TicketStatus.ANALYSIS)),
            (source.id, _duplicate_set(actor, target)),
        ]

    async def test_ignored_target_is_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Only a `Duplicated` target is rejected (tickets.md, Duplicate
        Handling, Terminology: the target is any non-Duplicated Ticket).
        The already-assigned source keeps its assignee."""
        actor = await va_user()
        owner = await va_user()
        source = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=owner.id
        )
        target = await ticket_factory(status=TicketStatus.IGNORED.value)

        await _mark(db_session, source.id, target.id, actor)

        assert await _states(db_session, [source.id, target.id]) == {
            source.id: (TicketStatus.DUPLICATED, target.id, owner.id),
            target.id: (TicketStatus.IGNORED, None, None),
        }
        assert await _events(db_session, [source.id, target.id]) == [
            (source.id, _duplicated(actor, TicketStatus.ANALYZED)),
            (source.id, _duplicate_set(actor, target)),
        ]


# ---------------------------------------------------------------------------
# ATR 5: atomic repoint of dependents
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDependents:
    async def test_dependents_are_repointed_in_uuid_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Mark B as a duplicate of C while A1 and A2 point to B. The
        dependents are inserted in descending UUID order, so their events
        follow the locked UUID order rather than insertion order. Every
        link then points to the non-Duplicated C, and the flushed rows
        satisfy `chk_ticket_duplicate_status_coherence`."""
        actor = await va_user()
        owner = await va_user()
        low, high = _ordered_ids(2)
        b = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=owner.id
        )
        c = await ticket_factory(status=TicketStatus.ANALYZED.value)
        a_high = await ticket_factory(id=high, duplicate_of_id=b.id)
        a_low = await ticket_factory(id=low, duplicate_of_id=b.id)
        involved = [a_low.id, a_high.id, b.id, c.id]

        await _mark(db_session, b.id, c.id, actor)
        await db_session.flush()

        assert await _states(db_session, involved) == {
            a_low.id: (TicketStatus.DUPLICATED, c.id, None),
            a_high.id: (TicketStatus.DUPLICATED, c.id, None),
            b.id: (TicketStatus.DUPLICATED, c.id, owner.id),
            c.id: (TicketStatus.ANALYZED, None, None),
        }
        assert await _events(db_session, involved) == [
            (b.id, _duplicated(actor, TicketStatus.ANALYSIS)),
            (b.id, _duplicate_set(actor, c)),
            (a_low.id, _retargeted(b, c)),
            (a_high.id, _retargeted(b, c)),
        ]

    async def test_inaccessible_dependent_is_repointed_without_a_visibility_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ticket-service.md, `mark_as_duplicate` step 4e: dependents are a
        trusted system consequence of the authorized source mutation. The
        confidential dependent is invisible to the `non_confidential`
        caller."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        source = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        dependent = await ticket_factory(
            duplicate_of_id=source.id, is_confidential=True
        )

        await _mark(
            db_session, source.id, target.id, actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert await _states(db_session, [dependent.id]) == {
            dependent.id: (TicketStatus.DUPLICATED, target.id, None)
        }
        assert await _events(db_session, [dependent.id]) == [
            (dependent.id, _retargeted(source, target))
        ]


# ---------------------------------------------------------------------------
# Guards and their order, with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize("missing", ["source", "target"])
    async def test_missing_root_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        missing: str,
    ) -> None:
        actor = await va_user()
        existing = await ticket_factory(status=TicketStatus.NEW.value)
        absent = uuid.uuid7()
        source_id, target_id = (
            (absent, existing.id) if missing == "source" else (existing.id, absent)
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            source_id=source_id,
            target_id=target_id,
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("hidden", "source_status", "target_status"),
        [
            pytest.param(
                "source", TicketStatus.NEW, TicketStatus.ANALYSIS, id="source"
            ),
            pytest.param(
                "source",
                TicketStatus.IGNORED,
                TicketStatus.ANALYSIS,
                id="source-also-not-mutable",
            ),
            pytest.param(
                "source",
                TicketStatus.NEW,
                TicketStatus.DUPLICATED,
                id="source-also-duplicated-target",
            ),
            pytest.param(
                "target", TicketStatus.NEW, TicketStatus.ANALYSIS, id="target"
            ),
            pytest.param(
                "target",
                TicketStatus.IGNORED,
                TicketStatus.ANALYSIS,
                id="target-also-not-mutable-source",
            ),
            pytest.param(
                "target",
                TicketStatus.NEW,
                TicketStatus.DUPLICATED,
                id="target-also-duplicated",
            ),
            pytest.param("self", TicketStatus.NEW, None, id="self-also-self-duplicate"),
        ],
    )
    async def test_inaccessible_root_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        hidden: str,
        source_status: TicketStatus,
        target_status: TicketStatus | None,
    ) -> None:
        """A VA origin with a request-resolved `non_confidential` scope: an
        auto-assignment of the unassigned source before the denial would be
        observable. The hidden root is confidential and its only grant
        belongs to another user."""
        actor = await va_user()
        source = await ticket_factory(
            status=source_status.value, is_confidential=hidden in ("source", "self")
        )
        target = (
            source
            if target_status is None
            else await ticket_factory(
                status=target_status.value, is_confidential=hidden == "target"
            )
        )
        hidden_root = target if hidden == "target" else source
        await ticket_access_grant_factory(ticket_id=hidden_root.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            source_id=source.id,
            target_id=target.id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_source_is_not_mutable_before_the_target_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """The target is `Duplicated` as well: the source operability guard
        fires first."""
        actor = await va_user()
        source = await ticket_factory(status=status.value)
        target = await ticket_factory(status=TicketStatus.DUPLICATED.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            source_id=source.id,
            target_id=target.id,
            actor=actor,
        )

    async def test_duplicated_target_is_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The source has a dependent: the guard precedes Phase 2 and no
        dependent is locked or repointed."""
        actor = await va_user()
        source = await ticket_factory(status=TicketStatus.NEW.value)
        dependent = await ticket_factory(duplicate_of_id=source.id)
        target = await ticket_factory(status=TicketStatus.DUPLICATED.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            DuplicateTargetIsDuplicatedError,
            source_id=source.id,
            target_id=target.id,
            actor=actor,
            others=[dependent.id],
        )

    async def test_self_duplicate_is_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            SelfDuplicateError,
            source_id=ticket.id,
            target_id=ticket.id,
            actor=actor,
        )

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        source = await ticket_factory(status=TicketStatus.NEW.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await mark_as_duplicate(
                db_session,
                ticket_id=source.id,
                duplicate_of_id=target.id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
            )

        assert recorder.statements == []
        assert await _states(db_session, [source.id, target.id]) == {
            source.id: (TicketStatus.NEW, None, None),
            target.id: (TicketStatus.ANALYSIS, None, None),
        }
        assert await _events(db_session, [source.id, target.id]) == []


# ---------------------------------------------------------------------------
# Lock order: acting User, ordered roots, visibility, NOWAIT dependents
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    @pytest.mark.parametrize(
        "source_position", [0, 1], ids=["source-lower", "source-higher"]
    )
    async def test_user_then_roots_by_uuid_then_visibility_then_dependents(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        source_position: int,
    ) -> None:
        """ticket-service.md, `mark_as_duplicate` steps 1-3: the acting
        User `FOR SHARE`; both roots with blocking `FOR UPDATE` in
        ascending UUID order whichever is the source; one visibility
        statement for both roots after both locks; then the dependents
        `ORDER BY id FOR UPDATE NOWAIT`."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ids = _ordered_ids(2)
        source_id = ids[source_position]
        target_id = ids[1 - source_position]
        await ticket_factory(id=source_id, status=TicketStatus.ANALYSIS.value)
        await ticket_factory(id=target_id, status=TicketStatus.ANALYSIS.value)
        await ticket_factory(duplicate_of_id=source_id)

        with StatementRecorder(db_session) as recorder:
            await _mark(
                db_session, source_id, target_id, actor, scope=Scope.NON_CONFIDENTIAL
            )

        statements = recorder.statements
        user_share = next(
            i
            for i, s in enumerate(statements)
            if 'FROM "user"' in s and "FOR SHARE" in s
        )
        root_locks = [
            i
            for i, s in enumerate(statements)
            if "FROM ticket" in s and "FOR UPDATE" in s and "NOWAIT" not in s
        ]
        visibility = [i for i, s in enumerate(statements) if "ticket_access_grant" in s]
        dependents = [i for i, s in enumerate(statements) if "NOWAIT" in s]
        assert len(root_locks) == 2
        assert len(visibility) == 1
        assert len(dependents) == 1
        assert user_share < root_locks[0] < root_locks[1] < visibility[0]
        assert visibility[0] < dependents[0]
        assert _bound(recorder.parameters[user_share]) == [actor.id]
        assert [_bound(recorder.parameters[i]) for i in root_locks] == [
            [ids[0]],
            [ids[1]],
        ]
        assert set(ids) <= set(_bound(recorder.parameters[visibility[0]]))
        assert "FOR UPDATE" not in statements[visibility[0]]
        assert "ORDER BY ticket.id" in statements[dependents[0]]
        assert _bound(recorder.parameters[dependents[0]]) == [source_id]
        assert len(recorder.row_locks()) == 4
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# Identifier disclosure boundary after the link is established
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdentifierDisclosure:
    async def test_link_keeps_the_identifier_of_a_target_that_became_confidential(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ticket-service.md, `mark_as_duplicate` (after the steps) and
        tickets.md, Identifier Disclosure Boundary: the source detail keeps
        the stored target `SNTL-{n}`, while following it returns
        `TicketNotFoundError` for the `non_confidential` caller."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        caller = TicketCaller.authenticated(actor.id, Scope.NON_CONFIDENTIAL)
        source = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        await _mark(
            db_session, source.id, target.id, actor, scope=Scope.NON_CONFIDENTIAL
        )
        # Later loss of visibility, as by a committed confidentiality change.
        target.is_confidential = True
        await db_session.flush()

        detail = await get_ticket_detail(
            db_session, ticket_id=_sntl(source), caller=caller
        )

        assert detail.duplicate_of_ticket_id == _sntl(target)
        with pytest.raises(TicketNotFoundError):
            await get_ticket_detail(db_session, ticket_id=_sntl(target), caller=caller)


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


class _DriverError(Exception):
    """A DBAPI-level error carrying a PostgreSQL SQLSTATE."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


@pytest.mark.integration
class TestRollback:
    async def test_dependent_audit_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The failure is injected into the last write (the second
        dependent's `duplicate_target_changed`), after the assignment,
        promotion, source status and link, both source events, and the
        first repoint."""
        actor = await va_user()
        source = await ticket_factory(status=TicketStatus.NEW.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        first = await ticket_factory(duplicate_of_id=source.id)
        second = await ticket_factory(duplicate_of_id=source.id)
        # Primary keys are captured before the scope expires the instances.
        involved = [source.id, target.id, first.id, second.id]
        source_id, target_id, first_id, second_id = involved
        before = await _states(db_session, involved)
        repoints = 0
        original_log = TicketAuditLog.log_event

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal repoints
            if kwargs["event_type"] is TicketAuditEventType.DUPLICATE_TARGET_CHANGED:
                repoints += 1
                if repoints == 2:
                    raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            with pytest.raises(RuntimeError, match="injected"):
                await _mark(db_session, source_id, target_id, actor)
        monkeypatch.undo()

        assert repoints == 2
        assert before == {
            source_id: (TicketStatus.NEW, None, None),
            target_id: (TicketStatus.ANALYSIS, None, None),
            first_id: (TicketStatus.DUPLICATED, source_id, None),
            second_id: (TicketStatus.DUPLICATED, source_id, None),
        }
        assert await _states(db_session, involved) == before
        assert await _events(db_session, involved) == []

    async def test_other_database_error_on_the_dependent_lock_propagates_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only SQLSTATE `55P03` maps to
        `DuplicateConcurrentModificationError` (ticket-service.md,
        `mark_as_duplicate` step 3); any other database exception
        propagates (Q6). The `55P03` mapping itself is proven by the
        independent-session conflict test of ATR 6."""
        actor = await va_user()
        source = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        await ticket_factory(duplicate_of_id=source.id)
        failure = DBAPIError("SELECT", None, _DriverError("40P01"))
        original_execute = db_session.execute

        async def execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            lock = getattr(statement, "_for_update_arg", None)
            if lock is not None and lock.nowait:
                raise failure
            return await original_execute(statement, *args, **kwargs)

        monkeypatch.setattr(db_session, "execute", execute)

        with pytest.raises(DBAPIError) as raised:
            await _mark(db_session, source.id, target.id, actor)

        assert raised.value is failure

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        source = await ticket_factory(status=TicketStatus.NEW.value)
        target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        await ticket_factory(duplicate_of_id=source.id)

        async def forbidden() -> None:
            raise AssertionError("mark_as_duplicate() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _mark(db_session, source.id, target.id, actor)
