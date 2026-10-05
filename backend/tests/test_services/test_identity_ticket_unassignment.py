"""Tests for the identity-owned Ticket unassignment helpers
(`_unassign_active_tickets()` and `_unassign_tickets_on_va_role_loss()` in
backend/app/services/user_service.py).

See docs/features/identity/user-service.md (Private Helpers) for the
contract under test; docs/features/tickets/ticket-audit-log.md (Canonical
Automatic Comment Vocabulary, Testing Requirement 19) for the exact event
payload; and docs/features/platform/testing-strategy.md (User Lifecycle and
Management, "identity unassignment" bullet; Audit Trail Testing) for the
mandatory scenarios. Every test is single-session: the caller precondition
(the User locked `FOR NO KEY UPDATE`) is satisfied by locking the User in
the test session before calling the helper.

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_mutations
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.user_service import (
    _unassign_active_tickets,
    _unassign_tickets_on_va_role_loss,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
TicketFactory = Callable[..., Awaitable[Ticket]]

_EXTERNAL_GROUP = "Example Security Group"

# user-service.md, Private Helpers, `_unassign_active_tickets()`: the four
# identity-owned reasons (ticket-audit-log.md, Canonical Automatic Comment
# Vocabulary, minus the reconciliation-only `inactive assignee`).
_ACTIVE_REASONS = [
    "user deactivated",
    "vulnerability_analyst role removed",
    "vulnerability_analyst role removed by external sync",
    "vulnerability_analyst role removed after role mapping deletion",
]
# user-service.md, Private Helpers, `_unassign_tickets_on_va_role_loss()`.
_ROLE_LOSS_REASONS = [
    "vulnerability_analyst role removed",
    "vulnerability_analyst role removed by external sync",
    "vulnerability_analyst role removed after role mapping deletion",
]


def _ordered_ids(count: int) -> list[uuid.UUID]:
    """`count` fresh Ticket UUIDs in ascending order."""
    return sorted(uuid.uuid4() for _ in range(count))


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


async def _lock_user(db: AsyncSession, user: User) -> User:
    """Satisfy the caller precondition: the User `FOR NO KEY UPDATE`."""
    return (
        await db.execute(
            select(User).where(User.id == user.id).with_for_update(key_share=True)
        )
    ).scalar_one()


async def _states(
    db: AsyncSession, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, uuid.UUID | None]]:
    """Current `(status, assignee_id)` of each Ticket, read from the database."""
    rows = await db.execute(
        select(Ticket.id, Ticket.status, Ticket.assignee_id).where(Ticket.id.in_(ids))
    )
    return {row.id: (row.status, row.assignee_id) for row in rows}


async def _lock_and_unassign(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Lock the User as the caller would, then run the helper."""
    locked = (
        await db.execute(
            select(User).where(User.id == user_id).with_for_update(key_share=True)
        )
    ).scalar_one()
    await _unassign_active_tickets(db, locked, "user deactivated")


EventRow = tuple[
    uuid.UUID, str, uuid.UUID | None, str | None, str | None, str | None, Any
]
"""`(ticket_id, event_type, user_id, old_value, new_value, comment, detail)`."""


async def _events(db: AsyncSession, ids: list[uuid.UUID]) -> list[EventRow]:
    """Every TicketAuditEvent of the Tickets, in insertion (UUIDv7) order."""
    rows = (
        await db.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ids))
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    return [
        (
            r.ticket_id,
            r.event_type,
            r.user_id,
            r.old_value,
            r.new_value,
            r.comment,
            r.detail,
        )
        for r in rows
    ]


def _clear_event(
    ticket_id: uuid.UUID, username: str, reason: str
) -> tuple[uuid.UUID, str, None, str, None, str, None]:
    """ticket-audit-log.md, Canonical Automatic Comment Vocabulary (System
    unassignment) and user-service.md, Private Helpers step 4."""
    return (
        ticket_id,
        "assignment",
        None,
        username,
        None,
        f"Unassigned from {username}: {reason}",
        None,
    )


# ---------------------------------------------------------------------------
# `_unassign_active_tickets()`
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUnassignActiveTicketsSelectionAndLocks:
    async def test_selects_without_status_prefilter_and_locks_by_ascending_uuid(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, Private Helpers, `_unassign_active_tickets()`
        step 1: every Ticket ID assigned to the User, without filtering by
        status, ordered by Ticket UUID ascending, then `FOR UPDATE` in that
        order."""
        user = await user_factory(username="bob.va")
        other = await user_factory(username="carol.va")
        ids = _ordered_ids(6)
        statuses = [
            TicketStatus.ANALYSIS,
            TicketStatus.RESOLVED,
            TicketStatus.NEW,
            TicketStatus.IGNORED,
            TicketStatus.ANALYZED,
            TicketStatus.DUPLICATED,
        ]
        # Created out of UUID order so that creation order cannot pass for
        # lock order.
        for index in (3, 0, 5, 1, 4, 2):
            await ticket_factory(
                id=ids[index], status=statuses[index].value, assignee_id=user.id
            )
        await ticket_factory(status=TicketStatus.ANALYSIS.value, assignee_id=other.id)
        await ticket_factory(status=TicketStatus.ANALYSIS.value)
        locked = await _lock_user(db_session, user)

        with StatementRecorder(db_session) as recorder:
            await _unassign_active_tickets(
                db_session, locked, "vulnerability_analyst role removed"
            )

        statements = recorder.statements
        ticket_selects = [
            i
            for i, s in enumerate(statements)
            if s.lstrip().upper().startswith("SELECT") and "FROM ticket " in f"{s} "
        ]
        candidate = [i for i in ticket_selects if "FOR UPDATE" not in statements[i]]
        lock = [i for i in ticket_selects if "FOR UPDATE" in statements[i]]
        assert len(candidate) == 1
        assert len(lock) == 1
        assert candidate[0] < lock[0]

        candidate_sql = statements[candidate[0]]
        assert "ticket.assignee_id" in candidate_sql
        assert "ticket.status" not in candidate_sql
        assert "ORDER BY ticket.id" in candidate_sql
        assert _bound(recorder.parameters[candidate[0]]) == [user.id]

        lock_sql = statements[lock[0]]
        assert "ORDER BY ticket.id" in lock_sql
        assert sorted(_bound(recorder.parameters[lock[0]])) == ids
        # Exactly one row lock: the helper never acquires or upgrades the
        # caller's User lock.
        assert recorder.row_locks() == [lock_sql]

    async def test_no_assigned_ticket_takes_no_ticket_lock(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        user = await user_factory(username="bob.va")
        locked = await _lock_user(db_session, user)

        with StatementRecorder(db_session) as recorder:
            await _unassign_active_tickets(db_session, locked, "user deactivated")

        assert recorder.row_locks() == []
        assert recorder.writes() == []


@pytest.mark.integration
class TestUnassignActiveTicketsStatuses:
    async def test_clears_active_statuses_and_preserves_inactive_ones(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, Private Helpers step 3: `New` (anomalous),
        `Analysis`, and `Analyzed` lose only the assignee; `Resolved`,
        `Ignored`, and `Duplicated` keep it and create no event. No status
        changes."""
        user = await user_factory(username="bob.va")
        ids = _ordered_ids(6)
        statuses = {
            ids[0]: TicketStatus.RESOLVED,
            ids[1]: TicketStatus.ANALYZED,
            ids[2]: TicketStatus.IGNORED,
            ids[3]: TicketStatus.NEW,
            ids[4]: TicketStatus.DUPLICATED,
            ids[5]: TicketStatus.ANALYSIS,
        }
        for ticket_id in reversed(ids):
            await ticket_factory(
                id=ticket_id, status=statuses[ticket_id].value, assignee_id=user.id
            )
        locked = await _lock_user(db_session, user)

        await _unassign_active_tickets(db_session, locked, "user deactivated")

        assert await _states(db_session, ids) == {
            ids[0]: ("Resolved", user.id),
            ids[1]: ("Analyzed", None),
            ids[2]: ("Ignored", user.id),
            ids[3]: ("New", None),
            ids[4]: ("Duplicated", user.id),
            ids[5]: ("Analysis", None),
        }
        assert await _events(db_session, ids) == [
            _clear_event(ids[1], "bob.va", "user deactivated"),
            _clear_event(ids[3], "bob.va", "user deactivated"),
            _clear_event(ids[5], "bob.va", "user deactivated"),
        ]

    async def test_tickets_of_other_users_are_untouched(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        user = await user_factory(username="bob.va")
        other = await user_factory(username="carol.va")
        mine = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        theirs = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=other.id
        )
        unassigned = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        locked = await _lock_user(db_session, user)

        await _unassign_active_tickets(db_session, locked, "user deactivated")

        ids = [mine.id, theirs.id, unassigned.id]
        assert await _states(db_session, ids) == {
            mine.id: ("Analysis", None),
            theirs.id: ("Analysis", other.id),
            unassigned.id: ("Analysis", None),
        }
        assert await _events(db_session, ids) == [
            _clear_event(mine.id, "bob.va", "user deactivated")
        ]


@pytest.mark.integration
class TestUnassignActiveTicketsReasons:
    @pytest.mark.parametrize("reason", _ACTIVE_REASONS)
    async def test_each_identity_reason_produces_its_exact_payload(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        reason: Any,
    ) -> None:
        """ticket-audit-log.md, Canonical Automatic Comment Vocabulary:
        `comment = "Unassigned from {username}: {reason}"`, system actor,
        `old_value` the username, `new_value` and `detail` NULL."""
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        await _unassign_active_tickets(db_session, locked, reason)

        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analyzed", None)}
        assert await _events(db_session, [ticket.id]) == [
            _clear_event(ticket.id, "bob.va", reason)
        ]

    @pytest.mark.parametrize(
        "reason",
        ["inactive assignee", "user removed", "", "User Deactivated"],
        ids=["inactive-assignee", "arbitrary", "empty", "wrong-case"],
    )
    async def test_rejected_reason_raises_before_any_query(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        reason: str,
    ) -> None:
        """user-service.md, Private Helpers: the reconciliation-only
        `inactive assignee` and any other value raise `ValueError` before any
        Ticket mutation."""
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="reason"),
        ):
            await _unassign_active_tickets(db_session, locked, cast(Any, reason))

        assert recorder.statements == []
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", user.id)
        }
        assert await _events(db_session, [ticket.id]) == []


@pytest.mark.integration
class TestUnassignActiveTicketsIdempotency:
    async def test_repeated_invocation_creates_no_further_event(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        await _unassign_active_tickets(db_session, locked, "user deactivated")
        await _unassign_active_tickets(db_session, locked, "user deactivated")

        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
        assert await _events(db_session, [ticket.id]) == [
            _clear_event(ticket.id, "bob.va", "user deactivated")
        ]

    async def test_stale_candidates_are_revalidated_from_locked_current_rows(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """user-service.md, Private Helpers step 2-3 and ticket-audit-log.md
        Testing Requirement 19: a candidate that, between selection and
        locking, was reassigned (winner), already cleared, or moved to an
        inactive status is preserved without an event; only the still-valid
        candidate is cleared."""
        user = await user_factory(username="bob.va")
        winner = await user_factory(username="carol.va")
        reassigned_id, cleared_id, resolved_id, valid_id = _ordered_ids(4)
        for ticket_id in (reassigned_id, cleared_id, resolved_id, valid_id):
            await ticket_factory(
                id=ticket_id, status=TicketStatus.ANALYSIS.value, assignee_id=user.id
            )
        locked = await _lock_user(db_session, user)

        original_execute = db_session.execute
        calls = 0

        async def _interleaving_execute(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            result = await original_execute(*args, **kwargs)
            calls += 1
            if calls == 1:
                # After the candidate selection, before the Ticket locks.
                await original_execute(
                    update(Ticket)
                    .where(Ticket.id == reassigned_id)
                    .values(assignee_id=winner.id)
                    .execution_options(synchronize_session=False)
                )
                await original_execute(
                    update(Ticket)
                    .where(Ticket.id == cleared_id)
                    .values(assignee_id=None)
                    .execution_options(synchronize_session=False)
                )
                await original_execute(
                    update(Ticket)
                    .where(Ticket.id == resolved_id)
                    .values(status=TicketStatus.RESOLVED.value)
                    .execution_options(synchronize_session=False)
                )
            return result

        monkeypatch.setattr(db_session, "execute", _interleaving_execute)
        await _unassign_active_tickets(db_session, locked, "user deactivated")
        monkeypatch.undo()

        ids = [reassigned_id, cleared_id, resolved_id, valid_id]
        assert await _states(db_session, ids) == {
            reassigned_id: ("Analysis", winner.id),
            cleared_id: ("Analysis", None),
            resolved_id: ("Resolved", user.id),
            valid_id: ("Analysis", None),
        }
        assert await _events(db_session, ids) == [
            _clear_event(valid_id, "bob.va", "user deactivated")
        ]


@pytest.mark.integration
class TestUnassignActiveTicketsBoundaries:
    async def test_no_status_change_reconciliation_or_convergence(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """user-service.md, Private Helpers step 5: no status change, no
        gate reconciliation, no replacement assignee; the identity batch is
        not a Ticket convergence trigger."""
        reconcile_spy = AsyncMock(side_effect=AssertionError("must not reconcile"))
        monkeypatch.setattr(ticket_mutations, "reconcile_ticket_status", reconcile_spy)
        user = await user_factory(username="bob.va")
        analysis = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        analyzed = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        await _unassign_active_tickets(db_session, locked, "user deactivated")

        reconcile_spy.assert_not_called()
        assert pending_ticket_convergence_effects(db_session) == ()
        ids = [analysis.id, analyzed.id]
        assert await _states(db_session, ids) == {
            analysis.id: ("Analysis", None),
            analyzed.id: ("Analyzed", None),
        }
        assert [event[1] for event in await _events(db_session, ids)] == [
            "assignment",
            "assignment",
        ]

    async def test_flushes_without_commit_or_rollback(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)

        await _unassign_active_tickets(db_session, locked, "user deactivated")

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        # Flushed: the clear and its event are visible to a fresh read in
        # the same transaction.
        assert not db_session.dirty
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
        assert len(await _events(db_session, [ticket.id])) == 1

    async def test_audit_failure_propagates_and_rolls_back_with_the_caller(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(username="bob.va")
        user_id = user.id
        first_id, second_id = _ordered_ids(2)
        for ticket_id in (first_id, second_id):
            await ticket_factory(
                id=ticket_id, status=TicketStatus.ANALYSIS.value, assignee_id=user_id
            )

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(TicketAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await _lock_and_unassign(db_session, user_id)

        ids = [first_id, second_id]
        assert await _states(db_session, ids) == {
            first_id: ("Analysis", user_id),
            second_id: ("Analysis", user_id),
        }
        assert await _events(db_session, ids) == []

    async def test_caller_rollback_removes_every_clear_and_event(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        user = await user_factory(username="bob.va")
        user_id = user.id
        first_id, second_id = _ordered_ids(2)
        await ticket_factory(
            id=first_id, status=TicketStatus.ANALYSIS.value, assignee_id=user_id
        )
        await ticket_factory(
            id=second_id, status=TicketStatus.ANALYZED.value, assignee_id=user_id
        )

        async with rollback_test_scope(db_session):
            await _lock_and_unassign(db_session, user_id)
            assert len(await _events(db_session, [first_id, second_id])) == 2

        ids = [first_id, second_id]
        assert await _states(db_session, ids) == {
            first_id: ("Analysis", user_id),
            second_id: ("Analyzed", user_id),
        }
        assert await _events(db_session, ids) == []


# ---------------------------------------------------------------------------
# `_unassign_tickets_on_va_role_loss()`
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUnassignTicketsOnVaRoleLoss:
    @pytest.mark.parametrize("reason", _ROLE_LOSS_REASONS)
    async def test_final_loss_delegates_with_exact_payload(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        reason: Any,
    ) -> None:
        """user-service.md, Private Helpers,
        `_unassign_tickets_on_va_role_loss()` step 3: with no remaining VA
        origin, delegates to `_unassign_active_tickets()` with `reason`."""
        user = await user_factory(username="bob.va")
        manual_va = await user_role_factory(
            user_id=user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        await user_role_factory(user_id=user.id, role=Role.RESTRICTED_ANALYST.value)
        active_id, resolved_id = _ordered_ids(2)
        await ticket_factory(
            id=resolved_id, status=TicketStatus.RESOLVED.value, assignee_id=user.id
        )
        await ticket_factory(
            id=active_id, status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)
        # The caller has applied its UserRole deletion in this transaction.
        await db_session.delete(manual_va)
        await db_session.flush()

        await _unassign_tickets_on_va_role_loss(db_session, locked, reason)

        ids = [active_id, resolved_id]
        assert await _states(db_session, ids) == {
            active_id: ("Analysis", None),
            resolved_id: ("Resolved", user.id),
        }
        assert await _events(db_session, ids) == [
            _clear_event(active_id, "bob.va", reason)
        ]

    @pytest.mark.parametrize(
        "group_name", ["_manual", _EXTERNAL_GROUP], ids=["manual", "external"]
    )
    async def test_remaining_va_origin_changes_no_ticket(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        group_name: str,
    ) -> None:
        """user-service.md, Private Helpers,
        `_unassign_tickets_on_va_role_loss()` step 2: any remaining VA origin,
        from any `group_name`, leaves every Ticket and creates no event."""
        user = await user_factory(username="bob.va")
        removed_origin = "_manual" if group_name != "_manual" else _EXTERNAL_GROUP
        removed = await user_role_factory(
            user_id=user.id,
            role=Role.VULNERABILITY_ANALYST.value,
            group_name=removed_origin,
        )
        await user_role_factory(
            user_id=user.id,
            role=Role.VULNERABILITY_ANALYST.value,
            group_name=group_name,
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)
        await db_session.delete(removed)
        await db_session.flush()

        with StatementRecorder(db_session) as recorder:
            await _unassign_tickets_on_va_role_loss(
                db_session, locked, "vulnerability_analyst role removed"
            )

        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", user.id)
        }
        assert await _events(db_session, [ticket.id]) == []

    @pytest.mark.parametrize(
        "reason",
        ["user deactivated", "inactive assignee", "role revoked"],
        ids=["user-deactivated", "inactive-assignee", "arbitrary"],
    )
    async def test_rejected_reason_raises_before_any_ticket_change(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        reason: str,
    ) -> None:
        """user-service.md, Private Helpers: only the three role-loss
        reasons are accepted; any other value raises `ValueError` before
        Ticket mutation."""
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="reason"),
        ):
            await _unassign_tickets_on_va_role_loss(
                db_session, locked, cast(Any, reason)
            )

        assert recorder.statements == []
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", user.id)
        }
        assert await _events(db_session, [ticket.id]) == []

    async def test_reinvocation_after_final_loss_creates_no_event(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)

        await _unassign_tickets_on_va_role_loss(
            db_session, locked, "vulnerability_analyst role removed by external sync"
        )
        await _unassign_tickets_on_va_role_loss(
            db_session, locked, "vulnerability_analyst role removed by external sync"
        )

        assert await _events(db_session, [ticket.id]) == [
            _clear_event(
                ticket.id,
                "bob.va",
                "vulnerability_analyst role removed by external sync",
            )
        ]

    async def test_flushes_without_commit_rollback_or_convergence(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=user.id
        )
        locked = await _lock_user(db_session, user)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        reconcile_spy = AsyncMock(side_effect=AssertionError("must not reconcile"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(ticket_mutations, "reconcile_ticket_status", reconcile_spy)

        await _unassign_tickets_on_va_role_loss(
            db_session, locked, "vulnerability_analyst role removed"
        )

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        reconcile_spy.assert_not_called()
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
