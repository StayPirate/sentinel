"""Single-session service integration tests for `set_confidentiality()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Operability guard, explicit opt-outs;
  `set_confidentiality`; Architectural Test Requirements 14
  (confidentiality parts) and 15 (single-session part, including the
  converse self-loss case)).
- docs/features/tickets/tickets.md (Inactive Statuses and Mutability >
  Ignored, explicit exceptions; Confidential Tickets > Coordinated Release
  Date and Audit Trail; Set Confidentiality).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `confidentiality_changed` and the bullets after the table; Canonical
  Mutation and No-Event Matrix: Confidentiality toggle; Testing
  Requirements 1-7, 12 (automatic declassification deletion and CRD
  retention), and 29 (no event when declassification retains the CRD)).
- docs/features/tickets/ticket-deadlines.md (Testing Requirement 3:
  immutability of the start across a confidentiality change).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Ticket Accessibility > Confidentiality and explicit
  access grants).

The independent-session tests (the locked-current accessibility races of
Architectural Test Requirement 15 and the serialization of concurrent
confidentiality, grant, and CRD operations) are owned by
`tests/test_services/test_confidentiality_atomicity.py`; the HTTP contract
belongs to the e2e tier.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Delete, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_deadlines import DueDates
from app.services.ticket_service import assemble_ticket_detail, set_confidentiality
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
MaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]

ALL_STATUSES = [
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
]

FLAG = {True: "true", False: "false"}
"""The `confidentiality_changed` value format (ticket-audit-log.md, Event
Type Contract)."""

CRD = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
"""A retained Coordinated Release Date."""

FORBIDDEN = (
    "auto_assign_actor",
    "reconcile_ticket_status",
    "ensure_ticket_operable",
    "stabilize_acting_user",
    "refresh_priority_auto",
    "recalculate_cvss_chain",
)
"""`ticket_service` collaborators a visibility-only operation never calls
(ticket-service.md, `set_confidentiality`: no User lock, no operability
guard, no assignment, no reconciliation)."""

State = tuple[str, uuid.UUID | None, uuid.UUID | None, bool, datetime | None]
"""The persisted `(status, assignee_id, duplicate_of_id, is_confidential,
coordinated_release_at)` of a Ticket."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _changed(actor: User, old: bool, new: bool) -> EventRow:
    """The acting-user `confidentiality_changed` (`comment` and `detail`
    `NULL`)."""
    return EventRow(
        "confidentiality_changed", actor.id, FLAG[old], FLAG[new], None, None
    )


async def _set(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    actor: User,
    value: bool,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call the service as an API handler would."""
    return await set_confidentiality(
        db,
        ticket_id=ticket_id,
        is_confidential=value,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> State | None:
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one_or_none()
    return tuple(row) if row is not None else None  # type: ignore[return-value]


async def _grantees(db: AsyncSession, ticket_id: uuid.UUID) -> set[uuid.UUID]:
    """The users holding an explicit grant on the Ticket."""
    rows = await db.execute(
        select(TicketAccessGrant.user_id).where(
            TicketAccessGrant.ticket_id == ticket_id
        )
    )
    return set(rows.scalars())


async def _maintainers(
    db: AsyncSession, ticket_id: uuid.UUID
) -> set[tuple[uuid.UUID, uuid.UUID, uuid.UUID]]:
    """Every persisted `(id, ticket_package_id, user_id)` association under
    the Ticket's packages, excluded or not."""
    rows = await db.execute(
        select(
            TicketPackageMaintainer.id,
            TicketPackageMaintainer.ticket_package_id,
            TicketPackageMaintainer.user_id,
        )
        .join(
            TicketPackage, TicketPackage.id == TicketPackageMaintainer.ticket_package_id
        )
        .where(TicketPackage.ticket_id == ticket_id)
    )
    return {(r.id, r.ticket_package_id, r.user_id) for r in rows}


async def _visible(db: AsyncSession, ticket_id: uuid.UUID, user: User) -> bool:
    """The canonical predicate for a `non_confidential`-scope caller."""
    caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
    return bool(
        (
            await db.execute(
                select(ticket_visibility_condition(caller))
                .select_from(Ticket)
                .where(Ticket.id == ticket_id)
            )
        ).scalar_one()
    )


def _forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every `FORBIDDEN` collaborator with a recorder that fails."""
    calls: list[str] = []
    for name in FORBIDDEN:

        def _called(*_args: Any, _name: str = name, **_kwargs: Any) -> Any:
            calls.append(_name)
            raise AssertionError(f"{_name} must not be called")

        monkeypatch.setattr(ticket_service, name, _called)
    return calls


def _grant_writes(recorder: StatementRecorder) -> list[str]:
    return [s for s in recorder.writes() if "ticket_access_grant" in s]


# ---------------------------------------------------------------------------
# Effective transitions in every Ticket status
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEffectiveTransition:
    @pytest.mark.parametrize("old", [True, False], ids=["declassify", "classify"])
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=str)
    async def test_succeeds_in_every_status_with_one_exact_event_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        old: bool,
    ) -> None:
        """ticket-service.md, Operability guard (explicit opt-out) and
        `set_confidentiality` steps 4-7: an unassigned Ticket and an active
        VA actor make any auto-assignment observable. Status, assignee, and
        duplicate link are unchanged; the one acting-user event carries the
        preserved and requested flags; declassification also removes the
        Ticket's grant; nothing is registered for post-commit."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value, is_confidential=old)
        if old:
            await ticket_access_grant_factory(ticket_id=ticket.id)
        before = await _state(db_session, ticket.id)
        assert before is not None
        calls = _forbid(monkeypatch)

        result = await _set(db_session, ticket.id, actor, not old)

        assert calls == []
        assert result.id == ticket.id
        assert result.is_confidential is (not old)
        assert await _state(db_session, ticket.id) == (*before[:3], not old, None)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, old, not old)
        ]
        assert await _grantees(db_session, ticket.id) == set()
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_declassification_deletes_every_grant_of_only_this_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        """ticket-audit-log.md, the bullets after the Event Type Contract:
        several users' grants are deleted in one statement with only
        `confidentiality_changed` and no `access_grant_removed`; a grant on
        another confidential Ticket, even for the same user, is intact."""
        actor = await va_user()
        analyst_a = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        analyst_b = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        other = await ticket_factory(is_confidential=True)
        for user in (analyst_a, analyst_b, actor):
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        await ticket_access_grant_factory(ticket_id=other.id, user_id=analyst_a.id)

        with StatementRecorder(db_session) as recorder:
            await _set(db_session, ticket.id, actor, False)

        (deletion,) = _grant_writes(recorder)
        assert deletion.lstrip().startswith("DELETE FROM ticket_access_grant")
        assert await _grantees(db_session, ticket.id) == set()
        assert await _grantees(db_session, other.id) == {analyst_a.id}
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, True, False)
        ]
        assert await ticket_events_by_id(db_session, other.id) == []

    async def test_reclassification_recreates_no_grant_and_queries_none(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        """`false` to `true` after declassification creates only its own
        event, recreates no manual grant, and performs no grant query (a
        scope-`all` caller needs no visibility subquery either); the former
        grantee no longer sees the Ticket."""
        actor = await va_user()
        analyst = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=analyst.id)
        await _set(db_session, ticket.id, actor, False)

        with StatementRecorder(db_session) as recorder:
            await _set(db_session, ticket.id, actor, True)

        assert [s for s in recorder.statements if "ticket_access_grant" in s] == []
        assert await _grantees(db_session, ticket.id) == set()
        assert await _visible(db_session, ticket.id, analyst) is False
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, True, False),
            _changed(actor, False, True),
        ]

    async def test_maintainer_rows_are_retained_and_qualify_after_reclassification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        va_user: VAUser,
    ) -> None:
        """tickets.md, Set Confidentiality and rbac.md: maintainer
        associations are not grants. Across declassification and
        reclassification every row is unchanged; afterwards the maintainer
        of an included package sees the Ticket, the maintainer whose only
        package is excluded does not until that package is restored."""
        actor = await va_user()
        included_maintainer = await va_user(roles=())
        excluded_maintainer = await va_user(roles=())
        ticket = await ticket_factory(is_confidential=True)
        included = await ticket_package_factory(ticket_id=ticket.id)
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=included.id, user_id=included_maintainer.id
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=excluded_maintainer.id
        )
        rows = await _maintainers(db_session, ticket.id)
        assert len(rows) == 2

        await _set(db_session, ticket.id, actor, False)
        assert await _maintainers(db_session, ticket.id) == rows
        await _set(db_session, ticket.id, actor, True)

        assert await _maintainers(db_session, ticket.id) == rows
        assert await _visible(db_session, ticket.id, included_maintainer) is True
        assert await _visible(db_session, ticket.id, excluded_maintainer) is False
        excluded.deleted_at = None
        await db_session.flush()
        assert await _visible(db_session, ticket.id, excluded_maintainer) is True
        assert [
            e.event_type for e in await ticket_events_by_id(db_session, ticket.id)
        ] == [
            "confidentiality_changed",
            "confidentiality_changed",
        ]

    async def test_coordinated_release_date_is_retained_without_an_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ATR 14 and audit Testing Requirements 12 and 29: neither
        direction modifies `coordinated_release_at` or creates a
        `coordinated_release_changed` event."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True, coordinated_release_at=CRD)

        declassified = await _set(db_session, ticket.id, actor, False)
        assert declassified.coordinated_release_at == CRD
        await _set(db_session, ticket.id, actor, True)

        state = await _state(db_session, ticket.id)
        assert state is not None
        assert state[3:] == (True, CRD)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, True, False),
            _changed(actor, False, True),
        ]


# ---------------------------------------------------------------------------
# Same-value no-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    @pytest.mark.parametrize("value", [True, False])
    async def test_same_value_writes_nothing_and_returns_the_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        value: bool,
    ) -> None:
        """Step 3: a true no-op; an existing grant of a confidential Ticket
        survives a repeated `true`."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=value)
        if value:
            await ticket_access_grant_factory(ticket_id=ticket.id)
        before = await _state(db_session, ticket.id)
        grantees = await _grantees(db_session, ticket.id)

        with StatementRecorder(db_session) as recorder:
            result = await _set(db_session, ticket.id, actor, value)

        assert result.id == ticket.id
        assert result.is_confidential is value
        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == before
        assert await _grantees(db_session, ticket.id) == grantees
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Guards, accessibility, and visibility paths
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await ticket_factory(is_confidential=True)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await set_confidentiality(
                db_session,
                ticket_id=ticket.id,
                is_confidential=False,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
            )

        assert recorder.statements == []
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_missing_ticket_is_not_found(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        actor = await va_user()
        missing = uuid.uuid7()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _set(db_session, missing, actor, False)

        assert recorder.writes() == []
        assert await ticket_events_by_id(db_session, missing) == []

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(False, id="would-be-effective"),
            pytest.param(True, id="would-be-no-op"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_no_op_classification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        requested: bool,
    ) -> None:
        """Step 2: a `non_confidential`-scope caller without a grant or
        maintainership; the only grant belongs to another user. Denial has
        zero writes and events and keeps the other user's grant."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        grant = await ticket_access_grant_factory(ticket_id=ticket.id)
        before = await _state(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _set(
                db_session, ticket.id, actor, requested, scope=Scope.NON_CONFIDENTIAL
            )

        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == before
        assert await _grantees(db_session, ticket.id) == {grant.user_id}
        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize("path", ["scope-all", "grant", "maintainer"])
    async def test_every_visibility_path_authorizes_declassification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        va_user: VAUser,
        path: str,
    ) -> None:
        """rbac.md, Scope and Confidential Ticket Visibility. With the grant
        path, the declassification deletes the caller's own grant and still
        returns its normal success (ticket-service.md, Caller category and
        Ticket accessibility: authorization uses the locked pre-state)."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        scope = Scope.NON_CONFIDENTIAL
        if path == "scope-all":
            scope = Scope.ALL
        elif path == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=actor.id
            )

        result = await _set(db_session, ticket.id, actor, False, scope=scope)

        assert result.is_confidential is False
        assert await _grantees(db_session, ticket.id) == set()
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, True, False)
        ]

    async def test_classification_that_removes_the_callers_last_path_succeeds(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ATR 15, converse self-loss: a `non_confidential`-scope caller
        sees the public Ticket only through its non-confidentiality. Making
        it confidential returns the ordinary success; only the later request
        is denied, with no effect."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory()

        result = await _set(
            db_session, ticket.id, actor, True, scope=Scope.NON_CONFIDENTIAL
        )

        assert result.is_confidential is True
        assert await _visible(db_session, ticket.id, actor) is False
        with pytest.raises(TicketNotFoundError):
            await _set(
                db_session, ticket.id, actor, False, scope=Scope.NON_CONFIDENTIAL
            )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, False, True)
        ]


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLocking:
    async def test_only_the_ticket_is_locked_before_the_visibility_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        """Locking: the first statement is the Ticket `FOR UPDATE`, followed
        by the separate locked-current visibility statement; no User row
        is locked or read, and no audit history is read."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _set(
                db_session, ticket.id, actor, False, scope=Scope.NON_CONFIDENTIAL
            )

        statements = recorder.statements
        assert "FROM ticket" in statements[0]
        assert "FOR UPDATE" in statements[0]
        assert "ticket_access_grant" not in statements[0]
        assert list(recorder.parameters[0]) == [ticket.id]
        assert "ticket_access_grant" in statements[1]
        assert recorder.row_locks() == [statements[0]]
        assert [s for s in statements if 'FROM "user"' in s] == []
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(
        ("failure", "error"),
        [
            ("grant-deletion", RuntimeError),
            ("database", DBAPIError),
            ("audit", RuntimeError),
            ("flush", RuntimeError),
        ],
    )
    async def test_injected_failure_rolls_back_flag_grants_and_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
        error: type[Exception],
    ) -> None:
        """A declassification of a Ticket with two grants fails at the grant
        deletion (a service-level exception, or a genuine PostgreSQL error
        at that position), at the audit write, or at the flush inserting
        the event. The caller's rollback restores the flag and both grants
        and leaves no event."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        grants = {
            (await ticket_access_grant_factory(ticket_id=ticket.id)).user_id
            for _ in range(2)
        }
        ticket_id = ticket.id
        reached = False
        original_execute = db_session.execute
        original_log = TicketAuditLog.log_event
        original_flush = db_session.flush

        async def failing_execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal reached
            if isinstance(statement, Delete) and (
                getattr(statement.table, "name", None) == "ticket_access_grant"
            ):
                reached = True
                if failure == "grant-deletion":
                    raise RuntimeError("injected grant-deletion failure")
                return await original_execute(text("SELECT 1 / 0"))
            return await original_execute(statement, *args, **kwargs)

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if kwargs["event_type"] is TicketAuditEventType.CONFIDENTIALITY_CHANGED:
                reached = True
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(
                isinstance(o, TicketAuditEvent)
                and o.event_type == TicketAuditEventType.CONFIDENTIALITY_CHANGED
                for o in db_session.new
            ):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure in ("grant-deletion", "database"):
                monkeypatch.setattr(db_session, "execute", failing_execute)
            elif failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", failing_flush)
            with pytest.raises(error):
                await _set(db_session, ticket_id, actor, False)
        monkeypatch.undo()

        assert reached
        state = await _state(db_session, ticket_id)
        assert state is not None
        assert state[3] is True
        assert await _grantees(db_session, ticket_id) == grants
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_caller_rollback_after_return_restores_everything(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        grant = await ticket_access_grant_factory(ticket_id=ticket.id)
        ticket_id, grantee = ticket.id, grant.user_id

        async with rollback_test_scope(db_session):
            result = await _set(db_session, ticket_id, actor, False)
            assert result.is_confidential is False
            assert await _grantees(db_session, ticket_id) == set()
            assert len(await ticket_events_by_id(db_session, ticket_id)) == 1

        state = await _state(db_session, ticket_id)
        assert state is not None
        assert state[3] is True
        assert await _grantees(db_session, ticket_id) == {grantee}
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        async def forbidden() -> None:
            raise AssertionError("set_confidentiality() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _set(db_session, ticket.id, actor, False)


# ---------------------------------------------------------------------------
# Deadlines (ticket-deadlines.md, Testing Requirement 3)
# ---------------------------------------------------------------------------

CREATED_AT = datetime(2026, 9, 26, 10, 15, 30, tzinfo=UTC)
DETAIL_INSTANT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
"""The projection's controlled evaluation instant: before every due date."""


@pytest.mark.integration
class TestDeadlines:
    async def test_due_date_start_is_immutable_across_confidentiality_changes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CVE-less `High` `Analysis` Ticket (30-day tier): after
        classification and declassification `created_at` is unchanged and
        the due dates stay at +3, +18, +21, +30, +30 days from it."""
        monkeypatch.setattr(ticket_service, "_utc_now", lambda: DETAIL_INSTANT)
        actor = await va_user()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            created_at=CREATED_AT,
        )
        await tree(ticket, status=PackageStatus.ANALYSIS)
        expected = DueDates(
            triage=CREATED_AT + timedelta(days=3),
            submission=CREATED_AT + timedelta(days=18),
            um=CREATED_AT + timedelta(days=21),
            qa=CREATED_AT + timedelta(days=30),
            release=CREATED_AT + timedelta(days=30),
        )

        for value in (True, False):
            await _set(db_session, ticket.id, actor, value)
            detail = await assemble_ticket_detail(
                db_session, ticket_id=ticket.id, evaluation_date=EVAL
            )
            assert detail.is_confidential is value
            assert detail.created_at == CREATED_AT
            assert detail.due_dates == expected
