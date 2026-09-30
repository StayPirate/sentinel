"""Single-session service integration tests for `grant_access()`,
`revoke_access()`, and `list_access_grants()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Acting user convention; Caller
  category and Ticket accessibility; Operability guard, explicit opt-outs;
  Concurrency control; `set_confidentiality` (Concurrency and result);
  `grant_access`; `revoke_access`; `list_access_grants`; Service
  Exceptions; Architectural Test Requirements 14 (grant parts), 15
  (single-session part, including the converse self-loss case), and 16).
- docs/features/tickets/tickets.md (Confidential Tickets, including Audit
  Trail; TicketAccessGrantResponse; Access Grant Management).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `access_grant_added`, `access_grant_removed`, and the bullets after the
  table; Canonical Mutation and No-Event Matrix: "Confidentiality toggle
  or manual access grant/revoke" and "User deactivation or reactivation
  with retained Ticket grants"; Testing Requirements 1-7, 12
  (reactivation grant retention), and 23 (single-session part: true
  locked pre-state values)).
- docs/features/identity/user-service.md (`resolve_user_identifier()`;
  `reactivate_user()`; Access grant concurrent with user lifecycle or
  rename).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Ticket Accessibility > Locked mutations and
  Confidentiality and explicit access grants; Audit Trail Testing).

The independent-session tests (ATR 8 grant/grant, grant/revoke,
revoke/revoke, the confidentiality, lifecycle, and rename races, and the
locked-current accessibility races of ATR 15) are owned by
`tests/test_services/test_access_grants_atomicity.py`; the HTTP contract
(status codes, capability checks, response shape) belongs to the e2e
tier. The model-level duplicate-key backstop is proven by
`tests/test_models/test_ticket_access_grant.py`. The `assign_ticket()`
target lock mode (`FOR SHARE`, shared private helper) remains asserted by
`tests/test_services/test_assign_ticket.py::TestLockOrder`.

Deactivation cases (grant retention across `deactivate_user()`) are not
covered here: that operation does not exist yet.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketAuditEventType, TicketStatus
from app.core.exceptions import (
    InactiveUserError,
    TicketNotFoundError,
    UserNotFoundError,
)
from app.core.identifiers import format_ticket_id
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
from app.services.ticket_service import (
    AccessGrantAction,
    AccessGrantProjection,
    TicketNotConfidentialError,
    TicketUserProjection,
    grant_access,
    list_access_grants,
    resolve_ticket_locator,
    revoke_access,
    set_confidentiality,
)
from app.services.ticket_visibility import TicketCaller
from app.services.user_service import reactivate_user
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    UserFactory,
    VAUser,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
MaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]

GrantRow = tuple[uuid.UUID, uuid.UUID, datetime]
"""A persisted grant as `(user_id, granted_by_id, granted_at)`."""

ALL_STATUSES = [
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
]

OPERATIONS = ["grant", "revoke"]

FORMS = ["uuid", "username"]
"""The two target identifier forms (api-spec.md, User Identifier
Resolution; user-service.md, `resolve_user_identifier()`)."""

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
"""An original grant time well before the test transaction."""

EARLIER = datetime(2026, 2, 1, 9, 0, tzinfo=UTC)

FORBIDDEN = (
    "auto_assign_actor",
    "reconcile_ticket_status",
    "ensure_ticket_operable",
    "stabilize_acting_user",
    "refresh_priority_auto",
    "recalculate_cvss_chain",
)
"""`ticket_service` collaborators a visibility-only grant operation never
calls (ticket-service.md, Operability guard explicit opt-outs;
`grant_access` and `revoke_access`: no operability guard, no assignment,
no reconciliation)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _added(actor: User, username: str) -> EventRow:
    """The acting-user `access_grant_added` (ticket-audit-log.md, Event
    Type Contract): `old_value` `NULL`, `new_value` the target username,
    `comment` and `detail` `NULL`."""
    return EventRow("access_grant_added", actor.id, None, username, None, None)


def _removed(actor: User, username: str) -> EventRow:
    """The acting-user `access_grant_removed`: `old_value` the target
    username, `new_value`, `comment`, and `detail` `NULL`."""
    return EventRow("access_grant_removed", actor.id, username, None, None, None)


def _changed(actor: User, old: str, new: str) -> EventRow:
    """The acting-user `confidentiality_changed`."""
    return EventRow("confidentiality_changed", actor.id, old, new, None, None)


def _profile(
    user: User, *, username: str, full_name: str | None, active: bool
) -> TicketUserProjection:
    """The expected current `UserSummary`-like profile, with the literal
    values the test assigned."""
    return TicketUserProjection(
        id=user.id, username=username, full_name=full_name, active=active
    )


async def _person(
    user_factory: UserFactory,
    username: str,
    *,
    active: bool = True,
    full_name: str | None = None,
) -> User:
    """A User with a fictional username, email, and optional full name."""
    return await user_factory(
        username=username,
        email=f"{username}@example.com",
        active=active,
        full_name=full_name,
    )


def _identifier(user: User, form: str) -> str:
    return str(user.id) if form == "uuid" else user.username


def _caller(actor: User, scope: Scope) -> TicketCaller:
    return TicketCaller.authenticated(actor.id, scope)


async def _grant(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> ticket_service.AccessGrantMutationResult:
    """Call `grant_access()` as an API handler would."""
    return await grant_access(
        db,
        ticket_id=ticket_id,
        target_user=target,
        acting_user_id=actor.id,
        caller=_caller(actor, scope),
    )


async def _revoke(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> None:
    """Call `revoke_access()` as an API handler would."""
    await revoke_access(
        db,
        ticket_id=ticket_id,
        target_user=target,
        acting_user_id=actor.id,
        caller=_caller(actor, scope),
    )


async def _mutate(
    op: str,
    db: AsyncSession,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> None:
    if op == "grant":
        await _grant(db, ticket_id, target, actor, scope=scope)
    else:
        await _revoke(db, ticket_id, target, actor, scope=scope)


async def _list(
    db: AsyncSession, ticket_id: uuid.UUID, actor: User, *, scope: Scope = Scope.ALL
) -> list[AccessGrantProjection]:
    return await list_access_grants(
        db, ticket_id=ticket_id, caller=_caller(actor, scope)
    )


async def _grants(db: AsyncSession, ticket_id: uuid.UUID) -> set[GrantRow]:
    """Every persisted grant of the Ticket."""
    rows = await db.execute(
        select(
            TicketAccessGrant.user_id,
            TicketAccessGrant.granted_by_id,
            TicketAccessGrant.granted_at,
        ).where(TicketAccessGrant.ticket_id == ticket_id)
    )
    return {(r.user_id, r.granted_by_id, r.granted_at) for r in rows}


async def _transaction_now(db: AsyncSession) -> datetime:
    """PostgreSQL `now()`: the transaction timestamp every
    `server_default=func.now()` receives in this test (testing-strategy.md,
    `server_default=func.now()` Testing)."""
    return (await db.execute(select(func.now()))).scalar_one()


async def _ticket_state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None, uuid.UUID | None, bool]:
    """The persisted `(status, assignee_id, duplicate_of_id,
    is_confidential)` of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return (row.status, row.assignee_id, row.duplicate_of_id, row.is_confidential)


def _forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every `FORBIDDEN` collaborator with a recorder that fails."""
    calls: list[str] = []
    for name in FORBIDDEN:

        def _called(*_args: Any, _name: str = name, **_kwargs: Any) -> Any:
            calls.append(_name)
            raise AssertionError(f"{_name} must not be called")

        monkeypatch.setattr(ticket_service, name, _called)
    return calls


def _insert_tables(recorder: StatementRecorder) -> list[str]:
    """The target tables of the recorded `INSERT` statements."""
    return sorted(
        s.split()[2] for s in recorder.writes() if s.lstrip().startswith("INSERT")
    )


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


async def _assert_rejected(
    db: AsyncSession,
    op: str,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    scope: Scope = Scope.ALL,
) -> None:
    """Call the operation and assert the zero-side-effect contract of a
    rejection: the expected error, no write statement, the Ticket's grants
    unchanged, and no event."""
    before = await _grants(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _mutate(op, db, ticket_id, target, actor, scope=scope)

    assert recorder.writes() == []
    assert await _grants(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# Grant creation matrix
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGrantCreation:
    @pytest.mark.parametrize("form", FORMS)
    async def test_new_active_target_is_created_with_one_exact_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        form: str,
    ) -> None:
        """`grant_access` steps 7-10: one row attributed to the acting
        user with the database-assigned `granted_at`, one exact
        `access_grant_added`, and the `created` result whose projection
        carries the current target and grantor profiles."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-a", full_name="Grantee A")
        ticket = await ticket_factory(is_confidential=True)
        now = await _transaction_now(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await _grant(
                db_session, ticket.id, _identifier(target, form), actor
            )

        assert result.action is AccessGrantAction.CREATED
        assert result.action.value == "created"
        assert (
            result.grant.ticket_id,
            result.grant.user_id,
            result.grant.granted_by_id,
            result.grant.granted_at,
        ) == (ticket.id, target.id, actor.id, now)
        assert result.projection == AccessGrantProjection(
            user=_profile(
                target, username="grantee-a", full_name="Grantee A", active=True
            ),
            granted_at=now,
            granted_by=_profile(
                actor, username=actor.username, full_name=None, active=True
            ),
        )
        assert _insert_tables(recorder) == ["ticket_access_grant", "ticket_audit_event"]
        assert len(recorder.writes()) == 2
        assert await _grants(db_session, ticket.id) == {(target.id, actor.id, now)}
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(actor, "grantee-a")
        ]

    @pytest.mark.parametrize("form", FORMS)
    async def test_new_inactive_target_is_rejected_without_row_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        form: str,
    ) -> None:
        """Step 7: only an absent grant checks activity."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-inactive", active=False)
        ticket = await ticket_factory(is_confidential=True)

        await _assert_rejected(
            db_session,
            "grant",
            InactiveUserError,
            ticket_id=ticket.id,
            target=_identifier(target, form),
            actor=actor,
        )
        assert await _grants(db_session, ticket.id) == set()

    @pytest.mark.parametrize("active", [True, False], ids=["active", "inactive"])
    async def test_existing_grant_is_returned_with_original_provenance(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        active: bool,
    ) -> None:
        """Step 6 (tickets.md, Grant Access > Idempotency): the existing
        grant keeps its original granter and `granted_at`, is returned as
        `already_exists` without an activity check, write, or event, and
        projects the current profiles (an inactive target with `active =
        False`)."""
        actor = await va_user()
        granter = await _person(user_factory, "granter-b", full_name="Granter B")
        target = await _person(
            user_factory, "grantee-c", active=active, full_name="Grantee C"
        )
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id,
            user_id=target.id,
            granted_by_id=granter.id,
            granted_at=PAST,
        )

        with StatementRecorder(db_session) as recorder:
            result = await _grant(db_session, ticket.id, str(target.id), actor)

        assert result.action is AccessGrantAction.ALREADY_EXISTS
        assert result.action.value == "already_exists"
        assert (result.grant.granted_by_id, result.grant.granted_at) == (
            granter.id,
            PAST,
        )
        assert result.projection == AccessGrantProjection(
            user=_profile(
                target, username="grantee-c", full_name="Grantee C", active=active
            ),
            granted_at=PAST,
            granted_by=_profile(
                granter, username="granter-b", full_name="Granter B", active=True
            ),
        )
        assert recorder.writes() == []
        assert await _grants(db_session, ticket.id) == {(target.id, granter.id, PAST)}
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Revoke matrix
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRevoke:
    @pytest.mark.parametrize("active", [True, False], ids=["active", "inactive"])
    @pytest.mark.parametrize("form", FORMS)
    async def test_existing_grant_is_deleted_with_one_exact_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        form: str,
        active: bool,
    ) -> None:
        """`revoke_access` steps 7-9: activity is not a revoke guard. Only
        the target's grant on this Ticket is deleted; another user's grant
        on the Ticket and the target's grant on another Ticket are
        untouched."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-d", active=active)
        bystander = await _person(user_factory, "grantee-e")
        ticket = await ticket_factory(is_confidential=True)
        other = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=target.id)
        kept = await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=bystander.id, granted_at=PAST
        )
        elsewhere = await ticket_access_grant_factory(
            ticket_id=other.id, user_id=target.id, granted_at=PAST
        )

        with StatementRecorder(db_session) as recorder:
            await _revoke(db_session, ticket.id, _identifier(target, form), actor)

        deletions = [w for w in recorder.writes() if "ticket_access_grant" in w]
        assert len(deletions) == 1
        assert deletions[0].lstrip().startswith("DELETE FROM ticket_access_grant")
        assert _insert_tables(recorder) == ["ticket_audit_event"]
        assert await _grants(db_session, ticket.id) == {
            (bystander.id, kept.granted_by_id, PAST)
        }
        assert await _grants(db_session, other.id) == {
            (target.id, elsewhere.granted_by_id, PAST)
        }
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _removed(actor, "grantee-d")
        ]
        assert await ticket_events_by_id(db_session, other.id) == []

    @pytest.mark.parametrize("active", [True, False], ids=["active", "inactive"])
    @pytest.mark.parametrize("form", FORMS)
    async def test_absent_grant_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        form: str,
        active: bool,
    ) -> None:
        """Step 6: no write statement and no event; the target's grant on
        another Ticket does not count and is untouched."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-f", active=active)
        ticket = await ticket_factory(is_confidential=True)
        other = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory(ticket_id=other.id, user_id=target.id)
        before = await _grants(db_session, ticket.id)
        before_other = await _grants(db_session, other.id)

        with StatementRecorder(db_session) as recorder:
            await _revoke(db_session, ticket.id, _identifier(target, form), actor)

        assert recorder.writes() == []
        assert await _grants(db_session, ticket.id) == before
        assert await _grants(db_session, other.id) == before_other
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Guard precedence (accessibility, confidentiality, deferred target result)
# ---------------------------------------------------------------------------


async def _target(kind: str, user_factory: UserFactory) -> tuple[str, User | None]:
    """A raw UUID identifier of a target of the given kind: no User
    (`absent`), an inactive User, or an active User."""
    if kind == "absent":
        return str(uuid.uuid7()), None
    user = await _person(user_factory, f"grantee-{kind}", active=kind != "inactive")
    return str(user.id), user


@pytest.mark.integration
class TestPrecedence:
    @pytest.mark.parametrize("kind", ["active", "inactive", "absent"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_missing_ticket_is_not_found_whatever_the_target(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        va_user: VAUser,
        op: str,
        kind: str,
    ) -> None:
        """Steps 2-3: the deferred target result is never disclosed."""
        actor = await va_user()
        target, _ = await _target(kind, user_factory)

        await _assert_rejected(
            db_session,
            op,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            target=target,
            actor=actor,
        )

    @pytest.mark.parametrize("kind", ["active", "inactive", "absent", "granted"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        op: str,
        kind: str,
    ) -> None:
        """Step 3: a `non_confidential`-scope caller without a grant or
        maintainership. Denial precedes the target-absent, inactive, and
        no-op/existing-grant decisions (`granted`: the target already holds
        a grant, so grant would be `already_exists` and revoke effective)."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        target, user = await _target(
            "active" if kind == "granted" else kind, user_factory
        )
        if kind == "granted":
            assert user is not None
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)

        await _assert_rejected(
            db_session,
            op,
            TicketNotFoundError,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("kind", ["active", "absent"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_non_confidential_ticket_is_rejected_whether_or_not_target_exists(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        op: str,
        kind: str,
    ) -> None:
        """Step 4: the confidentiality guard precedes the deferred
        target-user result."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=False)
        target, _ = await _target(kind, user_factory)

        await _assert_rejected(
            db_session,
            op,
            TicketNotConfidentialError,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
        )

    @pytest.mark.parametrize("form", FORMS)
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_absent_target_of_an_accessible_confidential_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        op: str,
        form: str,
    ) -> None:
        """Step 5: `UserNotFoundError` is reachable only here; another
        user's grant on the Ticket is untouched."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        target = str(uuid.uuid7()) if form == "uuid" else "absent-user"

        await _assert_rejected(
            db_session,
            op,
            UserNotFoundError,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
        )

    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_caller_mismatch_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        op: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        target = await _person(user_factory, "grantee-g")
        ticket = await ticket_factory(is_confidential=True)
        operation = grant_access if op == "grant" else revoke_access

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await operation(
                db_session,
                ticket_id=ticket.id,
                target_user=str(target.id),
                acting_user_id=actor.id,
                caller=_caller(other, Scope.ALL),
            )

        assert recorder.statements == []
        assert await _grants(db_session, ticket.id) == set()
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Lock order and statements
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockOrder:
    @pytest.mark.parametrize("form", FORMS)
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_target_no_key_update_then_ticket_update_without_role_load(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        op: str,
        form: str,
    ) -> None:
        """Locking: the first statement resolves and locks the target User
        `FOR NO KEY UPDATE` from the supplied identifier; the next row lock
        is the Ticket `FOR UPDATE`, and there is no other. No role origin
        is loaded, and after the Ticket lock no statement selects from the
        User table (the grant projection only joins it) or reads audit
        history. The effective paths are used: a new grant and a revoke of
        an existing one."""
        actor = await va_user()
        target = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        if op == "revoke":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=target.id)
        identifier = _identifier(target, form)

        with StatementRecorder(db_session) as recorder:
            await _mutate(op, db_session, ticket.id, identifier, actor)

        statements = recorder.statements
        assert 'FROM "user"' in statements[0]
        assert "FOR NO KEY UPDATE" in statements[0]
        expected_bound = target.id if form == "uuid" else target.username
        assert expected_bound in _bound(recorder.parameters[0])
        assert "FROM ticket" in statements[1]
        assert "FOR UPDATE" in statements[1]
        assert "FOR NO KEY UPDATE" not in statements[1]
        assert ticket.id in _bound(recorder.parameters[1])
        assert recorder.row_locks() == [statements[0], statements[1]]
        assert [s for s in statements if "user_role" in s] == []
        assert [s for s in statements[2:] if 'FROM "user"' in s] == []
        assert recorder.selects_from("ticket_audit_event") == []
        assert not any('"user"' in w for w in recorder.writes())


# ---------------------------------------------------------------------------
# Every Ticket status (operability opt-out)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEveryStatus:
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=str)
    async def test_grant_and_revoke_succeed_without_lifecycle_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """Operability guard (explicit opt-out) and testing-strategy.md,
        Confidentiality and explicit access grants: an unassigned Ticket
        and an active VA actor make any auto-assignment observable. Both
        operations succeed in every status, including `Ignored` and
        `Duplicated`, without `TicketNotMutableError`, assignment,
        reconciliation, status change, or post-commit registration."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-h")
        ticket = await ticket_factory(status=status.value, is_confidential=True)
        before = await _ticket_state(db_session, ticket.id)
        calls = _forbid(monkeypatch)

        result = await _grant(db_session, ticket.id, str(target.id), actor)
        assert result.action is AccessGrantAction.CREATED
        await _revoke(db_session, ticket.id, str(target.id), actor)

        assert calls == []
        assert await _ticket_state(db_session, ticket.id) == before
        assert before[:2] == (status.value, None)
        assert await _grants(db_session, ticket.id) == set()
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(actor, "grantee-h"),
            _removed(actor, "grantee-h"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "flush", "caller"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_failure_or_caller_rollback_leaves_the_pre_state(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        failure: str,
    ) -> None:
        """An effective grant (absent grant, active target) or revoke
        (existing grant) fails at its audit write or at the flush inserting
        the event, or succeeds and is rolled back by the caller. Afterwards
        a grant leaves neither row nor event; a revoke's row is restored
        with its original provenance and no event exists."""
        actor = await va_user()
        target = await _person(user_factory, "grantee-i")
        ticket = await ticket_factory(is_confidential=True)
        if op == "revoke":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=target.id, granted_at=PAST
            )
        ticket_id, target_id = ticket.id, str(target.id)
        before = await _grants(db_session, ticket_id)
        event_type = (
            TicketAuditEventType.ACCESS_GRANT_ADDED
            if op == "grant"
            else TicketAuditEventType.ACCESS_GRANT_REMOVED
        )
        reached = False
        original_log = TicketAuditLog.log_event
        original_flush = db_session.flush

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if kwargs["event_type"] is event_type:
                reached = True
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(isinstance(o, TicketAuditEvent) for o in db_session.new):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "caller":
                await _mutate(op, db_session, ticket_id, target_id, actor)
                reached = await _grants(db_session, ticket_id) != before and (
                    len(await ticket_events_by_id(db_session, ticket_id)) == 1
                )
            else:
                if failure == "audit":
                    monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
                else:
                    monkeypatch.setattr(db_session, "flush", failing_flush)
                with pytest.raises(RuntimeError, match="injected"):
                    await _mutate(op, db_session, ticket_id, target_id, actor)
        monkeypatch.undo()

        assert reached
        assert await _grants(db_session, ticket_id) == before
        assert await ticket_events_by_id(db_session, ticket_id) == []

    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        op: str,
    ) -> None:
        actor = await va_user()
        target = await _person(user_factory, "grantee-j")
        ticket = await ticket_factory(is_confidential=True)
        if op == "revoke":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=target.id)

        async def forbidden() -> None:
            raise AssertionError(f"{op} must not commit or roll back")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _mutate(op, db_session, ticket.id, str(target.id), actor)


# ---------------------------------------------------------------------------
# ATR 15 converse: self-loss through the caller's own grant
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSelfLoss:
    async def test_revoking_the_callers_only_grant_succeeds_then_later_reads_deny(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        """ticket-service.md, Caller category and Ticket accessibility:
        authorization uses the locked pre-mutation state, so revoking the
        caller's last visibility path returns the ordinary success and
        only later requests are denied.

        Service-level only: over HTTP this is unreachable with the
        predefined roles, because `manage_confidentiality` exists only in
        `vulnerability_analyst`, whose scope is `all` (rbac.md)."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        caller = _caller(actor, Scope.NON_CONFIDENTIAL)

        await revoke_access(
            db_session,
            ticket_id=ticket.id,
            target_user=str(actor.id),
            acting_user_id=actor.id,
            caller=caller,
        )

        assert await _grants(db_session, ticket.id) == set()
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _removed(actor, actor.username)
        ]
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(
                db_session, format_ticket_id(ticket.sequence_id), caller
            )


# ---------------------------------------------------------------------------
# Listing (ATR 16)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListing:
    async def test_current_profiles_in_fixed_order_with_one_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
    ) -> None:
        """tickets.md, List Access Grants and TicketAccessGrantResponse:
        complete current profiles of target and grantor (set and `NULL`
        `full_name`; deactivated target and grantor with `active =
        False`), ordered `granted_at ASC, user_id ASC`. Two grants share
        one `granted_at` and are inserted in descending UUID order, and the
        earliest grant is inserted last, so neither insertion order nor a
        single sort key satisfies the assertion. A grantor's profile
        changed after the grant is projected as current. One statement, no
        event, and another Ticket's grant is not listed."""
        actor = await va_user()
        grantee_a = await _person(user_factory, "grantee-a", full_name="Grantee A")
        grantee_b = await _person(user_factory, "grantee-b")
        grantee_c = await _person(
            user_factory, "grantee-c", active=False, full_name="Grantee C"
        )
        granter_x = await _person(user_factory, "granter-x", full_name="Granter X")
        granter_y = await _person(user_factory, "granter-y", active=False)
        ticket = await ticket_factory(is_confidential=True)
        other = await ticket_factory(is_confidential=True)
        low, high = sorted((grantee_a, grantee_b), key=lambda u: u.id)
        for user in (high, low):
            await ticket_access_grant_factory(
                ticket_id=ticket.id,
                user_id=user.id,
                granted_by_id=granter_y.id,
                granted_at=PAST,
            )
        await ticket_access_grant_factory(
            ticket_id=ticket.id,
            user_id=grantee_c.id,
            granted_by_id=granter_x.id,
            granted_at=EARLIER,
        )
        await ticket_access_grant_factory(ticket_id=other.id, user_id=grantee_a.id)
        granter_x.full_name = "Granter X Renamed"
        await db_session.flush()

        with StatementRecorder(db_session) as recorder:
            listed = await _list(db_session, ticket.id, actor)

        profiles = {
            grantee_a.id: _profile(
                grantee_a, username="grantee-a", full_name="Grantee A", active=True
            ),
            grantee_b.id: _profile(
                grantee_b, username="grantee-b", full_name=None, active=True
            ),
        }
        by_y = _profile(granter_y, username="granter-y", full_name=None, active=False)
        assert listed == [
            AccessGrantProjection(
                user=_profile(
                    grantee_c, username="grantee-c", full_name="Grantee C", active=False
                ),
                granted_at=EARLIER,
                granted_by=_profile(
                    granter_x,
                    username="granter-x",
                    full_name="Granter X Renamed",
                    active=True,
                ),
            ),
            AccessGrantProjection(
                user=profiles[low.id], granted_at=PAST, granted_by=by_y
            ),
            AccessGrantProjection(
                user=profiles[high.id], granted_at=PAST, granted_by=by_y
            ),
        ]
        assert len(recorder.statements) == 1
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_accessible_confidential_ticket_without_grants_is_empty(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory()

        with StatementRecorder(db_session) as recorder:
            assert await _list(db_session, ticket.id, actor) == []

        assert len(recorder.statements) == 1

    @pytest.mark.parametrize("scope", [Scope.ALL, Scope.NON_CONFIDENTIAL], ids=str)
    async def test_non_confidential_ticket_is_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        scope: Scope,
    ) -> None:
        """Step 2: a non-confidential Ticket is visible to every caller and
        is rejected rather than listed."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=False)

        with pytest.raises(TicketNotConfidentialError):
            await _list(db_session, ticket.id, actor, scope=scope)

    @pytest.mark.parametrize(
        "case", ["missing", "inaccessible-with-grants", "inaccessible-without-grants"]
    )
    async def test_missing_or_inaccessible_ticket_is_not_found_never_empty(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        case: str,
    ) -> None:
        """Step 1: a `non_confidential`-scope caller without a grant or
        maintainership; other users' grants are never returned."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket_id = uuid.uuid7()
        if case != "missing":
            ticket = await ticket_factory(is_confidential=True)
            ticket_id = ticket.id
            if case == "inaccessible-with-grants":
                await ticket_access_grant_factory(ticket_id=ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _list(db_session, ticket_id, actor, scope=Scope.NON_CONFIDENTIAL)

        assert len(recorder.statements) == 1

    @pytest.mark.parametrize(
        ("path", "visible"),
        [
            ("own-grant", True),
            ("included-package-maintainer", True),
            ("excluded-package-maintainer", False),
        ],
    )
    async def test_visibility_paths(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        user_factory: UserFactory,
        va_user: VAUser,
        path: str,
        visible: bool,
    ) -> None:
        """rbac.md, Scope and Confidential Ticket Visibility, for a
        `non_confidential`-scope caller: the caller's own grant and a
        maintainership under an included package authorize the listing;
        a maintainership under an excluded package does not."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        grantee = await _person(user_factory, "grantee-k")
        ticket = await ticket_factory(is_confidential=True)
        grant = await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=grantee.id, granted_at=PAST
        )
        expected_users = {grantee.id}
        if path == "own-grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=actor.id, granted_at=EARLIER
            )
            expected_users.add(actor.id)
        else:
            package = await ticket_package_factory(
                ticket_id=ticket.id,
                deleted_at=None if visible else datetime(2026, 9, 1, 8, 0, tzinfo=UTC),
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=actor.id
            )

        if not visible:
            with pytest.raises(TicketNotFoundError):
                await _list(db_session, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)
            return

        listed = await _list(db_session, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)
        assert {p.user.id for p in listed} == expected_users
        assert listed[-1].user.id == grantee.id
        assert listed[-1].granted_by.id == grant.granted_by_id


# ---------------------------------------------------------------------------
# Reactivation retains grants (audit Testing Requirement 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReactivationRetention:
    async def test_reactivation_writes_no_grant_and_creates_no_ticket_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
    ) -> None:
        """user-service.md, `reactivate_user()`: a retained grant is not
        restored because it was never removed; no grant row is inserted,
        updated, or deleted and no Ticket audit event exists. The grant's
        current projection then shows the target active."""
        admin = await va_user()
        grantee = await _person(user_factory, "grantee-l", active=False)
        granter = await _person(user_factory, "granter-l")
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id,
            user_id=grantee.id,
            granted_by_id=granter.id,
            granted_at=PAST,
        )

        with StatementRecorder(db_session) as recorder:
            result = await reactivate_user(
                db_session, grantee.id, acting_user_id=admin.id
            )

        assert result.reactivated is True
        assert [w for w in recorder.writes() if "ticket_access_grant" in w] == []
        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []
        assert await _grants(db_session, ticket.id) == {(grantee.id, granter.id, PAST)}
        assert await ticket_events_by_id(db_session, ticket.id) == []
        (projection,) = await _list(db_session, ticket.id, admin)
        assert projection.user == _profile(
            grantee, username="grantee-l", full_name=None, active=True
        )

    async def test_grant_deleted_by_declassification_is_not_recreated(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        user_factory: UserFactory,
        va_user: VAUser,
    ) -> None:
        """user-service.md, `reactivate_user()`, and ticket-audit-log.md,
        the bullets after the Event Type Contract: a grant deleted by
        declassification while its user was inactive stays absent after
        reactivation and after reclassification; only the two
        `confidentiality_changed` events exist."""
        actor = await va_user()
        grantee = await _person(user_factory, "grantee-m", active=False)
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=grantee.id)
        caller = _caller(actor, Scope.ALL)

        await set_confidentiality(
            db_session,
            ticket_id=ticket.id,
            is_confidential=False,
            acting_user_id=actor.id,
            caller=caller,
        )
        await reactivate_user(db_session, grantee.id, acting_user_id=actor.id)
        assert await _grants(db_session, ticket.id) == set()
        await set_confidentiality(
            db_session,
            ticket_id=ticket.id,
            is_confidential=True,
            acting_user_id=actor.id,
            caller=caller,
        )

        assert await _grants(db_session, ticket.id) == set()
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, "true", "false"),
            _changed(actor, "false", "true"),
        ]
