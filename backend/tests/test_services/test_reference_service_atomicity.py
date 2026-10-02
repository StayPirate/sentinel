"""Atomicity, rollback, and independent-session tests for the manual Ticket
reference operations (backend/app/services/reference_service.py):
`create_reference()`, `update_reference()`, `delete_reference()`, and the
`list_references()` read.

Owning specifications:

- docs/features/tickets/ticket-references.md (Mutability and Concurrency:
  Manual Mutation Ordering and Race Outcomes, the manual/manual bullets and
  "If automatic insertion owns the normalized URL before manual create or a
  manual URL change, the manual operation returns `ReferenceConflictError`
  and creates no event"; Service Layer: transaction ownership, Service
  Exceptions, `create_reference()`, `update_reference()`,
  `delete_reference()`, `list_references()`; Ticket Audit Events).
- docs/features/tickets/ticket-audit-log.md (Cross-Event Ordering,
  Locking, and Rollback; Testing Requirements 7 and 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation; Audit Trail Testing; Ticket Accessibility: Single,
  nested, and assembled reads and Locked mutations; Ticket References:
  "Audit, rollback, and concurrency", bullets 1-3).
- docs/conventions.md (Transaction and Locking: Caller-Owned Service
  Transactions, Pessimistic Locking Pattern).

The single-session behavior (field states, exact events, no-ops,
precedence, validation, accessibility matrix) is covered by
`tests/test_services/test_reference_service.py`; this module adds only:

- caller-owned transactions: a caller rollback after a successful return
  removes every row change and event;
- injected database (reference write), audit-validation, audit-insert, and
  final-flush failures, including a multi-field PATCH failing on its second
  or third event: the exception propagates unchanged and the caller's
  rollback leaves no row change and no event;
- a non-uniqueness `IntegrityError` on the reference write (a genuine
  foreign-key violation and an injected error naming another constraint)
  propagates unchanged and is never a `ReferenceConflictError`;
- the uniqueness backstop: a genuine `(ticket_id, url)` uniqueness
  violation reached by the reference write is the only integrity error
  mapped to `ReferenceConflictError`, with no event, and the caller's
  transaction stays usable (the write ran inside a savepoint);
- committed cross-transaction timestamps: an equivalent-only PATCH keeps
  `updated_at`; a later effective PATCH advances it;
- the automatic-first race through independent sessions: the automatic
  row is inserted by `upsert_references()`, which acquires no Ticket
  lock. The insert's foreign-key check holds `FOR KEY SHARE` on the
  parent Ticket, so manual create and manual URL change wait at their
  Ticket `FOR UPDATE` and then observe the committed automatic row (or
  its absence after rollback);
- manual/manual races (create/create, update/update on one reference and
  on two references competing for one URL, update/delete in both orders,
  delete/delete), each waiter proven blocked on the Ticket lock;
- locked-current accessibility races for the three Ticket-path visibility
  losses, and the single-read coherence of `list_references()`.

Out of scope: the remaining manual/automatic races, automatic/automatic
races, and the committed forced automatic unique-key conflict
(`tests/test_services/test_reference_ingestion_races.py`); single-session
automatic ingestion, including candidate order
(`tests/test_services/test_reference_ingestion.py`); and per-CVE rollback,
which belongs to the CVE ingestion workflow tests.

Every race keeps the winner's transaction open, proves the waiter blocked
with `assert_lock_wait()` (never a sleep), and then releases the winner.
Committed rows are deleted explicitly at teardown by `CommittedWorld`
(testing-strategy.md, Concurrency Testing); `ticket_reference` rows are
removed by their `ON DELETE CASCADE` Ticket foreign key. Event assertions
read committed state through an independent probe session. Expected values
are transcribed from the specifications, never computed with the module
under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.engine import Connection
from sqlalchemy.exc import (
    DBAPIError,
    EmulatedDBAPIException,
    IntegrityError,
    OperationalError,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.core.enums import ReferenceType, Role, Scope, TicketAuditEventType
from app.core.exceptions import TicketNotFoundError
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.services import reference_service
from app.services.reference_service import (
    AutomaticReferenceInput,
    ManualReferenceCreateInput,
    ManualReferenceUpdateInput,
    ReferenceConflictError,
    ReferenceNotFoundError,
    ReferenceServiceError,
    TicketReferenceProjection,
    create_reference,
    delete_reference,
    list_references,
    update_reference,
    upsert_references,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Call = Callable[[AsyncSession], Awaitable[Any]]

AUTO_SOURCE = "sync_example_cves"
"""A fictional stable automatic fetcher name (ticket-references.md,
TicketReference: `source`)."""

CVE_ID = "CVE-2026-0001"
"""The canonical CVE ID passed to `upsert_references()`."""

SEEDED_URL = "https://issues.example.test/tickets/1"
SEEDED_RAW_VARIANT = "HTTP://ISSUES.EXAMPLE.TEST/tickets/1"
"""Normalizes to `SEEDED_URL` (URL Normalization)."""

OTHER_URL = "https://issues.example.test/tickets/2"

NEW_RAW_URL = "http://New.Example.TEST/advisories/7"
NEW_URL = "https://new.example.test/advisories/7"
NEW_RAW_VARIANT = "HTTPS://NEW.EXAMPLE.TEST/advisories/7"
"""Both raw forms normalize to `NEW_URL`."""

AUTO_URL = "https://advisory.example.test/1"
AUTO_RAW_VARIANT = "HTTP://Advisory.Example.TEST/1"
"""Normalizes to `AUTO_URL`."""

SPARE_URL = "https://spare.example.test/notes/3"
"""An unrelated identity used to prove a transaction is still usable."""

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)

MISSING_TICKET_ID = "00000000-0000-7000-8000-000000000000"
"""A Ticket UUID that is never persisted (foreign-key violation)."""

UNIQUE_URL_CONSTRAINT = "uq_ticket_reference_ticket_id_url"
"""The `(ticket_id, url)` identity constraint (docs/data-model.md)."""

FAILING_SQL = "SELECT 1 / 0"
"""A statement PostgreSQL rejects (`division_by_zero`), so the injected
database failure is genuine and aborts the transaction."""

INVALID_COMMENT = "Injected non-canonical comment"
"""Every reference event requires `comment = NULL`
(ticket-audit-log.md, Event Type Contract), so `log_event()` rejects this
value with `ValueError` during validation."""

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def probe(world: CommittedWorld) -> AsyncSession:
    """An independent session that only observes committed state."""
    return await world.open_session()


@dataclass(frozen=True, slots=True)
class RefRow:
    """One persisted reference, as stored."""

    url: str
    title: str | None
    description: str | None
    type: str | None
    source: str
    created_at: datetime
    updated_at: datetime


Committed = tuple[dict[uuid.UUID, RefRow], list[EventRow]]
"""The committed references of a Ticket keyed by id, and its audit events
in insertion order."""


async def _committed(probe: AsyncSession, ticket: Ticket) -> Committed:
    result = await probe.execute(
        select(
            TicketReference.id,
            TicketReference.url,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    rows = {r.id: RefRow(*r[1:]) for r in result}
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return rows, events


async def _session_rows(
    session: AsyncSession, ticket: Ticket
) -> dict[uuid.UUID, tuple[str, str | None, str | None, str | None]]:
    """`(url, type, title, description)` per reference, as seen by
    `session` inside its own (uncommitted) transaction."""
    result = await session.execute(
        select(
            TicketReference.id,
            TicketReference.url,
            TicketReference.type,
            TicketReference.title,
            TicketReference.description,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return {r.id: (r.url, r.type, r.title, r.description) for r in result}


async def _ticket(world: CommittedWorld, *, confidential: bool = False) -> Ticket:
    """A committed CVE-less `Analysis` Ticket registered for cleanup."""
    return await world.ticket(cve_id=None, is_confidential=confidential)


async def _actor(world: CommittedWorld) -> User:
    return await world.user(role=Role.VULNERABILITY_ANALYST)


async def _seed(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    url: str = SEEDED_URL,
    title: str | None = "Original title",
    description: str | None = "Original description",
    type: str | None = "issue",
    source: str = "manual",
    updated_at: datetime | None = None,
) -> uuid.UUID:
    """A committed reference with fully populated defaults."""
    reference = TicketReference(
        ticket_id=ticket.id,
        url=url,
        title=title,
        description=description,
        type=type,
        source=source,
    )
    if updated_at is not None:
        reference.created_at = updated_at
        reference.updated_at = updated_at
    world.session.add(reference)
    await world.session.commit()
    return reference.id


def _locator(ticket: Ticket) -> str:
    """The canonical `SNTL-{n}` locator, built literally."""
    return f"SNTL-{ticket.sequence_id}"


def _caller(user: User, scope: Scope = Scope.ALL) -> TicketCaller:
    return TicketCaller.authenticated(user.id, scope)


def _create(
    ticket: Ticket, actor: User, url: str, *, scope: Scope = Scope.ALL, **fields: Any
) -> Call:
    def call(db: AsyncSession) -> Awaitable[TicketReferenceProjection]:
        return create_reference(
            db,
            _locator(ticket),
            _caller(actor, scope),
            ManualReferenceCreateInput(url=url, **fields),
        )

    return call


def _update(
    ticket: Ticket,
    reference_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    **fields: Any,
) -> Call:
    def call(db: AsyncSession) -> Awaitable[TicketReferenceProjection]:
        return update_reference(
            db,
            _locator(ticket),
            reference_id,
            _caller(actor, scope),
            ManualReferenceUpdateInput(**fields),
        )

    return call


def _delete(
    ticket: Ticket, reference_id: uuid.UUID, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    def call(db: AsyncSession) -> Awaitable[None]:
        return delete_reference(
            db, _locator(ticket), reference_id, _caller(actor, scope)
        )

    return call


async def _list(
    db: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> list[TicketReferenceProjection]:
    return await list_references(
        db, _locator(ticket), caller, source=None, type=None, type_was_supplied=False
    )


def _added(actor: User, url: str) -> EventRow:
    return EventRow("reference_added", actor.id, None, url, None, None)


def _deleted(actor: User, url: str) -> EventRow:
    return EventRow("reference_deleted", actor.id, url, None, None, None)


def _url_changed(actor: User, old: str, new: str) -> EventRow:
    return EventRow("reference_url_changed", actor.id, old, new, None, None)


def _field_changed(
    field: str, actor: User, old: str | None, new: str | None, url: str
) -> EventRow:
    return EventRow(
        f"reference_{field}_changed", actor.id, old, new, None, {"url": url}
    )


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _sync_connection(session: AsyncSession) -> Connection:
    bind = session.bind
    assert isinstance(bind, AsyncConnection)
    connection = bind.sync_connection
    assert connection is not None
    return connection


class _Rewrite:
    """Replaces the `nth` statement of one session's connection that starts
    with `prefix` by `replacement` (without parameters), so PostgreSQL
    itself fails at exactly that write. `reached` counts the matches."""

    def __init__(self, prefix: str, replacement: str, nth: int) -> None:
        self.prefix = prefix
        self.replacement = replacement
        self.nth = nth
        self.reached = 0

    def __call__(
        self,
        _conn: Any,
        _cursor: Any,
        statement: str,
        parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> tuple[str, Any]:
        if statement.lstrip().startswith(self.prefix):
            self.reached += 1
            if self.reached == self.nth:
                return self.replacement, ()
        return statement, parameters


@contextmanager
def _rewrite(
    session: AsyncSession, prefix: str, replacement: str = FAILING_SQL, nth: int = 1
) -> Iterator[_Rewrite]:
    rewrite = _Rewrite(prefix, replacement, nth)
    connection = _sync_connection(session)
    event.listen(connection, "before_cursor_execute", rewrite, retval=True)
    try:
        yield rewrite
    finally:
        event.remove(connection, "before_cursor_execute", rewrite)


class _FakeConstraintError(Exception):
    """A driver error naming a constraint, as asyncpg errors do."""

    def __init__(self, constraint_name: str) -> None:
        super().__init__(f"violates constraint {constraint_name}")
        self.constraint_name = constraint_name


def _constraint_name(exc: DBAPIError) -> object:
    return getattr(exc.driver_exception, "constraint_name", None)


def _sqlstate(exc: DBAPIError) -> object:
    return getattr(exc.driver_exception, "sqlstate", None)


# ---------------------------------------------------------------------------
# Caller-owned transaction (Service Layer; ticket-audit-log.md TR 7)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCallerRollback:
    """The functions never commit; the workflow owner's rollback after a
    successful return removes the row change and every event."""

    async def test_create_then_caller_rollback_leaves_nothing(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        session = await world.open_session()

        result = await _create(ticket, actor, NEW_RAW_URL, title="Fictional")(session)

        assert await _session_rows(session, ticket) == {
            result.id: (NEW_URL, None, "Fictional", None)
        }
        assert await ticket_events_by_id(session, ticket.id) == [_added(actor, NEW_URL)]
        await session.rollback()
        assert await _committed(probe, ticket) == ({}, [])

    async def test_multi_field_update_then_caller_rollback_restores_everything(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """`update_reference()`: caller rollback leaves all fields,
        `updated_at`, and events unchanged."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        session = await world.open_session()

        result = await _update(
            ticket,
            reference_id,
            actor,
            url=NEW_RAW_URL,
            type=ReferenceType.ADVISORY,
            title="New title",
            description="New description",
        )(session)

        assert result.updated_at > PAST
        assert await _session_rows(session, ticket) == {
            reference_id: (NEW_URL, "advisory", "New title", "New description")
        }
        assert len(await ticket_events_by_id(session, ticket.id)) == 4
        await session.rollback()
        assert before[0][reference_id].updated_at == PAST
        assert await _committed(probe, ticket) == before
        assert before[1] == []

    async def test_delete_then_caller_rollback_retains_the_row(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        session = await world.open_session()

        await _delete(ticket, reference_id, actor)(session)

        assert await _session_rows(session, ticket) == {}
        assert await ticket_events_by_id(session, ticket.id) == [
            _deleted(actor, SEEDED_URL)
        ]
        await session.rollback()
        assert await _committed(probe, ticket) == before
        assert list(before[0]) == [reference_id]


# ---------------------------------------------------------------------------
# Injected failures (Race Outcomes: "Database, audit, or flush failure rolls
# back the complete caller-owned transaction"; testing-strategy.md bullet 2)
# ---------------------------------------------------------------------------

_WRITE_PREFIX = {
    "create": "INSERT INTO ticket_reference",
    "update": "UPDATE ticket_reference",
    "delete": "DELETE FROM ticket_reference",
}
_AUDIT_PREFIX = "INSERT INTO ticket_audit_event"
_EVENT_COUNT = {"create": 1, "update": 4, "delete": 1}

_FAILURE_CASES = [
    pytest.param("create", "reference-write", 1, id="create-reference-write"),
    pytest.param("create", "audit-validation", 1, id="create-audit-validation"),
    pytest.param("create", "audit-insert", 1, id="create-audit-insert"),
    pytest.param("create", "final-flush", 1, id="create-final-flush"),
    pytest.param("update", "reference-write", 1, id="update-reference-write"),
    pytest.param("update", "audit-validation", 2, id="update-audit-validation-2nd"),
    pytest.param("update", "audit-validation", 3, id="update-audit-validation-3rd"),
    pytest.param("update", "audit-insert", 2, id="update-audit-insert-2nd"),
    pytest.param("update", "audit-insert", 3, id="update-audit-insert-3rd"),
    pytest.param("update", "final-flush", 4, id="update-final-flush"),
    pytest.param("delete", "reference-write", 1, id="delete-reference-write"),
    pytest.param("delete", "audit-validation", 1, id="delete-audit-validation"),
    pytest.param("delete", "audit-insert", 1, id="delete-audit-insert"),
    pytest.param("delete", "final-flush", 1, id="delete-final-flush"),
]
"""`(operation, failure, nth)`: `nth` is the 1-based event at which an
audit failure happens; for `final-flush` it is the number of events
logged before the service's final flush."""


@pytest.mark.integration
class TestInjectedFailures:
    """Each failure propagates unchanged (never as a `Reference*Error`);
    the caller's rollback then leaves the committed reference rows and the
    zero-event history exactly as before. The update is a multi-field PATCH
    of all four fields, so a failure at its second or third event happens
    after the row change and the earlier event(s)."""

    @pytest.mark.parametrize(("op", "failure", "nth"), _FAILURE_CASES)
    async def test_failure_rolls_back_the_complete_operation(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        failure: str,
        nth: int,
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        assert before[1] == []
        call = {
            "create": _create(ticket, actor, NEW_RAW_URL),
            "update": _update(
                ticket,
                reference_id,
                actor,
                url=NEW_RAW_URL,
                type=ReferenceType.ADVISORY,
                title="New title",
                description="New description",
            ),
            "delete": _delete(ticket, reference_id, actor),
        }[op]
        session = await world.open_session()
        original_log = TicketAuditLog.log_event
        original_flush = session.flush
        logged = 0
        injected = OperationalError(
            "FLUSH", {}, Exception("injected final flush failure")
        )

        async def counting_log(*args: Any, **kwargs: Any) -> None:
            nonlocal logged
            if failure == "audit-validation" and logged + 1 == nth:
                kwargs = {**kwargs, "comment": INVALID_COMMENT}
            await original_log(*args, **kwargs)
            logged += 1

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            if logged == nth:
                raise injected
            await original_flush(*args, **kwargs)

        monkeypatch.setattr(TicketAuditLog, "log_event", counting_log)
        if failure == "final-flush":
            monkeypatch.setattr(session, "flush", failing_flush)
        database = failure in ("reference-write", "audit-insert")
        prefix = _AUDIT_PREFIX if failure == "audit-insert" else _WRITE_PREFIX[op]
        nth_statement = nth if failure == "audit-insert" else 1
        with (
            (
                _rewrite(session, prefix, nth=nth_statement)
                if database
                else nullcontext(None)
            ) as rewrite,
            # A `Reference*Error` would escape this context and fail the test.
            pytest.raises((DBAPIError, ValueError)) as raised,
        ):
            await call(session)
        monkeypatch.undo()

        error = raised.value
        assert not isinstance(error, ReferenceServiceError)
        if database:
            assert rewrite is not None
            assert rewrite.reached == nth_statement
            assert isinstance(error, DBAPIError)
            assert not isinstance(error, IntegrityError)
            assert "division by zero" in str(error.orig)
            assert logged == nth - 1
        else:
            if failure == "audit-validation":
                assert isinstance(error, ValueError)
                assert "is not the canonical value" in str(error)
                assert logged == nth - 1
            else:
                assert error is injected
                assert logged == _EVENT_COUNT[op]
            # The transaction is still alive: the row change and the events
            # before the failure exist until the caller rolls back.
            rows = await _session_rows(session, ticket)
            if op == "create":
                assert NEW_URL in {url for url, *_ in rows.values()}
            elif op == "update":
                assert rows[reference_id] == (
                    NEW_URL,
                    "advisory",
                    "New title",
                    "New description",
                )
            else:
                assert rows == {}
            assert len(await ticket_events_by_id(session, ticket.id)) == logged
        await session.rollback()

        assert await _committed(probe, ticket) == before


# ---------------------------------------------------------------------------
# Integrity errors other than the identity conflict (Service Exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOtherIntegrityErrors:
    """Only the exact `(ticket_id, url)` uniqueness violation maps to
    `ReferenceConflictError`; any other integrity error on the reference
    write propagates unchanged."""

    @pytest.mark.parametrize("op", ["create", "update"])
    async def test_genuine_foreign_key_violation_propagates(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        op: str,
    ) -> None:
        """The reference write is replaced by a statement that violates the
        `ticket_id` foreign key in PostgreSQL."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        if op == "create":
            call = _create(ticket, actor, NEW_RAW_URL)
            replacement = (
                "INSERT INTO ticket_reference (id, ticket_id, url, source) "
                f"VALUES (uuidv7(), '{MISSING_TICKET_ID}', '{NEW_URL}', 'manual')"
            )
        else:
            call = _update(ticket, reference_id, actor, url=NEW_RAW_URL)
            replacement = (
                f"UPDATE ticket_reference SET ticket_id = '{MISSING_TICKET_ID}' "
                f"WHERE id = '{reference_id}'"
            )
        session = await world.open_session()

        with (
            _rewrite(session, _WRITE_PREFIX[op], replacement) as rewrite,
            pytest.raises(IntegrityError) as raised,
        ):
            await call(session)

        assert rewrite.reached == 1
        assert not isinstance(raised.value, ReferenceServiceError)
        assert _sqlstate(raised.value) == "23503"
        assert _constraint_name(raised.value) not in (None, UNIQUE_URL_CONSTRAINT)
        await session.rollback()
        assert await _committed(probe, ticket) == before

    @pytest.mark.parametrize("op", ["create", "update"])
    async def test_injected_integrity_error_naming_another_constraint_propagates(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        op: str,
    ) -> None:
        """The SQLAlchemy 2.1 + asyncpg shape (`exc.orig` is an emulated
        DBAPI error exposing the driver error through `driver_exception`)
        naming a constraint other than the identity constraint, raised when
        the reference write reaches the connection."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        call = (
            _create(ticket, actor, NEW_RAW_URL)
            if op == "create"
            else _update(ticket, reference_id, actor, url=NEW_RAW_URL)
        )
        session = await world.open_session()
        failure = IntegrityError(
            "INSERT",
            {},
            EmulatedDBAPIException(
                "emulated dbapi error",
                _FakeConstraintError("ck_ticket_reference_example"),
            ),
        )
        prefix = _WRITE_PREFIX[op]
        reached = 0

        def raising(
            _conn: Any,
            _cursor: Any,
            statement: str,
            _parameters: Any,
            _context: Any,
            _executemany: bool,
        ) -> None:
            nonlocal reached
            if statement.lstrip().startswith(prefix):
                reached += 1
                raise failure

        connection = _sync_connection(session)
        event.listen(connection, "before_cursor_execute", raising)
        try:
            with pytest.raises(IntegrityError) as raised:
                await call(session)
        finally:
            event.remove(connection, "before_cursor_execute", raising)

        assert reached == 1
        assert raised.value is failure
        await session.rollback()
        assert await _committed(probe, ticket) == before


# ---------------------------------------------------------------------------
# Uniqueness backstop for the identity conflict (Race Outcomes, automatic
# first; Service Exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUniquenessBackstop:
    """The locked-current pre-check normally detects an existing identity.
    To reach the database backstop deterministically, the pre-check is
    replaced by one that finds nothing; the reference write then hits the
    genuine `uq_ticket_reference_ticket_id_url` violation of a committed
    automatic row. Exactly that violation maps to `ReferenceConflictError`
    (chained to the original `IntegrityError`) and creates no event. The
    write runs inside a savepoint, so the caller's transaction stays usable:
    a later create in the same transaction commits and is the only effect."""

    @pytest.fixture(autouse=True)
    def _blind_precheck(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def nothing_owned(*_args: Any, **_kwargs: Any) -> bool:
            return False

        monkeypatch.setattr(reference_service, "_url_owned_by_other", nothing_owned)

    async def test_create_maps_only_the_identity_violation(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        await _seed(
            world,
            ticket,
            url=AUTO_URL,
            title=None,
            description=None,
            type=None,
            source=AUTO_SOURCE,
        )
        before = await _committed(probe, ticket)
        session = await world.open_session()

        with pytest.raises(ReferenceConflictError) as raised:
            await _create(ticket, actor, AUTO_RAW_VARIANT)(session)

        cause = raised.value.__cause__
        assert isinstance(cause, IntegrityError)
        assert _sqlstate(cause) == "23505"
        assert _constraint_name(cause) == UNIQUE_URL_CONSTRAINT
        assert before[1] == []

        spare = await _create(ticket, actor, SPARE_URL)(session)
        await session.commit()
        rows, events = await _committed(probe, ticket)
        assert {row_id: row for row_id, row in rows.items() if row_id != spare.id} == (
            before[0]
        )
        assert rows[spare.id].url == SPARE_URL
        assert [(e.event_type, e.new_value) for e in events] == [
            (TicketAuditEventType.REFERENCE_ADDED, SPARE_URL)
        ]

    async def test_url_change_maps_only_the_identity_violation(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        await _seed(
            world,
            ticket,
            url=AUTO_URL,
            title=None,
            description=None,
            type=None,
            source=AUTO_SOURCE,
        )
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)
        session = await world.open_session()

        with pytest.raises(ReferenceConflictError) as raised:
            await _update(ticket, reference_id, actor, url=AUTO_RAW_VARIANT)(session)

        cause = raised.value.__cause__
        assert isinstance(cause, IntegrityError)
        assert _sqlstate(cause) == "23505"
        assert _constraint_name(cause) == UNIQUE_URL_CONSTRAINT

        # Usable after the mapped conflict: the transaction still reads the
        # unchanged manual row and commits with no effect.
        assert (await _session_rows(session, ticket))[reference_id][0] == SEEDED_URL
        await session.commit()
        assert await _committed(probe, ticket) == before
        assert before[1] == []


# ---------------------------------------------------------------------------
# Committed timestamps (update_reference(): equivalent PATCH is a true no-op)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCommittedTimestamps:
    async def test_equivalent_patch_keeps_and_effective_patch_advances_updated_at(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """Each step commits in its own transaction, so PostgreSQL `now()`
        differs between them and an unchanged `updated_at` is meaningful."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        first = await world.open_session()
        created = await _create(
            ticket,
            actor,
            NEW_RAW_URL,
            title="Fictional title",
            description="Fictional context",
            type=ReferenceType.ADVISORY,
        )(first)
        await first.commit()
        rows, events = await _committed(probe, ticket)
        original = rows[created.id]
        assert original.created_at == original.updated_at
        assert events == [_added(actor, NEW_URL)]

        second = await world.open_session()
        later_now = (await second.execute(select(func.now()))).scalar_one()
        assert later_now > original.updated_at
        result = await _update(
            ticket,
            created.id,
            actor,
            url=NEW_RAW_VARIANT,
            type=ReferenceType.ADVISORY,
            title="Fictional title",
            description="Fictional context",
        )(second)
        assert result.updated_at == original.updated_at
        await second.commit()
        assert await _committed(probe, ticket) == (
            {created.id: original},
            [_added(actor, NEW_URL)],
        )

        third = await world.open_session()
        changed = await _update(ticket, created.id, actor, title="Changed title")(third)
        await third.commit()
        rows, events = await _committed(probe, ticket)
        assert rows[created.id].updated_at == changed.updated_at
        assert rows[created.id].updated_at > original.updated_at
        assert rows[created.id].created_at == original.created_at
        assert rows[created.id].title == "Changed title"
        assert events == [
            _added(actor, NEW_URL),
            _field_changed("title", actor, "Fictional title", "Changed title", NEW_URL),
        ]


# ---------------------------------------------------------------------------
# Race helpers
# ---------------------------------------------------------------------------


@dataclass
class _Race:
    winner_result: Any
    waiter: AsyncSession
    recorder: StatementRecorder
    task: asyncio.Task[Any]


async def _serialize(
    world: CommittedWorld,
    first: Call,
    then: Call,
    *,
    release: str = "commit",
    stale: Callable[[AsyncSession], Awaitable[Any]] | None = None,
) -> _Race:
    """Run `first` in a winner session that keeps its Ticket lock, start
    `then` in a waiter session (optionally holding `stale` identity-map
    copies loaded before the race), prove the waiter blocked by the winner
    on the Ticket `FOR UPDATE` as its first and only statement, release the
    winner (`commit` or `rollback`), and wait for the waiter to finish.
    The waiter's transaction is left open."""
    winner = await world.open_session()
    waiter = await world.open_session()
    copies = await stale(waiter) if stale is not None else None

    winner_result = await first(winner)
    with SessionStatementRecorder(waiter) as recorder:
        task: asyncio.Task[Any] = world.start(waiter, then(waiter))
        await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])
        if release == "commit":
            await winner.commit()
        else:
            await winner.rollback()
        done, _pending = await asyncio.wait({task}, timeout=WAIT)
        assert task in done
    # The stale copies stay referenced until the waiter has decided.
    del copies
    return _Race(winner_result, waiter, recorder, task)


def _stale_reference(
    reference_id: uuid.UUID,
) -> Callable[[AsyncSession], Awaitable[TicketReference]]:
    """Loads the reference into the waiter's identity map before the race,
    so an implementation reading the stale copy would audit stale values."""

    async def load(session: AsyncSession) -> TicketReference:
        reference = await session.get(TicketReference, reference_id)
        assert reference is not None
        return reference

    return load


async def _assert_usable(
    race: _Race, ticket: Ticket, caller: TicketCaller, expected_ids: set[uuid.UUID]
) -> None:
    """The loser's transaction can still read and commit."""
    listed = await _list(race.waiter, ticket, caller)
    assert {item.id for item in listed} == expected_ids
    await race.waiter.commit()


# ---------------------------------------------------------------------------
# Manual/manual races (Race Outcomes; ticket-audit-log.md TR 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateCreateRace:
    async def test_first_committed_creator_wins_and_waiter_conflicts(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)

        race = await _serialize(
            world,
            _create(ticket, first_actor, NEW_RAW_URL),
            _create(ticket, second_actor, NEW_RAW_VARIANT),
        )

        with pytest.raises(ReferenceConflictError):
            race.task.result()
        assert race.recorder.writes() == []
        winner_id = race.winner_result.id
        # Still usable: another create in the same transaction commits.
        spare = await _create(ticket, second_actor, SPARE_URL)(race.waiter)
        await _assert_usable(race, ticket, _caller(second_actor), {winner_id, spare.id})
        rows, events = await _committed(probe, ticket)
        assert {k: v.url for k, v in rows.items()} == {
            winner_id: NEW_URL,
            spare.id: SPARE_URL,
        }
        assert events == [_added(first_actor, NEW_URL), _added(second_actor, SPARE_URL)]

    async def test_winner_rollback_lets_the_waiter_create(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)

        race = await _serialize(
            world,
            _create(ticket, first_actor, NEW_RAW_URL),
            _create(ticket, second_actor, NEW_RAW_VARIANT),
            release="rollback",
        )

        created = race.task.result()
        assert created.url == NEW_URL
        await race.waiter.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [created.id]
        assert rows[created.id].url == NEW_URL
        assert events == [_added(second_actor, NEW_URL)]


@pytest.mark.integration
class TestUpdateUpdateSameReference:
    async def test_effective_updates_audit_sequential_old_values(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """The waiter's stale copy still holds `Original title`; its event
        uses the winner's committed value as `old_value`."""
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)

        race = await _serialize(
            world,
            _update(ticket, reference_id, first_actor, title="First title"),
            _update(ticket, reference_id, second_actor, title="Second title"),
            stale=_stale_reference(reference_id),
        )

        assert race.task.result().title == "Second title"
        await race.waiter.commit()
        rows, events = await _committed(probe, ticket)
        assert rows[reference_id].title == "Second title"
        assert events == [
            _field_changed(
                "title", first_actor, "Original title", "First title", SEEDED_URL
            ),
            _field_changed(
                "title", second_actor, "First title", "Second title", SEEDED_URL
            ),
        ]

    async def test_waiter_requesting_the_current_state_is_a_no_op(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)

        race = await _serialize(
            world,
            _update(ticket, reference_id, first_actor, title="First title"),
            _update(ticket, reference_id, second_actor, title="First title"),
            stale=_stale_reference(reference_id),
        )

        result = race.task.result()
        assert race.recorder.writes() == []
        assert result.title == "First title"
        assert result.updated_at == race.winner_result.updated_at
        assert result.updated_at > PAST
        await race.waiter.commit()
        rows, events = await _committed(probe, ticket)
        assert rows[reference_id].updated_at == race.winner_result.updated_at
        assert events == [
            _field_changed(
                "title", first_actor, "Original title", "First title", SEEDED_URL
            )
        ]


@pytest.mark.integration
class TestUpdateUpdateCompetingUrl:
    async def test_first_committed_update_claims_the_identity(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)
        first_id = await _seed(world, ticket)
        second_id = await _seed(world, ticket, url=OTHER_URL)
        before = await _committed(probe, ticket)

        race = await _serialize(
            world,
            _update(ticket, first_id, first_actor, url=NEW_RAW_URL),
            _update(ticket, second_id, second_actor, url=NEW_RAW_VARIANT),
        )

        with pytest.raises(ReferenceConflictError):
            race.task.result()
        assert race.recorder.writes() == []
        await _assert_usable(race, ticket, _caller(second_actor), {first_id, second_id})
        rows, events = await _committed(probe, ticket)
        assert rows[first_id].url == NEW_URL
        assert rows[second_id] == before[0][second_id]
        assert events == [_url_changed(first_actor, SEEDED_URL, NEW_URL)]

    async def test_winner_rollback_lets_the_waiter_update(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)
        first_id = await _seed(world, ticket)
        second_id = await _seed(world, ticket, url=OTHER_URL)
        before = await _committed(probe, ticket)

        race = await _serialize(
            world,
            _update(ticket, first_id, first_actor, url=NEW_RAW_URL),
            _update(ticket, second_id, second_actor, url=NEW_RAW_VARIANT),
            release="rollback",
        )

        assert race.task.result().url == NEW_URL
        await race.waiter.commit()
        rows, events = await _committed(probe, ticket)
        assert rows[first_id] == before[0][first_id]
        assert rows[second_id].url == NEW_URL
        assert events == [_url_changed(second_actor, OTHER_URL, NEW_URL)]


@pytest.mark.integration
class TestUpdateDeleteRaces:
    async def test_update_first_then_delete_removes_the_updated_row(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        updater = await _actor(world)
        deleter = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)

        race = await _serialize(
            world,
            _update(ticket, reference_id, updater, url=NEW_RAW_URL),
            _delete(ticket, reference_id, deleter),
            stale=_stale_reference(reference_id),
        )

        assert race.task.result() is None
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            {},
            [
                _url_changed(updater, SEEDED_URL, NEW_URL),
                _deleted(deleter, NEW_URL),
            ],
        )

    async def test_delete_first_makes_the_waiting_update_not_found(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        deleter = await _actor(world)
        updater = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)

        race = await _serialize(
            world,
            _delete(ticket, reference_id, deleter),
            _update(ticket, reference_id, updater, title="Changed title"),
            stale=_stale_reference(reference_id),
        )

        with pytest.raises(ReferenceNotFoundError):
            race.task.result()
        assert race.recorder.writes() == []
        await _assert_usable(race, ticket, _caller(updater), set())
        assert await _committed(probe, ticket) == (
            {},
            [_deleted(deleter, SEEDED_URL)],
        )


@pytest.mark.integration
class TestDeleteDeleteRace:
    async def test_one_delete_wins_and_waiter_is_not_found(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        first_actor = await _actor(world)
        second_actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)
        sibling_id = await _seed(world, ticket, url=OTHER_URL)
        before = await _committed(probe, ticket)

        race = await _serialize(
            world,
            _delete(ticket, reference_id, first_actor),
            _delete(ticket, reference_id, second_actor),
            stale=_stale_reference(reference_id),
        )

        with pytest.raises(ReferenceNotFoundError):
            race.task.result()
        assert race.recorder.writes() == []
        await _assert_usable(race, ticket, _caller(second_actor), {sibling_id})
        assert await _committed(probe, ticket) == (
            {sibling_id: before[0][sibling_id]},
            [_deleted(first_actor, SEEDED_URL)],
        )


# ---------------------------------------------------------------------------
# Automatic-first race (Race Outcomes: "If automatic insertion owns the
# normalized URL before manual create or a manual URL change, the manual
# operation returns ReferenceConflictError and creates no event")
# ---------------------------------------------------------------------------


async def _insert_automatic(session: AsyncSession, ticket: Ticket) -> uuid.UUID:
    """The automatic row inserted by `upsert_references()`, which acquires
    no Ticket lock; the transaction is left open."""
    await upsert_references(
        session,
        ticket.id,
        CVE_ID,
        AUTO_SOURCE,
        None,
        [
            AutomaticReferenceInput(
                url=AUTO_URL,
                title="Fictional upstream advisory",
                explicit_type=ReferenceType.ADVISORY,
            )
        ],
    )
    return (
        await session.execute(
            select(TicketReference.id).where(
                TicketReference.ticket_id == ticket.id, TicketReference.url == AUTO_URL
            )
        )
    ).scalar_one()


async def _automatic_first(
    world: CommittedWorld, ticket: Ticket, manual: Call, *, release: str
) -> tuple[uuid.UUID, AsyncSession, StatementRecorder, asyncio.Task[Any]]:
    """Session A inserts the automatic row and keeps its transaction open;
    the manual operation in session B is proven blocked by A, then A
    commits or rolls back and B finishes (left open)."""
    automatic = await world.open_session()
    manual_session = await world.open_session()
    auto_id = await _insert_automatic(automatic, ticket)
    with SessionStatementRecorder(manual_session) as recorder:
        task = world.start(manual_session, manual(manual_session))
        await assert_lock_wait(task, waiter=manual_session, blocked_by=automatic)
        # The automatic insert's foreign-key check holds `FOR KEY SHARE` on
        # the parent Ticket row, which conflicts with the manual
        # operation's Ticket `FOR UPDATE`: the manual operation waits at its
        # first statement, before its pre-check and write.
        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])
        if release == "commit":
            await automatic.commit()
        else:
            await automatic.rollback()
        done, _pending = await asyncio.wait({task}, timeout=WAIT)
        assert task in done
    return auto_id, manual_session, recorder, task


@pytest.mark.integration
class TestAutomaticFirstRace:
    async def test_committed_automatic_row_makes_manual_create_conflict(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)

        auto_id, session, recorder, task = await _automatic_first(
            world, ticket, _create(ticket, actor, AUTO_RAW_VARIANT), release="commit"
        )

        with pytest.raises(ReferenceConflictError):
            task.result()
        assert recorder.writes() == []
        # B's transaction remains usable for another create that commits.
        spare = await _create(ticket, actor, SPARE_URL)(session)
        await session.commit()
        rows, events = await _committed(probe, ticket)
        assert set(rows) == {auto_id, spare.id}
        automatic = rows[auto_id]
        assert (
            automatic.url,
            automatic.title,
            automatic.description,
            automatic.type,
            automatic.source,
        ) == (AUTO_URL, "Fictional upstream advisory", None, "advisory", AUTO_SOURCE)
        assert events == [_added(actor, SPARE_URL)]

    async def test_rolled_back_automatic_row_lets_manual_create_succeed(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)

        _auto_id, session, _recorder, task = await _automatic_first(
            world, ticket, _create(ticket, actor, AUTO_RAW_VARIANT), release="rollback"
        )

        created = task.result()
        await session.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [created.id]
        assert (rows[created.id].url, rows[created.id].source) == (AUTO_URL, "manual")
        assert events == [_added(actor, AUTO_URL)]

    async def test_committed_automatic_row_makes_manual_url_change_conflict(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket, updated_at=PAST)
        before = await _committed(probe, ticket)

        auto_id, session, recorder, task = await _automatic_first(
            world,
            ticket,
            _update(ticket, reference_id, actor, url=AUTO_RAW_VARIANT),
            release="commit",
        )

        with pytest.raises(ReferenceConflictError):
            task.result()
        assert recorder.writes() == []
        # B's transaction remains usable: it continues with another
        # effective change of the same reference and commits.
        await _update(ticket, reference_id, actor, title="Later title")(session)
        await session.commit()
        rows, events = await _committed(probe, ticket)
        assert set(rows) == {reference_id, auto_id}
        assert rows[reference_id].url == SEEDED_URL
        assert rows[reference_id].title == "Later title"
        assert rows[reference_id].created_at == before[0][reference_id].created_at
        automatic = rows[auto_id]
        assert (
            automatic.url,
            automatic.title,
            automatic.description,
            automatic.type,
            automatic.source,
        ) == (AUTO_URL, "Fictional upstream advisory", None, "advisory", AUTO_SOURCE)
        assert events == [
            _field_changed("title", actor, "Original title", "Later title", SEEDED_URL)
        ]

    async def test_rolled_back_automatic_row_lets_manual_url_change_succeed(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)

        _auto_id, session, _recorder, task = await _automatic_first(
            world,
            ticket,
            _update(ticket, reference_id, actor, url=AUTO_RAW_VARIANT),
            release="rollback",
        )

        assert task.result().url == AUTO_URL
        await session.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [reference_id]
        assert rows[reference_id].url == AUTO_URL
        assert events == [_url_changed(actor, SEEDED_URL, AUTO_URL)]


# ---------------------------------------------------------------------------
# Locked-current accessibility (Manual Mutation Ordering step 1;
# testing-strategy.md, Ticket Accessibility: Locked mutations and Single,
# nested, and assembled reads)
# ---------------------------------------------------------------------------

LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-path visibility losses of `prepare_loss()`
(`association-changed` is a CVE-path loss and does not apply to
Ticket-scoped reference operations)."""


@pytest.mark.integration
class TestLockedCurrentAccessibility:
    """A `restricted_analyst` caller (effective scope `non_confidential`)
    sees the Ticket through exactly one path and first reads its references
    successfully. An independent session then holds the Ticket `FOR UPDATE`
    and removes that path; the mutation is proven blocked on the Ticket
    lock, the holder commits, and the mutation must be denied from the
    locked-current state with zero row change and zero events."""

    @pytest.mark.parametrize("loss", LOSSES)
    @pytest.mark.parametrize("op", ["create", "update", "delete"])
    async def test_visibility_lost_while_waiting_is_not_found(
        self, world: CommittedWorld, probe: AsyncSession, op: str, loss: str
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        reference_id = await _seed(world, ticket)
        before = await _committed(probe, ticket)
        caller = _caller(user, Scope.NON_CONFIDENTIAL)
        call = {
            "create": _create(ticket, user, NEW_RAW_URL, scope=Scope.NON_CONFIDENTIAL),
            "update": _update(
                ticket, reference_id, user, scope=Scope.NON_CONFIDENTIAL, title="New"
            ),
            "delete": _delete(ticket, reference_id, user, scope=Scope.NON_CONFIDENTIAL),
        }[op]
        mutator = await world.open_session()
        holder = await world.open_session()

        # Preliminary access succeeds in the mutator's own transaction.
        assert [i.id for i in await _list(mutator, ticket, caller)] == [reference_id]
        for statement in statements:
            await holder.execute(statement)
        with SessionStatementRecorder(mutator) as recorder:
            task = world.start(mutator, call(mutator))
            await assert_lock_wait(task, waiter=mutator, blocked_by=holder)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await holder.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        # The denial precedes every nested lookup, write, and event.
        assert recorder.writes() == []
        assert not any("ticket_reference" in s for s in recorder.statements)
        # The same transaction stays usable; its next read observes the
        # committed loss and selects nothing.
        with pytest.raises(TicketNotFoundError):
            await _list(mutator, ticket, caller)
        await mutator.commit()
        assert await _committed(probe, ticket) == before
        assert before[1] == []

    @pytest.mark.parametrize("loss", LOSSES)
    async def test_list_reads_one_coherent_view(
        self, world: CommittedWorld, probe: AsyncSession, loss: str
    ) -> None:
        """While the loss is uncommitted, the read neither waits for the
        Ticket lock nor loses access; once it commits, a new read returns
        `TicketNotFoundError` rather than rows selected after the loss."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        reference_id = await _seed(world, ticket)
        caller = _caller(user, Scope.NON_CONFIDENTIAL)
        reader = await world.open_session()
        holder = await world.open_session()

        for statement in statements:
            await holder.execute(statement)
        listed = await asyncio.wait_for(_list(reader, ticket, caller), timeout=WAIT)
        assert [item.id for item in listed] == [reference_id]
        await reader.rollback()
        await holder.commit()

        with pytest.raises(TicketNotFoundError):
            await _list(reader, ticket, caller)
        await reader.rollback()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [reference_id]
        assert events == []
