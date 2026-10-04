"""Initial publication boundary and automatic drain of Ticket convergence.

Owning specifications:

- docs/features/tickets/ticket-service.md (Ticket Convergence >
  Publication vocabulary; Initial publication boundary and database-free
  publisher; Publication policies; Publication failure logging).
- docs/features/tickets/ticket-mutations.md (Transaction-Local Ticket
  Convergence Registration, step 4: detach and consume).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff > Initial publication boundary, Publication
  policies, Control signals and security). The boundary is unit-tested
  with a substituted broker-publication call
  (`task_publication.publish_task`); the drain uses real PostgreSQL with
  independent sessions.

The per-owner policies (API, lifecycle evaluator, Product/threshold task,
lifecycle catch-up, convergence package unit) are covered with their
owners; this module proves the shared boundary and adapter once.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from celery.exceptions import SoftTimeLimitExceeded, WorkerShutdown
from kombu.exceptions import (  # type: ignore[import-untyped]
    EncodeError,
    OperationalError,
    SerializerNotInstalled,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.enums import Severity, TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import task_publication
from app.services.ticket_convergence_publication import (
    PUBLICATION_FAILED_EVENT,
    RUN_TICKET_CONVERGENCE_TASK,
    allocate_task_id,
    drain_ticket_convergence,
    publish_ticket_convergence,
)
from app.services.ticket_mutations import reconcile_ticket_status

SessionFactory = Callable[[], Awaitable[AsyncSession]]


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    error: BaseException | None = None
    fail_for: set[str] = field(default_factory=set)
    calls: list[dict[str, Any]] = field(default_factory=list)
    on_call: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        if self.on_call is not None:
            await self.on_call(call)
        ticket_id = options["kwargs"].get("ticket_id")
        if self.error is not None and (not self.fail_for or ticket_id in self.fail_for):
            raise self.error


@pytest.fixture
def publish(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


# ---------------------------------------------------------------------------
# Initial publication boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPublishTicketConvergence:
    async def test_submitted_is_one_root_task_with_detached_primitives(
        self, publish: _Publish
    ) -> None:
        ticket_id = uuid.uuid7()

        await publish_ticket_convergence(ticket_id=ticket_id, task_id="example-task-id")

        assert publish.calls == [
            {
                "task_name": RUN_TICKET_CONVERGENCE_TASK,
                "kwargs": {"ticket_id": str(ticket_id)},
                "task_id": "example-task-id",
            }
        ]
        assert RUN_TICKET_CONVERGENCE_TASK == "run_ticket_convergence"

    @pytest.mark.parametrize(
        "message", ["", "Connection refused", "broker rejected the task"]
    )
    async def test_operational_error_propagates_as_acceptance_unconfirmed(
        self, publish: _Publish, message: str
    ) -> None:
        """Classified by class only; the text is irrelevant and one
        attempt is made (no retry loop of its own)."""
        publish.error = OperationalError(message)

        with pytest.raises(OperationalError):
            await publish_ticket_convergence(ticket_id=uuid.uuid7(), task_id="t")

        assert len(publish.calls) == 1

    @pytest.mark.parametrize(
        "error",
        [
            asyncio.CancelledError(),
            WorkerShutdown(),
            SoftTimeLimitExceeded(),
            MemoryError(),
            EncodeError("cannot encode"),
            SerializerNotInstalled("no serializer"),
            RuntimeError("programming error"),
        ],
        ids=lambda e: type(e).__name__,
    )
    async def test_every_other_exception_propagates_unchanged(
        self, publish: _Publish, error: BaseException
    ) -> None:
        publish.error = error

        with pytest.raises(type(error)) as raised:
            await publish_ticket_convergence(ticket_id=uuid.uuid7(), task_id="t")

        assert raised.value is error
        assert not isinstance(raised.value, OperationalError)
        assert len(publish.calls) == 1

    async def test_rejects_non_primitive_arguments_before_publication(
        self, publish: _Publish
    ) -> None:
        invalid: list[dict[str, Any]] = [
            {"ticket_id": Ticket(status=TicketStatus.ANALYSIS.value), "task_id": "t"},
            {"ticket_id": str(uuid.uuid7()), "task_id": "t"},
            {"ticket_id": uuid.uuid7(), "task_id": uuid.uuid7()},
        ]

        for arguments in invalid:
            with pytest.raises(TypeError):
                await publish_ticket_convergence(**arguments)

        assert publish.calls == []

    def test_boundary_accepts_no_session(self) -> None:
        parameters = inspect.signature(publish_ticket_convergence).parameters
        assert list(parameters) == ["ticket_id", "task_id"]
        assert all(p.kind is p.KEYWORD_ONLY for p in parameters.values())

    async def test_boundary_emits_no_log(self, publish: _Publish) -> None:
        publish.error = OperationalError("down")
        with capture_logs() as logs:
            with pytest.raises(OperationalError):
                await publish_ticket_convergence(ticket_id=uuid.uuid7(), task_id="t")
            await asyncio.sleep(0)
        assert logs == []

    def test_allocated_task_ids_are_distinct_uuid_strings(self) -> None:
        first, second = allocate_task_id(), allocate_task_id()

        assert first != second
        assert str(uuid.UUID(first)) == first
        assert uuid.UUID(first).version == 7


# ---------------------------------------------------------------------------
# Automatic drain (real PostgreSQL, independent sessions)
# ---------------------------------------------------------------------------


@dataclass
class _World:
    setup: AsyncSession
    ticket_ids: list[uuid.UUID] = field(default_factory=list)

    async def ticket(self) -> uuid.UUID:
        ticket = Ticket(
            status=TicketStatus.ANALYSIS.value, severity_manual=Severity.HIGH.value
        )
        self.setup.add(ticket)
        await self.setup.commit()
        self.ticket_ids.append(ticket.id)
        return ticket.id

    async def cleanup(self) -> None:
        await self.setup.rollback()
        await self.setup.execute(
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            )
        )
        await self.setup.execute(delete(Ticket).where(Ticket.id.in_(self.ticket_ids)))
        await self.setup.commit()


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[_World]:
    committed = _World(await db_session_factory())
    try:
        yield committed
    finally:
        await committed.cleanup()


async def _register_exits(session: AsyncSession, *ticket_ids: uuid.UUID) -> None:
    """Lock each Ticket and reconcile a manual-zone exit (registers)."""
    for ticket_id in ticket_ids:
        ticket = (
            await session.execute(
                select(Ticket).where(Ticket.id == ticket_id).with_for_update()
            )
        ).scalar_one()
        await reconcile_ticket_status(
            ticket, session, previous_status=TicketStatus.IGNORED
        )


def _published_ticket_ids(publish: _Publish) -> list[str]:
    return [call["kwargs"]["ticket_id"] for call in publish.calls]


@pytest.mark.integration
class TestDrainTicketConvergence:
    async def test_commit_and_lock_release_precede_each_attempt_in_order(
        self,
        world: _World,
        db_session_factory: SessionFactory,
        publish: _Publish,
    ) -> None:
        first, second = await world.ticket(), await world.ticket()
        owner = await db_session_factory()
        probe = await db_session_factory()
        observed: list[tuple[str, bool]] = []

        async def check_unlocked(call: dict[str, Any]) -> None:
            ticket_id = uuid.UUID(call["kwargs"]["ticket_id"])
            locked = (
                await probe.execute(
                    select(Ticket.status)
                    .where(Ticket.id == ticket_id)
                    .with_for_update(nowait=True)
                )
            ).scalar_one()
            await probe.rollback()
            observed.append((locked, owner.in_transaction()))

        publish.on_call = check_unlocked
        async with owner:
            await _register_exits(owner, second, first, second)
            await owner.commit()

        await drain_ticket_convergence(owner)

        assert _published_ticket_ids(publish) == [str(second), str(first)]
        assert [call["task_name"] for call in publish.calls] == [
            RUN_TICKET_CONVERGENCE_TASK
        ] * 2
        task_ids = [call["task_id"] for call in publish.calls]
        assert len(set(task_ids)) == 2
        # Committed state is visible and no lock or transaction is held.
        assert observed == [(TicketStatus.ANALYSIS.value, False)] * 2

        await drain_ticket_convergence(owner)
        assert len(publish.calls) == 2

    async def test_operational_error_logs_once_and_later_effects_continue(
        self,
        world: _World,
        db_session_factory: SessionFactory,
        publish: _Publish,
    ) -> None:
        first, second = await world.ticket(), await world.ticket()
        owner = await db_session_factory()
        publish.error = OperationalError(
            "redis://user:secret@broker.example.test:6379 unreachable"
        )
        publish.fail_for = {str(first)}
        async with owner:
            await _register_exits(owner, first, second)
            await owner.commit()

        with capture_logs() as logs:
            await drain_ticket_convergence(owner)

        assert _published_ticket_ids(publish) == [str(first), str(second)]
        assert logs == [
            {
                "event": PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": str(first),
                "cause": "broker_operational_error",
            }
        ]
        # The committed unit is untouched and nothing is replayed.
        await drain_ticket_convergence(owner)
        assert len(publish.calls) == 2

    @pytest.mark.parametrize(
        "error",
        [RuntimeError("programming error"), EncodeError("x"), asyncio.CancelledError()],
        ids=lambda e: type(e).__name__,
    )
    async def test_non_operational_exception_propagates_without_event(
        self,
        world: _World,
        db_session_factory: SessionFactory,
        publish: _Publish,
        error: BaseException,
    ) -> None:
        first, second = await world.ticket(), await world.ticket()
        owner = await db_session_factory()
        publish.error = error
        async with owner:
            await _register_exits(owner, first, second)
            await owner.commit()

        with capture_logs() as logs, pytest.raises(type(error)):
            await drain_ticket_convergence(owner)

        assert _published_ticket_ids(publish) == [str(first)]
        assert logs == []
        # The detached remainder is consumed, never replayed.
        publish.error = None
        await drain_ticket_convergence(owner)
        assert _published_ticket_ids(publish) == [str(first)]

    async def test_rolled_back_transaction_publishes_nothing(
        self,
        world: _World,
        db_session_factory: SessionFactory,
        publish: _Publish,
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        async with owner:
            await _register_exits(owner, ticket_id)
            await owner.rollback()

        await drain_ticket_convergence(owner)

        assert publish.calls == []

    async def test_drain_without_effects_publishes_nothing(
        self, db_session_factory: SessionFactory, publish: _Publish
    ) -> None:
        owner = await db_session_factory()
        async with owner:
            await owner.execute(select(1))
            await owner.commit()

        await drain_ticket_convergence(owner)

        assert publish.calls == []
