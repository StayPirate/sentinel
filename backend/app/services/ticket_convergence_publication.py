"""Initial publication of the root Ticket convergence task.

Implements `docs/features/tickets/ticket-service.md` (Ticket Convergence >
Initial publication boundary and database-free publisher; Publication
policies; Publication failure logging) and the owner side of
`docs/features/tickets/ticket-mutations.md` (Transaction-Local Ticket
Convergence Registration, step 4).

- `publish_ticket_convergence()` is the Ticket-convergence-specific,
  database-free boundary: one submission of the registered root task
  `run_ticket_convergence` by name, with detached primitive values only. A
  normal return is `submitted`; `kombu.exceptions.OperationalError`
  propagates and means `acceptance_unconfirmed`; every other exception
  propagates unchanged. It logs nothing, adds no retry of its own beyond
  Celery's configured publication retry policy, and reads no result.
- `allocate_task_id()` allocates the transient root task ID in memory
  immediately before an attempt; no task ID is ever persisted.
- `drain_ticket_convergence()` is the automatic best-effort policy used by
  every automatic transaction owner after its commit and lock release: it
  detaches the committed sequence once and attempts each effect in
  registered order. A broker operational error emits exactly one
  `ticket_convergence_publication_failed` ERROR and is absorbed; every
  other exception propagates unchanged to the owner, which must not treat
  it as a pre-commit or transaction failure.
- The explicit operator rerun (`ticket_service.dispatch_ticket_convergence()`)
  calls the publisher directly and owns its own failure mapping.

The module is a service-layer leaf (standard library, structlog, Celery,
and the `task_publication` and registry leaves), so `ticket_mutations`,
`ticket_service`, `package_service`, and the CVE/fetcher infrastructure
can all reach it. Tests substitute `task_publication.publish_task`.
"""

from __future__ import annotations

import uuid
from typing import Final

import structlog
from celery.exceptions import OperationalError  # kombu.exceptions.OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import task_publication
from app.services.ticket_convergence_registry import (
    detach_ticket_convergence_effects,
)

logger = structlog.get_logger(__name__)

RUN_TICKET_CONVERGENCE_TASK: Final = "run_ticket_convergence"
"""Explicit registered name of the root Ticket convergence Celery task."""

PUBLICATION_FAILED_EVENT: Final = "ticket_convergence_publication_failed"
"""The one Ticket-owned event of a failed automatic publication."""

BROKER_OPERATIONAL_ERROR: Final = "broker_operational_error"
"""The closed sanitized `cause` category of a broker operational error."""


def allocate_task_id() -> str:
    """A new transient Celery root task ID (no broker I/O)."""
    return str(uuid.uuid7())


async def publish_ticket_convergence(*, ticket_id: uuid.UUID, task_id: str) -> None:
    """Submit one root Ticket convergence task (initial publication attempt).

    Category C (broker I/O only; no database session, query, HTTP, or
    Redis key of its own).

    Q1: `ticket_id` is the canonical internal Ticket UUID and `task_id`
    the transient root task ID allocated by the draining owner. No ORM
    instance or session is accepted. No database transaction or row lock
    may be open on the caller's side.

    Q3: exactly one `send_task()` call for `run_ticket_convergence` with
    `ticket_id` as its only argument, under Celery's configured
    publication retry policy. Never waits for a worker or reads a result;
    emits no log and selects no owner policy.

    Q4: returns `None` when the call returns without raising
    (`submitted`).

    Q6: `kombu.exceptions.OperationalError` propagates unchanged and means
    `acceptance_unconfirmed` (classified by class only). Every other
    exception — cancellation, worker signals, time limits, `MemoryError`,
    serialization and content errors, configuration errors, and
    programming errors — propagates unchanged. A non-UUID `ticket_id` or a
    non-string `task_id` raises `TypeError` before any publication.
    """
    if not isinstance(ticket_id, uuid.UUID):
        raise TypeError("ticket_id must be the internal Ticket UUID")
    if not isinstance(task_id, str):
        raise TypeError("task_id must be a string")
    await task_publication.publish_task(
        RUN_TICKET_CONVERGENCE_TASK,
        kwargs={"ticket_id": str(ticket_id)},
        task_id=task_id,
    )


async def _attempt_automatic_publication(ticket_id: uuid.UUID) -> None:
    """The automatic best-effort adapter for one detached effect."""
    try:
        await publish_ticket_convergence(
            ticket_id=ticket_id, task_id=allocate_task_id()
        )
    except OperationalError:
        logger.error(
            PUBLICATION_FAILED_EVENT,
            ticket_id=str(ticket_id),
            cause=BROKER_OPERATIONAL_ERROR,
        )


async def drain_ticket_convergence(session: AsyncSession) -> None:
    """Detach and attempt the owner's committed Ticket convergence effects.

    Category C (in-memory detach, then broker I/O only; no database work).

    Q1: `session` is the automatic owner's session whose root transaction
    has committed and whose row locks are released; the owner may already
    have closed it.

    Q3: atomically detaches the complete committed sequence, then attempts
    each effect once in registered order with a freshly allocated root
    task ID. A broker operational error leaves the owner's committed unit
    and accounting unchanged, emits exactly one sanitized
    `ticket_convergence_publication_failed` ERROR (`ticket_id`, `cause`,
    and the correlation already bound to the execution context; no
    exception text), and is absorbed so later effects continue.

    Q4: returns `None`; no publication result is exposed to the owner.

    Q5: a second call after a drain attempts nothing.

    Q6: every other exception propagates unchanged after the effects
    attempted so far; remaining detached effects are not replayed.
    """
    for effect in detach_ticket_convergence_effects(session):
        await _attempt_automatic_publication(effect.ticket_id)
