"""Transaction-local registry of Ticket convergence effects.

Implements the registration part of the lifecycle in
`docs/features/tickets/ticket-mutations.md` (Transaction-Local Ticket
Convergence Registration, steps 1-3) and the "registration" term of
`docs/features/tickets/ticket-service.md` (Ticket Convergence >
Publication vocabulary). `ticket_mutations.reconcile_ticket_status()`
step 5 is the only registrant.

- **Registration** appends one immutable `TicketConvergenceEffect`
  carrying only the internal Ticket UUID. It is a pure in-memory
  operation: no database query, no network, Redis, or Celery I/O, no task
  ID, no audit event, and no publication.
- **Deduplication and order**: at most one effect exists per Ticket in one
  transaction; effects keep first-registration order.
- **Transaction binding and discard**: the registry is stored in the
  session's `info` mapping but is bound to the identity of the session's
  root `SessionTransaction`, not merely to the reusable session object. A
  SQLAlchemy `after_transaction_end` listener discards the effects when
  that root transaction ends for any reason — commit, rollback, a failed
  commit followed by the owner's rollback, or session close (the path of
  pre-commit cancellation). A registry left behind by an earlier
  transaction is also ignored on every read and replaced on the next
  registration, so a new transaction never inherits a pending effect.
  Savepoint (nested transaction) boundaries do not discard effects: only
  the root transaction's outcome decides. A surviving effect from a rolled
  back savepoint could at most cause one redundant, idempotent convergence
  publication.

Consumption (owner detach after a successful commit, the database-free
publisher, the publication policies and logs) is not implemented yet: until
it exists, every effect is discarded when its transaction ends — including
after a successful commit — and nothing is ever published (implementation
roadmap dispatch D1, issue #600).

This leaf module imports only the standard library and SQLAlchemy so that
every later transaction owner (`ticket_service`, `package_service`, the
CVE/fetcher infrastructure) can reach it without violating the documented
module dependency directions (ticket-service.md, Initial publication
boundary and database-free publisher).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, SessionTransaction

_REGISTRY_KEY: Final = "sentinel.ticket_convergence_registry"
"""Key of the registry in `Session.info`."""


@dataclass(frozen=True, slots=True)
class TicketConvergenceEffect:
    """One declared future Ticket convergence publication.

    Carries only the Ticket's internal UUID: the primitive identity the
    publication boundary needs (ticket-mutations.md, registration step 1).
    """

    ticket_id: UUID


@dataclass(slots=True)
class _Registry:
    transaction: SessionTransaction
    effects: dict[UUID, TicketConvergenceEffect] = field(default_factory=dict)


def _current_registry(session: Session) -> _Registry | None:
    """The registry bound to the session's current root transaction, if any."""
    registry: _Registry | None = session.info.get(_REGISTRY_KEY)
    if registry is None:
        return None
    if registry.transaction is not session.get_transaction():
        # Left behind by an earlier transaction: never inherited.
        del session.info[_REGISTRY_KEY]
        return None
    return registry


def register_ticket_convergence(session: AsyncSession, ticket_id: UUID) -> None:
    """Register one Ticket convergence effect in the current transaction.

    Category A (in-memory transaction state only; no persisted state).

    Q1: `session` is the caller-owned session whose transaction is in
    progress; `ticket_id` is the internal Ticket UUID.

    Q3: binds the registry to the session's current root transaction and
    adds `TicketConvergenceEffect(ticket_id)` unless an effect for the same
    Ticket is already registered in this transaction (deduplication keeps
    the first registration and its position). Performs no database query,
    network, Redis, or Celery I/O, allocates no task ID, creates no audit
    event, and publishes nothing.

    Q4: returns `None`.

    Q6: raises `ValueError` when no transaction is in progress on
    `session` (an internal contract violation: registration always follows
    the caller's gate queries inside its transaction).
    """
    sync_session = session.sync_session
    transaction = sync_session.get_transaction()
    if transaction is None:
        raise ValueError(
            "Ticket convergence registration requires a transaction in progress."
        )
    registry = _current_registry(sync_session)
    if registry is None:
        registry = _Registry(transaction=transaction)
        sync_session.info[_REGISTRY_KEY] = registry
    registry.effects.setdefault(ticket_id, TicketConvergenceEffect(ticket_id))


def pending_ticket_convergence_effects(
    session: AsyncSession,
) -> tuple[TicketConvergenceEffect, ...]:
    """Return the effects registered in the session's current transaction.

    Category B (reads in-memory transaction state only; no I/O).

    Q1: `session` is the caller-owned session.

    Q3: returns the effects in first-registration order. A registry bound
    to an earlier, ended transaction is discarded and never returned; when
    no transaction is in progress the result is empty. Does not detach or
    consume the effects.

    Q4: an immutable tuple, possibly empty.

    Q6: raises no exception.
    """
    registry = _current_registry(session.sync_session)
    if registry is None:
        return ()
    return tuple(registry.effects.values())


@event.listens_for(Session, "after_transaction_end")
def _discard_on_transaction_end(session: Session, transaction: Any) -> None:
    """Discard the effects of a root transaction that has ended.

    SQLAlchemy invokes this listener for every `SessionTransaction` that
    ends (commit, rollback, or close). Nested (savepoint) transactions are
    ignored; the effects of the ending root transaction are dropped without
    publication.
    """
    if transaction.parent is not None:
        return
    registry: _Registry | None = session.info.get(_REGISTRY_KEY)
    if registry is not None and registry.transaction is transaction:
        del session.info[_REGISTRY_KEY]
