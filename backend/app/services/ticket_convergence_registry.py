"""Transaction-local registry of Ticket convergence effects.

Implements the lifecycle in `docs/features/tickets/ticket-mutations.md`
(Transaction-Local Ticket Convergence Registration, steps 1-5) and the
"registration" term of `docs/features/tickets/ticket-service.md` (Ticket
Convergence > Publication vocabulary). `ticket_mutations.reconcile_ticket_status()`
step 5 is the only registrant; transaction owners consume the effects
through `ticket_convergence_publication.drain_ticket_convergence()`.

- **Registration** appends one immutable `TicketConvergenceEffect`
  carrying only the internal Ticket UUID. It is a pure in-memory
  operation: no database query, no network, Redis, or Celery I/O, no task
  ID, no audit event, and no publication.
- **Deduplication and order**: at most one effect exists per Ticket in one
  transaction; effects keep first-registration order.
- **Transaction binding**: the registry is stored in the session's `info`
  mapping but is bound to the identity of the session's root
  `SessionTransaction`, not merely to the reusable session object. A
  registry left behind by an earlier transaction is ignored on every read
  and replaced on the next registration, so a new transaction never
  inherits a pending effect. Savepoint (nested transaction) boundaries
  neither commit nor discard effects: only the root transaction's outcome
  decides. A surviving effect from a rolled back savepoint could at most
  cause one redundant, idempotent convergence publication.
- **Discard**: when the root transaction ends without a successful commit
  — rollback, a definitely failed commit followed by the owner's rollback,
  a commit with an ambiguous outcome, or session close (the path of
  pre-commit cancellation) — an `after_transaction_end` listener drops its
  effects without publication.
- **Detach and consume**: an `after_commit` listener marks the root
  transaction's registry as committed; when that transaction then ends,
  its complete sequence moves to a detachable slot. The owner calls
  `detach_ticket_convergence_effects()` after its commit (and, by its
  contract, after closing its session) to take the sequence exactly once.
  The slot is dropped as soon as the session begins its next root
  transaction, so a reused session neither replays nor inherits an effect,
  whether or not the owner drained it. An interruption between commit and
  detach loses the publication; recovery is the explicit complete rerun.

This leaf module imports only the standard library and SQLAlchemy so that
every transaction owner (`ticket_service`, `package_service`, the
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

_DETACHABLE_KEY: Final = "sentinel.ticket_convergence_detachable"
"""Key of the committed, not yet detached sequence in `Session.info`."""


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
    committed: bool = False


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


def detach_ticket_convergence_effects(
    session: AsyncSession,
) -> tuple[TicketConvergenceEffect, ...]:
    """Atomically detach the effects of the session's committed transaction.

    Category B (in-memory transaction state only; no I/O).

    Q1: `session` is the owner's session whose root transaction has just
    committed; the owner may already have closed it. No new transaction
    may have begun on it since that commit.

    Q3: removes and returns the complete sequence registered by the last
    successfully committed root transaction, in first-registration order.
    A second call returns an empty tuple, so a detached effect is consumed
    exactly once even when its later publication attempt fails. Nothing is
    returned for a rolled back, failed, ambiguous, or cancelled
    transaction, nor once the session has begun another root transaction.

    Q4: an immutable tuple, possibly empty.

    Q6: raises no exception.
    """
    effects: tuple[TicketConvergenceEffect, ...] = session.sync_session.info.pop(
        _DETACHABLE_KEY, ()
    )
    return effects


@event.listens_for(Session, "after_transaction_create")
def _drop_undetached_on_new_transaction(session: Session, transaction: Any) -> None:
    """A new root transaction never inherits an undetached sequence."""
    if transaction.parent is None:
        session.info.pop(_DETACHABLE_KEY, None)


@event.listens_for(Session, "after_commit")
def _mark_committed(session: Session) -> None:
    """Mark the registry of the committing root transaction as committed.

    SQLAlchemy dispatches `after_commit` for root and savepoint commits
    while the committing transaction is still the session's current one;
    a savepoint release decides nothing.
    """
    if session.in_nested_transaction():
        return
    registry: _Registry | None = session.info.get(_REGISTRY_KEY)
    if registry is not None and registry.transaction is session.get_transaction():
        registry.committed = True


@event.listens_for(Session, "after_transaction_end")
def _finish_on_transaction_end(session: Session, transaction: Any) -> None:
    """Make a committed sequence detachable; discard every other outcome.

    SQLAlchemy invokes this listener for every `SessionTransaction` that
    ends (commit, rollback, or close). Nested (savepoint) transactions are
    ignored. The ending root transaction's registry is removed; its effects
    become detachable only when `_mark_committed()` observed its successful
    commit, and are otherwise dropped without publication.
    """
    if transaction.parent is not None:
        return
    registry: _Registry | None = session.info.get(_REGISTRY_KEY)
    if registry is None or registry.transaction is not transaction:
        return
    del session.info[_REGISTRY_KEY]
    if registry.committed and registry.effects:
        session.info[_DETACHABLE_KEY] = tuple(registry.effects.values())
