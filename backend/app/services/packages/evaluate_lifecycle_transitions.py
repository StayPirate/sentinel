"""`evaluate_lifecycle_transitions`: local lifecycle transition evaluator.

Implements docs/features/packages/product-lifecycle-transitions.md
(Fetcher: `evaluate_lifecycle_transitions`; Catch-Up). Each run captures
one UTC `evaluation_date` and, without any lifecycle cursor or phase cache:

1. finds the catalog Products with an eligibility mismatch through the
   shared scan (`find_product_eligibility_mismatches()`) and enqueues one
   `re_evaluate_product_eligibility(reason="reactive_ltss")` task per
   Product; a dispatch failure is logged with the Product ID, counted as a
   failed unit, and later Products continue;
2. selects the `Analysis`, `Analyzed`, and `Resolved` Tickets whose
   persisted status differs from the current gates
   (`find_lifecycle_gate_mismatches()`, built on the reconciliation gate
   SQL `ticket_mutations.gate_status_expression()`), then reconciles each
   in a fresh session and independent transaction through
   `package_service.reconcile_lifecycle_actionability_for_ticket()`. A
   pre-commit failure rolls back only that Ticket, is logged with the
   Ticket ID and exception type, and later Tickets continue; a commit
   exception or ambiguous commit outcome terminates the run without a
   terminal metric for that Ticket.

`SoftTimeLimitExceeded` and `MemoryError` are re-raised before both
per-item catches; cancellation is never caught. Candidate-enumeration
failures propagate as whole-run failures. Both read transactions end before
the first dispatch and the first Ticket unit.

`catch_up()` verifies one Ticket on the passed session and, on a gate
mismatch, delegates one reconciliation to an independent committed
session; it never recalculates Product eligibility.

After each Ticket unit commits and its session closes, its metrics are
recorded and then the Ticket convergence effect registered by the
delegated reconciliation (a `Resolved` regression) is drained before the
next Ticket (Algorithm step 5): a broker operational error is absorbed by
the automatic policy (`ticket_convergence_publication`), while any other
drain exception terminates the run with the committed Ticket's success
and update metrics preserved and `items_failed` unchanged. `catch_up()`
drains the same way after its independent reconciliation commits and
closes; a non-operational drain exception escapes to `run_catch_up`
without rollback or reclassification.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime
from typing import Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import ColumnElement, and_, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import TicketStatus
from app.database import async_session_factory
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.services.base_fetcher import BaseFetcher
from app.services.package_service import (
    reconcile_lifecycle_actionability_for_ticket,
)
from app.services.packages.product_eligibility_mismatch import (
    find_product_eligibility_mismatches,
)
from app.services.packages.product_eligibility_recalculation import (
    dispatch_product_eligibility_recalculation,
)
from app.services.ticket_convergence_publication import drain_ticket_convergence
from app.services.ticket_mutations import gate_status_expression

logger = structlog.get_logger(__name__)

GATE_ZONE_STATUSES: Final = (
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
)
"""Ticket statuses selected for lifecycle-aware gate reconciliation."""


def lifecycle_gate_mismatch_condition(evaluation_date: date) -> ColumnElement[bool]:
    """The `Ticket` is in the gate zone and its status differs from its gates.

    Uses the reconciliation gate SQL (`gate_status_expression()`) on
    `evaluation_date`, so it holds exactly for the Tickets whose
    `reconcile_ticket_status()` would change status on that date.
    """
    return and_(
        Ticket.status.in_(GATE_ZONE_STATUSES),
        Ticket.status != gate_status_expression(evaluation_date),
    )


async def find_lifecycle_gate_mismatches(
    db: AsyncSession, *, evaluation_date: date
) -> Sequence[uuid.UUID]:
    """Distinct gate-zone Ticket IDs whose status differs from current gates.

    Category B (read-only; no lock, write, audit, commit, or rollback).
    `New`, `Ignored`, and `Duplicated` are never selected. Ordered by
    Ticket ID; database exceptions propagate.
    """
    statement = (
        select(Ticket.id)
        .where(lifecycle_gate_mismatch_condition(evaluation_date))
        .order_by(Ticket.id)
    )
    return (await db.execute(statement)).scalars().all()


def _utc_today() -> date:
    """The current UTC date (patched by controlled-clock tests)."""
    return datetime.now(UTC).date()


class EvaluateLifecycleTransitions(BaseFetcher):
    """Reconcile lifecycle-derived Product eligibility and Ticket gate state."""

    name = "evaluate_lifecycle_transitions"
    description = (
        "Reconcile lifecycle-derived Product eligibility and Ticket gate state"
    )
    default_schedule = "15 4 * * *"
    participates_in_catch_up = True

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: one UTC date for every lifecycle and actionability check.
        evaluation_date = _utc_today()

        # Step 2: read-only Product mismatch scan, closed before dispatch.
        product_ids = await find_product_eligibility_mismatches(
            session, evaluation_date=evaluation_date
        )
        await session.commit()

        # Step 3: one eligibility task per Product, in ID order.
        dispatch_failed = 0
        for product_id in sorted(product_ids):
            try:
                await dispatch_product_eligibility_recalculation(
                    product_id, "reactive_ltss"
                )
            except SoftTimeLimitExceeded, MemoryError:
                raise
            except Exception as exc:
                dispatch_failed += 1
                self.record_failed()
                logger.warning(
                    "lifecycle_eligibility_dispatch_failed",
                    product_id=str(product_id),
                    error_type=type(exc).__name__,
                )
                continue
            self.record_succeeded()

        # Step 4: read-only gate-mismatch enumeration, closed before the units.
        ticket_ids = await find_lifecycle_gate_mismatches(
            session, evaluation_date=evaluation_date
        )
        await session.commit()

        # Steps 4-5: one independent transaction per Ticket.
        changed = ticket_failed = 0
        for ticket_id in ticket_ids:
            async with async_session_factory() as unit:
                try:
                    result = await reconcile_lifecycle_actionability_for_ticket(
                        unit, ticket_id, evaluation_date
                    )
                except SoftTimeLimitExceeded, MemoryError:
                    raise
                except Exception as exc:
                    await unit.rollback()
                    ticket_failed += 1
                    self.record_failed()
                    logger.warning(
                        "lifecycle_reconciliation_ticket_failed",
                        ticket_id=str(ticket_id),
                        error_type=type(exc).__name__,
                    )
                    continue
                # A commit exception terminates the run: never an item failure.
                await unit.commit()

            self.record_succeeded()
            if result.changed:
                changed += 1
                self.record_updated()
            # Step 5: drain after commit and close, before the next Ticket.
            await drain_ticket_convergence(unit)

        logger.info(
            "lifecycle_transitions_evaluated",
            products=len(product_ids),
            dispatched=len(product_ids) - dispatch_failed,
            dispatch_failed=dispatch_failed,
            tickets=len(ticket_ids),
            tickets_changed=changed,
            tickets_failed=ticket_failed,
        )

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Verify one Ticket's lifecycle-aware gate state; reconcile on mismatch.

        product-lifecycle-transitions.md (Catch-Up). The passed session
        only reads: a missing Ticket, an empty package tree, a `New` or
        manual-zone Ticket, or a converged Ticket returns silently. On a
        mismatch, one independent session runs
        `reconcile_lifecycle_actionability_for_ticket()` with the same
        `evaluation_date`, then commits and closes. Product eligibility is
        never recalculated. A pre-commit failure and a commit exception
        propagate to `run_catch_up` unchanged. After the commit and close,
        the registered Ticket convergence effect is drained; a broker
        operational error is absorbed and any other drain exception
        propagates without rollback or reclassification.
        """
        evaluation_date = _utc_today()
        ticket_uuid = uuid.UUID(ticket_id)
        has_package = exists(
            select(TicketPackage.id).where(TicketPackage.ticket_id == Ticket.id)
        ).correlate(Ticket)
        mismatch = (
            await session.execute(
                select(Ticket.id).where(
                    Ticket.id == ticket_uuid,
                    has_package,
                    lifecycle_gate_mismatch_condition(evaluation_date),
                )
            )
        ).scalar_one_or_none()
        await session.commit()
        if mismatch is None:
            return

        async with async_session_factory() as unit:
            result = await reconcile_lifecycle_actionability_for_ticket(
                unit, ticket_uuid, evaluation_date
            )
            await unit.commit()
        await drain_ticket_convergence(unit)
        logger.info(
            "lifecycle_catch_up_reconciled",
            ticket_id=ticket_id,
            changed=result.changed,
        )
