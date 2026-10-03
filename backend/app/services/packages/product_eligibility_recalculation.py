"""`re_evaluate_product_eligibility`: Product-originated eligibility workflow.

Implements docs/features/packages/product-lifecycle-transitions.md
(Sub-task: `re_evaluate_product_eligibility`). The thin Celery task in
`app/tasks/package_tasks.py` bridges into this workflow with one
`asyncio.run()` and owns the engine disposal; this module owns the
argument validation, the candidate selection, and the per-Ticket units:

1. `parse_recalculation_arguments()` rejects an unsupported `reason` or a
   non-UUID `catalog_product_id` with `ValueError` before any session.
2. `re_evaluate_product_eligibility()` captures one UTC `evaluation_date`,
   selects in a read-only session the distinct operable Tickets containing
   the catalog Product (directly or effectively excluded and EOL
   occurrences included), then processes them sequentially: one fresh
   session and independent transaction per Ticket, calling
   `package_service.recalculate_product_eligibility_for_ticket()`, then
   committing and closing that session.
3. A pre-commit Ticket failure rolls back only that Ticket, logs the Ticket
   ID, Product ID, reason, and exception type, and continues. A commit
   exception or ambiguous commit outcome propagates as a task failure
   without isolated classification; `SoftTimeLimitExceeded`,
   `MemoryError`, and cancellation propagate as whole-run failures.
4. One completion log carries the candidate, successful, skipped, no-op,
   changed-record, and failed-Ticket counts.

The post-commit Ticket convergence drain (Sub-task step 3 and the drain
sentence of step 4) is not implemented yet: a `Resolved` regression's
registered effect is discarded when its Ticket transaction ends
(`app/services/ticket_convergence_registry.py`; implementation roadmap
dispatch D1).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Final, cast

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import task_publication
from app.services.package_service import (
    PRODUCT_RECALCULATION_REASONS,
    ProductRecalculationReason,
    recalculate_product_eligibility_for_ticket,
)

logger = structlog.get_logger(__name__)

RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK: Final = "re_evaluate_product_eligibility"
"""Explicit registered name of the Celery sub-task."""

OPERABLE_TICKET_STATUSES: Final = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
)
"""Ticket statuses whose Product occurrences receive automatic maintenance."""


def parse_recalculation_arguments(
    catalog_product_id: object, reason: object
) -> tuple[uuid.UUID, ProductRecalculationReason]:
    """Validate the task arguments before any database session.

    `catalog_product_id` is a UUID or its string form (the serialized task
    argument); `reason` is `"threshold"` or `"reactive_ltss"`.

    Raises `ValueError` for an unsupported `reason` or a
    `catalog_product_id` that is not a UUID, after one structured ERROR
    naming the invalid argument (never its value).
    """
    if not isinstance(reason, str) or reason not in PRODUCT_RECALCULATION_REASONS:
        logger.error("product_eligibility_recalculation_invalid_reason")
        raise ValueError("unsupported Product eligibility recalculation reason")
    validated_reason = cast(ProductRecalculationReason, reason)
    if isinstance(catalog_product_id, uuid.UUID):
        return catalog_product_id, validated_reason
    try:
        if not isinstance(catalog_product_id, str):
            raise ValueError
        return uuid.UUID(catalog_product_id), validated_reason
    except ValueError:
        logger.error("product_eligibility_recalculation_invalid_product_id")
        raise ValueError("catalog_product_id must be a UUID") from None


async def dispatch_product_eligibility_recalculation(
    catalog_product_id: uuid.UUID, reason: ProductRecalculationReason
) -> None:
    """Enqueue one `re_evaluate_product_eligibility` task for one Product.

    Category C (broker I/O only). Called by the post-commit dispatchers
    (`sync_aimaas_thresholds` with `reason = "threshold"`,
    `evaluate_lifecycle_transitions` with `reason = "reactive_ltss"`) with no
    database transaction or row lock open. Publishes the detached string
    arguments by task name through `task_publication.publish_task()`;
    every publication exception propagates to the dispatcher, which logs it
    per Product and continues.
    """
    await task_publication.publish_task(
        RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK,
        kwargs={"catalog_product_id": str(catalog_product_id), "reason": reason},
    )


@dataclass(frozen=True, slots=True)
class ProductEligibilityRecalculationSummary:
    """Completion counts of one `re_evaluate_product_eligibility` run.

    `successful` counts committed Tickets. Each successful Ticket is either
    `skipped` (manual zone), `no_op` (operable, no changed record), or
    changed; `changed_records` sums the changed occurrences. `failed`
    counts isolated pre-commit Ticket failures.
    """

    candidates: int
    successful: int
    skipped: int
    no_op: int
    changed_records: int
    failed: int


async def select_candidate_ticket_ids(
    db: AsyncSession, catalog_product_id: uuid.UUID
) -> Sequence[uuid.UUID]:
    """Distinct operable Ticket IDs containing the catalog Product.

    Read-only, no lock. Includes directly or effectively excluded and EOL
    occurrences and every track status; ordered by Ticket ID.
    """
    statement = (
        select(TicketPackage.ticket_id)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.ticket_package_id == TicketPackage.id,
        )
        .join(
            TicketPackageProduct,
            TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
        )
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .where(
            TicketPackageProduct.product_id == catalog_product_id,
            Ticket.status.in_(OPERABLE_TICKET_STATUSES),
        )
        .distinct()
        .order_by(TicketPackage.ticket_id)
    )
    return (await db.execute(statement)).scalars().all()


def _utc_today() -> date:
    """The current UTC date (patched by controlled-clock tests)."""
    return datetime.now(UTC).date()


async def re_evaluate_product_eligibility(
    catalog_product_id: uuid.UUID,
    reason: ProductRecalculationReason,
    *,
    session_factory: async_sessionmaker[AsyncSession],
) -> ProductEligibilityRecalculationSummary:
    """Recalculate one catalog Product's eligibility in every operable Ticket.

    Category A workflow owning one independent transaction per Ticket
    (product-lifecycle-transitions.md, Sub-task:
    `re_evaluate_product_eligibility`, steps 1-5).

    Q1: `catalog_product_id` and `reason` were validated by
    `parse_recalculation_arguments()`; `session_factory` opens every
    session of the run.

    Q2: acquires no lock itself; each per-Ticket unit serializes on the
    Ticket row lock taken by the delegated service.

    Q3: one UTC `evaluation_date`; read-only candidate selection; per
    Ticket a fresh session, the service call (which flushes), commit, and
    close. A pre-commit failure rolls back that Ticket, is logged, and the
    run continues. No Celery retry, progress row, or `FetcherRun`.

    Q4: returns the completion counts, also logged once.

    Q5: re-invocation recomputes from current committed inputs; converged
    Tickets are no-ops. No candidate is a successful no-op.

    Q6: a candidate-selection error, a commit exception or ambiguous commit
    outcome, a rollback error, `SoftTimeLimitExceeded`, `MemoryError`, and
    cancellation propagate; earlier committed Tickets remain committed.
    """
    evaluation_date = _utc_today()

    async with session_factory() as session:
        ticket_ids = await select_candidate_ticket_ids(session, catalog_product_id)

    successful = skipped = no_op = changed_records = failed = 0
    for ticket_id in ticket_ids:
        async with session_factory() as session:
            try:
                result = await recalculate_product_eligibility_for_ticket(
                    session,
                    ticket_id,
                    catalog_product_id,
                    reason,
                    evaluation_date=evaluation_date,
                )
            except SoftTimeLimitExceeded, MemoryError:
                raise
            except Exception as exc:
                await session.rollback()
                failed += 1
                logger.warning(
                    "product_eligibility_recalculation_ticket_failed",
                    ticket_id=str(ticket_id),
                    catalog_product_id=str(catalog_product_id),
                    reason=reason,
                    error_type=type(exc).__name__,
                )
                continue
            # A commit exception propagates: it is never an isolated failure.
            await session.commit()

        successful += 1
        if result.manual_zone_skipped:
            skipped += 1
        elif result.changed == 0:
            no_op += 1
        changed_records += result.changed

    summary = ProductEligibilityRecalculationSummary(
        candidates=len(ticket_ids),
        successful=successful,
        skipped=skipped,
        no_op=no_op,
        changed_records=changed_records,
        failed=failed,
    )
    logger.info(
        "product_eligibility_recalculation_completed",
        catalog_product_id=str(catalog_product_id),
        reason=reason,
        candidates=summary.candidates,
        successful=summary.successful,
        skipped=summary.skipped,
        no_op=summary.no_op,
        changed_records=summary.changed_records,
        failed=summary.failed,
    )
    return summary
