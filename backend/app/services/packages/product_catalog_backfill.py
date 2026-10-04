"""`backfill_product_catalog`: Product catalog backfill workflow.

Implements docs/features/packages/product-catalog.md (Product Catalog
Backfill), the on-demand Celery sub-operation that `sync_smelt_products`
publishes after a committed snapshot makes at least one Product newly
current (Product Sync steps 6 and 8). The thin Celery task in
`app/tasks/package_tasks.py` bridges into this workflow with one
`asyncio.run()` and owns the engine disposal; this module owns the
selection, the per-pair units, and the completion log:

1. One read-only session selects every `(ticket_id, package_name)` pair of
   an active Ticket (`New`, `Analysis`, `Analyzed`) whose package marker
   is included, ordered by Ticket UUID then package name in code-point
   order, and is closed before any external request.
2. Each pair runs in a fresh session through
   `package_service.add_package_to_ticket()` as a system invocation with
   the `Product catalog backfill` comment, `active_ticket_only = True`, and
   `allow_excluded_reresolution = False`, sharing the invocation's single
   HTTP client, then commits and closes.
3. A locked inactive Ticket is skipped; a `PackageAlreadyExcludedError`
   from an exclusion committed after selection is an expected skip; every
   other `Exception`, including a commit failure, rolls back that pair,
   logs one sanitized warning, and is counted as failed. Cancellation,
   `SoftTimeLimitExceeded`, and `MemoryError` propagate after cleanup.
4. One completion log carries the six counts.

A pair never registers a Ticket convergence effect (its locked mutation
proceeds only for an active Ticket, while registration needs an
`Ignored`, `Duplicated`, or `Resolved` source status), so the workflow
detaches and publishes nothing; the package-add IBS request catch-up
(`add_package_to_ticket()` step 9) belongs to the IBS submission-tracking
workflow and is not published here.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.services.http_client import create_http_client
from app.services.package_service import (
    SYSTEM_INVOCATION,
    PackageAddedComment,
    PackageAlreadyExcludedError,
    PackageRecordsOutcome,
    SmeltUnavailableError,
    add_package_to_ticket,
)

logger = structlog.get_logger(__name__)

BACKFILL_PRODUCT_CATALOG_TASK: Final = "backfill_product_catalog"
"""Explicit registered name of the Celery sub-operation."""

BACKFILL_COMMENT: Final[PackageAddedComment] = "Product catalog backfill"
"""Canonical `package_added` comment of a backfill pair."""

_CODE_POINT_COLLATION: Final = "C"

HTTP_CLIENT_NAME: Final = "backfill_product_catalog"
"""Shared-factory HTTP client name of one backfill invocation."""

PAIR_FAILED_EVENT: Final = "product_catalog_backfill_pair_failed"
COMPLETED_EVENT: Final = "product_catalog_backfill_completed"

ACTIVE_TICKET_STATUSES: Final = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
)
"""Ticket statuses whose included package markers are selected."""


@dataclass(frozen=True, slots=True)
class ProductCatalogBackfillSummary:
    """Completion counts of one backfill invocation.

    Every candidate pair has exactly one outcome: `record_creating` (at
    least one package-tree record created), `no_op` (every package-tree
    record already existed, with or without new maintainer associations),
    `skipped_inactive`, `skipped_excluded`, or `failed`.
    """

    candidates: int
    record_creating: int
    no_op: int
    skipped_inactive: int
    skipped_excluded: int
    failed: int


async def select_backfill_pairs(db: AsyncSession) -> Sequence[tuple[uuid.UUID, str]]:
    """Every included package marker of an active Ticket, in processing order.

    Read-only, no lock. Pairs are distinct by the `(ticket_id,
    package_name)` unique constraint; ordered by Ticket UUID, then package
    name in Unicode code-point order.
    """
    statement = (
        select(TicketPackage.ticket_id, TicketPackage.package_name)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .where(
            Ticket.status.in_(ACTIVE_TICKET_STATUSES),
            TicketPackage.deleted_at.is_(None),
        )
        .order_by(
            TicketPackage.ticket_id,
            TicketPackage.package_name.collate(_CODE_POINT_COLLATION),
        )
    )
    rows = (await db.execute(statement)).all()
    return [(row.ticket_id, row.package_name) for row in rows]


def _log_pair_failure(ticket_id: uuid.UUID, package_name: str, exc: Exception) -> None:
    """One sanitized WARNING per failed pair (exception class, no text)."""
    fields: dict[str, str] = {
        "ticket_id": str(ticket_id),
        "package_name": package_name,
        "cause": type(exc).__name__,
    }
    if isinstance(exc, SmeltUnavailableError):
        fields["category"] = exc.category
    logger.warning(PAIR_FAILED_EVENT, **fields)


async def _rollback(session: AsyncSession) -> None:
    """Roll back a failed pair; a failing rollback is part of that failure.

    The session is closed by its context manager either way.
    """
    try:
        await session.rollback()
    except SoftTimeLimitExceeded, MemoryError:
        raise
    except Exception:  # nosec B110 -- the pair is already counted as failed
        pass


async def _backfill_pair(
    session_factory: async_sessionmaker[AsyncSession],
    http_client: httpx.AsyncClient,
    *,
    ticket_id: uuid.UUID,
    package_name: str,
) -> PackageRecordsOutcome | None:
    """One independent pair unit; `None` is a skipped-excluded pair.

    Returns the committed semantic outcome. A non-signal `Exception`
    escapes after the rollback, for the caller to count and log.
    """
    async with session_factory() as session:
        try:
            result = await add_package_to_ticket(
                session,
                ticket_id=ticket_id,
                package_name=package_name,
                acting_user_id=None,
                caller=SYSTEM_INVOCATION,
                audit_comment=BACKFILL_COMMENT,
                active_ticket_only=True,
                allow_excluded_reresolution=False,
                http_client=http_client,
            )
            await session.commit()
        except SoftTimeLimitExceeded, MemoryError:
            raise
        except PackageAlreadyExcludedError:
            await _rollback(session)
            return None
        except Exception:
            await _rollback(session)
            raise
    return result.outcome


async def run_product_catalog_backfill(
    *, session_factory: async_sessionmaker[AsyncSession]
) -> ProductCatalogBackfillSummary:
    """Re-resolve every included package of every active Ticket.

    Category A orchestration boundary owning one independent transaction
    per pair (product-catalog.md, Product Catalog Backfill).

    Q1: `session_factory` opens every session of the invocation.

    Q2: holds no lock itself; each pair serializes on the Ticket lock of
    the delegated `add_package_records()`, taken after its SMELT I/O.

    Q3: (1) selects the pairs in one read-only session closed before any
    I/O; (2) when there is at least one pair, opens one shared-factory HTTP
    client and processes the pairs in order, each in a fresh session that
    commits and closes; (3) classifies each pair as record-creating,
    no-op, skipped-inactive, skipped-excluded (an exclusion committed
    after selection), or failed (any other `Exception`, rolled back and
    logged once with Ticket UUID, package name, exception class, and the
    bounded SMELT category); (4) logs one completion line. Creates no
    audit event of its own (delegated `package_added` and
    `package_maintainer_added` events only), no `FetcherRun`, progress
    row, Redis key, or task publication.

    Q4: returns the completion counts, also logged once.

    Q5: idempotent with respect to current persisted state; repeats SMELT
    requests by design. Overlapping invocations converge through the
    Ticket lock and insert-if-missing record creation.

    Q6: a selection failure or HTTP client creation failure escapes before
    any pair; cancellation, `SoftTimeLimitExceeded`, and `MemoryError`
    propagate after closing the current pair session and the client.
    Earlier committed pairs remain committed.
    """
    async with session_factory() as session:
        pairs = await select_backfill_pairs(session)

    counts = dict.fromkeys(_COUNT_KEYS, 0)
    if pairs:
        async with create_http_client(HTTP_CLIENT_NAME) as client:
            for ticket_id, package_name in pairs:
                try:
                    outcome = await _backfill_pair(
                        session_factory,
                        client,
                        ticket_id=ticket_id,
                        package_name=package_name,
                    )
                except SoftTimeLimitExceeded, MemoryError:
                    raise
                except Exception as exc:
                    counts["failed"] += 1
                    _log_pair_failure(ticket_id, package_name, exc)
                    continue
                counts[_count_key(outcome)] += 1

    summary = ProductCatalogBackfillSummary(
        candidates=len(pairs),
        record_creating=counts["record_creating"],
        no_op=counts["no_op"],
        skipped_inactive=counts["skipped_inactive"],
        skipped_excluded=counts["skipped_excluded"],
        failed=counts["failed"],
    )
    logger.info(
        COMPLETED_EVENT,
        candidates=summary.candidates,
        record_creating=summary.record_creating,
        no_op=summary.no_op,
        skipped_inactive=summary.skipped_inactive,
        skipped_excluded=summary.skipped_excluded,
        failed=summary.failed,
    )
    return summary


_COUNT_KEYS: Final = (
    "record_creating",
    "no_op",
    "skipped_inactive",
    "skipped_excluded",
    "failed",
)


def _count_key(outcome: PackageRecordsOutcome | None) -> str:
    if outcome is None:
        return "skipped_excluded"
    if outcome is PackageRecordsOutcome.PACKAGE_TREE_CHANGED:
        return "record_creating"
    if outcome is PackageRecordsOutcome.ACTIVE_TICKET_ONLY_SKIPPED:
        return "skipped_inactive"
    return "no_op"
