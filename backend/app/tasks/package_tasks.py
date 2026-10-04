"""Celery tasks: package-domain sub-operations.

- `re_evaluate_product_eligibility`: see
  `docs/features/packages/product-lifecycle-transitions.md` (Sub-task:
  `re_evaluate_product_eligibility`) and
  `app/services/packages/product_eligibility_recalculation.py`.
- `run_ticket_convergence`: the root Ticket convergence task, see
  `docs/features/packages/package-service.md` (`run_ticket_convergence()`
  workflow) and `docs/features/tickets/ticket-service.md` (Ticket
  Convergence); published by `app.services.ticket_convergence_publication`.
- `backfill_product_catalog`: the Product catalog backfill, see
  `docs/features/packages/product-catalog.md` (Product Catalog Backfill)
  and `app/services/packages/product_catalog_backfill.py`; published by
  `sync_smelt_products` (Product Sync step 8).

This module is the thin boundary only: the explicit task names, the single
`asyncio.run()` per invocation, the engine disposal (`docs/conventions.md`,
Sync-to-Async Bridging; Cross-Loop Pooled Connection Lifecycle), and the
convergence wrapper's retry policy. Every task is a sub-operation, not a
`BaseFetcher`: no `FETCHER_REGISTRY` entry, schedule, or `FetcherRun`.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery_app
from app.database import async_session_factory, engine
from app.services.package_service import (
    run_ticket_convergence,
    ticket_convergence_failure_phase,
)
from app.services.packages.product_catalog_backfill import (
    BACKFILL_PRODUCT_CATALOG_TASK,
    run_product_catalog_backfill,
)
from app.services.packages.product_eligibility_recalculation import (
    RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK,
    parse_recalculation_arguments,
    re_evaluate_product_eligibility,
)
from app.services.ticket_convergence_publication import RUN_TICKET_CONVERGENCE_TASK

logger = structlog.get_logger(__name__)


async def _dispose_engine(*, primary_failed: bool, event: str) -> None:
    """Dispose the engine once; never mask a propagating primary exception."""
    try:
        await engine.dispose()
    except Exception:
        if not primary_failed:
            raise
        logger.warning(event)


async def re_evaluate_product_eligibility_async(
    catalog_product_id: str, reason: str
) -> None:
    """Run one task invocation with one async lifecycle.

    Validates the arguments (`ValueError` before any session), runs the
    package-domain workflow, and awaits `engine.dispose()` exactly once on
    every return and exception path, including validation failures,
    because the task is repeatedly invoked in one long-lived worker child.
    """
    try:
        product_id, validated_reason = parse_recalculation_arguments(
            catalog_product_id, reason
        )
        await re_evaluate_product_eligibility(
            product_id, validated_reason, session_factory=async_session_factory
        )
    except BaseException:
        await _dispose_engine(
            primary_failed=True,
            event="re_evaluate_product_eligibility_engine_dispose_failed",
        )
        raise
    await _dispose_engine(
        primary_failed=False,
        event="re_evaluate_product_eligibility_engine_dispose_failed",
    )


def _re_evaluate_product_eligibility_sync(catalog_product_id: str, reason: str) -> None:
    """Thin synchronous Celery wrapper: exactly one `asyncio.run()` per
    invocation. Registered by an explicit call (not decorator syntax) so the
    function stays fully typed, as in `app/tasks/fetchers.py`.
    """
    asyncio.run(re_evaluate_product_eligibility_async(catalog_product_id, reason))


re_evaluate_product_eligibility_task = celery_app.task(
    name=RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK
)(_re_evaluate_product_eligibility_sync)


# ---------------------------------------------------------------------------
# Root Ticket convergence task
# ---------------------------------------------------------------------------

TICKET_CONVERGENCE_RETRY_DELAYS: Final[tuple[int, ...]] = (5, 10, 20)
"""Countdown in seconds before retry 1, 2, and 3 (at most three retries)."""


def parse_ticket_convergence_argument(ticket_id: object) -> uuid.UUID:
    """Validate the task argument before any event loop or database work.

    Raises `ValueError` (a non-retryable caller-contract failure) after one
    structured ERROR when `ticket_id` is not the string form of a UUID.
    The rejected value is never logged.
    """
    try:
        if not isinstance(ticket_id, str):
            raise ValueError
        return uuid.UUID(ticket_id)
    except ValueError:
        logger.error(
            "ticket_convergence_invalid_ticket_id",
            cause="ticket_id is not a valid UUID",
        )
        raise ValueError("run_ticket_convergence requires a UUID ticket_id") from None


async def run_ticket_convergence_async(ticket_id: uuid.UUID) -> None:
    """Run one workflow invocation with one async lifecycle.

    Runs the complete package-domain workflow and awaits
    `engine.dispose()` exactly once on every return and exception path,
    because the task is repeatedly invoked, including every retry, in one
    long-lived worker child.
    """
    try:
        await run_ticket_convergence(
            ticket_id=ticket_id, session_factory=async_session_factory
        )
    except BaseException:
        await _dispose_engine(
            primary_failed=True, event="ticket_convergence_engine_dispose_failed"
        )
        raise
    await _dispose_engine(
        primary_failed=False, event="ticket_convergence_engine_dispose_failed"
    )


def _run_ticket_convergence_sync(
    # `self` is the bound Celery Task instance (celery ships no stubs —
    # see the mypy override in pyproject.toml).
    self: Any,
    ticket_id: str,
) -> None:
    """Thin bound synchronous wrapper of the root Ticket convergence task.

    Validates `ticket_id` (malformed: one ERROR and a non-retryable
    `ValueError`), then calls `asyncio.run()` exactly once. Cancellation,
    `SoftTimeLimitExceeded`, and `MemoryError` propagate without retry.
    Every other escaping workflow failure retries the complete workflow
    after 5, 10, then 20 seconds, logging a WARNING per retry; after
    exhaustion it emits one terminal ERROR with the Ticket UUID, the
    failed phase, and the sanitized cause (exception type only) and
    returns `None`. The `celery_task_id` correlation is bound by the
    worker signals. Creates no `FetcherRun`.
    """
    ticket_uuid = parse_ticket_convergence_argument(ticket_id)
    try:
        asyncio.run(run_ticket_convergence_async(ticket_uuid))
    except SoftTimeLimitExceeded, MemoryError:
        raise
    except Exception as exc:
        attempt = self.request.retries
        phase = ticket_convergence_failure_phase(exc)
        if attempt < len(TICKET_CONVERGENCE_RETRY_DELAYS):
            countdown = TICKET_CONVERGENCE_RETRY_DELAYS[attempt]
            logger.warning(
                "ticket_convergence_retrying",
                ticket_id=str(ticket_uuid),
                phase=phase,
                cause=type(exc).__name__,
                retries=attempt,
                countdown=countdown,
            )
            # No `exc=`: Celery's own retry log would otherwise render the
            # exception text, which may carry broker hosts or SQL details.
            raise self.retry(countdown=countdown) from exc
        logger.error(
            "ticket_convergence_failed",
            ticket_id=str(ticket_uuid),
            phase=phase,
            cause=type(exc).__name__,
            retries=attempt,
        )


run_ticket_convergence_task = celery_app.task(
    bind=True,
    name=RUN_TICKET_CONVERGENCE_TASK,
    max_retries=len(TICKET_CONVERGENCE_RETRY_DELAYS),
)(_run_ticket_convergence_sync)


# ---------------------------------------------------------------------------
# Product catalog backfill task
# ---------------------------------------------------------------------------


async def backfill_product_catalog_async() -> None:
    """Run one backfill invocation with one async lifecycle.

    Runs the complete workflow (which closes its HTTP client and every
    pair session itself) and then awaits `engine.dispose()` exactly once
    on every return and exception path, including cancellation, because
    the task is repeatedly invoked in one long-lived worker child.
    """
    try:
        await run_product_catalog_backfill(session_factory=async_session_factory)
    except BaseException:
        await _dispose_engine(
            primary_failed=True, event="product_catalog_backfill_engine_dispose_failed"
        )
        raise
    await _dispose_engine(
        primary_failed=False, event="product_catalog_backfill_engine_dispose_failed"
    )


def _backfill_product_catalog_sync() -> None:
    """Thin synchronous Celery wrapper: exactly one `asyncio.run()` per
    invocation. No arguments and no automatic retry: an escaping failure
    is a task failure, recovered by the next qualifying trigger
    (product-catalog.md, Product Catalog Backfill).
    """
    asyncio.run(backfill_product_catalog_async())


backfill_product_catalog_task = celery_app.task(name=BACKFILL_PRODUCT_CATALOG_TASK)(
    _backfill_product_catalog_sync
)
