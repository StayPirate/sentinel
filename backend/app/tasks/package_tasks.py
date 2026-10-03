"""Celery task: Product-originated eligibility recalculation sub-operation.

See `docs/features/packages/product-lifecycle-transitions.md` (Sub-task:
`re_evaluate_product_eligibility`) for the authoritative contract and
`app/services/packages/product_eligibility_recalculation.py` for the
workflow. This module is the thin boundary only: the explicit task name,
the single `asyncio.run()` per invocation, and the engine disposal
(`docs/conventions.md`, Sync-to-Async Bridging; Cross-Loop Pooled
Connection Lifecycle). The task is a sub-operation, not a `BaseFetcher`:
no `FETCHER_REGISTRY` entry, schedule, `FetcherRun`, or Celery retry.
"""

from __future__ import annotations

import asyncio

import structlog

from app.celery_app import celery_app
from app.database import async_session_factory, engine
from app.services.packages.product_eligibility_recalculation import (
    RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK,
    parse_recalculation_arguments,
    re_evaluate_product_eligibility,
)

logger = structlog.get_logger(__name__)


async def _dispose_engine(*, primary_failed: bool) -> None:
    """Dispose the engine once; never mask a propagating primary exception."""
    try:
        await engine.dispose()
    except Exception:
        if not primary_failed:
            raise
        logger.warning("re_evaluate_product_eligibility_engine_dispose_failed")


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
        await _dispose_engine(primary_failed=True)
        raise
    await _dispose_engine(primary_failed=False)


def _re_evaluate_product_eligibility_sync(catalog_product_id: str, reason: str) -> None:
    """Thin synchronous Celery wrapper: exactly one `asyncio.run()` per
    invocation. Registered by an explicit call (not decorator syntax) so the
    function stays fully typed, as in `app/tasks/fetchers.py`.
    """
    asyncio.run(re_evaluate_product_eligibility_async(catalog_product_id, reason))


re_evaluate_product_eligibility_task = celery_app.task(
    name=RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK
)(_re_evaluate_product_eligibility_sync)
