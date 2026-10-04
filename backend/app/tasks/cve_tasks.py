"""Celery tasks: CVE-ingestion sub-operations.

- `resolve_ticket_packages`: post-ingest CVE package resolution, see
  `docs/features/packages/package-service.md` (Post-ingest CVE package
  resolution) and `docs/features/tickets/cve-tracking.md` (Non-fetcher
  Celery sub-operations). It is published by the CVE fetcher finalization
  `BaseCVEFetcher.commit_and_dispatch()`, which projects `PostIngestTasks`
  into the five primitive arguments after the per-CVE commit.
- `fetch_single_cve`: one on-demand single-CVE fetch from one source, see
  `docs/features/tickets/cve-service.md` (On-Demand Fetch:
  fetch_single_cve) and `docs/features/platform/cve-fetcher-infrastructure.md`
  (Retry Policy for `fetch_single`). It is published by
  `cve_service.trigger_on_demand_fetch()`.

This module is the thin boundary only: the explicit task names, the single
`asyncio.run()` per invocation or attempt, the engine disposal
(`docs/conventions.md`, Sync-to-Async Bridging; Cross-Loop Pooled
Connection Lifecycle), and for `fetch_single_cve` the `self.retry()` call
requested by the workflow. Argument validation, session ownership, marker
handling, retry classification, and outcome handling belong to
`package_service` and `cve_service`. Both tasks are sub-operations, not
`BaseFetcher`s: no `FETCHER_REGISTRY` entry, schedule, `FetcherRun`, or
stored result; only `fetch_single_cve` retries.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.celery_app import celery_app
from app.database import async_session_factory, engine
from app.services.cve_service import (
    FETCH_SINGLE_CVE_TASK,
    FETCH_SINGLE_RETRY_DELAYS,
    FetchSingleRetry,
    run_fetch_single_cve,
)
from app.services.package_service import (
    RESOLVE_TICKET_PACKAGES_TASK,
    parse_post_ingest_arguments,
    run_post_ingest_package_resolution,
)

logger = structlog.get_logger(__name__)

_DISPOSE_FAILED_EVENT = "resolve_ticket_packages_engine_dispose_failed"
_FETCH_SINGLE_DISPOSE_FAILED_EVENT = "fetch_single_cve_engine_dispose_failed"


async def _dispose_engine(
    *, primary_failed: bool, event: str = _DISPOSE_FAILED_EVENT
) -> None:
    """Dispose the engine once; never mask a propagating primary exception."""
    try:
        await engine.dispose()
    except Exception:
        if not primary_failed:
            raise
        logger.warning(event)


async def resolve_ticket_packages_async(
    ticket_id: object,
    cpe_matches: object,
    affected_cpes: object,
    vendor_products: object,
    resolved_packages: object,
) -> None:
    """Run one task invocation with one async lifecycle.

    Validates the primitive arguments (a `ValueError` before any resolver,
    session, HTTP client, or SMELT work), runs the package-domain
    workflow, which closes its HTTP client and every package session
    itself, and then awaits `engine.dispose()` exactly once on every
    return and exception path, including validation failure and
    cancellation, because the task is repeatedly invoked in one
    long-lived worker child.
    """
    try:
        arguments = parse_post_ingest_arguments(
            ticket_id, cpe_matches, affected_cpes, vendor_products, resolved_packages
        )
        await run_post_ingest_package_resolution(
            ticket_id=arguments.ticket_id,
            cpe_matches=arguments.cpe_matches,
            affected_cpes=arguments.affected_cpes,
            vendor_products=arguments.vendor_products,
            resolved_packages=arguments.resolved_packages,
            session_factory=async_session_factory,
        )
    except BaseException:
        await _dispose_engine(primary_failed=True)
        raise
    await _dispose_engine(primary_failed=False)


def _resolve_ticket_packages_sync(
    ticket_id: str,
    cpe_matches: list[dict[str, object]],
    affected_cpes: list[str],
    vendor_products: list[list[str]],
    resolved_packages: list[str],
) -> None:
    """Thin synchronous Celery wrapper: exactly one `asyncio.run()` per
    invocation. No automatic retry: a malformed argument is a
    non-retryable caller-contract failure, and an escaping workflow
    failure is a task failure recovered only by a later trigger
    (package-service.md, Idempotency, delivery, and recovery). Registered
    by an explicit call (not decorator syntax) so the function stays
    fully typed, as in `app/tasks/fetchers.py`.
    """
    asyncio.run(
        resolve_ticket_packages_async(
            ticket_id, cpe_matches, affected_cpes, vendor_products, resolved_packages
        )
    )


resolve_ticket_packages_task = celery_app.task(name=RESOLVE_TICKET_PACKAGES_TASK)(
    _resolve_ticket_packages_sync
)


async def fetch_single_cve_async(
    fetcher_name: object,
    cve_id: object,
    source: object,
    token: object,
    *,
    attempt: int,
) -> FetchSingleRetry | None:
    """Run one `fetch_single_cve` attempt with one async lifecycle.

    Delegates the complete attempt to `cve_service.run_fetch_single_cve()`,
    which closes the fetcher's HTTP client and the marker client itself,
    then awaits `engine.dispose()` exactly once after all other cleanup, on
    every return and exception path, because the task is repeatedly
    invoked in one long-lived worker child.
    """
    try:
        outcome = await run_fetch_single_cve(
            fetcher_name,
            cve_id,
            source,
            token,
            attempt=attempt,
            session_factory=async_session_factory,
        )
    except BaseException:
        await _dispose_engine(
            primary_failed=True, event=_FETCH_SINGLE_DISPOSE_FAILED_EVENT
        )
        raise
    await _dispose_engine(
        primary_failed=False, event=_FETCH_SINGLE_DISPOSE_FAILED_EVENT
    )
    return outcome


def _fetch_single_cve_sync(
    # `self` is the bound Celery Task instance (see `app/tasks/fetchers.py`).
    self: Any,
    fetcher_name: object,
    cve_id: object,
    source: object,
    token: object,
) -> None:
    """Thin synchronous Celery wrapper: exactly one `asyncio.run()` per
    attempt. When the workflow requests a retry, raises `self.retry()`
    with its countdown (5, 10, then 20 seconds) and cause; each retry is a
    new attempt with a fresh fetcher, session, HTTP client, and event loop.
    Every exception propagates unchanged. Returns `None`; no result is
    stored.
    """
    outcome = asyncio.run(
        fetch_single_cve_async(
            fetcher_name, cve_id, source, token, attempt=self.request.retries
        )
    )
    if outcome is not None:
        raise self.retry(exc=outcome.cause, countdown=outcome.countdown)


fetch_single_cve_task = celery_app.task(
    bind=True,
    name=FETCH_SINGLE_CVE_TASK,
    max_retries=len(FETCH_SINGLE_RETRY_DELAYS),
)(_fetch_single_cve_sync)
