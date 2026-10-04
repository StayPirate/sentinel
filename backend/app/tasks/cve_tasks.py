"""Celery tasks: CVE-ingestion sub-operations.

- `resolve_ticket_packages`: post-ingest CVE package resolution, see
  `docs/features/packages/package-service.md` (Post-ingest CVE package
  resolution) and `docs/features/tickets/cve-tracking.md` (Non-fetcher
  Celery sub-operations). It is published by the CVE fetcher finalization
  `BaseCVEFetcher.commit_and_dispatch()`, which projects `PostIngestTasks`
  into the five primitive arguments after the per-CVE commit.

This module is the thin boundary only: the explicit task name, the single
`asyncio.run()` per invocation, and the engine disposal
(`docs/conventions.md`, Sync-to-Async Bridging; Cross-Loop Pooled
Connection Lifecycle). Argument validation, candidate resolution, session
ownership, and outcome handling belong to `package_service`. The task is
a sub-operation, not a `BaseFetcher`: no `FETCHER_REGISTRY` entry,
schedule, `FetcherRun`, automatic retry, or stored result.
"""

from __future__ import annotations

import asyncio

import structlog

from app.celery_app import celery_app
from app.database import async_session_factory, engine
from app.services.package_service import (
    RESOLVE_TICKET_PACKAGES_TASK,
    parse_post_ingest_arguments,
    run_post_ingest_package_resolution,
)

logger = structlog.get_logger(__name__)

_DISPOSE_FAILED_EVENT = "resolve_ticket_packages_engine_dispose_failed"


async def _dispose_engine(*, primary_failed: bool) -> None:
    """Dispose the engine once; never mask a propagating primary exception."""
    try:
        await engine.dispose()
    except Exception:
        if not primary_failed:
            raise
        logger.warning(_DISPOSE_FAILED_EVENT)


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
