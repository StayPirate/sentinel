"""Celery task: the all-CVE default-version CVSS recalculation.

- `recalculate_cvss_derived_state`: see
  `docs/features/platform/default-cvss-version-operations.md` (Task
  Identity and Workflow; Task Adoption; Timeout and Cancellation) and
  `app/services/cvss_recalculation.py`. It is published by the manual
  admission with a preallocated task ID.

This module is the thin boundary only: the explicit task name, the input
validation order (`target_version` first, then the task ID), and the single
`asyncio.run()` per invocation (`docs/conventions.md`, Sync-to-Async
Bridging). It performs no business query, settings read, transaction, or
engine disposal: the service workflow owns its connection and awaits the
shared engine's disposal at its outer boundary (Cross-Loop Pooled
Connection Lifecycle). No automatic retry, soft or hard time limit,
`acks_late`, or `reject_on_worker_lost` is configured, and `self.retry()` is
never called. The task is not a fetcher: no `FETCHER_REGISTRY` entry,
schedule, `FetcherRun`, or stored result.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.celery_app import celery_app
from app.database import async_session_factory
from app.services.cvss_recalculation import (
    RECALCULATE_CVSS_DERIVED_STATE_TASK,
    run_cvss_derived_state_recalculation,
    validate_target_version,
    validate_task_id,
)


def _recalculate_cvss_derived_state_sync(
    # `self` is the bound Celery Task instance (celery ships no stubs —
    # see the mypy override in pyproject.toml).
    self: Any,
    target_version: object,
) -> None:
    """Thin bound synchronous wrapper of the all-CVE recalculation.

    Validates `target_version` from input only (non-retryable `ValueError`,
    no event), then `task.request.id` as a canonical UUIDv4 (one
    `task_id_invalid` adoption rejection and a non-retryable `ValueError`),
    then calls `asyncio.run()` exactly once with the validated ID passed
    explicitly. Returns `None`; every exception and control signal from
    the workflow propagates unchanged.
    """
    target = validate_target_version(target_version)
    task_id = validate_task_id(self.request.id, target_version=target)
    asyncio.run(
        run_cvss_derived_state_recalculation(target, task_id, async_session_factory)
    )


recalculate_cvss_derived_state_task = celery_app.task(
    bind=True, name=RECALCULATE_CVSS_DERIVED_STATE_TASK
)(_recalculate_cvss_derived_state_sync)
