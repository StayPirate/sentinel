"""Publication of a registered Celery task by name from the Service layer.

The substitutable, service-layer mechanism through which a fetcher or other
service workflow enqueues a registered Celery sub-operation after its
commit (implementation decision for issue #765, roadmap umbrella #761 H10).

- **No import cycle.** `app.celery_app` imports `app.services.fetcher_discovery`
  (and therefore every fetcher module) at load time, so a fetcher cannot
  import the Celery application at module level. The application is
  resolved lazily inside `publish_task()`, when every module is loaded.
- **Layer direction.** The task is published by its registered name through
  `Celery.send_task()`; this Service module never imports a task module
  itself, so no Service → Task dependency exists (docs/architecture.md,
  Backend Layer Architecture). Only the Celery application module, which
  registers the task modules, is resolved at call time.
- **No result.** `ignore_result=True` is explicit, matching the
  no-result-backend contract (docs/features/platform/fetcher-infrastructure.md,
  Celery Integration, Result handling); no task result is ever read.
- **Substitutable.** Callers invoke `task_publication.publish_task(...)`
  through this module so tests replace the broker call.

The publication is network I/O on the broker: callers invoke it only after
their commit, with no database transaction or row lock open
(docs/conventions.md, Transaction Hygiene Rules). Broker and serialization
exceptions propagate unchanged; the caller applies its own failure policy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping


async def publish_task(task_name: str, *, kwargs: Mapping[str, str]) -> None:
    """Enqueue the registered Celery task `task_name` with `kwargs`.

    Category C (external broker I/O only; no database or Redis key access).

    Q1: `task_name` is the explicit registered task name; `kwargs` holds
    only detached primitive (string) arguments.

    Q3: submits exactly one message through `send_task()` on the default
    route without waiting for execution, in a worker thread so the event
    loop is not blocked. Adds no retry beyond Celery's configured
    publication retry policy.

    Q4: returns `None` once the publication call returns without raising.

    Q6: every publication exception propagates unchanged.
    """
    # Deferred: `app.celery_app` imports every fetcher module at load time.
    from app.celery_app import celery_app

    await asyncio.to_thread(
        celery_app.send_task, task_name, kwargs=dict(kwargs), ignore_result=True
    )
