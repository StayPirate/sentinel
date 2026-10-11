"""Test-owned Celery application launcher for the local process system suite.

Spawned worker and Beat processes use this module as their `-A` app path
(`celery -A tests.support.system_fetcher_app worker ...`) instead of
`app.celery_app` directly. Importing `tests.support.system_fetcher` first
registers `EvaluateTestPipeline` into the spawned process's
`FETCHER_REGISTRY` *before* `app.celery_app` is imported — this ordering
matters because worker/Beat startup handlers
(`app.tasks.worker_startup`, `app.tasks.beat_startup`) call
`bootstrap_fetcher_configs()` / `reconcile_beat_schedule()` against
whatever `FETCHER_REGISTRY` contains at that point, and both read the
registry only after `app.celery_app` finishes its own import-time
`app.services.fetcher_discovery` import.

After both imports complete, this module prunes both fetcher registries
— see docs/features/platform/testing-strategy.md (Registration
Boundary). `app.celery_app`'s import chain pulls in
`app.services.fetcher_discovery`, which registers every production
`BaseFetcher` subclass in `FETCHER_REGISTRY` and, for a CVE fetcher, in
`_CVE_SOURCE_TYPE_MAP` as well:

- `FETCHER_REGISTRY` is reduced to exactly the test-only fetcher. Left
  unpruned, this spawned process would bootstrap a `FetcherConfig` row,
  a redbeat schedule entry, and a real dispatch for every production
  fetcher too, risking genuine outbound network calls and domain-table
  mutations this suite must never produce, and risking that this
  suite's own assertions (`wait_config_row`, `snapshot_domain_tables`,
  "exactly one finalized run") observe a production fetcher's activity
  instead of only the test fetcher's.
- `_CVE_SOURCE_TYPE_MAP` is emptied, since the test-only fetcher is not
  a CVE fetcher. The two registries form one registration unit
  (docs/features/platform/cve-fetcher-infrastructure.md,
  `__init_subclass__` Validation); pruning only the first would leave
  every production CVE fetcher visible to `get_fetch_single_fetchers()`
  and `get_all_cve_source_types()` here, without its `FETCHER_REGISTRY`
  entry or `FetcherConfig` row.

Pruning happens strictly at import time of this module — before
Celery's own `celeryd_after_setup`/`beat_init` startup signals fire and invoke
`bootstrap_fetcher_configs()` — so the bootstrap and reconciliation
handlers only ever see the test fetcher. The production discovery
import path itself still runs unpruned; only the resulting registries
are restricted afterward. `tests/test_support/test_system_fetcher_app.py`
verifies both registries in a fresh interpreter.

This module MUST NOT be imported by any production entrypoint — see
`docs/features/platform/testing-strategy.md` (Local Process System
Testing, Registration Boundary).
"""

from __future__ import annotations

import tests.support.system_fetcher  # noqa: F401  (registration side effect)
from app.celery_app import celery_app
from app.services.base_cve_fetcher import _CVE_SOURCE_TYPE_MAP
from app.services.base_fetcher import FETCHER_REGISTRY
from tests.support.system_fetcher import SYSTEM_FETCHER_NAME, EvaluateTestPipeline

FETCHER_REGISTRY.clear()
FETCHER_REGISTRY[SYSTEM_FETCHER_NAME] = EvaluateTestPipeline
_CVE_SOURCE_TYPE_MAP.clear()

__all__ = ["celery_app"]
