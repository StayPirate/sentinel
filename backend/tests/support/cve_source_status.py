"""Shared test-only CVE fetcher definitions for the per-CVE source-status
tests of `cve_service.get_cve_source_status()`.

Consumers:

- `tests/test_services/test_cve_source_status.py` (the service matrix);
- `tests/test_api/test_cve_source_status.py` (the HTTP contract).

Definitions register as an import-time side effect of
`BaseCVEFetcher.__init_subclass__`, so callers use them only under the
`isolated_fetcher_registries` fixture, which restores both registries.
See docs/features/platform/cve-fetcher-infrastructure.md
(`__init_subclass__` Validation — Test isolation).
"""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
)
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cve_ingest import UpsertAction
from app.services.cve_service import KEV_FETCHER_NAME


async def _execute_stub(self: BaseCVEFetcher, session: AsyncSession) -> None:
    return None


async def _fetch_single_stub(
    self: BaseCVEFetcher, cve_id: str, session: AsyncSession
) -> CVEFetchResult:
    return CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)


def clear_fetcher_registries() -> None:
    """Empty both registries so a test controls their exact content."""
    FETCHER_REGISTRY.clear()
    _CVE_SOURCE_TYPE_MAP.clear()


def define_cve_fetcher(
    source: CVESourceType, *, refetchable: bool = True, name: str | None = None
) -> type[BaseCVEFetcher]:
    """Register one test-only CVE fetcher for `source`.

    `refetchable` sets `supports_fetch_single` (with a stub `fetch_single()`
    when true); `name` defaults to a unique valid fetcher name.
    """
    namespace: dict[str, Any] = {
        "name": name or f"test_status_{source.value}_{uuid.uuid4().hex[:8]}",
        "description": "Test-only CVE source-status fetcher",
        "default_schedule": "0 * * * *",
        "execute": _execute_stub,
        "cve_source_type": source,
        "supports_fetch_single": refetchable,
    }
    if refetchable:
        namespace["fetch_single"] = _fetch_single_stub
    return cast(
        type[BaseCVEFetcher],
        type(f"_StatusFetcher_{source.value}", (BaseCVEFetcher,), namespace),
    )


def define_kev_fetcher() -> type[BaseCVEFetcher]:
    """The KEV source: catalog-based, never refetchable, under its stable
    fetcher name `sync_cisa_kev`."""
    return define_cve_fetcher(
        CVESourceType.KEV, refetchable=False, name=KEV_FETCHER_NAME
    )
