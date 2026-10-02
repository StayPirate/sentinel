"""Fetcher module discovery — single source of truth for fetcher imports.

Importing this module populates `FETCHER_REGISTRY` and
`_CVE_SOURCE_TYPE_MAP` (`app/services/base_cve_fetcher.py`) as a side
effect of importing every concrete `BaseFetcher` subclass module. Every
process that consumes either registry (API server, Celery worker, Celery
Beat) imports this module once at startup.

See `docs/features/platform/fetcher-infrastructure.md` (Fetcher
Discovery (Module Import)) for the full specification.

No production fetcher exists yet — see
`docs/features/platform/fetcher-infrastructure.md` (Domain Placement)
for where future fetchers will be added, one import line per fetcher,
when they are implemented.
"""

from __future__ import annotations
