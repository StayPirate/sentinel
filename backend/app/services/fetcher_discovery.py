"""Fetcher module discovery — single source of truth for fetcher imports.

Importing this module populates `FETCHER_REGISTRY` and
`_CVE_SOURCE_TYPE_MAP` (`app/services/base_cve_fetcher.py`) as a side
effect of importing every concrete `BaseFetcher` subclass module. Every
process that consumes either registry (API server, Celery worker, Celery
Beat) imports this module once at startup.

See `docs/features/platform/fetcher-infrastructure.md` (Fetcher
Discovery (Module Import)) for the full specification.

One `import` line per concrete fetcher module, placed in its domain
package (`docs/features/platform/fetcher-infrastructure.md`, Domain
Placement). The drift test parses these statements statically, so each
must use the plain `import app.services.<domain>.<module>` form.
"""

from __future__ import annotations

import app.services.packages.evaluate_lifecycle_transitions
import app.services.packages.sync_aimaas_lifecycle
import app.services.packages.sync_aimaas_thresholds
import app.services.packages.sync_smelt_products
import app.services.tickets.evaluate_failed_cve_sources
import app.services.tickets.sync_cisa_kev
import app.services.tickets.sync_epss_scores
import app.services.tickets.sync_ghsa_advisories
import app.services.tickets.sync_kernel_cves
import app.services.tickets.sync_mitre_cves
import app.services.tickets.sync_osv_advisories
import app.services.tickets.sync_redhat_cves  # noqa: F401
