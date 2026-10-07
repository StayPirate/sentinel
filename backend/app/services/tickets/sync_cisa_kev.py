"""`sync_cisa_kev`: CISA Known Exploited Vulnerabilities catalog fetcher.

Implements docs/features/tickets/cve-sync-kev.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- `execute()` downloads the complete catalog once, before any per-entry
  database work, so no HTTP request is made while a per-entry lock is
  held. A transport failure, a status other than 200, an undecodable
  body, or an unexpected structure aborts the run with a sanitized
  `FetcherError` chained from its cause.
- Each entry is processed in its own transaction: the canonical `cveID`
  check, a lock-free lookup of the existing CVE (an unknown CVE is skipped
  silently), the enrichment-only payload through `cve_service.upsert_cve()`,
  the source reference through `reference_service.upsert_references()`,
  the pre-finalization flush, and `commit_and_dispatch()` outside the
  per-entry catch.
- The documented deviation applies: no isolated source-status write on a
  per-entry error (cve-sync-kev.md, Conventions).
- `supports_fetch_single = False`: the base `fetch_single()` safety net is
  inherited and `participates_in_catch_up` derives as `False`.

`cve_service` and `reference_service` are imported as module objects and
dereferenced at call time: `cve_service` belongs to the import cycle of
`base_cve_fetcher`.
"""

from __future__ import annotations

import uuid
from asyncio import CancelledError
from typing import ClassVar, Final

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, ReferenceType
from app.models.cve import CVE
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import BaseCVEFetcher, CVEFetchResult
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import CVEIngestPayload
from app.services.tickets import cisa_kev_catalog
from app.services.tickets.cisa_kev_catalog import KevCatalog

logger = structlog.get_logger(__name__)

CISA_KEV_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
"""The complete catalog (Fetcher Definition, Source)."""

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (cve-fetcher-infrastructure.md, Batch Error
Handling): canonical CVE-ID when valid, fetcher name, and exception class
name only."""

CVE_FETCH_CANDIDATE_SKIPPED_EVENT: Final = "cve_fetch_candidate_skipped"
"""The WARNING of one rejected `cwes` item (Error Handling, Candidate skip
event): canonical CVE-ID, fetcher name, and closed reason."""

CISA_KEV_CATALOG_RECEIVED_EVENT: Final = "cisa_kev_catalog_received"
"""The INFO observability record of the catalog `count` (Algorithm
step 2)."""

INVALID_CWE_REASON: Final = "invalid_cwe"

SOURCE_REFERENCE_TITLE: Final = "CISA KEV"


class InvalidCveIdError(ValueError):
    """An entry that is not an object, or whose `cveID` is absent, not a
    string, or not a canonical CVE-ID. Never raised; its class name is the
    `cause` of the step-3f WARNING."""


class SyncCisaKev(BaseCVEFetcher):
    """Sync Known Exploited Vulnerabilities from the CISA KEV catalog."""

    name = "sync_cisa_kev"
    cve_source_type = CVESourceType.KEV
    description = "Sync Known Exploited Vulnerabilities from CISA KEV catalog"
    default_schedule = (
        "0 4,10,18,22 * * *"  # 4x daily, aligned to US Eastern business hours
    )
    supports_fetch_single = False
    source_reference_url_pattern: ClassVar[str] = (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        "?field_cve={cve_id}"
    )

    # No fetch_single() override: the BaseCVEFetcher safety net applies and
    # get_fetch_single_fetchers() excludes this fetcher.

    async def execute(self, session: AsyncSession) -> None:
        """Download the full KEV catalog and process all entries."""
        catalog = await self._download()
        logger.info(
            CISA_KEV_CATALOG_RECEIVED_EVENT,
            fetcher_name=self.name,
            count=catalog.count,
            entries=len(catalog.entries),
        )
        for entry in catalog.entries:
            await self._process_entry(session, entry)

    async def _download(self) -> KevCatalog:
        """Algorithm steps 1-2: one `GET`, no database work."""
        try:
            response = await self.http_client.get(CISA_KEV_URL)
        except httpx.DecodingError as e:
            # An undecodable content encoding is a response, not a transport
            # failure.
            raise FetcherError("CISA KEV feed returned unparseable response") from e
        except httpx.TransportError as e:
            raise FetcherError("Failed to connect to CISA KEV feed") from e
        if response.status_code != 200:
            message = f"CISA KEV feed returned HTTP {response.status_code}"
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise FetcherError(message) from e
            raise FetcherError(message)
        try:
            document = response.json()
        except (ValueError, RecursionError) as e:
            raise FetcherError("CISA KEV feed returned unparseable response") from e
        try:
            return cisa_kev_catalog.parse_catalog(document)
        except cisa_kev_catalog.KevCatalogStructureError as e:
            raise FetcherError("CISA KEV feed has unexpected structure") from e

    async def _process_entry(self, session: AsyncSession, entry: object) -> None:
        """Algorithm step 3 for one entry, in its own transaction."""
        cve_id = cisa_kev_catalog.entry_cve_id(entry)
        if not (
            isinstance(entry, dict)
            and isinstance(cve_id, str)
            and self._is_valid_cve_id(cve_id)
        ):
            # Step 3f: invalid input before database work, no rollback.
            self._entry_failed(None, InvalidCveIdError.__name__)
            return

        try:
            exists = await self._cve_exists(session, cve_id)
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await session.rollback()
            self._entry_failed(cve_id, type(e).__name__)
            return
        if not exists:
            # Enrichment-only scope: skip silently and end the read.
            await session.rollback()
            return

        try:
            fetch_result = await self._ingest(session, cve_id, entry)
            await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await session.rollback()
            self._entry_failed(cve_id, type(e).__name__)
        else:
            # Keep finalization outside the pre-commit per-item catch.
            await self.commit_and_dispatch(session, fetch_result)

    async def _cve_exists(self, session: AsyncSession, cve_id: str) -> bool:
        """Lock-free lookup of an existing CVE by canonical CVE-ID; the
        lock is `upsert_cve()`'s."""
        cve_uuid: uuid.UUID | None = await session.scalar(
            select(CVE.id).where(CVE.cve_id == cve_id)
        )
        return cve_uuid is not None

    async def _ingest(
        self, session: AsyncSession, cve_id: str, entry: dict[str, object]
    ) -> CVEFetchResult:
        """Algorithm step 3d up to the finalization token; never commits
        and records no metric."""
        reference_url = self.source_reference_url_pattern.format(cve_id=cve_id)
        enrichment = cisa_kev_catalog.extract(entry, reference_url=reference_url)
        for _ in range(enrichment.skipped_cwes):
            logger.warning(
                CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                cve_id=cve_id,
                fetcher_name=self.name,
                reason=INVALID_CWE_REASON,
            )
        payload = CVEIngestPayload(
            kev_data=enrichment.kev_entry,
            cwe_classifications=enrichment.cwe_classifications,
        )
        result = await cve_service.upsert_cve(
            session, cve_id, self.cve_source_type, payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            self.name,
            reference_service.AutomaticReferenceInput(
                url=reference_url,
                title=SOURCE_REFERENCE_TITLE,
                explicit_type=ReferenceType.ADVISORY,
            ),
            (),
        )
        return CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, payload)
        )

    def _entry_failed(self, cve_id: str | None, cause: str) -> None:
        """Steps 3e/3f: one WARNING (no `cve_id` without a canonical one)
        and one failed unit."""
        if cve_id is None:
            logger.warning(
                CVE_FETCH_ITEM_FAILED_EVENT, fetcher_name=self.name, cause=cause
            )
        else:
            logger.warning(
                CVE_FETCH_ITEM_FAILED_EVENT,
                cve_id=cve_id,
                fetcher_name=self.name,
                cause=cause,
            )
        self.record_failed()
