"""`sync_epss_scores`: FIRST.org EPSS score enrichment fetcher.

Implements docs/features/tickets/cve-sync-epss.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- `fetch_single()` requests one CVE from the EPSS API, validates the
  response (`epss_score_record`), and ingests the score, percentile, and
  assessment date as an enrichment-only payload through
  `cve_service.upsert_cve()` in the caller's transaction. An empty `data`
  array raises `CVENotInSource` before any database work. Every HTTP
  error status and every transport, decoding, and validation failure
  propagates as its original exception, so `is_infrastructure_failure()`
  and `is_retryable_condition()` keep classifying it.
- `execute()` follows template 1 of Session Lifecycle for API-based CVE
  Fetchers over one active-Ticket scope snapshot, with the consecutive
  infrastructure-failure abort and the once-per-run diagnostic staleness
  check.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

`cve_service` is imported as a module object and dereferenced at call
time: it belongs to the import cycle of `base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
from asyncio import CancelledError
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.services import cve_service
from app.services.base_cve_fetcher import (
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import CVEIngestPayload, EPSSEntry
from app.services.http_client import is_infrastructure_failure
from app.services.tickets import epss_score_record

logger = structlog.get_logger(__name__)

EPSS_URL: Final = "https://api.first.org/data/v1/epss"
"""The EPSS API endpoint; the CVE-ID is the `cve` query parameter
(Algorithm step 1)."""

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (cve-fetcher-infrastructure.md, Batch Error
Handling): canonical CVE-ID, fetcher name, and exception class name only."""

EPSS_DATA_STALE_EVENT: Final = "epss_data_stale"
"""The diagnostic staleness WARNING (Algorithm, Staleness validation)."""

EPSS_STALENESS_CHECK_FAILED_EVENT: Final = "epss_staleness_check_failed"
"""The DEBUG record of a swallowed staleness-check exception."""

_ABORT_THRESHOLD: Final = 3
"""Consecutive infrastructure failures that abort a periodic run."""

_STALENESS_TOLERANCE: Final = timedelta(days=1)
"""Stale when the assessment date is earlier than today (UTC) minus this."""


def _utc_today() -> date:
    """The current UTC date (the staleness reference)."""
    return datetime.now(UTC).date()


class SyncEpssScores(BaseCVEFetcher):
    """Sync EPSS scores from the FIRST.org EPSS API."""

    name = "sync_epss_scores"
    cve_source_type = CVESourceType.EPSS
    description = "Sync EPSS scores from FIRST.org"
    default_schedule = "0 14 * * *"
    default_request_delay = 0.2

    source_reference_url_pattern = None  # No per-CVE page on FIRST.org

    _last_assessed_date: date | None = None
    """The `date` of the first successful parse since the last reset;
    reset at every `execute()` entry."""

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest the EPSS score of one CVE.

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any HTTP
        request.

        Q3: one `GET` with the `cve` query parameter, without redirects.
        A non-empty response caches its assessment date on the first
        successful parse, then the enrichment-only payload carrying only
        `epss_score` goes to `upsert_cve()` in `session`. Adds no flush
        beyond its delegate's own, never commits, records no metric,
        throttles nothing, and performs no staleness check.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        no package handoff (`post_ingest = None`).

        Q5: idempotent through `upsert_cve()`: equal content is
        `unchanged`.

        Q6: HTTP 200 with an empty `data` array raises `CVENotInSource`
        before any database work. An HTTP error status raises its original
        `httpx.HTTPStatusError`; transport errors, JSON decoding errors,
        `pydantic.ValidationError` (schema mismatch, more than one entry,
        an out-of-range or unparseable value, or U+0000), and delegate
        exceptions propagate unchanged.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        body = await self._fetch_epss(cve_id)
        entry = self._extract_entry(body)
        if entry is None:
            raise CVENotInSource()
        payload = CVEIngestPayload(epss_score=entry)
        result = await cve_service.upsert_cve(
            session, cve_id, self.cve_source_type, payload
        )
        return CVEFetchResult(result.action, None)

    async def _fetch_epss(self, cve_id: str) -> Any:
        """Request one CVE and decode the body; no database work."""
        response = await self.http_client.get(EPSS_URL, params={"cve": cve_id})
        response.raise_for_status()
        return response.json()

    def _extract_entry(self, body: object) -> EPSSEntry | None:
        """Validate and convert the entry, or `None` for an empty `data`.

        Caches the assessment date of the first successful parse for the
        periodic staleness check.
        """
        records = epss_score_record.parse_response(body).data
        if not records:
            return None
        entry = epss_score_record.to_epss_entry(records[0])
        if self._last_assessed_date is None:
            self._last_assessed_date = entry.assessed_at
        return entry

    async def execute(self, session: AsyncSession) -> None:
        """Periodic batch over the CVEs of active Tickets.

        Scope snapshot: the in-scope CVE-ID set is queried once at the
        start of execute(). New tickets created mid-run are covered by
        the default catch_up() mechanism and on-demand fetch_single().
        """
        self._last_assessed_date = None
        request_delay = self.config.request_delay if self.config is not None else 0.0
        cve_ids = await self._get_active_ticket_cve_ids(session)
        staleness_checked = False
        consecutive_failures = 0
        for cve_id in cve_ids:
            try:
                result = await self.fetch_single(cve_id, session)
                await session.flush()
            except CancelledError, SoftTimeLimitExceeded, MemoryError:
                raise  # whole-run signals — never catch per-item
            except CVENotInSource:
                await session.rollback()
                await self._isolated_status_commit(cve_id, CVESourceFetchStatus.MISSING)
                self.record_succeeded()
                consecutive_failures = 0  # API responded — clean skip
            except Exception as e:
                await session.rollback()
                await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
                logger.warning(
                    CVE_FETCH_ITEM_FAILED_EVENT,
                    cve_id=cve_id,
                    fetcher_name=self.name,
                    cause=type(e).__name__,
                )
                self.record_failed()
                if is_infrastructure_failure(e):
                    consecutive_failures += 1
                    if consecutive_failures >= _ABORT_THRESHOLD:
                        raise FetcherError(
                            f"{self.name}: source unreachable"
                            " — aborted after 3 consecutive failures"
                        ) from e
                else:
                    consecutive_failures = 0  # API responded — data error
            else:
                # Keep finalization outside the pre-commit per-item catch.
                await self.commit_and_dispatch(session, result)
                consecutive_failures = 0
            if not staleness_checked and self._last_assessed_date is not None:
                try:
                    self._check_staleness(self._last_assessed_date)
                except CancelledError, SoftTimeLimitExceeded, MemoryError:
                    raise  # whole-run signals — never swallowed
                except Exception as e:
                    # Staleness is purely diagnostic.
                    logger.debug(
                        EPSS_STALENESS_CHECK_FAILED_EVENT,
                        fetcher_name=self.name,
                        cause=type(e).__name__,
                    )
                staleness_checked = True
            await asyncio.sleep(request_delay)

    def _check_staleness(self, assessed_at: date) -> None:
        """Log `epss_data_stale` when `assessed_at` is earlier than today
        (UTC) minus one day; never raises for stale data."""
        today = _utc_today()
        if assessed_at < today - _STALENESS_TOLERANCE:
            logger.warning(
                EPSS_DATA_STALE_EVENT,
                fetcher_name=self.name,
                assessed_at=assessed_at.isoformat(),
                expected=today.isoformat(),
            )

    async def _get_active_ticket_cve_ids(self, session: AsyncSession) -> list[str]:
        """The run's scope snapshot (cve-service.md, Active-Ticket CVE Scope)."""
        return await cve_service.get_active_ticket_cve_ids(session)
