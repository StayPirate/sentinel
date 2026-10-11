"""`sync_nvd_cves`: NVD CVE API 2.0 fetcher.

Implements docs/features/tickets/cve-sync-nvd.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- Every NVD request (CVE API and Source API) carries the `apiKey` header
  when `NVD_API_KEY` is set, attached per request from
  `settings.nvd_api_key`; the key is never a client default header or a
  query parameter. A key that is not a valid header value fails application
  startup (`Settings`), so no request is built with it. Redirects are never
  followed.
- `execute()` follows template 2 of Session Lifecycle for API-based CVE
  Fetchers: `now` is captured at entry, and the derived cursor
  (`fetcher_execution.get_derived_cursor()`) is read and its transaction
  ended before the first NVD request; a first run and a stale cursor return
  without any request. The Source API cache is built once (degraded mode on
  failure), then the `startIndex` pages of the `lastModified` window are
  requested with the first page's `totalResults` as the fixed bound and the
  run's `request_delay` between requests; a persistent HTTP 429 is retried
  once after 30 seconds. A page-level failure aborts the run with a
  sanitized `FetcherError` chained only from a content-free cause. Each CVE
  is processed in its own transaction with `commit_and_dispatch()` outside
  the per-CVE catch.
- `fetch_single()` sends one `cveId` query and, when the response holds the
  requested CVE, resolves provider names through the Source API cache that
  every `fetch_single()` of the process shares: a successful build serves
  for `SOURCE_CACHE_TTL` seconds on a monotonic clock, and a degraded build
  is never stored. Every HTTP error status propagates unchanged so
  `is_retryable_condition()` keeps classifying it; HTTP 404 is a rejected
  request, never a missing CVE.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

The record mapping, the Source API cache, and the CPE selection are the
pure functions of `nvd_cve_record`; this module owns the requests, the log
events built from the facts they report, and the ingestion.

`cve_service`, `reference_service`, and `fetcher_execution` are imported as
module objects and dereferenced at call time: `cve_service` belongs to the
import cycle of `base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
import time
from asyncio import CancelledError
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.services import cve_service, fetcher_execution, reference_service
from app.services.base_cve_fetcher import (
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    CVE_FETCH_ITEM_FAILED_EVENT,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.tickets import nvd_cve_record

logger = structlog.get_logger(__name__)

NVD_CVE_API_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
"""The CVE API endpoint of both the periodic window query and `fetch_single()`."""

NVD_SOURCE_API_URL: Final = "https://services.nvd.nist.gov/rest/json/source/2.0"
"""The Source API endpoint (NVD Source API Caching)."""

API_KEY_HEADER: Final = "apiKey"
"""The NVD-proprietary API key request header (HTTP Client Configuration)."""

NVD_FIRST_RUN_EVENT: Final = "nvd_first_run"
"""The first-run INFO (First Run and >120-day Gap Handling)."""

NVD_CURSOR_RESET_EVENT: Final = "nvd_cursor_reset"
"""The stale-cursor WARNING (First Run and >120-day Gap Handling)."""

NVD_SOURCE_API_UNAVAILABLE_EVENT: Final = "nvd_source_api_unavailable"
"""The degraded-mode WARNING (NVD Source API Failure Handling)."""

NVD_SOURCE_ENTRIES_SKIPPED_EVENT: Final = "nvd_source_entries_skipped"
"""The count-only WARNING of malformed Source API entries."""

NVD_SOURCE_CACHE_INCOMPLETE_EVENT: Final = "nvd_source_cache_incomplete"
"""The pagination-guard WARNING of the Source API cache."""

NVD_VULN_STATUS_UNRECOGNIZED_EVENT: Final = "nvd_vuln_status_unrecognized"
"""The bounded WARNING of an unlisted `vulnStatus` (canonical CVE-ID and
fetcher name, never the value)."""

CONNECTION_FAILED: Final = "Failed to connect to NVD API"
TIMED_OUT: Final = "NVD API request timed out"
RATE_LIMIT_EXHAUSTED: Final = "NVD API rate limit exceeded — retries exhausted"
UNPARSEABLE_RESPONSE: Final = "NVD API returned unparseable response"

_OVERLAP: Final = timedelta(minutes=15)
"""The overlap buffer between the cursor and the window start."""

_STALE_AFTER: Final = timedelta(days=120)
"""NVD's maximum `lastModified` range; a longer window resets the cursor."""

RATE_LIMIT_RETRY_DELAY: Final = 30.0
"""Seconds to wait before the single page retry after a persistent HTTP 429
(NVD's documented rate-limit window)."""

_NVD_DATE_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.000"
"""NVD Date Format: UTC, `.000` milliseconds, no offset."""

SOURCE_CACHE_TTL: Final = 3600.0
"""Seconds a successful Source API build serves the `fetch_single()` calls of
one process (NVD Source API Caching, Lifecycle); a fixed value, not a
setting."""

_monotonic = time.monotonic
"""The clock of the shared Source API cache."""


class _SharedSourceCache:
    """The Source API cache that every `fetch_single()` of the process shares
    (NVD Source API Caching, Lifecycle).

    Holds only the identifier-to-name mapping of the last successful build
    and that build's completion time on `_monotonic()`: nothing bound to an
    event loop, session, or HTTP client, so it outlives the per-attempt
    `asyncio.run()` of the worker tasks. A degraded build is never stored.
    """

    __slots__ = ("_built_at", "_names")

    def __init__(self) -> None:
        self._names: Mapping[str, str] | None = None
        self._built_at = 0.0

    def get(self) -> Mapping[str, str] | None:
        """The stored mapping while its age is below `SOURCE_CACHE_TTL`,
        `None` before the first build and once it has expired."""
        if self._names is None or _monotonic() - self._built_at >= SOURCE_CACHE_TTL:
            return None
        return self._names

    def store(self, names: Mapping[str, str]) -> None:
        """Replace the stored mapping with a build completed now."""
        self._names = names
        self._built_at = _monotonic()

    def clear(self) -> None:
        """Forget the stored mapping."""
        self._names = None
        self._built_at = 0.0


_shared_source_cache: Final = _SharedSourceCache()
"""The process-wide instance; `execute()` never reads or fills it."""


class NvdResponseError(Exception):
    """A `fetch_single()` response that is neither an HTTP error nor the
    single requested record: another 2xx status, or `totalResults >= 1`
    with an empty or multi-element `vulnerabilities`. Non-retryable; the
    fixed message carries no response content."""

    def __init__(self) -> None:
        super().__init__("NVD API returned an unexpected response")


class SyncNvdCves(BaseCVEFetcher):
    """Sync CVE data from the NVD CVE API 2.0."""

    name = "sync_nvd_cves"
    cve_source_type = CVESourceType.NVD
    description = "Sync CVEs from NVD REST API v2"
    default_schedule = "0 */6 * * *"
    default_request_delay = 6.0

    class Settings(BaseModel):
        model_config = ConfigDict(extra="ignore", validate_default=True)

        results_per_page: int = Field(
            default=2000,
            ge=100,
            le=2000,
            description="Number of CVE records per API page.",
        )

    source_reference_url_pattern = nvd_cve_record.SOURCE_REFERENCE_URL_PATTERN

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest one CVE from the NVD CVE API.

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any request.

        Q3: one `GET /cves/2.0?cveId=…` with the per-request API key header,
        without redirects or throttle. When the response holds the requested
        CVE, the provider cache is the one shared by the process while it is
        valid; otherwise one Source API request builds it (degraded mode and
        its WARNING on any failure, never stored). The element is mapped, its
        skip and unknown-status facts logged, then `upsert_cve()` and
        `upsert_references()` (the NVD source reference first, then
        `.references[]`) run in `session`. Adds no flush beyond its
        delegates' own, never commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and the
        optional package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: `totalResults == 0`, or a single element whose `.id` is a string
        different from `cve_id`, raises `CVENotInSource` before any database
        work. Every non-200 status other than a 2xx (3xx, every 4xx
        including 404, 429, 5xx) raises its original `httpx.HTTPStatusError`;
        another 2xx, or `totalResults >= 1` with an empty or multi-element
        `vulnerabilities`, raises `NvdResponseError`. An unparseable body
        raises `NvdPageError`; a structurally non-processable element raises
        `NvdRecordStructureError`; a payload value containing U+0000 raises
        `pydantic.ValidationError`. Transport and delegate exceptions
        propagate unchanged.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        response = await self.http_client.get(
            NVD_CVE_API_URL, params={"cveId": cve_id}, headers=_headers()
        )
        if response.status_code != 200:
            response.raise_for_status()
            raise NvdResponseError()
        page = nvd_cve_record.parse_page(response.content)
        if page.total_results == 0:
            raise CVENotInSource()
        if len(page.vulnerabilities) != 1:
            raise NvdResponseError()
        element = page.vulnerabilities[0]
        record_id = _raw_cve_id(element)
        if not isinstance(record_id, str):
            # Not the requested CVE in processable form: no Source API request.
            raise nvd_cve_record.NvdRecordStructureError
        if record_id != cve_id:
            raise CVENotInSource()
        source_names = await self._shared_source_names()
        return await self._ingest(session, element, source_names)

    async def execute(self, session: AsyncSession) -> None:
        """Periodic batch over the CVEs modified since the cursor."""
        now = datetime.now(UTC)
        last_sync = await fetcher_execution.get_derived_cursor(session, self.name)
        # End the read transaction before any NVD request.
        await session.rollback()
        if last_sync is None:
            logger.info(NVD_FIRST_RUN_EVENT, fetcher_name=self.name)
            return  # First run: this run's started_at becomes the cursor.
        window_start = last_sync.astimezone(UTC) - _OVERLAP
        if now - window_start > _STALE_AFTER:
            logger.warning(
                NVD_CURSOR_RESET_EVENT,
                fetcher_name=self.name,
                age_days=(now - window_start).days,
            )
            return

        request_delay = (
            self.config.request_delay
            if self.config is not None
            else self.default_request_delay
        )
        results_per_page: int = self.get_setting("results_per_page")
        source_names = await self._source_names()
        await asyncio.sleep(request_delay)

        start_index = 0
        total_results: int | None = None
        while True:
            page = await self._get_page(
                {
                    "lastModStartDate": window_start.strftime(_NVD_DATE_FORMAT),
                    "lastModEndDate": now.strftime(_NVD_DATE_FORMAT),
                    "startIndex": str(start_index),
                    "resultsPerPage": str(results_per_page),
                }
            )
            if total_results is None:
                # The first page's count is the fixed exit bound.
                total_results = page.total_results
            for element in page.vulnerabilities:
                await self._process_vulnerability(session, element, source_names)
            start_index += results_per_page
            if start_index >= total_results:
                return
            await asyncio.sleep(request_delay)

    async def _shared_source_names(self) -> Mapping[str, str] | None:
        """The provider cache of `fetch_single()`: the process-wide cache
        while valid, otherwise one `_source_names()` build, stored only when
        it succeeded; `None` is degraded mode."""
        names = _shared_source_cache.get()
        if names is None:
            names = await self._source_names()
            if names is not None:
                _shared_source_cache.store(names)
        return names

    async def _source_names(self) -> Mapping[str, str] | None:
        """One Source API request (NVD Source API Caching); `None` is
        degraded mode. A failure is never raised."""
        cache: nvd_cve_record.NvdSourceCache | None = None
        try:
            response = await self.http_client.get(
                NVD_SOURCE_API_URL, headers=_headers()
            )
        except httpx.HTTPError:
            pass  # Transport or decoding failure: degraded mode.
        else:
            if response.status_code == 200:
                cache = nvd_cve_record.build_source_cache(response.content)
        if cache is None or cache.names is None:
            logger.warning(NVD_SOURCE_API_UNAVAILABLE_EVENT, fetcher_name=self.name)
            return None
        if cache.malformed_entries:
            logger.warning(
                NVD_SOURCE_ENTRIES_SKIPPED_EVENT,
                fetcher_name=self.name,
                count=cache.malformed_entries,
            )
        if cache.incomplete:
            logger.warning(NVD_SOURCE_CACHE_INCOMPLETE_EVENT, fetcher_name=self.name)
        return cache.names

    async def _get_page(self, params: dict[str, str]) -> nvd_cve_record.NvdCvePage:
        """One CVE page (Algorithm steps 4.b-c, Rate Limiting); a persistent
        HTTP 429 is retried once after `RATE_LIMIT_RETRY_DELAY`."""
        response = await self._request_page(params)
        if response.status_code == 429:
            await asyncio.sleep(RATE_LIMIT_RETRY_DELAY)
            response = await self._request_page(params)
            if response.status_code == 429:
                _raise_chained(response, RATE_LIMIT_EXHAUSTED)
        if response.status_code != 200:
            _raise_chained(response, f"NVD API returned HTTP {response.status_code}")
        try:
            return nvd_cve_record.parse_page(response.content)
        except nvd_cve_record.NvdPageError as e:
            raise FetcherError(UNPARSEABLE_RESPONSE) from e

    async def _request_page(self, params: dict[str, str]) -> httpx.Response:
        """One page request; no database work."""
        try:
            return await self.http_client.get(
                NVD_CVE_API_URL, params=params, headers=_headers()
            )
        except httpx.DecodingError as e:
            # An undecodable content encoding is a response, not a transport
            # failure.
            raise FetcherError(UNPARSEABLE_RESPONSE) from e
        except httpx.TimeoutException as e:
            raise FetcherError(TIMED_OUT) from e
        except httpx.TransportError as e:
            raise FetcherError(CONNECTION_FAILED) from e

    async def _process_vulnerability(
        self,
        session: AsyncSession,
        element: object,
        source_names: Mapping[str, str] | None,
    ) -> None:
        """Algorithm step 4.e for one page element, in its own transaction."""
        cve_id = nvd_cve_record.element_cve_id(element)
        if cve_id is None:
            # No canonical CVE-ID: invalid input before database work, no
            # status write, and no identifier in the event.
            cause = (
                nvd_cve_record.NvdRecordIdError
                if isinstance(_raw_cve_id(element), str)
                else nvd_cve_record.NvdRecordStructureError
            )
            self._item_failed(None, cause.__name__)
            return
        try:
            result = await self._ingest(session, element, source_names)
            await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await session.rollback()
            await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
            self._item_failed(cve_id, type(e).__name__)
        else:
            # Keep finalization outside the pre-commit per-item catch.
            await self.commit_and_dispatch(session, result)

    async def _ingest(
        self,
        session: AsyncSession,
        element: object,
        source_names: Mapping[str, str] | None,
    ) -> CVEFetchResult:
        """Field Mapping, upsert, and references up to the finalization token;
        never commits and records no metric."""
        record = nvd_cve_record.map_vulnerability(element, source_names)
        for reason in sorted(record.skip_reasons):
            logger.warning(
                CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                cve_id=record.cve_id,
                fetcher_name=self.name,
                reason=reason,
            )
        if record.unrecognized_vuln_status:
            logger.warning(
                NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
                cve_id=record.cve_id,
                fetcher_name=self.name,
            )
        result = await cve_service.upsert_cve(
            session, record.cve_id, self.cve_source_type, record.payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            record.cve_id,
            self.name,
            record.source_reference,
            record.upstream_references,
        )
        return CVEFetchResult(
            result.action,
            cve_service.build_post_ingest_tasks(result, record.payload),
        )

    def _item_failed(self, cve_id: str | None, cause: str) -> None:
        """One per-item WARNING (no `cve_id` without a canonical one) and one
        failed unit."""
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


def _headers() -> dict[str, str]:
    """The per-request headers: `apiKey` when a key is configured, read at
    call time and never stored on the client. `Settings` has already
    rejected a key that is not a valid header value."""
    api_key = settings.nvd_api_key.get_secret_value()
    return {API_KEY_HEADER: api_key} if api_key else {}


def _raw_cve_id(element: object) -> object:
    """The raw `.id` member of an element, `None` when there is none."""
    cve = element.get("cve") if isinstance(element, dict) else None
    return cve.get("id") if isinstance(cve, dict) else None


def _raise_chained(response: httpx.Response, message: str) -> None:
    """Raise `FetcherError(message)` chained from the response's
    `httpx.HTTPStatusError` when it has one. Its text carries the status
    line, the request URL (no API key), and for a 3xx the `Location` value;
    never record content."""
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise FetcherError(message) from e
    raise FetcherError(message)
