"""`sync_ghsa_advisories`: GitHub Advisory Database CVE fetcher.

Implements docs/features/tickets/cve-sync-ghsa.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- Every request carries `Authorization: Bearer <GITHUB_TOKEN>`, attached
  per request from `settings.github_token`. An empty or unset token raises
  `FetcherError("GITHUB_TOKEN not configured")` before any database read
  or HTTP request. Redirects are never followed.
- `execute()` follows template 2 of Session Lifecycle for API-based CVE
  Fetchers: the derived cursor (`fetcher_execution.get_derived_cursor()`)
  is read and its transaction ended before the first GitHub request; a
  first run and a stale cursor return without any request. Pages of
  reviewed, non-withdrawn advisories modified since the window start are
  followed through `Link` `rel="next"` after the fail-closed next-URL
  check, with the run's `request_delay` between pages. A page-level
  failure aborts the run with a sanitized `FetcherError` chained only from
  a content-free cause. Each advisory is processed in its own transaction
  with `commit_and_dispatch()` outside the per-advisory catch.
- `fetch_single()` sends one `?cve_id=` query and processes the first
  advisory; HTTP 401 raises the sanitized authentication `FetcherError`,
  every other HTTP error status propagates unchanged so
  `is_retryable_condition()` keeps classifying it.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

`cve_service`, `reference_service`, and `fetcher_execution` are imported as
module objects and dereferenced at call time: `cve_service` belongs to the
import cycle of `base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
from asyncio import CancelledError
from datetime import UTC, datetime, timedelta
from typing import Final
from urllib.parse import urlsplit

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.services import cve_service, fetcher_execution, reference_service
from app.services.base_cve_fetcher import (
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.tickets import ghsa_advisory_record

logger = structlog.get_logger(__name__)

GHSA_ADVISORIES_URL: Final = "https://api.github.com/advisories"
"""The advisories endpoint of both the periodic query and `fetch_single()`."""

_NEXT_URL_SCHEME: Final = "https"
_NEXT_URL_NETLOC: Final = "api.github.com"
_NEXT_URL_PATH: Final = "/advisories"

GITHUB_API_VERSION: Final = "2022-11-28"

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (cve-fetcher-infrastructure.md, Batch Error
Handling): canonical CVE-ID when valid, fetcher name, and exception class
name only."""

CVE_FETCH_CANDIDATE_SKIPPED_EVENT: Final = "cve_fetch_candidate_skipped"
"""The WARNING of one rejected CWE (Response Validation, Candidate skip
event): canonical CVE-ID, fetcher name, and closed reason."""

GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT: Final = "ghsa_version_range_unrecognized"
"""The WARNING of one unrecognized `vulnerable_version_range` (Version range
parsing rules): canonical CVE-ID and fetcher name, never the range."""

GHSA_CURSOR_RESET_EVENT: Final = "ghsa_cursor_reset"
"""The stale-cursor WARNING (Stale Cursor Handling)."""

INVALID_CWE_REASON: Final = "invalid_cwe"

TOKEN_NOT_CONFIGURED: Final = "GITHUB_TOKEN not configured"
AUTHENTICATION_FAILED: Final = "GitHub API authentication failed"
RATE_LIMITED: Final = "GitHub API rate limit exceeded or access denied"
CONNECTION_FAILED: Final = "Failed to connect to GitHub Advisory API"
UNPARSEABLE_RESPONSE: Final = "GitHub Advisory API returned unparseable response"
UNTRUSTED_NEXT_URL: Final = "GitHub Advisory API returned an untrusted next-page URL"

_OVERLAP: Final = timedelta(minutes=15)
"""The overlap buffer between the cursor and the window start."""

_STALE_AFTER: Final = timedelta(days=30)
"""The window-start age beyond which the cursor is reset."""

_RATE_LIMIT_STATUSES: Final = frozenset({403, 429})


class InvalidCveIdError(ValueError):
    """A page element that is not an object, or whose `cve_id` is not a
    string or not a canonical CVE-ID. Never raised; its class name is the
    `cause` of the step-6.d.ii WARNING."""


class GhsaResponseError(Exception):
    """A `fetch_single()` response that is neither an HTTP error nor a
    usable array: another 2xx status, a non-array root, or a non-object
    first element. Non-retryable; the fixed message carries no upstream
    data."""

    def __init__(self) -> None:
        super().__init__("GitHub Advisory API returned an unexpected response")


class SyncGhsaAdvisories(BaseCVEFetcher):
    """Sync CVE data from the GitHub Advisory Database REST API."""

    name = "sync_ghsa_advisories"
    cve_source_type = CVESourceType.GHSA
    description = "Sync CVE data from GitHub Advisory Database"
    default_schedule = "0 */3 * * *"
    default_request_delay = 1.0

    source_reference_url_pattern = None

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest one CVE from the GitHub Advisory REST API.

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: an empty or unset `GITHUB_TOKEN` raises the token `FetcherError`
        first; a malformed `cve_id` then raises `CVENotInSource`, both
        before any HTTP request.

        Q3: one `GET /advisories?cve_id=…&type=reviewed&is_withdrawn=false`
        with the bearer token, without redirects or throttle. The first
        advisory is validated and extracted; each rejected CWE and each
        unrecognized range logs one bounded WARNING. Then `upsert_cve()`
        and `upsert_references()` (the `html_url` source reference first,
        then `references[]`) run in `session`. Adds no flush beyond its
        delegates' own, never commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        the optional package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: an empty array, or a first advisory whose `cve_id` is absent,
        `null`, malformed, or different from `cve_id`, raises
        `CVENotInSource` before any database work. HTTP 401 raises
        `FetcherError("GitHub API authentication failed")`; any other HTTP
        error status raises its original `httpx.HTTPStatusError`; another
        2xx, a non-array root, or a non-object first element raises
        `GhsaResponseError`. Transport, JSON decoding,
        `pydantic.ValidationError` (schema mismatch, or a payload value
        containing U+0000 or over its length bound), and delegate
        exceptions propagate unchanged.
        """
        token = self._token()
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        response = await self.http_client.get(
            GHSA_ADVISORIES_URL,
            params={"cve_id": cve_id, "type": "reviewed", "is_withdrawn": "false"},
            headers=_headers(token),
        )
        if response.status_code == 401:
            _raise_chained(response, AUTHENTICATION_FAILED)
        if response.status_code != 200:
            response.raise_for_status()
            raise GhsaResponseError()
        document = response.json()
        if not isinstance(document, list):
            raise GhsaResponseError()
        if not document:
            raise CVENotInSource()
        advisory = document[0]
        if not isinstance(advisory, dict):
            raise GhsaResponseError()
        if ghsa_advisory_record.element_cve_id(advisory) != cve_id:
            raise CVENotInSource()
        return await self._ingest(session, cve_id, advisory)

    async def execute(self, session: AsyncSession) -> None:
        """Periodic batch over the advisories modified since the cursor."""
        token = self._token()
        now = datetime.now(UTC)
        last_sync = await fetcher_execution.get_derived_cursor(session, self.name)
        # End the read transaction before any GitHub request.
        await session.rollback()
        if last_sync is None:
            return  # First run: this run's started_at becomes the cursor.
        window_start = last_sync - _OVERLAP
        if now - window_start > _STALE_AFTER:
            logger.warning(
                GHSA_CURSOR_RESET_EVENT,
                fetcher_name=self.name,
                age_days=(now - window_start).days,
            )
            return

        request_delay = (
            self.config.request_delay
            if self.config is not None
            else self.default_request_delay
        )
        url: str | None = GHSA_ADVISORIES_URL
        params: dict[str, str] | None = {
            "type": "reviewed",
            "is_withdrawn": "false",
            "modified": f">={window_start.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "sort": "updated",
            "direction": "asc",
            "per_page": "100",
        }
        first_page = True
        while url is not None:
            if not first_page:
                await asyncio.sleep(request_delay)
            first_page = False
            response = await self._get_page(url, params, token)
            params = None  # A next URL already carries every query parameter.
            for element in _page_elements(response):
                await self._process_advisory(session, element)
            url = _next_page_url(response)

    def _token(self) -> str:
        """The configured `GITHUB_TOKEN` (Algorithm step 1)."""
        token = settings.github_token.get_secret_value()
        if not token:
            raise FetcherError(TOKEN_NOT_CONFIGURED)
        return token

    async def _get_page(
        self, url: str, params: dict[str, str] | None, token: str
    ) -> httpx.Response:
        """One page request (Algorithm steps 6.a-b); no database work."""
        try:
            response = await self.http_client.get(
                url, params=params, headers=_headers(token)
            )
        except httpx.DecodingError as e:
            # An undecodable content encoding is a response, not a transport
            # failure.
            raise FetcherError(UNPARSEABLE_RESPONSE) from e
        except httpx.TransportError as e:
            raise FetcherError(CONNECTION_FAILED) from e
        if response.status_code == 401:
            _raise_chained(response, AUTHENTICATION_FAILED)
        if response.status_code in _RATE_LIMIT_STATUSES:
            _raise_chained(response, RATE_LIMITED)
        if response.status_code != 200:
            _raise_chained(
                response,
                f"GitHub Advisory API returned HTTP {response.status_code}",
            )
        return response

    async def _process_advisory(self, session: AsyncSession, element: object) -> None:
        """Algorithm step 6.d for one page element, in its own transaction."""
        raw_cve_id = ghsa_advisory_record.element_cve_id(element)
        if isinstance(element, dict) and raw_cve_id is None:
            return  # Step 6.d.i: no CVE-ID yet — silent skip, no metric.
        if not (
            isinstance(element, dict)
            and isinstance(raw_cve_id, str)
            and self._is_valid_cve_id(raw_cve_id)
        ):
            # Step 6.d.ii: invalid input before database work, no rollback.
            self._advisory_failed(None, InvalidCveIdError.__name__)
            return
        cve_id = raw_cve_id
        try:
            result = await self._ingest(session, cve_id, element)
            await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await session.rollback()
            await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
            self._advisory_failed(cve_id, type(e).__name__)
        else:
            # Keep finalization outside the pre-commit per-item catch.
            await self.commit_and_dispatch(session, result)

    async def _ingest(
        self, session: AsyncSession, cve_id: str, element: dict[str, object]
    ) -> CVEFetchResult:
        """Steps 6.d.iii-v up to the finalization token; never commits and
        records no metric."""
        advisory = ghsa_advisory_record.parse_advisory(element)
        extraction = ghsa_advisory_record.extract(advisory)
        for _ in range(extraction.skipped_cwes):
            logger.warning(
                CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                cve_id=cve_id,
                fetcher_name=self.name,
                reason=INVALID_CWE_REASON,
            )
        for _ in range(extraction.unrecognized_ranges):
            logger.warning(
                GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
                cve_id=cve_id,
                fetcher_name=self.name,
            )
        result = await cve_service.upsert_cve(
            session, cve_id, self.cve_source_type, extraction.payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            self.name,
            extraction.source_reference,
            extraction.upstream_references,
        )
        return CVEFetchResult(
            result.action,
            cve_service.build_post_ingest_tasks(result, extraction.payload),
        )

    def _advisory_failed(self, cve_id: str | None, cause: str) -> None:
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


def _headers(token: str) -> dict[str, str]:
    """The request headers; the token is attached per request only."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def _raise_chained(response: httpx.Response, message: str) -> None:
    """Raise `FetcherError(message)` chained from the response's
    `httpx.HTTPStatusError` when it has one. Its text carries the status
    line, the request URL (no token), and for a 3xx the `Location` value;
    never advisory content."""
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise FetcherError(message) from e
    raise FetcherError(message)


def _page_elements(response: httpx.Response) -> list[object]:
    """Algorithm step 6.c: the advisory array of one page."""
    try:
        document = response.json()
    except (ValueError, RecursionError) as e:
        raise FetcherError(UNPARSEABLE_RESPONSE) from e
    if not isinstance(document, list):
        raise FetcherError(UNPARSEABLE_RESPONSE)
    return document


def _next_page_url(response: httpx.Response) -> str | None:
    """Algorithm step 6.e: the `Link` `rel="next"` URL after the fail-closed
    next-URL check, or `None` when pagination is complete."""
    url = response.links.get("next", {}).get("url")
    if url is None:
        return None
    if not _is_trusted_next_url(url):
        raise FetcherError(UNTRUSTED_NEXT_URL)
    return url


def _is_trusted_next_url(url: str) -> bool:
    """HTTPS, exact host `api.github.com` with no user information or
    explicit port, exact path `/advisories`, any query, no fragment.

    Whitespace and control characters are rejected before parsing, so the
    checked and the requested URL cannot differ.
    """
    if any(character.isspace() or not character.isprintable() for character in url):
        return False
    if "#" in url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return (
        parts.scheme == _NEXT_URL_SCHEME
        and parts.netloc == _NEXT_URL_NETLOC
        and parts.path == _NEXT_URL_PATH
    )
