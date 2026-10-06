"""`sync_redhat_cves`: Red Hat Security Data CVE enrichment fetcher.

Implements docs/features/tickets/cve-sync-redhat.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- `fetch_single()` requests one CVE from the Red Hat Security Data API,
  validates and extracts the consumed fields (`redhat_cve_record`), and
  ingests the observed CVSS vectors, CWE, and package-name candidates
  through `cve_service.upsert_cve()`, then the source, `references[]`, and
  Bugzilla links through `reference_service.upsert_references()`, in the
  caller's transaction. HTTP 404, or a record with no value passing its
  own gate, raises `CVENotInSource` before any database work. Every other
  HTTP status and transport, decoding, and schema failure propagates as
  its original exception, so `is_infrastructure_failure()` and
  `is_retryable_condition()` keep classifying it.
- `execute()` follows template 1 of Session Lifecycle for API-based CVE
  Fetchers over one active-Ticket scope snapshot, with the consecutive
  infrastructure-failure abort.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

`cve_service` and `reference_service` are imported as module objects and
dereferenced at call time: `cve_service` belongs to the import cycle of
`base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
from asyncio import CancelledError
from typing import ClassVar, Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import (
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import CVEIngestPayload, CVSSAssessmentEntry, CWEEntry
from app.services.http_client import is_infrastructure_failure
from app.services.tickets import redhat_cve_record
from app.services.tickets.redhat_cve_record import RedhatExtraction

logger = structlog.get_logger(__name__)

REDHAT_CVE_URL: Final = (
    "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
)
"""The per-CVE endpoint of the Red Hat Security Data API (Algorithm step 1)."""

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (cve-fetcher-infrastructure.md, Batch Error
Handling): canonical CVE-ID, fetcher name, and exception class name only."""

CVE_FETCH_CANDIDATE_SKIPPED_EVENT: Final = "cve_fetch_candidate_skipped"
"""The WARNING of one rejected vector or CWE (§ Response Validation,
Candidate skip event): canonical CVE-ID, fetcher name, and closed reason."""

SOURCE_REFERENCE_TITLE: Final = "Red Hat"

_ABORT_THRESHOLD: Final = 3
"""Consecutive infrastructure failures that abort a periodic run."""


class RedhatResponseError(Exception):
    """An HTTP 2xx status other than 200: neither a record nor an HTTP
    error. Non-retryable; the fixed message carries no upstream data."""

    def __init__(self) -> None:
        super().__init__("Red Hat Security Data API returned an unexpected status")


class SyncRedhatCves(BaseCVEFetcher):
    """Sync CVE enrichment data from the Red Hat Security Data API."""

    name = "sync_redhat_cves"
    cve_source_type = CVESourceType.REDHAT
    description = "Sync CVE data from Red Hat Security API"
    default_schedule = "0 3 * * *"
    default_request_delay = 2.0

    source_reference_url_pattern: ClassVar[str] = (
        "https://access.redhat.com/security/cve/{cve_id}"
    )

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest one CVE from the Red Hat Security Data API.

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any HTTP
        request.

        Q3: one `GET` without redirects. HTTP 200 is validated and
        extracted; each rejected vector or CWE logs one
        `cve_fetch_candidate_skipped` WARNING. The payload carries only the
        non-empty `cvss_assessments`, `cwe_classifications`, and
        `resolved_packages` and is built before any write; then
        `upsert_cve()` and `upsert_references()` (source reference first,
        then `references[]` lines, then Bugzilla) run in `session`. Adds no
        flush beyond its delegates' own, never commits, and records no
        metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        the optional package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: HTTP 404, or HTTP 200 with no extractable data, raises
        `CVENotInSource` before any database work. Any other non-200
        status raises its original `httpx.HTTPStatusError`
        (`RedhatResponseError` for another 2xx); transport, JSON decoding,
        `pydantic.ValidationError` (schema mismatch, or a payload value
        containing U+0000), and delegate exceptions propagate unchanged.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        extraction = await self._fetch_extraction(cve_id)
        for reason in extraction.skipped:
            logger.warning(
                CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                cve_id=cve_id,
                fetcher_name=self.name,
                reason=reason,
            )
        if not extraction.has_extractable_data:
            raise CVENotInSource()

        payload = _ingest_payload(extraction)
        upstream = _upstream_references(extraction)
        result = await cve_service.upsert_cve(
            session, cve_id, self.cve_source_type, payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            self.name,
            reference_service.AutomaticReferenceInput(
                url=self.source_reference_url_pattern.format(cve_id=cve_id),
                title=SOURCE_REFERENCE_TITLE,
                explicit_type=ReferenceType.ADVISORY,
            ),
            upstream,
        )
        return CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, payload)
        )

    async def _fetch_extraction(self, cve_id: str) -> RedhatExtraction:
        """Request one record and extract it; no database work."""
        response = await self.http_client.get(REDHAT_CVE_URL.format(cve_id=cve_id))
        if response.status_code == 404:
            raise CVENotInSource()
        if response.status_code != 200:
            response.raise_for_status()
            raise RedhatResponseError()
        record = redhat_cve_record.parse_response(response.json())
        return redhat_cve_record.extract(record)

    async def execute(self, session: AsyncSession) -> None:
        """Periodic batch over the CVEs of active Tickets.

        Scope snapshot: the in-scope CVE-ID set is queried once at the
        start of execute(). New tickets created mid-run are covered by
        the default catch_up() mechanism and on-demand fetch_single().
        """
        request_delay = self.config.request_delay if self.config is not None else 0.0
        cve_ids = await self._get_active_ticket_cve_ids(session)
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
            await asyncio.sleep(request_delay)

    async def _get_active_ticket_cve_ids(self, session: AsyncSession) -> list[str]:
        """The run's scope snapshot (cve-service.md, Active-Ticket CVE Scope)."""
        return await cve_service.get_active_ticket_cve_ids(session)


def _ingest_payload(extraction: RedhatExtraction) -> CVEIngestPayload:
    """The enrichment payload: only the non-empty observed child fields
    are set; every other field is omitted (§ Field Mapping)."""
    fields: dict[str, object] = {}
    if extraction.cvss_vectors:
        fields["cvss_assessments"] = [
            CVSSAssessmentEntry(
                provider_name=redhat_cve_record.PROVIDER_NAME, vector_string=vector
            )
            for vector in extraction.cvss_vectors
        ]
    if extraction.cwe_id is not None:
        fields["cwe_classifications"] = [
            CWEEntry(cwe_id=extraction.cwe_id, source=redhat_cve_record.PROVIDER_NAME)
        ]
    if extraction.package_names:
        fields["resolved_packages"] = list(extraction.package_names)
    return CVEIngestPayload.model_validate(fields)


def _upstream_references(
    extraction: RedhatExtraction,
) -> list[reference_service.AutomaticReferenceInput]:
    """`references[]` lines in order, then the Bugzilla link last."""
    upstream = [
        reference_service.AutomaticReferenceInput(url=url)
        for url in extraction.reference_urls
    ]
    if extraction.bugzilla is not None:
        upstream.append(
            reference_service.AutomaticReferenceInput(
                url=extraction.bugzilla.url,
                title=extraction.bugzilla.title,
                explicit_type=ReferenceType.ISSUE,
            )
        )
    return upstream
