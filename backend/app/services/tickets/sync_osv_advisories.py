"""`sync_osv_advisories`: OSV (osv.dev) CVE enrichment fetcher.

Implements docs/features/tickets/cve-sync-osv.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- `fetch_single()` performs the three phases of the Algorithm: the CVE
  record (Phase 1), each alias record (Phase 2), and each related record
  (Phase 3), throttled between consecutive requests (step 16). All HTTP
  completes before any database work. HTTP 404, or a Phase 1 record with
  no extractable data, raises `CVENotInSource`. Every other Phase 1 HTTP
  status and transport, decoding, and schema failure propagates as its
  original exception, so `is_infrastructure_failure()` and
  `is_retryable_condition()` keep classifying it. An alias or related
  sub-request never fails the CVE: it succeeds, is an authoritative HTTP
  404 skip, or is a failed sub-request logged with one bounded
  `osv_subrequest_skipped` WARNING (steps 7, 10, and 11). When every listed
  sub-request failed, the completeness guard raises `CompletenessGuardError`
  before any write. The `osv` affected-version scope is replaced only when
  every alias was completely observed (step 13). The payload is then
  ingested through `cve_service.upsert_cve()` and the source, Phase 1,
  alias, and related references through
  `reference_service.upsert_references()`, in the caller's transaction.
- `execute()` follows template 1 of Session Lifecycle for API-based CVE
  Fetchers over one active-Ticket scope snapshot, with the consecutive
  infrastructure-failure abort.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

`cve_service`, `reference_service`, and `osv_vulnerability_record` are
imported as module objects and dereferenced at call time: `cve_service`
belongs to the import cycle of `base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
import json
from asyncio import CancelledError
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar, Final, Literal

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import (
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    ExternalIdentifierEntry,
)
from app.services.http_client import is_infrastructure_failure
from app.services.tickets import osv_vulnerability_record
from app.services.tickets.osv_vulnerability_record import (
    OsvAliasRecord,
    OsvCveRecord,
    OsvRelatedRecord,
)

logger = structlog.get_logger(__name__)

OSV_VULN_URL: Final = "https://api.osv.dev/v1/vulns/{record_id}"
"""The vulnerability-record endpoint of every phase (Algorithm steps 1, 5,
and 8); `record_id` is the CVE-ID or an ID that passed the step-5 check."""

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (cve-fetcher-infrastructure.md, Batch Error
Handling): canonical CVE-ID, fetcher name, and exception class name only."""

OSV_SUBREQUEST_SKIPPED_EVENT: Final = "osv_subrequest_skipped"
"""The sub-request skip WARNING (Algorithm step 7): CVE-ID, fetcher name,
record kind, the record ID only when safe, closed reason, and the HTTP
status when one was received."""

SOURCE_REFERENCE_TITLE: Final = "OSV"

SOURCE_CONTAINER: Final = "osv"
"""The stable `source_container` of the OSV affected-version scope."""

_ABORT_THRESHOLD: Final = 3
"""Consecutive infrastructure failures that abort a periodic run."""

type RecordKind = Literal["alias", "related"]
type SkipReason = Literal[
    "not_found", "unsafe_id", "http_status", "transport", "invalid_body"
]


class OsvResponseError(Exception):
    """A Phase 1 HTTP 2xx status other than 200: neither a record nor an
    HTTP error. Non-retryable; the fixed message carries no upstream
    data."""

    def __init__(self) -> None:
        super().__init__("OSV API returned an unexpected status")


class CompletenessGuardError(Exception):
    """The per-CVE completeness guard (Algorithm step 11): every listed
    alias and related sub-request failed, so OSV enrichment cannot be
    reliably obtained for this CVE in this run.

    A per-CVE condition, not a whole-run failure: it derives from
    `Exception` directly, not from `FetcherError`, and is non-retryable.
    The fixed message carries no upstream data.
    """

    def __init__(self) -> None:
        super().__init__("Every OSV alias and related sub-request failed")


@dataclass(frozen=True, slots=True)
class _SubRequest[RecordT]:
    """The outcome of one alias or related sub-request (Algorithm step 11).

    `record` is set only when the sub-request succeeded; `not_found` marks
    the authoritative HTTP 404 skip; neither marks a failed sub-request.
    """

    record_id: str
    record: RecordT | None = None
    not_found: bool = False

    @property
    def observed(self) -> bool:
        """Succeeded or authoritatively skipped: a complete observation."""
        return self.record is not None or self.not_found


@dataclass(frozen=True, slots=True)
class _Observation:
    """Everything one `fetch_single()` call observed before any write."""

    record: OsvCveRecord
    aliases: list[_SubRequest[OsvAliasRecord]]
    related: list[_SubRequest[OsvRelatedRecord]]


class _ThrottledRequests:
    """The HTTP requests of one `fetch_single()` call (Algorithm step 16):
    the delay separates every two consecutive requests; none precedes the
    first."""

    def __init__(self, client: httpx.AsyncClient, delay: float) -> None:
        self._client = client
        self._delay = delay
        self._requested = False

    async def get(self, record_id: str) -> httpx.Response:
        if self._requested:
            await asyncio.sleep(self._delay)
        self._requested = True
        return await self._client.get(OSV_VULN_URL.format(record_id=record_id))


class SyncOsvAdvisories(BaseCVEFetcher):
    """Sync CVE enrichment data from the OSV REST API."""

    name = "sync_osv_advisories"
    cve_source_type = CVESourceType.OSV
    description = "Sync CVE enrichment data from OSV (osv.dev)"
    default_schedule = "0 5 * * *"
    default_request_delay = 0.2
    default_run_timeout = 14400

    source_reference_url_pattern: ClassVar[str] = (
        "https://osv.dev/vulnerability/{cve_id}"
    )

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest one CVE from the OSV REST API (three phases).

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any HTTP
        request.

        Q3: `GET /v1/vulns/{cve_id}` (Phase 1), then one `GET` per alias ID
        (Phase 2) and per related ID (Phase 3) in declared order, without
        redirects. An ID failing the step-5 check is not requested. The
        delay (the run's `request_delay`, otherwise the class
        `default_request_delay`) separates consecutive requests. Each
        sub-request that does not succeed logs one `osv_subrequest_skipped`
        WARNING. The payload carries the `osv` replacement only when every
        alias was completely observed, and the non-empty
        `external_identifiers` and `resolved_packages`; it omits every
        global field and is built before any write. Then `upsert_cve()` and
        `upsert_references()` (source reference first, then the Phase 1,
        alias, and related references) run in `session`. Adds no flush
        beyond its delegates' own, never commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        the optional package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: Phase 1 HTTP 404, or HTTP 200 with no extractable data, raises
        `CVENotInSource` before any database work. Any other Phase 1
        non-200 status raises its original `httpx.HTTPStatusError`
        (`OsvResponseError` for another 2xx); transport, JSON decoding,
        `pydantic.ValidationError` (schema mismatch, or a payload value that
        contains U+0000, is over-length, or conflicts with a same-key
        value), and delegate exceptions propagate unchanged. When at least
        one alias or related ID is listed and every sub-request failed,
        raises `CompletenessGuardError` before any database work.
        Sub-request failures never leave this method; cancellation,
        `SoftTimeLimitExceeded`, and `MemoryError` are never absorbed.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        observation = await self._observe(cve_id)

        payload = _ingest_payload(cve_id, observation)
        upstream = _upstream_references(observation)
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

    async def _observe(self, cve_id: str) -> _Observation:
        """Phases 1-3 and the completeness guard; no database work."""
        requests = _ThrottledRequests(self.http_client, self._request_delay())
        response = await requests.get(cve_id)
        if response.status_code == 404:
            raise CVENotInSource()
        if response.status_code != 200:
            response.raise_for_status()
            raise OsvResponseError()
        record = osv_vulnerability_record.parse_cve_record(response.json())
        if not osv_vulnerability_record.has_extractable_data(record):
            raise CVENotInSource()

        aliases = [
            await self._sub_request(
                requests,
                cve_id,
                "alias",
                record_id,
                osv_vulnerability_record.parse_alias_record,
            )
            for record_id in record.aliases or ()
        ]
        related = [
            await self._sub_request(
                requests,
                cve_id,
                "related",
                record_id,
                osv_vulnerability_record.parse_related_record,
            )
            for record_id in record.related or ()
        ]
        outcomes = [*aliases, *related]
        if outcomes and not any(outcome.observed for outcome in outcomes):
            raise CompletenessGuardError()
        return _Observation(record, aliases, related)

    async def _sub_request[RecordT](
        self,
        requests: _ThrottledRequests,
        cve_id: str,
        record_kind: RecordKind,
        record_id: str,
        parse: Callable[[object], RecordT],
    ) -> _SubRequest[RecordT]:
        """One alias or related sub-request (Algorithm steps 5-10).

        Absorbs only the documented failed-sub-request kinds: an unsafe ID,
        an `httpx.HTTPError`, a non-200 status, and an undecodable or
        invalid HTTP 200 body.
        """
        if not osv_vulnerability_record.is_safe_record_id(record_id):
            self._log_skip(cve_id, record_kind, None, "unsafe_id", None)
            return _SubRequest(record_id)
        try:
            response = await requests.get(record_id)
        except httpx.HTTPError:
            self._log_skip(cve_id, record_kind, record_id, "transport", None)
            return _SubRequest(record_id)
        if response.status_code == 404:
            self._log_skip(cve_id, record_kind, record_id, "not_found", 404)
            return _SubRequest(record_id, not_found=True)
        if response.status_code != 200:
            self._log_skip(
                cve_id, record_kind, record_id, "http_status", response.status_code
            )
            return _SubRequest(record_id)
        try:
            record = parse(response.json())
        except json.JSONDecodeError, UnicodeDecodeError, ValidationError:
            self._log_skip(cve_id, record_kind, record_id, "invalid_body", 200)
            return _SubRequest(record_id)
        return _SubRequest(record_id, record)

    def _log_skip(
        self,
        cve_id: str,
        record_kind: RecordKind,
        record_id: str | None,
        reason: SkipReason,
        status_code: int | None,
    ) -> None:
        """The sub-request skip WARNING; `record_id` and `status_code` are
        omitted when `None` (an unsafe ID, no HTTP response)."""
        fields: dict[str, object] = {
            "cve_id": cve_id,
            "fetcher_name": self.name,
            "record_kind": record_kind,
        }
        if record_id is not None:
            fields["record_id"] = record_id
        fields["reason"] = reason
        if status_code is not None:
            fields["status_code"] = status_code
        logger.warning(OSV_SUBREQUEST_SKIPPED_EVENT, **fields)

    def _request_delay(self) -> float:
        """The run's `request_delay`, or the class default outside a run
        (Algorithm step 16)."""
        if self.config is not None:
            return self.config.request_delay
        return self.default_request_delay

    async def execute(self, session: AsyncSession) -> None:
        """Periodic batch over the CVEs of active Tickets.

        Scope snapshot: the in-scope CVE-ID set is queried once at the
        start of execute(). New tickets created mid-run are covered by
        the default catch_up() mechanism and on-demand fetch_single().
        """
        request_delay = self._request_delay()
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


def _ingest_payload(cve_id: str, observation: _Observation) -> CVEIngestPayload:
    """The enrichment payload (Algorithm steps 13 and 14).

    The `osv` replacement (Phase 1 `GIT` entries, then each succeeded
    alias's entries in alias order) is emitted only when every alias was
    completely observed; otherwise the scope is unobserved and omitted.
    `external_identifiers` and `resolved_packages` are set only when
    non-empty; every other field is omitted.
    """
    aliases = [
        (outcome.record_id, outcome.record)
        for outcome in observation.aliases
        if outcome.record is not None
    ]
    related = [
        outcome.record for outcome in observation.related if outcome.record is not None
    ]
    fields: dict[str, object] = {}
    if all(outcome.observed for outcome in observation.aliases):
        entries: list[AffectedVersionEntry] = osv_vulnerability_record.git_entries(
            observation.record
        )
        for _, alias in aliases:
            entries.extend(osv_vulnerability_record.alias_entries(alias))
        fields["affected_version_operations"] = [
            AffectedVersionScopeOperation(
                source_container=SOURCE_CONTAINER,
                operation=AffectedVersionOperation.REPLACE,
                entries=entries,
            )
        ]
    identifiers: list[ExternalIdentifierEntry] = []
    for record_id, alias in aliases:
        identifier = osv_vulnerability_record.external_identifier(
            record_id, alias, cve_id
        )
        if identifier is not None:
            identifiers.append(identifier)
    if identifiers:
        fields["external_identifiers"] = identifiers
    names: dict[str, None] = {}
    package_records: list[OsvAliasRecord | OsvRelatedRecord] = [
        alias for _, alias in aliases
    ]
    package_records.extend(related)
    for record in package_records:
        for name in osv_vulnerability_record.package_names(record):
            names.setdefault(name, None)
    if names:
        fields["resolved_packages"] = list(names)
    return CVEIngestPayload.model_validate(fields)


def _upstream_references(
    observation: _Observation,
) -> list[reference_service.AutomaticReferenceInput]:
    """Phase 1 references, then each succeeded alias's, then each succeeded
    related record's, in declared order (Algorithm step 15)."""
    records: list[OsvCveRecord | OsvAliasRecord | OsvRelatedRecord] = [
        observation.record
    ]
    records.extend(
        outcome.record for outcome in observation.aliases if outcome.record is not None
    )
    records.extend(
        outcome.record for outcome in observation.related if outcome.record is not None
    )
    return [
        candidate
        for record in records
        for candidate in osv_vulnerability_record.reference_candidates(record)
    ]
