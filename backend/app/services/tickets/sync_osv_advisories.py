"""`sync_osv_advisories`: OSV (osv.dev) CVE enrichment fetcher.

Implements docs/features/tickets/cve-sync-osv.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- `fetch_single()` performs the two phases of the Algorithm: the CVE
  record (Phase 1) and each non-CVE alias record (Phase 2), throttled
  between consecutive requests (step 13). `related` is not consumed. All
  HTTP completes before any database work. HTTP 404, or a Phase 1 record
  with no extractable data, raises `CVENotInSource`. Every other Phase 1
  HTTP status and transport, decoding, and schema failure propagates as its
  original exception, so `is_infrastructure_failure()` and
  `is_retryable_condition()` keep classifying it. A `CVE-*` alias is
  skipped silently and is not a sub-request (step 5). An alias sub-request
  never fails the CVE: it succeeds, is an authoritative HTTP 404 skip, or
  is a failed sub-request logged with one bounded `osv_subrequest_skipped`
  WARNING (steps 7 and 8). When every alias sub-request failed, the
  completeness guard raises `CompletenessGuardError` before any write. Only
  a succeeded alias record that applies to the processed CVE contributes
  data (step 6). The `osv` affected-version scope is replaced only when
  every alias sub-request was completely observed (step 10). The payload is
  then ingested through `cve_service.upsert_cve()` and the source, Phase 1,
  and applicable alias references through
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
    CVE_FETCH_ITEM_FAILED_EVENT,
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
)

logger = structlog.get_logger(__name__)

OSV_VULN_URL: Final = "https://api.osv.dev/v1/vulns/{record_id}"
"""The vulnerability-record endpoint of both phases (Algorithm steps 1 and
5); `record_id` is the CVE-ID or an alias ID that passed the step-5 check."""

OSV_SUBREQUEST_SKIPPED_EVENT: Final = "osv_subrequest_skipped"
"""The sub-request skip WARNING (Algorithm step 7): CVE-ID, fetcher name,
the record ID only when safe, closed reason, and the HTTP status when one
was received."""

SOURCE_REFERENCE_TITLE: Final = "OSV"

SOURCE_CONTAINER: Final = "osv"
"""The stable `source_container` of the OSV affected-version scope."""

_ABORT_THRESHOLD: Final = 3
"""Consecutive infrastructure failures that abort a periodic run."""

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
    """The per-CVE completeness guard (Algorithm step 8): every alias
    sub-request failed, so OSV enrichment cannot be reliably obtained for
    this CVE in this run.

    A per-CVE condition, not a whole-run failure: it derives from
    `Exception` directly, not from `FetcherError`, and is non-retryable.
    The fixed message carries no upstream data.
    """

    def __init__(self) -> None:
        super().__init__("Every OSV alias sub-request failed")


@dataclass(frozen=True, slots=True)
class _SubRequest:
    """The outcome of one alias sub-request (Algorithm step 8).

    `record` is set only when the sub-request succeeded, whether or not the
    record applies; `not_found` marks the authoritative HTTP 404 skip;
    neither marks a failed sub-request.
    """

    record_id: str
    record: OsvAliasRecord | None = None
    not_found: bool = False

    @property
    def observed(self) -> bool:
        """Succeeded or authoritatively skipped: a complete observation."""
        return self.record is not None or self.not_found


@dataclass(frozen=True, slots=True)
class _Observation:
    """Everything one `fetch_single()` call observed before any write."""

    cve_id: str
    record: OsvCveRecord
    aliases: list[_SubRequest]

    @property
    def complete(self) -> bool:
        """Every alias sub-request was completely observed (step 10)."""
        return all(outcome.observed for outcome in self.aliases)

    def applicable_aliases(self) -> list[tuple[str, OsvAliasRecord]]:
        """The succeeded alias records that apply to the processed CVE
        (step 6), with their requested IDs, in declared order."""
        return [
            (outcome.record_id, outcome.record)
            for outcome in self.aliases
            if outcome.record is not None
            and osv_vulnerability_record.applies_to(outcome.record, self.cve_id)
        ]


class _ThrottledRequests:
    """The HTTP requests of one `fetch_single()` call (Algorithm step 13):
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

    source_reference_url_pattern: ClassVar[str] = (
        "https://osv.dev/vulnerability/{cve_id}"
    )

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch and ingest one CVE from the OSV REST API (two phases).

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID to fetch; `session` is the caller's
        per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any HTTP
        request.

        Q3: `GET /v1/vulns/{cve_id}` (Phase 1), then one `GET` per alias ID
        (Phase 2) in declared order, without redirects. A `CVE-*` alias is
        skipped silently and is not a sub-request; another ID failing the
        step-5 check is not requested. The delay (the run's
        `request_delay`, otherwise the class `default_request_delay`)
        separates consecutive requests. Each sub-request that does not
        succeed logs one `osv_subrequest_skipped` WARNING. Only succeeded
        alias records that apply to `cve_id` contribute data. The payload
        carries the `osv` replacement only when every alias sub-request was
        completely observed, and the non-empty `external_identifiers` and
        `resolved_packages`; it omits every global field and is built before
        any write. Then `upsert_cve()` and `upsert_references()` (source
        reference first, then the Phase 1 and applicable alias references)
        run in `session`. Adds no flush beyond its delegates' own, never
        commits, and records no metric.

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
        one alias sub-request is listed and every one failed, raises
        `CompletenessGuardError` before any database work.
        Sub-request failures never leave this method; cancellation,
        `SoftTimeLimitExceeded`, and `MemoryError` are never absorbed.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        observation = await self._observe(cve_id)

        payload = _ingest_payload(observation)
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
        """Phases 1 and 2 and the completeness guard; no database work."""
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
            await self._sub_request(requests, cve_id, record_id)
            for record_id in record.aliases or ()
            if not osv_vulnerability_record.is_cve_alias(record_id)
        ]
        if aliases and not any(outcome.observed for outcome in aliases):
            raise CompletenessGuardError()
        return _Observation(cve_id, record, aliases)

    async def _sub_request(
        self, requests: _ThrottledRequests, cve_id: str, record_id: str
    ) -> _SubRequest:
        """One alias sub-request (Algorithm steps 5, 7, and 8).

        Absorbs only the documented failed-sub-request kinds: an unsafe ID,
        an `httpx.HTTPError`, a non-200 status, and an undecodable or
        invalid HTTP 200 body.
        """
        if not osv_vulnerability_record.is_safe_record_id(record_id):
            self._log_skip(cve_id, None, "unsafe_id", None)
            return _SubRequest(record_id)
        try:
            response = await requests.get(record_id)
        except httpx.HTTPError:
            self._log_skip(cve_id, record_id, "transport", None)
            return _SubRequest(record_id)
        if response.status_code == 404:
            self._log_skip(cve_id, record_id, "not_found", 404)
            return _SubRequest(record_id, not_found=True)
        if response.status_code != 200:
            self._log_skip(cve_id, record_id, "http_status", response.status_code)
            return _SubRequest(record_id)
        try:
            record = osv_vulnerability_record.parse_alias_record(response.json())
        except json.JSONDecodeError, UnicodeDecodeError, ValidationError:
            self._log_skip(cve_id, record_id, "invalid_body", 200)
            return _SubRequest(record_id)
        return _SubRequest(record_id, record)

    def _log_skip(
        self,
        cve_id: str,
        record_id: str | None,
        reason: SkipReason,
        status_code: int | None,
    ) -> None:
        """The sub-request skip WARNING; `record_id` and `status_code` are
        omitted when `None` (an unsafe ID, no HTTP response)."""
        fields: dict[str, object] = {"cve_id": cve_id, "fetcher_name": self.name}
        if record_id is not None:
            fields["record_id"] = record_id
        fields["reason"] = reason
        if status_code is not None:
            fields["status_code"] = status_code
        logger.warning(OSV_SUBREQUEST_SKIPPED_EVENT, **fields)

    def _request_delay(self) -> float:
        """The run's `request_delay`, or the class default outside a run
        (Algorithm step 13)."""
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


def _ingest_payload(observation: _Observation) -> CVEIngestPayload:
    """The enrichment payload (Algorithm steps 6, 10, and 11).

    The `osv` replacement (Phase 1 `GIT` entries, then each applicable
    alias's entries in alias order) is emitted only when every alias
    sub-request was completely observed; otherwise the scope is unobserved
    and omitted. `external_identifiers` and `resolved_packages` come from
    the applicable aliases and are set only when non-empty; every other
    field is omitted.
    """
    aliases = observation.applicable_aliases()
    fields: dict[str, object] = {}
    if observation.complete:
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
            record_id, alias, observation.cve_id
        )
        if identifier is not None:
            identifiers.append(identifier)
    if identifiers:
        fields["external_identifiers"] = identifiers
    names: dict[str, None] = {}
    for _, alias in aliases:
        for name in osv_vulnerability_record.package_names(alias):
            names.setdefault(name, None)
    if names:
        fields["resolved_packages"] = list(names)
    return CVEIngestPayload.model_validate(fields)


def _upstream_references(
    observation: _Observation,
) -> list[reference_service.AutomaticReferenceInput]:
    """Phase 1 references, then each applicable alias's, in declared order
    (Algorithm step 12)."""
    records: list[OsvCveRecord | OsvAliasRecord] = [observation.record]
    records.extend(alias for _, alias in observation.applicable_aliases())
    return [
        candidate
        for record in records
        for candidate in osv_vulnerability_record.reference_candidates(record)
    ]
