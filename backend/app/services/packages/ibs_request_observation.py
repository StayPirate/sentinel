"""Lock-free discovery and classification of one IBS request scope.

Implements docs/features/packages/ibs-submission-tracking.md (Required
Roots, Request Discovery and Detail, Action-Scoped CVE Evidence, Effective
SR, Release Discovery, Accepted RR Provenance, Observation Outcomes,
Delivery Derivation; Shared Authoritative Reconciliation > Algorithm steps
2-3) for `app.services.packages.ibs_request_reconciliation`, which reads
the step-1 snapshot before any IBS request and applies the outcome under
the Ticket lock. Nothing here touches the database.

- `EvidenceCache` performs the IBS requests of one invocation: each
  artifact is obtained at most once per identity (searches per logical
  package, current release evidence and source histories per package,
  request detail per request number, exact lookups per package and
  revision, action diffs per action) and reused by every scope; an
  incomplete or failed artifact stays incomplete or failed for every scope
  that needs it. The caller's request delay separates every two
  consecutive IBS requests of the invocation; none precedes the first.
- `observe_scope()` exhausts the required roots of one scope, applying the
  release proof first, and returns the complete `Observation`: the derived
  delivery value and the request, action, and correlation writes. An
  incomplete or failed observation raises `UnusableObservation` with one
  bounded `reason_category`.

Failures of the known IBS request kinds (credentials not configured,
authentication, transport, HTTP status) are failed observations; every
other exception, including `SoftTimeLimitExceeded`, `MemoryError`, and
cancellation, propagates. No log carries upstream text or a project outside
the `SUSE:` namespace.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, NoReturn

import httpx
import structlog

from app.core.enums import DeliveryStatus, IBSRequestActionType, IBSRequestState
from app.core.identifiers import is_valid_cve_id
from app.services.ibs_client import (
    DiffIssue,
    IBSAuthenticationError,
    IBSClient,
    IBSCredentialsNotConfiguredError,
    IBSRequestActionDetail,
    IBSRequestDetail,
    IBSResponseDataError,
    RequestActionDiff,
    RequestActionIssue,
    RequestEvidenceResult,
    RequestIdSearchResult,
    SourceHistory,
)
from app.services.packages.ibs_request_identity import (
    ActionKey,
    ActionMatch,
    action_identity,
    action_key,
    classify_action,
    detail_action_key,
    is_valid_scope_identity,
)

logger = structlog.get_logger(__name__)

ISSUE_IGNORED_EVENT: Final = "ibs_request_issue_ignored"
INVALID_CVE_LABEL_CATEGORY: Final = "invalid_cve_label"

SUSE_NAMESPACE: Final = "SUSE:"
INTEGER_MAX: Final = 2_147_483_647
"""The largest value of a PostgreSQL `INTEGER` column."""
REVISION_MAX_LENGTH: Final = 255
"""The length of `IBSRequestAction.accepted_revision`."""

_EVIDENCE_STATES: Final = frozenset({"added", "changed"})
_OPEN_STATES: Final = frozenset({IBSRequestState.NEW, IBSRequestState.REVIEW})
_PROGRESSING_STATES: Final = frozenset(
    {IBSRequestState.NEW, IBSRequestState.REVIEW, IBSRequestState.ACCEPTED}
)
_EMPTY_SOURCE_TREE: Final = "0"


class UnusableObservation(Exception):  # noqa: N818 — an outcome, not an error
    """The scope's observation is incomplete or failed.

    Carries one bounded `reason_category`, the request number whose
    evidence caused it when there is one, the HTTP status of an
    `http_status` failure, and whether a required operation `failed`
    (rather than returning incomplete evidence). Never carries upstream
    content.
    """

    def __init__(
        self,
        reason_category: str,
        *,
        request_number: int | None = None,
        http_status: int | None = None,
        failed: bool = False,
    ) -> None:
        super().__init__(f"IBS request observation unusable: {reason_category}")
        self.reason_category = reason_category
        self.request_number = request_number
        self.http_status = http_status
        self.failed = failed


# ---------------------------------------------------------------------------
# Scope and step-1 snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IBSRequestScope:
    """One track scope: the semantic locator `(ticket_id, cve_id,
    package_id, package_name, track_id, codestream)` of Scope Identity.

    `cve_id` is the Ticket CVE (`None` for a CVE-less Ticket),
    `package_name` the logical package, and `codestream` the IBS track
    reference.
    """

    ticket_id: uuid.UUID
    cve_id: str | None
    package_id: uuid.UUID
    package_name: str
    track_id: uuid.UUID
    codestream: str


@dataclass(frozen=True, slots=True)
class RetainedRequest:
    """One retained `IBSRequest` row."""

    id: uuid.UUID
    request_number: int
    state: IBSRequestState
    superseded_by_request_number: int | None
    upstream_created_at: datetime
    upstream_updated_at: datetime
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RetainedAction:
    """One retained `IBSRequestAction` row with its parent request."""

    id: uuid.UUID
    request: RetainedRequest
    action_type: IBSRequestActionType
    source_project: str | None
    source_package: str | None
    target_project: str | None
    target_package: str | None
    target_release_project: str | None
    logical_package: str
    codestream_name: str
    incident_number: int | None
    accepted_revision: str | None
    accepted_srcmd5: str | None
    created_at: datetime
    updated_at: datetime

    @property
    def key(self) -> ActionKey:
        return action_key(
            self.request.request_number,
            self.action_type,
            source_project=self.source_project,
            source_package=self.source_package,
            target_project=self.target_project,
            target_package=self.target_package,
            target_release_project=self.target_release_project,
        )


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    """The step-1 read of one scope.

    `delivery_status` is the pre-I/O delivery baseline (`None` when the
    track did not exist); `correlated` the actions correlated to the track;
    `in_flight` the retained accepted submission actions of the scope's
    package and codestream that are not correlated to the track and whose
    incident has no retained accepted release action of that package and
    codestream; `fingerprint` the identities and row timestamps compared by
    the stale-negative guard.
    """

    delivery_status: DeliveryStatus | None
    correlated: tuple[RetainedAction, ...]
    in_flight: tuple[RetainedAction, ...]
    fingerprint: frozenset[tuple[object, ...]]


# ---------------------------------------------------------------------------
# Observation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestWrite:
    """The current parent state of one request, from its point detail."""

    request_number: int
    state: IBSRequestState
    superseded_by_request_number: int | None
    upstream_created_at: datetime
    upstream_updated_at: datetime


@dataclass(frozen=True, slots=True)
class ActionWrite:
    """One relevant action, in the stored form, to upsert and correlate to
    the scope's track."""

    key: ActionKey
    request_number: int
    action_type: IBSRequestActionType
    source_project: str
    source_package: str
    target_project: str | None
    target_package: str | None
    target_release_project: str | None
    logical_package: str
    codestream_name: str
    incident_number: int | None
    accepted_revision: str | None
    accepted_srcmd5: str | None


@dataclass(frozen=True, slots=True)
class Observation:
    """A complete observation: the strongest proven delivery value and the
    evidence writes, both ordered by request number and identity."""

    derived: DeliveryStatus
    requests: tuple[RequestWrite, ...]
    actions: tuple[ActionWrite, ...]


NO_MATCH: Final = Observation(DeliveryStatus.PENDING, (), ())
"""A complete no-match without evidence writes."""


def order(key: ActionKey) -> tuple[str, ...]:
    """A total order over semantic identities: request number first."""
    number = key[0]
    assert isinstance(number, int)
    return (f"{number:020d}", *("" if part is None else str(part) for part in key[1:]))


# ---------------------------------------------------------------------------
# Evidence cache
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Unusable:
    reason_category: str
    http_status: int | None = None
    failed: bool = False


def _raise(unusable: _Unusable, request_number: int | None) -> NoReturn:
    raise UnusableObservation(
        unusable.reason_category,
        request_number=request_number,
        http_status=unusable.http_status,
        failed=unusable.failed,
    )


def _evidence[T](result: RequestEvidenceResult[T]) -> T | _Unusable:
    if result.value is not None:
        return result.value
    assert result.incomplete_reason is not None
    return _Unusable(result.incomplete_reason)


def _cve_labels(
    issues: tuple[RequestActionIssue, ...] | list[DiffIssue],
) -> tuple[frozenset[str], bool]:
    """The qualifying CVE labels (`cve` tracker, `added` or `changed`, a
    canonical label) and whether a `cve` issue in those states had a
    missing or invalid label."""
    labels: set[str] = set()
    ignored = False
    for issue in issues:
        if issue.tracker != "cve" or issue.state not in _EVIDENCE_STATES:
            continue
        if issue.label is not None and is_valid_cve_id(issue.label):
            labels.add(issue.label)
        else:
            ignored = True
    return frozenset(labels), ignored


def _log_ignored(
    *, package_name: str, codestream: str | None, request_number: int | None
) -> None:
    fields: dict[str, object] = {"package_name": package_name}
    if codestream is not None and codestream.startswith(SUSE_NAMESPACE):
        fields["codestream"] = codestream
    if request_number is not None:
        fields["request_number"] = request_number
    logger.warning(
        ISSUE_IGNORED_EVENT, reason_category=INVALID_CVE_LABEL_CATEGORY, **fields
    )


class EvidenceCache:
    """The IBS evidence of one invocation, obtained at most once per
    identity through the caller's open client and spaced by
    `request_delay` seconds."""

    def __init__(self, client: IBSClient, *, request_delay: float = 0.0) -> None:
        self._client = client
        self._request_delay = request_delay
        self._requested = False
        self._searches: dict[
            tuple[IBSRequestActionType, str], RequestIdSearchResult | _Unusable
        ] = {}
        self._details: dict[int, IBSRequestDetail | _Unusable] = {}
        self._histories: dict[
            tuple[str, str, str | None], SourceHistory | _Unusable
        ] = {}
        self._diffs: dict[ActionKey, frozenset[str] | _Unusable] = {}
        self._release_evidence: dict[tuple[str, str], frozenset[str] | _Unusable] = {}

    async def _request[T](self, operation: Callable[[], Awaitable[T]]) -> T | _Unusable:
        """Run one IBS operation after the request delay; a known request
        failure becomes a failed `_Unusable`."""
        if self._requested and self._request_delay > 0:
            await asyncio.sleep(self._request_delay)
        self._requested = True
        try:
            return await operation()
        except IBSCredentialsNotConfiguredError:
            return _Unusable("credentials_not_configured", failed=True)
        except IBSAuthenticationError as exc:
            return _Unusable(exc.reason, failed=True)
        except IBSResponseDataError as exc:
            return _Unusable(exc.reason)
        except httpx.HTTPStatusError as exc:
            return _Unusable(
                "http_status", http_status=exc.response.status_code, failed=True
            )
        except httpx.HTTPError:
            return _Unusable("transport", failed=True)

    async def search(
        self, action_type: IBSRequestActionType, package_name: str
    ) -> RequestIdSearchResult:
        """The open-request ID search for `{package_name}.` (source prefix
        for submissions, target prefix for releases)."""
        key = (action_type, package_name)
        if key not in self._searches:
            prefix = f"{package_name}."
            if action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
                result = await self._request(
                    lambda: self._client.search_request_ids(
                        action_type, states=_OPEN_STATES, source_package_prefix=prefix
                    )
                )
            else:
                result = await self._request(
                    lambda: self._client.search_request_ids(
                        action_type, states=_OPEN_STATES, target_package_prefix=prefix
                    )
                )
            self._searches[key] = (
                result if isinstance(result, _Unusable) else _evidence(result)
            )
        value = self._searches[key]
        if isinstance(value, _Unusable):
            _raise(value, None)
        return value

    async def detail(self, request_number: int) -> IBSRequestDetail:
        """The current point detail of `request_number`."""
        if request_number not in self._details:
            result = await self._request(
                lambda: self._client.get_request(request_number)
            )
            self._details[request_number] = (
                result if isinstance(result, _Unusable) else _evidence(result)
            )
        value = self._details[request_number]
        if isinstance(value, _Unusable):
            _raise(value, request_number)
        return value

    async def history(
        self,
        project: str,
        package: str,
        *,
        revision: str | None = None,
        request_number: int | None = None,
    ) -> SourceHistory:
        """The unpaged history of `project/package`, or its exact lookup at
        `revision`; `request_number` attributes a failure."""
        if not project.startswith(SUSE_NAMESPACE):
            raise UnusableObservation(
                "outside_suse_namespace", request_number=request_number
            )
        key = (project, package, revision)
        if key not in self._histories:
            result = await self._request(
                lambda: self._client.get_source_history(
                    project, package, revision=revision
                )
            )
            self._histories[key] = (
                result if isinstance(result, _Unusable) else _evidence(result)
            )
        value = self._histories[key]
        if isinstance(value, _Unusable):
            _raise(value, request_number)
        return value

    async def action_labels(
        self, action: IBSRequestActionDetail, package_name: str
    ) -> frozenset[str]:
        """The qualifying CVE labels of `action`'s own diff."""
        key = detail_action_key(action)
        if key not in self._diffs:
            result = await self._request(
                lambda: self._client.get_request_action_diff(
                    action, codestream_package=package_name
                )
            )
            outcome: frozenset[str] | _Unusable
            if isinstance(result, _Unusable):
                outcome = result
            else:
                diff = _evidence(result)
                if isinstance(diff, RequestActionDiff):
                    outcome, ignored = _cve_labels(diff.issues)
                    if ignored:
                        _log_ignored(
                            package_name=package_name,
                            codestream=_action_codestream(action),
                            request_number=action.request_number,
                        )
                else:
                    outcome = diff
            self._diffs[key] = outcome
        value = self._diffs[key]
        if isinstance(value, _Unusable):
            _raise(value, action.request_number)
        return value

    async def release_labels(
        self, codestream: str, package_name: str
    ) -> frozenset[str]:
        """The qualifying CVE labels of the current expanded sources of
        `package_name` in `codestream` (source info, then the diff against
        the empty tree). A failed package result or unusable response data
        is incomplete; a transport or HTTP error fails."""
        key = (codestream, package_name)
        if key not in self._release_evidence:
            self._release_evidence[key] = await self._current_labels(
                codestream, package_name
            )
        value = self._release_evidence[key]
        if isinstance(value, _Unusable):
            _raise(value, None)
        return value

    async def _current_labels(
        self, codestream: str, package_name: str
    ) -> frozenset[str] | _Unusable:
        info = await self._request(
            lambda: self._client.get_source_info(codestream, [package_name])
        )
        if isinstance(info, _Unusable):
            return info
        result = info[package_name]
        if result.source_info is None:
            assert result.failure is not None
            return _Unusable(result.failure)
        srcmd5 = result.source_info.srcmd5
        issues = await self._request(
            lambda: self._client.get_diff_issues(
                codestream, package_name, _EMPTY_SOURCE_TREE, srcmd5
            )
        )
        if isinstance(issues, _Unusable):
            return issues
        labels, ignored = _cve_labels(issues)
        if ignored:
            _log_ignored(
                package_name=package_name, codestream=codestream, request_number=None
            )
        return labels


def _action_codestream(action: IBSRequestActionDetail) -> str | None:
    if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
        return action.target_release_project
    return action.target_project


# ---------------------------------------------------------------------------
# Scope observation
# ---------------------------------------------------------------------------


async def observe_scope(
    scope: IBSRequestScope, snapshot: ScopeSnapshot, cache: EvidenceCache
) -> Observation:
    """Discover and classify one scope (Algorithm steps 2-3).

    A CVE-less scope, and a scope whose track was absent at step 1, are a
    complete no-match without any IBS request; the locked revalidation
    decides the latter. A logical package or codestream that the IBS
    operations would reject is incomplete (`invalid_identity`), and a
    codestream outside `SUSE:` is incomplete (`outside_suse_namespace`),
    both before any IBS request. Otherwise the release proof is applied
    first (unless the baseline is `RELEASED`), then every required root is
    exhausted. Raises `UnusableObservation` for an incomplete or failed
    observation; unknown exceptions propagate.
    """
    if scope.cve_id is None or snapshot.delivery_status is None:
        return NO_MATCH
    if not is_valid_scope_identity(scope.package_name, scope.codestream):
        raise UnusableObservation("invalid_identity")
    if not scope.codestream.startswith(SUSE_NAMESPACE):
        raise UnusableObservation("outside_suse_namespace")
    return await _ScopeObservation(scope, scope.cve_id, snapshot, cache).run()


def _find(detail: IBSRequestDetail, key: ActionKey) -> IBSRequestActionDetail | None:
    for action in detail.actions:
        if detail_action_key(action) == key:
            return action
    return None


def _request_write(detail: IBSRequestDetail) -> RequestWrite:
    successor = detail.superseded_by_request_number
    if detail.request_number > INTEGER_MAX or (
        successor is not None and successor > INTEGER_MAX
    ):
        raise UnusableObservation(
            "value_out_of_range", request_number=detail.request_number
        )
    return RequestWrite(
        request_number=detail.request_number,
        state=detail.state,
        superseded_by_request_number=successor,
        upstream_created_at=detail.upstream_created_at,
        upstream_updated_at=detail.upstream_updated_at,
    )


class _ScopeObservation:
    """The observation state of one scope."""

    def __init__(
        self,
        scope: IBSRequestScope,
        cve_id: str,
        snapshot: ScopeSnapshot,
        cache: EvidenceCache,
    ) -> None:
        self.cve_id = cve_id
        self.package_name = scope.package_name
        self.codestream = scope.codestream
        self.snapshot = snapshot
        self.cache = cache
        self.released = snapshot.delivery_status is DeliveryStatus.RELEASED
        self.correlated = {action.key for action in snapshot.correlated}
        self.strict: dict[int, IBSRequestDetail] = {}
        self.requests: dict[int, RequestWrite] = {}
        self.actions: dict[ActionKey, ActionWrite] = {}
        self.progress = False

    async def run(self) -> Observation:
        if not self.released:
            proven = await self._prove_first()
            if proven is not None:
                return proven
        await self._roots()
        return Observation(
            derived=DeliveryStatus.IN_PROGRESS
            if self.progress
            else DeliveryStatus.PENDING,
            requests=tuple(self.requests[n] for n in sorted(self.requests)),
            actions=tuple(self.actions[k] for k in sorted(self.actions, key=order)),
        )

    # -- release proof (Accepted RR Provenance, Release Discovery) --------

    async def _prove_first(self) -> Observation | None:
        """Apply the release proof to the correlated accepted release
        actions, then through the current release evidence and the release
        scan. A proven release ends the observation; otherwise an
        incomplete result found here makes the observation incomplete."""
        deferred: UnusableObservation | None = None
        releases = sorted(
            (
                action
                for action in self.snapshot.correlated
                if action.action_type is IBSRequestActionType.MAINTENANCE_RELEASE
            ),
            key=lambda action: order(action.key),
        )
        for retained in releases:
            try:
                detail = await self.cache.detail(retained.request.request_number)
                action = _find(detail, retained.key)
                if action is None or detail.state is not IBSRequestState.ACCEPTED:
                    continue
                if await self._prove(detail, action, diff_first=False):
                    return self._proven(detail, action)
            except UnusableObservation as exc:
                if exc.failed:
                    raise
                deferred = deferred or exc
        try:
            if self.cve_id in await self.cache.release_labels(
                self.codestream, self.package_name
            ):
                proven = await self._scan()
                if proven is not None:
                    return proven
        except UnusableObservation as exc:
            if exc.failed:
                raise
            deferred = deferred or exc
        if deferred is not None:
            raise deferred
        return None

    async def _prove(
        self,
        detail: IBSRequestDetail,
        action: IBSRequestActionDetail,
        *,
        diff_first: bool,
    ) -> bool:
        """Whether `action` of the accepted `detail` proves the release.

        Without acceptinfo it proves nothing. Missing acceptinfo `rev` or
        `srcmd5` is `missing_provenance`; a lookup of the action's own
        target package that does not return that revision with that
        checksum and the request number is `release_proof_failed`; an
        unavailable lookup or diff is incomplete. `diff_first` checks the
        release diff before the lookup (the release scan)."""
        accepted = action.acceptinfo
        if accepted is None:
            return False
        number = detail.request_number
        if diff_first and not await self._positive(action):
            return False
        if accepted.rev is None or accepted.srcmd5 is None:
            raise UnusableObservation("missing_provenance", request_number=number)
        assert action.target_project is not None
        assert action.target_package is not None
        lookup = await self.cache.history(
            action.target_project,
            action.target_package,
            revision=accepted.rev,
            request_number=number,
        )
        if len(lookup.entries) != 1 or (
            lookup.entries[0].srcmd5 != accepted.srcmd5
            or lookup.entries[0].request_number != number
        ):
            raise UnusableObservation("release_proof_failed", request_number=number)
        return diff_first or await self._positive(action)

    def _proven(
        self, detail: IBSRequestDetail, action: IBSRequestActionDetail
    ) -> Observation:
        """The complete positive observation of a proven release: only the
        proving action, its request, and its correlation."""
        return Observation(
            derived=DeliveryStatus.RELEASED,
            requests=(_request_write(detail),),
            actions=(self._action_write(detail, action),),
        )

    async def _scan(self) -> Observation | None:
        """The newest-first release scan of the codestream history."""
        history = await self.cache.history(self.codestream, self.package_name)
        seen: set[int] = set()
        for entry in reversed(history.entries):
            number = entry.request_number
            if number is None or number in seen:
                continue
            seen.add(number)
            detail = await self.cache.detail(number)
            matching = self._matching(detail, releases_only=True)
            if not matching:
                continue
            if detail.state is not IBSRequestState.ACCEPTED:
                raise UnusableObservation(
                    "contradictory_evidence", request_number=number
                )
            for action in matching:
                if action.acceptinfo is None:
                    return None
                if await self._prove(detail, action, diff_first=True):
                    return self._proven(detail, action)
        return None

    # -- roots 1-4 and 7 --------------------------------------------------

    async def _roots(self) -> None:
        for retained in sorted(self.snapshot.correlated, key=lambda a: order(a.key)):
            number = retained.request.request_number
            if retained.request.state is IBSRequestState.ACCEPTED:
                continue
            detail = await self.cache.detail(number)
            self.strict[number] = detail
            self.requests[number] = _request_write(detail)
        for action_type in (
            IBSRequestActionType.MAINTENANCE_INCIDENT,
            IBSRequestActionType.MAINTENANCE_RELEASE,
        ):
            found = await self.cache.search(action_type, self.package_name)
            for number in found.request_numbers:
                self.strict[number] = await self.cache.detail(number)
        for number in sorted(self.strict):
            await self._close_supersession(self.strict[number])
        for number in sorted(self.strict):
            detail = self.strict[number]
            for action in self._matching(detail):
                await self._evaluate(detail, action)
        if self.released:
            return
        for retained in sorted(self.snapshot.correlated, key=lambda a: order(a.key)):
            if (
                retained.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
                and retained.request.state is IBSRequestState.ACCEPTED
                and retained.request.request_number not in self.strict
                and await self._effective(
                    retained.request.request_number,
                    project=retained.target_project,
                    package=retained.target_package,
                    srcmd5=retained.accepted_srcmd5,
                )
            ):
                self.progress = True
        for retained in sorted(self.snapshot.in_flight, key=lambda a: order(a.key)):
            if retained.request.request_number not in self.strict:
                await self._in_flight(retained)

    async def _close_supersession(self, detail: IBSRequestDetail) -> None:
        """Point-fetch the successor chain of a superseded request."""
        visited = {detail.request_number}
        current = detail
        while current.state is IBSRequestState.SUPERSEDED:
            successor = current.superseded_by_request_number
            assert successor is not None
            if successor in visited:
                raise UnusableObservation(
                    "supersession_cycle", request_number=current.request_number
                )
            visited.add(successor)
            current = await self.cache.detail(successor)
            self.strict.setdefault(successor, current)

    def _matching(
        self, detail: IBSRequestDetail, *, releases_only: bool = False
    ) -> list[IBSRequestActionDetail]:
        """The actions of `detail` matching the scope, in identity order; an
        unresolved action makes the observation incomplete."""
        accepted = detail.state is IBSRequestState.ACCEPTED
        matching: list[IBSRequestActionDetail] = []
        for action in detail.actions:
            if (
                releases_only
                and action.action_type is not IBSRequestActionType.MAINTENANCE_RELEASE
            ):
                continue
            match = classify_action(
                action,
                action_identity(action, accepted=accepted),
                package_name=self.package_name,
                codestream=self.codestream,
            )
            if match is ActionMatch.UNRESOLVED:
                raise UnusableObservation(
                    "unresolved_action", request_number=detail.request_number
                )
            if match is ActionMatch.MATCHING:
                matching.append(action)
        return sorted(matching, key=lambda action: order(detail_action_key(action)))

    async def _positive(self, action: IBSRequestActionDetail) -> bool:
        return self.cve_id in await self.cache.action_labels(action, self.package_name)

    async def _evaluate(
        self, detail: IBSRequestDetail, action: IBSRequestActionDetail
    ) -> None:
        """Correlate a relevant matching action and record its progress.

        Requests that are `declined`, `revoked`, `deleted`, or `superseded`
        establish nothing and need no diff. An uncorrelated action needs a
        positive diff; a correlated one is retained evidence."""
        if detail.state not in _PROGRESSING_STATES:
            return
        key = detail_action_key(action)
        if key not in self.correlated and not await self._positive(action):
            return
        self._plan(detail, action)
        if detail.state is not IBSRequestState.ACCEPTED:
            self.progress = True
            return
        if (
            action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
            and not self.released
            and await self._effective(
                detail.request_number,
                project=action.target_project,
                package=action.target_package,
                srcmd5=None if action.acceptinfo is None else action.acceptinfo.srcmd5,
            )
        ):
            self.progress = True

    async def _effective(
        self,
        request_number: int,
        *,
        project: str | None,
        package: str | None,
        srcmd5: str | None,
    ) -> bool:
        """Whether the accepted submission `request_number` still
        establishes progress (Effective SR).

        Effective when its incident-package history has a revision with its
        number and its acceptinfo `srcmd5`, and no later revision carries
        another submission request; otherwise the latest later submission is
        the effective one and its own diff decides. Missing provenance or a
        history without the action's revision is `missing_provenance`; an
        unavailable history or later detail is incomplete."""
        if project is None or package is None or srcmd5 is None:
            raise UnusableObservation(
                "missing_provenance", request_number=request_number
            )
        history = await self.cache.history(
            project, package, request_number=request_number
        )
        own = [
            entry.revision
            for entry in history.entries
            if entry.request_number == request_number and entry.srcmd5 == srcmd5
        ]
        if not own:
            raise UnusableObservation(
                "missing_provenance", request_number=request_number
            )
        later = [
            entry.request_number
            for entry in history.entries
            if entry.revision > own[-1]
            and entry.request_number is not None
            and entry.request_number != request_number
        ]
        replacing: IBSRequestDetail | None = None
        for number in dict.fromkeys(later):
            detail = await self.cache.detail(number)
            if any(
                action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
                for action in detail.actions
            ):
                replacing = detail
        if replacing is None:
            return True
        for action in self._matching(replacing):
            if (
                action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
                and action.target_project == project
                and action.target_package == package
                and (
                    detail_action_key(action) in self.correlated
                    or await self._positive(action)
                )
            ):
                effective = await self._effective(
                    replacing.request_number,
                    project=project,
                    package=package,
                    srcmd5=None
                    if action.acceptinfo is None
                    else action.acceptinfo.srcmd5,
                )
                self._plan(replacing, action)
                return effective
        return False

    async def _in_flight(self, retained: RetainedAction) -> None:
        """An uncorrelated in-flight submission of root 1: unavailable
        evidence of it is not evidence; it is correlated only when its diff
        is positive and its incident history is available."""
        saved = (dict(self.requests), dict(self.actions), self.progress)
        number = retained.request.request_number
        try:
            detail = await self.cache.detail(number)
            action = _find(detail, retained.key)
            if action is None or not await self._positive(action):
                return
            effective = await self._effective(
                number,
                project=action.target_project,
                package=action.target_package,
                srcmd5=None if action.acceptinfo is None else action.acceptinfo.srcmd5,
            )
            self._plan(detail, action)
            if effective:
                self.progress = True
        except UnusableObservation as exc:
            if exc.failed:
                raise
            self.requests, self.actions, self.progress = saved

    # -- writes -------------------------------------------------------------

    def _plan(self, detail: IBSRequestDetail, action: IBSRequestActionDetail) -> None:
        self.requests[detail.request_number] = _request_write(detail)
        write = self._action_write(detail, action)
        self.actions[write.key] = write

    def _action_write(
        self, detail: IBSRequestDetail, action: IBSRequestActionDetail
    ) -> ActionWrite:
        identity = action_identity(
            action, accepted=detail.state is IBSRequestState.ACCEPTED
        )
        accepted = action.acceptinfo
        revision = None if accepted is None else accepted.rev
        if (
            identity.incident_number is not None
            and identity.incident_number > INTEGER_MAX
        ) or (revision is not None and len(revision) > REVISION_MAX_LENGTH):
            raise UnusableObservation(
                "value_out_of_range", request_number=detail.request_number
            )
        assert identity.logical_package == self.package_name
        return ActionWrite(
            key=detail_action_key(action),
            request_number=detail.request_number,
            action_type=action.action_type,
            source_project=action.source_project,
            source_package=action.source_package,
            target_project=action.target_project,
            target_package=action.target_package,
            target_release_project=action.target_release_project,
            logical_package=self.package_name,
            codestream_name=self.codestream,
            incident_number=identity.incident_number,
            accepted_revision=revision,
            accepted_srcmd5=None if accepted is None else accepted.srcmd5,
        )
