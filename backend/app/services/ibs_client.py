"""Client for the credentialed IBS API.

Implements docs/features/integrations/ibs-integration.md (Service Layer >
IBSClient) for the targeted source-info and expanded source-diff operations
used by track release detection, and for the request ID search, request
point detail, request action diff, and package source history operations
used by submission tracking, with the SSH-signature authentication of
Request Authentication and the in-memory cookies of Session Reuse
(`app.services.ibs_signature_auth`). The source-info and source-diff
parsing outcomes follow docs/features/packages/ibs-track-release-detection.md
(Source-Info Validation, Source-Diff Validation, XML and Response Safety);
the request records, field contracts, and parsers live in
`app.services.ibs_request_evidence` and are re-exported here.

Lifetime: one client per workflow invocation, created on that invocation's
event loop and closed before it ends (`async with IBSClient() as client`);
no client crosses an event loop or is held at module level. Construction
performs no I/O and succeeds without credentials; every operation then
raises `IBSCredentialsNotConfiguredError` after validating its input and
before any HTTP request.

Every operation is a read without side effects. The source-diff `POST` is
semantically read-only, so the client opts into the shared transport retry
for non-idempotent methods. Redirects are never followed. A final response
other than 2xx raises the original `httpx.HTTPStatusError` without reading
or parsing its body, with one exception: a source-diff HTTP 400 whose
request names a checksum `orev` other than `rev` has its body read through
the same XML safety boundary to apply the discriminator of
ibs-integration.md (Unavailable Old Revision), which raises
`IBSHistoricalRevisionUnavailable`. Every other source-diff 400 and 404
keeps its HTTP error outcome. Successful bodies are parsed incrementally by
the shared XML safety boundary without a byte or issue-count cap; no result
is returned until the complete document has parsed. The client logs
nothing, and its exceptions carry bounded reasons only, never response
content.

The request operations return `RequestEvidenceResult` values instead of
raising for unusable evidence: the operation-specific HTTP statuses (every
search 4xx except 401 and 403; a detail or history 404; a request action
diff 400 or 404) become incomplete results without reading the body, and a
parser failure, interrupted body, or invalid document becomes an incomplete
result with one bounded reason. Every other final non-2xx response raises
the original `httpx.HTTPStatusError`. No request URL ever contains a project
outside the `SUSE:` namespace.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final, Literal, Self, cast, get_args
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from app.config import settings
from app.core.enums import IBSRequestActionType, IBSRequestState
from app.core.ibs_ssh_key import (
    INVALID_USERNAME_MESSAGE,
    is_valid_ibs_username,
    load_ibs_ssh_private_key,
)
from app.services.http_client import create_http_client
from app.services.ibs_request_evidence import (
    SUSE_NAMESPACE,
    AcceptInfo,
    EvidenceHandler,
    IBSRequestActionDetail,
    IBSRequestDetail,
    IncompleteEvidenceError,
    IncompleteReason,
    RequestActionDiff,
    RequestActionIssue,
    RequestDetailHandler,
    RequestEvidenceResult,
    RequestIdSearchResult,
    SearchHandler,
    SourceHistory,
    SourceHistoryEntry,
    SourceHistoryHandler,
    is_lowercase_checksum,
    is_valid_ibs_name,
    is_valid_request_revision,
    request_action_diff_form,
)
from app.services.ibs_signature_auth import (
    AuthenticationFailureReason,
    IBSAuthenticationError,
    IBSSignatureAuth,
)
from app.services.xml_safety import SafeXMLParser, XMLSafetyError

__all__ = [
    "HTTP_CLIENT_NAME",
    "AcceptInfo",
    "AuthenticationFailureReason",
    "DiffIssue",
    "DiffIssueState",
    "IBSAuthenticationError",
    "IBSClient",
    "IBSCredentialsNotConfiguredError",
    "IBSHistoricalRevisionUnavailable",
    "IBSRequestActionDetail",
    "IBSRequestDetail",
    "IBSResponseDataError",
    "IncompleteReason",
    "RequestActionDiff",
    "RequestActionIssue",
    "RequestEvidenceResult",
    "RequestIdSearchResult",
    "ResponseDataReason",
    "SourceHistory",
    "SourceHistoryEntry",
    "SourceInfo",
    "SourceInfoFailure",
    "SourceInfoResult",
    "is_valid_checksum",
    "is_valid_ibs_name",
    "is_valid_request_revision",
]

HTTP_CLIENT_NAME: Final = "ibs_client"

SourceInfoFailure = Literal["missing", "duplicate", "upstream_error", "invalid_srcmd5"]
"""Why one requested source-info package is unusable."""

ResponseDataReason = Literal[
    "malformed_xml", "interrupted_response", "invalid_document", "invalid_issue"
]
"""Why a successful response body was rejected."""

DiffIssueState = Literal["added", "changed", "deleted"]

_DIFF_ISSUE_STATES: Final = frozenset(get_args(DiffIssueState))
_CHECKSUM: Final = re.compile(r"[0-9a-fA-F]{32}")
_EMPTY_SOURCE_TREE: Final = "0"


class IBSCredentialsNotConfiguredError(Exception):
    """`IBS_USERNAME` or `IBS_SSH_PRIVATE_KEY` is empty or unset.

    Raised by every operation after its input validation and before any
    HTTP request. Not an `httpx` exception and not retryable.
    """

    def __init__(self) -> None:
        super().__init__("IBS API credentials are not configured")


class IBSResponseDataError(Exception):
    """A successful source-info or source-diff response is unusable.

    `reason` is `malformed_xml` (not well-formed, a forbidden XML construct,
    or an undecodable body), `interrupted_response` (the body ended with a
    transport failure), `invalid_document` (document-level shape), or
    `invalid_issue` (a source-diff issue with an unusable structure). Never
    raised for an error response, including a source-diff 400 whose body
    is read only for the unavailable-revision classification. Raised by
    `get_source_info()` and `get_diff_issues()` only: the request action
    diff turns the same shape failures into incomplete results.
    """

    def __init__(self, reason: ResponseDataReason) -> None:
        super().__init__(f"IBS response data rejected: {reason}")
        self.reason: ResponseDataReason = reason


class IBSHistoricalRevisionUnavailable(Exception):  # noqa: N818 — specified name
    """IBS identified the source diff's `old_md5` as no longer available.

    Raised only when every condition of ibs-integration.md (Unavailable Old
    Revision) holds: `old_md5` is a checksum other than `"0"` and
    `new_md5`, the status is HTTP 400, and the complete body is a
    no-namespace `status` document with exactly one `summary` child whose
    text starts with `{project}/{package}/{old_md5}: not in repository`.
    Carries no response content. Not an `httpx` exception and not
    retryable.
    """

    def __init__(self) -> None:
        super().__init__("IBS source diff old revision is unavailable")


@dataclass(frozen=True, slots=True)
class SourceInfo:
    """One validated source-info entry: the expanded source checksum."""

    package: str
    srcmd5: str


@dataclass(frozen=True, slots=True)
class SourceInfoResult:
    """Exactly one of a validated `source_info` or a bounded `failure`."""

    source_info: SourceInfo | None = None
    failure: SourceInfoFailure | None = None

    def __post_init__(self) -> None:
        if (self.source_info is None) == (self.failure is None):
            msg = "SourceInfoResult needs exactly one of source_info and failure"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class DiffIssue:
    """One structured issue reference of an expanded source diff, as served.

    `label` is the canonical identity (for `tracker="cve"`, the CVE ID);
    `name` is tracker-native. Either may be absent. The caller evaluates
    them; nothing is reinterpreted here.
    """

    tracker: str
    state: DiffIssueState
    name: str | None
    label: str | None


class IBSClient:
    """IBS API client for one workflow invocation.

    Configuration defaults to the application settings (`IBS_API_URL`,
    `IBS_USERNAME`, `IBS_SSH_PRIVATE_KEY`); the keyword arguments replace
    them, for example in tests. `clock` returns the Unix time used for the
    signature's `created` value. Use as an async context manager or call
    `aclose()`.
    """

    def __init__(
        self,
        *,
        api_url: str | None = None,
        username: str | None = None,
        ssh_private_key: SecretStr | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        account = settings.ibs_username if username is None else username
        if account and not is_valid_ibs_username(account):
            raise ValueError(INVALID_USERNAME_MESSAGE)
        encoded_key = (
            settings.ibs_ssh_private_key if ssh_private_key is None else ssh_private_key
        ).get_secret_value()
        private_key = load_ibs_ssh_private_key(encoded_key) if encoded_key else None

        auth: IBSSignatureAuth | None = None
        if account and private_key is not None:
            auth = IBSSignatureAuth(
                username=account,
                private_key=private_key,
                clock=clock,
                discard_cookies=self._discard_cookies,
            )
        self._configured = auth is not None
        base_url = settings.ibs_api_url if api_url is None else api_url
        self._http = create_http_client(
            HTTP_CLIENT_NAME,
            retry_non_idempotent=True,
            headers={"accept": "application/xml"},
            base_url=f"{base_url}/",
            auth=auth,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the connection pool and drop every session cookie."""
        self._discard_cookies()
        await self._http.aclose()

    async def get_source_info(
        self, project: str, packages: Collection[str]
    ) -> Mapping[str, SourceInfoResult]:
        """Return one result per requested logical package.

        Calls `GET /source/{project}?view=info&nofilename=1` with one
        repeatable `package` parameter per distinct requested name, in one
        request. A requested package that is missing, duplicated,
        error-bearing (even with checksums), or carries a `srcmd5` that is
        not 32 hexadecimal characters yields a per-package failure; valid
        siblings remain usable. Unrequested entries are ignored.

        Raises `ValueError` for an invalid project, an empty collection, a
        bare string, or an invalid package name, before any HTTP request;
        `IBSCredentialsNotConfiguredError`; `IBSAuthenticationError`;
        `IBSResponseDataError` for a malformed or interrupted document, a root
        other than `sourceinfolist`, or an entry without `package`; and the
        `httpx` exception of a transport failure or non-2xx response.
        """
        _validate_name(project, "project")
        if isinstance(packages, str):
            msg = "packages must be a collection of package names, not a string"
            raise ValueError(msg)
        requested = list(dict.fromkeys(packages))
        if not requested:
            msg = "packages must not be empty"
            raise ValueError(msg)
        for package in requested:
            _validate_name(package, "package")
        self._require_credentials()

        handler = _SourceInfoHandler(frozenset(requested))
        params = [
            ("view", "info"),
            ("nofilename", "1"),
            *(("package", package) for package in requested),
        ]
        await self._read("GET", f"source/{_segment(project)}", params, handler)
        return {package: handler.result(package) for package in requested}

    async def get_diff_issues(
        self, project: str, package: str, old_md5: str, new_md5: str
    ) -> list[DiffIssue]:
        """Return the structured issues of the expanded diff `old_md5` → `new_md5`.

        Calls `POST /source/{project}/{package}?cmd=diff&view=xml&onlyissues=1
        &expand=1&orev={old_md5}&rev={new_md5}`. `old_md5` is a 32-character
        hexadecimal checksum or `"0"` (the empty source tree); `new_md5` is a
        checksum. Issues are returned faithfully in document order,
        duplicates included; a valid diff without issues returns an empty
        list.

        Raises `ValueError` for invalid input before any HTTP request;
        `IBSCredentialsNotConfiguredError`; `IBSAuthenticationError`;
        `IBSResponseDataError` for a malformed or interrupted document, a
        root other than `sourcediff` or more than one `issues` element
        (`invalid_document`), or an issue that is not an `issue` element
        without children carrying a non-empty `tracker` and a `state` of
        `added`, `changed`, or `deleted` (`invalid_issue`);
        `IBSHistoricalRevisionUnavailable` when the response identifies
        `old_md5` as unavailable; and the `httpx` exception of a transport
        failure (including an interrupted error body) or of every other
        non-2xx response, including every other 400 and every 404.
        """
        _validate_name(project, "project")
        _validate_name(package, "package")
        if old_md5 != _EMPTY_SOURCE_TREE and not _CHECKSUM.fullmatch(old_md5):
            msg = 'old_md5 must be a 32-character hexadecimal checksum or "0"'
            raise ValueError(msg)
        if not _CHECKSUM.fullmatch(new_md5):
            msg = "new_md5 must be a 32-character hexadecimal checksum"
            raise ValueError(msg)
        self._require_credentials()

        # Condition 1 of Unavailable Old Revision; conditions 2-4 are
        # evaluated on the response.
        unavailable_prefix = (
            f"{project}/{package}/{old_md5}: not in repository"
            if old_md5 not in {_EMPTY_SOURCE_TREE, new_md5}
            else None
        )
        handler = _DiffHandler(_diff_issue)
        params = [
            ("cmd", "diff"),
            ("view", "xml"),
            ("onlyissues", "1"),
            ("expand", "1"),
            ("orev", old_md5),
            ("rev", new_md5),
        ]
        path = f"source/{_segment(project)}/{_segment(package)}"
        await self._read(
            "POST", path, params, handler, unavailable_prefix=unavailable_prefix
        )
        return handler.issues

    async def search_request_ids(
        self,
        action_type: IBSRequestActionType,
        *,
        states: Collection[IBSRequestState] | None = None,
        source_package_prefix: str | None = None,
        target_package_prefix: str | None = None,
    ) -> RequestEvidenceResult[RequestIdSearchResult]:
        """Search request numbers with one typed same-action predicate.

        Calls `GET /search/request/id?match=action[@type='{action_type}' and
        starts-with({source|target}/@package,'{prefix}')]`, followed by
        ` and (state/@name='…' or …)` when `states` is given (in
        `IBSRequestState` order). `target/@releaseproject` is never part of
        the predicate. A complete result holds the distinct request numbers
        in ascending order and the reported `matches`.

        Raises `ValueError` before any HTTP request for an action type that
        is not an `IBSRequestActionType`, an empty, string, or non-member
        state collection, no prefix or both prefixes, a source-package
        prefix with `maintenance_release` or a target-package prefix with
        `maintenance_incident`, and a prefix that is not an IBS name; then
        `IBSCredentialsNotConfiguredError`; `IBSAuthenticationError`; and
        the `httpx` exception of a transport failure, a 403, a 5xx, or a
        3xx. Every other 4xx is an incomplete result (`not_found` for 404,
        `rejected` otherwise), as are a malformed or interrupted document
        (`malformed_xml`, `interrupted_response`), a document of another
        shape (`invalid_document`), an invalid entry (`invalid_entry`),
        duplicate numbers (`duplicate_identity`), and a count that differs
        from `matches` (`count_mismatch`).
        """
        if not isinstance(action_type, IBSRequestActionType):
            msg = "unsupported IBS request action type"
            raise ValueError(msg)
        selected = _validate_states(states)
        if source_package_prefix is not None and target_package_prefix is None:
            if action_type is not IBSRequestActionType.MAINTENANCE_INCIDENT:
                msg = "source_package_prefix requires maintenance_incident"
                raise ValueError(msg)
            field_path, prefix = "source/@package", source_package_prefix
        elif target_package_prefix is not None and source_package_prefix is None:
            if action_type is not IBSRequestActionType.MAINTENANCE_RELEASE:
                msg = "target_package_prefix requires maintenance_release"
                raise ValueError(msg)
            field_path, prefix = "target/@package", target_package_prefix
        else:
            msg = "exactly one of source_package_prefix and target_package_prefix"
            raise ValueError(msg)
        _validate_name(prefix, "package prefix")
        self._require_credentials()

        # IBS names contain no quote, bracket, or parenthesis, so the
        # literals cannot leave their XPath string.
        predicate = (
            f"action[@type='{action_type.value}' and "
            f"starts-with({field_path},'{prefix}')]"
        )
        if selected:
            alternatives = " or ".join(f"state/@name='{s.value}'" for s in selected)
            predicate = f"{predicate} and ({alternatives})"
        return await self._read_evidence(
            "GET",
            "search/request/id",
            [("match", predicate)],
            SearchHandler(),
            incomplete_status=_search_incomplete_status,
        )

    async def get_request(
        self, request_number: int
    ) -> RequestEvidenceResult[IBSRequestDetail]:
        """Point-fetch one request: `GET /request/{request_number}`.

        A complete result holds the parent and every `maintenance_incident`
        and `maintenance_release` action, validated and in the stored form
        of ibs-integration.md (Request Point Detail): projects outside
        `SUSE:` become `_redacted_`; actions of the six other IBS types are
        ignored.

        Raises `ValueError` for a request number that is not a positive
        integer before any HTTP request; `IBSCredentialsNotConfiguredError`;
        `IBSAuthenticationError`; and the `httpx` exception of a transport
        failure and of every final non-2xx response except 404. A 404 is an
        incomplete result (`not_found`), never a deleted state; so are a
        malformed or interrupted document, a root or `state` cardinality
        that is not one request with one state or an ID other than the
        requested number (`invalid_document`), an unknown state, invalid
        timestamp, or invalid supersession (`invalid_state`), an action
        type outside the eight IBS types (`unknown_action_type`), a
        supported action with a missing or invalid consumed field
        (`invalid_action`), and two supported actions with one semantic
        identity (`duplicate_identity`).
        """
        if (
            isinstance(request_number, bool)
            or not isinstance(request_number, int)
            or request_number < 1
        ):
            msg = "request_number must be a positive integer"
            raise ValueError(msg)
        self._require_credentials()
        return await self._read_evidence(
            "GET",
            f"request/{request_number}",
            [],
            RequestDetailHandler(request_number),
            incomplete_status=_not_found_status,
        )

    async def get_request_action_diff(
        self, action: IBSRequestActionDetail, *, codestream_package: str
    ) -> RequestEvidenceResult[RequestActionDiff]:
        """Diff one supported request action: `POST /source/{project}/
        {package}?cmd=diff&view=xml&withissues=1&onlyissues=1&{form}`.

        The accepted form applies when the action has acceptinfo, the
        not-accepted form (always `expand=1`) otherwise; `codestream_package`
        is the logical package of the action's codestream and is used only
        by the not-accepted form (ibs-integration.md, Request Action Diff).
        A complete result holds the issues as served, in document order,
        including `changed` and duplicates; nothing is filtered or logged.

        Raises `ValueError` for an `action` that is not an
        `IBSRequestActionDetail` with valid field values and for a
        `codestream_package` that is not an IBS name. Then, without any
        request and without the credential check, a missing form input is
        an incomplete result (`missing_diff_input`), and so is a path
        project or `oproject` outside `SUSE:` (`outside_suse_namespace`).
        Then raises `IBSCredentialsNotConfiguredError`;
        `IBSAuthenticationError`; and the `httpx` exception of a transport
        failure and of every final non-2xx response except 400 and 404,
        which are incomplete results (`rejected`, `not_found`) whose body
        is not read. A malformed or interrupted document, another root or
        a repeated `issues` element (`invalid_document`), and an issue
        without a non-empty `tracker` or `state` (`invalid_issue`) are
        incomplete results; never `IBSHistoricalRevisionUnavailable` or
        `IBSResponseDataError`.
        """
        checked = _validate_diff_action(action)
        _validate_name(codestream_package, "codestream package")
        try:
            form = request_action_diff_form(checked, codestream_package)
        except IncompleteEvidenceError as exc:
            return RequestEvidenceResult(incomplete_reason=exc.reason)
        self._require_credentials()

        params = [
            ("cmd", "diff"),
            ("view", "xml"),
            ("withissues", "1"),
            ("onlyissues", "1"),
            *form.params,
        ]
        path = f"source/{_segment(form.project)}/{_segment(form.package)}"
        result = await self._read_evidence(
            "POST",
            path,
            params,
            _DiffHandler(_request_action_issue),
            incomplete_status=_diff_incomplete_status,
        )
        if result.value is None:
            return RequestEvidenceResult(incomplete_reason=result.incomplete_reason)
        return RequestEvidenceResult(value=RequestActionDiff(tuple(result.value)))

    async def get_source_history(
        self, project: str, package: str, *, revision: str | None = None
    ) -> RequestEvidenceResult[SourceHistory]:
        """Read package source history: `GET /source/{project}/{package}/
        _history`, unpaged without `revision`, or the exact lookup
        `?rev={revision}`; `limit` and `startbefore` are never sent.

        A complete unpaged history is non-empty, starts at revision 1, and
        is contiguous; a revision lookup returns exactly that revision; a
        checksum lookup returns at least one entry, each with that checksum
        (ibs-integration.md, Package Source History). Entries are ascending
        and carry the revision, checksum, UTC time, and optional request
        number.

        Raises `ValueError` before any HTTP request for a `project` or
        `package` that is not an IBS name, a `project` outside `SUSE:`, and
        a `revision` that is neither a positive decimal number nor a
        lowercase 32-character checksum; then
        `IBSCredentialsNotConfiguredError`; `IBSAuthenticationError`; and
        the `httpx` exception of a transport failure and of every final
        non-2xx response except 404, which is an incomplete result
        (`not_found`). An empty lookup or an unpaged history that is not
        complete is `history_unavailable`; duplicate revisions are
        `duplicate_identity`; an invalid, unordered, or non-matching entry
        is `invalid_entry`; a malformed or interrupted document is
        `malformed_xml` or `interrupted_response`.
        """
        _validate_name(project, "project")
        _validate_name(package, "package")
        if not project.startswith(SUSE_NAMESPACE):
            msg = "source history project must be in the SUSE: namespace"
            raise ValueError(msg)
        if revision is not None and not is_valid_request_revision(revision):
            msg = "revision must be a positive decimal number or a lowercase checksum"
            raise ValueError(msg)
        self._require_credentials()

        params = [] if revision is None else [("rev", revision)]
        path = f"source/{_segment(project)}/{_segment(package)}/_history"
        return await self._read_evidence(
            "GET",
            path,
            params,
            SourceHistoryHandler(revision),
            incomplete_status=_not_found_status,
        )

    def _require_credentials(self) -> None:
        if not self._configured:
            raise IBSCredentialsNotConfiguredError

    def _discard_cookies(self) -> None:
        self._http.cookies.clear()

    async def _read(
        self,
        method: str,
        path: str,
        params: list[tuple[str, str]],
        handler: _SourceInfoHandler | _DiffHandler[DiffIssue],
        *,
        unavailable_prefix: str | None = None,
    ) -> None:
        async with self._http.stream(method, path, params=tuple(params)) as response:
            if not response.is_success:
                if (
                    unavailable_prefix is not None
                    and response.status_code == httpx.codes.BAD_REQUEST
                    and await _names_unavailable_revision(response, unavailable_prefix)
                ):
                    raise IBSHistoricalRevisionUnavailable
                response.raise_for_status()
            parser = SafeXMLParser(handler)
            reason: ResponseDataReason | None = None
            try:
                async for chunk in response.aiter_bytes():
                    parser.feed(chunk)
                parser.close()
            except XMLSafetyError, httpx.DecodingError:
                reason = "malformed_xml"
            except httpx.TransportError:
                reason = "interrupted_response"
            if reason is not None:
                raise IBSResponseDataError(reason)

    async def _read_evidence[T](
        self,
        method: str,
        path: str,
        params: list[tuple[str, str]],
        handler: EvidenceHandler[T],
        *,
        incomplete_status: Callable[[int], IncompleteReason | None],
    ) -> RequestEvidenceResult[T]:
        """Read one request-evidence document.

        A final non-2xx status for which `incomplete_status` returns a
        reason is an incomplete result, without reading the body; every
        other one raises the original `httpx.HTTPStatusError`. A successful
        body is parsed completely through the XML safety boundary before
        `handler.result()` is taken.
        """
        reason: IncompleteReason
        async with self._http.stream(method, path, params=tuple(params)) as response:
            if not response.is_success:
                status_reason = incomplete_status(response.status_code)
                if status_reason is not None:
                    return RequestEvidenceResult(incomplete_reason=status_reason)
                response.raise_for_status()
            parser = SafeXMLParser(handler)
            try:
                async for chunk in response.aiter_bytes():
                    parser.feed(chunk)
                parser.close()
                return RequestEvidenceResult(value=handler.result())
            except XMLSafetyError, httpx.DecodingError:
                reason = "malformed_xml"
            except httpx.TransportError:
                reason = "interrupted_response"
            except IncompleteEvidenceError as exc:
                reason = exc.reason
            except IBSResponseDataError as exc:  # the shared source-diff handler
                reason = exc.reason
        return RequestEvidenceResult(incomplete_reason=reason)


def is_valid_checksum(value: object) -> bool:
    """Whether `value` is a 32-character hexadecimal source checksum this
    client accepts as `old_md5` or `new_md5`. Pure predicate."""
    return isinstance(value, str) and _CHECKSUM.fullmatch(value) is not None


def _validate_name(value: str, what: str) -> None:
    if not is_valid_ibs_name(value):
        msg = f"invalid IBS {what} name"
        raise ValueError(msg)


def _segment(value: str) -> str:
    return quote(value, safe=":+")


def _validate_states(
    states: Collection[IBSRequestState] | None,
) -> tuple[IBSRequestState, ...]:
    """The selected states in `IBSRequestState` order; `()` for `None`."""
    if states is None:
        return ()
    if isinstance(states, str) or not states:
        msg = "states must be a non-empty collection of IBSRequestState"
        raise ValueError(msg)
    selected = set(states)
    if not all(isinstance(state, IBSRequestState) for state in selected):
        msg = "states must be a non-empty collection of IBSRequestState"
        raise ValueError(msg)
    return tuple(state for state in IBSRequestState if state in selected)


def _search_incomplete_status(status: int) -> IncompleteReason | None:
    """ibs-integration.md (Request ID Search): every 4xx except 401 and 403
    is incomplete evidence."""
    if status == httpx.codes.NOT_FOUND:
        return "not_found"
    if 400 <= status < 500 and status not in {
        httpx.codes.UNAUTHORIZED,
        httpx.codes.FORBIDDEN,
    }:
        return "rejected"
    return None


def _not_found_status(status: int) -> IncompleteReason | None:
    """Point detail and source history: only a 404 is incomplete evidence."""
    return "not_found" if status == httpx.codes.NOT_FOUND else None


def _diff_incomplete_status(status: int) -> IncompleteReason | None:
    """Request action diff: a 400 or 404 is incomplete evidence for that
    action, and its body is not read."""
    if status == httpx.codes.NOT_FOUND:
        return "not_found"
    if status == httpx.codes.BAD_REQUEST:
        return "rejected"
    return None


@dataclass
class _SourceInfoEntry:
    srcmd5: str | None
    error: bool = False


@dataclass
class _SourceInfoHandler:
    """Collects the `sourceinfo` entries of the requested packages."""

    requested: frozenset[str]
    entries: dict[str, list[_SourceInfoEntry]] = field(default_factory=dict)
    _depth: int = 0
    _current: _SourceInfoEntry | None = None

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            if name != "sourceinfolist":
                raise IBSResponseDataError("invalid_document")
        elif self._depth == 2 and name == "sourceinfo":
            package = attributes.get("package")
            if not package:
                raise IBSResponseDataError("invalid_document")
            if package in self.requested:
                self._current = _SourceInfoEntry(srcmd5=attributes.get("srcmd5"))
                self.entries.setdefault(package, []).append(self._current)
        elif self._depth == 3 and name == "error" and self._current is not None:
            self._current.error = True

    def end_element(self, name: str) -> None:
        if self._depth == 2:
            self._current = None
        self._depth -= 1

    def character_data(self, data: str) -> None:
        return None

    def result(self, package: str) -> SourceInfoResult:
        entries = self.entries.get(package, [])
        if not entries:
            return SourceInfoResult(failure="missing")
        if len(entries) > 1:
            return SourceInfoResult(failure="duplicate")
        [entry] = entries
        if entry.error:
            return SourceInfoResult(failure="upstream_error")
        if entry.srcmd5 is None or not _CHECKSUM.fullmatch(entry.srcmd5):
            return SourceInfoResult(failure="invalid_srcmd5")
        return SourceInfoResult(source_info=SourceInfo(package, entry.srcmd5))


@dataclass
class _DiffHandler[I]:
    """Collects the issues of a `sourcediff` document; `issue` validates
    and types one `issues` child.

    An unrecognized shape inside `issues` is rejected rather than skipped,
    because a diff without qualifying issues advances the caller's
    checkpoint or is a no-match: it never turns into a successful no-match.
    Shape failures raise `IBSResponseDataError`; the request action diff
    turns them into incomplete results.
    """

    issue: Callable[[str, Mapping[str, str]], I]
    issues: list[I] = field(default_factory=list)
    _depth: int = 0
    _issues_elements: int = 0
    _in_issues: bool = False

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            if name != "sourcediff":
                raise IBSResponseDataError("invalid_document")
        elif self._depth == 2 and name == "issues":
            self._issues_elements += 1
            if self._issues_elements > 1:
                raise IBSResponseDataError("invalid_document")
            self._in_issues = True
        elif self._in_issues and self._depth == 3:
            self.issues.append(self.issue(name, attributes))
        elif self._in_issues:
            raise IBSResponseDataError("invalid_issue")

    def end_element(self, name: str) -> None:
        if self._depth == 2:
            self._in_issues = False
        self._depth -= 1

    def character_data(self, data: str) -> None:
        return None

    def result(self) -> list[I]:
        return self.issues


async def _names_unavailable_revision(response: httpx.Response, prefix: str) -> bool:
    """Whether a source-diff HTTP 400 body satisfies conditions 3 and 4 of
    ibs-integration.md (Unavailable Old Revision) for `prefix`.

    Reads the complete body through the XML safety boundary. A body that is
    not well-formed, is undecodable, contains a forbidden construct, or has
    another shape returns `False`, so the caller keeps the HTTP error. A
    transport failure while reading the body propagates unchanged (the
    transport outcome). Retains at most `len(prefix)` characters of the
    summary and nothing else.
    """
    handler = _StatusSummaryHandler(limit=len(prefix))
    parser = SafeXMLParser(handler)
    try:
        async for chunk in response.aiter_bytes():
            parser.feed(chunk)
        parser.close()
    except XMLSafetyError, httpx.DecodingError:
        return False
    summary = handler.summary_prefix()
    return summary is not None and summary.startswith(prefix)


@dataclass
class _StatusSummaryHandler:
    """Collects the start of the single `summary` of a `status` document.

    The root must be the no-namespace `status` element (a namespaced name
    is reported as `"{uri} {local}"`, so it never equals `"status"`) with
    exactly one no-namespace `summary` child that contains text only.
    """

    limit: int
    _depth: int = 0
    _root_is_status: bool = False
    _summaries: int = 0
    _in_summary: bool = False
    _summary_has_child: bool = False
    _text: list[str] = field(default_factory=list)
    _length: int = 0

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            self._root_is_status = name == "status"
        elif self._depth == 2 and name == "summary":
            self._summaries += 1
            self._in_summary = True
        elif self._in_summary:
            self._summary_has_child = True

    def end_element(self, name: str) -> None:
        if self._depth == 2:
            self._in_summary = False
        self._depth -= 1

    def character_data(self, data: str) -> None:
        if self._in_summary and self._depth == 2 and self._length < self.limit:
            kept = data[: self.limit - self._length]
            self._text.append(kept)
            self._length += len(kept)

    def summary_prefix(self) -> str | None:
        """The retained summary start, or `None` for any other shape."""
        if not self._root_is_status or self._summaries != 1 or self._summary_has_child:
            return None
        return "".join(self._text)


def _diff_issue(name: str, attributes: Mapping[str, str]) -> DiffIssue:
    tracker = attributes.get("tracker")
    state = attributes.get("state")
    if name != "issue" or not tracker or state not in _DIFF_ISSUE_STATES:
        raise IBSResponseDataError("invalid_issue")
    return DiffIssue(
        tracker=tracker,
        state=cast(DiffIssueState, state),
        name=attributes.get("name"),
        label=attributes.get("label"),
    )


def _request_action_issue(
    name: str, attributes: Mapping[str, str]
) -> RequestActionIssue:
    """One request action diff issue: an `issue` element with a non-empty
    `tracker` and `state`, returned as served (ibs-integration.md, Request
    Action Diff)."""
    tracker = attributes.get("tracker")
    state = attributes.get("state")
    if name != "issue" or not tracker or not state:
        raise IBSResponseDataError("invalid_issue")
    return RequestActionIssue(
        tracker=tracker,
        state=state,
        name=attributes.get("name"),
        label=attributes.get("label"),
    )


def _validate_diff_action(action: object) -> IBSRequestActionDetail:
    """`action` if it is a request action whose present values satisfy the
    point-detail field contracts; otherwise `ValueError`."""
    if not isinstance(action, IBSRequestActionDetail):
        msg = "action must be an IBSRequestActionDetail"
        raise ValueError(msg)
    accepted = action.acceptinfo or AcceptInfo()
    names = (
        action.source_project,
        action.source_package,
        action.target_project,
        action.target_package,
        action.target_release_project,
        accepted.oproject,
        accepted.opackage,
    )
    checksums = (accepted.srcmd5, accepted.xsrcmd5, accepted.osrcmd5, accepted.oxsrcmd5)
    if (
        not all(value is None or is_valid_ibs_name(value) for value in names)
        or not all(value is None or is_lowercase_checksum(value) for value in checksums)
        or not (
            action.source_revision is None
            or is_valid_request_revision(action.source_revision)
        )
    ):
        msg = "invalid IBS request action"
        raise ValueError(msg)
    return action
