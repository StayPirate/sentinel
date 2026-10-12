"""Client for the credentialed IBS API.

Implements docs/features/integrations/ibs-integration.md (Service Layer >
IBSClient) for the targeted source-info and expanded source-diff operations
used by track release detection, with the SSH-signature authentication of
Request Authentication and the in-memory cookies of Session Reuse
(`app.services.ibs_signature_auth`). The parsing outcomes follow
docs/features/packages/ibs-track-release-detection.md (Source-Info
Validation, Source-Diff Validation, XML and Response Safety).

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
or parsing its body; every source-diff 400 and 404 therefore keeps its HTTP
error outcome here. Successful bodies are parsed incrementally by the
shared XML safety boundary without a byte or issue-count cap; no result is
returned until the complete document has parsed. The client logs nothing,
and its exceptions carry bounded reasons only, never response content.
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
from app.core.ibs_ssh_key import (
    INVALID_USERNAME_MESSAGE,
    is_valid_ibs_username,
    load_ibs_ssh_private_key,
)
from app.services.http_client import create_http_client
from app.services.ibs_signature_auth import (
    AuthenticationFailureReason,
    IBSAuthenticationError,
    IBSSignatureAuth,
)
from app.services.xml_safety import SafeXMLParser, XMLSafetyError

__all__ = [
    "HTTP_CLIENT_NAME",
    "AuthenticationFailureReason",
    "DiffIssue",
    "DiffIssueState",
    "IBSAuthenticationError",
    "IBSClient",
    "IBSCredentialsNotConfiguredError",
    "IBSResponseDataError",
    "ResponseDataReason",
    "SourceInfo",
    "SourceInfoFailure",
    "SourceInfoResult",
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
    raised for an error response, whose body is not parsed.
    """

    def __init__(self, reason: ResponseDataReason) -> None:
        super().__init__(f"IBS response data rejected: {reason}")
        self.reason: ResponseDataReason = reason


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
        `added`, `changed`, or `deleted` (`invalid_issue`); and the `httpx`
        exception of a transport failure or non-2xx response, including
        every 400 and 404.
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

        handler = _DiffHandler()
        params = [
            ("cmd", "diff"),
            ("view", "xml"),
            ("onlyissues", "1"),
            ("expand", "1"),
            ("orev", old_md5),
            ("rev", new_md5),
        ]
        path = f"source/{_segment(project)}/{_segment(package)}"
        await self._read("POST", path, params, handler)
        return handler.issues

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
        handler: _SourceInfoHandler | _DiffHandler,
    ) -> None:
        async with self._http.stream(method, path, params=tuple(params)) as response:
            if not response.is_success:
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


def _validate_name(value: str, what: str) -> None:
    """An IBS project or package name: printable ASCII without whitespace
    or `/`, and not a dot segment."""
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or not all(0x21 <= ord(character) <= 0x7E for character in value)
        or "/" in value
    ):
        msg = f"invalid IBS {what} name"
        raise ValueError(msg)


def _segment(value: str) -> str:
    return quote(value, safe=":+")


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
class _DiffHandler:
    """Collects the issues of a `sourcediff` document.

    An unrecognized shape inside `issues` is rejected rather than skipped,
    because a diff without qualifying issues advances the caller's
    checkpoint: it never turns into a successful no-match.
    """

    issues: list[DiffIssue] = field(default_factory=list)
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
            self.issues.append(_issue(name, attributes))
        elif self._in_issues:
            raise IBSResponseDataError("invalid_issue")

    def end_element(self, name: str) -> None:
        if self._depth == 2:
            self._in_issues = False
        self._depth -= 1

    def character_data(self, data: str) -> None:
        return None


def _issue(name: str, attributes: Mapping[str, str]) -> DiffIssue:
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
