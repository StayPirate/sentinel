"""The IBS Product repository download boundary.

Implements docs/features/packages/ibs-product-release-detection.md for one
detector invocation, without any database, Redis, or filesystem access:

- Download Origin and Repository Paths: anonymous requests rooted at the
  validated `IBS_DOWNLOAD_BASE_URL`, built from qualified repository
  names and validated artifact locations (`ibs_repodata`);
- Repository Traversal: current associations first, retained historical
  associations only after every current one completed without a match,
  deterministic order, and the stop rules of the outcome table;
- HTTP and Redirect Contract: `Accept-Encoding: identity`, media types,
  and at most one manually validated 302 of the updateinfo artifact to
  `dist.suse.de` with an identical path (`repomd.xml` is never
  redirected); no credential, `Authorization` header, or cookie is sent
  on any request;
- Repomd Contract, Resource and XML Safety, Snapshot Consistency, and
  Updateinfo and Advisory Validation: streamed, bounded, checksummed, and
  completely parsed snapshots (`ibs_updateinfo`);
- Reconciliation Boundary: each repository is examined at most once per
  invocation and its result reused for every dependent occurrence;
  nothing is retained across invocations;
- Irreversibility, Audit, and Observability: the repository-level events
  `ibs_product_release_repository_failed` and
  `ibs_product_release_advisories_ignored`.

`ProductRepositoryDownloads` is used once per invocation as an async
context manager. The caller (the Product release detector) passes every
candidate occurrence up front and calls `observe()` per occurrence before
taking any lock, so all repository I/O precedes each local mutation.
Shared transport retries of the caller's HTTP client apply before a
failure is classified. Only the specified failure classes are converted;
cancellation, `SoftTimeLimitExceeded`, `MemoryError`, and programming
errors propagate.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
import zlib
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Final, Self
from urllib.parse import urlsplit

import httpx
import structlog

from app.config import settings
from app.services.http_client import INFRA_FAILURE_TYPES
from app.services.packages.ibs_repodata import (
    CHECKSUM_ALGORITHMS,
    REPOMD_MAX_BYTES,
    UPDATEINFO_MAX_COMPRESSED_BYTES,
    RepositoryDataError,
    RepositoryFailureCategory,
    UpdateinfoIdentity,
    order_tier,
    parse_repomd,
    qualify_repository_name,
    repository_root_url,
)
from app.services.packages.ibs_updateinfo import UpdateinfoParser, UpdateinfoSnapshot

logger = structlog.get_logger(__name__)

REPOSITORY_FAILED_EVENT: Final = "ibs_product_release_repository_failed"
ADVISORIES_IGNORED_EVENT: Final = "ibs_product_release_advisories_ignored"
MALFORMED_ADVISORY_CATEGORY: Final = "malformed_advisory"

REDIRECT_HOST: Final = "dist.suse.de"

_REPOMD_MEDIA_TYPES: Final = frozenset({"application/xml", "text/xml"})
_UPDATEINFO_MEDIA_TYPES: Final = frozenset({"application/gzip", "application/x-gzip"})
_REPOMD_ACCEPT: Final = "application/xml, text/xml"
_UPDATEINFO_ACCEPT: Final = "application/gzip, application/x-gzip"
_GZIP_MAGIC: Final = b"\x1f\x8b"
_INVALID_LOCATION_ERROR: Final = "Invalid URL in location header"
_DECOMPRESS_CHUNK: Final = 1024 * 1024

# RFC 9110 media-type grammar: type "/" subtype *( OWS ";" OWS parameter ).
_TOKEN: Final = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED: Final = (
    r'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
)
_MEDIA_TYPE: Final = re.compile(
    rf"({_TOKEN})/({_TOKEN})(?:[ \t]*;[ \t]*(?:{_TOKEN}=(?:{_TOKEN}|{_QUOTED}))?)*"
)
_SAFE_PATH_SEGMENT: Final = re.compile(r"[^\x00-\x20\x7f-\xff%\\/]+")


@dataclass(frozen=True, slots=True)
class ProductOccurrenceCandidate:
    """One selected Product occurrence and its repository tiers.

    `current_repositories` are the Product's associations seen in the
    latest complete catalog snapshot; `historical_repositories` the other
    retained associations. Unqualified names are never requested.
    """

    occurrence_id: uuid.UUID
    cve_id: str
    package_name: str
    current_repositories: Collection[str]
    historical_repositories: Collection[str]


@dataclass(frozen=True, slots=True)
class ProductReleaseMatch:
    """The first matching repository and its selected advisory."""

    repository: str
    issued_at: datetime
    advisory_id: str


@dataclass(frozen=True, slots=True)
class ProductReleaseNoMatch:
    """Every candidate repository completed without a matching advisory."""


@dataclass(frozen=True, slots=True)
class ProductReleaseIncomplete:
    """Traversal stopped at a repository that did not complete.

    No lower-priority repository may become definitive in this invocation.
    """

    repository: str
    reason_category: RepositoryFailureCategory
    http_status: int | None = None


ProductReleaseObservation = (
    ProductReleaseMatch | ProductReleaseNoMatch | ProductReleaseIncomplete
)


@dataclass(frozen=True, slots=True)
class _NonMatch:
    """HTTP 404 for `repomd.xml`, or valid metadata without updateinfo."""


@dataclass(frozen=True, slots=True)
class _Accepted:
    snapshot: UpdateinfoSnapshot


@dataclass(frozen=True, slots=True)
class _Failed:
    category: RepositoryFailureCategory
    http_status: int | None


_RepositoryResult = _NonMatch | _Accepted | _Failed


class _Absent:
    """HTTP 404 for `repomd.xml`."""


_ABSENT: Final = _Absent()


class ProductRepositoryDownloads:
    """Repository observations for one detector invocation.

    `client` is the caller's shared HTTP client; it supplies the transport
    (TLS, shared retries), the timeout, and the `User-Agent`. Requests are
    built independently of the client's other defaults: no default header,
    query parameter, cookie, or authentication is sent, and redirects are
    never followed automatically. `base_url` defaults to the validated
    `IBS_DOWNLOAD_BASE_URL`. Duplicate
    occurrence IDs are rejected with `ValueError`.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        candidates: Iterable[ProductOccurrenceCandidate],
        *,
        base_url: str | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url or settings.ibs_download_base_url
        self._candidates: dict[uuid.UUID, ProductOccurrenceCandidate] = {}
        for candidate in candidates:
            if candidate.occurrence_id in self._candidates:
                raise ValueError("duplicate occurrence ID")
            self._candidates[candidate.occurrence_id] = candidate
        self._cve_filter = frozenset(c.cve_id for c in self._candidates.values())
        self._results: dict[str, _RepositoryResult] = {}
        self._lock = asyncio.Lock()
        self._affected: dict[str, set[uuid.UUID]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for repository, occurrences in self._affected.items():
            result = self._results[repository]
            assert isinstance(result, _Failed)
            fields: dict[str, object] = {
                "repository": repository,
                "affected_occurrence_count": len(occurrences),
                "reason_category": result.category,
            }
            if result.http_status is not None:
                fields["http_status"] = result.http_status
            logger.warning(REPOSITORY_FAILED_EVENT, **fields)
        self._affected.clear()
        self._results.clear()

    async def observe(self, occurrence_id: uuid.UUID) -> ProductReleaseObservation:
        """Traverse the occurrence's repositories and return its outcome.

        Raises `KeyError` for an occurrence that was not a candidate.
        """
        candidate = self._candidates[occurrence_id]
        current = order_tier(candidate.current_repositories)
        seen = set(current)
        historical = [
            name
            for name in order_tier(candidate.historical_repositories)
            if name not in seen
        ]
        for repository in (*current, *historical):
            result = await self._result(repository)
            if isinstance(result, _Failed):
                self._affected.setdefault(repository, set()).add(occurrence_id)
                return ProductReleaseIncomplete(
                    repository=repository,
                    reason_category=result.category,
                    http_status=result.http_status,
                )
            if isinstance(result, _Accepted):
                advisory = result.snapshot.match(
                    candidate.cve_id, candidate.package_name
                )
                if advisory is not None:
                    return ProductReleaseMatch(
                        repository=repository,
                        issued_at=advisory.issued_at,
                        advisory_id=advisory.advisory_id,
                    )
        return ProductReleaseNoMatch()

    async def _result(self, repository: str) -> _RepositoryResult:
        async with self._lock:
            return await self._examine_once(repository)

    async def _examine_once(self, repository: str) -> _RepositoryResult:
        cached = self._results.get(repository)
        if cached is not None:
            return cached
        try:
            result: _RepositoryResult = await self._examine(repository)
        except RepositoryDataError as exc:
            result = _Failed(category=exc.category, http_status=exc.http_status)
        self._results[repository] = result
        if isinstance(result, _Accepted) and result.snapshot.malformed_advisory_count:
            logger.warning(
                ADVISORIES_IGNORED_EVENT,
                repository=repository,
                reason_category=MALFORMED_ADVISORY_CATEGORY,
                advisory_count=result.snapshot.malformed_advisory_count,
            )
        return result

    async def _examine(self, repository: str) -> _RepositoryResult:
        """One repository examination under the snapshot protocol."""
        segments = qualify_repository_name(repository)
        assert segments is not None
        root = repository_root_url(self._base_url, segments)
        first = await self._fetch_repomd(root)
        for _ in range(2):
            if first is _ABSENT or first is None:
                return _NonMatch()
            assert isinstance(first, UpdateinfoIdentity)
            snapshot = await self._fetch_updateinfo(root, first)
            second = await self._fetch_repomd(root)
            if second == first:
                return _Accepted(snapshot)
            first = second
        raise RepositoryDataError("snapshot_changed")

    async def _fetch_repomd(self, root: str) -> UpdateinfoIdentity | _Absent | None:
        response = await self._open(
            httpx.URL(f"{root}/repodata/repomd.xml"),
            accept=_REPOMD_ACCEPT,
            redirect_allowed=False,
        )
        try:
            if response.status_code == 404:
                return _ABSENT
            if response.status_code != 200:
                raise RepositoryDataError(
                    "http_status", http_status=response.status_code
                )
            _check_media_type(response, _REPOMD_MEDIA_TYPES)
            length = _content_length(response)
            if length is not None and length > REPOMD_MAX_BYTES:
                raise RepositoryDataError("resource_limit")
            body = bytearray()

            def consume(chunk: bytes) -> None:
                body.extend(chunk)
                if len(body) > REPOMD_MAX_BYTES:
                    raise RepositoryDataError("resource_limit")

            await _read_body(response, consume)
            if length is not None and len(body) != length:
                raise RepositoryDataError("size")
        finally:
            await response.aclose()
        return parse_repomd(bytes(body))

    async def _fetch_updateinfo(
        self, root: str, identity: UpdateinfoIdentity
    ) -> UpdateinfoSnapshot:
        response = await self._open(
            httpx.URL(f"{root}/{identity.location}"),
            accept=_UPDATEINFO_ACCEPT,
            redirect_allowed=True,
        )
        try:
            if response.status_code != 200:
                raise RepositoryDataError(
                    "http_status", http_status=response.status_code
                )
            _check_media_type(response, _UPDATEINFO_MEDIA_TYPES)
            length = _content_length(response)
            if length is not None:
                if length > UPDATEINFO_MAX_COMPRESSED_BYTES:
                    raise RepositoryDataError("resource_limit")
                if length != identity.size:
                    raise RepositoryDataError("size")
            stream = _UpdateinfoStream(
                identity,
                UpdateinfoParser(
                    metadata_timestamp=identity.timestamp, cve_filter=self._cve_filter
                ),
            )
            await _read_body(response, stream.feed)
            return stream.close()
        finally:
            await response.aclose()

    async def _open(
        self, url: httpx.URL, *, accept: str, redirect_allowed: bool
    ) -> httpx.Response:
        """Send an anonymous GET, applying the one-redirect rule.

        Only the updateinfo artifact may follow one compliant 302; any
        other redirect fails the repository. Returns the open streamed
        response; the caller closes it.
        """
        response = await self._send(url, accept=accept)
        status = response.status_code
        if status == 302 and redirect_allowed:
            target = await _redirect_target(url, response)
            response = await self._send(target, accept=accept)
            status = response.status_code
            if 300 <= status < 400:
                await response.aclose()
                raise RepositoryDataError("redirect", http_status=status)
        elif 300 <= status < 400:
            await response.aclose()
            raise RepositoryDataError("redirect", http_status=status)
        return response

    async def _send(self, url: httpx.URL, *, accept: str) -> httpx.Response:
        # Built directly rather than through `build_request()`, which would
        # merge the client's default headers, query parameters, and cookies.
        headers = {"Accept": accept, "Accept-Encoding": "identity"}
        user_agent = self._client.headers.get("user-agent")
        if user_agent is not None:
            headers["User-Agent"] = user_agent
        request = httpx.Request(
            "GET",
            url,
            headers=headers,
            extensions={"timeout": self._client.timeout.as_dict()},
        )
        try:
            return await self._client.send(
                request, auth=None, stream=True, follow_redirects=False
            )
        except httpx.TimeoutException:
            raise RepositoryDataError("timeout") from None
        except httpx.RemoteProtocolError as exc:
            # httpx builds the next request of every redirect response, even
            # when not following it, and reports an unparseable `Location`
            # this way after closing the response.
            if str(exc).startswith(_INVALID_LOCATION_ERROR):
                raise RepositoryDataError("redirect") from None
            raise RepositoryDataError("transport") from None
        except INFRA_FAILURE_TYPES:
            raise RepositoryDataError("transport") from None


async def _redirect_target(source: httpx.URL, response: httpx.Response) -> httpx.URL:
    """Validate a 302 `Location` and return the target URL.

    The target must be one absolute `https://dist.suse.de` URL without
    port, user information, query, or fragment, whose path is
    byte-identical to the source path and safe.
    """
    locations = response.headers.get_list("location")
    await response.aclose()
    if len(locations) != 1:
        raise RepositoryDataError("redirect", http_status=302)
    location = locations[0]
    source_path = source.raw_path.decode("ascii")
    try:
        parts = urlsplit(location)
    except ValueError:
        raise RepositoryDataError("redirect", http_status=302) from None
    if (
        any(ord(character) <= 0x20 or ord(character) >= 0x7F for character in location)
        or "?" in location
        or "#" in location
        or parts.scheme != "https"
        or parts.netloc != REDIRECT_HOST
        or parts.path != source_path
        or not _is_safe_path(parts.path)
    ):
        raise RepositoryDataError("redirect", http_status=302)
    return source.copy_with(scheme="https", host=REDIRECT_HOST, port=None)


def _is_safe_path(path: str) -> bool:
    segments = path.split("/")
    return (
        path.startswith("/")
        and len(segments) > 1
        and all(
            segment not in (".", "..") and _SAFE_PATH_SEGMENT.fullmatch(segment)
            for segment in segments[1:]
        )
    )


def _check_media_type(response: httpx.Response, accepted: frozenset[str]) -> None:
    values = response.headers.get_list("content-type")
    if len(values) != 1:
        raise RepositoryDataError("content_type")
    match = _MEDIA_TYPE.fullmatch(values[0])
    if match is None or f"{match[1]}/{match[2]}".lower() not in accepted:
        raise RepositoryDataError("content_type")


def _content_length(response: httpx.Response) -> int | None:
    """The single non-negative decimal `Content-Length`, if present."""
    values = response.headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1 or not (values[0].isascii() and values[0].isdigit()):
        raise RepositoryDataError("size")
    return int(values[0])


async def _read_body(
    response: httpx.Response, consume: Callable[[bytes], None]
) -> None:
    """Pass the undecoded body to `consume`; an interrupted body is a
    transport or timeout failure."""
    try:
        async for chunk in response.aiter_raw():
            consume(chunk)
    except httpx.TimeoutException:
        raise RepositoryDataError("timeout") from None
    except INFRA_FAILURE_TYPES:
        raise RepositoryDataError("transport") from None


class _UpdateinfoStream:
    """Bounded decompression, checksums, and parsing of one artifact."""

    def __init__(self, identity: UpdateinfoIdentity, parser: UpdateinfoParser) -> None:
        self._identity = identity
        self._parser = parser
        self._compressed = 0
        self._open = 0
        self._head = b""
        self._compressed_hash = hashlib.new(
            CHECKSUM_ALGORITHMS[identity.checksum_type][0]
        )
        self._open_hash = hashlib.new(
            CHECKSUM_ALGORITHMS[identity.open_checksum_type][0]
        )
        # wbits 31: exactly one gzip member, header and trailer (CRC32,
        # ISIZE) verified by zlib.
        self._decompressor = zlib.decompressobj(wbits=31)

    def feed(self, chunk: bytes) -> None:
        self._compressed += len(chunk)
        if self._compressed > self._identity.size:
            raise RepositoryDataError("size")
        if len(self._head) < len(_GZIP_MAGIC):
            self._head += chunk[: len(_GZIP_MAGIC) - len(self._head)]
            if not _GZIP_MAGIC.startswith(self._head):
                raise RepositoryDataError("content_type")
        self._compressed_hash.update(chunk)
        data = chunk
        while data:
            if self._decompressor.eof:
                raise RepositoryDataError("gzip")
            self._accept(self._decompress(data))
            data = self._decompressor.unconsumed_tail
        if self._decompressor.unused_data:
            raise RepositoryDataError("gzip")

    def close(self) -> UpdateinfoSnapshot:
        identity = self._identity
        if self._compressed != identity.size:
            raise RepositoryDataError("size")
        while not self._decompressor.eof:
            output = self._decompress(b"")
            if not output:
                break
            self._accept(output)
        if not self._decompressor.eof or self._decompressor.unused_data:
            raise RepositoryDataError("gzip")
        if self._open != identity.open_size:
            raise RepositoryDataError("size")
        if (
            self._compressed_hash.hexdigest() != identity.checksum
            or self._open_hash.hexdigest() != identity.open_checksum
        ):
            raise RepositoryDataError("checksum")
        return self._parser.close()

    def _decompress(self, data: bytes) -> bytes:
        try:
            return self._decompressor.decompress(data, _DECOMPRESS_CHUNK)
        except zlib.error:
            raise RepositoryDataError("gzip") from None

    def _accept(self, output: bytes) -> None:
        if not output:
            return
        self._open += len(output)
        # `open_size` is within the absolute and ratio limits (repomd
        # contract), so this bound enforces both while decompressing.
        if self._open > self._identity.open_size:
            raise RepositoryDataError("size")
        self._open_hash.update(output)
        self._parser.feed(output)
