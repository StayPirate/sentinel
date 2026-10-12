"""Tests for one repository examination of the IBS Product download boundary.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Download Origin and Repository Paths: anonymous requests; HTTP and Redirect
Contract; Repomd Contract with Checksums; Resource and XML Safety; Snapshot
Consistency; the failure rows of Repository Traversal), docs/features/
integrations/ibs-integration.md (Origins and Authentication, Business Rule 1,
Security), docs/features/platform/networking.md (Transport-Level Retry before
classification; Redirect Policy, IBS Product-repodata exception), and
docs/conventions.md (External String Admissibility: an inadmissible
character in `repomd.xml` or updateinfo is the repository's XML failure).

The parser-level matrices of `ibs_repodata`, `ibs_updateinfo`, and
`xml_safety` have their own tests; these tests drive the composed boundary
(`ProductRepositoryDownloads`) through `httpx.MockTransport` with fictional
repositories from `tests/support/ibs_download.py` and assert the
occurrence outcome, the bounded failure category, and the exact requests.
No network, database, or Redis is used.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Final
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services import http_client
from app.services.packages.ibs_product_download import (
    ProductReleaseIncomplete,
    ProductReleaseMatch,
    ProductReleaseNoMatch,
    ProductReleaseObservation,
)
from app.services.packages.ibs_repodata import (
    REPOMD_MAX_BYTES,
    REPOMD_MAX_DEPTH,
    REPOMD_MAX_ELEMENTS,
    UPDATEINFO_MAX_COMPRESSED_BYTES,
    UPDATEINFO_MAX_OPEN_BYTES,
    UPDATEINFO_MAX_RATIO,
    RepositoryFailureCategory,
)
from app.services.packages.ibs_updateinfo import (
    UPDATEINFO_MAX_DEPTH,
    UPDATEINFO_MAX_UPDATES,
    UpdateinfoParser,
)
from tests.support.ibs_download import (
    DEFAULT_CVE,
    DEFAULT_PACKAGE,
    REDIRECT_HOST,
    Artifact,
    DownloadServer,
    Responder,
    StreamedBody,
    advisory,
    artifact,
    candidate,
    gzip_member,
    gzip_response,
    observe,
    redirect_response,
    repomd_document,
    repository_path,
    source_package,
    streamed_response,
    unread_response,
    updateinfo_data,
    updateinfo_document,
    xml_response,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, NUL, SURROGATE

pytestmark = pytest.mark.unit

REPO: Final = "SUSE:Updates:Example:1:x86_64"
MATCH_ID: Final = "SUSE-Example-2024-1"
MATCH_ADVISORY: Final = advisory(
    MATCH_ID, cves=[DEFAULT_CVE], sources=[DEFAULT_PACKAGE]
)
MATCH_DOCUMENT: Final = updateinfo_document(MATCH_ADVISORY)
DOWNLOAD_HOST: Final = "download.example.test"
DIST: Final = f"https://{REDIRECT_HOST}"
INJECT: Final = "QQINJECTQQ"
REPOMD_TYPE: Final = 'application/xml;name="repomd.xml"'


def _artifact(checksum_type: str = "sha256") -> Artifact:
    return artifact(MATCH_DOCUMENT, checksum_type=checksum_type)


def _stored(open_bytes: bytes) -> Artifact:
    """An artifact compressed without deflate compression (ratio ~1)."""
    compressed = gzip.compress(open_bytes, compresslevel=0, mtime=0)
    return Artifact(compressed=compressed, open_bytes=open_bytes)


def _with(item: Artifact, *, timestamp: int | None = None) -> Artifact:
    return Artifact(
        compressed=item.compressed,
        open_bytes=item.open_bytes,
        checksum_type=item.checksum_type,
        timestamp=item.timestamp if timestamp is None else timestamp,
        location=item.location,
    )


def _repomd(item: Artifact | None = None, **overrides: str) -> bytes:
    """A repomd document declaring `item`, with child-markup overrides."""
    if item is None:
        return repomd_document()
    return repomd_document(updateinfo_data(item, overrides=overrides))


def _xml(document: bytes, content_type: str = REPOMD_TYPE) -> Responder:
    """A repeatable responder serving `document` as `repomd.xml`."""
    return lambda _: xml_response(document, content_type=content_type)


def _status(status: int) -> Responder:
    return lambda _: httpx.Response(
        status, headers={"Content-Type": "text/html"}, content=b"<html/>"
    )


def _raise(error: BaseException) -> Responder:
    def respond(_: httpx.Request) -> httpx.Response:
        raise error

    return respond


def _stream(
    body: StreamedBody,
    content_type: str,
    headers: list[tuple[str, str]] | None = None,
) -> Responder:
    return lambda _: streamed_response(body, content_type=content_type, headers=headers)


def _server(item: Artifact | None = None) -> DownloadServer:
    server = DownloadServer()
    server.add(REPO, item if item is not None else _artifact())
    return server


def _serve_artifact(server: DownloadServer, item: Artifact) -> None:
    """Serve `item` at its own href with the live-shaped 302 to dist."""
    dist = server.artifact_url(REPO, item, host=REDIRECT_HOST)
    server.script(server.artifact_url(REPO, item), lambda _: redirect_response(dist))
    server.script(dist, lambda _: gzip_response(item.compressed))


async def _observe(
    server: DownloadServer, client: httpx.AsyncClient | None = None
) -> ProductReleaseObservation:
    async with client or server.client() as active:
        [outcome] = await observe(active, candidate(current=[REPO]))
    return outcome


def _assert_incomplete(
    outcome: ProductReleaseObservation,
    category: RepositoryFailureCategory,
    http_status: int | None = None,
) -> None:
    assert outcome == ProductReleaseIncomplete(
        repository=REPO, reason_category=category, http_status=http_status
    )


def _assert_matched(outcome: ProductReleaseObservation) -> None:
    assert isinstance(outcome, ProductReleaseMatch)
    assert outcome.repository == REPO
    assert outcome.advisory_id == MATCH_ID


def _repomd_url(server: DownloadServer, host: str = DOWNLOAD_HOST) -> str:
    return server.repomd_url(REPO, host=host)


def _dist_url(server: DownloadServer, item: Artifact) -> str:
    return server.artifact_url(REPO, item, host=REDIRECT_HOST)


def _hosts(server: DownloadServer) -> list[str]:
    return [request.url.host for request in server.requests]


def _artifact_requests(server: DownloadServer) -> list[httpx.Request]:
    return [r for r in server.requests if r.url.path.endswith(".xml.gz")]


def _chunks(data: bytes, size: int = 1024) -> Iterator[bytes]:
    for offset in range(0, len(data), size):
        yield data[offset : offset + size]


# ---------------------------------------------------------------------------
# Accepted examination and request shape
# ---------------------------------------------------------------------------


class TestAcceptedExamination:
    async def test_live_shaped_repository_matches_with_exact_requests(self) -> None:
        item = _artifact()
        server = _server(item)

        outcome = await _observe(server)

        _assert_matched(outcome)
        assert [str(request.url) for request in server.requests] == [
            _repomd_url(server),
            server.artifact_url(REPO, item),
            _dist_url(server, item),
            _repomd_url(server),
        ]

    async def test_artifact_served_directly_without_redirect_is_accepted(
        self,
    ) -> None:
        item = _artifact()
        server = DownloadServer()
        server.add(REPO, item, direct=True)

        _assert_matched(await _observe(server))
        assert REDIRECT_HOST not in _hosts(server)

    async def test_302_for_repomd_fails_without_following(self) -> None:
        # The one-redirect exception covers the metadata artifact only.
        item = _artifact()
        server = _server(item)
        dist_repomd = _repomd_url(server, REDIRECT_HOST)
        server.script(_repomd_url(server), lambda _: redirect_response(dist_repomd))
        server.script(dist_repomd, _xml(_repomd(item)))

        _assert_incomplete(await _observe(server), "redirect", 302)
        assert server.requests_to(dist_repomd) == []

    async def test_every_request_is_anonymous_identity_get_despite_client_defaults(
        self,
    ) -> None:
        item = _artifact()
        server = _server(item)
        # The redirect also tries to plant a cookie in the client's jar.
        server.script(
            server.artifact_url(REPO, item),
            lambda _: httpx.Response(
                302,
                headers={
                    "Location": _dist_url(server, item),
                    "Set-Cookie": "planted=fictional-planted; Path=/",
                },
            ),
        )
        client = httpx.AsyncClient(
            transport=server.transport(),
            headers={
                "Authorization": "Bearer fictional-token",
                "X-Api-Key": "fictional-key",
                "PRIVATE-TOKEN": "fictional-private",
                "User-Agent": "Sentinel/test (fictional)",
            },
            params={"apikey": "fictional-param"},
            auth=("fictional-user", "fictional-pass"),
            cookies={"session": "fictional"},
            follow_redirects=True,
            timeout=httpx.Timeout(10.0, read=120.0),
        )
        # Control: the client attaches every default to an ordinary request.
        control = client.build_request("GET", _repomd_url(server))
        assert control.headers["authorization"] == "Bearer fictional-token"
        assert control.headers["x-api-key"] == "fictional-key"
        assert control.headers["cookie"] == "session=fictional"
        assert control.url.query == b"apikey=fictional-param"

        outcome = await _observe(server, client)

        _assert_matched(outcome)
        assert len(server.requests) == 4
        for request in server.requests:
            assert request.method == "GET"
            assert request.url.query == b""
            assert set(request.headers) == {
                "host",
                "accept",
                "accept-encoding",
                "user-agent",
            }
            assert request.headers["accept-encoding"] == "identity"
            # Only the client's User-Agent and timeout are inherited.
            assert request.headers["user-agent"] == "Sentinel/test (fictional)"
            assert request.extensions["timeout"] == {
                "connect": 10.0,
                "read": 120.0,
                "write": 10.0,
                "pool": 10.0,
            }
        assert "application/xml" in server.requests[0].headers["accept"]
        assert "gzip" in server.requests[1].headers["accept"]
        assert "gzip" in server.requests[2].headers["accept"]

    async def test_shared_factory_client_supplies_user_agent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = _artifact()
        server = _server(item)
        monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: server.transport())
        client = http_client.create_http_client("detect_ibs_product_releases")

        _assert_matched(await _observe(server, client))
        for request in server.requests:
            assert request.headers["user-agent"].startswith("Sentinel/")
            assert "detect_ibs_product_releases" in request.headers["user-agent"]
            assert request.headers["accept-encoding"] == "identity"

    async def test_client_following_redirects_does_not_follow_a_second_one(
        self,
    ) -> None:
        item = _artifact()
        server = _server(item)
        dist = _dist_url(server, item)
        server.script(dist, lambda _: redirect_response(dist))
        client = httpx.AsyncClient(transport=server.transport(), follow_redirects=True)

        _assert_incomplete(await _observe(server, client), "redirect", 302)
        assert len(server.requests_to(dist)) == 1


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------

_NON_COMPLIANT_LOCATIONS: Final[dict[str, Callable[[str], str]]] = {
    "other-host": lambda p: f"https://dist.example.test{p}",
    "same-origin": lambda p: f"https://{DOWNLOAD_HOST}{p}",
    "http-downgrade": lambda p: f"http://{REDIRECT_HOST}{p}",
    "other-scheme": lambda p: f"ftp://{REDIRECT_HOST}{p}",
    "explicit-default-port": lambda p: f"https://{REDIRECT_HOST}:443{p}",
    "other-port": lambda p: f"https://{REDIRECT_HOST}:8443{p}",
    "userinfo": lambda p: f"https://fictional-user@{REDIRECT_HOST}{p}",
    "query": lambda p: f"{DIST}{p}?mirror=1",
    "empty-query": lambda p: f"{DIST}{p}?",
    "fragment": lambda p: f"{DIST}{p}#fragment",
    "empty-fragment": lambda p: f"{DIST}{p}#",
    "host-case": lambda p: f"https://DIST.SUSE.DE{p}",
    "host-trailing-dot": lambda p: f"https://{REDIRECT_HOST}.{p}",
    "host-suffix": lambda p: f"https://{REDIRECT_HOST}.example.test{p}",
    "path-change": lambda p: (
        f"{DIST}/RH.epam/RH7.0-LT/x86_64/{p.rsplit('/', 2)[-2]}/{p.rsplit('/', 1)[-1]}"
    ),
    "path-prefix-dropped": lambda p: f"{DIST}{p.removeprefix('/ibs')}",
    "trailing-slash": lambda p: f"{DIST}{p}/",
    "duplicate-separator": lambda p: f"{DIST}/{p}",
    "percent-encoded": lambda p: f"{DIST}{p.replace('/SUSE/', '/%53USE/')}",
    "dot-segment": lambda p: f"{DIST}{p.replace('/ibs/', '/ibs/./')}",
    "dot-dot-segment": lambda p: f"{DIST}/ibs/../ibs{p.removeprefix('/ibs')}",
    "backslash": lambda p: DIST + p.replace("/update/", "/update\\"),
    "relative": lambda p: p,
    "scheme-relative": lambda p: f"//{REDIRECT_HOST}{p}",
    "trailing-space": lambda p: f"{DIST}{p} ",
    "inner-space": lambda p: f"{DIST}{p.replace('/update/', '/up date/')}",
    "empty": lambda p: "",
}


class TestRedirect:
    @pytest.mark.parametrize("kind", list(_NON_COMPLIANT_LOCATIONS))
    async def test_non_compliant_artifact_302_fails_without_following(
        self, kind: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        location = _NON_COMPLIANT_LOCATIONS[kind](
            f"{repository_path(REPO)}/{item.href}"
        )
        server.script(
            server.artifact_url(REPO, item), lambda _: redirect_response(location)
        )

        _assert_incomplete(await _observe(server), "redirect", 302)
        assert _hosts(server) == [DOWNLOAD_HOST, DOWNLOAD_HOST]

    async def test_302_without_location_fails(self) -> None:
        item = _artifact()
        server = _server(item)
        server.script(server.artifact_url(REPO, item), _status(302))

        _assert_incomplete(await _observe(server), "redirect", 302)
        assert REDIRECT_HOST not in _hosts(server)

    async def test_302_with_two_identical_location_headers_fails(self) -> None:
        item = _artifact()
        server = _server(item)
        target = _dist_url(server, item)
        server.script(
            server.artifact_url(REPO, item),
            lambda _: httpx.Response(302, headers=[("Location", target)] * 2),
        )

        _assert_incomplete(await _observe(server), "redirect", 302)
        assert REDIRECT_HOST not in _hosts(server)

    @pytest.mark.parametrize("resource", ["repomd", "artifact"])
    async def test_302_with_unparseable_location_fails_as_redirect(
        self, resource: str
    ) -> None:
        # httpx rejects the `Location` itself and closes the response, so
        # the status code is not available to the classification.
        item = _artifact()
        server = _server(item)
        if resource == "repomd":
            url, target = _repomd_url(server), _repomd_url(server, REDIRECT_HOST)
        else:
            url, target = server.artifact_url(REPO, item), _dist_url(server, item)
        server.script(url, lambda _: redirect_response(f"{target}\t"))

        _assert_incomplete(await _observe(server), "redirect")
        assert REDIRECT_HOST not in _hosts(server)

    async def test_remote_protocol_error_other_than_location_is_transport(
        self,
    ) -> None:
        server = _server()

        def broken(request: httpx.Request) -> httpx.Response:
            raise httpx.RemoteProtocolError("Server disconnected", request=request)

        server.script(_repomd_url(server), broken)

        _assert_incomplete(await _observe(server), "transport")

    async def test_302_with_non_ascii_location_fails(self) -> None:
        item = _artifact()
        server = _server(item)
        target = _dist_url(server, item).replace("update", "updäte")
        server.script(
            server.artifact_url(REPO, item),
            lambda _: httpx.Response(302, headers=[(b"Location", target.encode())]),
        )

        _assert_incomplete(await _observe(server), "redirect", 302)
        assert REDIRECT_HOST not in _hosts(server)

    @pytest.mark.parametrize("status", [300, 301, 303, 304, 307, 308])
    @pytest.mark.parametrize("resource", ["repomd", "artifact"])
    async def test_other_3xx_with_compliant_location_fails(
        self, status: int, resource: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        if resource == "repomd":
            url, target = _repomd_url(server), _repomd_url(server, REDIRECT_HOST)
        else:
            url, target = server.artifact_url(REPO, item), _dist_url(server, item)
        server.script(url, lambda _: redirect_response(target, status=status))

        _assert_incomplete(await _observe(server), "redirect", status)
        assert REDIRECT_HOST not in _hosts(server)

    @pytest.mark.parametrize("status", [301, 302, 307])
    async def test_second_redirect_from_dist_fails(self, status: int) -> None:
        item = _artifact()
        server = _server(item)
        url, target = server.artifact_url(REPO, item), _dist_url(server, item)
        server.script(url, lambda _: redirect_response(target))
        server.script(target, lambda _: redirect_response(target, status=status))

        _assert_incomplete(await _observe(server), "redirect", status)
        assert len(server.requests_to(target)) == 1


# ---------------------------------------------------------------------------
# HTTP status, transport, timeout, and shared retries
# ---------------------------------------------------------------------------

_SEND_FAILURES: Final = [
    pytest.param(httpx.ConnectError, "transport", id="ConnectError"),
    pytest.param(httpx.ReadError, "transport", id="ReadError"),
    pytest.param(httpx.RemoteProtocolError, "transport", id="RemoteProtocolError"),
    pytest.param(httpx.ProxyError, "transport", id="ProxyError"),
    pytest.param(httpx.ConnectTimeout, "timeout", id="ConnectTimeout"),
    pytest.param(httpx.ReadTimeout, "timeout", id="ReadTimeout"),
    pytest.param(httpx.PoolTimeout, "timeout", id="PoolTimeout"),
]
_BODY_FAILURES: Final = [
    pytest.param(httpx.ReadError, "transport", id="ReadError"),
    pytest.param(httpx.RemoteProtocolError, "transport", id="RemoteProtocolError"),
    pytest.param(httpx.ReadTimeout, "timeout", id="ReadTimeout"),
]


class TestStatusClassification:
    @pytest.mark.parametrize("status", [400, 401, 403, 410, 429, 500, 503])
    async def test_repomd_non_success_status_is_http_status(self, status: int) -> None:
        server = _server()
        server.script(_repomd_url(server), _status(status))

        _assert_incomplete(await _observe(server), "http_status", status)
        assert len(server.requests) == 1

    @pytest.mark.parametrize("status", [403, 404, 410, 429, 500])
    async def test_artifact_non_success_status_is_http_status(
        self, status: int
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(_dist_url(server, item), _status(status))

        _assert_incomplete(await _observe(server), "http_status", status)
        assert len(server.requests_to(_repomd_url(server))) == 1

    async def test_repomd_404_is_successful_non_match(self) -> None:
        server = DownloadServer()

        assert await _observe(server) == ProductReleaseNoMatch()
        assert len(server.requests) == 1

    @pytest.mark.parametrize(("error", "category"), _SEND_FAILURES)
    @pytest.mark.parametrize("resource", ["repomd", "artifact"])
    async def test_failure_at_send_is_classified(
        self,
        error: type[httpx.TransportError],
        category: RepositoryFailureCategory,
        resource: str,
    ) -> None:
        item = _artifact()
        server = _server(item)
        url = _repomd_url(server) if resource == "repomd" else _dist_url(server, item)
        server.script(url, _raise(error("fictional failure")))

        _assert_incomplete(await _observe(server), category)

    @pytest.mark.parametrize(("error", "category"), _BODY_FAILURES)
    @pytest.mark.parametrize("resource", ["repomd", "artifact"])
    async def test_failure_mid_body_is_classified(
        self,
        error: type[httpx.TransportError],
        category: RepositoryFailureCategory,
        resource: str,
    ) -> None:
        item = _artifact()
        server = _server(item)
        if resource == "repomd":
            body = StreamedBody([_repomd(item)[:100]], error=error("fictional"))
            server.script(_repomd_url(server), _stream(body, "application/xml"))
        else:
            body = StreamedBody([item.compressed[:10]], error=error("fictional"))
            server.script(_dist_url(server, item), _stream(body, "application/x-gzip"))

        _assert_incomplete(await _observe(server), category)
        assert body.exhausted


def _shared_client(
    monkeypatch: pytest.MonkeyPatch, server: DownloadServer
) -> tuple[httpx.AsyncClient, AsyncMock]:
    """A real `create_http_client` client whose network transport is `server`.

    The shared retry transport is real; its backoff sleep is recorded
    instead of awaited. Environment proxies are cleared so no proxy mount
    bypasses the substituted transport.
    """
    sleep = AsyncMock()
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=sleep))
    for variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: server.transport())
    return http_client.create_http_client("ibs-product-download-test"), sleep


class TestSharedRetries:
    async def test_transient_503_retried_by_shared_client_then_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _repomd_url(server),
            httpx.Response(503),
            httpx.Response(503),
            _xml(_repomd(item)),
        )
        client, sleep = _shared_client(monkeypatch, server)

        _assert_matched(await _observe(server, client))
        assert len(server.requests_to(_repomd_url(server))) == 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0]
        for request in server.requests:
            assert request.headers["accept-encoding"] == "identity"
            assert "authorization" not in request.headers

    @pytest.mark.parametrize("resource", ["repomd", "artifact"])
    async def test_persistent_500_after_shared_retries_is_http_status(
        self, monkeypatch: pytest.MonkeyPatch, resource: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        url = _repomd_url(server) if resource == "repomd" else _dist_url(server, item)
        server.script(url, _status(500))
        client, sleep = _shared_client(monkeypatch, server)

        _assert_incomplete(await _observe(server, client), "http_status", 500)
        assert len(server.requests_to(url)) == 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]

    @pytest.mark.parametrize(
        ("error", "category"),
        [
            pytest.param(httpx.ConnectError, "transport", id="transport"),
            pytest.param(httpx.ReadTimeout, "timeout", id="timeout"),
        ],
    )
    async def test_persistent_send_failure_after_shared_retries_is_classified(
        self,
        monkeypatch: pytest.MonkeyPatch,
        error: type[httpx.TransportError],
        category: RepositoryFailureCategory,
    ) -> None:
        server = _server()
        server.script(_repomd_url(server), _raise(error("fictional failure")))
        client, sleep = _shared_client(monkeypatch, server)

        _assert_incomplete(await _observe(server, client), category)
        assert len(server.requests) == 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]

    async def test_429_without_retry_after_is_not_retried_and_is_http_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = _server()
        server.script(_repomd_url(server), _status(429))
        client, sleep = _shared_client(monkeypatch, server)

        _assert_incomplete(await _observe(server, client), "http_status", 429)
        assert len(server.requests) == 1
        sleep.assert_not_awaited()


# ---------------------------------------------------------------------------
# Media types and gzip magic
# ---------------------------------------------------------------------------


class TestMediaType:
    @pytest.mark.parametrize(
        "content_type",
        [
            "application/xml",
            "text/xml",
            'application/xml;name="repomd.xml"',
            "Application/XML; charset=UTF-8",
            "TEXT/xml ; charset=utf-8",
            'text/xml;charset="utf-8";name=repomd',
        ],
    )
    async def test_repomd_accepted_media_type(self, content_type: str) -> None:
        item = _artifact()
        server = _server(item)
        server.script(_repomd_url(server), _xml(_repomd(item), content_type))

        _assert_matched(await _observe(server))

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([("Content-Type", "text/html")], id="text-html"),
            pytest.param([("Content-Type", "application/json")], id="json"),
            pytest.param([("Content-Type", "application/x-gzip")], id="gzip"),
            pytest.param([("Content-Type", "application/rss+xml")], id="other-xml"),
            pytest.param([("Content-Type", "")], id="empty"),
            pytest.param([("Content-Type", "application/xml;charset")], id="param"),
            pytest.param([("Content-Type", "application/xml;=x")], id="no-name"),
            pytest.param([("Content-Type", 'application/xml;a="x')], id="quote"),
            pytest.param([("Content-Type", "application/xml, text/xml")], id="list"),
            pytest.param([("Content-Type", "application /xml")], id="space"),
            pytest.param([("Content-Type", "application")], id="no-subtype"),
            pytest.param([], id="missing"),
            pytest.param([("Content-Type", "application/xml")] * 2, id="duplicated"),
        ],
    )
    async def test_repomd_rejected_media_type(
        self, headers: list[tuple[str, str]]
    ) -> None:
        item = _artifact()
        server = _server(item)
        document = _repomd(item)
        server.script(
            _repomd_url(server),
            lambda _: unread_response(200, headers, document),
        )

        _assert_incomplete(await _observe(server), "content_type")
        assert _artifact_requests(server) == []

    @pytest.mark.parametrize(
        "content_type",
        [
            "application/gzip",
            "application/x-gzip",
            "Application/X-GZIP; name=updateinfo",
            'application/x-gzip;name="x-updateinfo.xml.gz"',
        ],
    )
    async def test_updateinfo_accepted_media_type(self, content_type: str) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _dist_url(server, item),
            lambda _: gzip_response(item.compressed, content_type=content_type),
        )

        _assert_matched(await _observe(server))

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([("Content-Type", "application/octet-stream")], id="octet"),
            pytest.param([("Content-Type", "application/xml")], id="xml"),
            pytest.param([("Content-Type", "text/html")], id="html"),
            pytest.param([("Content-Type", "application/x-gzip; x")], id="param"),
            pytest.param([], id="missing"),
            pytest.param([("Content-Type", "application/gzip")] * 2, id="duplicated"),
        ],
    )
    async def test_updateinfo_rejected_media_type(
        self, headers: list[tuple[str, str]]
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _dist_url(server, item),
            lambda _: unread_response(200, headers, item.compressed),
        )

        _assert_incomplete(await _observe(server), "content_type")

    @pytest.mark.parametrize(
        "compressed",
        [
            pytest.param(MATCH_DOCUMENT, id="plain-xml"),
            pytest.param(b"\x1f\x8c" + gzip_member(MATCH_DOCUMENT)[2:], id="second"),
            pytest.param(b"\x8b\x1f" + gzip_member(MATCH_DOCUMENT)[2:], id="swapped"),
        ],
    )
    async def test_updateinfo_without_gzip_magic_is_content_type(
        self, compressed: bytes
    ) -> None:
        server = _server(Artifact(compressed=compressed, open_bytes=MATCH_DOCUMENT))

        _assert_incomplete(await _observe(server), "content_type")


# ---------------------------------------------------------------------------
# Content-Length and transfer limits
# ---------------------------------------------------------------------------

_MALFORMED_LENGTHS: Final = [
    pytest.param(["{n}", "{n}"], id="duplicate-equal"),
    pytest.param(["{n}", "1"], id="duplicate-conflicting"),
    pytest.param(["+{n}"], id="plus-sign"),
    pytest.param(["-{n}"], id="minus-sign"),
    pytest.param(["0x{n}"], id="hexadecimal"),
    pytest.param(["{n}.0"], id="fraction"),
    pytest.param(["{n}, {n}"], id="comma-list"),
    pytest.param([""], id="empty"),
    pytest.param([" {n}"], id="whitespace"),
]


class TestRepomdContentLength:
    @pytest.mark.parametrize("values", _MALFORMED_LENGTHS)
    async def test_malformed_content_length_is_size(self, values: list[str]) -> None:
        item = _artifact()
        server = _server(item)
        document = _repomd(item)
        headers = [
            ("Content-Length", v.replace("{n}", str(len(document)))) for v in values
        ]
        server.script(
            _repomd_url(server),
            _stream(StreamedBody([document]), "application/xml", headers=headers),
        )

        _assert_incomplete(await _observe(server), "size")
        assert _artifact_requests(server) == []

    @pytest.mark.parametrize("delta", [-1, 1])
    async def test_content_length_differing_from_actual_bytes_is_size(
        self, delta: int
    ) -> None:
        item = _artifact()
        server = _server(item)
        document = _repomd(item)
        headers = [("Content-Length", str(len(document) + delta))]
        server.script(
            _repomd_url(server),
            _stream(StreamedBody([document]), "application/xml", headers=headers),
        )

        _assert_incomplete(await _observe(server), "size")
        assert _artifact_requests(server) == []

    async def test_exact_content_length_is_accepted(self) -> None:
        item = _artifact()
        server = _server(item)
        document = _repomd(item)
        headers = [("Content-Length", str(len(document)))]
        server.script(
            _repomd_url(server),
            lambda _: streamed_response(
                StreamedBody(_chunks(document, 100)),
                content_type="application/xml",
                headers=headers,
            ),
        )

        _assert_matched(await _observe(server))

    async def test_content_length_over_limit_fails_before_reading(self) -> None:
        server = _server()
        body = StreamedBody(b"x" for _ in range(REPOMD_MAX_BYTES + 1))
        headers = [("Content-Length", str(REPOMD_MAX_BYTES + 1))]
        server.script(
            _repomd_url(server), _stream(body, "application/xml", headers=headers)
        )

        _assert_incomplete(await _observe(server), "resource_limit")
        assert body.yielded == 0

    async def test_streamed_body_over_limit_without_content_length_aborts(
        self,
    ) -> None:
        server = _server()
        body = StreamedBody(b" " * 1024 for _ in range(4 * REPOMD_MAX_BYTES // 1024))
        server.script(_repomd_url(server), _stream(body, "application/xml"))

        _assert_incomplete(await _observe(server), "resource_limit")
        assert body.yielded == REPOMD_MAX_BYTES // 1024 + 1
        assert not body.exhausted

    async def test_body_at_limit_without_content_length_is_parsed(self) -> None:
        item = _artifact()
        server = _server(item)
        document = _repomd(item)
        padding = b" " * (REPOMD_MAX_BYTES - len(document))
        padded = document.replace(b"</repomd>", padding + b"</repomd>")
        assert len(padded) == REPOMD_MAX_BYTES
        server.script(
            _repomd_url(server),
            lambda _: streamed_response(
                StreamedBody(_chunks(padded)), content_type="application/xml"
            ),
        )

        _assert_matched(await _observe(server))


class TestUpdateinfoContentLength:
    async def test_content_length_over_compressed_limit_fails_before_reading(
        self,
    ) -> None:
        item = _artifact()
        server = _server(item)
        body = StreamedBody([item.compressed])
        headers = [("Content-Length", str(UPDATEINFO_MAX_COMPRESSED_BYTES + 1))]
        server.script(
            _dist_url(server, item),
            _stream(body, "application/x-gzip", headers=headers),
        )

        _assert_incomplete(await _observe(server), "resource_limit")
        assert body.yielded == 0

    @pytest.mark.parametrize("delta", [-1, 1])
    async def test_content_length_differing_from_repomd_size_fails_before_reading(
        self, delta: int
    ) -> None:
        item = _artifact()
        server = _server(item)
        body = StreamedBody([item.compressed])
        headers = [("Content-Length", str(len(item.compressed) + delta))]
        server.script(
            _dist_url(server, item),
            _stream(body, "application/x-gzip", headers=headers),
        )

        _assert_incomplete(await _observe(server), "size")
        assert body.yielded == 0

    @pytest.mark.parametrize("values", _MALFORMED_LENGTHS)
    async def test_malformed_content_length_is_size(self, values: list[str]) -> None:
        item = _artifact()
        server = _server(item)
        body = StreamedBody([item.compressed])
        size = str(len(item.compressed))
        headers = [("Content-Length", v.replace("{n}", size)) for v in values]
        server.script(
            _dist_url(server, item),
            _stream(body, "application/x-gzip", headers=headers),
        )

        _assert_incomplete(await _observe(server), "size")
        assert body.yielded == 0

    async def test_bytes_beyond_repomd_size_abort_without_content_length(
        self,
    ) -> None:
        item = _artifact()
        server = _server(item)
        body = StreamedBody([item.compressed, *(b"\x00" * 1024 for _ in range(64))])
        server.script(_dist_url(server, item), _stream(body, "application/x-gzip"))

        _assert_incomplete(await _observe(server), "size")
        assert body.yielded == 2
        assert not body.exhausted

    async def test_bytes_short_of_repomd_size_is_size(self) -> None:
        item = _artifact()
        server = _server(item)
        body = StreamedBody([item.compressed[:-1]])
        server.script(_dist_url(server, item), _stream(body, "application/x-gzip"))

        _assert_incomplete(await _observe(server), "size")

    async def test_chunked_body_without_content_length_is_accepted(self) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _dist_url(server, item),
            lambda _: streamed_response(
                StreamedBody(_chunks(item.compressed, 7)),
                content_type="application/x-gzip",
            ),
        )

        _assert_matched(await _observe(server))


# ---------------------------------------------------------------------------
# Declared sizes, gzip, and integrity
# ---------------------------------------------------------------------------


class TestDeclaredSizeLimits:
    @pytest.mark.parametrize(
        ("overrides", "category"),
        [
            pytest.param({"size": "<size>0</size>"}, "size", id="zero-byte"),
            pytest.param(
                {"size": f"<size>{UPDATEINFO_MAX_COMPRESSED_BYTES + 1}</size>"},
                "resource_limit",
                id="compressed-over-limit",
            ),
            pytest.param(
                {
                    "size": "<size>3000000</size>",
                    "open-size": "<open-size>"
                    f"{UPDATEINFO_MAX_OPEN_BYTES + 1}</open-size>",
                },
                "resource_limit",
                id="open-over-limit",
            ),
            pytest.param(
                {
                    "size": "<size>1000</size>",
                    "open-size": "<open-size>"
                    f"{1000 * UPDATEINFO_MAX_RATIO + 1}</open-size>",
                },
                "resource_limit",
                id="ratio-over-limit",
            ),
        ],
    )
    async def test_declared_size_outside_limits_fails_without_artifact_download(
        self, overrides: dict[str, str], category: RepositoryFailureCategory
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(_repomd_url(server), _xml(_repomd(item, **overrides)))

        _assert_incomplete(await _observe(server), category)
        assert _artifact_requests(server) == []


def _flip(data: bytes, index: int) -> bytes:
    mutable = bytearray(data)
    mutable[index] ^= 0xFF
    return bytes(mutable)


_MEMBER: Final = gzip_member(MATCH_DOCUMENT)


def _large_document(advisories: int) -> bytes:
    """A valid updateinfo document of several MiB with a moderate ratio.

    Each fictional advisory carries a distinct deterministic digest so
    that deflate cannot reach the 100:1 limit; the matching advisory is
    the last one, so every decompression step must be parsed.
    """
    fillers = [
        advisory(
            f"SUSE-Example-Filler-{index}",
            cves=[f"CVE-2023-{index:05d}"],
            sources=[f"filler{index}"],
            extra="<note>"
            + hashlib.sha256(str(index).encode()).hexdigest() * 4
            + "</note>",
        )
        for index in range(advisories)
    ]
    return updateinfo_document(*fillers, MATCH_ADVISORY)


class TestLargeArtifact:
    async def test_single_chunk_inflating_beyond_several_steps_is_accepted(
        self,
    ) -> None:
        document = _large_document(4_000)
        item = artifact(document)
        # One received chunk inflates to several 1 MiB decompression steps.
        assert len(document) > 3 * 1024 * 1024
        assert len(document) < len(item.compressed) * UPDATEINFO_MAX_RATIO
        server = _server(item)

        _assert_matched(await _observe(server))

    async def test_decompressed_bytes_beyond_open_size_fail_in_bounded_steps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A member that inflates beyond its declared open size stops at the
        # first decompression step that would exceed the declaration.
        document = _large_document(4_000)
        item = artifact(document)
        declared = len(document) // 4
        fed: list[int] = []
        original = UpdateinfoParser.feed

        def counting_feed(self: UpdateinfoParser, data: bytes) -> None:
            fed.append(len(data))
            original(self, data)

        monkeypatch.setattr(UpdateinfoParser, "feed", counting_feed)
        server = _server(item)
        server.script(
            _repomd_url(server),
            _xml(_repomd(item, **{"open-size": f"<open-size>{declared}</open-size>"})),
        )

        _assert_incomplete(await _observe(server), "size")
        assert declared > 1024 * 1024
        assert fed == [1024 * 1024]


class TestGzipIntegrity:
    @pytest.mark.parametrize(
        "compressed",
        [
            pytest.param(_MEMBER[:-4], id="truncated-trailer"),
            pytest.param(_MEMBER[:30], id="truncated-stream"),
            pytest.param(_MEMBER + _MEMBER, id="concatenated-members"),
            pytest.param(_MEMBER + b"\x00" * 8, id="zero-padding"),
            pytest.param(_MEMBER + b"\x00", id="one-zero-byte"),
            pytest.param(_MEMBER + b"junk", id="trailing-bytes"),
            pytest.param(_flip(_MEMBER, -8), id="crc"),
            pytest.param(_flip(_MEMBER, -1), id="isize"),
            pytest.param(_flip(_MEMBER, 3), id="header-flags"),
        ],
    )
    async def test_invalid_gzip_member_is_gzip(self, compressed: bytes) -> None:
        server = _server(Artifact(compressed=compressed, open_bytes=MATCH_DOCUMENT))

        _assert_incomplete(await _observe(server), "gzip")
        assert _hosts(server).count(REDIRECT_HOST) == 1

    @pytest.mark.parametrize(
        ("checksum_type", "field"),
        [
            ("sha256", "checksum"),
            ("sha256", "open-checksum"),
            ("sha", "checksum"),
            ("sha", "open-checksum"),
        ],
    )
    async def test_checksum_mismatch_is_checksum(
        self, checksum_type: str, field: str
    ) -> None:
        item = _artifact(checksum_type)
        length = {"sha256": 64, "sha": 40}[checksum_type]
        server = _server(item)
        markup = f'<{field} type="{checksum_type}">{"0" * length}</{field}>'
        server.script(_repomd_url(server), _xml(_repomd(item, **{field: markup})))

        _assert_incomplete(await _observe(server), "checksum")

    @pytest.mark.parametrize("checksum_type", ["sha256", "sha"])
    async def test_valid_checksums_match_in_either_case(
        self, checksum_type: str
    ) -> None:
        item = _artifact(checksum_type)
        server = _server(item)
        overrides = {
            "checksum": f'<checksum type="{checksum_type}">'
            f"{item.checksum.upper()}</checksum>",
            "open-checksum": f'<open-checksum type="{checksum_type}">'
            f"{item.open_checksum.upper()}</open-checksum>",
        }
        server.script(_repomd_url(server), _xml(_repomd(item, **overrides)))

        _assert_matched(await _observe(server))

    async def test_decompressed_bytes_short_of_open_size_is_size(self) -> None:
        item = _artifact()
        server = _server(item)
        open_size = f"<open-size>{len(item.open_bytes) + 1}</open-size>"
        server.script(
            _repomd_url(server), _xml(_repomd(item, **{"open-size": open_size}))
        )

        _assert_incomplete(await _observe(server), "size")

    async def test_decompressed_bytes_over_open_size_abort_while_streaming(
        self,
    ) -> None:
        item = _stored(updateinfo_document(MATCH_ADVISORY, " " * 200_000))
        server = _server(item)
        open_size = "<open-size>2000</open-size>"
        server.script(
            _repomd_url(server), _xml(_repomd(item, **{"open-size": open_size}))
        )
        body = StreamedBody(_chunks(item.compressed))
        server.script(_dist_url(server, item), _stream(body, "application/x-gzip"))

        _assert_incomplete(await _observe(server), "size")
        assert body.yielded < 10
        assert not body.exhausted


# ---------------------------------------------------------------------------
# Repomd structure through the boundary
# ---------------------------------------------------------------------------


class TestRepomdStructure:
    async def test_repomd_without_updateinfo_is_non_match_without_artifact(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(REPO, None)

        assert await _observe(server) == ProductReleaseNoMatch()
        assert len(server.requests) == 1

    async def test_two_updateinfo_entries_is_xml_structure(self) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _repomd_url(server),
            _xml(repomd_document(updateinfo_data(item), updateinfo_data(item))),
        )

        _assert_incomplete(await _observe(server), "xml_structure")
        assert len(server.requests) == 1

    @pytest.mark.parametrize(
        "href",
        [
            "../repodata/x.xml.gz",
            "repodata/../../x.xml.gz",
            "/repodata/x.xml.gz",
            "https://dist.suse.de/repodata/x.xml.gz",
            "//dist.suse.de/repodata/x.xml.gz",
            "repodata//x.xml.gz",
            "repodata/%2e%2e/x.xml.gz",
            "repodata/x.xml.gz?query",
            "repodata/x.xml.gz#fragment",
            "updateinfo.xml.gz",
        ],
    )
    async def test_unsafe_location_is_unsafe_path_without_artifact(
        self, href: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        location = f'<location href="{href}"/>'
        server.script(_repomd_url(server), _xml(_repomd(item, location=location)))

        _assert_incomplete(await _observe(server), "unsafe_path")
        assert len(server.requests) == 1

    @pytest.mark.parametrize("algorithm", ["md5", "sha512", "SHA256", ""])
    async def test_unsupported_checksum_is_checksum_without_artifact(
        self, algorithm: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        markup = f'<checksum type="{algorithm}">{item.checksum}</checksum>'
        server.script(_repomd_url(server), _xml(_repomd(item, checksum=markup)))

        _assert_incomplete(await _observe(server), "checksum")
        assert len(server.requests) == 1

    async def test_other_namespace_is_xml_structure(self) -> None:
        item = _artifact()
        server = _server(item)
        document = repomd_document(
            updateinfo_data(item), namespace="http://example.test/repo"
        )
        server.script(_repomd_url(server), _xml(document))

        _assert_incomplete(await _observe(server), "xml_structure")
        assert len(server.requests) == 1


# ---------------------------------------------------------------------------
# XML safety through the boundary
# ---------------------------------------------------------------------------

_DECLARATION: Final = b'<?xml version="1.0" encoding="UTF-8"?>\n'


def _with_prolog(document: bytes, prolog: bytes) -> bytes:
    assert document.startswith(_DECLARATION)
    return _DECLARATION + prolog + document[len(_DECLARATION) :]


def _nested(depth: int) -> bytes:
    return b"<a>" * depth + b"</a>" * depth


def _hostile_repomd_documents() -> list[object]:
    valid = _repomd(_artifact())
    return [
        pytest.param(
            _with_prolog(valid, b"<!DOCTYPE repomd>"), "xml_structure", id="dtd"
        ),
        pytest.param(
            _with_prolog(valid, b'<!DOCTYPE repomd [<!ENTITY e "x">]>'),
            "xml_structure",
            id="entity-declaration",
        ),
        pytest.param(
            _with_prolog(
                valid, b'<!DOCTYPE repomd SYSTEM "https://evil.example.test/x.dtd">'
            ),
            "xml_structure",
            id="external-dtd",
        ),
        pytest.param(
            _with_prolog(
                valid.replace(b"<revision>", b"<revision>&e;"),
                b'<!DOCTYPE repomd [<!ENTITY e SYSTEM "file:///etc/hostname">]>',
            ),
            "xml_structure",
            id="external-entity",
        ),
        pytest.param(
            valid.replace(b"<revision>", b"<revision>&undefined;"),
            "xml_structure",
            id="undefined-entity",
        ),
        pytest.param(valid[:-20], "xml_structure", id="unfinalized"),
        pytest.param(valid + b"<repomd/>", "xml_structure", id="second-root"),
        pytest.param(
            valid.replace(b"</repomd>", _nested(REPOMD_MAX_DEPTH) + b"</repomd>"),
            "resource_limit",
            id="depth",
        ),
        pytest.param(
            valid.replace(b"</repomd>", b"<a/>" * REPOMD_MAX_ELEMENTS + b"</repomd>"),
            "resource_limit",
            id="element-count",
        ),
    ]


def _hostile_updateinfo_documents() -> list[object]:
    valid = MATCH_DOCUMENT
    return [
        pytest.param(
            _with_prolog(valid, b"<!DOCTYPE updates>"), "xml_structure", id="dtd"
        ),
        pytest.param(
            _with_prolog(valid, b'<!DOCTYPE updates [<!ENTITY e "x">]>'),
            "xml_structure",
            id="entity-declaration",
        ),
        pytest.param(
            _with_prolog(
                valid.replace(b"</updates>", b"&e;</updates>"),
                b'<!DOCTYPE updates [<!ENTITY e SYSTEM "https://evil.example.test/">]>',
            ),
            "xml_structure",
            id="external-entity",
        ),
        pytest.param(
            valid.replace(b"</updates>", b"&undefined;</updates>"),
            "xml_structure",
            id="undefined-entity-after-match",
        ),
        pytest.param(
            valid.replace(b"</updates>", b""), "xml_structure", id="unfinalized"
        ),
        pytest.param(
            valid.replace(b"</updates>", b"<update><id>x</updates>"),
            "xml_structure",
            id="malformed-after-match",
        ),
        pytest.param(
            valid.replace(b"</updates>", _nested(UPDATEINFO_MAX_DEPTH) + b"</updates>"),
            "resource_limit",
            id="depth-after-match",
        ),
        pytest.param(
            valid.replace(
                b"</updates>", b"<update/>" * UPDATEINFO_MAX_UPDATES + b"</updates>"
            ),
            "resource_limit",
            id="update-count-after-match",
        ),
        pytest.param(
            valid.replace(b"<updates>", b'<updates xmlns="http://example.test/u">'),
            "xml_structure",
            id="namespaced-root",
        ),
    ]


class TestXMLSafety:
    @pytest.mark.parametrize(("document", "category"), _hostile_repomd_documents())
    async def test_hostile_repomd_fails_without_artifact_download(
        self, document: bytes, category: RepositoryFailureCategory
    ) -> None:
        server = _server()
        server.script(_repomd_url(server), _xml(document))

        _assert_incomplete(await _observe(server), category)
        assert len(server.requests) == 1

    @pytest.mark.parametrize(("document", "category"), _hostile_updateinfo_documents())
    async def test_hostile_updateinfo_fails_after_download_and_never_matches(
        self, document: bytes, category: RepositoryFailureCategory
    ) -> None:
        server = _server(_stored(document))

        _assert_incomplete(await _observe(server), category)
        assert _hosts(server).count(REDIRECT_HOST) == 1

    async def test_interrupted_body_with_matching_prefix_never_matches(self) -> None:
        item = _stored(MATCH_DOCUMENT)
        server = _server(item)
        body = StreamedBody(
            [item.compressed[: len(item.compressed) - 20]],
            error=httpx.ReadError("fictional reset"),
        )
        server.script(_dist_url(server, item), _stream(body, "application/x-gzip"))

        _assert_incomplete(await _observe(server), "transport")


# ---------------------------------------------------------------------------
# External String Admissibility (docs/conventions.md)
# ---------------------------------------------------------------------------

Encode = Callable[[str], bytes]


def _raw(character: str) -> bytes:
    return character.encode("utf-8", "surrogatepass")


def _decimal_reference(character: str) -> bytes:
    return f"&#{ord(character)};".encode()


def _hex_reference(character: str) -> bytes:
    return f"&#x{ord(character):X};".encode()


_ENCODINGS: Final = [
    pytest.param(_raw, id="raw"),
    pytest.param(_decimal_reference, id="decimal-reference"),
    pytest.param(_hex_reference, id="hex-reference"),
]


def _inject(document: bytes, payload: bytes) -> bytes:
    assert INJECT.encode() in document
    return document.replace(INJECT.encode(), payload)


_HOSTILE_UPDATES: Final = [
    pytest.param(
        advisory(f"SUSE-{INJECT}-1", cves=[DEFAULT_CVE], sources=[DEFAULT_PACKAGE]),
        id="advisory-id",
    ),
    pytest.param(
        advisory(
            MATCH_ID,
            cves=[DEFAULT_CVE, f"CVE-2024-{INJECT}"],
            sources=[DEFAULT_PACKAGE],
        ),
        id="cve-reference-id",
    ),
    pytest.param(
        advisory(
            MATCH_ID,
            cves=[DEFAULT_CVE],
            packages=[
                source_package(DEFAULT_PACKAGE),
                source_package(f"ex{INJECT}ample"),
            ],
        ),
        id="source-package-name",
    ),
    pytest.param(
        advisory(
            MATCH_ID,
            cves=[DEFAULT_CVE],
            sources=[DEFAULT_PACKAGE],
            issued=f"1717068854{INJECT}",
        ),
        id="issued-date",
    ),
    pytest.param(
        MATCH_ADVISORY.replace('status="stable"', f'status="stable{INJECT}"'),
        id="status",
    ),
]


class TestExternalStringAdmissibility:
    def test_payload_forms_are_the_required_bytes(self) -> None:
        assert _raw(NUL) == b"\x00"
        assert _raw(SURROGATE) == b"\xed\xa0\x80"
        assert _decimal_reference(NUL) == b"&#0;"
        assert _hex_reference(SURROGATE) == b"&#xD800;"

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize("encode", _ENCODINGS)
    @pytest.mark.parametrize("field", ["location", "checksum", "timestamp"])
    async def test_inadmissible_character_in_repomd_is_xml_failure(
        self, character: str, encode: Encode, field: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        markup = {
            "location": f'<location href="repodata/a{INJECT}b-updateinfo.xml.gz"/>',
            "checksum": f'<checksum type="sha256">{item.checksum[:-1]}{INJECT}'
            "</checksum>",
            "timestamp": f"<timestamp>{item.timestamp}{INJECT}</timestamp>",
        }[field]
        document = _inject(_repomd(item, **{field: markup}), encode(character))
        server.script(_repomd_url(server), _xml(document))

        _assert_incomplete(await _observe(server), "xml_structure")
        assert len(server.requests) == 1

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize("encode", _ENCODINGS)
    @pytest.mark.parametrize("update", _HOSTILE_UPDATES)
    async def test_inadmissible_character_in_updateinfo_is_xml_failure(
        self, character: str, encode: Encode, update: str
    ) -> None:
        hostile = _inject(
            updateinfo_document(MATCH_ADVISORY, update), encode(character)
        )
        server = _server(artifact(hostile))

        _assert_incomplete(await _observe(server), "xml_structure")
        assert _hosts(server).count(REDIRECT_HOST) == 1


# ---------------------------------------------------------------------------
# Snapshot consistency
# ---------------------------------------------------------------------------


class TestSnapshotConsistency:
    async def test_equal_snapshots_download_artifact_once(self) -> None:
        item = _artifact()
        server = _server(item)

        _assert_matched(await _observe(server))
        assert len(server.requests_to(_repomd_url(server))) == 2
        assert len(server.requests_to(server.artifact_url(REPO, item))) == 1
        assert len(server.requests_to(_dist_url(server, item))) == 1

    async def test_unrelated_repodata_change_does_not_restart(self) -> None:
        item = _artifact()
        server = _server(item)
        first = _repomd(item)
        second = (
            first.replace(b"<revision>1782862012</revision>", b"<revision>1</revision>")
            .replace(b"a" * 64, b"c" * 64)
            .replace(
                b"</repomd>",
                b'<data type="other"><location href="repodata/o.xml.gz"/></data>'
                b"</repomd>",
            )
        )
        assert first != second
        server.script(_repomd_url(server), _xml(first), _xml(second))

        _assert_matched(await _observe(server))
        assert len(server.requests_to(_repomd_url(server))) == 2
        assert _hosts(server).count(REDIRECT_HOST) == 1

    async def test_equivalent_checksum_case_does_not_restart(self) -> None:
        item = _artifact()
        server = _server(item)
        upper = _repomd(
            item, checksum=f'<checksum type="sha256">{item.checksum.upper()}</checksum>'
        )
        server.script(_repomd_url(server), _xml(upper), _xml(_repomd(item)))

        _assert_matched(await _observe(server))
        assert _hosts(server).count(REDIRECT_HOST) == 1

    async def test_changed_snapshot_restarts_once_with_second_snapshot(self) -> None:
        old = _artifact()
        new = artifact(
            updateinfo_document(
                advisory(
                    "SUSE-Example-2024-2",
                    cves=[DEFAULT_CVE],
                    sources=[DEFAULT_PACKAGE],
                    issued="1717000000",
                )
            )
        )
        server = _server(old)
        _serve_artifact(server, new)
        server.script(_repomd_url(server), _xml(_repomd(old)), _xml(_repomd(new)))

        outcome = await _observe(server)

        assert isinstance(outcome, ProductReleaseMatch)
        assert outcome.advisory_id == "SUSE-Example-2024-2"
        assert len(server.requests_to(_repomd_url(server))) == 3
        assert len(server.requests_to(_dist_url(server, old))) == 1
        assert len(server.requests_to(_dist_url(server, new))) == 1

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            ("location", None),
            ("timestamp", None),
            ("checksum", "checksum"),
            ("open-checksum", "checksum"),
            ("size", "size"),
            ("open-size", "size"),
        ],
    )
    async def test_each_identity_field_change_restarts(
        self, field: str, expected: RepositoryFailureCategory | None
    ) -> None:
        """A single changed tuple field restarts the examination; the second
        download is validated against the second snapshot."""
        item = _artifact()
        server = _server(item)
        moved = Artifact(
            compressed=item.compressed,
            open_bytes=item.open_bytes,
            location="repodata/other-updateinfo.xml.gz",
        )
        _serve_artifact(server, moved)
        changed = {
            "location": f'<location href="{moved.href}"/>',
            "timestamp": f"<timestamp>{item.timestamp + 1}</timestamp>",
            "checksum": f'<checksum type="sha256">{"0" * 64}</checksum>',
            "open-checksum": f'<open-checksum type="sha256">{"0" * 64}</open-checksum>',
            "size": f"<size>{len(item.compressed) + 1}</size>",
            "open-size": f"<open-size>{len(item.open_bytes) + 1}</open-size>",
        }[field]
        server.script(
            _repomd_url(server),
            _xml(_repomd(item)),
            _xml(_repomd(item, **{field: changed})),
        )

        outcome = await _observe(server)

        if expected is None:
            _assert_matched(outcome)
            assert len(server.requests_to(_repomd_url(server))) == 3
        else:
            _assert_incomplete(outcome, expected)
            assert len(server.requests_to(_repomd_url(server))) == 2
        assert _hosts(server).count(REDIRECT_HOST) == 2

    async def test_repeated_change_is_snapshot_changed(self) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _repomd_url(server),
            _xml(_repomd(item)),
            _xml(_repomd(_with(item, timestamp=item.timestamp + 1))),
            _xml(_repomd(_with(item, timestamp=item.timestamp + 2))),
        )

        _assert_incomplete(await _observe(server), "snapshot_changed")
        assert len(server.requests_to(_repomd_url(server))) == 3
        assert _hosts(server).count(REDIRECT_HOST) == 2

    @pytest.mark.parametrize("third", ["absent", "no-updateinfo"])
    async def test_disappearance_after_restart_is_snapshot_changed(
        self, third: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _repomd_url(server),
            _xml(_repomd(item)),
            _xml(_repomd(_with(item, timestamp=item.timestamp + 1))),
            _status(404) if third == "absent" else _xml(_repomd(None)),
        )

        _assert_incomplete(await _observe(server), "snapshot_changed")
        assert len(server.requests_to(_repomd_url(server))) == 3
        assert _hosts(server).count(REDIRECT_HOST) == 2

    @pytest.mark.parametrize("second", ["absent", "no-updateinfo"])
    async def test_disappeared_second_snapshot_is_non_match_without_second_download(
        self, second: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        server.script(
            _repomd_url(server),
            _xml(_repomd(item)),
            _status(404) if second == "absent" else _xml(_repomd(None)),
        )

        assert await _observe(server) == ProductReleaseNoMatch()
        assert len(server.requests_to(_repomd_url(server))) == 2
        assert _hosts(server).count(REDIRECT_HOST) == 1

    async def test_second_snapshot_failure_is_incomplete(self) -> None:
        item = _artifact()
        server = _server(item)
        server.script(_repomd_url(server), _xml(_repomd(item)), _status(503))

        _assert_incomplete(await _observe(server), "http_status", 503)
        assert _hosts(server).count(REDIRECT_HOST) == 1


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


class TestPropagation:
    @pytest.mark.parametrize(
        "error", [asyncio.CancelledError, MemoryError], ids=lambda e: e.__name__
    )
    @pytest.mark.parametrize("stage", ["send", "body"])
    async def test_error_raised_by_transport_propagates(
        self, error: type[BaseException], stage: str
    ) -> None:
        item = _artifact()
        server = _server(item)
        url = _dist_url(server, item)
        if stage == "send":
            server.script(url, _raise(error()))
        else:
            body = StreamedBody([item.compressed[:5]], error=error())
            server.script(url, _stream(body, "application/x-gzip"))

        with pytest.raises(error):
            await _observe(server)
