"""Shared IBS Product repository fixtures and a fake download server.

The files under `backend/tests/fixtures/ibs_download/` were captured
anonymously and read-only from the default `IBS_DOWNLOAD_BASE_URL`
(`https://download.suse.de/ibs`) on 2026-10-12
(docs/conventions.md, External Integration Contract Verification;
docs/features/packages/ibs-product-release-detection.md, External Contract
Verification Status):

- `repomd_<family>.xml` are complete `repodata/repomd.xml` documents
  stored as served, for a current repository
  (`SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64`), a historical one
  (`...:15-SP2:x86_64`), a suffixless one
  (`SUSE:Updates:openSUSE-Leap-Micro:5.5`), another architecture
  (`...:15-SP6:aarch64`), LTSS (`SUSE:Updates:SLE-SERVER:12-SP5-LTSS:x86_64`),
  ESPOS without updateinfo
  (`SUSE:Updates:SLE-Product-HPC:15-SP6-ESPOS:x86_64`), a source companion
  without updateinfo (`SUSE:Updates:RES:7-LTSS:src`, never requested by
  Sentinel), and a legacy SHA-1 repository
  (`SUSE:Updates:SLE-SERVER:11-SP4:x86_64`). They contain repository
  metadata only; no personal identifier was present.
- `updateinfo_<family>.xml` are the decompressed updateinfo documents of
  the current, suffixless, LTSS, and legacy SHA-1 repositories, trimmed to
  representative advisories: stable and retracted security advisories, a
  recommended advisory with a CVE, feature and optional advisories with an
  empty `references`, advisories with several source packages and with a
  `nosrc` entry, and two security advisories sharing CVEs. Each advisory's
  `from` address, `title`, `description`, `message`, and every reference
  `title` were replaced with fictional text; every advisory keeps at most
  three CVE and two other references and at most two binary packages per
  collection. IDs, issued times, references' type/id/href, and package
  entries are retained: they are consumed public data. Because they are
  trimmed, these documents do not match the checksums in the repomd
  fixtures; the fake server below builds consistent repomd documents.
- `responses.json` records, per request, the status, media type,
  `Content-Length` values, and redirect `Location`: every `repomd.xml`
  above, an absent repository and two Debian/Ubuntu targets (HTTP 404,
  never requested by Sentinel), an anonymous HTTP 403
  (`SUSE:Updates:SLL:9.4:x86_64`, status and media type only; its HTML
  body was not retained), an updateinfo artifact served directly
  (HTTP 200), the same-path HTTP 302 to `dist.suse.de` of the four
  captured artifacts with the verification that the complete downloaded
  bytes matched the repomd sizes and checksums, and a path-changing HTTP
  302 observed for a Red Hat-derived repository
  (`SUSE:Updates:RES:7-LTSS:x86_64`), which the contract treats as a
  repository failure.

`DownloadServer` is an `httpx.MockTransport` handler serving fictional
repositories under `TEST_BASE_URL` with live-shaped responses: `repomd.xml`
as `application/xml;name="repomd.xml"`, the updateinfo artifact as a
same-path 302 to `https://dist.suse.de` followed by `application/x-gzip`.
Tests register repositories, script exact responses per URL, and inspect
`requests`. Every response helper returns an unread body, as a real
transport does (`unread_response`). `StreamedBody` serves a lazily yielded body without
`Content-Length` (optionally failing mid-body) and counts the chunks it
handed out, so tests can prove that a download was aborted early.
`candidate()` and `observe()` drive one `ProductRepositoryDownloads`
invocation against such a client.

Consumers: `tests/test_services/test_packages/test_ibs_download_contract.py`
and the `test_ibs_*` boundary tests in the same directory.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from xml.sax.saxutils import escape, quoteattr

import httpx

from app.services.packages.ibs_product_download import (
    ProductOccurrenceCandidate,
    ProductReleaseObservation,
    ProductRepositoryDownloads,
)

FIXTURE_DIR: Final = (
    Path(__file__).resolve().parent.parent / "fixtures" / "ibs_download"
)

REPOMD_FIXTURES: Final = (
    "current",
    "historical",
    "suffixless",
    "architecture",
    "ltss",
    "espos_no_updateinfo",
    "source_no_updateinfo",
    "legacy_sha1",
)
REPOMD_WITH_UPDATEINFO: Final = (
    "current",
    "historical",
    "suffixless",
    "architecture",
    "ltss",
    "legacy_sha1",
)
UPDATEINFO_FIXTURES: Final = ("current", "suffixless", "ltss", "legacy_sha1")

TEST_BASE_URL: Final = "https://download.example.test/ibs"
"""A fictional, validated `IBS_DOWNLOAD_BASE_URL`."""

REDIRECT_HOST: Final = "dist.suse.de"
REPOMD_NAMESPACE: Final = "http://linux.duke.edu/metadata/repo"


def load_repomd_fixture(name: str) -> bytes:
    return (FIXTURE_DIR / f"repomd_{name}.xml").read_bytes()


def load_updateinfo_fixture(name: str) -> bytes:
    return (FIXTURE_DIR / f"updateinfo_{name}.xml").read_bytes()


def load_responses() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURE_DIR / "responses.json").read_text(encoding="utf-8")
    )
    return data


# --- Synthetic documents -------------------------------------------------


def source_package(
    name: str,
    *,
    version: str = "1.0",
    release: str = "150600.1.1",
    arch: str = "src",
    epoch: str = "0",
    src: str | None = None,
) -> str:
    """One `package` element; `src` defaults to the conventional path."""
    if src is None:
        src = f"{arch}/{name}-{version}-{release}.{arch}.rpm"
    attributes = {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "src": src,
    }
    rendered = " ".join(
        f"{key}={quoteattr(value)}" for key, value in attributes.items()
    )
    filename = escape(src.rsplit("/", 1)[-1])
    return f"<package {rendered}><filename>{filename}</filename></package>"


def binary_package(name: str, *, arch: str = "x86_64") -> str:
    return source_package(name, arch=arch)


def advisory(
    advisory_id: str,
    *,
    cves: Iterable[str] = (),
    sources: Iterable[str] = (),
    issued: str = "1717068854",
    type_: str = "security",
    status: str = "stable",
    references: Iterable[str] | None = None,
    packages: Iterable[str] | None = None,
    extra: str = "",
) -> str:
    """One `update` element in the live shape with fictional text.

    `references` and `packages`, when given, replace the generated CVE
    references and source/binary package entries verbatim.
    """
    if references is None:
        references = [
            f'<reference href="https://cve.example.test/{cve}" id={quoteattr(cve)}'
            f' title="Fictional reference title" type="cve"/>'
            for cve in cves
        ]
    if packages is None:
        packages = [source_package(name) for name in sources] + [
            binary_package(f"{name}-tools") for name in sources
        ]
    return (
        f'<update from="maintenance@example.invalid" status={quoteattr(status)}'
        f' type={quoteattr(type_)} version="1">'
        f"<id>{escape(advisory_id)}</id>"
        f"<title>Fictional title</title><severity>moderate</severity>"
        f"<release>Fictional release</release>"
        f"<issued date={quoteattr(issued)}/>"
        f"<references>{''.join(references)}</references>"
        f"<description>Fictional description.</description>"
        f"<pkglist><collection>{''.join(packages)}</collection></pkglist>"
        f"{extra}</update>"
    )


def updateinfo_document(*updates: str) -> bytes:
    body = "".join(updates)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<updates>{body}</updates>\n'.encode()
    )


def gzip_member(data: bytes) -> bytes:
    """One deterministic gzip member (fixed mtime)."""
    return gzip.compress(data, mtime=0)


@dataclass(frozen=True)
class Artifact:
    """A served updateinfo artifact and its repomd declaration."""

    compressed: bytes
    open_bytes: bytes
    checksum_type: str = "sha256"
    timestamp: int = 1_782_862_012
    location: str | None = None

    @property
    def algorithm(self) -> str:
        return {"sha256": "sha256", "sha": "sha1"}[self.checksum_type]

    @property
    def checksum(self) -> str:
        return hashlib.new(self.algorithm, self.compressed).hexdigest()

    @property
    def open_checksum(self) -> str:
        return hashlib.new(self.algorithm, self.open_bytes).hexdigest()

    @property
    def href(self) -> str:
        return self.location or f"repodata/{self.checksum}-updateinfo.xml.gz"


def artifact(open_bytes: bytes, **kwargs: Any) -> Artifact:
    return Artifact(compressed=gzip_member(open_bytes), open_bytes=open_bytes, **kwargs)


def updateinfo_data(
    item: Artifact,
    *,
    overrides: dict[str, str] | None = None,
    omit: Iterable[str] = (),
) -> str:
    """The `data type="updateinfo"` element declaring `item`.

    `overrides` replaces a child's complete markup by child name
    (`location`, `checksum`, `open-checksum`, `timestamp`, `size`,
    `open-size`); `omit` drops children.
    """
    children = {
        "checksum": f'<checksum type="{item.checksum_type}">{item.checksum}</checksum>',
        "open-checksum": (
            f'<open-checksum type="{item.checksum_type}">{item.open_checksum}'
            "</open-checksum>"
        ),
        "location": f'<location href="{item.href}"/>',
        "timestamp": f"<timestamp>{item.timestamp}</timestamp>",
        "size": f"<size>{len(item.compressed)}</size>",
        "open-size": f"<open-size>{len(item.open_bytes)}</open-size>",
    }
    children.update(overrides or {})
    rendered = "".join(
        markup for name, markup in children.items() if name not in set(omit)
    )
    return f'<data type="updateinfo">{rendered}</data>'


PRIMARY_DATA: Final = (
    '<data type="primary"><checksum type="sha256">'
    + "a" * 64
    + '</checksum><open-checksum type="sha256">'
    + "b" * 64
    + '</open-checksum><location href="repodata/primary.xml.gz"/>'
    "<timestamp>1782862012</timestamp><size>10</size><open-size>20</open-size>"
    "</data>"
)


def repomd_document(*data: str, namespace: str = REPOMD_NAMESPACE) -> bytes:
    """A `repomd.xml` document with the live header and the given `data`."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<repomd xmlns="{namespace}" xmlns:rpm="http://linux.duke.edu/metadata/rpm">'
        "<revision>1782862012</revision>"
        "<tags><repo>obsrepository://build.example.test/Example/update</repo></tags>"
        f"{PRIMARY_DATA}{''.join(data)}</repomd>\n"
    ).encode()


# --- Fake server ---------------------------------------------------------


def repository_path(repo_name: str) -> str:
    """The URL path of a repository root under `TEST_BASE_URL`."""
    return "/ibs/" + "/".join(repo_name.split(":")) + "/update"


Responder = Callable[[httpx.Request], httpx.Response] | httpx.Response


@dataclass
class DownloadServer:
    """`httpx.MockTransport` handler for fictional Product repositories.

    `repositories` maps a repository name to its artifact (`None` serves a
    repomd without updateinfo); unregistered repositories return 404.
    `scripted` maps an exact URL to responses consumed in order (the last
    one repeats); it takes precedence over the default responses.
    `direct` names repositories whose artifact is served without redirect.
    """

    repositories: dict[str, Artifact | None] = field(default_factory=dict)
    scripted: dict[str, list[Responder]] = field(default_factory=dict)
    direct: set[str] = field(default_factory=set)
    requests: list[httpx.Request] = field(default_factory=list)

    def add(
        self, repo_name: str, item: Artifact | None, *, direct: bool = False
    ) -> None:
        self.repositories[repo_name] = item
        if direct:
            self.direct.add(repo_name)

    def repomd_url(self, repo_name: str, *, host: str = "download.example.test") -> str:
        return f"https://{host}{repository_path(repo_name)}/repodata/repomd.xml"

    def artifact_url(
        self, repo_name: str, item: Artifact, *, host: str = "download.example.test"
    ) -> str:
        return f"https://{host}{repository_path(repo_name)}/{item.href}"

    def script(self, url: str, *responses: Responder) -> None:
        self.scripted[url] = list(responses)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport())

    def requests_to(self, url: str) -> list[httpx.Request]:
        return [request for request in self.requests if str(request.url) == url]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        queue = self.scripted.get(url)
        if queue:
            responder = queue.pop(0) if len(queue) > 1 else queue[0]
            return responder(request) if callable(responder) else responder
        return self._default(request)

    def _default(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for repo_name, item in self.repositories.items():
            root = repository_path(repo_name)
            if (
                path == f"{root}/repodata/repomd.xml"
                and request.url.host != REDIRECT_HOST
            ):
                data = [updateinfo_data(item)] if item is not None else []
                return xml_response(repomd_document(*data))
            if item is not None and path == f"{root}/{item.href}":
                if request.url.host == REDIRECT_HOST or repo_name in self.direct:
                    return gzip_response(item.compressed)
                return redirect_response(
                    f"https://{REDIRECT_HOST}{request.url.raw_path.decode()}"
                )
        return unread_response(
            404, [("Content-Type", "text/html; charset=utf-8")], b"<html/>"
        )


def unread_response(
    status: int, headers: list[tuple[str, str]], content: bytes
) -> httpx.Response:
    """A response whose body is still unread, as from a real transport.

    `httpx.Response(content=...)` is read on construction, so the
    boundary's `aiter_raw()` would refuse it. The live `Content-Length`
    is set explicitly.
    """
    return httpx.Response(
        status,
        headers=[*headers, ("Content-Length", str(len(content)))],
        stream=httpx.ByteStream(content),
    )


def xml_response(
    content: bytes,
    *,
    status: int = 200,
    content_type: str = 'application/xml;name="repomd.xml"',
) -> httpx.Response:
    return unread_response(status, [("Content-Type", content_type)], content)


def gzip_response(
    content: bytes, *, content_type: str = "application/x-gzip"
) -> httpx.Response:
    return unread_response(200, [("Content-Type", content_type)], content)


def redirect_response(location: str, *, status: int = 302) -> httpx.Response:
    return unread_response(
        status,
        [("Location", location), ("Content-Type", "application/x-gzip")],
        b"",
    )


@dataclass
class StreamedBody:
    """A response body yielded lazily, chunk by chunk.

    A response built from it has no automatic `Content-Length`. `error`,
    when set, is raised after the chunks. `yielded` counts the chunks
    handed out; `exhausted` tells whether the reader consumed them all.
    """

    chunks: Iterable[bytes]
    error: BaseException | None = None
    yielded: int = 0
    exhausted: bool = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk
        self.exhausted = True
        if self.error is not None:
            raise self.error


def streamed_response(
    body: StreamedBody,
    *,
    content_type: str | None,
    headers: list[tuple[str, str]] | None = None,
    status: int = 200,
) -> httpx.Response:
    """A response streaming `body`; `content_type=None` omits the header."""
    merged = [("Content-Type", content_type)] if content_type is not None else []
    return httpx.Response(status, headers=[*merged, *(headers or [])], content=body)


# --- Boundary invocation -------------------------------------------------

DEFAULT_CVE: Final = "CVE-2024-0001"
DEFAULT_PACKAGE: Final = "example"


def candidate(
    *,
    current: Iterable[str] = (),
    historical: Iterable[str] = (),
    package_name: str = DEFAULT_PACKAGE,
    cve_id: str = DEFAULT_CVE,
) -> ProductOccurrenceCandidate:
    """One Product occurrence with a fresh occurrence ID."""
    return ProductOccurrenceCandidate(
        occurrence_id=uuid.uuid4(),
        cve_id=cve_id,
        package_name=package_name,
        current_repositories=tuple(current),
        historical_repositories=tuple(historical),
    )


async def observe(
    client: httpx.AsyncClient,
    *candidates: ProductOccurrenceCandidate,
    base_url: str | None = TEST_BASE_URL,
) -> list[ProductReleaseObservation]:
    """One invocation observing every candidate in the given order."""
    async with ProductRepositoryDownloads(
        client, candidates, base_url=base_url
    ) as downloads:
        return [await downloads.observe(item.occurrence_id) for item in candidates]
