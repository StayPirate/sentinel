"""Shared OSV fixtures and a fake vulnerability-record endpoint.

The files under `backend/tests/fixtures/osv/` are live
`GET https://api.osv.dev/v1/vulns/{id}` responses captured anonymously on
2026-10-07 through Sentinel's production HTTP client
(`create_http_client(name="sync_osv_advisories")`, its standard User-Agent,
redirects not followed). Phase 1 CVE records:

- `cve_git_ranges.json` (CVE-2021-44228): one `GIT` range with four pairs,
  `introduced: "0"` in the middle, and a closing `last_affected`; one
  `GHSA` alias; `SUSE-SU`/`openSUSE-SU` related IDs;
- `cve_git_unpaired_introduced.json` (CVE-2024-12797): one `GIT` range
  with three `introduced` events followed by six `fixed` events; `GHSA`
  and `PYSEC` aliases;
- `cve_git_repeated_fixed.json` (CVE-2023-26136): one `GIT` range
  `introduced: "0"` followed by two `fixed` events;
- `cve_git_mirror_repos.json` (CVE-2024-2961): two `GIT` ranges with
  identical events under two different `repo` URLs; no `aliases`;
- `cve_kernel_ecosystem_range.json` (CVE-2024-26581): `GIT` ranges with a
  `fixed` triple, a `last_affected` close, and version strings instead of
  commit SHAs, plus a second `affected[]` entry with a `package` and
  `ECOSYSTEM` ranges; no `aliases`;
- `cve_no_affected.json` (CVE-2023-45288): no `affected`; `BIT`, `GHSA`,
  and `GO` aliases;
- `cve_references_only.json` (CVE-2014-0160): no `affected` and no
  `aliases`; only `references` and `related`;
- `cve_multi_cve_aliases.json` (CVE-2023-4863): `A`, `ASB`, `CVE`,
  `GHSA`, `PYSEC`, and two `RUSTSEC` aliases.

Phase 2 alias records:

- `alias_ghsa_ecosystem.json` (GHSA-jfh8-c2jp-5v3q): Maven `ECOSYSTEM`
  ranges, one closing `last_affected`, `versions[]`, and an entry without
  `ranges`;
- `alias_ghsa_semver.json` (GHSA-8hfj-j24r-96c4): an npm `SEMVER` range
  and a NuGet `ECOSYSTEM` range with `versions[]`;
- `alias_ghsa_multi_cve.json` (GHSA-j7hp-h8jx-5ppr): `aliases` naming two
  CVEs; crates.io and npm `SEMVER` ranges;
- `alias_pysec.json` (PYSEC-2025-49): a `GIT` and an `ECOSYSTEM` range and
  `versions[]`; one CVE alias;
- `alias_rustsec.json` (RUSTSEC-2023-0034): one crates.io `SEMVER` range;
  one CVE alias;
- `alias_bit.json` (BIT-golang-2023-45288) and `alias_go.json`
  (GO-2024-2687): excluded-prefix records with two-pair `SEMVER` ranges;
- `alias_curl_no_package.json` (CURL-CVE-2023-38545): an `affected[]`
  entry without `package` (a `SEMVER` and a `GIT` range) and no
  `references`;
- `alias_asb_no_purl.json` (ASB-A-299477569): Android packages without
  `purl`.

Phase 3 related records:

- `related_suse.json` (SUSE-SU-2021:4096-1): four `affected[]` entries
  naming two distinct packages, and `upstream`;
- `related_opensuse_reference_without_url.json`
  (openSUSE-SU-2024:11666-1): a reference object without `url`, and
  `upstream`.

HTTP 404 bodies, stored byte-for-byte as served with
`Content-Type: application/json` and no trailing newline:

- `not_found.json`: the body for an unknown CVE-ID (CVE-2099-99999);
- `alias_not_found.json`: the body for a listed alias that has no
  standalone record (GHSA-rxwq-x6h5-x525, an alias of CVE-2024-3094).

The records were trimmed and sanitized before saving (docs/conventions.md,
External Integration Contract Verification): `affected[]`, `versions[]`,
`references[]`, `related[]`, the `GIT` ranges of the kernel record, and
lists inside unconsumed members were shortened, keeping the real shapes;
every `summary` and `details` was replaced with fictional text; every
`credits[]` was replaced with one fictional `Example Researcher` entry
(keeping a `contact` and `type` member only where one existed); and every
URL, in any member, whose prefix is not an organisation, vendor, or
advisory-database location was replaced with a fictional
`https://advisory.example.invalid/upstream/<n>` URL — including mailing
list posts, personal blogs, personal and third-party GitHub accounts, and
exploit archives. The one replaced `repo`, a personal GitHub mirror of
glibc, became `https://git.example.invalid/mirror/<n>`. Advisory IDs,
package names, ecosystems, purls, organisation repositories, commit SHAs,
and vendor advisory URLs are public product data, not personal
identifiers, and are retained.

`OsvServer` is an in-process `httpx.MockTransport` handler for the
vulnerability-record endpoint (docs/features/tickets/cve-sync-osv.md,
Algorithm): `bodies` maps a record ID to the JSON served with HTTP 200,
and any other ID is answered with the live CVE 404 body. Tests register
raw `responses` (status codes, undecodable bodies, transport errors) and
inspect `requests` in order.

Consumers, all under `tests/test_services/test_tickets/`: the fixture
loaders by `test_osv_vulnerability_contract.py`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "osv"

OSV_HOST = "api.osv.dev"
OSV_VULNS_PATH_PREFIX = "/v1/vulns/"
"""Path of the vulnerability-record endpoint up to the `{id}` segment."""

CVE_FIXTURES = (
    "cve_git_ranges",
    "cve_git_unpaired_introduced",
    "cve_git_repeated_fixed",
    "cve_git_mirror_repos",
    "cve_kernel_ecosystem_range",
    "cve_no_affected",
    "cve_references_only",
    "cve_multi_cve_aliases",
)
"""Sanitized live HTTP 200 Phase 1 CVE records, by fixture name."""

ALIAS_FIXTURES = (
    "alias_ghsa_ecosystem",
    "alias_ghsa_semver",
    "alias_ghsa_multi_cve",
    "alias_pysec",
    "alias_rustsec",
    "alias_bit",
    "alias_go",
    "alias_curl_no_package",
    "alias_asb_no_purl",
)
"""Sanitized live HTTP 200 Phase 2 alias records, by fixture name."""

RELATED_FIXTURES = ("related_suse", "related_opensuse_reference_without_url")
"""Sanitized live HTTP 200 Phase 3 related records, by fixture name."""

RECORD_FIXTURES = (*CVE_FIXTURES, *ALIAS_FIXTURES, *RELATED_FIXTURES)

NOT_FOUND_FIXTURE = "not_found"
"""The live HTTP 404 body for an unknown CVE-ID, stored as served."""

ALIAS_NOT_FOUND_FIXTURE = "alias_not_found"
"""The live HTTP 404 body for an alias without a standalone record."""

FIXTURE_RECORD_IDS: Mapping[str, str] = {
    "cve_git_ranges": "CVE-2021-44228",
    "cve_git_unpaired_introduced": "CVE-2024-12797",
    "cve_git_repeated_fixed": "CVE-2023-26136",
    "cve_git_mirror_repos": "CVE-2024-2961",
    "cve_kernel_ecosystem_range": "CVE-2024-26581",
    "cve_no_affected": "CVE-2023-45288",
    "cve_references_only": "CVE-2014-0160",
    "cve_multi_cve_aliases": "CVE-2023-4863",
    "alias_ghsa_ecosystem": "GHSA-jfh8-c2jp-5v3q",
    "alias_ghsa_semver": "GHSA-8hfj-j24r-96c4",
    "alias_ghsa_multi_cve": "GHSA-j7hp-h8jx-5ppr",
    "alias_pysec": "PYSEC-2025-49",
    "alias_rustsec": "RUSTSEC-2023-0034",
    "alias_bit": "BIT-golang-2023-45288",
    "alias_go": "GO-2024-2687",
    "alias_curl_no_package": "CURL-CVE-2023-38545",
    "alias_asb_no_purl": "ASB-A-299477569",
    "related_suse": "SUSE-SU-2021:4096-1",
    "related_opensuse_reference_without_url": "openSUSE-SU-2024:11666-1",
}
"""The requested ID of every HTTP 200 fixture."""


def load_record_fixture(name: str) -> dict[str, Any]:
    """Return one sanitized live HTTP 200 record as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed (a 404 body as served)."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def osv_vuln_url(record_id: str) -> str:
    """The production request URL for `record_id`."""
    return f"https://{OSV_HOST}{OSV_VULNS_PATH_PREFIX}{record_id}"


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def status(code: int, content: bytes = b"") -> Responder:
    """A responder that answers with `code` and the raw `content`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(code, content=content, request=request)

    return respond


def body(value: Any) -> Responder:
    """A responder that serves the JSON `value` with HTTP 200."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=value, request=request)

    return respond


class OsvServer:
    """A fake OSV vulnerability-record endpoint for `httpx.MockTransport`.

    `bodies` maps a record ID to the JSON body served for it with HTTP 200
    (any JSON value, mutable by tests); `responses` maps a record ID to a
    callable that returns a raw response or raises a transport error
    instead. A request for any other ID, or for another host or path, is
    answered with the live HTTP 404 body. Every request is recorded in
    `requests`, in order.
    """

    def __init__(self, bodies: Mapping[str, Any] | None = None) -> None:
        self.bodies: dict[str, Any] = dict(bodies or {})
        self.responses: dict[str, Responder] = {}
        self.requests: list[httpx.Request] = []

    @classmethod
    def for_fixtures(cls, *names: str) -> OsvServer:
        """Serve the named HTTP 200 fixtures under their requested IDs."""
        return cls(
            {FIXTURE_RECORD_IDS[name]: load_record_fixture(name) for name in names}
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        record_id = requested_record_id(request)
        if record_id is not None and record_id in self.responses:
            return self.responses[record_id](request)
        if record_id is None or record_id not in self.bodies:
            return httpx.Response(
                404,
                content=load_raw_fixture(NOT_FOUND_FIXTURE),
                headers={"Content-Type": "application/json"},
                request=request,
            )
        return httpx.Response(200, json=self.bodies[record_id], request=request)

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def requested_ids(self) -> list[str | None]:
        return [requested_record_id(request) for request in self.requests]


def requested_record_id(request: httpx.Request) -> str | None:
    """The `{id}` of a vulnerability-record request, or `None` for another
    host, another path, or an empty or multi-segment remainder."""
    url = request.url
    if url.host != OSV_HOST or not url.path.startswith(OSV_VULNS_PATH_PREFIX):
        return None
    record_id = url.path.removeprefix(OSV_VULNS_PATH_PREFIX)
    if not record_id or "/" in record_id:
        return None
    return record_id
