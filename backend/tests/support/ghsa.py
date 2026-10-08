"""Shared GitHub Advisory Database fixtures and a fake advisories endpoint.

The files under `backend/tests/fixtures/ghsa/` are live
`GET https://api.github.com/advisories` responses captured anonymously on
2026-10-08 with Python `urllib` requests carrying
`User-Agent: sentinel-contract-probe`, `Accept: application/vnd.github+json`,
and `X-GitHub-Api-Version: 2022-11-28`. The advisory fixtures are single
elements of six consecutive pages of the periodic query
`?type=reviewed&is_withdrawn=false&modified=>=2026-09-23T22:00:34Z&sort=updated&direction=asc&per_page=100`
(docs/features/tickets/cve-sync-ghsa.md, Algorithm):

- `advisory_v3_v4.json` (GHSA-25hc-qcg6-38wj, CVE-2024-38355): a v3 and a
  v4 Base vector, two `npm` entries for one package with two ranges
  (`>=, <` and `<`), and two CWEs;
- `advisory_v4_non_base.json` (GHSA-m2h6-j472-rp4c, CVE-2026-69248): a
  null v3 vector and a v4 vector with the non-Base metric `E:P`; `pip`;
- `advisory_v3_v4_non_base_ranges.json` (GHSA-574f-3g2m-x479,
  CVE-2025-14813): a v3 Base vector beside a v4 vector with the non-Base
  metrics `RE:M/U:Red`; `maven` entries with `>=, <=`, `=`, and `<=`
  ranges, a repeated package name, and a null `first_patched_version`;
  `repository_advisory_url` is null;
- `advisory_null_cve_id.json` (GHSA-94p4-4cq8-9g67): `cve_id` is null and
  `identifiers` lists only the GHSA-ID; no `epss`;
- `advisory_erlang.json` (GHSA-f4hc-ppw9-4hhw, CVE-2026-55736): the
  `erlang` ecosystem (Hex) and a v4-only Base vector;
- `advisory_multi_ecosystem.json` (GHSA-wpqr-6v78-jr5g, CVE-2026-12537):
  `npm` and `actions` entries, including an `=` range on a pre-release;
- `advisory_empty_source_location.json` (GHSA-7rjr-3q55-vv33,
  CVE-2021-45046): `source_code_location` is the empty string; `maven`;
- `advisory_gt_range.json` (GHSA-vc4h-q48j-5hcx, CVE-2026-105851): the only
  advisory of the capture with the `>, <` shape (both of its two entries);
  a six-digit CVE sequence number and no `epss`.

The single-query responses
(`?type=reviewed&is_withdrawn=false&cve_id={CVE-ID}`, Algorithm,
`fetch_single(cve_id)`):

- `single_reviewed.json`: the list of one advisory served for
  CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q), whose v3 vector carries the
  Temporal metric `E:H`;
- `single_empty.json`: `[]`, stored byte-for-byte as served for an unknown
  CVE-ID (CVE-1999-99999); a withdrawn-only (CVE-2017-17461) and an
  unreviewed-only (CVE-2026-76286) CVE-ID were answered with the same body;
- `auth_401.json`: the HTTP 401 body served for a fictional bearer token,
  stored byte-for-byte as served (CRLF line endings, no trailing newline).

The advisories were trimmed and sanitized before saving (docs/conventions.md,
External Integration Contract Verification): every top-level key and its
JSON type was kept, and only `vulnerabilities[]` (GHSA-574f-3g2m-x479 to 5
of 26, GHSA-7rjr-3q55-vv33 to 4 of 7, GHSA-jfh8-c2jp-5v3q to 4 of 10) and
`references[]` (GHSA-574f-3g2m-x479 to 5 of 35, GHSA-7rjr-3q55-vv33 to 5
of 26, GHSA-jfh8-c2jp-5v3q to 6 of 75) were shortened. Every `summary` and
`description` was replaced with fictional text; every non-empty `credits[]`
was replaced with one fictional entry keeping the first credit's `type` and
the real key set and types of its `user` object (`login`
`example-researcher`, `id` 1000, a fictional `node_id`, and every URL under
`https://github.example.invalid/`). Reference URLs on mailing-list archives,
exploit archives, and personal GitHub accounts were replaced with fictional
`https://advisory.example.invalid/upstream/<n>` URLs. URLs of organisations,
vendors, projects, and advisory databases (NVD, GitHub advisories, the
Apache, Red Hat, OSV, and EEF CNA sites, VulnCheck, and the GitHub
organisations of the affected projects), the advisories' own API URLs,
GHSA-IDs, CVE-IDs, package names, ecosystems, ranges, CWEs, CVSS vectors
and scores, EPSS values, and dates are public product data, not personal
identifiers, and are retained.

`LIVE_NEXT_LINK` and `LIVE_NEXT_PREV_LINK` are `Link` header values served
for the first and second page of the same capture. On a multi-page result
the last page still carries a `Link` header with only `rel="prev"` (verified
live on 2026-10-08 by an independent re-verification: 4 pages of
100/100/100/4 advisories for `modified=>=2026-10-05T00:00:00Z`), and a
single-page response carries none.

`GhsaServer` is an in-process `httpx.MockTransport` handler for the
advisories endpoint: page requests are served from `pages` with a fake
`after=cursor-<i>` cursor and `rel="next"` links, single queries from
`singles`. Tests override raw responses and `Link` headers and inspect the
recorded requests in order.

Consumers, all under `tests/test_services/test_tickets/`: the fixture
loaders and the live `Link` values by `test_ghsa_advisory_contract.py`;
later, the parser and fetcher tests of `sync_ghsa_advisories`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ghsa"

GHSA_HOST = "api.github.com"
ADVISORIES_PATH = "/advisories"
ADVISORIES_URL = f"https://{GHSA_HOST}{ADVISORIES_PATH}"

ADVISORY_FIXTURES = (
    "advisory_v3_v4",
    "advisory_v4_non_base",
    "advisory_v3_v4_non_base_ranges",
    "advisory_null_cve_id",
    "advisory_erlang",
    "advisory_multi_ecosystem",
    "advisory_empty_source_location",
    "advisory_gt_range",
)
"""Sanitized live advisories from the periodic pages, by fixture name."""

FIXTURE_CVE_IDS: Mapping[str, str | None] = {
    "advisory_v3_v4": "CVE-2024-38355",
    "advisory_v4_non_base": "CVE-2026-69248",
    "advisory_v3_v4_non_base_ranges": "CVE-2025-14813",
    "advisory_null_cve_id": None,
    "advisory_erlang": "CVE-2026-55736",
    "advisory_multi_ecosystem": "CVE-2026-12537",
    "advisory_empty_source_location": "CVE-2021-45046",
    "advisory_gt_range": "CVE-2026-105851",
}
"""The `cve_id` of every advisory fixture."""

SINGLE_REVIEWED_FIXTURE = "single_reviewed"
"""The live single-query body for CVE-2021-44228: a list of one advisory."""

SINGLE_REVIEWED_CVE_ID = "CVE-2021-44228"

SINGLE_EMPTY_FIXTURE = "single_empty"
"""The live single-query body without a match (`[]`), stored as served."""

AUTH_401_FIXTURE = "auth_401"
"""The live HTTP 401 body for a bad token, stored as served."""

LIVE_NEXT_LINK = (
    "<https://api.github.com/advisories?type=reviewed&is_withdrawn=false"
    "&modified=%3E%3D2026-09-23T22%3A00%3A34Z&sort=updated&direction=asc"
    "&per_page=100&after=Y3Vyc29yOnYyOpK0MjAyNi0wOS0yNVQxOTowNDoxMVrOAAWV0w%3D%3D>;"
    ' rel="next"'
)
"""The live `Link` header of the first page."""

LIVE_NEXT_PREV_LINK = (
    "<https://api.github.com/advisories?type=reviewed&is_withdrawn=false"
    "&modified=%3E%3D2026-09-23T22%3A00%3A34Z&sort=updated&direction=asc"
    "&per_page=100&after=Y3Vyc29yOnYyOpK0MjAyNi0wOS0yOVQyMzo0NjowNFrOAAexTQ%3D%3D>;"
    ' rel="next", '
    "<https://api.github.com/advisories?type=reviewed&is_withdrawn=false"
    "&modified=%3E%3D2026-09-23T22%3A00%3A34Z&sort=updated&direction=asc"
    "&per_page=100&before=Y3Vyc29yOnYyOpK0MjAyNi0wOS0yNVQxOTowNTozMFrOAAWVyQ%3D%3D>;"
    ' rel="prev"'
)
"""The live `Link` header of the second page."""

JSON_CONTENT_TYPE = "application/json; charset=utf-8"
"""The live `Content-Type` of every response."""

_CURSOR = re.compile(r"cursor-([0-9]+)")


def load_advisory_fixture(name: str) -> dict[str, Any]:
    """Return one sanitized live advisory object as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_list_fixture(name: str) -> list[Any]:
    """Return one live single-query body (a JSON array) as parsed JSON."""
    data: list[Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed (a body as served)."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def status(
    code: int, content: bytes = b"", headers: Mapping[str, str] | None = None
) -> Responder:
    """A responder that answers with `code`, the raw `content`, and
    `headers`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code, content=content, headers=dict(headers or {}), request=request
        )

    return respond


def body(value: Any, headers: Mapping[str, str] | None = None) -> Responder:
    """A responder that serves the JSON `value` with HTTP 200 and `headers`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return _json_response(request, value, headers)

    return respond


def _json_response(
    request: httpx.Request, value: Any, headers: Mapping[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(
        200,
        content=json.dumps(value).encode(),
        headers={"Content-Type": JSON_CONTENT_TYPE, **(headers or {})},
        request=request,
    )


def is_advisories_request(request: httpx.Request) -> bool:
    """Whether `request` targets `https://api.github.com/advisories` (no
    explicit port)."""
    url = request.url
    return (
        url.scheme == "https"
        and url.host == GHSA_HOST
        and url.port is None
        and url.path == ADVISORIES_PATH
    )


def requested_cve_id(request: httpx.Request) -> str | None:
    """The `cve_id` query parameter of a single query, or `None` for a page
    request or another endpoint."""
    if not is_advisories_request(request) or "cve_id" not in request.url.params:
        return None
    cve_id: str = request.url.params["cve_id"]
    return cve_id


def requested_page_index(request: httpx.Request) -> int | None:
    """The fake page index of a page request (`after=cursor-<i>`, page 0
    without `after`), or `None` for a single query, an unknown cursor, or
    another endpoint."""
    if not is_advisories_request(request) or "cve_id" in request.url.params:
        return None
    after = request.url.params.get("after")
    if after is None:
        return 0
    match = _CURSOR.fullmatch(after)
    return int(match.group(1)) if match else None


def next_page_url(request: httpx.Request, index: int) -> str:
    """The fake next-page URL: the request URL with `after=cursor-<index>`,
    every other query parameter preserved."""
    return str(request.url.copy_set_param("after", f"cursor-{index}"))


class GhsaServer:
    """A fake GitHub Advisory Database endpoint for `httpx.MockTransport`.

    A request whose query has a `cve_id` parameter is a single query:
    `single_responses[cve_id]` answers it when present; otherwise
    `singles[cve_id]` is served with HTTP 200, and `[]` for an unknown
    CVE-ID. Any other request is a page request: page 0 without an `after`
    parameter, page `i` for `after=cursor-<i>`. `page_responses[i]`
    answers it when present; otherwise `pages[i]` (any JSON value) is served
    with HTTP 200 and, unless it is the last page, a
    `Link: <next>; rel="next"` header whose URL is the request URL with
    `after=cursor-<i+1>`. `link_overrides[i]` replaces that header (`None`
    omits it). An unknown page or cursor, and a request to another scheme,
    host, port, or path, are answered with HTTP 404. Every request is
    recorded in `requests`, in order.
    """

    def __init__(
        self,
        pages: Sequence[Any] | None = None,
        singles: Mapping[str, Any] | None = None,
    ) -> None:
        self.pages: list[Any] = list(pages) if pages is not None else [[]]
        self.singles: dict[str, Any] = dict(singles or {})
        self.link_overrides: dict[int, str | None] = {}
        self.page_responses: dict[int, Responder] = {}
        self.single_responses: dict[str, Responder] = {}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not is_advisories_request(request):
            return httpx.Response(404, request=request)
        cve_id = requested_cve_id(request)
        if cve_id is not None:
            if cve_id in self.single_responses:
                return self.single_responses[cve_id](request)
            return _json_response(request, self.singles.get(cve_id, []))
        index = requested_page_index(request)
        if index is not None and index in self.page_responses:
            return self.page_responses[index](request)
        if index is None or index >= len(self.pages):
            return httpx.Response(404, request=request)
        headers: dict[str, str] = {}
        link = self._link(request, index)
        if link is not None:
            headers["Link"] = link
        return _json_response(request, self.pages[index], headers)

    def _link(self, request: httpx.Request, index: int) -> str | None:
        if index in self.link_overrides:
            return self.link_overrides[index]
        if index + 1 >= len(self.pages):
            return None
        return f'<{next_page_url(request, index + 1)}>; rel="next"'

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def authorization_headers(self) -> list[str | None]:
        """The `Authorization` header of every request, in order."""
        return [request.headers.get("Authorization") for request in self.requests]

    @property
    def page_requests(self) -> list[httpx.Request]:
        """The recorded advisories requests without a `cve_id` parameter."""
        return [
            request
            for request in self.requests
            if is_advisories_request(request) and "cve_id" not in request.url.params
        ]

    @property
    def single_requests(self) -> list[httpx.Request]:
        """The recorded advisories requests with a `cve_id` parameter."""
        return [
            request
            for request in self.requests
            if requested_cve_id(request) is not None
        ]

    @property
    def requested_page_indexes(self) -> list[int | None]:
        return [requested_page_index(request) for request in self.page_requests]
