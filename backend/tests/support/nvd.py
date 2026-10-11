"""NVD CVE API 2.0 and Source API fixtures.

The files under `backend/tests/fixtures/nvd/` are sanitized live responses of
`https://services.nvd.nist.gov/rest/json/cves/2.0` and
`https://services.nvd.nist.gov/rest/json/source/2.0`, consumed by
`app/services/tickets/nvd_cve_record.py`
(docs/features/tickets/cve-sync-nvd.md). They were captured anonymously on
2026-10-10 with Python `urllib` and `curl` requests, without an API key and
at least 7 seconds apart (docs/conventions.md, External Integration Contract
Verification). All 37 requests were answered with HTTP 200.

Windows (`lastModStartDate`/`lastModEndDate`, `resultsPerPage=2000`, every
page fetched): `2026-10-01` to `2026-10-04` (1,799 records), `2026-09-01` to
`2026-09-20` (12,040, 7 pages), `2025-03-01` to `2025-03-04` (12),
`2026-07-01` to `2026-07-31` (18,098, 10 pages), and `2026-01-01` to
`2026-04-30` (1,165): 33,114 distinct records. Findings over all of them:

- Every page envelope has the integers `totalResults`, `resultsPerPage`, and
  `startIndex`, the strings `format` (`NVD_CVE`), `version` (`2.0`), and
  `timestamp`, and the array `vulnerabilities`. An unknown CVE-ID
  (`cveId=CVE-2099-99999`) returns `totalResults` 0 with an empty
  `vulnerabilities` array.
- Every element is `{"cve": {...}}`. `id`, `published`, `lastModified`,
  `vulnStatus`, `sourceIdentifier`, `cveTags`, `descriptions`, `metrics`,
  and `references` are always present; `metrics` is always an object (empty
  in every Rejected and some other records). Both timestamps always have the
  form `YYYY-MM-DDTHH:MM:SS.sss` without an offset.
- `vulnStatus`: Analyzed 10,383; Awaiting Analysis 2,536; Deferred 12,062;
  Modified 4,738; Received 1,768; Rejected 1,373; Undergoing Analysis 254.
- Every record has exactly one English description (at most 3,998
  characters); 9,633 also have a Spanish one.
- `metrics` members: `cvssMetricV31` 28,186 records, `cvssMetricV2` 2,612,
  `cvssMetricV30` 293, `cvssMetricV40` 8,899, and the non-CVSS `ssvcV203`
  27,085. Every CVSS vector prefix matches its array, the External Base
  Reduction accepts all 44,406 vectors, and it reduces every v4.0 vector
  (all carry non-Base metrics). No source appears twice in one array.
- Provider identity (cve-sync-nvd.md § Source identity): of 6,981 `Primary`
  CVSS entries, 6,815 come from NVD's identifier `nvd@nist.gov` and 166 from
  the record's CNA; 34 CVSS entries from `nvd@nist.gov` are `Secondary`.
  Weaknesses: 555 `Primary` entries come from the record's CNA and 56 from
  `nvd@nist.gov` are `Secondary`. Under the source rule, every non-NVD
  identifier resolves through the Source API, 66 CVSS entries resolve to
  the reserved `SUSE`, and no two sources of one array resolve to one
  display name.
- Weakness descriptions are `CWE-<n>` (35,108), `NVD-CWE-noinfo` (1,036),
  or `NVD-CWE-Other` (102). Every reference has `url` and `source`; `tags`
  appears on 42,019 of 117,659, every tag listed in ticket-references.md
  § CVE Source Tag Mapping. Rejected records have no references.
- `affected` (all 31,741 non-Rejected records) repeats the CVE record: of 400
  sampled records, 382 equal the CNA `affected[]`, 17 the CNA plus ADP
  entries, and 1 is an older copy of an entry the CNA has since updated.
  All 60 sampled `ssvcV203` entries equal the CISA-ADP SSVC of the CVE
  record (keys re-spelled). Neither is consumed.
- No string contains U+0000.

Source API: one response of 514 sources (`totalResults` = `resultsPerPage`
= 514), 818 identifiers (817 distinct; one entry lists one identifier
twice), names at most 80 characters, none blank or untrimmed, `NIST` with
the single identifier `nvd@nist.gov`, and a `SUSE` entry.

Window volumes for the run-duration projection of `sync_nvd_cves`
(`resultsPerPage=1`): 6-hour windows of 2026-10-07 to 2026-10-09 between
18 and 1,340 records; 30 days ending 2026-10-10: 27,192; 120 days ending
2026-10-10: 386,005.

Fixtures (`record_*` are single `vulnerabilities[]` elements, the others
complete response bodies):

- `record_analyzed_full` (CVE-2025-52221): NVD and CISA-ADP v3.1 vectors and
  CWEs, English and Spanish descriptions, an `AND` firmware/hardware
  configuration, tagged references, `ssvcV203`, and `affected`;
- `record_modified_v2` (CVE-2005-1439): an NVD v2 vector and an
  `NVD-CWE-Other` weakness;
- `record_awaiting_v30` (CVE-2026-68493): a CNA v3.0 vector, no
  `configurations`;
- `record_awaiting_v40_non_base` (CVE-2026-64634): a CNA v4.0 vector with
  non-Base metrics;
- `record_reserved_suse` (CVE-2025-46808): a v3.1 vector and a CWE whose
  source resolves to `SUSE`;
- `record_deferred_without_metrics` (CVE-2023-54233) and `record_received`
  (CVE-2022-4994): an empty `metrics` object and no `weaknesses`;
- `record_cwe_placeholder` (CVE-2026-7803): an IBM CWE beside an NVD
  `NVD-CWE-noinfo` weakness, and a wildcard entry with a version range;
- `record_undergoing_configurations` (CVE-2026-0157): Undergoing Analysis
  with `configurations`;
- `record_firmware_hardware` (CVE-2022-38555) and
  `record_multiple_configurations` (CVE-2022-36524, two configurations):
  firmware `o` entries with hardware `h` platforms;
- `record_escaped_criteria` (CVE-2025-56588): a `criteria` with `\\/`;
- `record_cna_primary_cvss` (CVE-2026-24304): a CNA `Primary` v3.1 vector
  and NVD's own vector typed `Secondary`;
- `record_cna_primary_cwe` (CVE-2026-45489): a CNA `Primary` weakness, NVD's
  own weakness typed `Secondary`, and a CISA-ADP weakness;
- `single_log4shell` (`cveId=CVE-2021-44228`): NVD v3.1 and v2 vectors, the
  `cisa*` members, NVD's own weakness typed `Secondary`, a wildcard
  configuration repeating one `criteria` with different ranges, and an
  `AND` firmware/hardware configuration;
- `single_platform_also_vulnerable` (`cveId=CVE-2026-50355`): one
  `criteria` vulnerable in one configuration and a platform in another;
- `page_rejected`: the complete page of the 2025-03-01 window, 12 Rejected
  records;
- `page_empty`: the unknown CVE-ID response, byte-for-byte;
- `source_page`: the Source API response trimmed to the 12 sources the
  fixtures reference, plus `MITRE` and `SUSE`.

Trimming and sanitization: configurations keep at most four `cpeMatch`
entries per node (`single_log4shell` and `single_platform_also_vulnerable`
keep two of their configurations), `single_log4shell` keeps 5 of 103
references, and `affected` keeps its first source with one entry. Every
description is replaced with fictional text; every reference URL with a
fictional `https://advisory.example.invalid/upstream/<n>` URL; every e-mail
identifier (`sourceIdentifier`, metric, weakness, reference, `affected`,
and Source API identifiers) with a fictional `<organization>-<n>@example.com`
address used consistently across all fixtures, and every `contactEmail`
with `contact-<organization>@example.com`. NVD's institutional identifier
`nvd@nist.gov`, organization UUIDs, organization names, CPE strings (all of
organization vendors), `matchCriteriaId` values, vectors, CWEs, tags, and
dates are public data, not personal identifiers, and are retained.

`NvdServer` is an in-process `httpx.MockTransport` handler for both
endpoints: window pages are served by `startIndex` (page `i` for
`startIndex = i * resultsPerPage`) inside a page envelope whose
`totalResults` covers every configured page unless overridden, `cveId`
queries from `singles`, and the Source API from `sources` (the trimmed
`source_page` body by default). Tests override raw responses, queue one-shot
responses, and inspect the recorded requests (URL, query, headers) in order.

Consumers, under `tests/test_services/test_tickets/`:
`test_nvd_cve_record_contract.py` and `test_nvd_cve_record.py` (fixture
loaders); `test_sync_nvd_cves.py`, `test_sync_nvd_cves_execute.py`, and
`test_sync_nvd_cves_reachability.py` (loaders and `NvdServer`).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"

NVD_HOST = "services.nvd.nist.gov"
CVE_API_PATH = "/rest/json/cves/2.0"
SOURCE_API_PATH = "/rest/json/source/2.0"
CVE_API_URL = f"https://{NVD_HOST}{CVE_API_PATH}"
SOURCE_API_URL = f"https://{NVD_HOST}{SOURCE_API_PATH}"

API_KEY_HEADER = "apiKey"
"""The NVD-proprietary API key header, spelled literally."""

JSON_CONTENT_TYPE = "application/json"
"""The `Content-Type` of the fake JSON responses (not read by the fetcher)."""

NVD_SOURCE_IDENTIFIER = "nvd@nist.gov"
"""NVD's own source identifier (test-local copy)."""

CISA_ADP_SOURCE_IDENTIFIER = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
"""The CISA-ADP source identifier of the Source API."""

RECORD_CVE_IDS: Mapping[str, str] = {
    "record_analyzed_full": "CVE-2025-52221",
    "record_modified_v2": "CVE-2005-1439",
    "record_awaiting_v30": "CVE-2026-68493",
    "record_awaiting_v40_non_base": "CVE-2026-64634",
    "record_reserved_suse": "CVE-2025-46808",
    "record_deferred_without_metrics": "CVE-2023-54233",
    "record_received": "CVE-2022-4994",
    "record_cwe_placeholder": "CVE-2026-7803",
    "record_undergoing_configurations": "CVE-2026-0157",
    "record_firmware_hardware": "CVE-2022-38555",
    "record_multiple_configurations": "CVE-2022-36524",
    "record_escaped_criteria": "CVE-2025-56588",
    "record_cna_primary_cvss": "CVE-2026-24304",
    "record_cna_primary_cwe": "CVE-2026-45489",
}
"""Single-element record fixture name → its CVE-ID."""

RECORD_FIXTURES: tuple[str, ...] = tuple(RECORD_CVE_IDS)

SINGLE_LOG4SHELL = "single_log4shell"
SINGLE_PLATFORM_ALSO_VULNERABLE = "single_platform_also_vulnerable"
PAGE_REJECTED = "page_rejected"
PAGE_EMPTY = "page_empty"

PAGE_FIXTURES: tuple[str, ...] = (
    SINGLE_LOG4SHELL,
    SINGLE_PLATFORM_ALSO_VULNERABLE,
    PAGE_REJECTED,
    PAGE_EMPTY,
)
"""Complete CVE API response bodies."""

SOURCE_PAGE = "source_page"
"""The trimmed Source API response body."""


def load_raw_fixture(name: str) -> bytes:
    """One fixture's bytes, as a response body."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def load_json_fixture(name: str) -> Any:
    """One fixture as parsed JSON."""
    return json.loads(load_raw_fixture(name))


def load_record(name: str) -> dict[str, Any]:
    """One `vulnerabilities[]` element: a record fixture, or the only element
    of a single-record page fixture."""
    data: dict[str, Any] = load_json_fixture(name)
    if name in PAGE_FIXTURES:
        (element,) = data["vulnerabilities"]
        record: dict[str, Any] = element
        return record
    return data


def all_records() -> list[tuple[str, dict[str, Any]]]:
    """Every captured element with its fixture name, page elements included."""
    records = [(name, load_record(name)) for name in RECORD_FIXTURES]
    for name in (SINGLE_LOG4SHELL, SINGLE_PLATFORM_ALSO_VULNERABLE):
        records.append((name, load_record(name)))
    for element in load_json_fixture(PAGE_REJECTED)["vulnerabilities"]:
        records.append((PAGE_REJECTED, element))
    return records


# ---------------------------------------------------------------------------
# Fake NVD endpoints
# ---------------------------------------------------------------------------


def page_body(
    elements: Sequence[Any], total_results: int, start_index: int = 0
) -> dict[str, Any]:
    """A CVE API page envelope with every member of the live envelope."""
    return {
        "resultsPerPage": len(elements),
        "startIndex": start_index,
        "totalResults": total_results,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-10T00:00:00.000",
        "vulnerabilities": list(elements),
    }


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: BaseException) -> Responder:
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


def body(value: Any, code: int = 200) -> Responder:
    """A responder that serves the JSON `value` with `code`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return _json_response(request, value, code)

    return respond


def _json_response(
    request: httpx.Request, value: Any, code: int = 200
) -> httpx.Response:
    return httpx.Response(
        code,
        content=json.dumps(value).encode(),
        headers={"Content-Type": JSON_CONTENT_TYPE},
        request=request,
    )


def _is_endpoint(request: httpx.Request, path: str) -> bool:
    url = request.url
    return (
        url.scheme == "https"
        and url.host == NVD_HOST
        and url.port is None
        and url.path == path
    )


def is_cve_api_request(request: httpx.Request) -> bool:
    """Whether `request` targets the CVE API (no explicit port)."""
    return _is_endpoint(request, CVE_API_PATH)


def is_source_api_request(request: httpx.Request) -> bool:
    """Whether `request` targets the Source API (no explicit port)."""
    return _is_endpoint(request, SOURCE_API_PATH)


def requested_cve_id(request: httpx.Request) -> str | None:
    """The `cveId` parameter of a CVE API request, `None` otherwise."""
    if not is_cve_api_request(request) or "cveId" not in request.url.params:
        return None
    cve_id: str = request.url.params["cveId"]
    return cve_id


def request_kind(request: httpx.Request) -> str:
    """`source`, `single` (a `cveId` query), `page`, or `other`."""
    if is_source_api_request(request):
        return "source"
    if requested_cve_id(request) is not None:
        return "single"
    if is_cve_api_request(request):
        return "page"
    return "other"


def requested_page_index(request: httpx.Request) -> int | None:
    """The page index `startIndex / resultsPerPage` of a window page
    request, `None` when either is absent or not a multiple."""
    if request_kind(request) != "page":
        return None
    try:
        start_index = int(request.url.params["startIndex"])
        results_per_page = int(request.url.params["resultsPerPage"])
    except KeyError, ValueError:
        return None
    if results_per_page <= 0 or start_index % results_per_page:
        return None
    return start_index // results_per_page


class NvdServer:
    """A fake NVD CVE API and Source API for `httpx.MockTransport`.

    A Source API request is answered by the next `source_once` responder,
    else by `source_response`, else with `sources` (any JSON value) and
    HTTP 200. A CVE API request with a `cveId` parameter is a single query:
    the next `single_once[cve_id]` responder, else `single_responses[cve_id]`,
    else a page of `singles[cve_id]` (an empty page for an unknown CVE-ID)
    whose `totalResults` is its element count. Any other CVE API request is a
    window page `i` (`startIndex = i * resultsPerPage`): the next
    `page_once[i]` responder, else `page_responses[i]`, else `pages[i]` (a
    list of elements) in a page envelope whose `totalResults` is
    `totals[i]` when set, otherwise the count that makes `len(pages)` pages
    of `resultsPerPage` with the last one's elements. An unknown page and a
    request to another scheme, host, port, or path are answered with HTTP
    404. Every request is recorded in `requests`, in order.
    """

    def __init__(
        self,
        pages: Sequence[Sequence[Any]] | None = None,
        singles: Mapping[str, Sequence[Any]] | None = None,
        sources: Any = None,
    ) -> None:
        self.pages: list[list[Any]] = (
            [list(page) for page in pages] if pages is not None else [[]]
        )
        self.totals: dict[int, int] = {}
        self.page_responses: dict[int, Responder] = {}
        self.page_once: dict[int, list[Responder]] = {}
        self.singles: dict[str, list[Any]] = {
            cve_id: list(elements) for cve_id, elements in (singles or {}).items()
        }
        self.single_responses: dict[str, Responder] = {}
        self.single_once: dict[str, list[Responder]] = {}
        self.sources: Any = (
            load_json_fixture(SOURCE_PAGE) if sources is None else sources
        )
        self.source_response: Responder | None = None
        self.source_once: list[Responder] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        kind = request_kind(request)
        if kind == "source":
            return self._source(request)
        if kind == "single":
            return self._single(request)
        if kind == "page":
            return self._page(request)
        return httpx.Response(404, request=request)

    def _source(self, request: httpx.Request) -> httpx.Response:
        if self.source_once:
            return self.source_once.pop(0)(request)
        if self.source_response is not None:
            return self.source_response(request)
        return _json_response(request, self.sources)

    def _single(self, request: httpx.Request) -> httpx.Response:
        cve_id = requested_cve_id(request)
        assert cve_id is not None
        queued = self.single_once.get(cve_id)
        if queued:
            return queued.pop(0)(request)
        if cve_id in self.single_responses:
            return self.single_responses[cve_id](request)
        elements = self.singles.get(cve_id, [])
        return _json_response(request, page_body(elements, len(elements)))

    def _page(self, request: httpx.Request) -> httpx.Response:
        index = requested_page_index(request)
        if index is None:
            return httpx.Response(404, request=request)
        queued = self.page_once.get(index)
        if queued:
            return queued.pop(0)(request)
        if index in self.page_responses:
            return self.page_responses[index](request)
        if index >= len(self.pages):
            return httpx.Response(404, request=request)
        results_per_page = int(request.url.params["resultsPerPage"])
        total = self.totals.get(
            index,
            results_per_page * (len(self.pages) - 1) + len(self.pages[-1]),
        )
        return _json_response(
            request,
            page_body(self.pages[index], total, index * results_per_page),
        )

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def kinds(self) -> list[str]:
        """The `request_kind()` of every request, in order."""
        return [request_kind(request) for request in self.requests]

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def api_key_headers(self) -> list[str | None]:
        """The `apiKey` header of every request, in order."""
        return [request.headers.get(API_KEY_HEADER) for request in self.requests]

    @property
    def page_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if request_kind(r) == "page"]

    @property
    def single_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if request_kind(r) == "single"]

    @property
    def source_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if request_kind(r) == "source"]

    @property
    def requested_page_indexes(self) -> list[int | None]:
        return [requested_page_index(request) for request in self.page_requests]
