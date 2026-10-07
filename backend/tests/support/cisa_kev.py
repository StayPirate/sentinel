"""Shared CISA KEV fixture and a fake catalog endpoint.

`backend/tests/fixtures/cisa_kev/known_exploited_vulnerabilities.json` is
a trimmed copy of the live catalog
`GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
captured anonymously on 2026-10-07 without following redirects
(`catalogVersion` `2026.10.04`). It keeps the five top-level members in
their live order and five unmodified live entries, minified with the
live `\\uXXXX` escapes; `count` is set to the trimmed length (5):

- CVE-2026-88779: one CWE, `forensicTriage` `"Yes"`;
- CVE-2026-81963: two CWEs, `forensicTriage` `"No"`;
- CVE-2015-3246: an empty `cwes`;
- CVE-2026-20316: one CWE, `knownRansomwareCampaignUse` `"Known"`;
- CVE-2026-104286: a six-digit sequence number, two CWEs,
  `forensicTriage` `"Yes"`.

Every retained field, including free text and the `notes` URLs, was
reviewed: it names vendors, products, and public advisory pages only and
contains no personal identifier, so nothing was replaced
(docs/conventions.md, External Integration Contract Verification).

`KevServer` is an in-process `httpx.MockTransport` handler for the
catalog URL (docs/features/tickets/cve-sync-kev.md, Algorithm): it serves
`catalog` with HTTP 200, or the raw `response` responder when a test sets
one (status codes, undecodable bodies, transport errors).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "cisa_kev"
    / "known_exploited_vulnerabilities.json"
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
"""The production catalog URL (cve-sync-kev.md, Fetcher Definition)."""

REFERENCE_URL_PATTERN = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"
)
"""The constructed per-CVE reference URL (cve-sync-kev.md, Field Mapping)."""

FIXTURE_CVE_IDS = (
    "CVE-2026-88779",
    "CVE-2026-81963",
    "CVE-2015-3246",
    "CVE-2026-20316",
    "CVE-2026-104286",
)
"""The fixture entries' `cveID` values, in catalog order."""


def load_raw_catalog() -> bytes:
    """Return the fixture file's bytes unparsed."""
    return FIXTURE_PATH.read_bytes()


def load_catalog() -> dict[str, Any]:
    """Return the fixture catalog as parsed JSON (a fresh copy)."""
    data: dict[str, Any] = json.loads(load_raw_catalog())
    return data


def fixture_entry(cve_id: str) -> dict[str, Any]:
    """The fixture entry for `cve_id` (a fresh copy)."""
    for entry in load_catalog()["vulnerabilities"]:
        if entry["cveID"] == cve_id:
            result: dict[str, Any] = entry
            return result
    raise KeyError(cve_id)


def entry_for(
    cve_id: str,
    *,
    date_added: Any = "2026-10-01",
    cwes: Any = ("CWE-79",),
) -> dict[str, Any]:
    """A live-shaped entry for `cve_id`: the first fixture entry's
    unconsumed members with the given consumed values."""
    entry = fixture_entry(FIXTURE_CVE_IDS[0])
    entry["cveID"] = cve_id
    entry["dateAdded"] = date_added
    entry["cwes"] = list(cwes) if isinstance(cwes, tuple) else cwes
    return entry


def catalog_of(*entries: Mapping[str, Any] | Any) -> dict[str, Any]:
    """A live-shaped catalog carrying `entries` with a matching `count`."""
    catalog = load_catalog()
    catalog["vulnerabilities"] = [
        dict(entry) if isinstance(entry, Mapping) else copy.deepcopy(entry)
        for entry in entries
    ]
    catalog["count"] = len(entries)
    return catalog


def reference_url(cve_id: str) -> str:
    """The constructed per-CVE reference URL."""
    return REFERENCE_URL_PATTERN.format(cve_id=cve_id)


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def status(code: int, content: bytes = b"", **headers: str) -> Responder:
    """A responder that answers with `code`, the raw `content`, and
    `headers` (underscores become hyphens)."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            content=content,
            headers={key.replace("_", "-"): value for key, value in headers.items()},
            request=request,
        )

    return respond


def raw_body(content: bytes) -> Responder:
    """A responder that serves the raw `content` with HTTP 200."""
    return status(200, content, content_type="application/json")


class KevServer:
    """A fake CISA KEV catalog endpoint for `httpx.MockTransport`.

    `catalog` is the decoded document served with HTTP 200 (mutable by
    tests; any JSON value). `response`, when set, answers instead. Every
    request is recorded in `requests`; a request for another URL is
    answered with HTTP 404.
    """

    def __init__(self, catalog: Any = None) -> None:
        self.catalog: Any = load_catalog() if catalog is None else catalog
        self.response: Responder | None = None
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) != KEV_URL:
            return httpx.Response(404, request=request)
        if self.response is not None:
            return self.response(request)
        return httpx.Response(200, json=self.catalog, request=request)

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
