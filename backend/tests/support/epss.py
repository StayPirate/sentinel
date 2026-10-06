"""Shared FIRST.org EPSS fixtures and a fake single-CVE endpoint.

The files under `backend/tests/fixtures/epss/` are live
`GET https://api.first.org/data/v1/epss?cve={CVE-ID}` response bodies,
captured anonymously on 2026-10-06 through Sentinel's production HTTP
client (`create_http_client(name="sync_epss_scores")`, its standard
User-Agent), stored byte-for-byte as served (each body ends with one newline):

- `scored.json` (CVE-2024-6387): one `data[]` entry;
- `scored_percentile_one.json` (CVE-2021-44228): one entry whose
  `percentile` is the upper bound `"1.000000000"`;
- `scored_low.json` (CVE-2026-0001): one entry with a low score and
  percentile;
- `unscored.json` (CVE-2099-99999, a syntactically valid CVE-ID that EPSS
  does not score): `total: 0` and `data: []`.

The bodies carry only CVE-IDs, decimal scores, a publication date, and
the envelope; they contain no personal identifier, so nothing was
replaced (docs/conventions.md, External Integration Contract
Verification).

`EpssServer` is an in-process `httpx.MockTransport` handler for the EPSS
endpoint (docs/features/tickets/cve-sync-epss.md, Algorithm): `entries`
maps a CVE-ID to the `data[0]` object served for it in a live-shaped
envelope with HTTP 200, and any other CVE-ID is answered with the live
unscored envelope. Tests register raw `responses` (status codes,
undecodable bodies, transport errors, malformed envelopes) and inspect
`requests`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "epss"

EPSS_URL = "https://api.first.org/data/v1/epss"
"""The production EPSS endpoint, without the `cve` query parameter."""

SCORED_FIXTURES = ("scored", "scored_percentile_one", "scored_low")
"""Live HTTP 200 responses with one `data[]` entry, by fixture name."""

UNSCORED_FIXTURE = "unscored"
"""The live HTTP 200 response for a CVE-ID that EPSS does not score."""

ALL_FIXTURES = (*SCORED_FIXTURES, UNSCORED_FIXTURE)


def load_fixture(name: str) -> dict[str, Any]:
    """Return one live EPSS response body as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def scored_entry(name: str = "scored") -> dict[str, Any]:
    """The `data[0]` object of one scored fixture (a fresh copy)."""
    entry: dict[str, Any] = load_fixture(name)["data"][0]
    return entry


def envelope(*entries: Mapping[str, Any]) -> dict[str, Any]:
    """A live-shaped envelope (the unscored fixture's) carrying `entries`."""
    body = load_fixture(UNSCORED_FIXTURE)
    body["data"] = [dict(entry) for entry in entries]
    body["total"] = len(entries)
    return body


def entry_for(
    cve_id: str,
    *,
    epss: str = "0.500000000",
    percentile: str = "0.500000000",
    date: str = "2026-10-06",
) -> dict[str, str]:
    """A live-shaped `data[]` entry for `cve_id`."""
    return {"cve": cve_id, "epss": epss, "percentile": percentile, "date": date}


def epss_url(cve_id: str) -> str:
    """The production request URL for `cve_id`."""
    return str(httpx.URL(EPSS_URL, params={"cve": cve_id}))


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


class EpssServer:
    """A fake EPSS single-CVE endpoint for `httpx.MockTransport`.

    `entries` maps a CVE-ID to the `data[0]` object served for it with
    HTTP 200 in a live-shaped envelope (mutable by tests); `responses`
    maps a CVE-ID to a callable that returns a raw response or raises a
    transport error instead. A request for any other CVE-ID, or for
    another path, is answered with the live unscored envelope. Every
    request is recorded in `requests`.
    """

    def __init__(self, entries: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.entries: dict[str, dict[str, Any]] = {
            cve_id: dict(entry) for cve_id, entry in (entries or {}).items()
        }
        self.responses: dict[str, Responder] = {}
        self.requests: list[httpx.Request] = []

    @classmethod
    def scoring(cls, *cve_ids: str, **fields: str) -> EpssServer:
        """Serve one `entry_for(cve_id, **fields)` per CVE-ID."""
        return cls({cve_id: entry_for(cve_id, **fields) for cve_id in cve_ids})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        cve_id = requested_cve_id(request)
        if cve_id is not None and cve_id in self.responses:
            return self.responses[cve_id](request)
        if cve_id is None or cve_id not in self.entries:
            return httpx.Response(
                200,
                content=load_raw_fixture(UNSCORED_FIXTURE),
                headers={"Content-Type": "application/json; charset=utf-8"},
                request=request,
            )
        return httpx.Response(200, json=envelope(self.entries[cve_id]), request=request)

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def requested_cve_ids(self) -> list[str | None]:
        return [requested_cve_id(request) for request in self.requests]


def requested_cve_id(request: httpx.Request) -> str | None:
    """The `cve` query parameter of an EPSS request, or `None` for another
    path or a request without exactly one `cve` parameter."""
    url = request.url
    if f"{url.scheme}://{url.host}{url.path}" != EPSS_URL:
        return None
    values = url.params.get_list("cve")
    return values[0] if len(values) == 1 else None
