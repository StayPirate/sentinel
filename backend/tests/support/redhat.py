"""Shared Red Hat Security Data fixtures and a fake per-CVE endpoint.

The files under `backend/tests/fixtures/redhat/` are live
`GET https://access.redhat.com/hydra/rest/securitydata/cve/{CVE-ID}.json`
responses captured anonymously on 2026-10-06 through Sentinel's production
HTTP client (`create_http_client(name="sync_redhat_cves")`, its standard
User-Agent):

- `cve_full_v3.json` (CVE-2024-6387): `cvss3`, `cwe`, `references`,
  `bugzilla`, `package_state` with duplicate names and one container path
  containing `/`, `affected_release`, `mitigation`, `acknowledgement`,
  `statement`, and `details`;
- `cve_v2_v3.json` (CVE-2016-5195): both `cvss` (v2) and `cvss3`, no `cwe`,
  one `package_state` entry;
- `cve_v2_only.json` (CVE-2014-0160): `cvss` only, `cwe`, and duplicate
  package names;
- `cve_no_cvss.json` (CVE-2005-3623): no `cvss`, `cvss3`, `cwe`, or
  `package_state`; only `references`, `bugzilla`, and unconsumed fields;
- `not_found.json`: the HTTP 404 body for an unknown CVE-ID, stored
  byte-for-byte as served with `Content-Type: application/json`. It is a
  JSON *string* literal, not an object, and Sentinel does not consume it.

They were sanitized before saving (docs/conventions.md, External
Integration Contract Verification): every `details` element, `statement`,
`acknowledgement`, and `mitigation.value` was replaced with fictional text;
every reference URL whose host is not `www.cve.org`, `nvd.nist.gov`, or
`www.cisa.gov` was replaced with a fictional
`https://advisory.example.invalid/upstream/<n>` URL; and `package_state`
and `affected_release` were trimmed. Bugzilla descriptions, Red Hat
product names, CPEs, and package names are public product and flaw data,
not personal identifiers, and are retained.

`RedhatServer` is an in-process `httpx.MockTransport` handler for the
per-CVE endpoint (docs/features/tickets/cve-sync-redhat.md, Algorithm):
`bodies` maps a CVE-ID to the JSON served with HTTP 200, and any other
CVE-ID is answered with the live 404 body. Tests register raw `responses`
(status codes, undecodable bodies, transport errors) and inspect
`requests`.

Consumers, all under `tests/test_services/test_tickets/`: the fixture
loaders by `test_redhat_cve_contract.py` and `test_redhat_cve_record.py`;
`RedhatServer` by `test_sync_redhat_cves.py`,
`test_sync_redhat_cves_execute.py`, and
`test_sync_redhat_cves_reachability.py`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "redhat"

REDHAT_CVE_PATH_PREFIX = "/hydra/rest/securitydata/cve/"
"""Path of the per-CVE endpoint up to the `{CVE-ID}.json` segment."""

CVE_SUCCESS_FIXTURES = ("cve_full_v3", "cve_v2_v3", "cve_v2_only", "cve_no_cvss")
"""Sanitized live HTTP 200 per-CVE responses, by fixture name."""

NOT_FOUND_FIXTURE = "not_found"
"""The live HTTP 404 body for an unknown CVE-ID, stored as served."""


def load_cve_fixture(name: str) -> dict[str, Any]:
    """Return one sanitized live HTTP 200 per-CVE response as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed (the 404 body as served)."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def redhat_cve_url(cve_id: str) -> str:
    """The production per-CVE request URL for `cve_id`."""
    return f"https://access.redhat.com{REDHAT_CVE_PATH_PREFIX}{cve_id}.json"


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


class RedhatServer:
    """A fake Red Hat per-CVE endpoint for `httpx.MockTransport`.

    `bodies` maps a CVE-ID to the JSON body served for it with HTTP 200
    (any JSON value, mutable by tests); `responses` maps a CVE-ID to a
    callable that returns a raw response or raises a transport error
    instead. A request for any other CVE-ID, or for another path, is
    answered with the live HTTP 404 body. Every request is recorded in
    `requests`.
    """

    def __init__(self, bodies: Mapping[str, Any] | None = None) -> None:
        self.bodies: dict[str, Any] = dict(bodies or {})
        self.responses: dict[str, Responder] = {}
        self.requests: list[httpx.Request] = []

    @classmethod
    def for_fixtures(cls, *names: str) -> RedhatServer:
        """Serve the named success fixtures under their own CVE-IDs."""
        fixtures = [load_cve_fixture(name) for name in names]
        return cls({fixture["name"]: fixture for fixture in fixtures})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        cve_id = requested_cve_id(request)
        if cve_id is not None and cve_id in self.responses:
            return self.responses[cve_id](request)
        if cve_id is None or cve_id not in self.bodies:
            return httpx.Response(
                404,
                content=load_raw_fixture(NOT_FOUND_FIXTURE),
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(200, json=self.bodies[cve_id])

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
    """The `{CVE-ID}` of a per-CVE request path, or `None` for another path."""
    path = request.url.path
    if not path.startswith(REDHAT_CVE_PATH_PREFIX) or not path.endswith(".json"):
        return None
    return path.removeprefix(REDHAT_CVE_PATH_PREFIX).removesuffix(".json") or None
