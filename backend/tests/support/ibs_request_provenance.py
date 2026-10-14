"""Sanitized IBS provenance-chain fixtures and their loader.

The documents under `backend/tests/fixtures/ibs/reconciliation/` were
captured read-only from the IBS API (`https://api.suse.de`) on 2026-10-14
with `secbox osc -A https://api.suse.de api [-X POST] ...`
(docs/conventions.md, External Integration Contract Verification;
docs/features/packages/ibs-submission-tracking.md, Required Roots, Effective
SR, Release Discovery, Accepted RR Provenance). Each call ran in a capture
process that kept stdout and stderr in memory and wrote only an
allow-listed rebuild of the document; nothing raw reached a terminal or a
file. The diff requests were built with the production
`request_action_diff_form()` from the captured point detail, and the
current release evidence with the source-info and `orev=0` source-diff
forms of `IBSClient`. Only consumed elements and attributes were written:

- point detail: `request/@id`; `state/@name`, `@created`, `@when`,
  `@superseded_by`; `action/@type`; `source/@project`, `@package`, `@rev`;
  `target/@project`, `@package`, `@releaseproject`; `acceptinfo/@rev`,
  `@srcmd5`, `@xsrcmd5`, `@osrcmd5`, `@oxsrcmd5`, `@oproject`, `@opackage`;
- source history: `revision/@rev` with its `srcmd5`, `time`, and
  `requestid` children;
- diffs: `sourcediff`, `issues`, `issue/@state`, `@tracker`, `@name`,
  `@label`;
- source info: `sourceinfo/@package`, `@srcmd5`, and an `error` child.

Everything else was discarded unread, notably the state `who`, the request
`creator`, `description`, `review`, and `history` elements, the history
`user`, `comment`, and `version` children, and all headers, signatures,
and cookies.

Values: the real-to-fictional mapping of the earlier request capture
(`tests/support/ibs_request_api.py`) no longer exists, so this group has
its own fictional block. Request numbers start at 960001 (one value per
real number, also inside `SUSE:Maintenance:REQUEST:{n}` projects and
history `requestid`), incident numbers at 81001 (also in
`SUSE:Maintenance:{n}` projects and `.{n}` package suffixes), and every
checksum is a fictional MD5-shaped value that keeps the equalities of the
live data. Revision numbers, timestamps, and the public CVE and bug
identifiers are as served. Every captured project is a `SUSE:` project; no
personal identifier was present.

Three chains:

- **A — current release evidence of the `openvpn` chain of
  `tests/support/ibs_request_api.py`** in `SUSE:SLE-15-SP6:Update`:
  `a_sourceinfo_current` (the expanded `srcmd5`, a new fictional value)
  and `a_diff_current` (its `orev=0` diff), which carries the two CVEs
  that release request 910051 of that group released.
- **B — a release before 2023** of `openvpn` in its origin codestream
  `SUSE:SLE-15:Update` (incident 81001): `b_history_codestream` (three
  release requests; the newest, 960003, is the proving one),
  `b_request_rr_accepted` (960003, with the codestream action and
  patchinfo actions), `b_history_lookup` (the exact lookup of its target
  package `openvpn.81001`), `b_diff_rr_accepted` (its release diff),
  `b_history_incident` (branch commit, the SR, the release request),
  `b_request_sr_accepted` (SR 960004, whose acceptinfo `xsrcmd5` differs
  from the release action's `source/@rev`), `b_diff_sr_accepted`, and the
  current release evidence `b_sourceinfo_current` and `b_diff_current`.
- **C — a kernel incident** in `SUSE:SLE-15-SP6:Update` (incident 81003,
  previous incident 81004): `c_history_codestream_source` and
  `c_history_codestream_default` (32 release requests each; the newest
  is 960036, the one before 960035); `c_request_rr_accepted` (960035:
  `submit` actions, flavor release actions without acceptinfo,
  `kernel-source` and `kernel-default-base` with acceptinfo) and
  `c_request_rr_newer` (960036, incident 81005); the exact lookups
  `c_history_lookup_source`, `c_history_lookup_source_newer`, and
  `c_history_lookup_default_base`; the release diffs `c_diff_rr_source`,
  `c_diff_rr_source_newer` (disjoint CVE sets), and
  `c_diff_rr_default_base` (an empty `issues` element: the package's own
  changelog references no CVE); `c_history_incident_source` (branch, SR
  960037, branch, SR 960038, the release request) and
  `c_history_incident_default_base` (branch, release request: no SR);
  `c_request_sr_first` and `c_request_sr_second` with their accepted
  diffs `c_diff_sr_first` and `c_diff_sr_second`.

The `orev=0` diff of the kernel codestream package was verified live (HTTP
200, about 17,000 issues, 2.4 MB, 4 s) and is not stored because of its
size; its shape is the one of `a_diff_current` and `b_diff_current`.

`responses.json` records the method, decoded path, ordered query, and
status of each request with the fictional values. `ProvenanceServer`
serves the documents at their recorded method, path, and query through the
authenticating `IBSServer`, so the same path can serve an unpaged history
and an exact lookup.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx

from tests.support.ibs_api import FIXTURE_DIR, IBSServer, Responder, xml_response

PROVENANCE_FIXTURE_DIR: Final = FIXTURE_DIR / "reconciliation"
PROVENANCE_FIXTURE_DATE: Final = "2026-10-14"

SP6: Final = "SUSE:SLE-15-SP6:Update"
SLE15: Final = "SUSE:SLE-15:Update"

A_CVES: Final = ("CVE-2026-63650", "CVE-2026-84732")
"""The CVEs that release request 910051 of the request group released."""
B_CVE: Final = "CVE-2022-0547"
B_RR: Final = 960003
B_SR: Final = 960004
B_INCIDENT: Final = 81001
C_RR: Final = 960035
C_RR_NEWER: Final = 960036
C_SR_FIRST: Final = 960037
C_SR_SECOND: Final = 960038
C_INCIDENT: Final = 81003
C_INCIDENT_NEWER: Final = 81005

PROVENANCE_FIXTURES: Final = (
    "a_sourceinfo_current",
    "a_diff_current",
    "b_history_codestream",
    "b_request_rr_accepted",
    "b_history_lookup",
    "b_diff_rr_accepted",
    "b_history_incident",
    "b_request_sr_accepted",
    "b_diff_sr_accepted",
    "b_sourceinfo_current",
    "b_diff_current",
    "c_history_codestream_source",
    "c_history_codestream_default",
    "c_request_rr_accepted",
    "c_request_rr_newer",
    "c_history_lookup_source",
    "c_history_lookup_source_newer",
    "c_history_lookup_default_base",
    "c_diff_rr_source",
    "c_diff_rr_source_newer",
    "c_diff_rr_default_base",
    "c_history_incident_source",
    "c_history_incident_default_base",
    "c_request_sr_first",
    "c_request_sr_second",
    "c_diff_sr_first",
    "c_diff_sr_second",
)


def load_provenance_fixture(name: str) -> bytes:
    """The bytes of provenance fixture `name` (without the `.xml` suffix)."""
    return (PROVENANCE_FIXTURE_DIR / f"{name}.xml").read_bytes()


def load_provenance_responses() -> dict[str, Any]:
    """The parsed `reconciliation/responses.json`."""
    data: dict[str, Any] = json.loads(
        (PROVENANCE_FIXTURE_DIR / "responses.json").read_text(encoding="utf-8")
    )
    return data


def provenance_fixture_record(name: str) -> dict[str, Any]:
    """The recorded method, path, query, and status of fixture `name`."""
    record: dict[str, Any] = load_provenance_responses()["documents"][f"{name}.xml"]
    return record


def provenance_fixture_query(name: str) -> list[tuple[str, str]]:
    """The ordered query of the live request that produced fixture `name`."""
    return [(key, value) for key, value in provenance_fixture_record(name)["query"]]


def provenance_fixture_paths() -> list[Path]:
    """Every stored provenance fixture document."""
    return sorted(PROVENANCE_FIXTURE_DIR.glob("*.xml"))


Query = tuple[tuple[str, str], ...]


@dataclass
class QueryRoutes:
    """Query-aware routes on top of `IBSServer`, which routes by method and
    path only: one dispatcher per `(method, path)` selects the responder of
    the request's exact ordered query. An unrouted query is recorded in
    `unrouted` and answered with HTTP 404."""

    server: IBSServer
    unrouted: list[tuple[str, str, Query]] = field(default_factory=list)
    _routes: dict[tuple[str, str], dict[Query, Responder]] = field(default_factory=dict)

    def route(
        self, method: str, path: str, query: list[tuple[str, str]], responder: Responder
    ) -> None:
        key = (method, path)
        if key not in self._routes:
            self._routes[key] = {}
            self.server.route(method, path, self._dispatcher(key))
        self._routes[key][tuple(query)] = responder

    def _dispatcher(self, key: tuple[str, str]) -> Responder:
        def dispatch(request: httpx.Request) -> httpx.Response:
            query = tuple(request.url.params.multi_items())
            responder = self._routes[key].get(query)
            if responder is None:
                self.unrouted.append((key[0], key[1], query))
                return httpx.Response(404)
            return responder(request)

        return dispatch


def serve_provenance_fixture(routes: QueryRoutes, name: str) -> None:
    """Route fixture `name` at its recorded method, path, and query."""
    record = provenance_fixture_record(name)
    routes.route(
        record["method"],
        record["path"],
        provenance_fixture_query(name),
        xml_response(load_provenance_fixture(name)),
    )
