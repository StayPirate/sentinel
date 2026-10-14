"""Sanitized IBS request-operation fixtures and their loader.

The documents under `backend/tests/fixtures/ibs/requests/` were captured
read-only from the IBS API (`https://api.suse.de`) on 2026-10-14 with
`secbox osc -A https://api.suse.de api [-X POST] ...` (docs/conventions.md,
External Integration Contract Verification;
docs/features/integrations/ibs-integration.md, Request ID Search, Request
Point Detail, Request Action Diff, Package Source History). Each call ran
in a capture process that kept stdout and stderr in memory; error status
lines and status documents were read with `osc --debug`. Nothing raw
reached a terminal or a file. Only the consumed elements and attributes
were written:

- search: `collection/@matches`, `request/@id`;
- point detail: `request/@id`; `state/@name`, `@created`, `@when`,
  `@superseded_by`; `action/@type`; `source/@project`, `@package`, `@rev`;
  `target/@project`, `@package`, `@releaseproject`; `acceptinfo/@rev`,
  `@srcmd5`, `@xsrcmd5`, `@osrcmd5`, `@oxsrcmd5`, `@oproject`,
  `@opackage`;
- request action diff: `sourcediff`, `issues`, `issue/@state`, `@tracker`,
  `@name`, `@label`;
- source history: `revision/@rev` with its `srcmd5`, `time`, and
  `requestid` children;
- error responses: `status/@code` and `@origin`.

Everything else was discarded unread, notably the state `who`, the
request `creator`, `description`, `review`, and `history` elements, the
action `options` element, the diff `old`, `new`, and `files` elements and
the issue `url`, the history `vrev` attribute and `user`, `comment`, and
`version` children, every error summary, and all headers, signatures, and
cookies. The client tests add unconsumed elements and attributes back to
synthetic documents to prove they are ignored.

Values: request numbers are fictional (from 910001, one value per real
number, also inside `SUSE:Maintenance:REQUEST:{n}` staging projects and
history `requestid`), incident numbers are fictional (from 80001, also in
`SUSE:Maintenance:{n}` projects and `.{n}` package suffixes), and every
checksum is a fictional MD5-shaped value that keeps the equalities of the
live data. `0123456789abcdef0123456789abcdef` is a fictional checksum that
was never stored upstream. Every project outside `SUSE:` and `openSUSE:`
was replaced by `home:fictional` (two detail fixtures). Revision numbers,
timestamps, and the public CVE and bug identifiers are as served. No
personal identifier remains.

The success documents form one coherent chain for `openvpn` in
`SUSE:SLE-15-SP6:Update` (fictional incident 80001):

- `request_sr_accepted_earlier` (SR 910052) and `request_sr_accepted`
  (SR 910053) are the two accepted submissions of the incident; their
  incident-package history is `history_incident`, whose revisions without
  `requestid` are branch commits; `history_lookup_checksum_multiple` looks
  up the checksum those branch commits share;
- `request_rr_revoked` (RR 910141) released SR 910052's contents and was
  revoked; `request_rr_accepted` (RR 910051) released the incident with one
  codestream action and patchinfo actions; `history_lookup_revision` is the
  exact lookup of its target package, and `history_codestream` the
  codestream history ending with it;
- `request_sr_open` (SR 910015) is a later open submission;
- `diff_sr_accepted`, `diff_rr_accepted`, `diff_rr_patchinfo_accepted`, and
  `diff_sr_open` are the request action diffs of those actions, in the form
  ibs-integration.md (Request Action Diff) derives from their point detail.

The other documents are an open release request with patchinfo actions
without `source/@rev` (`request_rr_open`, `python311` in
`SUSE:SLE-15-SP4:Update`, with `diff_rr_open`); an accepted kernel release
request with `submit` actions, link-released flavor actions without
`acceptinfo`, and `kernel-default-base` with `acceptinfo`
(`request_rr_kernel`); an SR superseded by a declined SR
(`request_sr_superseded`, `request_sr_declined`); an accepted SR from a
personal project and its accepted-form diff through its `SUSE:Maintenance`
target (`request_sr_home`, `diff_sr_home_accepted`); a request whose only
action is a `submit` (`request_non_maintenance`); the ID searches the
client constructs, plus an all-states and a single-state search and the
rejected `target/@releaseproject` predicate; and the 400 and 404 responses
of each operation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from tests.support.ibs_api import FIXTURE_DIR, IBSServer, status_response, xml_response

REQUEST_FIXTURE_DIR: Final = FIXTURE_DIR / "requests"
REQUEST_FIXTURE_DATE: Final = "2026-10-14"

SEARCH_FIXTURES: Final = (
    "search_open_sr_source_prefix",
    "search_open_rr_target_prefix",
    "search_open_rr_empty",
    "search_single_state",
    "search_all_states",
)
SEARCH_ERROR_FIXTURES: Final = ("search_error_releaseproject",)
DETAIL_FIXTURES: Final = (
    "request_sr_open",
    "request_sr_accepted",
    "request_sr_accepted_earlier",
    "request_sr_declined",
    "request_sr_superseded",
    "request_sr_home",
    "request_rr_open",
    "request_rr_accepted",
    "request_rr_revoked",
    "request_rr_kernel",
    "request_non_maintenance",
)
DETAIL_ERROR_FIXTURES: Final = ("request_not_found",)
ACTION_DIFF_FIXTURES: Final = (
    "diff_sr_accepted",
    "diff_sr_open",
    "diff_sr_home_accepted",
    "diff_rr_accepted",
    "diff_rr_patchinfo_accepted",
    "diff_rr_open",
)
ACTION_DIFF_ERROR_FIXTURES: Final = (
    "diff_error_bad_link",
    "diff_error_unavailable_checksum",
    "diff_error_unknown_project",
    "diff_error_unknown_package",
)
HISTORY_FIXTURES: Final = (
    "history_codestream",
    "history_incident",
    "history_lookup_revision",
    "history_lookup_checksum_multiple",
    "history_lookup_unknown_revision",
    "history_lookup_unknown_checksum",
)
HISTORY_ERROR_FIXTURES: Final = (
    "history_error_unknown_package",
    "history_error_unknown_project",
)
REQUEST_FIXTURES: Final = (
    *SEARCH_FIXTURES,
    *SEARCH_ERROR_FIXTURES,
    *DETAIL_FIXTURES,
    *DETAIL_ERROR_FIXTURES,
    *ACTION_DIFF_FIXTURES,
    *ACTION_DIFF_ERROR_FIXTURES,
    *HISTORY_FIXTURES,
    *HISTORY_ERROR_FIXTURES,
)

FICTIONAL_UNSTORED_CHECKSUM: Final = "0123456789abcdef0123456789abcdef"
"""A fictional checksum that IBS never stored (lookups and diffs)."""


def load_request_fixture(name: str) -> bytes:
    """The bytes of request fixture `name` (without the `.xml` suffix)."""
    return (REQUEST_FIXTURE_DIR / f"{name}.xml").read_bytes()


def load_request_responses() -> dict[str, Any]:
    """The parsed `requests/responses.json`."""
    data: dict[str, Any] = json.loads(
        (REQUEST_FIXTURE_DIR / "responses.json").read_text(encoding="utf-8")
    )
    return data


def request_fixture_record(name: str) -> dict[str, Any]:
    """The recorded method, path, query, and status of fixture `name`."""
    record: dict[str, Any] = load_request_responses()["documents"][f"{name}.xml"]
    return record


def request_fixture_query(name: str) -> list[tuple[str, str]]:
    """The ordered query of the live request that produced fixture `name`."""
    return [(key, value) for key, value in request_fixture_record(name)["query"]]


def request_fixture_paths() -> list[Path]:
    """Every stored request fixture document."""
    return sorted(REQUEST_FIXTURE_DIR.glob("*.xml"))


def serve_request_fixture(server: IBSServer, name: str) -> None:
    """Route fixture `name` on `server` at its recorded method and path,
    with its recorded status."""
    record = request_fixture_record(name)
    document = load_request_fixture(name)
    status = record["status"]
    responder = (
        xml_response(document) if status == 200 else status_response(status, document)
    )
    server.route(record["method"], record["path"], responder)
