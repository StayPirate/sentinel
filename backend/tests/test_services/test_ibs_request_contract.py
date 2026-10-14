"""Contract tests for the IBS request-operation documents.

Contract under test: docs/features/integrations/ibs-integration.md (Request
ID Search, Request Point Detail, Request Action Diff, Package Source
History, Request Contract Verification Status), verified against the
sanitized live captures of 2026-10-14 described in
`tests/support/ibs_request_api.py` (docs/conventions.md, External
Integration Contract Verification). Every consumed field is asserted for
name, nesting, cardinality, and format, and every recorded request against
the form the specification derives; the documents are read with the
standard-library tree parser because the fixtures are trusted.

The capture kept only consumed elements and attributes, so unconsumed
content is absent here by construction; the client tests add it back to
synthetic documents. Not observed live and therefore covered by synthetic
documents only: HTTP 403 outcomes, the `deleted` state on a maintenance
request, an action type outside the eight IBS types, a supported action
missing a required field, malformed or interrupted bodies, U+0000 and
surrogates, a `matches` count that differs from the entries, duplicate
entries, an issue without `tracker` or `state`, and an unpaged history
that does not start at revision 1 or has a gap. The response media type
was not observable through `osc api` and is not consumed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Final

import pytest

from tests.support.ibs_request_api import (
    ACTION_DIFF_ERROR_FIXTURES,
    ACTION_DIFF_FIXTURES,
    DETAIL_ERROR_FIXTURES,
    DETAIL_FIXTURES,
    FICTIONAL_UNSTORED_CHECKSUM,
    HISTORY_ERROR_FIXTURES,
    HISTORY_FIXTURES,
    REQUEST_FIXTURE_DATE,
    REQUEST_FIXTURES,
    SEARCH_ERROR_FIXTURES,
    SEARCH_FIXTURES,
    load_request_fixture,
    load_request_responses,
    request_fixture_paths,
    request_fixture_query,
    request_fixture_record,
)

pytestmark = pytest.mark.unit

_DECIMAL: Final = re.compile(r"[1-9][0-9]*")
_CHECKSUM: Final = re.compile(r"[0-9a-f]{32}")
_IBS_NAME: Final = re.compile(r"[A-Za-z0-9_.:+\-]{1,255}")
_TIMESTAMP: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}")
_CVE: Final = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_STATES: Final = frozenset(
    {"new", "review", "accepted", "declined", "revoked", "superseded", "deleted"}
)
_ACTION_TYPES: Final = frozenset(
    {
        "submit",
        "delete",
        "add_role",
        "set_bugowner",
        "change_devel",
        "release",
        "maintenance_incident",
        "maintenance_release",
    }
)
_SUPPORTED: Final = frozenset({"maintenance_incident", "maintenance_release"})
_REQUIRED: Final = {
    "maintenance_incident": {
        ("source", "project"),
        ("source", "package"),
        ("target", "releaseproject"),
    },
    "maintenance_release": {
        ("source", "project"),
        ("source", "package"),
        ("target", "project"),
        ("target", "package"),
    },
}
_ACCEPTINFO: Final = ("rev", "srcmd5", "xsrcmd5", "osrcmd5", "oxsrcmd5")
_ALLOWED: Final = {
    "collection": {"matches"},
    "request": {"id"},
    "state": {"name", "created", "when", "superseded_by"},
    "action": {"type"},
    "source": {"project", "package", "rev"},
    "target": {"project", "package", "releaseproject"},
    "acceptinfo": {*_ACCEPTINFO, "oproject", "opackage"},
    "sourcediff": set(),
    "issues": set(),
    "issue": {"state", "tracker", "name", "label"},
    "revisionlist": set(),
    "revision": {"rev"},
    "srcmd5": set(),
    "time": set(),
    "requestid": set(),
    "status": {"code", "origin"},
}
_TEXT_ELEMENTS: Final = frozenset({"srcmd5", "time", "requestid"})
_DIFF_BASE: Final = [
    ("cmd", "diff"),
    ("view", "xml"),
    ("withissues", "1"),
    ("onlyissues", "1"),
]


def _root(name: str) -> ET.Element:
    return ET.fromstring(load_request_fixture(name))


def _status(name: str) -> int:
    status: int = request_fixture_record(name)["status"]
    return status


def _path(name: str) -> str:
    path: str = request_fixture_record(name)["path"]
    return path


def _actions(name: str, action_type: str | None = None) -> list[ET.Element]:
    return [
        action
        for action in _root(name).findall("action")
        if action_type is None or action.get("type") == action_type
    ]


def _state(name: str) -> ET.Element:
    [state] = _root(name).findall("state")
    return state


def _acceptinfo(action: ET.Element) -> ET.Element:
    acceptinfo = action.find("acceptinfo")
    assert acceptinfo is not None
    return acceptinfo


def _attr(action: ET.Element, element: str, attribute: str) -> str | None:
    child = action.find(element)
    return None if child is None else child.get(attribute)


def _identity(request_id: str, action: ET.Element) -> tuple[str | None, ...]:
    """The semantic identity of ibs-integration.md (Request Point Detail),
    on the raw values (the client applies the project replacement)."""
    if action.get("type") == "maintenance_incident":
        return (
            request_id,
            "maintenance_incident",
            _attr(action, "source", "project"),
            _attr(action, "source", "package"),
            _attr(action, "target", "releaseproject"),
        )
    return (
        request_id,
        "maintenance_release",
        _attr(action, "target", "project"),
        _attr(action, "target", "package"),
    )


def _diff_path(project: str | None, package: str | None) -> str:
    return f"/source/{project}/{package}"


class TestFixtureInventory:
    def test_every_fixture_is_recorded_and_every_record_has_a_fixture(self) -> None:
        recorded = set(load_request_responses()["documents"])
        stored = {path.name for path in request_fixture_paths()}
        expected = {f"{name}.xml" for name in REQUEST_FIXTURES}
        assert recorded == stored == expected

    def test_capture_metadata(self) -> None:
        responses = load_request_responses()
        assert responses["api_url"] == "https://api.suse.de"
        assert responses["captured_at"] == REQUEST_FIXTURE_DATE

    def test_success_and_error_statuses(self) -> None:
        for name in (
            *SEARCH_FIXTURES,
            *DETAIL_FIXTURES,
            *ACTION_DIFF_FIXTURES,
            *HISTORY_FIXTURES,
        ):
            assert _status(name) == 200, name
        assert {
            name: _status(name)
            for name in (
                *SEARCH_ERROR_FIXTURES,
                *DETAIL_ERROR_FIXTURES,
                *ACTION_DIFF_ERROR_FIXTURES,
                *HISTORY_ERROR_FIXTURES,
            )
        } == {
            "search_error_releaseproject": 400,
            "request_not_found": 404,
            "diff_error_bad_link": 400,
            "diff_error_unavailable_checksum": 400,
            "diff_error_unknown_project": 404,
            "diff_error_unknown_package": 404,
            "history_error_unknown_package": 404,
            "history_error_unknown_project": 404,
        }

    @pytest.mark.parametrize("name", REQUEST_FIXTURES)
    def test_only_allow_listed_content_was_retained(self, name: str) -> None:
        for element in _root(name).iter():
            assert element.tag in _ALLOWED, element.tag
            assert set(element.attrib) <= _ALLOWED[element.tag], element.tag
            if element.tag not in _TEXT_ELEMENTS:
                assert (element.text or "").strip() == "", element.tag
            assert (element.tail or "").strip() == "", element.tag

    @pytest.mark.parametrize("name", REQUEST_FIXTURES)
    def test_no_project_outside_the_suse_namespaces_remains(self, name: str) -> None:
        text = load_request_fixture(name).decode()
        record = request_fixture_record(name)
        rendered = f"{text} {record['path']} {record['query']}"
        assert set(re.findall(r"home:[A-Za-z0-9_.:+\-]*", rendered)) <= {
            "home:fictional"
        }
        for element in _root(name).iter():
            for attribute in ("project", "releaseproject", "oproject"):
                value = element.get(attribute)
                if value is not None:
                    assert value.startswith(("SUSE:", "openSUSE:", "home:fictional"))


class TestSearchContract:
    @pytest.mark.parametrize(
        ("name", "match"),
        [
            (
                "search_open_sr_source_prefix",
                "action[@type='maintenance_incident' and starts-with("
                "source/@package,'openvpn.')] and (state/@name='new' or "
                "state/@name='review')",
            ),
            (
                "search_open_rr_target_prefix",
                "action[@type='maintenance_release' and starts-with("
                "target/@package,'kernel-source.')] and (state/@name='new' or "
                "state/@name='review')",
            ),
            (
                "search_open_rr_empty",
                "action[@type='maintenance_release' and starts-with("
                "target/@package,'openvpn.')] and (state/@name='new' or "
                "state/@name='review')",
            ),
            (
                "search_single_state",
                "action[@type='maintenance_incident' and starts-with("
                "source/@package,'openvpn.')] and (state/@name='declined')",
            ),
            (
                "search_all_states",
                "action[@type='maintenance_incident' and starts-with("
                "source/@package,'openvpn.')]",
            ),
        ],
    )
    def test_request_uses_the_typed_same_action_predicate(
        self, name: str, match: str
    ) -> None:
        assert request_fixture_record(name)["method"] == "GET"
        assert _path(name) == "/search/request/id"
        assert request_fixture_query(name) == [("match", match)]

    @pytest.mark.parametrize("name", SEARCH_FIXTURES)
    def test_collection_reports_matches_and_distinct_positive_ids(
        self, name: str
    ) -> None:
        root = _root(name)
        assert root.tag == "collection"
        matches = root.get("matches")
        assert matches is not None
        assert matches == "0" or _DECIMAL.fullmatch(matches)
        assert {child.tag for child in root} <= {"request"}
        ids = [child.get("id") for child in root]
        for request_id in ids:
            assert request_id is not None
            assert _DECIMAL.fullmatch(request_id)
        assert all(list(child) == [] for child in root)
        assert len(ids) == len(set(ids)) == int(matches)

    def test_empty_result_is_a_zero_match_collection(self) -> None:
        root = _root("search_open_rr_empty")
        assert root.attrib == {"matches": "0"}
        assert list(root) == []

    def test_several_matches(self) -> None:
        assert int(_root("search_all_states").get("matches") or 0) > 40
        assert int(_root("search_open_rr_target_prefix").get("matches") or 0) == 2

    def test_open_sr_search_finds_the_open_submission(self) -> None:
        [entry] = list(_root("search_open_sr_source_prefix"))
        assert entry.get("id") == _root("request_sr_open").get("id")

    def test_release_project_predicate_is_rejected(self) -> None:
        [(_, match)] = request_fixture_query("search_error_releaseproject")
        assert "target/@releaseproject=" in match
        assert _root("search_error_releaseproject").attrib == {
            "code": "illegal_xpath_error"
        }


class TestPointDetailContract:
    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_root_id_equals_the_requested_number(self, name: str) -> None:
        root = _root(name)
        assert root.tag == "request"
        request_id = root.get("id")
        assert request_id is not None
        assert _DECIMAL.fullmatch(request_id)
        assert request_fixture_record(name)["method"] == "GET"
        assert _path(name) == f"/request/{request_id}"
        assert request_fixture_query(name) == []

    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_exactly_one_state_with_offset_less_timestamps(self, name: str) -> None:
        root = _root(name)
        [state] = root.findall("state")
        assert state.get("name") in _STATES
        for attribute in ("created", "when"):
            assert _TIMESTAMP.fullmatch(state.get(attribute) or "")
        superseded_by = state.get("superseded_by")
        if state.get("name") == "superseded":
            assert superseded_by is not None
            assert _DECIMAL.fullmatch(superseded_by)
            assert superseded_by != root.get("id")
        else:
            assert superseded_by is None

    def test_observed_states(self) -> None:
        observed = {name: _state(name).get("name") for name in DETAIL_FIXTURES}
        assert set(observed.values()) == _STATES - {"deleted"}
        assert observed["request_sr_open"] == "new"
        assert observed["request_rr_open"] == "review"

    def test_superseded_request_names_its_captured_successor(self) -> None:
        state = _state("request_sr_superseded")
        assert state.get("superseded_by") == _root("request_sr_declined").get("id")

    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_action_types_are_ibs_types(self, name: str) -> None:
        for action in _actions(name):
            assert action.get("type") in _ACTION_TYPES

    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_supported_actions_carry_their_required_fields(self, name: str) -> None:
        for action in _actions(name):
            action_type = action.get("type")
            if action_type not in _SUPPORTED:
                continue
            for element, attribute in _REQUIRED[action_type]:
                assert _attr(action, element, attribute), (element, attribute)
            for element in ("source", "target", "acceptinfo"):
                assert len(action.findall(element)) <= 1

    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_consumed_values_satisfy_their_field_contracts(self, name: str) -> None:
        for action in _actions(name):
            if action.get("type") not in _SUPPORTED:
                continue
            for element, attributes in (
                ("source", ("project", "package")),
                ("target", ("project", "package", "releaseproject")),
                ("acceptinfo", ("oproject", "opackage")),
            ):
                for attribute in attributes:
                    value = _attr(action, element, attribute)
                    if value is not None:
                        assert _IBS_NAME.fullmatch(value)
                        assert value not in {".", ".."}
            revision = _attr(action, "source", "rev")
            if revision is not None:
                assert _DECIMAL.fullmatch(revision) or _CHECKSUM.fullmatch(revision)
            acceptinfo = action.find("acceptinfo")
            if acceptinfo is not None:
                assert _DECIMAL.fullmatch(acceptinfo.get("rev") or "")
                for attribute in _ACCEPTINFO[1:]:
                    value = acceptinfo.get(attribute)
                    if value is not None:
                        assert _CHECKSUM.fullmatch(value)

    @pytest.mark.parametrize("name", DETAIL_FIXTURES)
    def test_semantic_identities_are_distinct(self, name: str) -> None:
        root = _root(name)
        identities = Counter(
            _identity(root.get("id") or "", action)
            for action in _actions(name)
            if action.get("type") in _SUPPORTED
        )
        assert all(count == 1 for count in identities.values())

    def test_open_submission_pairs_its_incident_action_with_a_delete(self) -> None:
        incident, delete = _actions("request_sr_open")
        assert incident.get("type") == "maintenance_incident"
        assert _attr(incident, "target", "project") == "SUSE:Maintenance"
        assert _attr(incident, "target", "package") is None
        assert incident.find("acceptinfo") is None
        assert _CHECKSUM.fullmatch(_attr(incident, "source", "rev") or "")
        assert delete.get("type") == "delete"
        assert delete.find("source") is None
        staging = _attr(incident, "source", "project")
        assert (
            staging == f"SUSE:Maintenance:REQUEST:{_root('request_sr_open').get('id')}"
        )
        assert _attr(delete, "target", "project") == staging

    @pytest.mark.parametrize(
        "name",
        ["request_sr_accepted", "request_sr_accepted_earlier", "request_sr_home"],
    )
    def test_accepted_submission_moves_to_its_incident(self, name: str) -> None:
        [incident] = _actions(name, "maintenance_incident")
        assert re.fullmatch(
            r"SUSE:Maintenance:[1-9][0-9]*", _attr(incident, "target", "project") or ""
        )
        assert _attr(incident, "target", "package")
        acceptinfo = incident.find("acceptinfo")
        assert acceptinfo is not None
        assert set(acceptinfo.attrib) == set(_ACCEPTINFO)

    def test_accepted_release_acceptinfo_without_xsrcmd5(self) -> None:
        code, *patchinfo = _actions("request_rr_accepted")
        acceptinfo = code.find("acceptinfo")
        assert acceptinfo is not None
        assert set(acceptinfo.attrib) == {
            "rev",
            "srcmd5",
            "osrcmd5",
            "oxsrcmd5",
            "oproject",
            "opackage",
        }
        assert patchinfo
        for action in patchinfo:
            assert action.get("type") == "maintenance_release"
            assert _attr(action, "source", "package") == "patchinfo"
            assert _attr(action, "source", "rev") is None
            info = action.find("acceptinfo")
            assert info is not None
            assert set(info.attrib) == {"rev", "srcmd5", "osrcmd5"}
        targets = {_attr(action, "target", "project") for action in patchinfo}
        assert any(target.startswith("SUSE:Updates:") for target in targets if target)

    @pytest.mark.parametrize("name", ["request_rr_open", "request_rr_revoked"])
    def test_not_accepted_release_has_no_acceptinfo(self, name: str) -> None:
        for action in _actions(name):
            assert action.find("acceptinfo") is None

    def test_open_release_patchinfo_actions_have_no_source_revision(self) -> None:
        code, *patchinfo = _actions("request_rr_open")
        assert _CHECKSUM.fullmatch(_attr(code, "source", "rev") or "")
        assert patchinfo
        assert all(_attr(action, "source", "rev") is None for action in patchinfo)

    def test_kernel_release_request(self) -> None:
        actions = _actions("request_rr_kernel")
        types = Counter(action.get("type") for action in actions)
        assert types["submit"] == 3
        assert set(types) == {"submit", "maintenance_release"}
        for action in _actions("request_rr_kernel", "submit"):
            assert _attr(action, "target", "project") == "SUSE:Channels"
        releases = {
            (_attr(action, "source", "package") or "").split(".")[0]: action
            for action in _actions("request_rr_kernel", "maintenance_release")
            if _attr(action, "target", "project") == "SUSE:SLE-15-SP6:Update"
            and not (_attr(action, "source", "package") or "").startswith("patchinfo")
        }
        assert releases["kernel-source"].find("acceptinfo") is not None
        assert releases["kernel-default-base"].find("acceptinfo") is not None
        assert releases["kernel-default"].find("acceptinfo") is None
        assert releases["dtb-aarch64"].find("acceptinfo") is None
        without = [name for name, a in releases.items() if a.find("acceptinfo") is None]
        assert len(without) == 12

    def test_personal_project_submission_was_sanitized(self) -> None:
        [incident] = _actions("request_sr_home", "maintenance_incident")
        assert _attr(incident, "source", "project") == "home:fictional"
        assert _attr(incident, "target", "releaseproject") == "SUSE:SLE-11-SP3:Update"

    def test_request_with_only_ignored_action_types(self) -> None:
        actions = _actions("request_non_maintenance")
        assert actions
        assert {action.get("type") for action in actions} == {"submit"}
        assert _DECIMAL.fullmatch(_attr(actions[0], "source", "rev") or "")

    def test_release_targets_name_the_incident(self) -> None:
        for name in ("request_rr_accepted", "request_rr_open", "request_rr_revoked"):
            for action in _actions(name, "maintenance_release"):
                incident = (_attr(action, "source", "project") or "").removeprefix(
                    "SUSE:Maintenance:"
                )
                assert _DECIMAL.fullmatch(incident)
                assert (_attr(action, "target", "package") or "").endswith(
                    f".{incident}"
                )

    def test_unknown_request_is_a_404_not_found(self) -> None:
        assert _root("request_not_found").attrib == {"code": "not_found"}
        assert _path("request_not_found").startswith("/request/")


def _accepted_form(action: ET.Element) -> tuple[str, list[tuple[str, str]]]:
    """The accepted form of ibs-integration.md (Request Action Diff)."""
    acceptinfo = action.find("acceptinfo")
    assert acceptinfo is not None
    params = [
        ("rev", acceptinfo.get("xsrcmd5") or acceptinfo.get("srcmd5") or ""),
        ("orev", acceptinfo.get("oxsrcmd5") or acceptinfo.get("osrcmd5") or "0"),
    ]
    for attribute in ("oproject", "opackage"):
        value = acceptinfo.get(attribute)
        if value is not None:
            params.append((attribute, value))
    path = _diff_path(
        _attr(action, "target", "project"), _attr(action, "target", "package")
    )
    return path, [*_DIFF_BASE, *params]


def _not_accepted_form(
    action: ET.Element, codestream_package: str
) -> tuple[str, list[tuple[str, str]]]:
    """The not-accepted form of ibs-integration.md (Request Action Diff)."""
    codestream = (
        _attr(action, "target", "releaseproject")
        if action.get("type") == "maintenance_incident"
        else _attr(action, "target", "project")
    )
    params = [
        ("expand", "1"),
        ("rev", _attr(action, "source", "rev") or ""),
        ("oproject", codestream or ""),
        ("opackage", codestream_package),
    ]
    path = _diff_path(
        _attr(action, "source", "project"), _attr(action, "source", "package")
    )
    return path, [*_DIFF_BASE, *params]


def _recorded(name: str) -> tuple[str, list[tuple[str, str]]]:
    assert request_fixture_record(name)["method"] == "POST"
    return _path(name), request_fixture_query(name)


def _issues(name: str) -> list[ET.Element]:
    root = _root(name)
    containers = root.findall("issues")
    assert len(containers) <= 1
    return [] if not containers else list(containers[0])


class TestRequestActionDiffContract:
    def test_accepted_submission_form(self) -> None:
        [action] = _actions("request_sr_accepted", "maintenance_incident")
        assert _recorded("diff_sr_accepted") == _accepted_form(action)
        assert dict(request_fixture_query("diff_sr_accepted"))["rev"] == (
            _acceptinfo(action).get("xsrcmd5")
        )

    def test_accepted_personal_project_submission_uses_its_suse_target(self) -> None:
        [action] = _actions("request_sr_home", "maintenance_incident")
        path, query = _recorded("diff_sr_home_accepted")
        assert (path, query) == _accepted_form(action)
        assert path.startswith("/source/SUSE:Maintenance:")
        assert "home:" not in f"{path} {query}"

    def test_accepted_release_code_action_form(self) -> None:
        code = _actions("request_rr_accepted")[0]
        path, query = _recorded("diff_rr_accepted")
        assert (path, query) == _accepted_form(code)
        assert [key for key, _ in query[4:]] == ["rev", "orev", "oproject", "opackage"]
        assert dict(query)["rev"] == _acceptinfo(code).get("srcmd5")

    def test_accepted_release_patchinfo_form_falls_back_to_osrcmd5(self) -> None:
        patchinfo = _actions("request_rr_accepted")[1]
        path, query = _recorded("diff_rr_patchinfo_accepted")
        assert (path, query) == _accepted_form(patchinfo)
        assert [key for key, _ in query[4:]] == ["rev", "orev"]
        assert dict(query)["orev"] == _acceptinfo(patchinfo).get("osrcmd5")

    def test_open_submission_form_expands_against_the_logical_package(self) -> None:
        [action] = _actions("request_sr_open", "maintenance_incident")
        assert _recorded("diff_sr_open") == _not_accepted_form(action, "openvpn")

    def test_open_release_form_uses_the_target_codestream(self) -> None:
        code = _actions("request_rr_open")[0]
        assert _recorded("diff_rr_open") == _not_accepted_form(code, "python311")

    def test_not_accepted_error_forms(self) -> None:
        [declined] = _actions("request_sr_declined", "maintenance_incident")
        assert _recorded("diff_error_bad_link") == _not_accepted_form(
            declined, "openvpn"
        )
        [opened] = _actions("request_sr_open", "maintenance_incident")
        assert _recorded("diff_error_unknown_package") == _not_accepted_form(
            opened, "sentinel-nonexistent-pkg"
        )
        path, query = _recorded("diff_error_unknown_project")
        assert path.startswith("/source/SUSE:Maintenance:REQUEST:")
        assert [key for key, _ in query] == [
            *[key for key, _ in _DIFF_BASE],
            "expand",
            "rev",
            "oproject",
            "opackage",
        ]

    def test_unavailable_checksum_uses_the_accepted_form_shape(self) -> None:
        [action] = _actions("request_sr_accepted", "maintenance_incident")
        expected_path, expected = _accepted_form(action)
        path, query = _recorded("diff_error_unavailable_checksum")
        assert path == expected_path
        assert dict(query)["rev"] == FICTIONAL_UNSTORED_CHECKSUM
        assert dict(query)["orev"] == dict(expected)["orev"]

    @pytest.mark.parametrize("name", ACTION_DIFF_FIXTURES)
    def test_document_is_a_sourcediff_with_at_most_one_issues(self, name: str) -> None:
        root = _root(name)
        assert root.tag == "sourcediff"
        assert {child.tag for child in root} <= {"issues"}
        _issues(name)

    @pytest.mark.parametrize("name", ACTION_DIFF_FIXTURES)
    def test_every_issue_has_the_consumed_fields(self, name: str) -> None:
        for issue in _issues(name):
            assert issue.tag == "issue"
            assert list(issue) == []
            assert issue.get("tracker")
            assert issue.get("state")
            assert issue.get("name")
            label = issue.get("label") or ""
            if issue.get("tracker") == "cve":
                assert _CVE.fullmatch(label)
                assert label == f"CVE-{issue.get('name')}"
            else:
                assert not _CVE.fullmatch(label)

    def test_observed_issue_states_include_changed(self) -> None:
        states = {
            (issue.get("tracker"), issue.get("state"))
            for name in ACTION_DIFF_FIXTURES
            for issue in _issues(name)
        }
        assert {("cve", "added"), ("cve", "changed")} <= states

    def test_release_diff_carries_the_submission_issues(self) -> None:
        def issue_set(name: str) -> set[tuple[str | None, ...]]:
            return {
                (i.get("tracker"), i.get("state"), i.get("name"), i.get("label"))
                for i in _issues(name)
            }

        assert issue_set("diff_rr_accepted") == issue_set("diff_sr_accepted")
        assert any(i.get("tracker") == "cve" for i in _issues("diff_rr_accepted"))

    def test_patchinfo_diff_is_an_empty_issues_element(self) -> None:
        root = _root("diff_rr_patchinfo_accepted")
        assert [child.tag for child in root] == ["issues"]
        assert _issues("diff_rr_patchinfo_accepted") == []

    def test_error_documents(self) -> None:
        assert _root("diff_error_bad_link").attrib == {
            "code": "400",
            "origin": "backend",
        }
        assert _root("diff_error_unavailable_checksum").attrib == {
            "code": "400",
            "origin": "backend",
        }
        assert _root("diff_error_unknown_project").attrib == {"code": "unknown_project"}
        assert _root("diff_error_unknown_package").attrib == {"code": "unknown_package"}


def _entries(name: str) -> list[ET.Element]:
    root = _root(name)
    assert root.tag == "revisionlist"
    assert {child.tag for child in root} <= {"revision"}
    return list(root)


def _revisions(name: str) -> list[int]:
    return [int(entry.get("rev") or "0") for entry in _entries(name)]


class TestSourceHistoryContract:
    @pytest.mark.parametrize("name", [*HISTORY_FIXTURES, *HISTORY_ERROR_FIXTURES])
    def test_request_is_an_unpaged_history_or_an_exact_lookup(self, name: str) -> None:
        assert request_fixture_record(name)["method"] == "GET"
        path = _path(name)
        assert re.fullmatch(r"/source/SUSE:[^/]+/[^/]+/_history", path)
        query = request_fixture_query(name)
        assert [key for key, _ in query] in ([], ["rev"])
        for _, revision in query:
            assert _DECIMAL.fullmatch(revision) or _CHECKSUM.fullmatch(revision)

    @pytest.mark.parametrize("name", HISTORY_FIXTURES)
    def test_entries_carry_the_consumed_fields(self, name: str) -> None:
        for entry in _entries(name):
            assert set(entry.attrib) == {"rev"}
            assert _DECIMAL.fullmatch(entry.get("rev") or "")
            children = Counter(child.tag for child in entry)
            assert children["srcmd5"] == children["time"] == 1
            assert children["requestid"] <= 1
            assert _CHECKSUM.fullmatch(entry.findtext("srcmd5") or "")
            assert re.fullmatch(r"0|[1-9][0-9]*", entry.findtext("time") or "")
            requestid = entry.findtext("requestid")
            if requestid is not None:
                assert _DECIMAL.fullmatch(requestid)

    @pytest.mark.parametrize("name", HISTORY_FIXTURES)
    def test_entries_are_ascending_and_distinct(self, name: str) -> None:
        revisions = _revisions(name)
        assert revisions == sorted(set(revisions))

    @pytest.mark.parametrize("name", ["history_codestream", "history_incident"])
    def test_unpaged_history_is_numbered_from_one_without_gaps(self, name: str) -> None:
        assert request_fixture_query(name) == []
        revisions = _revisions(name)
        assert revisions == list(range(1, len(revisions) + 1))
        assert len(revisions) > 1

    def test_codestream_history_names_a_request_for_every_revision(self) -> None:
        entries = _entries("history_codestream")
        assert all(entry.find("requestid") is not None for entry in entries)
        assert entries[-1].findtext("requestid") == _root("request_rr_accepted").get(
            "id"
        )

    def test_incident_history_contains_branch_commits_and_submissions(self) -> None:
        requests = [
            entry.findtext("requestid") for entry in _entries("history_incident")
        ]
        assert None in requests
        assert _root("request_sr_accepted_earlier").get("id") in requests
        assert _root("request_sr_accepted").get("id") in requests
        assert requests[-1] == _root("request_rr_accepted").get("id")

    def test_revision_lookup_returns_exactly_that_revision(self) -> None:
        [(_, revision)] = request_fixture_query("history_lookup_revision")
        [entry] = _entries("history_lookup_revision")
        assert entry.get("rev") == revision
        code = _actions("request_rr_accepted")[0]
        acceptinfo = code.find("acceptinfo")
        assert acceptinfo is not None
        assert _path("history_lookup_revision") == (
            f"/source/{_attr(code, 'target', 'project')}/"
            f"{_attr(code, 'target', 'package')}/_history"
        )
        assert revision == acceptinfo.get("rev")
        assert entry.findtext("srcmd5") == acceptinfo.get("srcmd5")
        assert entry.findtext("requestid") == _root("request_rr_accepted").get("id")

    def test_checksum_lookup_returns_every_revision_with_it(self) -> None:
        [(_, checksum)] = request_fixture_query("history_lookup_checksum_multiple")
        assert _CHECKSUM.fullmatch(checksum)
        entries = _entries("history_lookup_checksum_multiple")
        assert len(entries) > 1
        assert {entry.findtext("srcmd5") for entry in entries} == {checksum}
        expected = [
            int(entry.get("rev") or "0")
            for entry in _entries("history_incident")
            if entry.findtext("srcmd5") == checksum
        ]
        assert _revisions("history_lookup_checksum_multiple") == expected
        assert expected != list(range(expected[0], expected[0] + len(expected)))

    @pytest.mark.parametrize(
        "name", ["history_lookup_unknown_revision", "history_lookup_unknown_checksum"]
    )
    def test_lookup_without_an_entry_is_an_empty_list(self, name: str) -> None:
        assert _root(name).tag == "revisionlist"
        assert _entries(name) == []

    def test_unknown_checksum_lookup_used_a_never_stored_checksum(self) -> None:
        assert request_fixture_query("history_lookup_unknown_checksum") == [
            ("rev", FICTIONAL_UNSTORED_CHECKSUM)
        ]

    def test_error_documents(self) -> None:
        assert _root("history_error_unknown_package").attrib == {
            "code": "unknown_package"
        }
        assert _root("history_error_unknown_project").attrib == {
            "code": "unknown_project"
        }
