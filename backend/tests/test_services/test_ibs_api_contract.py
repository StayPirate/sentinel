"""Contract tests for the IBS API source-info and source-diff documents.

Contract under test: docs/features/integrations/ibs-integration.md (Project
Source Info, Source Diff with Issue Extraction, Track-Release Contract
Verification Status, Authentication Contract Verification Status) and
docs/features/packages/ibs-track-release-detection.md (Authoritative IBS
Evidence, Source-Info Validation, Source-Diff Validation, External Contract
Verification), verified against the sanitized live captures described in
`tests/support/ibs_api.py` (docs/conventions.md, External Integration
Contract Verification). Every consumed field is asserted for name, nesting,
cardinality, and format; the documents are read with the standard-library
tree parser because the fixtures are trusted.

Observed live and retained: a requested package that does not exist is
returned as an entry with an `<error>` child rather than omitted, and a
valid empty diff has no `issues` element. Not retained, and therefore
covered by synthetic documents in the client tests: a requested package
entirely absent from the response, duplicate entries, an `<error>` child on
an entry that also carries checksums, malformed or interrupted documents,
and the HTTP 400/404 error responses (whose unavailable-revision
classification belongs to the track detector item). The response media type
was not observable through `osc api` and is not consumed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Final

import pytest

from tests.support.ibs_api import (
    DIFF_FIXTURES,
    FIXTURE_DIR,
    LIVE_CHALLENGE,
    LIVE_PROJECT,
    SOURCEINFO_FIXTURES,
    fixture_query,
    load_fixture,
    load_responses,
)

pytestmark = pytest.mark.unit

_CHECKSUM: Final = re.compile(r"[0-9a-f]{32}")
_CVE: Final = re.compile(r"CVE-\d{4}-\d{4,}")
_STATES: Final = frozenset({"added", "changed", "deleted"})


def _root(name: str) -> ET.Element:
    return ET.fromstring(load_fixture(name))


def _requested(name: str) -> list[str]:
    return [value for key, value in fixture_query(name) if key == "package"]


def _issues(name: str) -> list[ET.Element]:
    root = _root(name)
    containers = root.findall("issues")
    assert len(containers) <= 1
    return [] if not containers else list(containers[0])


class TestFixtureInventory:
    def test_every_fixture_is_recorded_and_every_record_has_a_fixture(self) -> None:
        recorded = set(load_responses()["documents"])
        stored = {path.name for path in Path(FIXTURE_DIR).glob("*.xml")}
        expected = {f"{name}.xml" for name in (*SOURCEINFO_FIXTURES, *DIFF_FIXTURES)}
        assert recorded == stored == expected

    def test_every_request_targets_the_live_project_and_succeeded(self) -> None:
        responses = load_responses()
        assert responses["api_url"] == "https://api.suse.de"
        for record in responses["documents"].values():
            assert record["path"].startswith(f"/source/{LIVE_PROJECT}")
            assert record["status"] == 200

    def test_unauthenticated_record_matches_the_specified_challenge(self) -> None:
        record = load_responses()["unauthenticated"]
        assert record["status"] == 401
        assert record["www_authenticate"] == [LIVE_CHALLENGE]
        assert record["set_cookie"] == []


class TestSourceInfoContract:
    @pytest.mark.parametrize("name", SOURCEINFO_FIXTURES)
    def test_request_uses_the_targeted_form(self, name: str) -> None:
        query = fixture_query(name)
        assert query[:2] == [("view", "info"), ("nofilename", "1")]
        assert [key for key, _ in query[2:]] == ["package"] * len(_requested(name))

    @pytest.mark.parametrize("name", SOURCEINFO_FIXTURES)
    def test_root_is_sourceinfolist_with_one_entry_per_requested_package(
        self, name: str
    ) -> None:
        root = _root(name)
        assert root.tag == "sourceinfolist"
        assert {child.tag for child in root} == {"sourceinfo"}
        packages = Counter(entry.get("package") for entry in root)
        assert packages == Counter(_requested(name))

    def test_single_requested_package_is_still_a_list(self) -> None:
        root = _root("sourceinfo_single_linked")
        assert root.tag == "sourceinfolist"
        assert len(root) == 1

    @pytest.mark.parametrize("name", SOURCEINFO_FIXTURES)
    def test_usable_entries_carry_an_expanded_checksum_and_link_context(
        self, name: str
    ) -> None:
        usable = [e for e in _root(name) if e.find("error") is None]
        assert usable
        for entry in usable:
            srcmd5 = entry.get("srcmd5")
            lsrcmd5 = entry.get("lsrcmd5")
            assert srcmd5 is not None
            assert _CHECKSUM.fullmatch(srcmd5)
            # Linked packages: the expanded state differs from the local
            # link revision, which is link context only.
            assert lsrcmd5 is not None
            assert _CHECKSUM.fullmatch(lsrcmd5)
            assert lsrcmd5 != srcmd5
            linked = entry.findall("linked")
            assert linked
            for link in linked:
                assert link.get("project")
                assert link.get("package")
                assert list(link) == []

    def test_missing_package_is_an_error_bearing_entry_without_checksum(
        self,
    ) -> None:
        [entry] = [
            e
            for e in _root("sourceinfo_multiple")
            if e.get("package") == "sentinel-nonexistent-pkg"
        ]
        errors = entry.findall("error")
        assert len(errors) == 1
        assert (errors[0].text or "").startswith("404 ")
        assert entry.get("srcmd5") is None
        assert entry.findall("linked")

    def test_unconsumed_children_occur(self) -> None:
        tags = {child.tag for entry in _root("sourceinfo_multiple") for child in entry}
        assert tags == {"linked", "originproject", "error"}


class TestSourceDiffContract:
    @pytest.mark.parametrize("name", DIFF_FIXTURES)
    def test_request_uses_the_expanded_issue_form(self, name: str) -> None:
        query = fixture_query(name)
        assert [key for key, _ in query] == [
            "cmd",
            "view",
            "onlyissues",
            "expand",
            "orev",
            "rev",
        ]
        assert query[:4] == [
            ("cmd", "diff"),
            ("view", "xml"),
            ("onlyissues", "1"),
            ("expand", "1"),
        ]
        orev, rev = query[4][1], query[5][1]
        assert orev == "0" or _CHECKSUM.fullmatch(orev)
        assert _CHECKSUM.fullmatch(rev)

    @pytest.mark.parametrize("name", DIFF_FIXTURES)
    def test_root_is_sourcediff_naming_the_compared_states(self, name: str) -> None:
        root = _root(name)
        query = dict(fixture_query(name))
        assert root.tag == "sourcediff"
        children = [child.tag for child in root]
        assert children[:3] == ["old", "new", "files"]
        assert set(children) <= {"old", "new", "files", "issues"}
        old, new = root.find("old"), root.find("new")
        assert old is not None
        assert new is not None
        assert old.get("rev") == query["orev"]
        assert new.get("rev") == query["rev"] == new.get("srcmd5")

    @pytest.mark.parametrize("name", DIFF_FIXTURES)
    def test_every_issue_has_the_consumed_structured_fields(self, name: str) -> None:
        for issue in _issues(name):
            assert issue.tag == "issue"
            assert list(issue) == []
            assert set(issue.attrib) == {"state", "tracker", "name", "label", "url"}
            assert issue.get("state") in _STATES
            assert issue.get("tracker")
            assert issue.get("name")

    @pytest.mark.parametrize("name", DIFF_FIXTURES)
    def test_cve_label_is_the_canonical_identity(self, name: str) -> None:
        for issue in _issues(name):
            label = issue.get("label") or ""
            if issue.get("tracker") == "cve":
                assert _CVE.fullmatch(label)
                assert label == f"CVE-{issue.get('name')}"
            else:
                assert not _CVE.fullmatch(label)

    def test_first_observation_is_from_the_empty_tree_and_multi_cve(self) -> None:
        root = _root("diff_first_observation")
        old = root.find("old")
        assert old is not None
        assert old.get("rev") == "0"
        issues = _issues("diff_first_observation")
        assert {i.get("state") for i in issues} == {"added"}
        trackers = Counter(i.get("tracker") for i in issues)
        assert set(trackers) == {"cve", "bnc", "fate", "jsc"}
        assert trackers["cve"] > 1

    def test_incremental_diff_reports_added_and_changed(self) -> None:
        pairs = {
            (i.get("tracker"), i.get("state")) for i in _issues("diff_added_changed")
        }
        assert pairs == {
            ("cve", "added"),
            ("cve", "changed"),
            ("bnc", "added"),
            ("bnc", "changed"),
        }

    def test_reverse_diff_reports_deleted(self) -> None:
        pairs = {(i.get("tracker"), i.get("state")) for i in _issues("diff_deleted")}
        assert pairs == {("cve", "deleted"), ("bnc", "deleted")}

    def test_empty_diff_has_no_issues_element(self) -> None:
        root = _root("diff_empty")
        assert root.find("issues") is None
        query = dict(fixture_query("diff_empty"))
        assert query["orev"] == query["rev"]
