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
an entry that also carries checksums, and malformed or interrupted
documents. The source-diff HTTP 400 and 404 error responses are retained
and asserted against docs/features/integrations/ibs-integration.md
(Unavailable Old Revision) before the client's classification uses them;
a historical checksum whose stored tree was actually removed is
documentation-only (OBS source inspection), because its backend path is the
one the fabricated checksums take. The response media type was not
observable through `osc api` and is not consumed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Final

import pytest

from tests.support.ibs_api import (
    DIFF_ERROR_FIXTURES,
    DIFF_FIXTURES,
    FICTIONAL_OREV,
    FICTIONAL_REV,
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
        expected = {
            f"{name}.xml"
            for name in (*SOURCEINFO_FIXTURES, *DIFF_FIXTURES, *DIFF_ERROR_FIXTURES)
        }
        assert recorded == stored == expected

    def test_every_request_targets_the_live_project(self) -> None:
        responses = load_responses()
        assert responses["api_url"] == "https://api.suse.de"
        for record in responses["documents"].values():
            assert record["path"].startswith(f"/source/{LIVE_PROJECT}")

    def test_success_documents_succeeded_and_error_documents_did_not(self) -> None:
        documents = load_responses()["documents"]
        for name in (*SOURCEINFO_FIXTURES, *DIFF_FIXTURES):
            assert documents[f"{name}.xml"]["status"] == 200
        assert {
            name: documents[f"{name}.xml"]["status"] for name in DIFF_ERROR_FIXTURES
        } == {
            "diff_error_orev_unavailable": 400,
            "diff_error_rev_unavailable": 400,
            "diff_error_both_unavailable": 400,
            "diff_error_no_such_revision": 404,
            "diff_error_unknown_package": 404,
        }

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


def _request_identity(name: str) -> tuple[str, str, str, str]:
    """`(project, package, orev, rev)` of the live request of `name`."""
    record = load_responses()["documents"][f"{name}.xml"]
    project, package = record["path"].removeprefix("/source/").split("/")
    query = dict(fixture_query(name))
    return project, package, query["orev"], query["rev"]


class TestSourceDiffErrorContract:
    """ibs-integration.md, Unavailable Old Revision: the HTTP 400 backend
    status document naming the checksum IBS failed to resolve, and the
    404 responses that never identify unavailable history."""

    @pytest.mark.parametrize("name", DIFF_ERROR_FIXTURES)
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

    @pytest.mark.parametrize("name", DIFF_ERROR_FIXTURES)
    def test_body_is_a_no_namespace_status_with_exactly_one_summary(
        self, name: str
    ) -> None:
        root = _root(name)
        assert root.tag == "status"
        assert [child.tag for child in root] == ["summary"]
        [summary] = list(root)
        assert list(summary) == []
        assert summary.text

    @pytest.mark.parametrize(
        ("name", "named"),
        [
            ("diff_error_orev_unavailable", "orev"),
            ("diff_error_rev_unavailable", "rev"),
            ("diff_error_both_unavailable", "rev"),
        ],
    )
    def test_unavailable_checksum_summary_names_the_unresolved_checksum(
        self, name: str, named: str
    ) -> None:
        project, package, orev, rev = _request_identity(name)
        checksum = orev if named == "orev" else rev
        root = _root(name)
        summary = root.find("summary")
        assert summary is not None
        assert root.attrib == {"code": "400", "origin": "backend"}
        assert (summary.text or "").startswith(
            f"{project}/{package}/{checksum}: not in repository"
        )

    def test_only_the_orev_sample_satisfies_the_discriminator_inputs(self) -> None:
        """Condition 1 (a checksum `orev` other than `0` and `rev`) holds
        for the `orev` and both-unavailable samples; only the `orev` sample
        also names `orev` (condition 4), because IBS resolves `rev` first."""
        _, _, orev, rev = _request_identity("diff_error_orev_unavailable")
        assert orev == FICTIONAL_OREV
        assert _CHECKSUM.fullmatch(rev)
        assert rev not in {FICTIONAL_OREV, FICTIONAL_REV}
        _, _, orev, rev = _request_identity("diff_error_rev_unavailable")
        assert (orev, rev) == ("0", FICTIONAL_REV)
        _, _, orev, rev = _request_identity("diff_error_both_unavailable")
        assert (orev, rev) == (FICTIONAL_OREV, FICTIONAL_REV)

    def test_numeric_revision_is_a_404_no_such_revision(self) -> None:
        root = _root("diff_error_no_such_revision")
        _, _, orev, _ = _request_identity("diff_error_no_such_revision")
        assert orev.isdigit()
        assert not _CHECKSUM.fullmatch(orev)
        assert root.attrib == {"code": "not_found"}
        summary = root.find("summary")
        assert summary is not None
        assert summary.text == "no such revision"

    def test_unknown_package_is_a_404_with_its_own_summary(self) -> None:
        project, package, _, _ = _request_identity("diff_error_unknown_package")
        root = _root("diff_error_unknown_package")
        assert root.attrib == {"code": "unknown_package"}
        summary = root.find("summary")
        assert summary is not None
        assert summary.text == f"Package not found: {project}/{package}"
        assert "not in repository" not in (summary.text or "")
