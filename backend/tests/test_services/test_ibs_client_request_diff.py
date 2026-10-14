"""Tests for `IBSClient.get_request_action_diff()`.

Contract under test: docs/features/integrations/ibs-integration.md (Request
Action Diff, including its stated differences from IBS; Unavailable Old
Revision, scope sentence; Service Layer > IBSClient, the diff method and
its escaping outcomes; Product Repository Download Boundary > "Retry safety
for POST operations"); docs/features/platform/networking.md (Transport-Level
Retry > Method Safety); docs/features/packages/ibs-submission-tracking.md
(Action-Scoped CVE Evidence: issues returned faithfully, never merged
across actions). Live documents are the sanitized captures of
`tests/support/ibs_request_api.py`; each live diff is requested from the
action the client parsed from the matching live point detail.
"""

from __future__ import annotations

import dataclasses
import xml.etree.ElementTree as ET
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest

from app.core.enums import IBSRequestActionType
from app.services.ibs_client import (
    AcceptInfo,
    IBSCredentialsNotConfiguredError,
    IBSRequestActionDetail,
    IncompleteReason,
    RequestActionDiff,
    RequestActionIssue,
    RequestEvidenceResult,
)
from tests.support.ibs_api import (
    IBSServer,
    Responder,
    ibs_client,
    status_response,
    xml_response,
)
from tests.support.ibs_request_api import (
    FICTIONAL_UNSTORED_CHECKSUM,
    load_request_fixture,
    request_fixture_query,
    request_fixture_record,
    serve_request_fixture,
)

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_INCIDENT: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
_RELEASE: Final = IBSRequestActionType.MAINTENANCE_RELEASE
_SUM_A: Final = "a" * 32
_SUM_B: Final = "b" * 32
_SUM_C: Final = "c" * 32
_SUM_D: Final = "d" * 32
_BASE: Final = [
    ("cmd", "diff"),
    ("view", "xml"),
    ("withissues", "1"),
    ("onlyissues", "1"),
]

_OPEN_SR: Final = IBSRequestActionDetail(
    request_number=920001,
    action_type=_INCIDENT,
    source_project="SUSE:Maintenance:REQUEST:920001",
    source_package="curl.SUSE_SLE-15-SP6_Update",
    source_revision=_SUM_A,
    target_project="SUSE:Maintenance",
    target_release_project="SUSE:SLE-15-SP6:Update",
)
_OPEN_RR: Final = IBSRequestActionDetail(
    request_number=920002,
    action_type=_RELEASE,
    source_project="SUSE:Maintenance:80001",
    source_package="curl.SUSE_SLE-15-SP6_Update",
    source_revision=_SUM_A,
    target_project="SUSE:SLE-15-SP6:Update",
    target_package="curl.80001",
)
_ACCEPTED_SR: Final = dataclasses.replace(
    _OPEN_SR,
    target_project="SUSE:Maintenance:80001",
    target_package="curl.SUSE_SLE-15-SP6_Update",
    acceptinfo=AcceptInfo(
        rev="2", srcmd5=_SUM_A, xsrcmd5=_SUM_B, osrcmd5=_SUM_C, oxsrcmd5=_SUM_D
    ),
)
_ACCEPTED_RR: Final = dataclasses.replace(
    _OPEN_RR,
    acceptinfo=AcceptInfo(
        rev="1",
        srcmd5=_SUM_B,
        osrcmd5=_SUM_C,
        oxsrcmd5=_SUM_D,
        oproject="SUSE:SLE-15-SP6:Update",
        opackage="curl.80000",
    ),
)


def _sourcediff(issues: str = "", *, wrap: bool = True) -> Responder:
    inner = f"<issues>{issues}</issues>" if wrap else issues
    return xml_response(f"<sourcediff>{inner}</sourcediff>".encode())


def _issue(**attributes: str) -> str:
    rendered = " ".join(f'{name}="{value}"' for name, value in attributes.items())
    return f"<issue {rendered}/>"


def _path(action: IBSRequestActionDetail) -> str:
    if action.acceptinfo is not None:
        return f"/source/{action.target_project}/{action.target_package}"
    return f"/source/{action.source_project}/{action.source_package}"


async def _diff(
    server: IBSServer,
    action: IBSRequestActionDetail,
    responder: Responder | None = None,
    *,
    codestream_package: str = "curl",
    path: str | None = None,
) -> RequestEvidenceResult[RequestActionDiff]:
    if responder is not None:
        server.route("POST", path or _path(action), responder)
    async with ibs_client() as client:
        return await client.get_request_action_diff(
            action, codestream_package=codestream_package
        )


def _sent(server: IBSServer) -> tuple[str, list[tuple[str, str]]]:
    [request] = [r for r in server.requests if "authorization" in r.headers]
    assert request.method == "POST"
    assert request.content == b""
    return request.url.path, list(request.url.params.multi_items())


async def _live_action(server: IBSServer, detail: str, index: int = 0) -> Any:
    serve_request_fixture(server, detail)
    number = int(request_fixture_record(detail)["path"].removeprefix("/request/"))
    async with ibs_client() as client:
        result = await client.get_request(number)
    assert result.value is not None
    server.requests.clear()
    return result.value.actions[index]


def _fixture_issues(name: str) -> tuple[RequestActionIssue, ...]:
    root = ET.fromstring(load_request_fixture(name))
    return tuple(
        RequestActionIssue(
            tracker=issue.get("tracker") or "",
            state=issue.get("state") or "",
            name=issue.get("name"),
            label=issue.get("label"),
        )
        for issue in root.iter("issue")
    )


class TestLiveDiffs:
    @pytest.mark.parametrize(
        ("detail", "index", "diff", "codestream_package"),
        [
            ("request_sr_accepted", 0, "diff_sr_accepted", "openvpn"),
            ("request_sr_open", 0, "diff_sr_open", "openvpn"),
            ("request_sr_home", 0, "diff_sr_home_accepted", "openvpn-openssl1"),
            ("request_rr_accepted", 0, "diff_rr_accepted", "openvpn"),
            ("request_rr_accepted", 1, "diff_rr_patchinfo_accepted", "patchinfo"),
            ("request_rr_open", 0, "diff_rr_open", "python311"),
        ],
    )
    async def test_live_diff_is_requested_as_recorded_and_complete(
        self,
        server: IBSServer,
        detail: str,
        index: int,
        diff: str,
        codestream_package: str,
    ) -> None:
        action = await _live_action(server, detail, index)
        serve_request_fixture(server, diff)
        result = await _diff(server, action, codestream_package=codestream_package)

        assert result == RequestEvidenceResult(
            value=RequestActionDiff(_fixture_issues(diff))
        )
        record = request_fixture_record(diff)
        assert _sent(server) == (record["path"], request_fixture_query(diff))

    async def test_live_release_diff_carries_changed_issues(
        self, server: IBSServer
    ) -> None:
        action = await _live_action(server, "request_rr_open")
        serve_request_fixture(server, "diff_rr_open")
        result = await _diff(server, action, codestream_package="python311")
        assert result.value is not None
        assert {i.state for i in result.value.issues} == {"added", "changed"}

    async def test_live_patchinfo_diff_is_a_valid_empty_issue_set(
        self, server: IBSServer
    ) -> None:
        action = await _live_action(server, "request_rr_accepted", 1)
        serve_request_fixture(server, "diff_rr_patchinfo_accepted")
        result = await _diff(server, action, codestream_package="patchinfo")
        assert result == RequestEvidenceResult(value=RequestActionDiff(()))

    async def test_live_bad_link_is_incomplete(self, server: IBSServer) -> None:
        action = await _live_action(server, "request_sr_declined")
        serve_request_fixture(server, "diff_error_bad_link")
        result = await _diff(server, action, codestream_package="openvpn")
        assert result == RequestEvidenceResult(incomplete_reason="rejected")
        assert _sent(server) == (
            request_fixture_record("diff_error_bad_link")["path"],
            request_fixture_query("diff_error_bad_link"),
        )

    async def test_live_unknown_old_package_is_incomplete(
        self, server: IBSServer
    ) -> None:
        action = await _live_action(server, "request_sr_open")
        serve_request_fixture(server, "diff_error_unknown_package")
        result = await _diff(
            server, action, codestream_package="sentinel-nonexistent-pkg"
        )
        assert result == RequestEvidenceResult(incomplete_reason="not_found")
        assert _sent(server) == (
            request_fixture_record("diff_error_unknown_package")["path"],
            request_fixture_query("diff_error_unknown_package"),
        )

    async def test_live_removed_staging_project_is_incomplete(
        self, server: IBSServer
    ) -> None:
        record = request_fixture_record("diff_error_unknown_project")
        project, package = record["path"].removeprefix("/source/").split("/")
        query = dict(request_fixture_query("diff_error_unknown_project"))
        action = IBSRequestActionDetail(
            request_number=int(project.rsplit(":", 1)[1]),
            action_type=_INCIDENT,
            source_project=project,
            source_package=package,
            source_revision=query["rev"],
            target_project="SUSE:Maintenance",
            target_release_project=query["oproject"],
        )
        serve_request_fixture(server, "diff_error_unknown_project")
        result = await _diff(server, action, codestream_package=query["opackage"])
        assert result == RequestEvidenceResult(incomplete_reason="not_found")
        assert _sent(server) == (record["path"], list(query.items()))

    async def test_live_unavailable_checksum_400_is_incomplete_not_history(
        self, server: IBSServer
    ) -> None:
        action = await _live_action(server, "request_sr_accepted")
        assert action.acceptinfo is not None
        unavailable = dataclasses.replace(
            action,
            acceptinfo=dataclasses.replace(
                action.acceptinfo, xsrcmd5=FICTIONAL_UNSTORED_CHECKSUM
            ),
        )
        serve_request_fixture(server, "diff_error_unavailable_checksum")
        result = await _diff(server, unavailable, codestream_package="openvpn")
        assert result == RequestEvidenceResult(incomplete_reason="rejected")
        assert _sent(server)[1] == request_fixture_query(
            "diff_error_unavailable_checksum"
        )


class TestForm:
    async def test_accepted_submission_uses_target_and_expanded_checksums(
        self, server: IBSServer
    ) -> None:
        await _diff(server, _ACCEPTED_SR, _sourcediff())
        assert _sent(server) == (
            "/source/SUSE:Maintenance:80001/curl.SUSE_SLE-15-SP6_Update",
            [*_BASE, ("rev", _SUM_B), ("orev", _SUM_D)],
        )

    async def test_accepted_release_uses_srcmd5_and_old_package(
        self, server: IBSServer
    ) -> None:
        await _diff(server, _ACCEPTED_RR, _sourcediff())
        assert _sent(server) == (
            "/source/SUSE:SLE-15-SP6:Update/curl.80001",
            [
                *_BASE,
                ("rev", _SUM_B),
                ("orev", _SUM_D),
                ("oproject", "SUSE:SLE-15-SP6:Update"),
                ("opackage", "curl.80000"),
            ],
        )

    @pytest.mark.parametrize(
        ("acceptinfo", "expected"),
        [
            (
                AcceptInfo(srcmd5=_SUM_A, osrcmd5=_SUM_C),
                [("rev", _SUM_A), ("orev", _SUM_C)],
            ),
            (AcceptInfo(xsrcmd5=_SUM_B), [("rev", _SUM_B), ("orev", "0")]),
            (
                AcceptInfo(srcmd5=_SUM_A, opackage="curl.1"),
                [("rev", _SUM_A), ("orev", "0"), ("opackage", "curl.1")],
            ),
            (
                AcceptInfo(srcmd5=_SUM_A, oproject="SUSE:P"),
                [("rev", _SUM_A), ("orev", "0"), ("oproject", "SUSE:P")],
            ),
        ],
        ids=["osrcmd5_fallback", "empty_tree", "opackage_only", "oproject_only"],
    )
    async def test_accepted_fallbacks(
        self,
        server: IBSServer,
        acceptinfo: AcceptInfo,
        expected: list[tuple[str, str]],
    ) -> None:
        action = dataclasses.replace(_ACCEPTED_RR, acceptinfo=acceptinfo)
        await _diff(server, action, _sourcediff())
        assert _sent(server)[1] == [*_BASE, *expected]

    @pytest.mark.parametrize(
        ("action", "codestream"),
        [(_OPEN_SR, "SUSE:SLE-15-SP6:Update"), (_OPEN_RR, "SUSE:SLE-15-SP6:Update")],
        ids=["incident_release_project", "release_target_project"],
    )
    async def test_not_accepted_form_expands_against_the_codestream_package(
        self, server: IBSServer, action: IBSRequestActionDetail, codestream: str
    ) -> None:
        await _diff(server, action, _sourcediff(), codestream_package="curl")
        assert _sent(server) == (
            f"/source/{action.source_project}/{action.source_package}",
            [
                *_BASE,
                ("expand", "1"),
                ("rev", _SUM_A),
                ("oproject", codestream),
                ("opackage", "curl"),
            ],
        )

    async def test_incident_codestream_is_the_release_project(
        self, server: IBSServer
    ) -> None:
        action = dataclasses.replace(
            _OPEN_SR,
            target_project="SUSE:Other",
            target_release_project="SUSE:SLE-15-SP7:Update",
        )
        await _diff(server, action, _sourcediff())
        assert ("oproject", "SUSE:SLE-15-SP7:Update") in _sent(server)[1]

    @pytest.mark.parametrize(
        "action",
        [
            _OPEN_SR,
            _OPEN_RR,
            dataclasses.replace(_OPEN_SR, source_revision="7"),
            dataclasses.replace(_OPEN_RR, target_release_project="SUSE:X"),
        ],
    )
    async def test_not_accepted_action_is_never_diffed_without_expand(
        self, server: IBSServer, action: IBSRequestActionDetail
    ) -> None:
        await _diff(server, action, _sourcediff())
        params = _sent(server)[1]
        assert params.count(("expand", "1")) == 1

    async def test_accepted_action_is_never_expanded(self, server: IBSServer) -> None:
        await _diff(server, _ACCEPTED_SR, _sourcediff())
        assert "expand" not in dict(_sent(server)[1])

    async def test_codestream_package_is_unused_by_the_accepted_form(
        self, server: IBSServer
    ) -> None:
        await _diff(server, _ACCEPTED_SR, _sourcediff(), codestream_package="other")
        assert "other" not in str(_sent(server))

    async def test_plus_is_kept_in_the_path_and_encoded_in_the_query(
        self, server: IBSServer
    ) -> None:
        action = dataclasses.replace(_OPEN_RR, source_package="libstdc++6.SUSE_X")
        await _diff(server, action, _sourcediff(), codestream_package="libstdc++6")
        [request] = [r for r in server.requests if "authorization" in r.headers]
        assert request.url.raw_path.startswith(
            b"/source/SUSE:Maintenance:80001/libstdc++6.SUSE_X?"
        )
        assert b"opackage=libstdc%2B%2B6" in request.url.raw_path


class TestNoRequest:
    @pytest.mark.parametrize(
        ("action", "reason"),
        [
            (dataclasses.replace(_OPEN_SR, source_revision=None), "missing_diff_input"),
            (
                dataclasses.replace(_OPEN_RR, target_project=None),
                "missing_diff_input",
            ),
            (
                dataclasses.replace(_ACCEPTED_SR, target_project=None),
                "missing_diff_input",
            ),
            (
                dataclasses.replace(_ACCEPTED_SR, target_package=None),
                "missing_diff_input",
            ),
            (
                dataclasses.replace(
                    _ACCEPTED_SR, acceptinfo=AcceptInfo(rev="2", osrcmd5=_SUM_C)
                ),
                "missing_diff_input",
            ),
            (
                dataclasses.replace(_ACCEPTED_SR, acceptinfo=AcceptInfo()),
                "missing_diff_input",
            ),
            (
                dataclasses.replace(_OPEN_SR, source_project="_redacted_"),
                "outside_suse_namespace",
            ),
            (
                dataclasses.replace(_OPEN_SR, target_release_project="_redacted_"),
                "outside_suse_namespace",
            ),
            (
                dataclasses.replace(_OPEN_RR, target_project="_redacted_"),
                "outside_suse_namespace",
            ),
            (
                dataclasses.replace(_OPEN_RR, source_project="openSUSE:Factory"),
                "outside_suse_namespace",
            ),
            (
                dataclasses.replace(_ACCEPTED_SR, target_project="_redacted_"),
                "outside_suse_namespace",
            ),
            (
                dataclasses.replace(
                    _ACCEPTED_RR,
                    acceptinfo=AcceptInfo(srcmd5=_SUM_A, oproject="_redacted_"),
                ),
                "outside_suse_namespace",
            ),
        ],
        ids=[
            "open_without_source_revision",
            "open_release_without_codestream",
            "accepted_without_target_project",
            "accepted_without_target_package",
            "accepted_without_new_checksum",
            "accepted_empty_acceptinfo",
            "open_from_personal_project",
            "open_to_personal_codestream",
            "open_release_to_personal_project",
            "open_release_from_opensuse",
            "accepted_to_personal_project",
            "accepted_old_personal_project",
        ],
    )
    async def test_unrequestable_diff_is_incomplete_without_any_request(
        self,
        server: IBSServer,
        action: IBSRequestActionDetail,
        reason: IncompleteReason,
    ) -> None:
        async with ibs_client(username="") as client:
            result = await client.get_request_action_diff(
                action, codestream_package="curl"
            )
        assert result == RequestEvidenceResult(incomplete_reason=reason)
        assert server.requests == []

    async def test_accepted_personal_source_is_diffed_through_its_target(
        self, server: IBSServer
    ) -> None:
        action = dataclasses.replace(_ACCEPTED_SR, source_project="_redacted_")
        result = await _diff(server, action, _sourcediff())
        assert result.value == RequestActionDiff(())
        assert all("redacted" not in str(r.url) for r in server.requests)

    async def test_credentials_are_checked_before_a_requestable_diff(
        self, server: IBSServer
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await client.get_request_action_diff(
                    _OPEN_SR, codestream_package="curl"
                )
        assert server.requests == []


class TestInputValidation:
    @pytest.mark.parametrize(
        ("action", "codestream_package"),
        [
            (None, "curl"),
            ({"source_project": "SUSE:A"}, "curl"),
            (_OPEN_SR, ""),
            (_OPEN_SR, "cu rl"),
            (_OPEN_SR, "curl/x"),
            (_OPEN_SR, None),
            (dataclasses.replace(_OPEN_SR, source_package="a/b"), "curl"),
            (dataclasses.replace(_OPEN_SR, source_project="SUSE:a b"), "curl"),
            (dataclasses.replace(_OPEN_SR, source_revision="A" * 32), "curl"),
            (dataclasses.replace(_OPEN_SR, source_revision="0"), "curl"),
            (dataclasses.replace(_OPEN_SR, target_release_project=""), "curl"),
            (
                dataclasses.replace(
                    _ACCEPTED_SR, acceptinfo=AcceptInfo(srcmd5="A" * 32)
                ),
                "curl",
            ),
            (
                dataclasses.replace(
                    _ACCEPTED_RR, acceptinfo=AcceptInfo(srcmd5=_SUM_A, opackage="a b")
                ),
                "curl",
            ),
        ],
        ids=[
            "no_action",
            "mapping",
            "empty_package",
            "space",
            "slash",
            "none_package",
            "invalid_source_package",
            "invalid_source_project",
            "upper_case_revision",
            "zero_revision",
            "empty_release_project",
            "upper_case_acceptinfo",
            "invalid_old_package",
        ],
    )
    async def test_invalid_input_raises_before_any_request(
        self, server: IBSServer, action: Any, codestream_package: Any
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(ValueError, match=r"invalid IBS|IBSRequestActionDetail"):
                await client.get_request_action_diff(
                    action, codestream_package=codestream_package
                )
        assert server.requests == []


class TestResponse:
    async def test_issues_are_returned_faithfully(self, server: IBSServer) -> None:
        issues = "".join(
            [
                _issue(state="added", tracker="cve", name="2026-1", label="CVE-2026-1"),
                _issue(
                    state="changed", tracker="cve", name="2026-2", label="CVE-2026-2"
                ),
                _issue(state="added", tracker="cve", name="2026-1", label="CVE-2026-1"),
                _issue(state="deleted", tracker="bnc", name="1", label="bsc#1"),
                _issue(state="added", tracker="cve", name="2026-3"),
                _issue(state="added", tracker="gh", label="GHSA-x"),
                _issue(state="weird", tracker="jsc", name="J-1", label=""),
            ]
        )
        result = await _diff(server, _ACCEPTED_SR, _sourcediff(issues))
        assert result.value == RequestActionDiff(
            (
                RequestActionIssue("cve", "added", "2026-1", "CVE-2026-1"),
                RequestActionIssue("cve", "changed", "2026-2", "CVE-2026-2"),
                RequestActionIssue("cve", "added", "2026-1", "CVE-2026-1"),
                RequestActionIssue("bnc", "deleted", "1", "bsc#1"),
                RequestActionIssue("cve", "added", "2026-3", None),
                RequestActionIssue("gh", "added", None, "GHSA-x"),
                RequestActionIssue("jsc", "weird", "J-1", ""),
            )
        )

    async def test_unconsumed_content_is_ignored(self, server: IBSServer) -> None:
        body = (
            '<sourcediff key="x"><old project="SUSE:A" package="a" rev="1"/>'
            '<new project="SUSE:B" package="b"/><files><file state="changed">'
            "<diff>fictional changes text</diff></file></files><issues>"
            '<issue state="added" tracker="cve" name="2026-1" label="CVE-2026-1" '
            'url="https://example.test/x"/></issues></sourcediff>'
        )
        result = await _diff(server, _ACCEPTED_SR, xml_response(body.encode()))
        assert result.value == RequestActionDiff(
            (RequestActionIssue("cve", "added", "2026-1", "CVE-2026-1"),)
        )

    @pytest.mark.parametrize(
        "responder",
        [
            _sourcediff(),
            _sourcediff("", wrap=False),
            _sourcediff("<old/><new/><files/>", wrap=False),
        ],
        ids=["empty_issues", "no_issues", "no_issues_with_files"],
    )
    async def test_diff_without_issues_is_a_valid_empty_set(
        self, server: IBSServer, responder: Responder
    ) -> None:
        result = await _diff(server, _ACCEPTED_SR, responder)
        assert result == RequestEvidenceResult(value=RequestActionDiff(()))

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            ("<sourcediff><issues/><issues/></sourcediff>", "invalid_document"),
            ("<issues/>", "invalid_document"),
            ('<status code="400"/>', "invalid_document"),
            (
                '<sourcediff><issues><issue state="added"/></issues></sourcediff>',
                "invalid_issue",
            ),
            (
                '<sourcediff><issues><issue tracker="" state="added"/></issues>'
                "</sourcediff>",
                "invalid_issue",
            ),
            (
                '<sourcediff><issues><issue tracker="cve"/></issues></sourcediff>',
                "invalid_issue",
            ),
            (
                '<sourcediff><issues><issue tracker="cve" state=""/></issues>'
                "</sourcediff>",
                "invalid_issue",
            ),
            (
                '<sourcediff><issues><reference tracker="cve" state="added"/>'
                "</issues></sourcediff>",
                "invalid_issue",
            ),
            (
                '<sourcediff><issues><issue tracker="cve" state="added"><x/></issue>'
                "</issues></sourcediff>",
                "invalid_issue",
            ),
            ("<sourcediff><issues>", "malformed_xml"),
        ],
        ids=[
            "two_issues_elements",
            "wrong_root",
            "status_document",
            "missing_tracker",
            "empty_tracker",
            "missing_state",
            "empty_state",
            "other_element",
            "nested_child",
            "truncated",
        ],
    )
    async def test_unusable_diff_is_incomplete(
        self, server: IBSServer, body: str, reason: IncompleteReason
    ) -> None:
        result = await _diff(server, _ACCEPTED_SR, xml_response(body.encode()))
        assert result == RequestEvidenceResult(incomplete_reason=reason)


class TestHttpStatus:
    @pytest.mark.parametrize(
        ("status", "reason"), [(400, "rejected"), (404, "not_found")]
    )
    async def test_400_and_404_are_incomplete_without_reading_the_body(
        self, server: IBSServer, status: int, reason: IncompleteReason
    ) -> None:
        read: list[bool] = []

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                read.append(True)
                yield load_request_fixture("diff_error_unavailable_checksum")

        result = await _diff(
            server, _ACCEPTED_SR, lambda _: httpx.Response(status, stream=Body())
        )
        assert result == RequestEvidenceResult(incomplete_reason=reason)
        assert read == []

    async def test_unavailable_checksum_summary_is_never_history_unavailable(
        self, server: IBSServer
    ) -> None:
        action = dataclasses.replace(
            _ACCEPTED_SR,
            acceptinfo=AcceptInfo(xsrcmd5=_SUM_B, oxsrcmd5=_SUM_D),
        )
        summary = (
            f"SUSE:Maintenance:80001/curl.SUSE_SLE-15-SP6_Update/{_SUM_D}: "
            "not in repository. fictional"
        )
        body = (
            f'<status code="400" origin="backend"><summary>{summary}</summary></status>'
        )
        result = await _diff(server, action, status_response(400, body.encode()))
        assert result == RequestEvidenceResult(incomplete_reason="rejected")

    @pytest.mark.parametrize("status", [403, 409, 429, 500])
    async def test_other_status_propagates(
        self, server: IBSServer, status: int
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _diff(server, _ACCEPTED_SR, status_response(status, b"<status/>"))
        assert raised.value.response.status_code == status

    async def test_post_is_retried_on_connection_error(
        self, server: IBSServer, sleep: AsyncMock
    ) -> None:
        attempts: list[int] = []

        def drop_first(request: httpx.Request) -> httpx.Response | None:
            attempts.append(1)
            if len(attempts) == 1:
                raise httpx.ConnectError("fictional failure", request=request)
            return None

        server.intercept = drop_first
        result = await _diff(server, _ACCEPTED_SR, _sourcediff())
        assert result.value == RequestActionDiff(())
        assert [r.method for r in server.requests] == ["POST"] * 3
        sleep.assert_awaited_once_with(1.0)

    async def test_post_is_retried_on_timeout_then_propagates(
        self, server: IBSServer
    ) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("fictional timeout", request=request)

        server.intercept = timeout
        with pytest.raises(httpx.ReadTimeout):
            await _diff(server, _ACCEPTED_SR, _sourcediff())
        assert [r.method for r in server.requests] == ["POST"] * 4
