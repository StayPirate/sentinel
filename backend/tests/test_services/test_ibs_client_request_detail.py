"""Tests for `IBSClient.get_request()`.

Contract under test: docs/features/integrations/ibs-integration.md (Request
Point Detail, including IBS names, the closed action-type set, and the
replacement of projects outside `SUSE:`; Service Layer > IBSClient, the
detail method and its escaping outcomes);
docs/features/packages/ibs-submission-tracking.md (Request States, Data
Model > IBSRequestAction semantic identities, Testing Requirements bullets
1 and 2, parsing parts). Live documents are the sanitized captures of
`tests/support/ibs_request_api.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

import httpx
import pytest

from app.core.enums import IBSRequestActionType, IBSRequestState
from app.services.ibs_client import (
    AcceptInfo,
    IBSRequestActionDetail,
    IBSRequestDetail,
    IncompleteReason,
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
    load_request_fixture,
    request_fixture_record,
    serve_request_fixture,
)

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_INCIDENT: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
_RELEASE: Final = IBSRequestActionType.MAINTENANCE_RELEASE
_NUMBER: Final = 920001
_CREATED: Final = "2026-10-01T05:20:43"
_WHEN: Final = "2026-10-01T09:16:55"
_SUM_A: Final = "a" * 32
_SUM_B: Final = "b" * 32
_SUM_C: Final = "c" * 32
_STATE: Final = f'<state name="new" created="{_CREATED}" when="{_WHEN}"/>'


def _attrs(values: dict[str, str]) -> str:
    return " ".join(f'{key}="{value}"' for key, value in values.items())


def _incident(
    source: dict[str, str] | None = None,
    target: dict[str, str] | None = None,
    acceptinfo: dict[str, str] | None = None,
    extra: str = "",
) -> str:
    source = (
        {
            "project": f"SUSE:Maintenance:REQUEST:{_NUMBER}",
            "package": "curl.SUSE_SLE-15-SP6_Update",
            "rev": _SUM_A,
        }
        if source is None
        else source
    )
    target = (
        {"project": "SUSE:Maintenance", "releaseproject": "SUSE:SLE-15-SP6:Update"}
        if target is None
        else target
    )
    accepted = "" if acceptinfo is None else f"<acceptinfo {_attrs(acceptinfo)}/>"
    return (
        f'<action type="maintenance_incident"><source {_attrs(source)}/>'
        f"<target {_attrs(target)}/>{accepted}{extra}</action>"
    )


def _release(
    source: dict[str, str] | None = None,
    target: dict[str, str] | None = None,
    acceptinfo: dict[str, str] | None = None,
) -> str:
    source = (
        {
            "project": "SUSE:Maintenance:80001",
            "package": "curl.SUSE_SLE-15-SP6_Update",
            "rev": _SUM_A,
        }
        if source is None
        else source
    )
    target = (
        {"project": "SUSE:SLE-15-SP6:Update", "package": "curl.80001"}
        if target is None
        else target
    )
    accepted = "" if acceptinfo is None else f"<acceptinfo {_attrs(acceptinfo)}/>"
    return (
        f'<action type="maintenance_release"><source {_attrs(source)}/>'
        f"<target {_attrs(target)}/>{accepted}</action>"
    )


def _detail(*actions: str, state: str = _STATE, root: str = "") -> Responder:
    body = f'<request id="{_NUMBER}"{root}>{"".join(actions)}{state}</request>'
    return xml_response(body.encode())


async def _get(
    server: IBSServer, responder: Responder | None, number: int = _NUMBER
) -> RequestEvidenceResult[IBSRequestDetail]:
    if responder is not None:
        server.route("GET", f"/request/{number}", responder)
    async with ibs_client() as client:
        return await client.get_request(number)


async def _value(server: IBSServer, responder: Responder) -> IBSRequestDetail:
    result = await _get(server, responder)
    assert result.incomplete_reason is None
    assert result.value is not None
    return result.value


async def _reason(server: IBSServer, responder: Responder) -> IncompleteReason | None:
    result = await _get(server, responder)
    assert result.value is None
    return result.incomplete_reason


async def _live(server: IBSServer, name: str) -> IBSRequestDetail:
    serve_request_fixture(server, name)
    number = int(request_fixture_record(name)["path"].removeprefix("/request/"))
    result = await _get(server, None, number)
    assert result.value is not None, result.incomplete_reason
    [signed] = [r for r in server.requests if "authorization" in r.headers]
    assert signed.method == "GET"
    assert signed.url.path == f"/request/{number}"
    assert signed.url.query == b""
    return result.value


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


class TestLiveDetails:
    async def test_open_submission(self, server: IBSServer) -> None:
        detail = await _live(server, "request_sr_open")
        assert detail == IBSRequestDetail(
            request_number=910015,
            state=IBSRequestState.NEW,
            upstream_created_at=_utc("2026-10-01T05:20:43"),
            upstream_updated_at=_utc("2026-10-01T09:16:55"),
            superseded_by_request_number=None,
            actions=(
                IBSRequestActionDetail(
                    request_number=910015,
                    action_type=_INCIDENT,
                    source_project="SUSE:Maintenance:REQUEST:910015",
                    source_package="openvpn.SUSE_SLE-15-SP6_Update",
                    source_revision="b28e7df0a50947dc1327f4da92c888b6",
                    target_project="SUSE:Maintenance",
                    target_package=None,
                    target_release_project="SUSE:SLE-15-SP6:Update",
                    acceptinfo=None,
                ),
            ),
        )

    async def test_accepted_submission_with_complete_acceptinfo(
        self, server: IBSServer
    ) -> None:
        detail = await _live(server, "request_sr_accepted")
        assert detail.state is IBSRequestState.ACCEPTED
        [action] = detail.actions
        assert action.target_project == "SUSE:Maintenance:80001"
        assert action.target_package == "openvpn.SUSE_SLE-15-SP6_Update"
        assert action.acceptinfo == AcceptInfo(
            rev="10",
            srcmd5="0f7d47874bfd58176c66276bb3e2320c",
            xsrcmd5="91054a5ca2b02f7921270c7462a526d0",
            osrcmd5="085c5cdd702c40cf571553a08ad4d0b6",
            oxsrcmd5="b1d7f1158d968bf4b4bf012de7cf15f8",
        )

    async def test_superseded_and_declined_submissions(self, server: IBSServer) -> None:
        superseded = await _live(server, "request_sr_superseded")
        assert superseded.state is IBSRequestState.SUPERSEDED
        assert superseded.superseded_by_request_number == 910095
        server.requests.clear()
        declined = await _live(server, "request_sr_declined")
        assert declined.state is IBSRequestState.DECLINED
        assert declined.superseded_by_request_number is None

    async def test_personal_project_is_replaced_in_the_result(
        self, server: IBSServer
    ) -> None:
        detail = await _live(server, "request_sr_home")
        [action] = detail.actions
        assert action.source_project == "_redacted_"
        assert action.target_project == "SUSE:Maintenance:80013"
        assert "home:" not in repr(detail)

    async def test_accepted_release_with_patchinfo_actions(
        self, server: IBSServer
    ) -> None:
        detail = await _live(server, "request_rr_accepted")
        code, *patchinfo = detail.actions
        assert code.action_type is _RELEASE
        assert code.acceptinfo == AcceptInfo(
            rev="1",
            srcmd5="c40f9d03a8728b65ac857fe47495c082",
            osrcmd5="eaa736f26f67a409be8ccd779db7d1e2",
            oxsrcmd5="eaa736f26f67a409be8ccd779db7d1e2",
            oproject="SUSE:SLE-15-SP6:Update",
            opackage="openvpn.80002",
        )
        assert len(patchinfo) == 15
        for action in patchinfo:
            assert action.source_package == "patchinfo"
            assert action.source_revision is None
            assert action.acceptinfo is not None
            assert action.acceptinfo.xsrcmd5 is None
            assert action.acceptinfo.oproject is None

    async def test_open_and_revoked_releases_have_no_acceptinfo(
        self, server: IBSServer
    ) -> None:
        opened = await _live(server, "request_rr_open")
        assert opened.state is IBSRequestState.REVIEW
        assert opened.actions[0].source_revision is not None
        assert all(a.source_revision is None for a in opened.actions[1:])
        server.requests.clear()
        revoked = await _live(server, "request_rr_revoked")
        assert revoked.state is IBSRequestState.REVOKED
        assert all(a.acceptinfo is None for a in (*opened.actions, *revoked.actions))

    async def test_kernel_release_keeps_release_actions_and_ignores_submits(
        self, server: IBSServer
    ) -> None:
        detail = await _live(server, "request_rr_kernel")
        assert len(detail.actions) == 32
        assert {a.action_type for a in detail.actions} == {_RELEASE}
        assert all(a.target_project != "SUSE:Channels" for a in detail.actions)
        by_package = {a.target_package: a for a in detail.actions}
        assert by_package["kernel-default.80007"].acceptinfo is None
        assert by_package["kernel-default-base.80007"].acceptinfo is not None
        assert by_package["kernel-source.80007"].acceptinfo is not None
        assert sum(a.acceptinfo is None for a in detail.actions) == 12

    async def test_request_with_only_ignored_types_is_complete_and_empty(
        self, server: IBSServer
    ) -> None:
        detail = await _live(server, "request_non_maintenance")
        assert detail.state is IBSRequestState.REVOKED
        assert detail.actions == ()

    async def test_live_404_is_incomplete_never_deleted(
        self, server: IBSServer
    ) -> None:
        serve_request_fixture(server, "request_not_found")
        result = await _get(server, None, 99999999)
        assert result == RequestEvidenceResult(incomplete_reason="not_found")


class TestInputValidation:
    @pytest.mark.parametrize("number", [0, -1, True, False, 1.0, "7", None])
    async def test_invalid_number_raises_before_any_request(
        self, server: IBSServer, number: Any
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(ValueError, match="positive integer"):
                await client.get_request(number)
        assert server.requests == []


class TestState:
    @pytest.mark.parametrize("state", list(IBSRequestState))
    async def test_every_known_state(
        self, server: IBSServer, state: IBSRequestState
    ) -> None:
        successor = ' superseded_by="920002"' if state == "superseded" else ""
        detail = await _value(
            server,
            _detail(
                _incident(),
                state=(
                    f'<state name="{state.value}" created="{_CREATED}" '
                    f'when="{_WHEN}"{successor}/>'
                ),
            ),
        )
        assert detail.state is state
        assert detail.superseded_by_request_number == (920002 if successor else None)

    @pytest.mark.parametrize(
        ("when", "expected"),
        [
            ("2026-10-01T09:16:55", "2026-10-01T09:16:55+00:00"),
            ("2026-10-01T09:16:55Z", "2026-10-01T09:16:55+00:00"),
            ("2026-10-01T11:16:55+02:00", "2026-10-01T09:16:55+00:00"),
            ("2026-10-01T04:16:55-05:00", "2026-10-01T09:16:55+00:00"),
        ],
    )
    async def test_timestamps_are_utc(
        self, server: IBSServer, when: str, expected: str
    ) -> None:
        detail = await _value(
            server,
            _detail(state=f'<state name="new" created="{_CREATED}" when="{when}"/>'),
        )
        assert detail.upstream_updated_at == datetime.fromisoformat(expected)
        assert detail.upstream_updated_at.tzinfo is UTC
        assert detail.upstream_created_at == _utc(_CREATED)

    @pytest.mark.parametrize(
        "state",
        [
            f'<state name="open" created="{_CREATED}" when="{_WHEN}"/>',
            f'<state name="NEW" created="{_CREATED}" when="{_WHEN}"/>',
            f'<state created="{_CREATED}" when="{_WHEN}"/>',
            f'<state name="new" when="{_WHEN}"/>',
            f'<state name="new" created="{_CREATED}"/>',
            f'<state name="new" created="2026-13-01T00:00:00" when="{_WHEN}"/>',
            f'<state name="new" created="2026-10-01" when="{_WHEN}"/>',
            f'<state name="new" created="2026-10-01T05:20:43.5" when="{_WHEN}"/>',
            f'<state name="new" created="2026-10-01 05:20:43" when="{_WHEN}"/>',
            f'<state name="new" created="{_CREATED}+25:00" when="{_WHEN}"/>',
            f'<state name="new" created="" when="{_WHEN}"/>',
            f'<state name="superseded" created="{_CREATED}" when="{_WHEN}"/>',
            (
                f'<state name="superseded" created="{_CREATED}" when="{_WHEN}" '
                f'superseded_by="{_NUMBER}"/>'
            ),
            (
                f'<state name="superseded" created="{_CREATED}" when="{_WHEN}" '
                'superseded_by="0"/>'
            ),
            (
                f'<state name="superseded" created="{_CREATED}" when="{_WHEN}" '
                'superseded_by="x"/>'
            ),
            (
                f'<state name="accepted" created="{_CREATED}" when="{_WHEN}" '
                'superseded_by="920002"/>'
            ),
            (
                f'<state name="declined" created="{_CREATED}" when="{_WHEN}" '
                'superseded_by=""/>'
            ),
        ],
        ids=[
            "unknown_name",
            "upper_case_name",
            "missing_name",
            "missing_created",
            "missing_when",
            "invalid_date",
            "date_only",
            "fractional_seconds",
            "space_separator",
            "invalid_offset",
            "empty_created",
            "superseded_without_successor",
            "superseded_by_itself",
            "zero_successor",
            "non_numeric_successor",
            "successor_on_accepted",
            "empty_successor_on_declined",
        ],
    )
    async def test_invalid_state_is_incomplete(
        self, server: IBSServer, state: str
    ) -> None:
        assert await _reason(server, _detail(_incident(), state=state)) == (
            "invalid_state"
        )

    @pytest.mark.parametrize(
        "body",
        [
            f'<request id="{_NUMBER}">{_incident()}</request>',
            f'<request id="{_NUMBER}">{_STATE}{_STATE}</request>',
            f'<request id="920002">{_STATE}</request>',
            f'<request id="0{_NUMBER}">{_STATE}</request>',
            f"<request>{_STATE}</request>",
            f'<requests id="{_NUMBER}">{_STATE}</requests>',
            f'<collection matches="1"><request id="{_NUMBER}"/></collection>',
        ],
        ids=[
            "no_state",
            "two_states",
            "other_id",
            "leading_zero_id",
            "missing_id",
            "wrong_root",
            "search_document",
        ],
    )
    async def test_document_shape_is_incomplete(
        self, server: IBSServer, body: str
    ) -> None:
        assert await _reason(server, xml_response(body.encode())) == (
            "invalid_document"
        )

    async def test_reopened_declined_request_is_current_state(
        self, server: IBSServer
    ) -> None:
        detail = await _value(
            server,
            _detail(
                state=f'<state name="review" created="{_CREATED}" when="{_WHEN}"/>'
            ),
        )
        assert detail.state is IBSRequestState.REVIEW


class TestActionTypes:
    @pytest.mark.parametrize(
        "action_type",
        ["submit", "delete", "add_role", "set_bugowner", "change_devel", "release"],
    )
    async def test_six_types_are_ignored(
        self, server: IBSServer, action_type: str
    ) -> None:
        ignored = (
            f'<action type="{action_type}"><source project="home:x" package="a b"/>'
            '<target project="?"/><acceptinfo rev="x"/></action>'
        )
        detail = await _value(server, _detail(ignored, _incident(), ignored))
        assert [a.action_type for a in detail.actions] == [_INCIDENT]

    @pytest.mark.parametrize(
        "action",
        [
            '<action type="patchinfo"><source project="SUSE:A" package="p"/></action>',
            '<action type="Maintenance_Release"/>',
            '<action type=""/>',
            "<action/>",
        ],
        ids=["patchinfo", "case_variant", "empty", "missing"],
    )
    async def test_any_other_type_is_incomplete(
        self, server: IBSServer, action: str
    ) -> None:
        assert await _reason(server, _detail(_incident(), action)) == (
            "unknown_action_type"
        )

    async def test_patchinfo_release_actions_are_ordinary_actions(
        self, server: IBSServer
    ) -> None:
        detail = await _value(
            server,
            _detail(
                _release(
                    source={
                        "project": "SUSE:Maintenance:80001",
                        "package": "patchinfo",
                    },
                    target={
                        "project": "SUSE:Updates:SLE-Module-Basesystem:15-SP7:x86_64",
                        "package": "patchinfo.80001",
                    },
                )
            ),
        )
        [action] = detail.actions
        assert action.source_package == "patchinfo"
        assert action.source_revision is None


class TestRequiredAndOptionalFields:
    @pytest.mark.parametrize(
        ("builder", "element", "attribute"),
        [
            (_incident, "source", "project"),
            (_incident, "source", "package"),
            (_incident, "target", "releaseproject"),
            (_release, "source", "project"),
            (_release, "source", "package"),
            (_release, "target", "project"),
            (_release, "target", "package"),
        ],
    )
    async def test_missing_required_field_is_incomplete(
        self, server: IBSServer, builder: Any, element: str, attribute: str
    ) -> None:
        base = await _value(server, _detail(builder()))
        [action] = base.actions
        values = {
            "source": {
                "project": action.source_project,
                "package": action.source_package,
            },
            "target": {
                key: value
                for key, value in (
                    ("project", action.target_project),
                    ("package", action.target_package),
                    ("releaseproject", action.target_release_project),
                )
                if value is not None
            },
        }
        del values[element][attribute]
        server.requests.clear()
        assert (
            await _reason(server, _detail(builder(values["source"], values["target"])))
            == "invalid_action"
        )

    @pytest.mark.parametrize("builder", [_incident, _release])
    async def test_missing_source_element_is_incomplete(
        self, server: IBSServer, builder: Any
    ) -> None:
        action = builder().replace("<source ", "<origin ")
        assert await _reason(server, _detail(action)) == "invalid_action"

    async def test_optional_fields_absent_are_none(self, server: IBSServer) -> None:
        detail = await _value(
            server,
            _detail(
                _incident(
                    source={
                        "project": "SUSE:Maintenance:REQUEST:1",
                        "package": "curl.SUSE_SLE-15-SP6_Update",
                    },
                    target={"releaseproject": "SUSE:SLE-15-SP6:Update"},
                ),
                _release(
                    source={"project": "SUSE:Maintenance:80001", "package": "curl.x"},
                ),
            ),
        )
        incident, release = detail.actions
        assert incident.source_revision is None
        assert incident.target_project is None
        assert incident.target_package is None
        assert incident.acceptinfo is None
        assert release.target_release_project is None

    async def test_optional_release_project_of_a_release_action_is_consumed(
        self, server: IBSServer
    ) -> None:
        detail = await _value(
            server,
            _detail(
                _release(
                    target={
                        "project": "SUSE:SLE-15-SP6:Update",
                        "package": "curl.80001",
                        "releaseproject": "SUSE:SLE-15-SP6:Update",
                    }
                )
            ),
        )
        assert detail.actions[0].target_release_project == "SUSE:SLE-15-SP6:Update"

    async def test_empty_acceptinfo_element_is_present_and_empty(
        self, server: IBSServer
    ) -> None:
        detail = await _value(server, _detail(_incident(acceptinfo={})))
        assert detail.actions[0].acceptinfo == AcceptInfo()

    @pytest.mark.parametrize(
        ("attribute", "value", "valid"),
        [
            ("rev", "7", True),
            ("rev", _SUM_A, True),
            ("rev", "", False),
            ("rev", "0", False),
            ("rev", "07", False),
            ("rev", "-7", False),
            ("rev", "A" * 32, False),
            ("rev", "a" * 31, False),
            ("rev", "a" * 33, False),
            ("project", "", False),
            ("package", "", False),
            ("package", "a b", False),
            ("package", "a/b", False),
            ("package", "a'b", False),
            ("package", "..", False),
            ("package", "x" * 256, False),
        ],
    )
    async def test_source_field_contracts(
        self, server: IBSServer, attribute: str, value: str, valid: bool
    ) -> None:
        source = {
            "project": "SUSE:Maintenance:REQUEST:1",
            "package": "curl.SUSE_SLE-15-SP6_Update",
            attribute: value,
        }
        result = await _get(server, _detail(_incident(source=source)))
        if valid:
            assert result.value is not None
            assert result.value.actions[0].source_revision == value
        else:
            assert result == RequestEvidenceResult(incomplete_reason="invalid_action")

    @pytest.mark.parametrize("attribute", ["project", "package", "releaseproject"])
    @pytest.mark.parametrize("value", ["", "SUSE:a b", "SUSE:a/b", "SUSE:é"])
    async def test_target_names_must_be_ibs_names(
        self, server: IBSServer, attribute: str, value: str
    ) -> None:
        target = {
            "project": "SUSE:SLE-15-SP6:Update",
            "package": "curl.80001",
            attribute: value,
        }
        assert await _reason(server, _detail(_release(target=target))) == (
            "invalid_action"
        )

    @pytest.mark.parametrize(
        ("attribute", "value"),
        [
            ("rev", "0"),
            ("rev", "x"),
            ("rev", ""),
            ("rev", _SUM_A),
            ("srcmd5", "A" * 32),
            ("xsrcmd5", "a" * 31),
            ("osrcmd5", ""),
            ("oxsrcmd5", "g" * 32),
            ("oproject", "SUSE:a b"),
            ("oproject", ""),
            ("opackage", "a/b"),
            ("opackage", ""),
        ],
    )
    async def test_acceptinfo_field_contracts(
        self, server: IBSServer, attribute: str, value: str
    ) -> None:
        acceptinfo = {"rev": "3", "srcmd5": _SUM_B, attribute: value}
        assert await _reason(server, _detail(_release(acceptinfo=acceptinfo))) == (
            "invalid_action"
        )

    @pytest.mark.parametrize("element", ["source", "target", "acceptinfo"])
    async def test_repeated_consumed_element_is_incomplete(
        self, server: IBSServer, element: str
    ) -> None:
        repeated = f'<{element} project="SUSE:A" package="b" releaseproject="SUSE:C"/>'
        action = _incident(acceptinfo={"rev": "1"}, extra=repeated)
        assert await _reason(server, _detail(action)) == "invalid_action"

    async def test_unknown_elements_and_attributes_are_ignored(
        self, server: IBSServer
    ) -> None:
        plain = await _value(
            server, _detail(_incident(acceptinfo={"rev": "2", "srcmd5": _SUM_B}))
        )
        server.requests.clear()
        noisy_action = (
            _incident(acceptinfo={"rev": "2", "srcmd5": _SUM_B, "lsrcmd5": _SUM_C})
            .replace("<source ", '<source fictional="1" ')
            .replace(
                "</action>",
                "<options><sourceupdate>cleanup</sourceupdate></options>"
                '<person name="fictional" role="maintainer"/></action>',
            )
        )
        noisy = await _value(
            server,
            _detail(
                "<description>Fictional free text</description>",
                noisy_action,
                '<review state="new" by_user="fictional-user"/>',
                state=(
                    f'<state name="new" created="{_CREATED}" when="{_WHEN}" '
                    'who="fictional-user"><comment>free text</comment></state>'
                    '<history who="fictional-user" when="2026-10-01T05:20:43">'
                    "<description>x</description></history>"
                ),
                root=' creator="fictional-user"',
            ),
        )
        assert noisy == plain


class TestProjectReplacement:
    @pytest.mark.parametrize(
        ("project", "stored"),
        [
            ("SUSE:SLE-15-SP6:Update", "SUSE:SLE-15-SP6:Update"),
            ("SUSE:Maintenance:REQUEST:1", "SUSE:Maintenance:REQUEST:1"),
            ("home:fictional:branches:SUSE:SLE-15:Update", "_redacted_"),
            ("openSUSE:Factory", "_redacted_"),
            ("suse:lower", "_redacted_"),
            ("SUSE", "_redacted_"),
            ("SUSEX:Update", "_redacted_"),
            ("_redacted_", "_redacted_"),
        ],
    )
    async def test_every_consumed_project_outside_suse_is_replaced(
        self, server: IBSServer, project: str, stored: str
    ) -> None:
        detail = await _value(
            server,
            _detail(
                _incident(
                    source={"project": project, "package": "a", "rev": "1"},
                    target={
                        "project": project,
                        "package": "a.x",
                        "releaseproject": project,
                    },
                ),
                _release(
                    source={"project": project, "package": "b"},
                    target={
                        "project": project,
                        "package": "b.1",
                        "releaseproject": project,
                    },
                    acceptinfo={"oproject": project, "opackage": "b.0"},
                ),
            ),
        )
        incident, release = detail.actions
        assert {
            incident.source_project,
            incident.target_project,
            incident.target_release_project,
            release.source_project,
            release.target_project,
            release.target_release_project,
            release.acceptinfo.oproject if release.acceptinfo else None,
        } == {stored}

    async def test_identities_colliding_through_replacement_are_incomplete(
        self, server: IBSServer
    ) -> None:
        def from_home(project: str) -> str:
            return _incident(
                source={"project": project, "package": "curl", "rev": "1"},
            )

        assert (
            await _reason(
                server,
                _detail(from_home("home:fictional-a"), from_home("home:fictional-b")),
            )
            == "duplicate_identity"
        )

    async def test_distinct_projects_inside_suse_do_not_collide(
        self, server: IBSServer
    ) -> None:
        def from_project(project: str) -> str:
            return _incident(source={"project": project, "package": "curl"})

        detail = await _value(
            server, _detail(from_project("SUSE:A"), from_project("SUSE:B"))
        )
        assert len(detail.actions) == 2


class TestSemanticIdentity:
    async def test_duplicate_incident_identity_ignores_target_fields(
        self, server: IBSServer
    ) -> None:
        first = _incident(
            target={"project": "SUSE:Maintenance", "releaseproject": "SUSE:R"}
        )
        second = _incident(
            target={
                "project": "SUSE:Maintenance:80001",
                "package": "x",
                "releaseproject": "SUSE:R",
            }
        )
        assert await _reason(server, _detail(first, second)) == "duplicate_identity"

    async def test_duplicate_release_identity_ignores_source_fields(
        self, server: IBSServer
    ) -> None:
        first = _release()
        second = _release(source={"project": "SUSE:Maintenance:80002", "package": "z"})
        assert await _reason(server, _detail(first, second)) == "duplicate_identity"

    async def test_actions_of_different_types_never_collide(
        self, server: IBSServer
    ) -> None:
        detail = await _value(server, _detail(_incident(), _release()))
        assert [a.action_type for a in detail.actions] == [_INCIDENT, _RELEASE]

    async def test_actions_keep_document_order(self, server: IBSServer) -> None:
        packages = ["zz", "aa", "mm"]
        detail = await _value(
            server,
            _detail(
                *(
                    _release(target={"project": "SUSE:T", "package": f"{p}.1"})
                    for p in packages
                )
            ),
        )
        assert [a.target_package for a in detail.actions] == [
            f"{p}.1" for p in packages
        ]
        assert all(a.request_number == _NUMBER for a in detail.actions)


class TestHttpStatus:
    @pytest.mark.parametrize("status", [400, 403, 410, 429, 500])
    async def test_status_other_than_404_propagates(
        self, server: IBSServer, status: int
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _get(server, status_response(status, b"<status/>"))
        assert raised.value.response.status_code == status

    async def test_404_body_is_not_read(self, server: IBSServer) -> None:
        read: list[bool] = []

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                read.append(True)
                yield load_request_fixture("request_not_found")

        result = await _get(server, lambda _: httpx.Response(404, stream=Body()))
        assert result == RequestEvidenceResult(incomplete_reason="not_found")
        assert read == []
