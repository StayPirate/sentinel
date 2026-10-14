"""Tests for `IBSClient.get_source_history()`.

Contract under test: docs/features/integrations/ibs-integration.md (Package
Source History: unpaged history, exact revision and checksum lookups, field
forms, and the start-at-1 contiguity check; Service Layer > IBSClient, the
history method and its escaping outcomes);
docs/features/packages/ibs-submission-tracking.md (Request Discovery and
Detail, history reads; Testing Requirements, history completeness and
lookups). Live documents are the sanitized captures of
`tests/support/ibs_request_api.py`.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any, Final

import httpx
import pytest

from app.services.ibs_client import (
    IBSCredentialsNotConfiguredError,
    IncompleteReason,
    RequestEvidenceResult,
    SourceHistory,
    SourceHistoryEntry,
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
    request_fixture_query,
    request_fixture_record,
    serve_request_fixture,
)

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_PROJECT: Final = "SUSE:SLE-15-SP6:Update"
_PACKAGE: Final = "curl"
_PATH: Final = f"/source/{_PROJECT}/{_PACKAGE}/_history"
_SUM_A: Final = "a" * 32
_SUM_B: Final = "b" * 32


def _revision(
    rev: str = "1",
    srcmd5: str | None = _SUM_A,
    time: str | None = "1700000000",
    requestid: str | None = None,
    extra: str = "",
) -> str:
    children = "".join(
        f"<{tag}>{value}</{tag}>"
        for tag, value in (("srcmd5", srcmd5), ("time", time), ("requestid", requestid))
        if value is not None
    )
    return f'<revision rev="{rev}" vrev="1">{children}{extra}</revision>'


def _history(*revisions: str) -> Responder:
    return xml_response(f"<revisionlist>{''.join(revisions)}</revisionlist>".encode())


async def _read(
    server: IBSServer,
    responder: Responder | None,
    revision: str | None = None,
    *,
    project: str = _PROJECT,
    package: str = _PACKAGE,
) -> RequestEvidenceResult[SourceHistory]:
    if responder is not None:
        server.route("GET", f"/source/{project}/{package}/_history", responder)
    async with ibs_client() as client:
        return await client.get_source_history(project, package, revision=revision)


def _sent(server: IBSServer) -> tuple[str, list[tuple[str, str]]]:
    [request] = [r for r in server.requests if "authorization" in r.headers]
    assert request.method == "GET"
    return request.url.path, list(request.url.params.multi_items())


def _fixture_entries(name: str) -> tuple[SourceHistoryEntry, ...]:
    root = ET.fromstring(load_request_fixture(name))
    return tuple(
        SourceHistoryEntry(
            revision=int(entry.get("rev") or "0"),
            srcmd5=entry.findtext("srcmd5") or "",
            time=datetime.fromtimestamp(int(entry.findtext("time") or "0"), tz=UTC),
            request_number=(
                None
                if entry.findtext("requestid") is None
                else int(entry.findtext("requestid") or "0")
            ),
        )
        for entry in root
    )


async def _live(server: IBSServer, name: str) -> RequestEvidenceResult[SourceHistory]:
    record = request_fixture_record(name)
    project, package, _ = record["path"].removeprefix("/source/").split("/")
    query = request_fixture_query(name)
    serve_request_fixture(server, name)
    result = await _read(
        server,
        None,
        None if not query else query[0][1],
        project=project,
        package=package,
    )
    assert _sent(server) == (record["path"], query)
    return result


class TestLiveHistories:
    @pytest.mark.parametrize(
        "name",
        [
            "history_codestream",
            "history_incident",
            "history_lookup_revision",
            "history_lookup_checksum_multiple",
        ],
    )
    async def test_live_history_is_requested_as_recorded_and_complete(
        self, server: IBSServer, name: str
    ) -> None:
        result = await _live(server, name)
        assert result == RequestEvidenceResult(
            value=SourceHistory(_fixture_entries(name))
        )

    async def test_live_incident_history_keeps_revisions_without_request(
        self, server: IBSServer
    ) -> None:
        result = await _live(server, "history_incident")
        assert result.value is not None
        numbers = [entry.request_number for entry in result.value.entries]
        assert None in numbers
        assert {910052, 910053, 910051} <= set(numbers)
        assert all(entry.time.tzinfo is UTC for entry in result.value.entries)

    async def test_live_checksum_lookup_returns_several_non_contiguous_entries(
        self, server: IBSServer
    ) -> None:
        result = await _live(server, "history_lookup_checksum_multiple")
        assert result.value is not None
        revisions = [entry.revision for entry in result.value.entries]
        assert revisions == [1, 2, 3, 4, 5, 6, 7, 9]

    @pytest.mark.parametrize(
        "name", ["history_lookup_unknown_revision", "history_lookup_unknown_checksum"]
    )
    async def test_live_lookup_without_entry_is_unavailable_history(
        self, server: IBSServer, name: str
    ) -> None:
        result = await _live(server, name)
        assert result == RequestEvidenceResult(incomplete_reason="history_unavailable")

    @pytest.mark.parametrize(
        "name", ["history_error_unknown_package", "history_error_unknown_project"]
    )
    async def test_live_404_is_incomplete(self, server: IBSServer, name: str) -> None:
        result = await _live(server, name)
        assert result == RequestEvidenceResult(incomplete_reason="not_found")


class TestRequest:
    async def test_unpaged_history_sends_no_parameter(self, server: IBSServer) -> None:
        await _read(server, _history(_revision()))
        assert _sent(server) == (_PATH, [])

    @pytest.mark.parametrize("revision", ["1", "42", _SUM_A])
    async def test_lookup_sends_only_rev(
        self, server: IBSServer, revision: str
    ) -> None:
        responder = _history(
            _revision(rev=revision if revision.isdigit() else "3", srcmd5=_SUM_A)
        )
        await _read(server, responder, revision)
        assert _sent(server) == (_PATH, [("rev", revision)])

    async def test_paging_parameters_are_never_sent(self, server: IBSServer) -> None:
        await _read(server, _history(_revision()))
        await _read(server, _history(_revision(rev="5")), "5")
        for request in server.requests:
            assert "limit" not in request.url.params
            assert "startbefore" not in request.url.params


class TestInputValidation:
    @pytest.mark.parametrize(
        ("project", "package", "revision"),
        [
            ("home:fictional", _PACKAGE, None),
            ("openSUSE:Factory", _PACKAGE, None),
            ("_redacted_", _PACKAGE, None),
            ("suse:lower", _PACKAGE, None),
            ("SUSE:a b", _PACKAGE, None),
            (_PROJECT, "", None),
            (_PROJECT, "a/b", None),
            (_PROJECT, "..", None),
            (_PROJECT, _PACKAGE, ""),
            (_PROJECT, _PACKAGE, "0"),
            (_PROJECT, _PACKAGE, "01"),
            (_PROJECT, _PACKAGE, "-1"),
            (_PROJECT, _PACKAGE, "1.0"),
            (_PROJECT, _PACKAGE, "A" * 32),
            (_PROJECT, _PACKAGE, "a" * 31),
            (_PROJECT, _PACKAGE, "latest"),
            (_PROJECT, _PACKAGE, 1),
        ],
    )
    async def test_invalid_input_raises_before_any_request(
        self, server: IBSServer, project: str, package: str, revision: Any
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(ValueError, match=r"\S"):
                await client.get_source_history(project, package, revision=revision)
        assert server.requests == []

    async def test_credentials_are_checked_after_input_and_before_http(
        self, server: IBSServer
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await client.get_source_history(_PROJECT, _PACKAGE)
        assert server.requests == []


class TestCompleteness:
    async def test_entry_fields(self, server: IBSServer) -> None:
        result = await _read(
            server,
            _history(
                _revision("1", _SUM_A, "0"),
                _revision("2", _SUM_B, "1700000000", "910001"),
            ),
        )
        assert result.value == SourceHistory(
            (
                SourceHistoryEntry(1, _SUM_A, datetime(1970, 1, 1, tzinfo=UTC), None),
                SourceHistoryEntry(
                    2, _SUM_B, datetime.fromtimestamp(1700000000, tz=UTC), 910001
                ),
            )
        )

    @pytest.mark.parametrize(
        "revisions",
        [
            [],
            ["2", "3"],
            ["1", "2", "4"],
            ["1", "3"],
        ],
        ids=["empty", "not_from_one", "gap", "gap_after_first"],
    )
    async def test_unpaged_history_that_is_not_complete_is_unavailable(
        self, server: IBSServer, revisions: list[str]
    ) -> None:
        result = await _read(server, _history(*(_revision(r) for r in revisions)))
        assert result == RequestEvidenceResult(incomplete_reason="history_unavailable")

    @pytest.mark.parametrize(
        ("revisions", "revision", "reason"),
        [
            (["1", "1"], None, "duplicate_identity"),
            (["2", "1"], None, "invalid_entry"),
            ([], "7", "history_unavailable"),
            (["8"], "7", "invalid_entry"),
            (["6", "7"], "7", "invalid_entry"),
            (["7", "7"], "7", "duplicate_identity"),
            ([], _SUM_A, "history_unavailable"),
            (["4", "3"], _SUM_A, "invalid_entry"),
            (["3", "3"], _SUM_A, "duplicate_identity"),
        ],
        ids=[
            "unpaged_duplicate",
            "unpaged_descending",
            "revision_empty",
            "revision_other",
            "revision_extra",
            "revision_duplicate",
            "checksum_empty",
            "checksum_descending",
            "checksum_duplicate",
        ],
    )
    async def test_inconsistent_lists_are_incomplete(
        self,
        server: IBSServer,
        revisions: list[str],
        revision: str | None,
        reason: IncompleteReason,
    ) -> None:
        result = await _read(
            server, _history(*(_revision(r) for r in revisions)), revision
        )
        assert result == RequestEvidenceResult(incomplete_reason=reason)

    async def test_checksum_lookup_entry_with_another_checksum_is_incomplete(
        self, server: IBSServer
    ) -> None:
        result = await _read(
            server,
            _history(_revision("3", _SUM_A), _revision("4", _SUM_B)),
            _SUM_A,
        )
        assert result == RequestEvidenceResult(incomplete_reason="invalid_entry")

    async def test_checksum_lookup_with_several_entries_is_complete(
        self, server: IBSServer
    ) -> None:
        result = await _read(
            server,
            _history(_revision("3", _SUM_A), _revision("9", _SUM_A)),
            _SUM_A,
        )
        assert result.value is not None
        assert [e.revision for e in result.value.entries] == [3, 9]

    @pytest.mark.parametrize(
        "entry",
        [
            '<revision vrev="1"><srcmd5>'
            + _SUM_A
            + "</srcmd5><time>1</time></revision>",
            _revision(rev="0"),
            _revision(rev="01"),
            _revision(rev="x"),
            _revision(rev=""),
            _revision(srcmd5=None),
            _revision(srcmd5="A" * 32),
            _revision(srcmd5="a" * 31),
            _revision(srcmd5=f" {_SUM_A}"),
            _revision(srcmd5=""),
            _revision(srcmd5="a" * 65),
            _revision(time=None),
            _revision(time="-1"),
            _revision(time="1.5"),
            _revision(time="01"),
            _revision(time=""),
            _revision(time="9" * 30),
            _revision(time="9" * 70),
            _revision(requestid=""),
            _revision(requestid="0"),
            _revision(requestid="x"),
            _revision(requestid="9" * 70),
            _revision(extra=f"<srcmd5>{_SUM_B}</srcmd5>"),
            _revision(extra="<time>2</time>"),
            _revision(extra="<requestid>1</requestid><requestid>2</requestid>"),
            f'<revision rev="1"><srcmd5><b>{_SUM_A}</b></srcmd5><time>1</time>'
            "</revision>",
            '<entry rev="1"/>',
        ],
        ids=[
            "missing_rev",
            "zero_rev",
            "leading_zero_rev",
            "non_numeric_rev",
            "empty_rev",
            "missing_srcmd5",
            "upper_case_srcmd5",
            "short_srcmd5",
            "whitespace_srcmd5",
            "empty_srcmd5",
            "long_srcmd5",
            "missing_time",
            "negative_time",
            "fractional_time",
            "leading_zero_time",
            "empty_time",
            "overflowing_time",
            "long_time",
            "empty_requestid",
            "zero_requestid",
            "non_numeric_requestid",
            "long_requestid",
            "repeated_srcmd5",
            "repeated_time",
            "repeated_requestid",
            "nested_element",
            "other_entry_element",
        ],
    )
    async def test_invalid_entry_is_incomplete(
        self, server: IBSServer, entry: str
    ) -> None:
        result = await _read(server, _history(entry))
        assert result == RequestEvidenceResult(incomplete_reason="invalid_entry")

    async def test_unconsumed_children_and_attributes_are_ignored(
        self, server: IBSServer
    ) -> None:
        noisy = _revision(
            requestid="910001",
            extra=(
                "<version>1.0</version><user>fictional-user</user>"
                f"<comment>{'free text ' * 50}<b>x</b></comment>"
            ),
        )
        result = await _read(server, _history(noisy))
        assert result.value == SourceHistory(
            (
                SourceHistoryEntry(
                    1, _SUM_A, datetime.fromtimestamp(1700000000, tz=UTC), 910001
                ),
            )
        )

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            ("<revisions/>", "invalid_document"),
            ("<collection matches='0'/>", "invalid_document"),
            ("<revisionlist><revision rev='1'>", "malformed_xml"),
        ],
    )
    async def test_document_shape(
        self, server: IBSServer, body: str, reason: IncompleteReason
    ) -> None:
        result = await _read(server, xml_response(body.encode()))
        assert result == RequestEvidenceResult(incomplete_reason=reason)


class TestHttpStatus:
    @pytest.mark.parametrize("status", [400, 403, 410, 429, 500])
    async def test_status_other_than_404_propagates(
        self, server: IBSServer, status: int
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _read(server, status_response(status, b"<status/>"))
        assert raised.value.response.status_code == status

    async def test_404_body_is_not_read(self, server: IBSServer) -> None:
        read: list[bool] = []

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                read.append(True)
                yield load_request_fixture("history_error_unknown_package")

        result = await _read(server, lambda _: httpx.Response(404, stream=Body()))
        assert result == RequestEvidenceResult(incomplete_reason="not_found")
        assert read == []
