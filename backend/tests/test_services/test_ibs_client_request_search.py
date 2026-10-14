"""Tests for `IBSClient.search_request_ids()`.

Contract under test: docs/features/integrations/ibs-integration.md (Request
ID Search; Service Layer > IBSClient, the search method and its escaping
outcomes); docs/features/packages/ibs-submission-tracking.md (Request
Discovery and Detail, search completeness). The live documents are the
sanitized captures of `tests/support/ibs_request_api.py`; every recorded
request is compared with the one the client builds.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any, Final

import httpx
import pytest

from app.core.enums import IBSRequestActionType, IBSRequestState
from app.services.ibs_client import (
    IBSCredentialsNotConfiguredError,
    IncompleteReason,
    RequestEvidenceResult,
    RequestIdSearchResult,
)
from tests.support.ibs_api import (
    IBSServer,
    Responder,
    ibs_client,
    status_response,
    xml_response,
)
from tests.support.ibs_request_api import (
    request_fixture_query,
    serve_request_fixture,
)

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_PATH: Final = "/search/request/id"
_INCIDENT: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
_RELEASE: Final = IBSRequestActionType.MAINTENANCE_RELEASE
_OPEN: Final = frozenset({IBSRequestState.NEW, IBSRequestState.REVIEW})


async def _search(
    server: IBSServer,
    responder: Responder | None = None,
    *args: Any,
    **kwargs: Any,
) -> RequestEvidenceResult[RequestIdSearchResult]:
    if responder is not None:
        server.route("GET", _PATH, responder)
    async with ibs_client() as client:
        return await client.search_request_ids(*args, **kwargs)


async def _open_sr(
    server: IBSServer, responder: Responder | None
) -> RequestEvidenceResult[RequestIdSearchResult]:
    return await _search(
        server, responder, _INCIDENT, states=_OPEN, source_package_prefix="curl."
    )


def _collection(body: str) -> Responder:
    return xml_response(body.encode())


def _match(server: IBSServer) -> str:
    [request] = [r for r in server.requests if "authorization" in r.headers]
    assert request.method == "GET"
    assert request.url.path == _PATH
    assert list(request.url.params.keys()) == ["match"]
    match: str = request.url.params["match"]
    return match


class TestLiveSearches:
    @pytest.mark.parametrize(
        ("name", "arguments", "expected"),
        [
            (
                "search_open_sr_source_prefix",
                {
                    "action_type": _INCIDENT,
                    "states": _OPEN,
                    "source_package_prefix": "openvpn.",
                },
                (910015,),
            ),
            (
                "search_open_rr_target_prefix",
                {
                    "action_type": _RELEASE,
                    "states": [IBSRequestState.REVIEW, IBSRequestState.NEW],
                    "target_package_prefix": "kernel-source.",
                },
                (910054, 910055),
            ),
            (
                "search_open_rr_empty",
                {
                    "action_type": _RELEASE,
                    "states": _OPEN,
                    "target_package_prefix": "openvpn.",
                },
                (),
            ),
            (
                "search_single_state",
                {
                    "action_type": _INCIDENT,
                    "states": {IBSRequestState.DECLINED},
                    "source_package_prefix": "openvpn.",
                },
                (910095,),
            ),
        ],
    )
    async def test_live_search_is_built_as_recorded_and_complete(
        self,
        server: IBSServer,
        name: str,
        arguments: dict[str, Any],
        expected: tuple[int, ...],
    ) -> None:
        serve_request_fixture(server, name)
        result = await _search(server, None, **arguments)

        assert result == RequestEvidenceResult(
            value=RequestIdSearchResult(request_numbers=expected, matches=len(expected))
        )
        [(_, recorded)] = request_fixture_query(name)
        assert _match(server) == recorded

    async def test_live_search_without_states_returns_sorted_distinct_numbers(
        self, server: IBSServer
    ) -> None:
        serve_request_fixture(server, "search_all_states")
        result = await _search(
            server, None, _INCIDENT, source_package_prefix="openvpn."
        )

        assert result.value is not None
        numbers = result.value.request_numbers
        assert result.value.matches == len(numbers) == 47
        assert list(numbers) == sorted(set(numbers))
        [(_, recorded)] = request_fixture_query("search_all_states")
        assert _match(server) == recorded

    async def test_live_rejected_predicate_is_incomplete(
        self, server: IBSServer
    ) -> None:
        serve_request_fixture(server, "search_error_releaseproject")
        result = await _open_sr(server, None)
        assert result == RequestEvidenceResult(incomplete_reason="rejected")


class TestPredicate:
    @pytest.mark.parametrize(
        ("states", "suffix"),
        [
            (None, ""),
            ([IBSRequestState.ACCEPTED], " and (state/@name='accepted')"),
            (
                [IBSRequestState.REVIEW, IBSRequestState.NEW, IBSRequestState.NEW],
                " and (state/@name='new' or state/@name='review')",
            ),
            (
                list(IBSRequestState),
                " and (state/@name='new' or state/@name='review' or "
                "state/@name='accepted' or state/@name='declined' or "
                "state/@name='revoked' or state/@name='superseded' or "
                "state/@name='deleted')",
            ),
        ],
        ids=["none", "single", "deduplicated_and_ordered", "all"],
    )
    async def test_states_are_combined_with_the_same_action_predicate(
        self,
        server: IBSServer,
        states: Collection[IBSRequestState] | None,
        suffix: str,
    ) -> None:
        await _search(
            server,
            _collection('<collection matches="0"/>'),
            _RELEASE,
            states=states,
            target_package_prefix="glibc.",
        )
        assert _match(server) == (
            "action[@type='maintenance_release' and "
            "starts-with(target/@package,'glibc.')]" + suffix
        )

    @pytest.mark.parametrize(
        ("action_type", "keyword", "field"),
        [
            (_INCIDENT, "source_package_prefix", "source/@package"),
            (_RELEASE, "target_package_prefix", "target/@package"),
        ],
    )
    @pytest.mark.parametrize(
        "states",
        [
            None,
            [IBSRequestState.NEW],
            [IBSRequestState.REVIEW],
            [IBSRequestState.NEW, IBSRequestState.REVIEW],
        ],
        ids=["none", "new", "review", "open"],
    )
    async def test_release_project_is_never_part_of_the_predicate(
        self,
        server: IBSServer,
        action_type: IBSRequestActionType,
        keyword: str,
        field: str,
        states: Collection[IBSRequestState] | None,
    ) -> None:
        await _search(
            server,
            _collection('<collection matches="0"/>'),
            action_type,
            states=states,
            **{keyword: "go1.27."},
        )
        match = _match(server)
        assert "releaseproject" not in match
        assert match.startswith(
            f"action[@type='{action_type.value}' and starts-with({field},'go1.27.')]"
        )

    async def test_plus_is_percent_encoded_in_the_query(
        self, server: IBSServer
    ) -> None:
        await _search(
            server,
            _collection('<collection matches="0"/>'),
            _INCIDENT,
            source_package_prefix="libstdc++6.",
        )
        [request] = [r for r in server.requests if "authorization" in r.headers]
        assert b"libstdc%2B%2B6." in request.url.raw_path
        assert "libstdc++6." in _match(server)


class TestInputValidation:
    @pytest.mark.parametrize(
        ("args", "kwargs"),
        [
            (("maintenance_incident",), {"source_package_prefix": "curl."}),
            ((None,), {"source_package_prefix": "curl."}),
            ((IBSRequestState.NEW,), {"source_package_prefix": "curl."}),
            ((_INCIDENT,), {"states": [], "source_package_prefix": "curl."}),
            ((_INCIDENT,), {"states": set(), "source_package_prefix": "curl."}),
            ((_INCIDENT,), {"states": "new", "source_package_prefix": "curl."}),
            (
                (_INCIDENT,),
                {"states": IBSRequestState.NEW, "source_package_prefix": "curl."},
            ),
            ((_INCIDENT,), {"states": ["new"], "source_package_prefix": "curl."}),
            ((_INCIDENT,), {"states": [None], "source_package_prefix": "curl."}),
            ((_INCIDENT,), {}),
            (
                (_INCIDENT,),
                {"source_package_prefix": "curl.", "target_package_prefix": "curl."},
            ),
            ((_RELEASE,), {"source_package_prefix": "curl."}),
            ((_INCIDENT,), {"target_package_prefix": "curl."}),
            ((_INCIDENT,), {"source_package_prefix": ""}),
            ((_INCIDENT,), {"source_package_prefix": "curl'."}),
            ((_INCIDENT,), {"source_package_prefix": "curl)."}),
            ((_INCIDENT,), {"source_package_prefix": "curl ."}),
            ((_INCIDENT,), {"source_package_prefix": "cu/rl."}),
            ((_RELEASE,), {"target_package_prefix": "curl]."}),
            ((_RELEASE,), {"target_package_prefix": "é."}),
            ((_RELEASE,), {"target_package_prefix": ".."}),
        ],
        ids=[
            "type_plain_string",
            "type_none",
            "type_other_enum",
            "states_empty_list",
            "states_empty_set",
            "states_string",
            "states_single_member",
            "states_plain_strings",
            "states_none_member",
            "no_prefix",
            "both_prefixes",
            "source_prefix_with_release",
            "target_prefix_with_incident",
            "empty_prefix",
            "quote",
            "parenthesis",
            "space",
            "slash",
            "bracket",
            "non_ascii",
            "dot_segment",
        ],
    )
    async def test_invalid_input_raises_before_any_request_and_credentials(
        self, server: IBSServer, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(ValueError, match=r"\S") as raised:
                await client.search_request_ids(*args, **kwargs)
        assert server.requests == []
        for key in ("source_package_prefix", "target_package_prefix"):
            prefix = kwargs.get(key)
            if prefix:
                assert prefix not in str(raised.value)

    async def test_credentials_are_checked_after_input_and_before_http(
        self, server: IBSServer
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await client.search_request_ids(
                    _INCIDENT, states=_OPEN, source_package_prefix="curl."
                )
        assert server.requests == []


class TestCompleteness:
    async def test_numbers_are_sorted_whatever_the_upstream_order(
        self, server: IBSServer
    ) -> None:
        result = await _open_sr(
            server,
            _collection(
                '<collection matches="3"><request id="30"/><request id="4"/>'
                '<request id="200"/></collection>'
            ),
        )
        assert result.value == RequestIdSearchResult((4, 30, 200), 3)

    async def test_unconsumed_attributes_and_children_are_ignored(
        self, server: IBSServer
    ) -> None:
        result = await _open_sr(
            server,
            _collection(
                '<collection matches="1" extra="x"><request id="7" creator="x">'
                "<description>free text</description></request></collection>"
            ),
        )
        assert result.value == RequestIdSearchResult((7,), 1)

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            (
                '<collection matches="3"><request id="1"/><request id="2"/>'
                "</collection>",
                "count_mismatch",
            ),
            ('<collection matches="1"/>', "count_mismatch"),
            (
                '<collection matches="0"><request id="1"/></collection>',
                "count_mismatch",
            ),
            (
                '<collection matches="2"><request id="5"/><request id="5"/>'
                "</collection>",
                "duplicate_identity",
            ),
            ('<collection matches="1"><request/></collection>', "invalid_entry"),
            ('<collection matches="1"><request id=""/></collection>', "invalid_entry"),
            ('<collection matches="1"><request id="0"/></collection>', "invalid_entry"),
            (
                '<collection matches="1"><request id="-4"/></collection>',
                "invalid_entry",
            ),
            (
                '<collection matches="1"><request id="04"/></collection>',
                "invalid_entry",
            ),
            (
                '<collection matches="1"><request id="4.0"/></collection>',
                "invalid_entry",
            ),
            (
                '<collection matches="1"><request id="\u0664"/></collection>',
                "invalid_entry",
            ),
            (
                '<collection matches="1"><request id="' + "9" * 5000 + '"/>'
                "</collection>",
                "invalid_entry",
            ),
            ('<collection matches="1"><other id="1"/></collection>', "invalid_entry"),
            ("<collection/>", "invalid_document"),
            ('<collection matches=""/>', "invalid_document"),
            ('<collection matches="-1"/>', "invalid_document"),
            ('<collection matches="one"/>', "invalid_document"),
            ('<requests matches="0"/>', "invalid_document"),
            ("<collection matches=\"1\"><request id='1'/>", "malformed_xml"),
        ],
        ids=[
            "fewer_entries",
            "no_entries",
            "more_entries",
            "duplicate_ids",
            "missing_id",
            "empty_id",
            "zero_id",
            "negative_id",
            "leading_zero",
            "decimal_point",
            "non_ascii_digit",
            "huge_id",
            "other_child",
            "missing_matches",
            "empty_matches",
            "negative_matches",
            "non_numeric_matches",
            "wrong_root",
            "truncated",
        ],
    )
    async def test_unusable_response_is_incomplete_never_negative(
        self, server: IBSServer, body: str, reason: IncompleteReason
    ) -> None:
        result = await _open_sr(server, _collection(body))
        assert result == RequestEvidenceResult(incomplete_reason=reason)


class _UnreadBody(httpx.AsyncByteStream):
    """A body that records whether anything read it."""

    def __init__(self) -> None:
        self.read = False

    async def __aiter__(self) -> Any:
        self.read = True
        yield b'<status code="fictional"/>'

    async def aclose(self) -> None:
        return None


class TestHttpStatus:
    @pytest.mark.parametrize(
        ("status", "reason"),
        [
            (400, "rejected"),
            (404, "not_found"),
            (405, "rejected"),
            (409, "rejected"),
            (410, "rejected"),
            (422, "rejected"),
            (429, "rejected"),
        ],
    )
    async def test_client_error_other_than_401_and_403_is_incomplete(
        self, server: IBSServer, status: int, reason: IncompleteReason
    ) -> None:
        body = _UnreadBody()
        result = await _open_sr(server, lambda _: httpx.Response(status, stream=body))
        assert result == RequestEvidenceResult(incomplete_reason=reason)
        assert body.read is False

    @pytest.mark.parametrize("status", [403, 302, 500])
    async def test_other_status_propagates_as_http_error(
        self, server: IBSServer, status: int
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _open_sr(server, status_response(status, b"<status/>"))
        assert raised.value.response.status_code == status

    async def test_rate_limit_is_retried_once_when_guided_then_incomplete(
        self, server: IBSServer
    ) -> None:
        server.route(
            "GET",
            _PATH,
            lambda _: httpx.Response(429, headers={"retry-after": "1"}),
        )
        result = await _open_sr(server, None)
        assert result == RequestEvidenceResult(incomplete_reason="rejected")
        assert len([r for r in server.requests if r.url.path == _PATH]) == 3
