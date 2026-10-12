"""Tests for `IBSClient` (backend/app/services/ibs_client.py).

Contract under test: docs/features/integrations/ibs-integration.md
(Origins and Authentication, Request Authentication, Session Reuse,
Project Source Info, Source Diff with Issue Extraction, Service Layer >
IBSClient, Security); docs/features/packages/ibs-track-release-detection.md
(Source-Info Validation, Source-Diff Validation, XML and Response Safety);
docs/features/platform/networking.md (Transport-Level Retry, Method Safety,
Redirect Policy); docs/conventions.md (External String Admissibility).

Every client is a real `create_http_client` client: only the network
transport is replaced by the fake IBS API of `tests/support/ibs_api.py`,
so the shared retry transport, the authentication flow, and the cookie jar
are the production ones. Retry backoff sleeps are recorded, not awaited.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr

from app.config import settings
from app.services import http_client
from app.services import ibs_client as ibs_client_module
from app.services.ibs_client import (
    DiffIssue,
    IBSAuthenticationError,
    IBSClient,
    IBSCredentialsNotConfiguredError,
    IBSResponseDataError,
    SourceInfo,
    SourceInfoResult,
)
from tests.support.ibs_api import (
    LIVE_CHALLENGE,
    LIVE_PROJECT,
    LIVE_REALM,
    SESSION_COOKIE_NAME,
    TEST_API_URL,
    IBSServer,
    Responder,
    chunked_response,
    fixture_query,
    load_fixture,
    status_response,
    verify_signature_header,
    xml_response,
)
from tests.support.ibs_keys import fictional_ed25519_key, fictional_settings_value

pytestmark = pytest.mark.unit

_CLOCK: Final = 1700000000.75
_PROJECT_PATH: Final = f"/source/{LIVE_PROJECT}"
_OLD: Final = "746089c90539b6ff4a924ce513b6b800"
_NEW: Final = "de84bf76520480292946d884daf7308a"
_SUDO: Final = "f6cf5398175f44ce4265e2381f6309b2"


def _diff_path(package: str = "pkg") -> str:
    return f"{_PROJECT_PATH}/{package}"


@pytest.fixture
def sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    recorded = AsyncMock()
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=recorded))
    return recorded


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, sleep: AsyncMock) -> IBSServer:
    """The fake IBS API behind every client the test creates."""
    fake = IBSServer(public_key=fictional_ed25519_key().public_key())
    for variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: fake.transport())
    return fake


def _client(
    *,
    username: str = "jdoe",
    key: str | None = None,
    clock: Callable[[], float] = lambda: _CLOCK,
) -> IBSClient:
    return IBSClient(
        api_url=TEST_API_URL,
        username=username,
        ssh_private_key=SecretStr(fictional_settings_value() if key is None else key),
        clock=clock,
    )


def _signed(server: IBSServer) -> list[httpx.Request]:
    return [r for r in server.requests if "authorization" in r.headers]


def _document(body: str) -> Responder:
    return xml_response(body.encode())


def _sourceinfo(*entries: str) -> Responder:
    return _document(f"<sourceinfolist>{''.join(entries)}</sourceinfolist>")


def _entry(package: str, srcmd5: str = "0" * 32, inner: str = "") -> str:
    return f'<sourceinfo package="{package}" srcmd5="{srcmd5}">{inner}</sourceinfo>'


def _sourcediff(issues: str) -> Responder:
    return _document(
        '<sourcediff key="0"><old/><new/><files/>'
        f"<issues>{issues}</issues></sourcediff>"
    )


def _issue(**attributes: str) -> str:
    rendered = " ".join(f'{name}="{value}"' for name, value in attributes.items())
    return f"<issue {rendered}/>"


async def _source_info(
    server: IBSServer,
    responder: Responder,
    packages: list[str],
) -> dict[str, SourceInfoResult]:
    server.route("GET", _PROJECT_PATH, responder)
    async with _client() as client:
        return dict(await client.get_source_info(LIVE_PROJECT, packages))


async def _diff(
    server: IBSServer,
    responder: Responder,
    old: str = _OLD,
    new: str = _NEW,
) -> list[DiffIssue]:
    server.route("POST", _diff_path(), responder)
    async with _client() as client:
        return await client.get_diff_issues(LIVE_PROJECT, "pkg", old, new)


# ---------------------------------------------------------------------------
# Construction, configuration, and credentials
# ---------------------------------------------------------------------------


class TestConstructionAndCredentials:
    @pytest.mark.parametrize(
        ("username", "key"),
        [("", "configured"), ("jdoe", ""), ("", "")],
        ids=["username_empty", "key_empty", "both_empty"],
    )
    async def test_operations_without_credentials_raise_before_any_request(
        self, server: IBSServer, username: str, key: str
    ) -> None:
        encoded = fictional_settings_value() if key else ""
        client = _client(username=username, key=encoded)
        try:
            with pytest.raises(IBSCredentialsNotConfiguredError) as raised:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
            assert str(raised.value) == "IBS API credentials are not configured"
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await client.get_diff_issues(LIVE_PROJECT, "openssh", "0", _NEW)
        finally:
            await client.aclose()
        assert server.requests == []

    async def test_input_validation_precedes_the_credential_check(
        self, server: IBSServer
    ) -> None:
        async with _client(username="") as client:
            with pytest.raises(ValueError, match="packages must not be empty"):
                await client.get_source_info(LIVE_PROJECT, [])
            with pytest.raises(ValueError, match="old_md5"):
                await client.get_diff_issues(LIVE_PROJECT, "pkg", "1", _NEW)
        assert server.requests == []

    def test_construction_reads_the_application_settings(
        self, monkeypatch: pytest.MonkeyPatch, server: IBSServer
    ) -> None:
        monkeypatch.setattr(settings, "ibs_api_url", TEST_API_URL)
        monkeypatch.setattr(settings, "ibs_username", "jdoe")
        monkeypatch.setattr(
            settings, "ibs_ssh_private_key", SecretStr(fictional_settings_value())
        )
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )

        async def run() -> None:
            async with IBSClient() as client:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])

        asyncio.run(run())
        [signed] = _signed(server)
        assert str(signed.url).startswith(f"{TEST_API_URL}/source/")
        verified = verify_signature_header(
            signed.headers["authorization"],
            public_key=fictional_ed25519_key().public_key(),
            realm=LIVE_REALM,
        )
        assert verified.key_id == "jdoe"

    def test_construction_with_unset_settings_credentials_succeeds(
        self, monkeypatch: pytest.MonkeyPatch, server: IBSServer
    ) -> None:
        monkeypatch.setattr(settings, "ibs_username", "")
        monkeypatch.setattr(settings, "ibs_ssh_private_key", SecretStr(""))

        async def run() -> None:
            async with IBSClient(api_url=TEST_API_URL) as client:
                with pytest.raises(IBSCredentialsNotConfiguredError):
                    await client.get_source_info(LIVE_PROJECT, ["openssh"])

        asyncio.run(run())
        assert server.requests == []

    @pytest.mark.parametrize("username", ['jdoe"', "j doe", "jdoe\\"])
    def test_inadmissible_username_override_is_rejected(self, username: str) -> None:
        with pytest.raises(ValueError, match="Invalid IBS_USERNAME"):
            IBSClient(api_url=TEST_API_URL, username=username)

    def test_invalid_key_override_is_rejected_without_detail(self) -> None:
        with pytest.raises(ValueError, match="Invalid IBS_SSH_PRIVATE_KEY") as raised:
            IBSClient(
                api_url=TEST_API_URL, username="jdoe", ssh_private_key=SecretStr("x")
            )
        assert str(raised.value).startswith("Invalid IBS_SSH_PRIVATE_KEY:")
        assert raised.value.__context__ is None

    async def test_requests_use_the_shared_factory_defaults(
        self, server: IBSServer
    ) -> None:
        await _source_info(
            server, xml_response(load_fixture("sourceinfo_single_linked")), ["openssh"]
        )
        for request in server.requests:
            assert request.headers["accept"] == "application/xml"
            assert request.headers["user-agent"].startswith("Sentinel/")
            assert (
                "(ibs_client; +https://github.com/StayPirate/sentinel)"
                in (request.headers["user-agent"])
            )
            assert request.url.host == "api.ibs.example.test"
            assert request.url.scheme == "https"


# ---------------------------------------------------------------------------
# Request authentication and session reuse
# ---------------------------------------------------------------------------


class TestRequestAuthentication:
    async def test_first_request_is_unsigned_then_signed_once(
        self, server: IBSServer
    ) -> None:
        server.realm = "Fictional realm from the challenge"
        server.challenges = [
            'Basic realm="ignored", Signature realm="Fictional realm from the '
            'challenge",headers="(created)"'
        ]
        await _source_info(
            server, xml_response(load_fixture("sourceinfo_single_linked")), ["openssh"]
        )

        unsigned, signed = server.requests
        assert "authorization" not in unsigned.headers
        assert "cookie" not in unsigned.headers
        assert "cookie" not in signed.headers
        assert unsigned.url == signed.url
        assert signed.method == unsigned.method == "GET"
        [verified] = server.signatures
        assert verified.key_id == "jdoe"
        assert verified.created == 1700000000
        assert signed.headers["authorization"].startswith(
            'Signature keyId="jdoe",algorithm="ssh",headers="(created)",'
            'created=1700000000,signature="'
        )

    async def test_session_cookie_is_reused_within_the_client(
        self, server: IBSServer
    ) -> None:
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        server.route(
            "POST", _diff_path("sudo"), xml_response(load_fixture("diff_empty"))
        )
        async with _client() as client:
            await client.get_source_info(LIVE_PROJECT, ["openssh"])
            await client.get_diff_issues(LIVE_PROJECT, "sudo", _SUDO, _SUDO)

        assert len(server.requests) == 3
        reused = server.requests[2]
        assert reused.method == "POST"
        assert "authorization" not in reused.headers
        assert (
            reused.headers["cookie"] == f"{SESSION_COOKIE_NAME}=fictional-session-0001"
        )
        assert len(server.signatures) == 1

    async def test_rejected_session_is_discarded_and_answered_with_one_signature(
        self, server: IBSServer
    ) -> None:
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        async with _client() as client:
            await client.get_source_info(LIVE_PROJECT, ["openssh"])
            server.expire_sessions()
            await client.get_source_info(LIVE_PROJECT, ["openssh"])
            await client.get_source_info(LIVE_PROJECT, ["openssh"])

        stale, resigned, reused = server.requests[2:]
        assert (
            stale.headers["cookie"] == f"{SESSION_COOKIE_NAME}=fictional-session-0001"
        )
        assert "authorization" not in stale.headers
        assert "cookie" not in resigned.headers
        assert "authorization" in resigned.headers
        assert (
            reused.headers["cookie"] == f"{SESSION_COOKIE_NAME}=fictional-session-0002"
        )
        assert len(server.requests) == 5

    async def test_clients_do_not_share_sessions(self, server: IBSServer) -> None:
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        for _ in range(2):
            async with _client() as client:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
        assert len(server.signatures) == 2
        assert all("cookie" not in r.headers for r in server.requests)

    async def test_session_is_not_required_for_correctness(
        self, server: IBSServer
    ) -> None:
        server.issue_session = False
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        async with _client() as client:
            for _ in range(2):
                result = await client.get_source_info(LIVE_PROJECT, ["openssh"])
                assert result["openssh"].source_info is not None
        assert len(server.requests) == 4
        assert len(server.signatures) == 2

    async def test_rejected_signature_raises_after_one_signed_attempt(
        self, server: IBSServer
    ) -> None:
        server.reject_signatures = True
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        async with _client() as client:
            with pytest.raises(IBSAuthenticationError) as raised:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
            assert raised.value.reason == "signature_rejected"
            assert len(client._http.cookies) == 0
        assert len(server.requests) == 2
        assert len(_signed(server)) == 1
        assert "jdoe" not in str(raised.value)
        assert LIVE_REALM not in str(raised.value)

    @pytest.mark.parametrize(
        "challenges",
        [[], ['Basic realm="fictional"'], [LIVE_CHALLENGE, LIVE_CHALLENGE]],
        ids=["none", "basic_only", "two_signature"],
    )
    async def test_unsupported_challenge_raises_without_further_request(
        self, server: IBSServer, challenges: list[str]
    ) -> None:
        server.challenges = challenges
        server.route("POST", _diff_path(), xml_response(load_fixture("diff_empty")))
        async with _client() as client:
            with pytest.raises(IBSAuthenticationError) as raised:
                await client.get_diff_issues(LIVE_PROJECT, "pkg", "0", _NEW)
        assert raised.value.reason == "unsupported_challenge"
        assert len(server.requests) == 1
        assert _signed(server) == []

    async def test_basic_is_never_answered(self, server: IBSServer) -> None:
        server.challenges = ['Basic realm="fictional"']
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        with pytest.raises(IBSAuthenticationError):
            await _source_info(server, xml_response(b""), ["openssh"])
        assert all("authorization" not in r.headers for r in server.requests)

    @pytest.mark.parametrize("status", [403, 404, 400])
    async def test_non_401_error_is_never_answered_with_a_signature(
        self, server: IBSServer, status: int
    ) -> None:
        server.intercept = lambda _: httpx.Response(status)
        async with _client() as client:
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
        assert raised.value.response.status_code == status
        assert len(server.requests) == 1
        assert _signed(server) == []

    async def test_transport_retry_resends_the_same_signature(
        self, server: IBSServer, sleep: AsyncMock
    ) -> None:
        failures = iter([True])

        def flaky(request: httpx.Request) -> httpx.Response | None:
            if "authorization" in request.headers and next(failures, False):
                return httpx.Response(503)
            return None

        server.intercept = flaky
        server.route("POST", _diff_path(), xml_response(load_fixture("diff_deleted")))
        issues = await _diff(server, xml_response(load_fixture("diff_deleted")))

        assert len(issues) == 2
        unsigned, first, retried = server.requests
        assert "authorization" not in unsigned.headers
        assert first.headers["authorization"] == retried.headers["authorization"]
        assert len(server.signatures) == 1
        sleep.assert_awaited_once_with(1.0)

    async def test_read_only_post_is_retried_on_connection_error(
        self, server: IBSServer, sleep: AsyncMock
    ) -> None:
        attempts: list[int] = []

        def drop_first(request: httpx.Request) -> httpx.Response | None:
            attempts.append(1)
            if len(attempts) == 1:
                raise httpx.ConnectError(
                    "fictional connection failure", request=request
                )
            return None

        server.intercept = drop_first
        issues = await _diff(server, xml_response(load_fixture("diff_deleted")))
        assert len(issues) == 2
        assert [r.method for r in server.requests] == ["POST"] * 3
        sleep.assert_awaited_once_with(1.0)

    async def test_redirect_is_not_followed(self, server: IBSServer) -> None:
        server.intercept = lambda _: httpx.Response(
            302, headers={"location": "https://elsewhere.example.test/source"}
        )
        async with _client() as client:
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
        assert raised.value.response.status_code == 302
        assert [r.url.host for r in server.requests] == ["api.ibs.example.test"]

    async def test_no_credential_material_in_logs_or_exceptions(
        self, server: IBSServer, caplog: pytest.LogCaptureFixture
    ) -> None:
        key = fictional_settings_value()
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        server.route("POST", _diff_path(), _document("<sourcediff><bad/>"))
        with caplog.at_level(logging.DEBUG):
            async with _client(key=key) as client:
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
                with pytest.raises(IBSResponseDataError) as raised:
                    await client.get_diff_issues(LIVE_PROJECT, "pkg", "0", _NEW)
                server.reject_signatures = True
                server.expire_sessions()
                with pytest.raises(IBSAuthenticationError) as rejected:
                    await client.get_source_info(LIVE_PROJECT, ["openssh"])

        signature = _signed(server)[0].headers["authorization"].split('signature="')[1]
        rendered = "\n".join(
            [caplog.text, repr(raised.value), str(raised.value), repr(rejected.value)]
        )
        for secret in (
            key[:24],
            signature[:24],
            "fictional-session",
            LIVE_REALM,
            "jdoe",
        ):
            assert secret not in rendered


# ---------------------------------------------------------------------------
# Targeted source info
# ---------------------------------------------------------------------------


class TestSourceInfo:
    async def test_live_single_linked_package(self, server: IBSServer) -> None:
        results = await _source_info(
            server, xml_response(load_fixture("sourceinfo_single_linked")), ["openssh"]
        )
        assert results == {
            "openssh": SourceInfoResult(
                source_info=SourceInfo("openssh", "ab2ccc8c1ee7376c2a639ee600caa123")
            )
        }

    async def test_live_multiple_packages_with_error_entry_and_absent_package(
        self, server: IBSServer
    ) -> None:
        results = await _source_info(
            server,
            xml_response(load_fixture("sourceinfo_multiple")),
            ["openssh", "libxml2", "sentinel-nonexistent-pkg", "absent-package"],
        )
        assert results == {
            "openssh": SourceInfoResult(
                source_info=SourceInfo("openssh", "ab2ccc8c1ee7376c2a639ee600caa123")
            ),
            "libxml2": SourceInfoResult(
                source_info=SourceInfo("libxml2", "de84bf76520480292946d884daf7308a")
            ),
            "sentinel-nonexistent-pkg": SourceInfoResult(failure="upstream_error"),
            "absent-package": SourceInfoResult(failure="missing"),
        }

    async def test_request_is_one_targeted_get_with_repeatable_packages(
        self, server: IBSServer
    ) -> None:
        await _source_info(
            server,
            xml_response(load_fixture("sourceinfo_multiple")),
            ["openssh", "libxml2", "openssh", "sentinel-nonexistent-pkg"],
        )
        expected = fixture_query("sourceinfo_multiple")
        for request in server.requests:
            assert request.method == "GET"
            assert request.url.path == _PROJECT_PATH
            assert request.url.raw_path.startswith(b"/source/SUSE:SLE-15-SP6:Update?")
            assert list(request.url.params.multi_items()) == expected
        assert len(server.requests) == 2

    @pytest.mark.parametrize(
        ("entries", "expected"),
        [
            ((_entry("a"), _entry("a")), "duplicate"),
            ((_entry("a", inner="<error>fictional</error>"),), "upstream_error"),
            ((_entry("a", srcmd5="0" * 31),), "invalid_srcmd5"),
            ((_entry("a", srcmd5="0" * 33),), "invalid_srcmd5"),
            ((_entry("a", srcmd5="g" * 32),), "invalid_srcmd5"),
            ((_entry("a", srcmd5=""),), "invalid_srcmd5"),
            (('<sourceinfo package="a"/>',), "invalid_srcmd5"),
            ((_entry("b"),), "missing"),
        ],
        ids=[
            "duplicate",
            "error_with_checksum",
            "short_checksum",
            "long_checksum",
            "non_hex_checksum",
            "empty_checksum",
            "no_checksum",
            "missing",
        ],
    )
    async def test_unusable_package_fails_alone_and_siblings_stay_usable(
        self, server: IBSServer, entries: tuple[str, ...], expected: str
    ) -> None:
        results = await _source_info(
            server, _sourceinfo(*entries, _entry("ok", srcmd5="A" * 32)), ["a", "ok"]
        )
        assert results["a"] == SourceInfoResult(failure=expected)  # type: ignore[arg-type]
        assert results["ok"] == SourceInfoResult(source_info=SourceInfo("ok", "A" * 32))

    async def test_unrequested_entries_are_ignored(self, server: IBSServer) -> None:
        results = await _source_info(
            server,
            _sourceinfo(
                _entry("other", srcmd5="bad"),
                _entry("other"),
                _entry("a"),
                _entry("third", inner="<error>x</error>"),
            ),
            ["a"],
        )
        assert results == {"a": SourceInfoResult(source_info=SourceInfo("a", "0" * 32))}

    async def test_unconsumed_elements_and_attributes_are_ignored(
        self, server: IBSServer
    ) -> None:
        results = await _source_info(
            server,
            _document(
                '<sourceinfolist extra="1"><unknown><sourceinfo package="a"/></unknown>'
                + _entry(
                    "a",
                    inner='<filename>x</filename><linked project="p"/>'
                    "<originproject>p</originproject><deep><error/></deep>",
                )
                + "</sourceinfolist>"
            ),
            ["a"],
        )
        assert results["a"].source_info == SourceInfo("a", "0" * 32)

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            ("<sourceinfo/>", "invalid_document"),
            ("<directory/>", "invalid_document"),
            ('<ns:sourceinfolist xmlns:ns="urn:x"/>', "invalid_document"),
            (
                "<sourceinfolist><sourceinfo srcmd5='x'/></sourceinfolist>",
                "invalid_document",
            ),
            (
                '<sourceinfolist><sourceinfo package=""/></sourceinfolist>',
                "invalid_document",
            ),
            ("<sourceinfolist>", "malformed_xml"),
            ("", "malformed_xml"),
            ("<sourceinfolist></sourceinfo>", "malformed_xml"),
            ("<sourceinfolist/><second/>", "malformed_xml"),
        ],
        ids=[
            "wrong_root",
            "directory_root",
            "namespaced_root",
            "entry_without_package",
            "entry_with_empty_package",
            "truncated",
            "empty_body",
            "mismatched_tag",
            "two_roots",
        ],
    )
    async def test_unusable_document_fails_the_whole_call(
        self, server: IBSServer, body: str, reason: str
    ) -> None:
        with pytest.raises(IBSResponseDataError) as raised:
            await _source_info(server, _document(body), ["a"])
        assert raised.value.reason == reason

    async def test_interrupted_body_fails_the_whole_call(
        self, server: IBSServer
    ) -> None:
        document = load_fixture("sourceinfo_multiple")
        with pytest.raises(IBSResponseDataError) as raised:
            await _source_info(
                server,
                chunked_response([document[:100], document[100:]], fail_after=True),
                ["openssh"],
            )
        assert raised.value.reason == "interrupted_response"

    @pytest.mark.parametrize(
        "packages",
        [
            [],
            (),
            set(),
            "openssh",
            ["openssh", ""],
            ["a/b"],
            ["."],
            [".."],
            ["a b"],
            ["a\x00"],
        ],
        ids=[
            "empty_list",
            "empty_tuple",
            "empty_set",
            "bare_string",
            "empty_name",
            "slash",
            "dot",
            "dot_dot",
            "space",
            "nul",
        ],
    )
    async def test_invalid_packages_raise_before_http(
        self, server: IBSServer, packages: Any
    ) -> None:
        async with _client() as client:
            with pytest.raises(ValueError, match="package"):
                await client.get_source_info(LIVE_PROJECT, packages)
        assert server.requests == []

    @pytest.mark.parametrize("project", ["", "a/b", "..", "a b", "caf\u00e9"])
    async def test_invalid_project_raises_before_http(
        self, server: IBSServer, project: str
    ) -> None:
        async with _client() as client:
            with pytest.raises(ValueError, match="invalid IBS project name"):
                await client.get_source_info(project, ["a"])
        assert server.requests == []


class TestResultRecords:
    @pytest.mark.parametrize(
        "arguments",
        [{}, {"source_info": SourceInfo("a", "0" * 32), "failure": "missing"}],
        ids=["neither", "both"],
    )
    def test_source_info_result_holds_exactly_one_outcome(
        self, arguments: dict[str, Any]
    ) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            SourceInfoResult(**arguments)


class TestPathEncoding:
    async def test_project_and_package_are_single_encoded_path_segments(
        self, server: IBSServer
    ) -> None:
        server.route("POST", "/source/home:j%x+y/lib?c++", _sourcediff(""))
        async with _client() as client:
            assert (
                await client.get_diff_issues("home:j%x+y", "lib?c++", "0", _NEW) == []
            )
        request = server.requests[-1]
        assert request.url.raw_path.split(b"?")[0] == b"/source/home:j%25x+y/lib%3Fc++"
        assert request.url.params["rev"] == _NEW


# ---------------------------------------------------------------------------
# Expanded source diff
# ---------------------------------------------------------------------------


class TestSourceDiff:
    async def test_live_first_observation_from_the_empty_tree(
        self, server: IBSServer
    ) -> None:
        server.route(
            "POST",
            _diff_path("sudo"),
            xml_response(load_fixture("diff_first_observation")),
        )
        async with _client() as client:
            issues = await client.get_diff_issues(LIVE_PROJECT, "sudo", "0", _SUDO)

        assert [r.url.params.multi_items() for r in server.requests][-1] == (
            fixture_query("diff_first_observation")
        )
        assert {issue.state for issue in issues} == {"added"}
        trackers = {issue.tracker for issue in issues}
        assert trackers == {"cve", "bnc", "fate", "jsc"}
        cves = [i for i in issues if i.tracker == "cve"]
        assert len(cves) == 27
        assert all(i.label == f"CVE-{i.name}" for i in cves)
        bnc = next(i for i in issues if i.tracker == "bnc")
        assert bnc.label is not None
        assert bnc.label.startswith("bsc#")

    async def test_live_added_and_changed(self, server: IBSServer) -> None:
        server.route(
            "POST",
            _diff_path("libxml2"),
            xml_response(load_fixture("diff_added_changed")),
        )
        async with _client() as client:
            issues = await client.get_diff_issues(LIVE_PROJECT, "libxml2", _OLD, _NEW)
        assert issues[:3] == [
            DiffIssue("cve", "changed", "2026-0989", "CVE-2026-0989"),
            DiffIssue("bnc", "changed", "1256805", "bsc#1256805"),
            DiffIssue("cve", "added", "2025-10911", "CVE-2025-10911"),
        ]
        assert len(issues) == 22
        assert list(server.requests[-1].url.params.multi_items()) == fixture_query(
            "diff_added_changed"
        )

    async def test_live_deleted(self, server: IBSServer) -> None:
        issues = await _diff(
            server,
            xml_response(load_fixture("diff_deleted")),
            _SUDO,
            "f736184f96b348a33510f43cdfa12bc9",
        )
        assert issues == [
            DiffIssue("cve", "deleted", "2026-35535", "CVE-2026-35535"),
            DiffIssue("bnc", "deleted", "1261420", "bsc#1261420"),
        ]

    async def test_live_empty_diff_without_issues_element(
        self, server: IBSServer
    ) -> None:
        assert (
            await _diff(server, xml_response(load_fixture("diff_empty")), _SUDO, _SUDO)
            == []
        )

    async def test_empty_issues_element(self, server: IBSServer) -> None:
        assert await _diff(server, _sourcediff("\n  ")) == []

    async def test_issues_are_returned_faithfully_with_duplicates(
        self, server: IBSServer
    ) -> None:
        cve = _issue(
            state="added", tracker="cve", name="2025-0001", label="CVE-2025-0001"
        )
        issues = await _diff(
            server,
            _sourcediff(
                cve
                + cve
                + _issue(state="added", tracker="cve", name="x", label="not-a-cve")
                + _issue(state="changed", tracker="cve")
                + _issue(state="added", tracker="bnc", name="2025-0002", label="")
                + _issue(state="deleted", tracker="custom-tracker", url="u")
            ),
        )
        assert issues == [
            DiffIssue("cve", "added", "2025-0001", "CVE-2025-0001"),
            DiffIssue("cve", "added", "2025-0001", "CVE-2025-0001"),
            DiffIssue("cve", "added", "x", "not-a-cve"),
            DiffIssue("cve", "changed", None, None),
            DiffIssue("bnc", "added", "2025-0002", ""),
            DiffIssue("custom-tracker", "deleted", None, None),
        ]

    async def test_request_is_the_expanded_issue_post(self, server: IBSServer) -> None:
        await _diff(server, _sourcediff(""), "0", _NEW)
        [request] = [r for r in server.requests if r.url.path == _diff_path()][-1:]
        assert request.method == "POST"
        assert list(request.url.params.multi_items()) == [
            ("cmd", "diff"),
            ("view", "xml"),
            ("onlyissues", "1"),
            ("expand", "1"),
            ("orev", "0"),
            ("rev", _NEW),
        ]

    @pytest.mark.parametrize(
        ("issues", "reason"),
        [
            (_issue(state="added"), "invalid_issue"),
            (_issue(tracker="cve"), "invalid_issue"),
            (_issue(tracker="", state="added"), "invalid_issue"),
            (_issue(tracker="cve", state=""), "invalid_issue"),
            (_issue(tracker="cve", state="removed"), "invalid_issue"),
            (_issue(tracker="cve", state="Added"), "invalid_issue"),
            ('<issue tracker="cve" state="added"><label/></issue>', "invalid_issue"),
            ('<entry tracker="cve" state="added"/>', "invalid_issue"),
            ("<issues/>", "invalid_issue"),
        ],
        ids=[
            "missing_tracker",
            "missing_state",
            "empty_tracker",
            "empty_state",
            "unknown_state",
            "state_case",
            "child_element",
            "other_element",
            "nested_issues",
        ],
    )
    async def test_unusable_issue_structure_fails(
        self, server: IBSServer, issues: str, reason: str
    ) -> None:
        with pytest.raises(IBSResponseDataError) as raised:
            await _diff(server, _sourcediff(issues))
        assert raised.value.reason == reason

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            ("<directory/>", "invalid_document"),
            ("<sourcediff><issues/><issues/></sourcediff>", "invalid_document"),
            ('<ns:sourcediff xmlns:ns="urn:x"/>', "invalid_document"),
            ("<sourcediff><issues>", "malformed_xml"),
            ("", "malformed_xml"),
            ("not xml", "malformed_xml"),
        ],
        ids=["wrong_root", "two_issues", "namespaced", "truncated", "empty", "text"],
    )
    async def test_unusable_document_fails(
        self, server: IBSServer, body: str, reason: str
    ) -> None:
        with pytest.raises(IBSResponseDataError) as raised:
            await _diff(server, _document(body))
        assert raised.value.reason == reason

    async def test_issues_outside_the_issues_element_are_ignored(
        self, server: IBSServer
    ) -> None:
        body = (
            '<sourcediff><old/><files><file><issue tracker="cve" state="x"/>'
            "</file></files></sourcediff>"
        )
        assert await _diff(server, _document(body)) == []

    async def test_interrupted_body_fails(self, server: IBSServer) -> None:
        document = load_fixture("diff_added_changed")
        with pytest.raises(IBSResponseDataError) as raised:
            await _diff(server, chunked_response([document[:500]], fail_after=True))
        assert raised.value.reason == "interrupted_response"

    async def test_large_document_streamed_in_small_chunks_has_no_cap(
        self, server: IBSServer
    ) -> None:
        issue = _issue(state="added", tracker="bnc", name="1", label="bsc#1").encode()
        document = (
            b'<sourcediff key="0"><issues>' + issue * 50000 + b"</issues></sourcediff>"
        )
        chunks = [document[i : i + 997] for i in range(0, len(document), 997)]
        issues = await _diff(server, chunked_response(chunks))
        assert len(issues) == 50000

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("", _NEW),
            ("00", _NEW),
            ("0" * 31, _NEW),
            ("g" * 32, _NEW),
            (_OLD, "0"),
            (_OLD, ""),
            (_OLD, _NEW + "0"),
        ],
    )
    async def test_invalid_checksums_raise_before_http(
        self, server: IBSServer, old: str, new: str
    ) -> None:
        async with _client() as client:
            with pytest.raises(ValueError, match="md5"):
                await client.get_diff_issues(LIVE_PROJECT, "pkg", old, new)
        assert server.requests == []

    @pytest.mark.parametrize("package", ["", "a/b", ".", "a\tb"])
    async def test_invalid_package_raises_before_http(
        self, server: IBSServer, package: str
    ) -> None:
        async with _client() as client:
            with pytest.raises(ValueError, match="invalid IBS package name"):
                await client.get_diff_issues(LIVE_PROJECT, package, "0", _NEW)
        assert server.requests == []


# ---------------------------------------------------------------------------
# HTTP errors and XML safety (both operations)
# ---------------------------------------------------------------------------

_OPERATIONS: Final = ["source_info", "diff"]


async def _run(server: IBSServer, operation: str, responder: Responder) -> object:
    if operation == "source_info":
        return await _source_info(server, responder, ["a"])
    return await _diff(server, responder)


class TestHttpErrors:
    @pytest.mark.parametrize("operation", _OPERATIONS)
    @pytest.mark.parametrize("status", [400, 403, 404, 409, 429])
    async def test_client_error_propagates_as_the_original_http_error(
        self, server: IBSServer, operation: str, status: int
    ) -> None:
        body = (
            b'<status code="400" origin="backend"><summary>SUSE:SLE-15-SP6:Update/pkg/'
            + _OLD.encode()
            + b": not in repository. fictional</summary></status>"
        )
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _run(server, operation, status_response(status, body))
        assert raised.value.response.status_code == status
        assert "not in repository" not in str(raised.value)

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_malformed_error_body_is_never_a_response_data_error(
        self, server: IBSServer, operation: str
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError):
            await _run(server, operation, status_response(400, b"<not-closed"))

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_persistent_5xx_after_shared_retries_propagates(
        self, server: IBSServer, sleep: AsyncMock, operation: str
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _run(server, operation, status_response(502))
        assert raised.value.response.status_code == 502
        assert sleep.await_count == 3

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_persistent_timeout_propagates_as_transport_error(
        self, server: IBSServer, operation: str
    ) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("fictional timeout", request=request)

        server.intercept = timeout
        with pytest.raises(httpx.ReadTimeout):
            await _run(server, operation, status_response(200))
        assert len(server.requests) == 4


class TestXmlSafety:
    @pytest.mark.parametrize("operation", _OPERATIONS)
    @pytest.mark.parametrize(
        "body",
        [
            "<!DOCTYPE sourcediff><sourcediff/>",
            '<!DOCTYPE r [<!ENTITY e "x">]><sourceinfolist>&e;</sourceinfolist>',
            '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
            '<!DOCTYPE r SYSTEM "http://example.test/r.dtd"><r/>',
            '<r a="&undefined;"/>',
        ],
        ids=[
            "doctype",
            "entity",
            "external_entity",
            "external_dtd",
            "undefined_entity",
        ],
    )
    async def test_dtds_and_entities_are_rejected(
        self, server: IBSServer, operation: str, body: str
    ) -> None:
        with pytest.raises(IBSResponseDataError) as raised:
            await _run(server, operation, _document(body))
        assert raised.value.reason == "malformed_xml"

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_undecodable_compressed_body_is_malformed(
        self, server: IBSServer, operation: str
    ) -> None:
        def corrupt(request: httpx.Request) -> httpx.Response:
            response = chunked_response([b"not gzip"])(request)
            response.headers["content-encoding"] = "gzip"
            return response

        with pytest.raises(IBSResponseDataError) as raised:
            await _run(server, operation, corrupt)
        assert raised.value.reason == "malformed_xml"


def _inadmissible_documents() -> Iterator[tuple[str, str, bytes]]:
    """(operation, case id, document) with each inadmissible character, raw
    and as a character reference, in every consumed field."""
    variants = {
        "nul_raw": b"\x00",
        "nul_reference": b"&#0;",
        "surrogate_raw": "\ud800".encode("utf-8", "surrogatepass"),
        "surrogate_reference": b"&#xD800;",
    }
    for case, value in variants.items():
        for field_name in ("package", "srcmd5"):
            attributes = {"package": b"a", "srcmd5": b"0" * 32}
            attributes[field_name] = attributes[field_name] + value
            rendered = b" ".join(
                k.encode() + b'="' + v + b'"' for k, v in attributes.items()
            )
            yield (
                "source_info",
                f"{field_name}_{case}",
                b"<sourceinfolist><sourceinfo " + rendered + b"/></sourceinfolist>",
            )
        for field_name in ("tracker", "state", "name", "label"):
            attributes = {
                "tracker": b"cve",
                "state": b"added",
                "name": b"2025-0001",
                "label": b"CVE-2025-0001",
            }
            attributes[field_name] = attributes[field_name] + value
            rendered = b" ".join(
                k.encode() + b'="' + v + b'"' for k, v in attributes.items()
            )
            yield (
                "diff",
                f"{field_name}_{case}",
                b"<sourcediff><issues><issue " + rendered + b"/></issues></sourcediff>",
            )


_INADMISSIBLE: Final = list(_inadmissible_documents())


class TestExternalStringAdmissibility:
    """docs/conventions.md (External String Admissibility, XML clause):
    U+0000 and a surrogate code point, raw or as a character reference, in
    any consumed field make the document not well-formed: the operation's
    parser-failure outcome, for the whole call."""

    @pytest.mark.parametrize(
        ("operation", "document"),
        [(operation, document) for operation, _, document in _INADMISSIBLE],
        ids=[f"{operation}-{case}" for operation, case, _ in _INADMISSIBLE],
    )
    async def test_inadmissible_character_is_a_parser_failure(
        self, server: IBSServer, operation: str, document: bytes
    ) -> None:
        with pytest.raises(IBSResponseDataError) as raised:
            await _run(server, operation, xml_response(document))
        assert raised.value.reason == "malformed_xml"

    async def test_supplementary_character_is_admissible(
        self, server: IBSServer
    ) -> None:
        issues = await _diff(
            server, _sourcediff(_issue(tracker="cve", state="added", name="&#x1F600;"))
        )
        assert issues[0].name == "\U0001f600"


# ---------------------------------------------------------------------------
# Lifetime
# ---------------------------------------------------------------------------


class TestLifetime:
    def test_each_invocation_creates_and_closes_its_client_on_its_own_loop(
        self, server: IBSServer
    ) -> None:
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        clients: list[IBSClient] = []

        async def invocation() -> None:
            async with _client() as client:
                clients.append(client)
                await client.get_source_info(LIVE_PROJECT, ["openssh"])
            assert client._http.is_closed

        asyncio.run(invocation())
        asyncio.run(invocation())
        assert len(clients) == 2
        assert clients[0] is not clients[1]
        assert all(client._http.is_closed for client in clients)
        assert len(server.signatures) == 2

    async def test_close_drops_session_cookies(self, server: IBSServer) -> None:
        server.route(
            "GET", _PROJECT_PATH, xml_response(load_fixture("sourceinfo_single_linked"))
        )
        client = _client()
        await client.get_source_info(LIVE_PROJECT, ["openssh"])
        assert len(client._http.cookies) == 1
        await client.aclose()
        assert len(client._http.cookies) == 0
        assert client._http.is_closed

    def test_no_module_level_client(self) -> None:
        for value in vars(ibs_client_module).values():
            assert not isinstance(value, IBSClient | httpx.AsyncClient)
