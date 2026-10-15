"""Cross-operation tests of the four `IBSClient` request operations.

Contract under test: docs/features/integrations/ibs-integration.md (Request
Authentication and Session Reuse as applied to the request operations;
Service Layer > IBSClient: credential and authentication rows, the XML
safety and log paragraph including U+0000, determinism and no side
effects; Security); docs/conventions.md (External String Admissibility, XML
clause); docs/features/platform/testing-strategy.md (External String
Admissibility); docs/features/packages/ibs-submission-tracking.md (Security
and Privacy bullets 2 and 3, client part; Testing Requirements bullet 11,
client logs and errors).
"""

from __future__ import annotations

import ast
import dataclasses
import logging
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, Final

import httpx
import pytest

from app.core.enums import IBSRequestActionType, IBSRequestState
from app.services import ibs_client as ibs_client_module
from app.services import ibs_request_evidence
from app.services.ibs_client import (
    AcceptInfo,
    IBSAuthenticationError,
    IBSClient,
    IBSCredentialsNotConfiguredError,
    IBSRequestActionDetail,
    RequestEvidenceResult,
)
from tests.support.ibs_api import (
    LIVE_CHALLENGE,
    SESSION_COOKIE_NAME,
    IBSServer,
    Responder,
    chunked_response,
    ibs_client,
    signed_requests,
    xml_response,
)
from tests.support.ibs_keys import fictional_settings_value

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_SUM: Final = "a" * 32
_PROJECT: Final = "SUSE:SLE-15-SP6:Update"
_ACTION: Final = IBSRequestActionDetail(
    request_number=920001,
    action_type=IBSRequestActionType.MAINTENANCE_INCIDENT,
    source_project="SUSE:Maintenance:REQUEST:920001",
    source_package="curl.SUSE_SLE-15-SP6_Update",
    source_revision=_SUM,
    target_project="SUSE:Maintenance:80001",
    target_package="curl.SUSE_SLE-15-SP6_Update",
    target_release_project=_PROJECT,
    acceptinfo=AcceptInfo(rev="2", srcmd5=_SUM, xsrcmd5=_SUM),
)
_SEARCH_DOC: Final = b'<collection matches="1"><request id="920001"/></collection>'
_DETAIL_DOC: Final = (
    b'<request id="920001"><action type="maintenance_incident">'
    b'<source project="SUSE:Maintenance:REQUEST:920001" package="curl.x" rev="1"/>'
    b'<target project="SUSE:Maintenance" releaseproject="SUSE:SLE-15-SP6:Update"/>'
    b'</action><state name="new" created="2026-10-01T05:20:43" '
    b'when="2026-10-01T09:16:55"/></request>'
)
_DIFF_DOC: Final = (
    b'<sourcediff><issues><issue state="added" tracker="cve" name="2026-1" '
    b'label="CVE-2026-1"/></issues></sourcediff>'
)
_HISTORY_DOC: Final = (
    b'<revisionlist><revision rev="1"><srcmd5>' + _SUM.encode() + b"</srcmd5>"
    b"<time>1700000000</time><requestid>920001</requestid></revision></revisionlist>"
)

Operation = Callable[[IBSClient], Awaitable[RequestEvidenceResult[Any]]]


@dataclasses.dataclass(frozen=True)
class _Op:
    method: str
    path: str
    document: bytes
    call: Operation


_OPERATIONS: Final = {
    "search": _Op(
        "GET",
        "/search/request/id",
        _SEARCH_DOC,
        lambda c: c.search_request_ids(
            IBSRequestActionType.MAINTENANCE_INCIDENT,
            states=[IBSRequestState.NEW],
            source_package_prefix="curl.",
        ),
    ),
    "detail": _Op(
        "GET", "/request/920001", _DETAIL_DOC, lambda c: c.get_request(920001)
    ),
    "diff": _Op(
        "POST",
        "/source/SUSE:Maintenance:80001/curl.SUSE_SLE-15-SP6_Update",
        _DIFF_DOC,
        lambda c: c.get_request_action_diff(_ACTION, codestream_package="curl"),
    ),
    "history": _Op(
        "GET",
        f"/source/{_PROJECT}/curl/_history",
        _HISTORY_DOC,
        lambda c: c.get_source_history(_PROJECT, "curl"),
    ),
}
_NAMES: Final = list(_OPERATIONS)


def _serve(server: IBSServer, name: str, responder: Responder | None = None) -> _Op:
    operation = _OPERATIONS[name]
    server.route(
        operation.method,
        operation.path,
        responder or xml_response(operation.document),
    )
    return operation


async def _run(
    server: IBSServer, name: str, responder: Responder | None = None
) -> RequestEvidenceResult[Any]:
    operation = _serve(server, name, responder)
    async with ibs_client() as client:
        return await operation.call(client)


class TestCredentialsAndAuthentication:
    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize(
        ("username", "key"),
        [("", "configured"), ("jdoe", ""), ("", "")],
        ids=["username_empty", "key_empty", "both_empty"],
    )
    async def test_unconfigured_credentials_raise_before_any_request(
        self, server: IBSServer, name: str, username: str, key: str
    ) -> None:
        encoded = fictional_settings_value() if key else ""
        async with ibs_client(username=username, key=encoded) as client:
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await _OPERATIONS[name].call(client)
        assert server.requests == []

    @pytest.mark.parametrize("name", _NAMES)
    async def test_unsigned_attempt_then_one_signed_retry(
        self, server: IBSServer, name: str
    ) -> None:
        result = await _run(server, name)
        assert result.value is not None
        unsigned, signed = server.requests
        assert "authorization" not in unsigned.headers
        assert unsigned.url == signed.url
        assert unsigned.method == signed.method == _OPERATIONS[name].method
        assert len(server.signatures) == 1
        assert server.signatures[0].key_id == "jdoe"

    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize(
        ("setup", "reason"),
        [
            ("reject", "signature_rejected"),
            ("basic", "unsupported_challenge"),
            ("two", "unsupported_challenge"),
        ],
    )
    async def test_authentication_failure_raises(
        self, server: IBSServer, name: str, setup: str, reason: str
    ) -> None:
        if setup == "reject":
            server.reject_signatures = True
        elif setup == "basic":
            server.challenges = ['Basic realm="fictional"']
        else:
            server.challenges = [LIVE_CHALLENGE, LIVE_CHALLENGE]
        with pytest.raises(IBSAuthenticationError) as raised:
            await _run(server, name)
        assert raised.value.reason == reason
        assert len(signed_requests(server)) == (1 if setup == "reject" else 0)

    async def test_session_is_reused_across_the_four_operations(
        self, server: IBSServer
    ) -> None:
        for name in _NAMES:
            _serve(server, name)
        async with ibs_client() as client:
            for name in _NAMES:
                result = await _OPERATIONS[name].call(client)
                assert result.value is not None
        assert len(server.signatures) == 1
        for request in server.requests[2:]:
            assert "authorization" not in request.headers
            assert request.headers["cookie"] == (
                f"{SESSION_COOKIE_NAME}=fictional-session-0001"
            )

    @pytest.mark.parametrize("name", _NAMES)
    async def test_redirect_is_not_followed(self, server: IBSServer, name: str) -> None:
        server.intercept = lambda _: httpx.Response(
            302, headers={"location": "https://elsewhere.example.test/x"}
        )
        with pytest.raises(httpx.HTTPStatusError):
            await _run(server, name)
        assert {r.url.host for r in server.requests} == {"api.ibs.example.test"}


class TestXmlSafety:
    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize(
        "body",
        [
            b"<!DOCTYPE r><r/>",
            b'<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>',
            b'<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
            b'<!DOCTYPE r SYSTEM "http://example.test/r.dtd"><r/>',
            b'<r a="&undefined;"/>',
            b"",
            b"not xml",
        ],
        ids=[
            "doctype",
            "entity",
            "external_entity",
            "external_dtd",
            "undefined_entity",
            "empty",
            "text",
        ],
    )
    async def test_forbidden_or_malformed_document_is_malformed(
        self, server: IBSServer, name: str, body: bytes
    ) -> None:
        result = await _run(server, name, xml_response(body))
        assert result == RequestEvidenceResult(incomplete_reason="malformed_xml")

    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize("cut", [1, 2, 3])
    async def test_truncated_document_is_malformed(
        self, server: IBSServer, name: str, cut: int
    ) -> None:
        document = _OPERATIONS[name].document
        truncated = document[: len(document) * cut // 4]
        result = await _run(server, name, xml_response(truncated))
        assert result == RequestEvidenceResult(incomplete_reason="malformed_xml")

    @pytest.mark.parametrize("name", _NAMES)
    async def test_interrupted_body_is_incomplete(
        self, server: IBSServer, name: str
    ) -> None:
        document = _OPERATIONS[name].document
        responder = chunked_response([document[:20]], fail_after=True)
        result = await _run(server, name, responder)
        assert result == RequestEvidenceResult(incomplete_reason="interrupted_response")

    @pytest.mark.parametrize("name", _NAMES)
    async def test_undecodable_compressed_body_is_malformed(
        self, server: IBSServer, name: str
    ) -> None:
        def corrupt(request: httpx.Request) -> httpx.Response:
            response = chunked_response([b"not gzip"])(request)
            response.headers["content-encoding"] = "gzip"
            return response

        result = await _run(server, name, corrupt)
        assert result == RequestEvidenceResult(incomplete_reason="malformed_xml")

    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize("media_type", ["text/xml", "application/xml", None])
    async def test_document_is_parsed_whatever_the_xml_media_type(
        self, server: IBSServer, name: str, media_type: str | None
    ) -> None:
        document = _OPERATIONS[name].document
        headers = {} if media_type is None else {"content-type": media_type}
        result = await _run(
            server,
            name,
            lambda _: httpx.Response(200, headers=headers, content=document),
        )
        assert result.value is not None

    @pytest.mark.parametrize("name", _NAMES)
    async def test_large_document_is_parsed_without_a_cap(
        self, server: IBSServer, name: str
    ) -> None:
        count = 10_000
        if name == "search":
            entries = "".join(f'<request id="{n}"/>' for n in range(1, count + 1))
            body = f'<collection matches="{count}">{entries}</collection>'
        elif name == "detail":
            actions = "".join(
                f'<action type="maintenance_release"><source project='
                f'"SUSE:Maintenance:1" package="p{n}"/><target project="SUSE:T" '
                f'package="p{n}.1"/></action>'
                for n in range(count)
            )
            body = _DETAIL_DOC.decode().replace("<action ", actions + "<action ", 1)
        elif name == "diff":
            issues = "".join(
                f'<issue state="added" tracker="bnc" name="{n}"/>' for n in range(count)
            )
            body = f"<sourcediff><issues>{issues}</issues></sourcediff>"
        else:
            entries = "".join(
                f'<revision rev="{n}"><srcmd5>{_SUM}</srcmd5><time>{n}</time>'
                "</revision>"
                for n in range(1, count + 1)
            )
            body = f"<revisionlist>{entries}</revisionlist>"
        result = await _run(server, name, xml_response(body.encode()))
        assert result.value is not None
        sizes = {
            "search": lambda v: len(v.request_numbers),
            "detail": lambda v: len(v.actions) - 1,
            "diff": lambda v: len(v.issues),
            "history": lambda v: len(v.entries),
        }
        assert sizes[name](result.value) == count

    @pytest.mark.parametrize("name", _NAMES)
    async def test_document_split_into_single_bytes_is_parsed(
        self, server: IBSServer, name: str
    ) -> None:
        document = _OPERATIONS[name].document
        chunks = [document[i : i + 1] for i in range(len(document))]
        result = await _run(server, name, chunked_response(chunks))
        assert result.value is not None


_INADMISSIBLE: Final = {
    "nul_raw": b"\x00",
    "nul_reference": b"&#0;",
    "surrogate_raw": "\ud800".encode("utf-8", "surrogatepass"),
    "surrogate_reference": b"&#xD800;",
    "surrogate_pair_reference": b"&#xD83D;&#xDE00;",
}
_FIELDS: Final = {
    "search": {"matches": b'matches="1"', "request_id": b'id="920001"'},
    "detail": {
        "request_id": b'request id="920001"',
        "action_type": b'type="maintenance_incident"',
        "source_project": b'project="SUSE:Maintenance:REQUEST:920001"',
        "source_package": b'package="curl.x"',
        "source_rev": b'rev="1"',
        "target_project": b'project="SUSE:Maintenance"',
        "target_releaseproject": b'releaseproject="SUSE:SLE-15-SP6:Update"',
        "state_name": b'name="new"',
        "state_created": b'created="2026-10-01T05:20:43"',
        "state_when": b'when="2026-10-01T09:16:55"',
    },
    "diff": {
        "state": b'state="added"',
        "tracker": b'tracker="cve"',
        "name": b'name="2026-1"',
        "label": b'label="CVE-2026-1"',
    },
    "history": {
        "rev": b'rev="1"',
        "srcmd5": b"<srcmd5>" + _SUM.encode(),
        "time": b"<time>1700000000",
        "requestid": b"<requestid>920001",
    },
}


def _inadmissible_cases() -> Iterator[tuple[str, str, bytes]]:
    """(operation, case id, document) with each inadmissible character, raw
    and as a character reference, appended to every consumed value."""
    for name, fields in _FIELDS.items():
        document = _OPERATIONS[name].document
        for field_id, field in fields.items():
            assert document.count(field) == 1, (name, field)
            for case, value in _INADMISSIBLE.items():
                if field.endswith(b'"'):
                    changed = document.replace(field, field[:-1] + value + b'"')
                else:
                    changed = document.replace(field, field + value)
                yield name, f"{field_id}-{case}", changed


_CASES: Final = list(_inadmissible_cases())


def _acceptinfo_cases() -> Iterator[tuple[str, bytes]]:
    for attribute in ("rev", "srcmd5", "xsrcmd5", "osrcmd5", "oxsrcmd5", "oproject"):
        for case, value in _INADMISSIBLE.items():
            document = _DETAIL_DOC.replace(
                b"</action>",
                b"<acceptinfo " + attribute.encode() + b'="x' + value + b'"/></action>',
            )
            yield f"acceptinfo_{attribute}-{case}", document
    for case, value in _INADMISSIBLE.items():
        document = _DETAIL_DOC.replace(
            b"</action>", b'<acceptinfo opackage="x' + value + b'"/></action>'
        )
        yield f"acceptinfo_opackage-{case}", document
    target = b'releaseproject="SUSE:SLE-15-SP6:Update"/>'
    assert _DETAIL_DOC.count(target) == 1
    for case, value in _INADMISSIBLE.items():
        document = _DETAIL_DOC.replace(
            target, target[:-2] + b' package="x' + value + b'"/>'
        )
        yield f"target_package-{case}", document
    for case, value in _INADMISSIBLE.items():
        document = _DETAIL_DOC.replace(
            b'name="new"',
            b'name="superseded" superseded_by="920002' + value + b'"',
        )
        yield f"superseded_by-{case}", document


_ACCEPTINFO_CASES: Final = list(_acceptinfo_cases())


class TestExternalStringAdmissibility:
    """An inadmissible character, raw or as a character reference, in any
    consumed field is not well-formed XML: the operation's parser-failure
    outcome (`malformed_xml`) for the whole result."""

    @pytest.mark.parametrize(
        ("name", "document"),
        [(name, document) for name, _, document in _CASES],
        ids=[f"{name}-{case}" for name, case, _ in _CASES],
    )
    async def test_inadmissible_character_is_a_parser_failure(
        self, server: IBSServer, name: str, document: bytes
    ) -> None:
        result = await _run(server, name, xml_response(document))
        assert result == RequestEvidenceResult(incomplete_reason="malformed_xml")

    @pytest.mark.parametrize(
        "document",
        [document for _, document in _ACCEPTINFO_CASES],
        ids=[case for case, _ in _ACCEPTINFO_CASES],
    )
    async def test_inadmissible_optional_detail_field_is_a_parser_failure(
        self, server: IBSServer, document: bytes
    ) -> None:
        result = await _run(server, "detail", xml_response(document))
        assert result == RequestEvidenceResult(incomplete_reason="malformed_xml")

    async def test_supplementary_character_is_admissible(
        self, server: IBSServer
    ) -> None:
        document = _DIFF_DOC.replace(b'name="2026-1"', b'name="&#x1F600;"')
        result = await _run(server, "diff", xml_response(document))
        assert result.value is not None
        assert result.value.issues[0].name == "\U0001f600"


_MARKER: Final = "FictionalMarker"
_PERSONAL: Final = "home:fictional-person"


def _noisy(name: str) -> bytes:
    """The operation's document with personal, free-text, and marker content
    in unconsumed places, plus a personal project in a consumed one."""
    document = _OPERATIONS[name].document
    if name == "detail":
        return document.replace(
            b"SUSE:Maintenance:REQUEST:920001", _PERSONAL.encode()
        ).replace(
            b"<state ",
            f'<description>{_MARKER}</description><review by_user="{_MARKER}"/>'
            f'<state who="{_MARKER}" '.encode(),
        )
    if name == "diff":
        return document.replace(
            b"<issues>",
            (
                f"<files><file><diff>{_MARKER} changes</diff></file></files><issues>"
            ).encode(),
        )
    if name == "history":
        return document.replace(
            b"</revision>",
            f"<user>{_MARKER}</user><comment>{_MARKER}</comment></revision>".encode(),
        )
    return document.replace(b"<request ", f'<request creator="{_MARKER}" '.encode())


class TestPrivacy:
    async def test_no_content_credential_or_personal_project_in_logs_results_or_urls(
        self, server: IBSServer, caplog: pytest.LogCaptureFixture
    ) -> None:
        key = fictional_settings_value()
        personal_action = dataclasses.replace(
            _ACTION, source_project="_redacted_", acceptinfo=None
        )
        for name in _NAMES:
            _serve(server, name, xml_response(_noisy(name)))
        rendered: list[str] = []
        with caplog.at_level(logging.DEBUG):
            async with ibs_client(key=key) as client:
                for name in _NAMES:
                    result = await _OPERATIONS[name].call(client)
                    assert result.value is not None, name
                    rendered.append(repr(result))
                not_requested = await client.get_request_action_diff(
                    personal_action, codestream_package="curl"
                )
                assert not_requested.incomplete_reason == "outside_suse_namespace"
                rendered.append(repr(not_requested))
                for name in _NAMES:
                    broken = f'<r a="{_MARKER}" b="{_PERSONAL}"><'.encode()
                    _serve(server, name, xml_response(broken))
                    rendered.append(repr(await _OPERATIONS[name].call(client)))

        signature = signed_requests(server)[0].headers["authorization"]
        text = "\n".join([caplog.text, *rendered])
        for forbidden in (
            _MARKER,
            _PERSONAL,
            "home:",
            "changes",
            key[:24],
            signature.split('signature="')[1][:24],
            "fictional-session",
        ):
            assert forbidden not in text
        for request in server.requests:
            assert "home:" not in str(request.url)
            assert "_redacted_" not in str(request.url)

    async def test_the_client_itself_logs_nothing(
        self, server: IBSServer, caplog: pytest.LogCaptureFixture
    ) -> None:
        for name in _NAMES:
            _serve(server, name)
        with caplog.at_level(logging.DEBUG):
            async with ibs_client() as client:
                for name in _NAMES:
                    await _OPERATIONS[name].call(client)
                await client.get_request_action_diff(
                    dataclasses.replace(_ACTION, target_project=None),
                    codestream_package="curl",
                )
        assert {
            record.name for record in caplog.records if record.name.startswith("app.")
        } == set()


class TestNoSideEffects:
    @pytest.mark.parametrize("name", _NAMES)
    async def test_repeated_calls_are_independent_identical_reads(
        self, server: IBSServer, name: str
    ) -> None:
        _serve(server, name)
        async with ibs_client() as client:
            first = await _OPERATIONS[name].call(client)
            second = await _OPERATIONS[name].call(client)
        assert first == second
        assert first.value is not None
        reads = [r for r in server.requests if r.url.path == _OPERATIONS[name].path]
        assert len(reads) == 3
        assert {r.method for r in reads} == {_OPERATIONS[name].method}
        assert len({str(r.url) for r in reads}) == 1
        assert all(r.content == b"" for r in reads)

    @pytest.mark.parametrize(
        "module", [ibs_client_module, ibs_request_evidence], ids=lambda m: m.__name__
    )
    def test_modules_import_no_persistence_broker_or_task_layer(
        self, module: Any
    ) -> None:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        forbidden = (
            "sqlalchemy",
            "redis",
            "celery",
            "aio_pika",
            "app.models",
            "app.db",
            "app.database",
            "app.tasks",
            "app.services.redis",
        )
        assert not [name for name in imported if name.startswith(forbidden)], imported
