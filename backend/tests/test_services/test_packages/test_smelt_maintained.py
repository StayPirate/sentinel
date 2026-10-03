"""Tests for the validated SMELT maintained-package retrieval.

Contract under test: docs/features/packages/package-model.md (SMELT Query
for Package Resolution: Envelope and error handling, Entry validation,
Consumed fields, Single authoritative representation, Processing step 1)
and the #782 decisions: the "unavailable" outcome is a raised
`MaintainedPackageUnavailableError` carrying only a bounded `category`
(`transport`, `http_status`, `envelope`, `schema`), the HTTP status code,
and the converted exception's class name, with no client-level log
record (D2); the body of any status other than 200 and 404 is not read
(D3); a missing, null, empty, or non-string `friendly_name` is absent
(D4); and the 255-character limit equals the
`TicketPackageTrack.reference` column length (D5). Only the two specified
skip warnings are emitted, and only for an accepted response.
Cancellation, `SoftTimeLimitExceeded`, `MemoryError`, and programming
errors propagate. The helper performs network I/O only (package-service.md,
Module invariant: I/O-then-Lock pattern).

Every test serves fictional responses through `httpx.MockTransport` (with
the sanitized live fixtures from `tests/support/smelt.py` where noted); no
network and no database are used.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import json
import traceback
from collections.abc import AsyncIterator, Callable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import String
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import WorkflowType
from app.models.ticket_package_track import TicketPackageTrack
from app.services import http_client
from app.services.packages import smelt_maintained
from app.services.packages.smelt_maintained import (
    REFERENCE_MAX_LENGTH,
    UNKNOWN_PROCESS_EVENT,
    UNSUPPORTED_PROCESS_EVENT,
    MaintainedCodestream,
    MaintainedPackage,
    MaintainedPackageNotFound,
    MaintainedPackageUnavailableError,
    MaintainedTarget,
    fetch_maintained_package,
    maintained_package_url,
)
from tests.support.smelt import (
    MAINTAINED_NOT_FOUND_FIXTURES,
    MAINTAINED_SUCCESS_FIXTURES,
    SMELT_TEST_API_URL,
    load_maintained_fixture,
)

PACKAGE = "example-package"
QUERY = "include_reactive_ltss=true"
ENDPOINT = f"{SMELT_TEST_API_URL}/experimental/v2/maintained/{PACKAGE}?{QUERY}"
RAW_PATH_PREFIX = b"/api/experimental/v2/maintained/"

SLE_CODESTREAM = "Example:SLE-15-SP1:Update"
SLFO_CODESTREAM = "Example:SLFO:Main"
SLFO_IBS_CODESTREAM = "Example:SLFO-IBS:1.0"
UNKNOWN_CODESTREAM = "Example:Unclassified:1"
BROKEN_CODESTREAM = "Example:Broken:1"

CPE_ONE = "cpe:/o:example:product-1:1"
CPE_TWO = "cpe:/o:example:product-2:1"
CPE_THREE = "cpe:/o:example:product-3:1"
FRIENDLY_ONE = "Example Product 1"
FRIENDLY_TWO = "Example Product 2"
FRIENDLY_THREE = "Example Product 3"

MARKER = "fictional-private-marker"
"""A private value placed in bodies and exception messages; never logged."""

NOT_FOUND_ENVELOPE: Final = {"status": "error", "data": f"Package {PACKAGE} not found"}

Respond = Callable[[httpx.Request], httpx.Response]

_DEFAULT: Final[Any] = object()
"""Builder default: use the standard valid value."""
_OMIT: Final[Any] = object()
"""Builder value: omit the key entirely."""

_DECLARED_TYPES = ("SLFO", "SLFO_IBS", "SLE_15", "UNKNOWN")
_SUPPORTED_TYPES = ("SLFO", "SLE_15")
_SKIPPED_TYPES = ("SLFO_IBS", "UNKNOWN")


@pytest.fixture(autouse=True)
def _smelt_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


# ---------------------------------------------------------------------------
# Response builders (fictional data only)
# ---------------------------------------------------------------------------


def _compact(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value is not _OMIT}


def _target(
    cpe: Any = CPE_ONE,
    friendly_name: Any = FRIENDLY_ONE,
    *,
    product: Any = _DEFAULT,
    definition_type: str = "channel",
) -> dict[str, Any]:
    """One target with every upstream field (unconsumed ones included)."""
    if product is _DEFAULT:
        product = _compact(
            {
                "id": 1001,
                "friendly_name": friendly_name,
                "cpe": cpe,
                "support_status": "General Support",
            }
        )
    return _compact(
        {
            "product": product,
            "repository": "EXAMPLE:Products:Product:1",
            "product_definition": {
                "name": "Example-Product_1",
                "url": "https://build.example.invalid/fictional/definition",
                "type": definition_type,
            },
        }
    )


def _entry(
    *,
    name: Any = SLE_CODESTREAM,
    process: Any = "SLE_15",
    targets: Any = _DEFAULT,
    codestream: Any = _DEFAULT,
) -> dict[str, Any]:
    """One grouped entry with every upstream field (unconsumed ones included)."""
    if codestream is _DEFAULT:
        codestream = _compact(
            {
                "name": name,
                "url": "https://build.example.invalid/fictional/codestream",
                "type": process,
            }
        )
    return _compact(
        {
            "codestream": codestream,
            "binary_packages": [{"name": "example-binary", "support_status": "L3"}],
            "targets": [_target()] if targets is _DEFAULT else targets,
            "support_status": "General Support",
        }
    )


def _success(*entries: Any) -> dict[str, Any]:
    return {"status": "success", "data": list(entries)}


def _sle_entry() -> dict[str, Any]:
    return _entry(name=SLE_CODESTREAM, process="SLE_15", targets=[_target()])


def _slfo_entry() -> dict[str, Any]:
    return _entry(
        name=SLFO_CODESTREAM,
        process="SLFO",
        targets=[_target(CPE_TWO, FRIENDLY_TWO, definition_type="compose")],
    )


def _ibs_entry(targets: Any = _DEFAULT) -> dict[str, Any]:
    return _entry(name=SLFO_IBS_CODESTREAM, process="SLFO_IBS", targets=targets)


def _unknown_entry(targets: Any = _DEFAULT) -> dict[str, Any]:
    return _entry(name=UNKNOWN_CODESTREAM, process="UNKNOWN", targets=targets)


SLE_RECORD = MaintainedCodestream(
    name=SLE_CODESTREAM,
    workflow_type=WorkflowType.IBS,
    targets=(MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE),),
)
SLFO_RECORD = MaintainedCodestream(
    name=SLFO_CODESTREAM,
    workflow_type=WorkflowType.GIT,
    targets=(MaintainedTarget(cpe=CPE_TWO, friendly_name=FRIENDLY_TWO),),
)


def _json(status_code: int, body: Any) -> Respond:
    """Serve `body` serialized as JSON (`None` is served as `null`)."""
    raw = json.dumps(body).encode()

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code, content=raw, headers={"content-type": "application/json"}
        )

    return respond


def _raw(
    status_code: int, raw: bytes, headers: dict[str, str] | None = None
) -> Respond:
    """Serve undecoded bytes as a stream (content-encoding is applied on read)."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code, stream=httpx.ByteStream(raw), headers=headers or {}
        )

    return respond


def _corrupt_gzip(status_code: int) -> Respond:
    return _raw(status_code, b"not gzip at all", {"content-encoding": "gzip"})


def _raise(error: BaseException) -> Respond:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def _redirect(status_code: int) -> Respond:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"Location": f"https://other.example.test/{MARKER}"},
        )

    return respond


class _BodyReadFailure(httpx.AsyncByteStream):
    """A body whose transfer fails with `error` after the headers arrived."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"status": "success", "data": [{"codestream": "'
        raise self._error


def _body_read_failure(status_code: int, error: BaseException) -> Respond:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, stream=_BodyReadFailure(error))

    return respond


class _TrackedStream(httpx.AsyncByteStream):
    """A body that records whether the response was closed."""

    def __init__(self, content: bytes) -> None:
        self._content = content
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._content

    async def aclose(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Invocation helpers
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    result: MaintainedPackage | MaintainedPackageNotFound | None
    error: MaintainedPackageUnavailableError | None
    requests: list[httpx.Request]
    logs: list[MutableMapping[str, Any]]


async def _fetch(
    respond: Respond, *, package_name: str = PACKAGE, **client_kwargs: Any
) -> _Outcome:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return respond(request)

    result: MaintainedPackage | MaintainedPackageNotFound | None = None
    error: MaintainedPackageUnavailableError | None = None
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, **client_kwargs) as client:
        with capture_logs() as logs:
            try:
                result = await fetch_maintained_package(
                    client, package_name=package_name
                )
            except MaintainedPackageUnavailableError as exc:
                error = exc
    return _Outcome(result=result, error=error, requests=requests, logs=logs)


def _found(outcome: _Outcome) -> MaintainedPackage:
    assert outcome.error is None
    assert len(outcome.requests) == 1
    assert isinstance(outcome.result, MaintainedPackage)
    return outcome.result


def _assert_not_found(outcome: _Outcome) -> None:
    assert outcome.error is None
    assert outcome.result == MaintainedPackageNotFound()
    assert outcome.logs == []
    assert len(outcome.requests) == 1


def _assert_unavailable(
    outcome: _Outcome,
    category: str,
    *,
    status_code: int | None = None,
    error_type: str | None = None,
) -> MaintainedPackageUnavailableError:
    """The outcome is exactly one bounded unavailable error and no log."""
    assert outcome.result is None
    error = outcome.error
    assert error is not None
    assert error.category == category
    assert error.status_code == status_code
    assert error.error_type == error_type
    assert error.args == (category,)
    assert str(error) == category
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    assert outcome.logs == []
    assert len(outcome.requests) == 1
    return error


def _unsupported_warning(codestream: str = SLFO_IBS_CODESTREAM) -> dict[str, Any]:
    return {
        "event": UNSUPPORTED_PROCESS_EVENT,
        "log_level": "warning",
        "package_name": PACKAGE,
        "codestream": codestream,
        "maintenance_process_type": "SLFO_IBS",
    }


def _unknown_warning(codestream: str = UNKNOWN_CODESTREAM) -> dict[str, Any]:
    return {
        "event": UNKNOWN_PROCESS_EVENT,
        "log_level": "warning",
        "package_name": PACKAGE,
        "codestream": codestream,
    }


def _ids(cases: list[tuple[str, Any]]) -> list[str]:
    return [name for name, _ in cases]


def _values(cases: list[tuple[str, Any]]) -> list[Any]:
    return [value for _, value in cases]


# ---------------------------------------------------------------------------
# Request construction (SMELT Query for Package Resolution)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_request_targets_exact_endpoint_with_one_get(self) -> None:
        outcome = await _fetch(_json(200, _success(_sle_entry())))

        (request,) = outcome.requests
        assert request.method == "GET"
        assert str(request.url) == ENDPOINT
        assert request.url.raw_path == RAW_PATH_PREFIX + PACKAGE.encode() + b"?" + (
            QUERY.encode()
        )
        assert request.url.path == f"/api/experimental/v2/maintained/{PACKAGE}"
        assert request.url.query == QUERY.encode()
        assert dict(request.url.params) == {"include_reactive_ltss": "true"}
        assert maintained_package_url(SMELT_TEST_API_URL, PACKAGE) == ENDPOINT

    @pytest.mark.parametrize(
        ("package_name", "segment"),
        [
            ("pkg/sub", b"pkg%2Fsub"),
            ("pkg?include_reactive_ltss=false", b"pkg%3Finclude_reactive_ltss%3Dfalse"),
            ("pkg#fragment", b"pkg%23fragment"),
            ("pkg name", b"pkg%20name"),
            ("pkg+plus", b"pkg%2Bplus"),
            ("pkg%41", b"pkg%2541"),
            ("pkg&other", b"pkg%26other"),
            ("pkg;param", b"pkg%3Bparam"),
            ("pkg-é", b"pkg-%C3%A9"),
            ("../pkg", b"..%2Fpkg"),
            ("pkg/..", b"pkg%2F.."),
            ("...", b"..."),
            (".pkg", b".pkg"),
            ("python3-pkg_name.1~2", b"python3-pkg_name.1~2"),
        ],
        ids=[
            "slash",
            "query",
            "fragment",
            "space",
            "plus",
            "percent",
            "ampersand",
            "semicolon",
            "non-ascii",
            "dot-dot-prefix",
            "dot-dot-suffix",
            "three-dots",
            "leading-dot",
            "unreserved-kept",
        ],
    )
    async def test_reserved_characters_are_encoded_into_one_path_segment(
        self, package_name: str, segment: bytes
    ) -> None:
        outcome = await _fetch(
            _json(200, _success(_sle_entry())), package_name=package_name
        )

        (request,) = outcome.requests
        path, _, query = request.url.raw_path.partition(b"?")
        assert path.split(b"/") == [
            b"",
            b"api",
            b"experimental",
            b"v2",
            b"maintained",
            segment,
        ]
        assert query == QUERY.encode()
        assert request.url.fragment == ""
        assert maintained_package_url(SMELT_TEST_API_URL, package_name) == (
            f"{SMELT_TEST_API_URL}/experimental/v2/maintained/"
            f"{segment.decode()}?{QUERY}"
        )

    async def test_package_name_case_is_preserved(self) -> None:
        outcome = await _fetch(
            _json(404, load_maintained_fixture("case_variant")),
            package_name="Kernel-Default",
        )

        _assert_not_found(outcome)
        assert outcome.requests[0].url.raw_path == (
            RAW_PATH_PREFIX + b"Kernel-Default?" + QUERY.encode()
        )

    @pytest.mark.parametrize(
        "package_name", ["", ".", ".."], ids=["empty", "dot", "dot-dot"]
    )
    async def test_name_that_cannot_form_a_segment_raises_before_any_request(
        self, package_name: str
    ) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json=_success(_sle_entry()))

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with (
                capture_logs() as logs,
                pytest.raises(ValueError, match="single URL path segment"),
            ):
                await fetch_maintained_package(client, package_name=package_name)

        assert requests == []
        assert logs == []
        with pytest.raises(ValueError, match="single URL path segment"):
            maintained_package_url(SMELT_TEST_API_URL, package_name)

    async def test_request_sends_no_credentials_despite_client_defaults(
        self,
    ) -> None:
        outcome = await _fetch(
            _json(200, _success(_sle_entry())),
            auth=("fictional-user", "fictional-secret"),
            headers={
                "Authorization": "Bearer fictional-token",
                "Cookie": "fictional=header-cookie",
            },
            cookies={"sessionid": "fictional-session"},
        )

        (request,) = outcome.requests
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert _found(outcome) == MaintainedPackage(codestreams=(SLE_RECORD,))

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_even_when_client_follows(
        self, status_code: int
    ) -> None:
        outcome = await _fetch(_redirect(status_code), follow_redirects=True)

        _assert_unavailable(outcome, "http_status", status_code=status_code)
        assert str(outcome.requests[0].url) == ENDPOINT

    @pytest.mark.parametrize(
        ("status_code", "text"),
        [
            (200, json.dumps(_success(_sle_entry()))),
            (200, json.dumps(_success())),
            (404, json.dumps(NOT_FOUND_ENVELOPE)),
            (200, "<html>not json</html>"),
            (200, json.dumps({"status": "success", "data": None})),
            (500, "fictional"),
        ],
        ids=["found", "not-found-200", "not-found-404", "envelope", "schema", "status"],
    )
    async def test_response_is_closed_for_every_outcome(
        self, status_code: int, text: str
    ) -> None:
        stream = _TrackedStream(text.encode())

        outcome = await _fetch(
            lambda request: httpx.Response(status_code, stream=stream)
        )

        assert len(outcome.requests) == 1
        assert stream.closed


# ---------------------------------------------------------------------------
# Envelope and pairing matrix (Envelope and error handling; Processing 1, 3)
# ---------------------------------------------------------------------------

_NOT_FOUND_404: list[tuple[str, Any]] = [
    ("jsend-error", NOT_FOUND_ENVELOPE),
    ("empty-string-data", {"status": "error", "data": ""}),
    ("unknown-keys", {**NOT_FOUND_ENVELOPE, "message": "fictional", "code": 404}),
    *[
        (f"fixture-{name}", load_maintained_fixture(name))
        for name in MAINTAINED_NOT_FOUND_FIXTURES
    ],
]

# (responder, expected `error_type` or `None` when absent).
_ENVELOPE_404: list[tuple[str, tuple[Respond, str | None]]] = [
    ("invalid-json", (_raw(404, b"<html>Not Found</html>"), "JSONDecodeError")),
    ("empty-body", (_raw(404, b""), "JSONDecodeError")),
    (
        "invalid-utf8",
        (_raw(404, b'{"status": "error", "data": "\xc3\x28"}'), "UnicodeDecodeError"),
    ),
    ("non-object-list", (_json(404, [NOT_FOUND_ENVELOPE]), None)),
    ("non-object-string", (_json(404, "Package example-package not found"), None)),
    ("non-object-number", (_json(404, 404), None)),
    ("non-object-null", (_json(404, None), None)),
    ("status-success", (_json(404, _success(_sle_entry())), None)),
    ("status-success-empty-data", (_json(404, _success()), None)),
    ("status-fail", (_json(404, {"status": "fail", "data": "fictional"}), None)),
    ("status-unknown", (_json(404, {"status": "missing", "data": "x"}), None)),
    ("status-wrong-case", (_json(404, {"status": "Error", "data": "x"}), None)),
    ("missing-status", (_json(404, {"data": "fictional"}), None)),
    ("non-string-status", (_json(404, {"status": 404, "data": "x"}), None)),
    ("null-status", (_json(404, {"status": None, "data": "x"}), None)),
    ("data-int", (_json(404, {"status": "error", "data": 404}), None)),
    ("data-null", (_json(404, {"status": "error", "data": None}), None)),
    ("data-list", (_json(404, {"status": "error", "data": ["x"]}), None)),
    ("data-object", (_json(404, {"status": "error", "data": {"m": "x"}}), None)),
    ("data-bool", (_json(404, {"status": "error", "data": False}), None)),
    ("missing-data", (_json(404, {"status": "error"}), None)),
    ("corrupt-gzip", (_corrupt_gzip(404), "DecodingError")),
]

_ENVELOPE_200: list[tuple[str, tuple[Respond, str | None]]] = [
    ("invalid-json", (_raw(200, b"<html>maintenance</html>"), "JSONDecodeError")),
    ("empty-body", (_raw(200, b""), "JSONDecodeError")),
    (
        "invalid-utf8",
        (_raw(200, b'{"status": "success", "data": "\xc3\x28"}'), "UnicodeDecodeError"),
    ),
    ("non-object-list", (_json(200, [_sle_entry()]), None)),
    ("non-object-string", (_json(200, "success"), None)),
    ("non-object-number", (_json(200, 200), None)),
    ("non-object-null", (_json(200, None), None)),
    ("status-error", (_json(200, NOT_FOUND_ENVELOPE), None)),
    (
        "status-error-with-array-data",
        (_json(200, {"status": "error", "data": [_sle_entry()]}), None),
    ),
    ("status-fail", (_json(200, {"status": "fail", "data": [_sle_entry()]}), None)),
    ("status-unknown", (_json(200, {"status": "ok", "data": [_sle_entry()]}), None)),
    (
        "status-wrong-case",
        (_json(200, {"status": "Success", "data": [_sle_entry()]}), None),
    ),
    ("missing-status", (_json(200, {"data": [_sle_entry()]}), None)),
    ("null-status", (_json(200, {"status": None, "data": [_sle_entry()]}), None)),
    ("status-true", (_json(200, {"status": True, "data": [_sle_entry()]}), None)),
    ("status-int", (_json(200, {"status": 1, "data": [_sle_entry()]}), None)),
    ("corrupt-gzip", (_corrupt_gzip(200), "DecodingError")),
]

_DATA_NOT_ARRAY: list[tuple[str, dict[str, Any]]] = [
    ("missing-data", {"status": "success"}),
    ("missing-data-other-key", {"status": "success", "results": [_sle_entry()]}),
    ("data-object", {"status": "success", "data": {"0": _sle_entry()}}),
    ("data-string", {"status": "success", "data": SLE_CODESTREAM}),
    ("data-null", {"status": "success", "data": None}),
    ("data-int", {"status": "success", "data": 1}),
    ("data-bool", {"status": "success", "data": True}),
]


@pytest.mark.unit
class TestEnvelopeAndPairing:
    async def test_200_success_with_entries_returns_maintained_package(
        self,
    ) -> None:
        outcome = await _fetch(_json(200, _success(_sle_entry(), _slfo_entry())))

        assert _found(outcome) == MaintainedPackage(
            codestreams=(SLE_RECORD, SLFO_RECORD)
        )
        assert outcome.logs == []

    async def test_200_success_with_empty_data_returns_not_found(self) -> None:
        outcome = await _fetch(_json(200, _success()))

        _assert_not_found(outcome)

    @pytest.mark.parametrize("body", _values(_NOT_FOUND_404), ids=_ids(_NOT_FOUND_404))
    async def test_404_with_valid_error_envelope_returns_not_found(
        self, body: Any
    ) -> None:
        outcome = await _fetch(_json(404, body))

        _assert_not_found(outcome)

    @pytest.mark.parametrize(
        ("respond", "error_type"), _values(_ENVELOPE_404), ids=_ids(_ENVELOPE_404)
    )
    async def test_404_without_valid_error_envelope_is_envelope_unavailable(
        self, respond: Respond, error_type: str | None
    ) -> None:
        outcome = await _fetch(respond)

        _assert_unavailable(outcome, "envelope", status_code=404, error_type=error_type)

    @pytest.mark.parametrize(
        ("respond", "error_type"), _values(_ENVELOPE_200), ids=_ids(_ENVELOPE_200)
    )
    async def test_200_without_success_envelope_is_envelope_unavailable(
        self, respond: Respond, error_type: str | None
    ) -> None:
        outcome = await _fetch(respond)

        _assert_unavailable(outcome, "envelope", status_code=200, error_type=error_type)

    @pytest.mark.parametrize(
        "body", _values(_DATA_NOT_ARRAY), ids=_ids(_DATA_NOT_ARRAY)
    )
    async def test_200_success_without_array_data_is_schema_unavailable(
        self, body: dict[str, Any]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        _assert_unavailable(outcome, "schema", status_code=200)

    async def test_recursion_error_while_decoding_is_envelope_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def loads(content: bytes) -> Any:
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(smelt_maintained, "json", SimpleNamespace(loads=loads))

        outcome = await _fetch(_json(200, _success(_sle_entry())))

        _assert_unavailable(
            outcome, "envelope", status_code=200, error_type="RecursionError"
        )

    async def test_deeply_nested_json_is_envelope_unavailable(self) -> None:
        # Whether the decoder exhausts its depth guard (RecursionError) or
        # reaches the unterminated end (JSONDecodeError) depends on the
        # interpreter's available C stack; the outcome is the same.
        outcome = await _fetch(_raw(200, b"[" * 100_000))

        assert outcome.result is None
        assert outcome.error is not None
        assert outcome.error.category == "envelope"
        assert outcome.error.status_code == 200
        assert outcome.error.error_type in {"RecursionError", "JSONDecodeError"}
        assert outcome.logs == []


def _valid_json_success(status_code: int) -> Respond:
    return _json(status_code, _success(_sle_entry()))


def _valid_json_error(status_code: int) -> Respond:
    return _json(status_code, NOT_FOUND_ENVELOPE)


def _invalid_json(status_code: int) -> Respond:
    return _raw(status_code, b"<html>fictional</html>")


def _empty_body(status_code: int) -> Respond:
    return _raw(status_code, b"")


@pytest.mark.unit
class TestHttpStatusFailure:
    """Any status other than 200 and 404; the body is never read (D3)."""

    @pytest.mark.parametrize(
        "status_code", [301, 302, 307, 308, 400, 401, 403, 429, 500, 502, 503, 201]
    )
    @pytest.mark.parametrize(
        "body",
        [_valid_json_success, _valid_json_error, _invalid_json, _empty_body],
        ids=["jsend-success", "jsend-error", "invalid-json", "empty"],
    )
    async def test_unexpected_status_is_http_status_unavailable(
        self, status_code: int, body: Callable[[int], Respond]
    ) -> None:
        outcome = await _fetch(body(status_code))

        _assert_unavailable(outcome, "http_status", status_code=status_code)

    @pytest.mark.parametrize("status_code", [301, 429, 500, 503])
    async def test_corrupt_compressed_body_is_not_read(self, status_code: int) -> None:
        outcome = await _fetch(_corrupt_gzip(status_code))

        _assert_unavailable(outcome, "http_status", status_code=status_code)

    @pytest.mark.parametrize("status_code", [302, 500, 503])
    async def test_failing_body_transfer_is_not_read(self, status_code: int) -> None:
        outcome = await _fetch(_body_read_failure(status_code, httpx.ReadError(MARKER)))

        _assert_unavailable(outcome, "http_status", status_code=status_code)

    async def test_server_error_after_shared_retries_is_http_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleep = AsyncMock()
        monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=sleep))
        attempts: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(request)
            return httpx.Response(503, json=NOT_FOUND_ENVELOPE)

        client = _real_shared_client(monkeypatch, handler)
        async with client:
            with (
                capture_logs() as logs,
                pytest.raises(MaintainedPackageUnavailableError) as raised,
            ):
                await fetch_maintained_package(client, package_name=PACKAGE)

        assert len(attempts) == 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]
        assert raised.value.category == "http_status"
        assert raised.value.status_code == 503
        assert raised.value.error_type is None
        assert logs == []


_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def _real_shared_client(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> httpx.AsyncClient:
    """A `create_http_client` client whose innermost transport is `handler`.

    The shared factory and its retry transport are real; only the network
    transport it wraps is substituted. Environment proxies are cleared so
    that no proxy mount bypasses the substituted transport.
    """
    for variable in _PROXY_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(
        httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(handler)
    )
    return http_client.create_http_client("smelt-maintained-test")


@pytest.mark.unit
class TestTransportFailure:
    """No HTTP response after the shared transport retries."""

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.PoolTimeout,
            httpx.ReadError,
            httpx.ProxyError,
            httpx.RemoteProtocolError,
        ],
        ids=lambda error: error.__name__,
    )
    async def test_transport_error_is_transport_unavailable(
        self, error: type[httpx.TransportError]
    ) -> None:
        outcome = await _fetch(_raise(error("fictional transport failure")))

        _assert_unavailable(outcome, "transport", error_type=error.__name__)

    @pytest.mark.parametrize("status_code", [200, 404])
    @pytest.mark.parametrize(
        "error",
        [httpx.ReadError, httpx.ReadTimeout, httpx.RemoteProtocolError],
        ids=lambda error: error.__name__,
    )
    async def test_transport_error_while_reading_body_is_transport_unavailable(
        self, status_code: int, error: type[httpx.TransportError]
    ) -> None:
        outcome = await _fetch(
            _body_read_failure(status_code, error("fictional connection reset"))
        )

        _assert_unavailable(
            outcome, "transport", status_code=status_code, error_type=error.__name__
        )

    async def test_transport_failure_after_shared_retries_is_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleep = AsyncMock()
        monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=sleep))
        attempts: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(request)
            raise httpx.ConnectError("fictional connection refused", request=request)

        client = _real_shared_client(monkeypatch, handler)
        async with client:
            with (
                capture_logs() as logs,
                pytest.raises(MaintainedPackageUnavailableError) as raised,
            ):
                await fetch_maintained_package(client, package_name=PACKAGE)

        assert len(attempts) == 4
        assert {str(request.url) for request in attempts} == {ENDPOINT}
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]
        assert raised.value.category == "transport"
        assert raised.value.status_code is None
        assert raised.value.error_type == "ConnectError"
        assert logs == []


# ---------------------------------------------------------------------------
# Entry validation (whole-response rejection as `schema`)
# ---------------------------------------------------------------------------


def _rejected(broken: Any) -> dict[str, Any]:
    """Valid supported and skipped entries followed by `broken`.

    The skipped entries would each warn if the response were accepted, so
    a rejected response proves that no skip warning precedes validation.
    """
    return _success(_sle_entry(), _ibs_entry(), _unknown_entry(), _slfo_entry(), broken)


def _broken(process: str = "SLE_15", **overrides: Any) -> dict[str, Any]:
    return _entry(name=BROKEN_CODESTREAM, process=process, **overrides)


def _broken_target(process: str, target: Any) -> dict[str, Any]:
    """A supported entry with one valid target followed by `target`."""
    return _broken(process, targets=[_target(CPE_THREE, FRIENDLY_THREE), target])


_NON_OBJECTS: list[tuple[str, Any]] = [
    ("string", "fictional"),
    ("int", 1),
    ("list", [{"name": BROKEN_CODESTREAM}]),
    ("null", None),
]
_BAD_NAMES: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("empty", ""),
    ("int", 1),
    ("null", None),
    ("list", [BROKEN_CODESTREAM]),
    ("bool", True),
    ("256-chars", "n" * 256),
    ("nul-only", "\x00"),
    ("nul-start", f"\x00{BROKEN_CODESTREAM}"),
    ("nul-middle", f"{BROKEN_CODESTREAM}\x00{BROKEN_CODESTREAM}"),
    ("nul-end", f"{BROKEN_CODESTREAM}\x00"),
]
_BAD_TYPES: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("null", None),
    ("int", 1),
    ("list", ["SLFO"]),
    ("empty", ""),
    ("lowercase-slfo", "slfo"),
    ("lowercase-sle-15", "sle_15"),
    ("undeclared", "SLE_12"),
    ("padded", " SLFO"),
]
_BAD_TARGETS: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("null", None),
    ("string", CPE_ONE),
    ("object", {"product": {"cpe": CPE_ONE}}),
    ("int", 1),
    ("empty", []),
]
_BAD_PRODUCTS: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("null", None),
    ("string", CPE_ONE),
    ("list", [{"cpe": CPE_ONE}]),
]
_BAD_CPES: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("empty", ""),
    ("int", 1),
    ("null", None),
    ("list", [CPE_ONE]),
    ("bool", False),
    ("nul-only", "\x00"),
    ("nul-start", f"\x00{CPE_ONE}"),
    ("nul-middle", f"{CPE_ONE}\x00{CPE_ONE}"),
    ("nul-end", f"{CPE_ONE}\x00"),
]

_SCHEMA_REJECTIONS: list[tuple[str, dict[str, Any]]] = [
    *[(f"entry-{kind}", _rejected(value)) for kind, value in _NON_OBJECTS],
    ("codestream-missing", _rejected(_broken(codestream=_OMIT))),
    *[
        (f"codestream-{kind}", _rejected(_broken(codestream=value)))
        for kind, value in _NON_OBJECTS
    ],
    *[
        (f"{process}-name-{kind}", _rejected(_entry(name=value, process=process)))
        for process in _DECLARED_TYPES
        for kind, value in _BAD_NAMES
    ],
    *[
        (f"type-{kind}", _rejected(_broken(process=value)))
        for kind, value in _BAD_TYPES
    ],
    *[
        (f"{process}-targets-{kind}", _rejected(_broken(process, targets=value)))
        for process in _SUPPORTED_TYPES
        for kind, value in _BAD_TARGETS
    ],
    *[
        (f"{process}-target-{kind}", _rejected(_broken_target(process, value)))
        for process in _SUPPORTED_TYPES
        for kind, value in _NON_OBJECTS
    ],
    *[
        (
            f"{process}-product-{kind}",
            _rejected(_broken_target(process, _target(product=value))),
        )
        for process in _SUPPORTED_TYPES
        for kind, value in _BAD_PRODUCTS
    ],
    *[
        (f"{process}-cpe-{kind}", _rejected(_broken_target(process, _target(value))))
        for process in _SUPPORTED_TYPES
        for kind, value in _BAD_CPES
    ],
    (
        "repeated-name-supported",
        _success(_sle_entry(), _entry(name=SLE_CODESTREAM, process="SLFO")),
    ),
    ("repeated-name-identical-entries", _success(_sle_entry(), _sle_entry())),
    (
        "repeated-name-supported-and-skipped",
        _success(
            _sle_entry(),
            _unknown_entry(),
            _entry(name=SLE_CODESTREAM, process="SLFO_IBS"),
        ),
    ),
    (
        "repeated-name-skipped-and-supported",
        _success(
            _ibs_entry(),
            _unknown_entry(),
            _entry(name=SLFO_IBS_CODESTREAM, process="SLFO"),
        ),
    ),
    (
        "repeated-name-two-skipped",
        _success(
            _sle_entry(),
            _ibs_entry(),
            _entry(name=SLFO_IBS_CODESTREAM, process="UNKNOWN"),
        ),
    ),
]


@pytest.mark.unit
class TestEntryValidation:
    @pytest.mark.parametrize(
        "body", _values(_SCHEMA_REJECTIONS), ids=_ids(_SCHEMA_REJECTIONS)
    )
    async def test_invalid_entry_rejects_whole_response_without_skip_warning(
        self, body: dict[str, Any]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        _assert_unavailable(outcome, "schema", status_code=200)

    @pytest.mark.parametrize("process", _SUPPORTED_TYPES)
    @pytest.mark.parametrize(
        "name",
        ["n" * REFERENCE_MAX_LENGTH, "é" * REFERENCE_MAX_LENGTH, "n"],
        ids=["255-ascii", "255-non-ascii", "one-char"],
    )
    async def test_supported_name_within_limit_is_accepted(
        self, process: str, name: str
    ) -> None:
        outcome = await _fetch(_json(200, _success(_entry(name=name, process=process))))

        (codestream,) = _found(outcome).codestreams
        assert codestream.name == name
        assert outcome.logs == []

    @pytest.mark.parametrize("process", _SKIPPED_TYPES)
    async def test_skipped_name_at_limit_is_accepted(self, process: str) -> None:
        name = "n" * REFERENCE_MAX_LENGTH

        outcome = await _fetch(
            _json(200, _success(_entry(name=name, process=process, targets=None)))
        )

        assert _found(outcome) == MaintainedPackage(codestreams=())
        (record,) = outcome.logs
        assert record["codestream"] == name

    async def test_name_is_not_trimmed_or_normalized(self) -> None:
        names = [" Example:Padded ", "Example:Padded", "example:padded"]

        outcome = await _fetch(
            _json(200, _success(*(_entry(name=name) for name in names)))
        )

        result = _found(outcome)
        assert [codestream.name for codestream in result.codestreams] == names


# ---------------------------------------------------------------------------
# Skipped maintenance processes (SLFO_IBS, UNKNOWN)
# ---------------------------------------------------------------------------

_UNVALIDATED_TARGETS: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("null", None),
    ("string", "fictional"),
    ("object", {"product": None}),
    ("empty", []),
    ("garbage-list", [None, 1, "x", {"product": {"cpe": 1}}, {"product": None}]),
    ("nul-cpe", [_target(f"{CPE_THREE}\x00", FRIENDLY_THREE)]),
    ("valid", [_target(CPE_THREE, FRIENDLY_THREE)]),
]


@pytest.mark.unit
class TestSkippedCodestreams:
    @pytest.mark.parametrize(
        "targets", _values(_UNVALIDATED_TARGETS), ids=_ids(_UNVALIDATED_TARGETS)
    )
    async def test_slfo_ibs_entry_is_skipped_with_one_unsupported_warning(
        self, targets: Any
    ) -> None:
        outcome = await _fetch(_json(200, _success(_sle_entry(), _ibs_entry(targets))))

        assert _found(outcome) == MaintainedPackage(codestreams=(SLE_RECORD,))
        assert outcome.logs == [_unsupported_warning()]

    @pytest.mark.parametrize(
        "targets", _values(_UNVALIDATED_TARGETS), ids=_ids(_UNVALIDATED_TARGETS)
    )
    async def test_unknown_entry_is_skipped_with_one_unknown_warning(
        self, targets: Any
    ) -> None:
        outcome = await _fetch(
            _json(200, _success(_sle_entry(), _unknown_entry(targets)))
        )

        assert _found(outcome) == MaintainedPackage(codestreams=(SLE_RECORD,))
        assert outcome.logs == [_unknown_warning()]

    async def test_all_skipped_response_returns_empty_package_not_not_found(
        self,
    ) -> None:
        outcome = await _fetch(
            _json(200, _success(_ibs_entry(None), _unknown_entry(_OMIT)))
        )

        result = _found(outcome)
        assert result == MaintainedPackage(codestreams=())
        assert not isinstance(result, MaintainedPackageNotFound)
        assert outcome.logs == [_unsupported_warning(), _unknown_warning()]

    async def test_mixed_response_returns_only_supported_in_response_order(
        self,
    ) -> None:
        second_ibs = "Example:SLFO-IBS:2.0"
        body = _success(
            _ibs_entry("fictional"),
            _slfo_entry(),
            _unknown_entry(),
            _entry(name=second_ibs, process="SLFO_IBS", targets=[None]),
            _sle_entry(),
        )

        outcome = await _fetch(_json(200, body))

        assert _found(outcome) == MaintainedPackage(
            codestreams=(SLFO_RECORD, SLE_RECORD)
        )
        assert outcome.logs == [
            _unsupported_warning(),
            _unknown_warning(),
            _unsupported_warning(second_ibs),
        ]

    async def test_warning_carries_the_unencoded_package_name(self) -> None:
        package_name = "Example Package/1"

        outcome = await _fetch(
            _json(200, _success(_ibs_entry(), _unknown_entry())),
            package_name=package_name,
        )

        assert _found(outcome) == MaintainedPackage(codestreams=())
        assert [record["package_name"] for record in outcome.logs] == [
            package_name,
            package_name,
        ]

    async def test_warning_has_exactly_the_specified_fields(self) -> None:
        outcome = await _fetch(_json(200, _success(_ibs_entry(), _unknown_entry())))

        unsupported, unknown = outcome.logs
        assert set(unsupported) == {
            "event",
            "log_level",
            "package_name",
            "codestream",
            "maintenance_process_type",
        }
        assert set(unknown) == {"event", "log_level", "package_name", "codestream"}
        assert (
            unsupported["event"] == "package_codestream_maintenance_process_unsupported"
        )
        assert unknown["event"] == "package_codestream_maintenance_process_unknown"
        assert unsupported["event"] == UNSUPPORTED_PROCESS_EVENT
        assert unknown["event"] == UNKNOWN_PROCESS_EVENT
        assert {unsupported["log_level"], unknown["log_level"]} == {"warning"}


# ---------------------------------------------------------------------------
# Mapping (Consumed fields; Single authoritative representation)
# ---------------------------------------------------------------------------


def _expected_from_fixture(body: dict[str, Any]) -> MaintainedPackage:
    """The expected result, computed directly from the fixture JSON."""
    workflow = {"SLFO": WorkflowType.GIT, "SLE_15": WorkflowType.IBS}
    return MaintainedPackage(
        codestreams=tuple(
            MaintainedCodestream(
                name=entry["codestream"]["name"],
                workflow_type=workflow[entry["codestream"]["type"]],
                targets=tuple(
                    MaintainedTarget(
                        cpe=target["product"]["cpe"],
                        friendly_name=target["product"]["friendly_name"],
                    )
                    for target in entry["targets"]
                ),
            )
            for entry in body["data"]
        )
    )


_ABSENT_FRIENDLY_NAMES: list[tuple[str, Any]] = [
    ("missing", _OMIT),
    ("null", None),
    ("empty", ""),
    ("int", 42),
    ("zero", 0),
    ("bool", False),
    ("list", [FRIENDLY_ONE]),
    ("object", {"name": FRIENDLY_ONE}),
]

_UNCONSUMED_GARBAGE: list[tuple[str, dict[str, Any]]] = [
    (
        "arbitrary-values-and-unknown-keys",
        {
            "status": "success",
            "message": [MARKER],
            "data": [
                {
                    "codestream": {
                        "name": SLE_CODESTREAM,
                        "type": "SLE_15",
                        "url": 42,
                        "extra": {"nested": [None]},
                    },
                    "binary_packages": "garbage",
                    "support_status": {"nested": 1},
                    "extra": None,
                    "targets": [
                        {
                            "product": {
                                "id": "not-an-int",
                                "friendly_name": FRIENDLY_ONE,
                                "cpe": CPE_ONE,
                                "support_status": ["x"],
                                "extra": True,
                            },
                            "repository": None,
                            "product_definition": 7,
                            "extra": [],
                        }
                    ],
                }
            ],
        },
    ),
    (
        "unconsumed-fields-omitted",
        {
            "status": "success",
            "data": [
                {
                    "codestream": {"name": SLE_CODESTREAM, "type": "SLE_15"},
                    "targets": [
                        {"product": {"cpe": CPE_ONE, "friendly_name": FRIENDLY_ONE}}
                    ],
                }
            ],
        },
    ),
    (
        "unconsumed-fields-null",
        _success(
            {
                "codestream": {"name": SLE_CODESTREAM, "type": "SLE_15", "url": None},
                "binary_packages": None,
                "support_status": None,
                "targets": [
                    {
                        "product": {
                            "id": None,
                            "cpe": CPE_ONE,
                            "friendly_name": FRIENDLY_ONE,
                            "support_status": None,
                        },
                        "repository": None,
                        "product_definition": None,
                    }
                ],
            }
        ),
    ),
]


@pytest.mark.unit
class TestMapping:
    @pytest.mark.parametrize(
        ("process", "workflow_type"),
        [("SLFO", WorkflowType.GIT), ("SLE_15", WorkflowType.IBS)],
    )
    async def test_supported_type_maps_to_workflow_type(
        self, process: str, workflow_type: WorkflowType
    ) -> None:
        outcome = await _fetch(_json(200, _success(_entry(process=process))))

        assert _found(outcome) == MaintainedPackage(
            codestreams=(
                MaintainedCodestream(
                    name=SLE_CODESTREAM,
                    workflow_type=workflow_type,
                    targets=(
                        MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE),
                    ),
                ),
            )
        )

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    async def test_sanitized_live_fixture_returns_every_record_as_received(
        self, name: str
    ) -> None:
        body = load_maintained_fixture(name)

        outcome = await _fetch(_json(200, body))

        result = _found(outcome)
        assert result == _expected_from_fixture(body)
        assert len(result.codestreams) == len(body["data"])

    async def test_codestreams_and_targets_keep_response_order(self) -> None:
        body = _success(
            _entry(
                name="Example:C",
                process="SLFO",
                targets=[_target(CPE_THREE), _target(CPE_ONE), _target(CPE_TWO)],
            ),
            _entry(name="Example:A", targets=[_target(CPE_TWO), _target(CPE_ONE)]),
            _entry(name="Example:B", process="SLFO", targets=[_target(CPE_ONE)]),
        )

        outcome = await _fetch(_json(200, body))

        result = _found(outcome)
        assert [(c.name, c.workflow_type) for c in result.codestreams] == [
            ("Example:C", WorkflowType.GIT),
            ("Example:A", WorkflowType.IBS),
            ("Example:B", WorkflowType.GIT),
        ]
        assert [[t.cpe for t in c.targets] for c in result.codestreams] == [
            [CPE_THREE, CPE_ONE, CPE_TWO],
            [CPE_TWO, CPE_ONE],
            [CPE_ONE],
        ]

    async def test_duplicate_and_channel_compose_targets_are_not_deduplicated(
        self,
    ) -> None:
        body = _success(
            _entry(
                name=SLE_CODESTREAM,
                targets=[
                    _target(CPE_ONE, FRIENDLY_ONE, definition_type="channel"),
                    _target(CPE_ONE, FRIENDLY_ONE, definition_type="compose"),
                    _target(CPE_ONE, "Example Product 1 Alias"),
                    _target(CPE_TWO, FRIENDLY_TWO),
                ],
            ),
            _entry(
                name=SLFO_CODESTREAM,
                process="SLFO",
                targets=[_target(CPE_ONE, FRIENDLY_ONE, definition_type="compose")],
            ),
        )

        outcome = await _fetch(_json(200, body))

        assert _found(outcome) == MaintainedPackage(
            codestreams=(
                MaintainedCodestream(
                    name=SLE_CODESTREAM,
                    workflow_type=WorkflowType.IBS,
                    targets=(
                        MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE),
                        MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE),
                        MaintainedTarget(
                            cpe=CPE_ONE, friendly_name="Example Product 1 Alias"
                        ),
                        MaintainedTarget(cpe=CPE_TWO, friendly_name=FRIENDLY_TWO),
                    ),
                ),
                MaintainedCodestream(
                    name=SLFO_CODESTREAM,
                    workflow_type=WorkflowType.GIT,
                    targets=(
                        MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE),
                    ),
                ),
            )
        )

    async def test_cpe_is_returned_verbatim(self) -> None:
        cpe = " CPE:/o:Example:Product-1:1 "

        outcome = await _fetch(_json(200, _success(_entry(targets=[_target(cpe)]))))

        (codestream,) = _found(outcome).codestreams
        assert [target.cpe for target in codestream.targets] == [cpe]

    @pytest.mark.parametrize(
        "friendly_name",
        _values(_ABSENT_FRIENDLY_NAMES),
        ids=_ids(_ABSENT_FRIENDLY_NAMES),
    )
    async def test_absent_friendly_name_falls_back_to_cpe_and_never_rejects(
        self, friendly_name: Any
    ) -> None:
        body = _success(
            _entry(
                targets=[
                    _target(CPE_ONE, friendly_name),
                    _target(CPE_TWO, FRIENDLY_TWO),
                ]
            )
        )

        outcome = await _fetch(_json(200, body))

        (codestream,) = _found(outcome).codestreams
        first, second = codestream.targets
        assert first == MaintainedTarget(cpe=CPE_ONE, friendly_name=None)
        assert first.log_label == CPE_ONE
        assert second.log_label == FRIENDLY_TWO
        assert outcome.logs == []

    async def test_friendly_name_containing_nul_is_returned_unchecked(self) -> None:
        """External String Admissibility covers only values that reach
        PostgreSQL; the log-only friendly name is not checked."""
        friendly_name = f"{FRIENDLY_ONE}\x00"
        body = _success(_entry(targets=[_target(CPE_ONE, friendly_name)]))

        outcome = await _fetch(_json(200, body))

        (codestream,) = _found(outcome).codestreams
        assert codestream.targets == (
            MaintainedTarget(cpe=CPE_ONE, friendly_name=friendly_name),
        )

    def test_log_label_prefers_friendly_name_over_cpe(self) -> None:
        assert MaintainedTarget(cpe=CPE_ONE, friendly_name=FRIENDLY_ONE).log_label == (
            FRIENDLY_ONE
        )
        assert MaintainedTarget(cpe=CPE_ONE, friendly_name=None).log_label == CPE_ONE

    @pytest.mark.parametrize(
        "body", _values(_UNCONSUMED_GARBAGE), ids=_ids(_UNCONSUMED_GARBAGE)
    )
    async def test_unconsumed_fields_do_not_reject_the_response(
        self, body: dict[str, Any]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        assert _found(outcome) == MaintainedPackage(codestreams=(SLE_RECORD,))
        assert outcome.logs == []

    async def test_result_is_immutable(self) -> None:
        outcome = await _fetch(_json(200, _success(_sle_entry())))

        result = _found(outcome)
        assert isinstance(result.codestreams, tuple)
        assert isinstance(result.codestreams[0].targets, tuple)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.codestreams[0].name = "Example:Changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Propagation (no conversion, no log)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPropagation:
    @pytest.mark.parametrize(
        "error",
        [
            asyncio.CancelledError(),
            SoftTimeLimitExceeded(),
            MemoryError(),
            httpx.UnsupportedProtocol("fictional unsupported protocol"),
            httpx.LocalProtocolError("fictional local protocol error"),
            RuntimeError("fictional programming error"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_non_converted_error_from_transport_propagates(
        self, error: BaseException
    ) -> None:
        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await _fetch(_raise(error))

        assert raised.value is error
        assert logs == []

    @pytest.mark.parametrize(
        "error",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda error: type(error).__name__,
    )
    async def test_non_converted_error_while_reading_body_propagates(
        self, error: BaseException
    ) -> None:
        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await _fetch(_body_read_failure(200, error))

        assert raised.value is error
        assert logs == []

    async def test_memory_error_during_json_decoding_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def loads(content: bytes) -> Any:
            raise MemoryError

        monkeypatch.setattr(smelt_maintained, "json", SimpleNamespace(loads=loads))

        with capture_logs() as logs, pytest.raises(MemoryError):
            await _fetch(_json(200, _success(_sle_entry())))

        assert logs == []


# ---------------------------------------------------------------------------
# Privacy (logging.md, Secrets and PII Discipline)
# ---------------------------------------------------------------------------

_RAW_FRAGMENTS = (
    MARKER,
    "smelt.example.test",
    "other.example.test",
    "build.example.invalid",
    "https://",
    "/api",
    "/maintained",
    "include_reactive_ltss",
    "cpe:/",
    "Example Product",
    "not found",
    '"status"',
    "<html>",
    "validation error",
    "input_value",
    "input_type",
    "Expecting value",
    "can't decode",
)


def _private_entry() -> dict[str, Any]:
    return _entry(
        name=f"Example:{MARKER}",
        targets=[_target(f"cpe:/o:example:{MARKER}:1", f"Example Product {MARKER}")],
    )


# (responder, category, status_code, converted from another exception).
_PRIVACY_CASES: list[tuple[str, tuple[Respond, str, int | None, bool]]] = [
    (
        "transport-error-message",
        (
            _raise(httpx.ConnectError(f"refused by {ENDPOINT} ({MARKER})")),
            "transport",
            None,
            True,
        ),
    ),
    (
        "transport-error-while-reading-body",
        (
            _body_read_failure(
                200, httpx.ReadError(f"reset reading {ENDPOINT} {MARKER}")
            ),
            "transport",
            200,
            True,
        ),
    ),
    (
        "http-status-with-private-body",
        (_json(500, _success(_private_entry())), "http_status", 500, False),
    ),
    ("redirect-location", (_redirect(302), "http_status", 302, False)),
    (
        "envelope-404-invalid-json",
        (_raw(404, f"<html>{MARKER} not found</html>".encode()), "envelope", 404, True),
    ),
    (
        "envelope-404-status-fail",
        (_json(404, {"status": "fail", "data": MARKER}), "envelope", 404, False),
    ),
    (
        "envelope-200-status-error",
        (_json(200, {"status": "error", "data": MARKER}), "envelope", 200, False),
    ),
    (
        "envelope-200-invalid-utf8",
        (
            _raw(200, f'{{"status": "{MARKER}\xff"}}'.encode("latin-1")),
            "envelope",
            200,
            True,
        ),
    ),
    ("envelope-200-corrupt-gzip", (_corrupt_gzip(200), "envelope", 200, True)),
    (
        "schema-data-not-array",
        (_json(200, {"status": "success", "data": MARKER}), "schema", 200, True),
    ),
    (
        "schema-entry-with-private-values",
        (
            _json(200, _success(_private_entry(), _entry(name=1, process=MARKER))),
            "schema",
            200,
            True,
        ),
    ),
    (
        "schema-target-with-private-values",
        (
            _json(
                200,
                _success(
                    _private_entry(),
                    _broken(targets=[_target(f"cpe:/o:example:{MARKER}:2"), MARKER]),
                ),
            ),
            "schema",
            200,
            True,
        ),
    ),
    (
        "schema-repeated-private-name",
        (
            _json(200, _success(_private_entry(), _private_entry())),
            "schema",
            200,
            False,
        ),
    ),
]


@pytest.mark.unit
class TestPrivacy:
    @pytest.mark.parametrize(
        ("respond", "category", "status_code", "converted"),
        _values(_PRIVACY_CASES),
        ids=_ids(_PRIVACY_CASES),
    )
    async def test_unavailable_error_carries_only_bounded_fields(
        self,
        respond: Respond,
        category: str,
        status_code: int | None,
        converted: bool,
    ) -> None:
        outcome = await _fetch(respond)

        assert outcome.logs == []
        error = outcome.error
        assert error is not None
        assert error.args == (category,)
        assert str(error) == category
        assert error.category == category
        assert error.status_code == status_code
        assert set(vars(error)) == {"category", "status_code", "error_type"}
        assert error.error_type is None or error.error_type.isidentifier()
        assert error.__cause__ is None
        if converted:
            assert error.__suppress_context__ is True
            assert error.__context__ is not None
        else:
            assert error.__context__ is None
        rendered = "".join(
            [
                *traceback.format_exception(error),
                repr(error),
                repr(vars(error)),
                repr(outcome.logs),
            ]
        )
        for fragment in (*_RAW_FRAGMENTS, PACKAGE):
            assert fragment not in rendered

    async def test_skip_warnings_contain_no_body_url_or_target_data(self) -> None:
        private_targets = [
            _target(f"cpe:/o:example:{MARKER}:1", f"Example Product {MARKER}"),
            MARKER,
        ]
        body = _success(
            _private_entry(),
            _ibs_entry(private_targets),
            _unknown_entry(private_targets),
        )

        outcome = await _fetch(_json(200, body))

        assert _found(outcome).codestreams
        assert outcome.logs == [_unsupported_warning(), _unknown_warning()]
        rendered = repr(outcome.logs)
        for fragment in _RAW_FRAGMENTS:
            assert fragment not in rendered

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    async def test_success_path_without_skips_emits_no_log_record(
        self, name: str
    ) -> None:
        outcome = await _fetch(_json(200, load_maintained_fixture(name)))

        assert _found(outcome).codestreams
        assert outcome.logs == []


# ---------------------------------------------------------------------------
# Boundary (package-service.md, Module invariant: I/O-then-Lock pattern)
# ---------------------------------------------------------------------------

_FORBIDDEN_MODULES = ("sqlalchemy", "app.models", "app.database", "app.db")
_FORBIDDEN_NAMES = frozenset(
    {
        "AsyncSession",
        "async_sessionmaker",
        "async_session_factory",
        "get_db",
        "with_for_update",
        "engine",
        "lock_accessible_ticket",
        "lock_accessible_ticket_by_locator",
    }
)
_FORBIDDEN_NAME_PARTS = ("session", "lock", "commit", "transaction")


@pytest.mark.unit
class TestIoOnlyBoundary:
    @staticmethod
    def _tree() -> ast.Module:
        source = Path(smelt_maintained.__file__).read_text(encoding="utf-8")
        return ast.parse(source)

    def test_module_imports_no_database_or_model_module(self) -> None:
        imported: list[str] = []
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.append(node.module)
                imported.extend(f"{node.module}.{a.name}" for a in node.names)

        assert imported
        for module in imported:
            for forbidden in _FORBIDDEN_MODULES:
                assert module != forbidden
                assert not module.startswith(f"{forbidden}.")

    def test_module_references_no_session_or_lock_name(self) -> None:
        names: set[str] = set()
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
            elif isinstance(
                node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
            ):
                names.add(node.name)

        assert names
        assert names.isdisjoint(_FORBIDDEN_NAMES)
        for name in names:
            for part in _FORBIDDEN_NAME_PARTS:
                assert part not in name.lower()

    def test_reference_limit_equals_track_reference_column_length(self) -> None:
        column_type = TicketPackageTrack.__table__.c.reference.type

        assert isinstance(column_type, String)
        assert REFERENCE_MAX_LENGTH == 255
        assert column_type.length == REFERENCE_MAX_LENGTH
