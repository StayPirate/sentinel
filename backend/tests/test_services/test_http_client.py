"""Tests for the shared HTTP client factory and TLS trust store
(backend/app/services/http_client.py).

All tests are unit tests: no database, no real network I/O, no real
sleeps. Retry sleeps are verified via a monkeypatched `asyncio.sleep`
that records call arguments instead of waiting. TLS tests never rely on
the default `SUSE_CA_CERT_PATH` (or the process CWD) — every path is
passed explicitly.
"""

from __future__ import annotations

import asyncio
import gzip
import ssl
import tracemalloc
import zlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest

from app.config import settings as app_settings
from app.core.exceptions import TLSConfigurationError
from app.services import http_client as hc

# The real SUSE Trust Root CA committed in the repository. Not a secret —
# a public CA certificate — safe to reference directly in tests instead
# of generating a throwaway certificate.
_REAL_CA_PATH = Path(__file__).resolve().parents[2] / "certs" / "SUSE_Trust_Root.crt"


@pytest.fixture(autouse=True)
def _isolated_ca_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure every test uses an explicit CA path, never the CWD-relative
    default — prevents tests from depending on the working directory."""
    monkeypatch.setattr(app_settings, "suse_ca_cert_path", str(_REAL_CA_PATH))


# ---------------------------------------------------------------------------
# build_tls_context()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBuildTlsContext:
    def test_valid_ca_returns_combined_context(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            context = hc.build_tls_context()
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        # Distinguishes "SUSE CA successfully loaded" from the "missing"
        # fallback path below, which also returns a CERT_REQUIRED context
        # (system-only) — the absence of the missing-CA warning is the
        # signal that the combined trust store branch actually ran.
        assert "suse_ca_cert_missing" not in caplog.text

    def test_missing_ca_warns_and_returns_system_only_context(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        missing_path = tmp_path / "does-not-exist.crt"
        monkeypatch.setattr(app_settings, "suse_ca_cert_path", str(missing_path))
        with caplog.at_level("WARNING"):
            context = hc.build_tls_context()
        assert isinstance(context, ssl.SSLContext)
        assert "suse_ca_cert_missing" in caplog.text

    def test_corrupt_ca_raises_tls_configuration_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        corrupt_path = tmp_path / "corrupt.crt"
        corrupt_path.write_text("this is not a valid certificate")
        monkeypatch.setattr(app_settings, "suse_ca_cert_path", str(corrupt_path))
        with pytest.raises(TLSConfigurationError) as exc_info:
            hc.build_tls_context()
        assert str(corrupt_path) in str(exc_info.value)

    def test_context_is_fresh_on_every_call(self) -> None:
        """No module-level caching — supports certificate rotation without
        process restart (docs/features/platform/networking.md)."""
        assert hc.build_tls_context() is not hc.build_tls_context()


# ---------------------------------------------------------------------------
# create_http_client() — defaults
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCreateHttpClientDefaults:
    async def test_user_agent_format(self) -> None:
        client = hc.create_http_client("test_component")
        try:
            ua = client.headers["user-agent"]
            assert ua.startswith("Sentinel/")
            assert "(test_component; +https://github.com/StayPirate/sentinel)" in ua
        finally:
            await client.aclose()

    async def test_user_agent_dev_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_not_found(_name: str) -> str:
            from importlib.metadata import PackageNotFoundError

            raise PackageNotFoundError

        monkeypatch.setattr(hc, "get_version", _raise_not_found)
        client = hc.create_http_client("test_component")
        try:
            assert "Sentinel/dev (" in client.headers["user-agent"]
        finally:
            await client.aclose()

    async def test_accept_header_default(self) -> None:
        client = hc.create_http_client("test_component")
        try:
            assert client.headers["accept"] == "application/json"
        finally:
            await client.aclose()

    async def test_accept_header_overridable(self) -> None:
        client = hc.create_http_client(
            "ibs_client", headers={"Accept": "application/xml"}
        )
        try:
            assert client.headers["accept"] == "application/xml"
        finally:
            await client.aclose()

    async def test_timeout_defaults(self) -> None:
        client = hc.create_http_client("test_component")
        try:
            timeout = client.timeout
            assert timeout.connect == 10.0
            assert timeout.read == 30.0
            assert timeout.write == 10.0
            assert timeout.pool == 10.0
        finally:
            await client.aclose()

    async def test_follow_redirects_disabled_by_default(self) -> None:
        client = hc.create_http_client("test_component")
        try:
            assert client.follow_redirects is False
        finally:
            await client.aclose()

    async def test_no_warning_on_defaults(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            client = hc.create_http_client("test_component")
        try:
            assert "tls_verify_overridden" not in caplog.text
            assert "redirects_enabled" not in caplog.text
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# create_http_client() — override safety
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCreateHttpClientOverrideSafety:
    async def test_user_agent_not_overridable_via_headers(self) -> None:
        client = hc.create_http_client(
            "test_component", headers={"User-Agent": "custom-agent/1.0"}
        )
        try:
            ua = client.headers["user-agent"]
            assert ua != "custom-agent/1.0"
            assert ua.startswith("Sentinel/")
        finally:
            await client.aclose()

    async def test_user_agent_not_overridable_case_insensitive(self) -> None:
        """A differently-cased 'user-agent' key must not slip through as a
        duplicate header alongside the template-generated one."""
        client = hc.create_http_client(
            "test_component", headers={"USER-AGENT": "custom-agent/1.0"}
        )
        try:
            values = client.headers.get_list("user-agent")
            assert len(values) == 1
            assert values[0].startswith("Sentinel/")
        finally:
            await client.aclose()

    async def test_verify_false_warns_with_caller_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            client = hc.create_http_client("sync_nvd_cves", verify=False)
        try:
            assert "tls_verify_overridden" in caplog.text
            assert "sync_nvd_cves" in caplog.text
        finally:
            await client.aclose()

    async def test_custom_ssl_context_warns_with_caller_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        custom_context = ssl.create_default_context()
        with caplog.at_level("WARNING"):
            client = hc.create_http_client("custom_client", verify=custom_context)
        try:
            assert "tls_verify_overridden" in caplog.text
            assert "custom_client" in caplog.text
        finally:
            await client.aclose()

    async def test_follow_redirects_true_warns_with_caller_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            client = hc.create_http_client("sync_example", follow_redirects=True)
        try:
            assert "redirects_enabled" in caplog.text
            assert "sync_example" in caplog.text
            assert client.follow_redirects is True
        finally:
            await client.aclose()

    async def test_timeout_overridable(self) -> None:
        client = hc.create_http_client("test_component", timeout=httpx.Timeout(5.0))
        try:
            assert client.timeout.connect == 5.0
        finally:
            await client.aclose()

    async def test_limits_default(self) -> None:
        client = hc.create_http_client("test_component")
        try:
            transport = _retry_transport(client)
            pool = transport._inner._pool  # type: ignore[attr-defined]
            assert pool._max_connections == 100
            assert pool._max_keepalive_connections == 20
        finally:
            await client.aclose()

    async def test_limits_overridable(self) -> None:
        client = hc.create_http_client(
            "test_component",
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        )
        try:
            transport = _retry_transport(client)
            pool = transport._inner._pool  # type: ignore[attr-defined]
            assert pool._max_connections == 5
            assert pool._max_keepalive_connections == 2
        finally:
            await client.aclose()

    async def test_retry_transport_is_wired_into_client(self) -> None:
        """The client returned by the factory actually uses
        `_RetryTransport` — guards against a regression where the retry
        policy silently stops being applied (e.g., accidentally
        re-enabling httpx's built-in transport retry instead). The
        content-coding policy wraps it, so it inspects only the response
        returned to the caller."""
        client = hc.create_http_client("test_component")
        try:
            assert isinstance(client._transport, hc._ContentCodingTransport)
            assert isinstance(client._transport._inner, hc._RetryTransport)
        finally:
            await client.aclose()

    async def test_retry_non_idempotent_is_forwarded_to_transport(self) -> None:
        client = hc.create_http_client("test_component", retry_non_idempotent=True)
        try:
            assert _retry_transport(client)._retry_non_idempotent is True
        finally:
            await client.aclose()


def _retry_transport(client: httpx.AsyncClient) -> hc._RetryTransport:
    """The factory's retry transport, inside the content-coding policy."""
    transport = client._transport
    assert isinstance(transport, hc._ContentCodingTransport)
    assert isinstance(transport._inner, hc._RetryTransport)
    return transport._inner


# ---------------------------------------------------------------------------
# Response content coding
# ---------------------------------------------------------------------------

_URL: Final = "https://example.suse.de/resource"
_PAYLOAD: Final = b'{"fictional": "payload"}'
_MIB: Final = 1024 * 1024


class _NetworkBody(httpx.AsyncByteStream):
    """An unread response body, as from a real transport, that records
    how many chunks were received and whether it was closed."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.chunks_received = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for offset in range(0, len(self._data), 64 * 1024):
            self.chunks_received += 1
            yield self._data[offset : offset + 64 * 1024]

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class _Network:
    """The network behind a factory client: every request receives a
    fresh response with the configured status, headers, and body."""

    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    content: bytes = _PAYLOAD
    requests: list[httpx.Request] = field(default_factory=list)
    bodies: list[_NetworkBody] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = _NetworkBody(self.content)
        self.bodies.append(body)
        return httpx.Response(self.status, headers=self.headers, stream=body)

    def declare(self, values: list[str]) -> None:
        """One `Content-Encoding` field per value."""
        self.headers = [("Content-Encoding", value) for value in values]


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> _Network:
    """Replaces only the factory's network transport, so the
    content-coding policy and the retry transport are the production
    ones."""
    served = _Network()
    monkeypatch.setattr(
        httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(served)
    )
    return served


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _zeros_gzip(size: int) -> bytes:
    """One gzip member of `size` zero bytes, built without holding them."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    parts = [compressor.compress(bytes(_MIB)) for _ in range(size // _MIB)]
    return b"".join([*parts, compressor.flush()])


def _innermost_open_size(data: bytes, layers: int) -> int:
    """The size `data` decodes to through `layers` gzip layers, counted
    without holding the innermost output."""
    for _ in range(layers - 1):
        data = gzip.decompress(data)
    decompressor = zlib.decompressobj(31)
    size = 0
    while data:
        size += len(decompressor.decompress(data, _MIB))
        data = decompressor.unconsumed_tail
    return size + len(decompressor.flush())


# Values a response may declare: at most one of gzip and deflate, matched
# as httpx matches decoders; identity and empty elements are no coding.
_PERMITTED_CODINGS: Final = [
    pytest.param([], lambda data: data, id="absent"),
    pytest.param(["identity"], lambda data: data, id="identity"),
    pytest.param([""], lambda data: data, id="empty"),
    pytest.param(["gzip"], _gzip, id="gzip"),
    pytest.param([" GZip "], _gzip, id="gzip-case-whitespace"),
    pytest.param(["deflate"], zlib.compress, id="deflate"),
    pytest.param(["identity, gzip"], _gzip, id="identity-element"),
    pytest.param(["gzip", "identity"], _gzip, id="identity-field"),
    pytest.param([", gzip ,"], _gzip, id="empty-elements"),
]
_REJECTED_CODINGS: Final = [
    pytest.param(["gzip, gzip"], id="stacked-gzip"),
    pytest.param(["gzip", "gzip"], id="stacked-fields"),
    pytest.param(["deflate, gzip"], id="deflate-then-gzip"),
    pytest.param(["gzip, identity, gzip"], id="stacked-around-identity"),
    pytest.param(["br"], id="br"),
    pytest.param(["zstd"], id="zstd"),
    pytest.param(["x-gzip"], id="x-gzip"),
    pytest.param(["compress"], id="compress"),
    pytest.param(["fictional-coding"], id="unknown"),
    pytest.param(["gzip, br"], id="gzip-then-br"),
]


@pytest.mark.unit
class TestResponseContentCodings:
    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            pytest.param([], [], id="absent"),
            pytest.param(["gzip"], ["gzip"], id="one"),
            pytest.param([" GZip "], ["gzip"], id="case-and-whitespace"),
            pytest.param(["identity", "IDENTITY"], [], id="identity"),
            pytest.param(["", " , "], [], id="empty-elements"),
            pytest.param(["identity, deflate"], ["deflate"], id="identity-dropped"),
            pytest.param(["gzip, br"], ["gzip", "br"], id="list-in-order"),
            pytest.param(["gzip", "zstd"], ["gzip", "zstd"], id="fields-in-order"),
        ],
    )
    def test_declared_codings_are_listed_in_order(
        self, values: list[str], expected: list[str]
    ) -> None:
        headers = httpx.Headers([("Content-Encoding", value) for value in values])
        assert hc.response_content_codings(headers) == expected


@pytest.mark.unit
class TestContentCodingPolicy:
    async def test_accept_encoding_advertises_the_permitted_codings(
        self, network: _Network
    ) -> None:
        async with hc.create_http_client("test_component") as client:
            await client.get(_URL)

        [request] = network.requests
        assert request.headers.get_list("accept-encoding") == ["gzip, deflate"]

    async def test_accept_encoding_override_is_replaced(
        self, network: _Network
    ) -> None:
        async with hc.create_http_client(
            "test_component", headers={"Accept-Encoding": "br, zstd"}
        ) as client:
            assert client.headers.get_list("accept-encoding") == ["gzip, deflate"]
            await client.get(_URL)

        [request] = network.requests
        assert request.headers.get_list("accept-encoding") == ["gzip, deflate"]

    @pytest.mark.parametrize(("values", "encode"), _PERMITTED_CODINGS)
    async def test_permitted_coding_is_decoded(
        self,
        network: _Network,
        values: list[str],
        encode: Callable[[bytes], bytes],
    ) -> None:
        network.declare(values)
        network.content = encode(_PAYLOAD)

        async with hc.create_http_client("test_component") as client:
            response = await client.get(_URL)
            async with client.stream("GET", _URL) as streamed:
                chunks = [chunk async for chunk in streamed.aiter_bytes()]

        assert response.content == _PAYLOAD
        assert b"".join(chunks) == _PAYLOAD

    @pytest.mark.parametrize("values", _REJECTED_CODINGS)
    async def test_rejected_coding_fails_on_read_before_any_byte(
        self, network: _Network, values: list[str]
    ) -> None:
        network.declare(values)
        network.content = _gzip(_gzip(_PAYLOAD))

        async with hc.create_http_client("test_component") as client:
            with pytest.raises(httpx.DecodingError) as raised:
                await client.get(_URL)

        [body] = network.bodies
        assert body.chunks_received == 0
        assert body.closed
        assert raised.value.request.url == _URL
        # The bounded message never echoes the declared value.
        assert all(value.strip() not in str(raised.value) for value in values)

    @pytest.mark.parametrize("values", _REJECTED_CODINGS)
    async def test_rejected_coding_keeps_status_and_headers_until_read(
        self, network: _Network, values: list[str]
    ) -> None:
        network.declare(values)

        async with (
            hc.create_http_client("test_component") as client,
            client.stream("GET", _URL) as response,
        ):
            assert response.status_code == 200
            assert response.headers.get_list("content-encoding") == values
            with pytest.raises(httpx.DecodingError):
                async for _ in response.aiter_bytes():
                    pass

        [body] = network.bodies
        assert body.chunks_received == 0
        assert body.closed

    async def test_rejected_coding_also_fails_a_raw_read(
        self, network: _Network
    ) -> None:
        """The undecoded body is rejected too, so a reader that decodes
        the payload itself must check the declared coding first."""
        network.declare(["gzip, gzip"])

        async with (
            hc.create_http_client("test_component") as client,
            client.stream("GET", _URL) as response,
        ):
            with pytest.raises(httpx.DecodingError):
                async for _ in response.aiter_raw():
                    pass

        assert network.bodies[0].chunks_received == 0

    async def test_unread_error_response_keeps_its_http_status_error(
        self, network: _Network
    ) -> None:
        network.status = 404
        network.declare(["gzip, gzip"])

        async with (
            hc.create_http_client("test_component") as client,
            client.stream("GET", _URL) as response,
        ):
            with pytest.raises(httpx.HTTPStatusError):
                response.raise_for_status()

        assert network.bodies[0].chunks_received == 0
        assert network.bodies[0].closed

    async def test_stacked_gzip_bomb_is_never_decoded(self, network: _Network) -> None:
        """Regression: three gzip layers of a few hundred bytes decode to
        64 MiB, and each further layer multiplies that again. The policy
        rejects them before any byte is received, so memory stays flat.
        Traced memory, unlike timing, is machine-independent."""
        bomb = _gzip(_gzip(_zeros_gzip(64 * _MIB)))
        assert len(bomb) < 1024
        assert _innermost_open_size(bomb, layers=3) == 64 * _MIB
        network.declare(["gzip, gzip, gzip"])
        network.content = bomb

        async with hc.create_http_client("test_component") as client:
            started = not tracemalloc.is_tracing()
            if started:
                tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                baseline = tracemalloc.get_traced_memory()[0]
                with pytest.raises(httpx.DecodingError):
                    await client.get(_URL)
                peak = tracemalloc.get_traced_memory()[1] - baseline
            finally:
                if started:
                    tracemalloc.stop()

        assert peak < _MIB
        assert network.bodies[0].chunks_received == 0

    async def test_rejection_is_a_data_quality_failure(self, network: _Network) -> None:
        """Like any undecodable body, a rejected coding is neither an
        infrastructure failure nor retryable (Infrastructure Failure
        Classification)."""
        network.declare(["br"])

        async with hc.create_http_client("test_component") as client:
            with pytest.raises(httpx.DecodingError) as raised:
                await client.get(_URL)

        assert len(network.requests) == 1
        assert hc.is_infrastructure_failure(raised.value) is False
        assert hc.is_retryable_condition(raised.value) is False


# ---------------------------------------------------------------------------
# Retry-After parsing
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseRetryAfter:
    def test_integer_seconds(self) -> None:
        assert hc._parse_retry_after("30") == 30.0

    def test_zero_is_valid(self) -> None:
        assert hc._parse_retry_after("0") == 0.0

    def test_negative_integer_treated_as_absent(self) -> None:
        assert hc._parse_retry_after("-5") is None

    def test_decimal_value_treated_as_absent(self) -> None:
        """RFC 7231 delay-seconds is `1*DIGIT` — fractional values are not
        a valid delay-seconds and must not be silently rounded/accepted."""
        assert hc._parse_retry_after("30.5") is None

    def test_leading_decimal_point_treated_as_absent(self) -> None:
        assert hc._parse_retry_after(".5") is None

    def test_malformed_string_treated_as_absent(self) -> None:
        assert hc._parse_retry_after("not-a-value") is None

    def test_empty_string_treated_as_absent(self) -> None:
        assert hc._parse_retry_after("") is None

    def test_http_date_in_future(self) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        future = datetime.now(UTC) + timedelta(seconds=45)
        header_value = format_datetime(future, usegmt=True)
        wait = hc._parse_retry_after(header_value)
        assert wait is not None
        # Allow small scheduling jitter between construction and parsing.
        assert 40 <= wait <= 46

    def test_http_date_already_elapsed_treated_as_absent(self) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        past = datetime.now(UTC) - timedelta(seconds=10)
        header_value = format_datetime(past, usegmt=True)
        assert hc._parse_retry_after(header_value) is None

    def test_http_date_with_unknown_offset_is_treated_as_utc(self) -> None:
        """RFC 5322 uses a `-0000` offset to signal "no timezone
        information" (as opposed to `+0000`, meaning "confirmed UTC").
        `email.utils.parsedate_to_datetime` parses `-0000` into a
        timezone-naive `datetime`. Sentinel treats an absent timezone
        as UTC rather than propagating a naive datetime into the
        subsequent arithmetic against `datetime.now(UTC)`."""
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        # Naive datetime whose wall-clock value matches UTC-now + 45s, so
        # that treating it as UTC (as the code under test does) yields the
        # expected delay regardless of the host's local timezone.
        future_utc_naive = (datetime.now(UTC) + timedelta(seconds=45)).replace(
            tzinfo=None
        )
        header_value = format_datetime(future_utc_naive)  # renders "-0000"
        wait = hc._parse_retry_after(header_value)
        assert wait is not None
        # Allow small scheduling jitter between construction and parsing.
        assert 40 <= wait <= 46


# ---------------------------------------------------------------------------
# _RetryTransport — test double
# ---------------------------------------------------------------------------


class _ScriptedTransport(httpx.AsyncBaseTransport):
    """A fake inner transport that plays back a scripted sequence of
    responses/exceptions, one per call to `handle_async_request`."""

    def __init__(self, script: list[Any]) -> None:
        self._script = list(script)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        item = self._script[self.calls]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        assert isinstance(item, httpx.Response)
        item.request = request
        return item

    async def aclose(self) -> None:
        pass


def _response(
    status_code: int, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status_code, headers=headers or {})


def _request(method: str = "GET") -> httpx.Request:
    return httpx.Request(method, "https://example.suse.de/resource")


@pytest.fixture
def mock_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    sleep_mock = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep_mock)
    return sleep_mock


# ---------------------------------------------------------------------------
# Transport-level retry — 5xx
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetryOn5xx:
    async def test_5xx_retried_four_attempts_then_returned(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(500) for _ in range(4)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 500
        assert inner.calls == 4
        assert mock_sleep.await_count == 3
        assert [c.args[0] for c in mock_sleep.await_args_list] == [1.0, 2.0, 4.0]

    async def test_5xx_succeeds_after_retry(self, mock_sleep: AsyncMock) -> None:
        script = [_response(500), _response(500), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 3
        assert mock_sleep.await_count == 2

    async def test_5xx_retried_for_post(self, mock_sleep: AsyncMock) -> None:
        """5xx retry applies to all methods, including non-idempotent ones."""
        script = [_response(503, {}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("POST"))

        assert response.status_code == 200
        assert inner.calls == 2

    async def test_4xx_non_429_not_retried(self, mock_sleep: AsyncMock) -> None:
        script = [_response(404)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 404
        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_discarded_response_is_closed_in_fixed_backoff_path(
        self, mock_sleep: AsyncMock
    ) -> None:
        """A bare 5xx with no `Retry-After` header takes the fixed-backoff
        path (not the guided path). The discarded response must still be
        closed before the retry, same as the guided path."""
        discarded = _response(500)
        script = [discarded, _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        await transport.handle_async_request(_request("GET"))

        assert discarded.is_closed


# ---------------------------------------------------------------------------
# Transport-level retry — connection/timeout/proxy/protocol errors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetryOnConnectionErrors:
    async def test_connect_error_retried_for_idempotent_method(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [
            httpx.ConnectError("boom"),
            httpx.ConnectError("boom"),
            _response(200),
        ]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 3
        assert mock_sleep.await_count == 2

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"])
    async def test_connect_error_retried_for_every_idempotent_method(
        self, mock_sleep: AsyncMock, method: str
    ) -> None:
        """The full idempotent-method matrix: GET, HEAD, OPTIONS, PUT, and
        DELETE all retry on connection error without any opt-in, per the
        Method Safety contract in `docs/features/platform/networking.md`."""
        script = [httpx.ConnectError("boom"), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request(method))

        assert response.status_code == 200
        assert inner.calls == 2
        assert mock_sleep.await_count == 1

    @pytest.mark.parametrize("method", ["POST", "PATCH"])
    async def test_connect_error_not_retried_for_non_idempotent_method_by_default(
        self, mock_sleep: AsyncMock, method: str
    ) -> None:
        """Neither POST nor PATCH retries on connection error without the
        `retry_non_idempotent` opt-in — retrying risks duplicate writes."""
        script = [httpx.ConnectError("boom")]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        with pytest.raises(httpx.ConnectError):
            await transport.handle_async_request(_request(method))

        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_connect_error_exhausts_after_four_attempts(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [httpx.ConnectError("boom") for _ in range(4)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        with pytest.raises(httpx.ConnectError):
            await transport.handle_async_request(_request("GET"))

        assert inner.calls == 4
        assert mock_sleep.await_count == 3

    async def test_read_timeout_not_retried_for_post_by_default(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [httpx.ReadTimeout("timed out")]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        with pytest.raises(httpx.ReadTimeout):
            await transport.handle_async_request(_request("POST"))

        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_read_timeout_retried_for_post_when_opted_in(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [httpx.ReadTimeout("timed out"), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=True)

        response = await transport.handle_async_request(_request("POST"))

        assert response.status_code == 200
        assert inner.calls == 2

    async def test_proxy_error_retried_like_connection_error(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [httpx.ProxyError("tunnel failed"), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2

    async def test_remote_protocol_error_retried_like_connection_error(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [httpx.RemoteProtocolError("bad response"), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2


# ---------------------------------------------------------------------------
# Transport-level retry — Retry-After guided path
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetryAfterGuidedPath:
    async def test_429_with_retry_after_under_boundary_retried_once(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(429, {"Retry-After": "5"}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2
        mock_sleep.assert_awaited_once_with(5.0)

    async def test_503_with_retry_after_under_boundary_retried_once(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(503, {"Retry-After": "10"}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2
        mock_sleep.assert_awaited_once_with(10.0)

    async def test_exactly_120_seconds_is_retried(self, mock_sleep: AsyncMock) -> None:
        script = [_response(429, {"Retry-After": "120"}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2
        mock_sleep.assert_awaited_once_with(120.0)

    async def test_over_120_seconds_not_retried(self, mock_sleep: AsyncMock) -> None:
        script = [_response(429, {"Retry-After": "121"})]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 429
        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_503_over_120_seconds_not_retried_even_though_5xx(
        self, mock_sleep: AsyncMock
    ) -> None:
        """A Retry-After > 120s on a 503 overrides the generic 5xx
        fixed-backoff eligibility entirely — no retry at all."""
        script = [_response(503, {"Retry-After": "300"})]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 503
        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_429_without_retry_after_not_retried(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(429)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 429
        assert inner.calls == 1
        assert mock_sleep.await_count == 0

    async def test_503_without_retry_after_uses_fixed_backoff(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(503), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2
        mock_sleep.assert_awaited_once_with(1.0)

    async def test_malformed_retry_after_falls_back_to_fixed_backoff(
        self, mock_sleep: AsyncMock
    ) -> None:
        script = [_response(503, {"Retry-After": "garbage"}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        mock_sleep.assert_awaited_once_with(1.0)

    async def test_guided_retry_is_final_attempt_even_if_it_fails_again(
        self, mock_sleep: AsyncMock
    ) -> None:
        """Path exclusivity: after the single guided retry, no further
        fixed-backoff retries are attempted even if the second response
        is again a 5xx/429."""
        script = [_response(429, {"Retry-After": "1"}), _response(500)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 500
        assert inner.calls == 2
        assert mock_sleep.await_count == 1

    async def test_discarded_response_is_closed_before_retry(
        self, mock_sleep: AsyncMock
    ) -> None:
        discarded = _response(503, {"Retry-After": "1"})
        script = [discarded, _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        await transport.handle_async_request(_request("GET"))

        assert discarded.is_closed

    async def test_guided_retry_propagates_exception_as_final_attempt(
        self, mock_sleep: AsyncMock
    ) -> None:
        """If the single guided retry itself raises a connection error,
        the exception propagates — this is the last attempt, there is no
        further catch/retry around it."""
        script = [
            _response(429, {"Retry-After": "1"}),
            httpx.ConnectError("boom"),
        ]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        with pytest.raises(httpx.ConnectError):
            await transport.handle_async_request(_request("GET"))

        assert inner.calls == 2
        assert mock_sleep.await_count == 1

    async def test_502_with_retry_after_ignores_guided_path(
        self, mock_sleep: AsyncMock
    ) -> None:
        """The guided Retry-After path is restricted to 429/503 per the
        dispatch rule. A 502 carrying Retry-After does not qualify — it
        falls through to the generic 5xx fixed-backoff rule instead."""
        script = [_response(502, {"Retry-After": "5"}), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        response = await transport.handle_async_request(_request("GET"))

        assert response.status_code == 200
        assert inner.calls == 2
        mock_sleep.assert_awaited_once_with(1.0)


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetrySleepCancellation:
    async def test_sleep_uses_asyncio_sleep(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Retry sleeps must go through asyncio.sleep() so they are
        cancellable on SoftTimeLimitExceeded / task revocation."""
        calls: list[float] = []

        async def _tracking_sleep(seconds: float) -> None:
            calls.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", _tracking_sleep)
        script = [_response(500), _response(200)]
        inner = _ScriptedTransport(script)
        transport = hc._RetryTransport(inner, retry_non_idempotent=False)

        await transport.handle_async_request(_request("GET"))

        assert calls == [1.0]


# ---------------------------------------------------------------------------
# is_infrastructure_failure()
# ---------------------------------------------------------------------------


def _status_error(status_code: int) -> httpx.HTTPStatusError:
    request = _request()
    response = _response(status_code)
    response.request = request
    return httpx.HTTPStatusError("error", request=request, response=response)


@pytest.mark.unit
class TestIsInfrastructureFailure:
    @pytest.mark.parametrize(
        "exc",
        [
            httpx.ConnectError("x"),
            httpx.ReadError("x"),
            httpx.WriteError("x"),
            httpx.CloseError("x"),
            httpx.ConnectTimeout("x"),
            httpx.ReadTimeout("x"),
            httpx.WriteTimeout("x"),
            httpx.PoolTimeout("x"),
            httpx.ProxyError("x"),
            httpx.RemoteProtocolError("x"),
        ],
    )
    def test_network_and_timeout_errors_are_infra_failures(
        self, exc: Exception
    ) -> None:
        assert hc.is_infrastructure_failure(exc) is True

    def test_5xx_status_error_is_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(_status_error(500)) is True
        assert hc.is_infrastructure_failure(_status_error(503)) is True

    def test_4xx_status_error_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(_status_error(404)) is False
        assert hc.is_infrastructure_failure(_status_error(429)) is False

    def test_decoding_error_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(httpx.DecodingError("x")) is False

    def test_too_many_redirects_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(httpx.TooManyRedirects("x")) is False

    def test_local_protocol_error_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(httpx.LocalProtocolError("x")) is False

    def test_unsupported_protocol_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(httpx.UnsupportedProtocol("x")) is False

    def test_generic_exception_is_not_infra_failure(self) -> None:
        assert hc.is_infrastructure_failure(ValueError("bad data")) is False


# ---------------------------------------------------------------------------
# is_retryable_condition()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsRetryableCondition:
    def test_network_errors_are_retryable(self) -> None:
        assert hc.is_retryable_condition(httpx.ConnectError("x")) is True

    def test_5xx_is_retryable(self) -> None:
        assert hc.is_retryable_condition(_status_error(500)) is True

    def test_429_is_retryable(self) -> None:
        """Unlike is_infrastructure_failure(), 429 IS retryable here — the
        server is reachable but rate-limiting, which clears after backoff."""
        assert hc.is_retryable_condition(_status_error(429)) is True

    def test_403_is_not_retryable(self) -> None:
        assert hc.is_retryable_condition(_status_error(403)) is False

    def test_404_is_not_retryable(self) -> None:
        assert hc.is_retryable_condition(_status_error(404)) is False

    def test_generic_exception_is_not_retryable(self) -> None:
        assert hc.is_retryable_condition(ValueError("bad data")) is False

    def test_superset_relationship_holds(self) -> None:
        """Every condition classified as an infrastructure failure must
        also be classified as retryable (superset invariant)."""
        candidates: list[Exception] = [
            httpx.ConnectError("x"),
            httpx.ReadTimeout("x"),
            httpx.ProxyError("x"),
            httpx.RemoteProtocolError("x"),
            _status_error(500),
            _status_error(503),
        ]
        for exc in candidates:
            if hc.is_infrastructure_failure(exc):
                assert hc.is_retryable_condition(exc) is True
