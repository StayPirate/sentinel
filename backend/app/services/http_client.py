"""Shared HTTP client factory and TLS trust store infrastructure.

Provides the cross-cutting HTTP client used by all outgoing network
connections from fetchers, `IBSClient`, and any future consumer, plus
the TLS trust store used by both HTTP and non-HTTP protocols (AMQPS).
No other application module creates an HTTP client or transport. See
`docs/features/platform/networking.md` for the full specification this
module implements.
"""

from __future__ import annotations

import asyncio
import email.utils
import ipaddress
import os
import re
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as get_version
from pathlib import Path
from typing import Any, Literal

import httpx
import structlog

from app.config import settings
from app.core.exceptions import TLSConfigurationError

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TLS trust store
# ---------------------------------------------------------------------------


def build_tls_context() -> ssl.SSLContext:
    """Build the combined TLS trust store (system CAs + SUSE CA).

    Returns an `ssl.SSLContext` suitable for any protocol (HTTPS, AMQPS).
    The context is built fresh on every invocation — no module-level
    caching — so a rotated CA is picked up automatically by any
    component that calls this function again (see
    `docs/features/platform/networking.md`, Certificate rotation).

    Behavior:
    - `SUSE_CA_CERT_PATH` missing: log WARNING, return system-only context.
      Whether this actually degrades connectivity to SUSE-internal
      services depends on whether the system CA bundle itself already
      trusts the SUSE CA (see `docs/features/platform/networking.md`,
      Trust Store Layering) — in the standard container image it does,
      so this path is a diagnostic signal, not necessarily a failure.
    - `SUSE_CA_CERT_PATH` corrupt/unparseable: raise `TLSConfigurationError`.
    - `SUSE_CA_CERT_PATH` valid: return combined context (system + SUSE CA).
    """
    context = ssl.create_default_context()
    ca_path = settings.suse_ca_cert_path

    if not Path(ca_path).is_file():
        logger.warning(
            "suse_ca_cert_missing",
            path=ca_path,
            detail="SUSE CA certificate not found at the configured path; "
            "using the system CA bundle only.",
        )
        return context

    try:
        context.load_verify_locations(cafile=ca_path)
    except (ssl.SSLError, OSError) as exc:
        raise TLSConfigurationError(path=ca_path, detail=str(exc)) from exc

    return context


# ---------------------------------------------------------------------------
# Retry classification
# ---------------------------------------------------------------------------

# Exception types that indicate no usable HTTP response was obtained from
# the target server (as opposed to the server responding with an error
# status code). Using parent classes ensures future httpx subclasses within
# these families are automatically covered.
INFRA_FAILURE_TYPES: tuple[type[Exception], ...] = (
    httpx.NetworkError,
    httpx.TimeoutException,
    httpx.ProxyError,
    httpx.RemoteProtocolError,
)

# HTTP methods considered idempotent per RFC 9110 Section 9.2.2. Retrying a
# non-idempotent method (POST, PATCH) on a connection/timeout error risks
# duplicate writes if the server received and began processing the request.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

# Transport-level retry backoff, in seconds, for 5xx responses and
# connection/timeout/proxy/protocol errors. 1 original attempt + 3 retries.
_FIXED_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)

# Retry-After values above this threshold (seconds) are not worth waiting
# for at the transport level — the caller propagates the error immediately.
_RETRY_AFTER_MAX_SECONDS = 120.0


def is_infrastructure_failure(exc: Exception) -> bool:
    """Classify whether an exception represents an infrastructure failure.

    Used by stateless per-CVE fetchers to drive the consecutive failure
    abort counter. Operates on exceptions that have already exhausted
    transport-level retry.

    Returns `True` for network errors, timeouts, proxy/protocol errors, and
    HTTP 5xx responses (server unreachable or persistently failing).
    Returns `False` for HTTP 4xx responses (proves reachability) and any
    other exception (data-quality error, not an infrastructure issue).
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return isinstance(exc, INFRA_FAILURE_TYPES)


def is_retryable_condition(exc: Exception) -> bool:
    """Classify whether a post-transport exception is worth retrying.

    Used by Celery task wrappers (`fetch_single_cve`, `run_catch_up`) to
    decide `self.retry()` vs immediate failure.

    Returns `True` for transient conditions where a subsequent attempt may
    succeed: infrastructure failures (network, timeout, proxy, protocol
    errors, HTTP 5xx) and rate limiting (HTTP 429). Returns `False` for
    permanent conditions: HTTP 4xx (except 429), parsing errors on HTTP
    200, and any non-httpx exception.

    This is a superset of `is_infrastructure_failure()`: every condition
    classified as an infrastructure failure is also retryable, plus HTTP
    429 (reachable but rate-limited).
    """
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return isinstance(exc, INFRA_FAILURE_TYPES)


def _parse_retry_after(value: str) -> float | None:
    """Parse a `Retry-After` header value into a wait time in seconds.

    Accepts an integer (seconds) or an HTTP-date (RFC 7231). Per RFC 7231
    Section 7.1.3, the delay-seconds form is `1*DIGIT` — decimal/fractional
    values (e.g. "30.5") are not a valid delay-seconds and are treated as
    absent, same as a negative integer. For HTTP-dates, a date that has
    already elapsed (delta <= 0) is treated as absent — this guards against
    zero-delay retries caused by server clock skew or stale dates. An
    unparseable string is treated as absent. All "absent" outcomes fall
    through to the generic status-code rule per the transport-level retry
    specification.
    """
    stripped = value.strip()

    if stripped.isascii() and stripped.isdigit():
        return float(int(stripped))

    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except ValueError, TypeError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    delta = (parsed - datetime.now(UTC)).total_seconds()
    return delta if delta > 0 else None


class _RetryTransport(httpx.AsyncBaseTransport):
    """Wraps the network transport (`_network_transport()`) with the
    transport-level retry policy specified in
    `docs/features/platform/networking.md`.

    httpx's built-in transport retry (`retries` parameter) is deliberately
    not used by the wrapped transport (`retries=0` is enforced) — it only
    covers TCP-connect failures with no awareness of HTTP method, status
    code, or `Retry-After`. This wrapper replaces it entirely.
    """

    def __init__(
        self, inner: httpx.AsyncBaseTransport, *, retry_non_idempotent: bool
    ) -> None:
        self._inner = inner
        self._retry_non_idempotent = retry_non_idempotent

    async def aclose(self) -> None:
        await self._inner.aclose()

    def _method_is_retryable_on_connection_error(self, method: str) -> bool:
        return self._retry_non_idempotent or method.upper() in _IDEMPOTENT_METHODS

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = await self._inner.handle_async_request(request)
            except INFRA_FAILURE_TYPES:
                if not self._method_is_retryable_on_connection_error(
                    request.method
                ) or attempt >= len(_FIXED_BACKOFF_SECONDS):
                    raise
                await asyncio.sleep(_FIXED_BACKOFF_SECONDS[attempt])
                attempt += 1
                continue

            decision, wait = self._classify_response(response)

            if decision == "guided":
                # Guided path: exactly one retry, then this is final —
                # mutually exclusive with the fixed-backoff path. If the
                # guided retry itself raises, the exception propagates
                # (no further catch — this is the last attempt).
                await response.aclose()
                assert wait is not None  # guided decision always carries a wait
                await asyncio.sleep(wait)
                return await self._inner.handle_async_request(request)

            if decision == "fixed_eligible" and attempt < len(_FIXED_BACKOFF_SECONDS):
                await response.aclose()
                await asyncio.sleep(_FIXED_BACKOFF_SECONDS[attempt])
                attempt += 1
                continue

            return response

    @staticmethod
    def _classify_response(
        response: httpx.Response,
    ) -> tuple[Literal["guided", "no_retry", "fixed_eligible"], float | None]:
        """Classify a response per the transport-level retry matrix.

        Dispatch rule: a `Retry-After` header on a 429/503 response takes
        precedence over the generic 5xx row. If present and parseable, it
        is either honored (<= 120s, one guided retry) or it disqualifies
        the response from any further retry entirely (> 120s) — even
        though a bare 503 would otherwise be eligible for the generic
        fixed-backoff retry. Retry-After absent or malformed is treated
        as absent, falling through to the generic status-code rule.
        """
        if response.status_code in (429, 503):
            raw = response.headers.get("retry-after")
            if raw is not None:
                wait = _parse_retry_after(raw)
                if wait is not None:
                    if wait <= _RETRY_AFTER_MAX_SECONDS:
                        return "guided", wait
                    return "no_retry", None

        if response.status_code >= 500:
            return "fixed_eligible", None
        return "no_retry", None


# ---------------------------------------------------------------------------
# Response content coding
# ---------------------------------------------------------------------------

# The content codings the shared client requests and decodes, each with the
# Python standard library. A response may apply at most one of them.
ACCEPT_ENCODING = "gzip, deflate"
_DECODABLE_CODINGS = frozenset({"gzip", "deflate"})
_REJECTED_CODING_MESSAGE = "Response content coding is outside the shared policy"


def response_content_codings(headers: httpx.Headers) -> list[str]:
    """The content codings a response declares, in the order applied.

    Every `Content-Encoding` field and comma-separated element counts,
    normalized as httpx does when it selects decoders (stripped,
    lowercased); empty elements and `identity` are not codings.
    """
    codings = (
        value.strip().lower()
        for value in headers.get_list("content-encoding", split_commas=True)
    )
    return [coding for coding in codings if coding not in ("", "identity")]


class _RejectedBodyStream(httpx.AsyncByteStream):
    """A response body that raises `httpx.DecodingError` when read, before
    any byte is received or decoded. Closing it closes the original body,
    which releases the connection."""

    def __init__(self, stream: httpx.AsyncByteStream, request: httpx.Request) -> None:
        self._stream = stream
        self._request = request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise httpx.DecodingError(_REJECTED_CODING_MESSAGE, request=self._request)
        yield b""  # pragma: no cover - makes this an async generator

    async def aclose(self) -> None:
        await self._stream.aclose()


class _ContentCodingTransport(httpx.AsyncBaseTransport):
    """Applies the response content-coding policy specified in
    `docs/features/platform/networking.md` (HTTP Response Compression).

    A final response that declares more than one content coding, or one
    other than `gzip` or `deflate`, keeps its status and headers, but its
    body fails when read. Wraps the retry transport, so only the response
    returned to the caller is inspected.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        codings = response_content_codings(response.headers)
        if len(codings) > 1 or not _DECODABLE_CODINGS.issuperset(codings):
            assert isinstance(response.stream, httpx.AsyncByteStream)
            response.stream = _RejectedBodyStream(response.stream, request)
        return response


# ---------------------------------------------------------------------------
# Proxy routing
# ---------------------------------------------------------------------------

# URL scheme -> the variable naming its proxy.
_PROXY_VARIABLES: tuple[tuple[str, str], ...] = (
    ("https", "HTTPS_PROXY"),
    ("http", "HTTP_PROXY"),
)
_NO_PROXY_VARIABLE = "NO_PROXY"
_PROXY_URL_SCHEMES = frozenset({"http", "https"})

# A `NO_PROXY` domain name: dot-separated labels, already lowercased.
_NO_PROXY_DOMAIN = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")


def _environment_variable(name: str) -> tuple[str, str] | None:
    """The `(variable, value)` read for a proxy variable, or `None`.

    The lowercase name is read first, then the uppercase one, as curl
    does; an empty value counts as unset.
    """
    for variable in (name.lower(), name):
        value = os.environ.get(variable)
        if value:
            return variable, value
    return None


def _environment_proxy(
    variable: str, value: str, trust_store: ssl.SSLContext | None
) -> httpx.Proxy:
    """The proxy that `value`, read from `variable`, configures.

    A value without a scheme means `http://`; userinfo becomes HTTP Basic
    proxy authentication. The TLS connection to an `https://` proxy is
    verified with the shared trust store: `trust_store`, the client's own
    context, or a new one when the caller overrode `verify`. Raises
    `ValueError` for any other scheme, a missing host, or an unparseable
    value; the message names the variable, never the value, which may hold
    credentials.
    """
    try:
        url = httpx.URL(value if "://" in value else f"http://{value}")
        valid = url.scheme in _PROXY_URL_SCHEMES and bool(url.host)
    except httpx.InvalidURL, ValueError:
        # `url.host` decodes the IDNA host name and may raise `ValueError`.
        valid = False
    if not valid:
        raise ValueError(
            f"{variable} is not a valid proxy URL: only http:// and https:// "
            "proxies are supported"
        )
    ssl_context = None
    if url.scheme == "https":
        ssl_context = build_tls_context() if trust_store is None else trust_store
    return httpx.Proxy(url, ssl_context=ssl_context)


@dataclass(frozen=True)
class _NoProxy:
    """The hosts a `NO_PROXY` value exempts from the proxies: IP-literal
    hosts within `networks`, each of `domains` and its subdomains, and the
    subdomains of each of `subdomains_of` (written with a leading `.` or
    `*.`)."""

    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    domains: tuple[str, ...]
    subdomains_of: tuple[str, ...]

    @classmethod
    def parse(cls, value: str) -> _NoProxy | None:
        """The rules of `value`; `None` when an entry is `*`, which exempts
        every host. An entry that is neither an IP address or network
        (IPv6 optionally in brackets) nor a domain name, such as one with a
        port or a scheme, is ignored."""
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        domains: list[str] = []
        subdomains_of: list[str] = []
        for raw_entry in value.lower().split(","):
            entry = raw_entry.strip()
            if entry == "*":
                return None
            bracketed = entry.startswith("[") and entry.endswith("]")
            try:
                networks.append(
                    ipaddress.ip_network(
                        entry[1:-1] if bracketed else entry, strict=False
                    )
                )
                continue
            except ValueError:
                pass
            entry = entry.removeprefix("*") if entry.startswith("*.") else entry
            domain = entry.removeprefix(".")
            if _NO_PROXY_DOMAIN.fullmatch(domain):
                (subdomains_of if entry.startswith(".") else domains).append(domain)
        return cls(tuple(networks), tuple(domains), tuple(subdomains_of))

    def matches(self, url: httpx.URL) -> bool:
        """Whether a request to `url` is exempt. Network entries match only
        IP-literal hosts, and domain entries only host names."""
        host = url.raw_host.decode("ascii")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return any(
                host == domain or host.endswith(f".{domain}") for domain in self.domains
            ) or any(host.endswith(f".{domain}") for domain in self.subdomains_of)
        return any(address in network for network in self.networks)


class _ProxyRouteTransport(httpx.AsyncBaseTransport):
    """Sends a request through the proxy configured for its URL scheme, or
    directly when none is or `NO_PROXY` exempts its host, as specified in
    `docs/features/platform/networking.md` (Proxy Configuration).

    The network layer under the retry transport, so the transport-level
    retry and the response content-coding policy apply on every route.
    """

    def __init__(
        self,
        direct: httpx.AsyncBaseTransport,
        proxies: dict[str, httpx.AsyncBaseTransport],
        no_proxy: _NoProxy,
    ) -> None:
        self._direct = direct
        self._proxies = proxies
        self._no_proxy = no_proxy

    async def aclose(self) -> None:
        for transport in (self._direct, *self._proxies.values()):
            await transport.aclose()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        proxy = self._proxies.get(request.url.scheme)
        if proxy is None or self._no_proxy.matches(request.url):
            return await self._direct.handle_async_request(request)
        return await proxy.handle_async_request(request)


def _network_transport(
    *,
    verify: ssl.SSLContext | bool,
    limits: httpx.Limits,
    trust_store: ssl.SSLContext | None,
) -> httpx.AsyncBaseTransport:
    """The direct connection pool, or, when the environment configures a
    proxy, a router over it and one pool per proxy. Every pool has the same
    TLS verification and limits, and httpx's built-in retry disabled.
    The proxy variables are read, and validated, on every call;
    `trust_store` is the client's shared trust-store context, `None` when
    the caller overrode `verify`."""
    proxies = {
        scheme: _environment_proxy(*configured, trust_store)
        for scheme, name in _PROXY_VARIABLES
        if (configured := _environment_variable(name)) is not None
    }
    no_proxy_variable = _environment_variable(_NO_PROXY_VARIABLE)
    no_proxy = _NoProxy.parse(no_proxy_variable[1] if no_proxy_variable else "")

    def pool(proxy: httpx.Proxy | None = None) -> httpx.AsyncBaseTransport:
        return httpx.AsyncHTTPTransport(
            verify=verify, limits=limits, retries=0, proxy=proxy
        )

    if not proxies or no_proxy is None:
        return pool()
    return _ProxyRouteTransport(
        pool(), {scheme: pool(proxy) for scheme, proxy in proxies.items()}, no_proxy
    )


# ---------------------------------------------------------------------------
# HTTP client factory
# ---------------------------------------------------------------------------

_PROJECT_URL = "https://github.com/vulnwatch/sentinel"

# `httpx.AsyncClient` arguments that would route requests around the shared
# transport stack or configure proxies outside the environment.
_ROUTING_OVERRIDES = frozenset({"mounts", "proxy", "transport", "trust_env"})


def _resolve_platform_version() -> str:
    try:
        return get_version("sentinel")
    except PackageNotFoundError:
        return "dev"


def _build_user_agent(name: str) -> str:
    return f"Sentinel/{_resolve_platform_version()} ({name}; +{_PROJECT_URL})"


def create_http_client(
    name: str,
    *,
    retry_non_idempotent: bool = False,
    **overrides: Any,
) -> httpx.AsyncClient:
    """Create a pre-configured httpx `AsyncClient`.

    Args:
        name: Identifies the calling component (fetcher name or client
            name). Used to build the User-Agent header and included in
            WARNING-level logs for TLS/redirect override traceability.
        retry_non_idempotent: when `True`, transport-level retry on
            connection error/timeout applies to all HTTP methods, not
            only idempotent ones. The caller is responsible for ensuring
            their operations are semantically safe to retry.
        **overrides: forwarded to `httpx.AsyncClient` (e.g., `timeout`,
            `limits`, `headers`, `verify`, `follow_redirects`). See
            "Override Safety" below for protected settings.

    Applies all cross-cutting defaults (User-Agent, timeouts, TLS,
    compression, Accept header, transport-level retry, proxies from the
    environment). Keyword arguments override individual defaults.

    Raises:
        TypeError: a `transport`, `mounts`, `proxy`, or `trust_env`
            override; requests always use the shared transport stack, and
            proxies come only from the environment.
        ValueError: a proxy variable holds an unsupported or invalid URL;
            the message names the variable, never its value.
        TLSConfigurationError: the SUSE CA file is corrupt (see
            `build_tls_context()`).

    Override safety:
        - User-Agent is always built from the standard template. Any
          `user-agent` key in a `headers` override is dropped and
          replaced with the template-generated value.
        - Accept-Encoding is always `ACCEPT_ENCODING`, the codings the
          response content-coding policy permits; any `accept-encoding`
          key in a `headers` override is replaced.
        - A `verify` or `ssl_context`-equivalent override that disables
          or replaces TLS verification emits a WARNING-level log
          including `name` for traceability.
        - A `follow_redirects=True` override emits a WARNING-level log
          including `name` for traceability (credential-forwarding risk).
        - Routing is not overridable: see `TypeError` above.
    """
    rejected = sorted(_ROUTING_OVERRIDES.intersection(overrides))
    if rejected:
        raise TypeError(
            f"create_http_client() does not accept {', '.join(rejected)}: "
            "requests always use the shared transport stack, and proxies "
            "come only from the environment"
        )

    headers = httpx.Headers(overrides.pop("headers", None) or {})
    if "accept" not in headers:
        headers["accept"] = "application/json"
    headers["accept-encoding"] = ACCEPT_ENCODING
    headers["user-agent"] = _build_user_agent(name)

    verify_override = overrides.pop("verify", None)
    verify: ssl.SSLContext | bool
    trust_store: ssl.SSLContext | None = None
    if verify_override is not None:
        logger.warning(
            "tls_verify_overridden",
            name=name,
            detail=f"TLS verify overridden by {name!r} — verify={verify_override!r}",
        )
        verify = verify_override
    else:
        verify = trust_store = build_tls_context()

    if overrides.get("follow_redirects", False):
        logger.warning(
            "redirects_enabled",
            name=name,
            detail=f"Redirect following enabled by {name!r} — credentials "
            "may be forwarded to redirect targets",
        )
    follow_redirects = overrides.pop("follow_redirects", False)

    timeout = overrides.pop(
        "timeout",
        httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
    )
    limits = overrides.pop(
        "limits",
        httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )

    network = _network_transport(verify=verify, limits=limits, trust_store=trust_store)
    transport = _ContentCodingTransport(
        _RetryTransport(network, retry_non_idempotent=retry_non_idempotent)
    )

    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        headers=headers,
        follow_redirects=follow_redirects,
        **overrides,
    )
