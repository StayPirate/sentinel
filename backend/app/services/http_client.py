"""Shared HTTP client factory and TLS trust store infrastructure.

Provides the cross-cutting HTTP client used by all outgoing network
connections from fetchers, `IBSClient`, and any future consumer, plus
the TLS trust store used by both HTTP and non-HTTP protocols (AMQPS).
See `docs/features/platform/networking.md` for the full specification
this module implements.
"""

from __future__ import annotations

import asyncio
import email.utils
import ssl
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
    """Wraps an `httpx.AsyncHTTPTransport` with the transport-level retry
    policy specified in `docs/features/platform/networking.md`.

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
# HTTP client factory
# ---------------------------------------------------------------------------

_PROJECT_URL = "https://github.com/StayPirate/sentinel"


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
    compression, Accept header, transport-level retry). Keyword
    arguments override individual defaults.

    Override safety:
        - User-Agent is always built from the standard template. Any
          `user-agent` key in a `headers` override is dropped and
          replaced with the template-generated value.
        - A `verify` or `ssl_context`-equivalent override that disables
          or replaces TLS verification emits a WARNING-level log
          including `name` for traceability.
        - A `follow_redirects=True` override emits a WARNING-level log
          including `name` for traceability (credential-forwarding risk).
    """
    headers = httpx.Headers(overrides.pop("headers", None) or {})
    if "accept" not in headers:
        headers["accept"] = "application/json"
    headers["user-agent"] = _build_user_agent(name)

    verify_override = overrides.pop("verify", None)
    verify: ssl.SSLContext | bool
    if verify_override is not None:
        logger.warning(
            "tls_verify_overridden",
            name=name,
            detail=f"TLS verify overridden by {name!r} — verify={verify_override!r}",
        )
        verify = verify_override
    else:
        verify = build_tls_context()

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

    inner_transport = httpx.AsyncHTTPTransport(verify=verify, limits=limits, retries=0)
    transport = _RetryTransport(
        inner_transport, retry_non_idempotent=retry_non_idempotent
    )

    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        headers=headers,
        follow_redirects=follow_redirects,
        **overrides,
    )
