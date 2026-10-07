"""Tests for `SyncOsvAdvisories.fetch_single()`
(backend/app/services/tickets/sync_osv_advisories.py).

Owning specifications:

- docs/features/tickets/cve-sync-osv.md (Role, same-vulnerability boundary
  and `related` records; Algorithm steps 1-14; Field Mapping; GIT Range
  Event Parsing; Response Validation, including External String
  Admissibility; OSV Reference Type Mapping; External Identifier Policy;
  Explicitly Ignored Fields; `fetch_single` Method; Error Handling,
  `fetch_single()` table, data preservation; Post-Ingest Package
  Candidates; `CompletenessGuardError`).
- docs/features/platform/cve-fetcher-infrastructure.md (Automatic Reference
  Caller Contract; `CVEFetchResult`; `fetch_single` Signaling Convention;
  Retry Policy and Error Categorization; Canonical Payload Producer
  Obligations).
- docs/features/tickets/cve-service.md (Canonical Payload Duplicate Handling;
  Affected-Version Snapshot Operations; CVEIngestPayload Schema;
  `build_post_ingest_tasks()`).
- docs/features/platform/networking.md (Infrastructure Failure
  Classification; Celery Retry Classification; Redirect Policy) and
  docs/features/platform/logging.md (Secrets and PII Discipline).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Typed result; External String Admissibility).

HTTP is the in-process `OsvServer` of `tests/support/osv.py`, injected as the
fetcher's HTTP client, serving the sanitized live fixtures under their
requested IDs (Phase 1 records under fictional CVE-IDs, alias records with
their CVE alias retargeted to the processed CVE where they must apply,
Algorithm step 6) or minimal fictional bodies. The throttle sleep is
recorded, never slept. Every test also asserts that no `CVE-*` ID is ever
requested as a sub-request (step 5). Outcome tests that end before any
database work use a session that fails on any use, and spies on
`cve_service.upsert_cve()` and `reference_service.upsert_references()`
prove no mutation was attempted; they are unit tests. Ingestion tests run
the real `upsert_cve()` and `upsert_references()` on `db_session`, rolled
back at teardown. All identifiers and texts are fictional, except the
public advisory and CVE identifiers of the live fixtures.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Final, cast

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import (
    CVEExternalIdentifierSource,
    CVESourceFetchStatus,
    CVESourceType,
    ReferenceType,
)
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import CVEFetchResult, CVENotInSource
from app.services.base_fetcher import FetcherRunConfig
from app.services.cve_ingest import (
    AffectedVersionOperation,
    CVEIngestPayload,
    ExternalIdentifierEntry,
    PostIngestTasks,
    UpsertAction,
)
from app.services.http_client import (
    is_infrastructure_failure,
    is_retryable_condition,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import osv_vulnerability_record
from app.services.tickets import sync_osv_advisories as sync_module
from app.services.tickets.sync_osv_advisories import (
    OSV_SUBREQUEST_SKIPPED_EVENT,
    CompletenessGuardError,
    OsvResponseError,
    SyncOsvAdvisories,
)
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.osv import (
    ALIAS_NOT_FOUND_FIXTURE,
    OSV_HOST,
    OSV_VULNS_PATH_PREFIX,
    OsvServer,
    load_raw_fixture,
    load_record_fixture,
    osv_vuln_url,
    raising,
    requested_record_id,
    status,
)
from tests.support.osv import (
    body as json_response,
)
from tests.support.ticket_mutations import EventRow, ticket_events

NAME: Final = "sync_osv_advisories"
SOURCE_URL: Final = "https://osv.dev/vulnerability/{cve_id}"
REPO: Final = "https://git.example.invalid/project/example"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
URL_3: Final = "https://advisory.example.invalid/upstream/3"
URL_4: Final = "https://advisory.example.invalid/upstream/4"
SECRET: Final = "Example-Secret-Upstream-Value"
"""An upstream value that must never reach a log record."""
PERSONAL: Final = "Alice Example <alice.example@example.invalid>"
INGESTION_COMMENT: Final = "CVE ingested from OSV"

ALIAS: Final = "GHSA-fict-0001-aaaa"
ALIAS_2: Final = "GHSA-fict-0002-bbbb"
ALIAS_3: Final = "PYSEC-2099-0003"
ALIAS_4: Final = "RUSTSEC-2099-0004"
RELATED: Final = "SUSE-SU-2099:0001-1"
"""A `related` ID: never requested (§ Explicitly Ignored Fields)."""
OTHER_CVE: Final = "CVE-2099-990000001"
OTHER_CVE_2: Final = "CVE-2099-990000002"
"""Other CVE-IDs listed as aliases: never requested (Algorithm step 5)."""

SKIP_KEYS: Final = frozenset(
    {
        "event",
        "log_level",
        "cve_id",
        "fetcher_name",
        "record_id",
        "reason",
        "status_code",
    }
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _NoSession:
    """A session that fails the test on any use."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used before the final write")


NO_SESSION: Final = cast(AsyncSession, _NoSession())


@dataclass
class Ingestion:
    """Spies on the two ingestion delegates; both call through."""

    payloads: list[CVEIngestPayload] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return len(self.payloads) + len(self.references)


@pytest.fixture
def ingestion(monkeypatch: pytest.MonkeyPatch) -> Ingestion:
    spy = Ingestion()
    real_upsert = cve_service.upsert_cve
    real_references = reference_service.upsert_references

    async def upsert_cve(
        db: AsyncSession, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> Any:
        spy.payloads.append(payload)
        return await real_upsert(db, cve_id, source, payload)

    async def upsert_references(
        session: AsyncSession,
        ticket_id: Any,
        cve_id: str,
        source: str,
        source_reference: AutomaticReferenceInput | None,
        upstream_references: Iterable[AutomaticReferenceInput],
    ) -> None:
        upstream = list(upstream_references)
        spy.references.append(
            {
                "ticket_id": ticket_id,
                "cve_id": cve_id,
                "source": source,
                "source_reference": source_reference,
                "upstream": upstream,
            }
        )
        await real_references(
            session, ticket_id, cve_id, source, source_reference, upstream
        )

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)
    return spy


@pytest.fixture
def server() -> OsvServer:
    return OsvServer()


@dataclass
class Throttle:
    """The recorded step-13 sleeps: each delay, and how many requests the
    server had received when it was requested."""

    server: OsvServer
    delays: list[float] = field(default_factory=list)
    after: list[int] = field(default_factory=list)

    async def sleep(self, delay: float) -> None:
        self.delays.append(delay)
        self.after.append(len(self.server.requests))


@pytest.fixture(autouse=True)
def throttle(server: OsvServer, monkeypatch: pytest.MonkeyPatch) -> Throttle:
    recorder = Throttle(server)
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=recorder.sleep))
    return recorder


@pytest.fixture(autouse=True)
def no_cve_sub_request(
    server: OsvServer, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Algorithm step 5: a `CVE-*` ID is requested only as a Phase 1 record,
    the first request of its `fetch_single()` call, never as an alias."""
    sub_requested: list[str] = []
    real_get = sync_module._ThrottledRequests.get

    async def get(self: Any, record_id: str) -> httpx.Response:
        if self._requested:
            sub_requested.append(record_id)
        return await real_get(self, record_id)

    monkeypatch.setattr(sync_module._ThrottledRequests, "get", get)
    yield
    assert [r for r in sub_requested if r.startswith("CVE-")] == []
    phase1 = [
        r for r in server.requested_ids if r is not None and r not in sub_requested
    ]
    assert all(r.startswith("CVE-") for r in phase1)


@pytest.fixture
async def fetcher(server: OsvServer) -> AsyncIterator[SyncOsvAdvisories]:
    instance = SyncOsvAdvisories()
    instance._http_client = server.client()
    try:
        yield instance
    finally:
        await instance._teardown_http_client()


@dataclass
class Target:
    cve: CVE
    ticket: Ticket | None

    @property
    def cve_id(self) -> str:
        return self.cve.cve_id


@pytest.fixture
async def target(db_session: AsyncSession) -> Target:
    """A CVE with its `Analysis` Ticket."""
    cve = CVE(cve_id=fictional_cve_id())
    db_session.add(cve)
    await db_session.flush()
    ticket = Ticket(status="Analysis", cve_id=cve.id)
    db_session.add(ticket)
    await db_session.flush()
    return Target(cve, ticket)


@pytest.fixture
async def ticketless(db_session: AsyncSession) -> Target:
    """An existing CVE that no Ticket references."""
    cve = CVE(cve_id=fictional_cve_id())
    db_session.add(cve)
    await db_session.flush()
    return Target(cve, None)


# ---------------------------------------------------------------------------
# Body builders and fixture retargeting
# ---------------------------------------------------------------------------


def _events(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{kind: value} for kind, value in pairs]


def _git(*pairs: tuple[str, str], repo: str = REPO) -> dict[str, Any]:
    return {"type": "GIT", "repo": repo, "events": _events(*pairs)}


def _package(
    name: str | None,
    ecosystem: str | None = "PyPI",
    purl: str | None = None,
    *,
    events: tuple[tuple[str, str], ...] = (("introduced", "0"), ("fixed", "1.0")),
    range_type: str = "ECOSYSTEM",
    versions: list[str] | None = None,
) -> dict[str, Any]:
    """One alias `affected[]` entry."""
    entry: dict[str, Any] = {
        "package": {"name": name, "ecosystem": ecosystem, "purl": purl},
        "ranges": [{"type": range_type, "events": _events(*events)}],
    }
    if versions is not None:
        entry["versions"] = versions
    return entry


def _alias_body(cve_id: str | None, *affected: dict[str, Any], **rest: Any) -> Any:
    """An alias record listing `cve_id` as its only CVE alias."""
    body: dict[str, Any] = {"aliases": [] if cve_id is None else [cve_id]}
    body["affected"] = list(affected)
    body.update(rest)
    return body


def _retargeted(name: str, real: str, cve_id: str) -> dict[str, Any]:
    """A live alias fixture whose `real` CVE alias names `cve_id` instead."""
    body = copy.deepcopy(load_record_fixture(name))
    body["aliases"] = [cve_id if alias == real else alias for alias in body["aliases"]]
    return body


def _row(
    *,
    product: str | None = None,
    package_name: str | None = None,
    ecosystem: str | None = None,
    package_url: str | None = None,
    repo: str | None = None,
    version: str | None = None,
    version_type: str | None = None,
    version_end: str | None = None,
    version_end_inclusive: bool | None = None,
) -> tuple[Any, ...]:
    return (
        product,
        package_name,
        ecosystem,
        package_url,
        repo,
        version,
        version_type,
        version_end,
        version_end_inclusive,
    )


def _git_row(
    version: str | None,
    version_end: str | None,
    inclusive: bool | None,
    repo: str = REPO,
) -> tuple[Any, ...]:
    return _row(
        repo=repo,
        version=version,
        version_type="git",
        version_end=version_end,
        version_end_inclusive=inclusive,
    )


def _package_row(
    name: str | None,
    ecosystem: str | None = "PyPI",
    purl: str | None = None,
    version: str | None = None,
    version_end: str | None = "1.0",
    inclusive: bool | None = False,
    version_type: str | None = None,
) -> tuple[Any, ...]:
    return _row(
        product=name,
        package_name=name,
        ecosystem=ecosystem,
        package_url=purl,
        version=version,
        version_type=version_type,
        version_end=version_end,
        version_end_inclusive=inclusive,
    )


async def _osv_rows(db: AsyncSession, cve: CVE) -> set[tuple[Any, ...]]:
    rows = await db.execute(
        select(
            CVEAffectedVersion.product,
            CVEAffectedVersion.package_name,
            CVEAffectedVersion.ecosystem,
            CVEAffectedVersion.package_url,
            CVEAffectedVersion.repo,
            CVEAffectedVersion.version,
            CVEAffectedVersion.version_type,
            CVEAffectedVersion.version_end,
            CVEAffectedVersion.version_end_inclusive,
        ).where(
            CVEAffectedVersion.cve_id == cve.id,
            CVEAffectedVersion.source_container == "osv",
        )
    )
    return {tuple(row) for row in rows}


async def _identifiers(db: AsyncSession, cve: CVE) -> set[tuple[str, str, str | None]]:
    rows = await db.execute(
        select(
            CVEExternalIdentifier.source,
            CVEExternalIdentifier.identifier,
            CVEExternalIdentifier.url,
        ).where(CVEExternalIdentifier.cve_id == cve.id)
    )
    return {(source, identifier, url) for source, identifier, url in rows}


async def _references(
    db: AsyncSession, ticket: Ticket | None
) -> dict[str, tuple[str | None, str | None, str]]:
    """Every reference of the Ticket: URL -> (title, type, source)."""
    assert ticket is not None
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.title,
            TicketReference.type,
            TicketReference.source,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return {url: (title, kind, source) for url, title, kind, source in rows}


def _skips(logs: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == OSV_SUBREQUEST_SKIPPED_EVENT]


def _skip(
    cve_id: str,
    reason: str,
    *,
    record_id: str | None = ALIAS,
    status_code: int | None = None,
) -> dict[str, Any]:
    """The exact expected skip WARNING."""
    expected: dict[str, Any] = {
        "event": OSV_SUBREQUEST_SKIPPED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "reason": reason,
    }
    if record_id is not None:
        expected["record_id"] = record_id
    if status_code is not None:
        expected["status_code"] = status_code
    return expected


def _assert_no_raw_value(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        assert "\\x00" not in rendered, entry
        for value in values:
            assert value not in rendered, entry


def _assert_single_segment_requests(server: OsvServer) -> None:
    for request in server.requests:
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == OSV_HOST
        assert request.url.query == b""
        assert request.url.path.startswith(OSV_VULNS_PATH_PREFIX)
        assert requested_record_id(request) is not None, request.url


FAILED_RESPONSES: Final[list[tuple[Any, str, int | None]]] = [
    (status(500, SECRET.encode()), "http_status", 500),
    (status(503), "http_status", 503),
    (status(429), "http_status", 429),
    (status(403, SECRET.encode()), "http_status", 403),
    (status(400), "http_status", 400),
    (status(410), "http_status", 410),
    (
        lambda request: httpx.Response(
            301, headers={"Location": osv_vuln_url("GHSA-moved")}
        ),
        "http_status",
        301,
    ),
    (status(302), "http_status", 302),
    (status(201, b'{"affected": []}'), "http_status", 201),
    (status(204), "http_status", 204),
    (raising(httpx.ConnectError(SECRET)), "transport", None),
    (raising(httpx.ReadTimeout(SECRET)), "transport", None),
    (raising(httpx.RemoteProtocolError(SECRET)), "transport", None),
    (status(200, b"{"), "invalid_body", 200),
    (status(200, b""), "invalid_body", 200),
    (status(200, b"\xff\xfe\xfd"), "invalid_body", 200),
    (status(200, f"<html>{SECRET}</html>".encode()), "invalid_body", 200),
    (status(200, b"[1]"), "invalid_body", 200),
    (status(200, b'"text"'), "invalid_body", 200),
    (status(200, f'{{"references": "{SECRET}"}}'.encode()), "invalid_body", 200),
    (
        json_response({"affected": [{"package": {"name": [SECRET]}}]}),
        "invalid_body",
        200,
    ),
]
"""Every failed-sub-request response kind (step 8), its WARNING reason,
and the status it carries."""

FAILED_IDS: Final = [
    "500",
    "503",
    "429",
    "403",
    "400",
    "410",
    "301",
    "302",
    "201",
    "204",
    "connect",
    "read_timeout",
    "protocol",
    "truncated_json",
    "empty_body",
    "invalid_utf8",
    "html",
    "array_root",
    "string_root",
    "references_string",
    "package_name_list",
]

UNSAFE_IDS: Final = [
    "",
    "..",
    ".",
    ".hidden",
    "GHSA/../../v1/vulns/CVE-2099-0001",
    "a/b",
    "/GHSA-fict-0001-aaaa",
    "GHSA-fict\x00",
    "\x00",
    "A" * 101,
    "GHSA fict",
    "GHSA-fict?x=1",
    "GHSA-fict#x",
    "GHSA%2Ffict",
    "-GHSA",
    "GHSA-fict\n",
]


# ---------------------------------------------------------------------------
# Phase 1 outcomes before any database work
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMissingBeforeMutation:
    @pytest.mark.parametrize(
        "cve_id",
        ["CVE-2099-1", "cve-2099-0001", "CVE-2099-0001 ", "", "CVE-2099-" + "1" * 12],
        ids=["short", "lowercase", "trailing_space", "empty", "over_long"],
    )
    async def test_malformed_cve_id_is_missing_without_http(
        self,
        cve_id: str,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert throttle.delays == []
        assert ingestion.calls == 0

    async def test_404_is_missing_and_requests_the_documented_url_once(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        cve_id = fictional_cve_id()

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert [request.method for request in server.requests] == ["GET"]
        assert server.requested_urls == [f"https://api.osv.dev/v1/vulns/{cve_id}"]
        assert server.requested_urls == [osv_vuln_url(cve_id)]
        assert throttle.delays == []
        assert ingestion.calls == 0
        assert logs == []

    async def test_404_body_is_not_consumed(
        self, fetcher: SyncOsvAdvisories, server: OsvServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = status(404, b"\x00not json")

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"id": "CVE-2099-0001", "summary": SECRET, "severity": [], "credits": []},
            {"affected": None, "references": None, "aliases": None},
            {"references": [], "aliases": []},
            {"related": [RELATED, OTHER_CVE], "upstream": [OTHER_CVE]},
            {"aliases": [OTHER_CVE, OTHER_CVE_2], "related": [RELATED]},
            {"withdrawn": "2026-01-01T00:00:00Z", "details": PERSONAL},
        ],
        ids=[
            "empty",
            "unconsumed_only",
            "null_fields",
            "empty_arrays",
            "only_related",
            "only_cve_aliases",
            "withdrawn",
        ],
    )
    async def test_200_without_extractable_data_is_missing_without_sub_requests(
        self,
        body: dict[str, Any],
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        cve_id = fictional_cve_id()
        server.bodies[cve_id] = body

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id]
        assert throttle.delays == []
        assert ingestion.calls == 0
        assert logs == []


async def _raised(
    fetcher: SyncOsvAdvisories, server: OsvServer, responder: Any
) -> BaseException:
    cve_id = fictional_cve_id()
    server.responses[cve_id] = responder
    with pytest.raises((httpx.HTTPError, ValueError, OsvResponseError)) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    assert server.requested_ids == [cve_id]
    return raised.value


@pytest.mark.unit
class TestPhase1ErrorPropagation:
    @pytest.mark.parametrize("code", [400, 401, 403, 405, 410, 422])
    async def test_other_4xx_is_an_unwrapped_non_retryable_status_error(
        self,
        code: int,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(code, SECRET.encode()))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    async def test_429_is_an_unwrapped_retryable_non_infrastructure_error(
        self, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        error = await _raised(fetcher, server, status(429))

        assert isinstance(error, httpx.HTTPStatusError)
        assert error.response.status_code == 429
        assert is_retryable_condition(error)
        assert not is_infrastructure_failure(error)

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    async def test_5xx_is_an_unwrapped_retryable_infrastructure_error(
        self, code: int, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        error = await _raised(fetcher, server, status(code))

        assert isinstance(error, httpx.HTTPStatusError)
        assert error.response.status_code == code
        assert is_retryable_condition(error)
        assert is_infrastructure_failure(error)

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("timed out"),
            httpx.ReadTimeout("timed out"),
            httpx.PoolTimeout("timed out"),
            httpx.RemoteProtocolError("closed"),
            httpx.ProxyError("proxy"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_transport_error_propagates_unwrapped_and_retryable(
        self, error: Exception, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)
        assert is_infrastructure_failure(raised)

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self, code: int, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        cve_id = fictional_cve_id()
        other = fictional_cve_id()
        server.bodies[other] = {"affected": []}
        server.responses[cve_id] = lambda request: httpx.Response(
            code, headers={"Location": osv_vuln_url(other)}
        )

        with pytest.raises(httpx.HTTPStatusError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value.response.status_code == code
        assert server.requested_ids == [cve_id]
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)

    @pytest.mark.parametrize("code", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_non_retryable_error_without_upstream_data(
        self,
        code: int,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            lambda request: httpx.Response(code, json={"affected": [], SECRET: 1}),
        )

        assert type(error) is OsvResponseError
        assert str(error) == "OSV API returned an unexpected status"
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "content", [b"", b"{", f"<html>{SECRET}</html>".encode(), b"\xff\xfe\xfd"]
    )
    async def test_unparseable_json_is_non_retryable(
        self,
        content: bytes,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(200, content))

        assert isinstance(error, ValueError)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "body",
        [
            [{"aliases": [ALIAS]}],
            SECRET,
            {"aliases": SECRET},
            {"aliases": [1]},
            {"references": [{"url": [SECRET]}]},
            {"affected": [{"ranges": [{"type": "GIT", "events": [{SECRET: "x"}]}]}]},
            {"affected": [{"ranges": [{"type": "GIT", "repo": [SECRET]}]}]},
        ],
        ids=[
            "array_root",
            "string_root",
            "aliases_string",
            "alias_integer",
            "reference_url_list",
            "unknown_event",
            "repo_list",
        ],
    )
    async def test_schema_mismatch_is_non_retryable_and_hides_the_input(
        self,
        body: Any,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(
            fetcher, server, lambda request: httpx.Response(200, json=body)
        )

        assert isinstance(error, ValidationError)
        assert SECRET not in str(error)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    async def test_production_client_follows_no_redirect(self) -> None:
        instance = SyncOsvAdvisories()
        try:
            assert instance.http_client.follow_redirects is False
        finally:
            await instance._teardown_http_client()
        assert SyncOsvAdvisories.http_client_options == {}


# ---------------------------------------------------------------------------
# Sub-requests and the completeness guard (no database work)
# ---------------------------------------------------------------------------


def _listing(server: OsvServer, aliases: list[str]) -> str:
    """Serve a Phase 1 record listing only `aliases` (and an unconsumed
    `related` ID)."""
    cve_id = fictional_cve_id()
    server.bodies[cve_id] = {"aliases": aliases, "related": [RELATED]}
    return cve_id


@pytest.mark.unit
class TestFailedSubRequests:
    @pytest.mark.parametrize(
        ("responder", "reason", "code"), FAILED_RESPONSES, ids=FAILED_IDS
    )
    async def test_each_failure_kind_is_one_bounded_skip_and_triggers_the_guard(
        self,
        responder: Any,
        reason: str,
        code: int | None,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, [ALIAS])
        server.responses[ALIAS] = responder

        with capture_logs() as logs, pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS]
        assert logs == [_skip(cve_id, reason, status_code=code)]
        _assert_no_raw_value(logs, SECRET)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("record_id", UNSAFE_IDS)
    async def test_unsafe_id_is_never_requested_nor_logged(
        self,
        record_id: str,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, [record_id])

        with capture_logs() as logs, pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id]
        assert throttle.delays == []
        assert logs == [_skip(cve_id, "unsafe_id", record_id=None)]
        if record_id:
            _assert_no_raw_value(logs, record_id)
        assert ingestion.calls == 0

    async def test_every_request_addresses_one_segment_on_the_osv_host(
        self, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        safe = ["GHSA-fict-0003-cccc", "PYSEC-2099-1", "SUSE-SU-2099:0003-1", "A.b_c"]
        cve_id = _listing(server, [*UNSAFE_IDS[:6], *safe[:2], *UNSAFE_IDS, *safe])
        for record_id in safe:
            server.responses[record_id] = status(503)

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, *safe[:2], *safe]
        assert server.requested_urls == [
            osv_vuln_url(record_id) for record_id in [cve_id, *safe[:2], *safe]
        ]
        _assert_single_segment_requests(server)

    async def test_guard_needs_every_listed_sub_request_to_fail(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, [ALIAS, "..", ALIAS_2, OTHER_CVE, ALIAS_3])
        server.responses[ALIAS] = status(503)
        server.responses[ALIAS_2] = raising(httpx.ConnectError("refused"))
        server.responses[ALIAS_3] = status(200, b"{")

        with capture_logs() as logs, pytest.raises(CompletenessGuardError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS, ALIAS_2, ALIAS_3]
        assert [entry["reason"] for entry in logs] == [
            "http_status",
            "unsafe_id",
            "transport",
            "invalid_body",
        ]
        assert ingestion.calls == 0
        assert str(raised.value) == "Every OSV alias sub-request failed"
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)

    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_whole_run_signal_in_a_sub_request_is_never_absorbed(
        self,
        signal: BaseException,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, [ALIAS, ALIAS_2])

        def respond(request: httpx.Request) -> httpx.Response:
            raise signal

        server.responses[ALIAS] = respond

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is signal
        assert server.requested_ids == [cve_id, ALIAS]
        assert logs == []
        assert ingestion.calls == 0

    async def test_undocumented_sub_request_exception_propagates(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = _listing(server, [ALIAS])
        server.bodies[ALIAS] = _alias_body(cve_id)
        error = RuntimeError(SECRET)

        def parse(body: object) -> Any:
            raise error

        monkeypatch.setattr(osv_vulnerability_record, "parse_alias_record", parse)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is error
        assert logs == []
        assert ingestion.calls == 0


# ---------------------------------------------------------------------------
# CVE-* aliases and related IDs are never requested (Algorithm step 5;
# Explicitly Ignored Fields)
# ---------------------------------------------------------------------------

CVE_ALIASES: Final = [OTHER_CVE, OTHER_CVE_2, "CVE-x/../y", "CVE-\x00" + SECRET]
"""`CVE-*` aliases, including ones that would fail the step-5 ID check: the
`CVE-` prefix is checked first, so none is requested or logged."""


@pytest.mark.unit
class TestSkippedIds:
    async def test_cve_aliases_and_related_ids_are_not_sub_requests(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        """With a failing alias, the `CVE-*` aliases and `related` IDs (each
        served with a record) neither count as observed nor are requested:
        the guard triggers after exactly one sub-request."""
        cve_id = fictional_cve_id()
        server.bodies[cve_id] = {
            "aliases": [*CVE_ALIASES[:2], ALIAS, *CVE_ALIASES[2:], cve_id],
            "related": [RELATED, OTHER_CVE],
        }
        for record_id in (OTHER_CVE, OTHER_CVE_2, RELATED):
            server.bodies[record_id] = _alias_body(cve_id, _package("example"))
        server.responses[ALIAS] = status(503)

        with capture_logs() as logs, pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS]
        assert throttle.after == [1]
        assert logs == [_skip(cve_id, "http_status", status_code=503)]
        _assert_no_raw_value(logs, SECRET, OTHER_CVE, OTHER_CVE_2, RELATED)
        assert ingestion.calls == 0


# ---------------------------------------------------------------------------
# Throttle (Algorithm step 13)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestThrottle:
    async def test_class_default_separates_every_request_outside_a_run(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, [ALIAS, "..", OTHER_CVE, ALIAS_2, ALIAS_3])
        for record_id in (ALIAS, ALIAS_2, ALIAS_3):
            server.responses[record_id] = status(503)
        assert fetcher.config is None

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS, ALIAS_2, ALIAS_3]
        # One delay between each consecutive pair; none for the unsafe ID,
        # the CVE alias, or the related ID.
        assert throttle.after == [1, 2, 3]
        assert throttle.delays == [0.2, 0.2, 0.2]
        assert SyncOsvAdvisories.default_request_delay == 0.2

    async def test_run_snapshot_delay_applies_inside_a_run(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, [ALIAS, ALIAS_2, ALIAS_3])
        for record_id in (ALIAS, ALIAS_2, ALIAS_3):
            server.responses[record_id] = raising(httpx.ConnectError("refused"))
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.75, custom_settings={}
        )

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert throttle.after == [1, 2, 3]
        assert throttle.delays == [0.75, 0.75, 0.75]

    async def test_single_request_is_never_delayed(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, ["a/b", *CVE_ALIASES])

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id]
        assert throttle.delays == []


# ---------------------------------------------------------------------------
# External String Admissibility and length bounds (before any write)
# ---------------------------------------------------------------------------

NUL: Final = f"{SECRET}\x00"


def _nul_phase1(field_name: str) -> dict[str, Any]:
    if field_name == "repo":
        return {"affected": [{"ranges": [_git(("fixed", "abc"), repo=NUL)]}]}
    events = [("introduced", "aaa"), (field_name, NUL)]
    if field_name == "introduced":
        events = [("introduced", NUL), ("fixed", "bbb")]
    return {"affected": [{"ranges": [_git(*events)]}]}


@pytest.mark.unit
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "field_name", ["introduced", "fixed", "last_affected", "limit", "repo"]
    )
    async def test_nul_in_a_phase1_git_value_fails_the_cve_before_any_write(
        self,
        field_name: str,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        server.bodies[cve_id] = _nul_phase1(field_name)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert logs == []

    @pytest.mark.parametrize(
        "affected",
        [
            _package(NUL),
            _package("example", NUL),
            _package("example", "PyPI", NUL),
            _package("example", events=(("introduced", NUL),)),
            _package("example", events=(("introduced", "1"), ("fixed", NUL))),
            _package(
                "example",
                range_type="SEMVER",
                events=(("introduced", "1"), ("last_affected", NUL)),
            ),
            _package("example", versions=["1.0", NUL]),
        ],
        ids=[
            "package_name",
            "ecosystem",
            "purl",
            "introduced",
            "fixed",
            "semver_last_affected",
            "versions",
        ],
    )
    async def test_nul_in_an_alias_value_fails_the_cve_before_any_write(
        self,
        affected: dict[str, Any],
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, [ALIAS])
        server.bodies[ALIAS] = _alias_body(cve_id, affected)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        # A payload failure, not a failed sub-request: no skip WARNING.
        assert logs == []
        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)

    @pytest.mark.parametrize(
        "affected",
        [
            _package("example", "E" * 51),
            _package("example", "PyPI", "pkg:pypi/" + "e" * 2040),
            _package("e" * 2049),
        ],
        ids=["ecosystem_51", "purl_2049", "package_name_2049"],
    )
    async def test_over_length_alias_value_fails_the_cve_before_any_write(
        self,
        affected: dict[str, Any],
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, [ALIAS])
        server.bodies[ALIAS] = _alias_body(cve_id, affected)

        with capture_logs() as logs, pytest.raises(ValidationError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert logs == []
        assert ingestion.calls == 0

    async def test_over_length_repo_fails_the_cve_before_any_write(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        repo = "https://git.example.invalid/" + "r" * 2021
        assert len(repo) == 2049
        server.bodies[cve_id] = {
            "affected": [{"ranges": [_git(("fixed", "abc"), repo=repo)]}]
        }

        with pytest.raises(ValidationError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0


@pytest.mark.integration
class TestLengthBounds:
    async def test_bounds_are_inclusive(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        purl = "pkg:pypi/" + "e" * 2039
        repo = "https://git.example.invalid/" + "r" * 2020
        name = "n" * 2048
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(("fixed", "abc"), repo=repo)]}],
            "aliases": [ALIAS],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id, _package(name, "E" * 50, purl)
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _osv_rows(db_session, target.cve) == {
            _git_row(None, "abc", False, repo=repo),
            _package_row(name, "E" * 50, purl),
        }


# ---------------------------------------------------------------------------
# Ingestion: completeness guard and scope completeness (real upsert_cve)
# ---------------------------------------------------------------------------

GIT_BODY_EVENTS: Final = (("introduced", "0"), ("fixed", "c1"))


async def _seed(
    db_session: AsyncSession,
    target: Target,
    fetcher: SyncOsvAdvisories,
    server: OsvServer,
) -> None:
    """Ingest one `osv` row, one GHSA identifier, and references."""
    server.bodies[target.cve_id] = {
        "affected": [{"ranges": [_git(*GIT_BODY_EVENTS)]}],
        "aliases": [ALIAS],
        "references": [{"type": "FIX", "url": URL_1}],
    }
    server.bodies[ALIAS] = _alias_body(
        target.cve_id,
        _package("example"),
        references=[{"type": "ADVISORY", "url": URL_2}],
    )
    result = await fetcher.fetch_single(target.cve_id, db_session)
    assert result.action is UpsertAction.UPDATED
    server.requests.clear()


SEEDED_ROWS: Final = {
    _git_row(None, "c1", False),
    _package_row("example"),
}
SEEDED_IDENTIFIER: Final = (
    "GHSA",
    ALIAS,
    f"https://github.com/advisories/{ALIAS}",
)


@pytest.mark.integration
class TestCompletenessGuard:
    async def test_all_failed_raises_before_any_write_and_keeps_previous_data(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        references = await _references(db_session, target.ticket)
        server.bodies[target.cve_id] = {
            "affected": [],
            "aliases": [ALIAS, "a/b", OTHER_CVE, ALIAS_2],
            "related": [RELATED],
            "references": [{"url": URL_4}],
        }
        server.bodies[OTHER_CVE] = {"affected": []}
        server.responses[ALIAS] = status(500)
        server.responses[ALIAS_2] = status(403)
        calls = ingestion.calls

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == calls
        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}
        assert await _references(db_session, target.ticket) == references

    @pytest.mark.parametrize(
        "outcome", ["applicable", "not_applicable", "no_extractable_data", "not_found"]
    )
    async def test_one_success_or_404_prevents_the_guard(
        self,
        outcome: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        """A succeeded sub-request counts as observed whether or not its
        record applies (step 8)."""
        server.bodies[target.cve_id] = {"aliases": [ALIAS, OTHER_CVE, ALIAS_2]}
        server.responses[ALIAS] = status(503)
        if outcome == "applicable":
            server.bodies[ALIAS_2] = _alias_body(target.cve_id)
        elif outcome == "not_applicable":
            server.bodies[ALIAS_2] = _alias_body(OTHER_CVE, _package("other"))
        elif outcome == "no_extractable_data":
            server.bodies[ALIAS_2] = {}

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert isinstance(result, CVEFetchResult)
        assert server.requested_ids == [target.cve_id, ALIAS, ALIAS_2]
        [payload] = ingestion.payloads
        # A failed alias leaves the scope unobserved.
        assert "affected_version_operations" not in payload.model_fields_set
        assert "resolved_packages" not in payload.model_fields_set
        reasons = [entry["reason"] for entry in _skips(logs)]
        assert reasons.count("not_found") == (outcome == "not_found")


@pytest.mark.integration
class TestScopeCompleteness:
    async def test_no_alias_replaces_the_scope_with_the_phase1_entries(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {
            "affected": [
                {
                    "ranges": [
                        _git(("introduced", "a1"), ("fixed", "b1"), ("limit", "l1")),
                        {"type": "SEMVER", "events": [{"introduced": "1.0"}]},
                    ]
                },
                {"ranges": [_git(("introduced", "c1"), ("last_affected", "d1"))]},
            ]
        }

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        [payload] = ingestion.payloads
        assert payload.affected_version_operations is not None
        [operation] = payload.affected_version_operations
        assert operation.source_container == "osv"
        assert operation.operation is AffectedVersionOperation.REPLACE
        assert await _osv_rows(db_session, target.cve) == {
            _git_row("a1", "b1", False),
            _git_row("a1", "l1", False),
            _git_row("c1", "d1", True),
        }

    async def test_present_empty_affected_clears_the_scope(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"affected": []}

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert server.requested_ids == [target.cve_id]
        operations = ingestion.payloads[-1].affected_version_operations or ()
        assert [(op.operation, op.entries) for op in operations] == [
            (AffectedVersionOperation.REPLACE, [])
        ]
        assert await _osv_rows(db_session, target.cve) == set()
        # External identifiers are additive.
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}

    @pytest.mark.parametrize("affected", ["absent", "null"])
    async def test_absent_phase1_affected_with_every_alias_observed_replaces(
        self,
        affected: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        body: dict[str, Any] = {"aliases": [ALIAS_2, "GHSA-fict-0404-dddd"]}
        if affected == "null":
            body["affected"] = None
        server.bodies[target.cve_id] = body
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, _package("other"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _osv_rows(db_session, target.cve) == {_package_row("other")}

    async def test_only_404_aliases_observe_an_empty_scope(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"aliases": [ALIAS]}
        del server.bodies[ALIAS]
        server.responses[ALIAS] = status(404, load_raw_fixture(ALIAS_NOT_FOUND_FIXTURE))

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _osv_rows(db_session, target.cve) == set()
        assert _skips(logs) == [
            _skip(target.cve_id, "not_found", status_code=404, record_id=ALIAS)
        ]
        # An alias absent from a later observation deletes no identifier.
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}

    @pytest.mark.parametrize(
        ("responder", "reason", "code"), FAILED_RESPONSES, ids=FAILED_IDS
    )
    async def test_any_failed_alias_omits_the_operation_and_retains_the_scope(
        self,
        responder: Any,
        reason: str,
        code: int | None,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"affected": [], "aliases": [ALIAS_2, ALIAS]}
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, _package("other"))
        server.responses[ALIAS] = responder

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        payload = ingestion.payloads[-1]
        assert "affected_version_operations" not in payload.model_fields_set
        # The succeeded applicable record still contributes its additive data.
        assert payload.resolved_packages == ["other"]
        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS
        assert await _identifiers(db_session, target.cve) == {
            SEEDED_IDENTIFIER,
            ("GHSA", ALIAS_2, f"https://github.com/advisories/{ALIAS_2}"),
        }
        assert result.action is UpsertAction.UPDATED
        assert _skips(logs) == [_skip(target.cve_id, reason, status_code=code)]

    async def test_unobserved_scope_values_never_reach_the_payload(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        """Only an emitted replacement carries entries, so an inadmissible
        Phase 1 or alias entry value of an omitted scope fails nothing."""
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(("fixed", f"{SECRET}\x00"))]}],
            "aliases": [ALIAS, ALIAS_2],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id, _package("example", "PyPI", f"pkg:pypi/{SECRET}\x00")
        )
        server.responses[ALIAS_2] = status(503)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        [payload] = ingestion.payloads
        assert "affected_version_operations" not in payload.model_fields_set
        assert payload.resolved_packages == ["example"]
        assert result.action is UpsertAction.UPDATED
        assert await _osv_rows(db_session, target.cve) == set()

    async def test_unsafe_alias_omits_the_operation(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"affected": [], "aliases": [ALIAS, "../x"]}

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert "affected_version_operations" not in (
            ingestion.payloads[-1].model_fields_set
        )
        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS
        assert result.action is UpsertAction.UNCHANGED

    @pytest.mark.parametrize(
        "aliases",
        [[], [OTHER_CVE], [OTHER_CVE, OTHER_CVE_2]],
        ids=["self", "self_and_other_cve", "self_and_two_other_cves"],
    )
    async def test_only_cve_aliases_replace_the_scope_with_the_phase1_entries(
        self,
        aliases: list[str],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        """Step 9: with no alias sub-request, Phase 1 is the complete
        dataset, even when it lists `CVE-*` aliases (served here with
        records that would contribute if requested) and `related` IDs."""
        await _seed(db_session, target, fetcher, server)
        throttle.delays.clear()
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(("introduced", "a1"), ("fixed", "b1"))]}],
            "aliases": [*aliases, target.cve_id],
            "related": [RELATED],
        }
        for record_id in (*aliases, RELATED):
            server.bodies[record_id] = _alias_body(
                target.cve_id,
                _package("cve-alias-pkg"),
                references=[{"type": "FIX", "url": URL_3}],
            )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert server.requested_ids == [target.cve_id]
        assert throttle.delays == []
        assert logs == []
        [*_, payload] = ingestion.payloads
        assert payload.model_fields_set == {"affected_version_operations"}
        assert await _osv_rows(db_session, target.cve) == {_git_row("a1", "b1", False)}
        assert ingestion.references[-1]["upstream"] == []

    async def test_cve_aliases_beside_a_404_alias_replace_the_scope(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"aliases": [OTHER_CVE, ALIAS_2, OTHER_CVE_2]}

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert server.requested_ids == [target.cve_id, ALIAS_2]
        assert _skips(logs) == [
            _skip(target.cve_id, "not_found", record_id=ALIAS_2, status_code=404)
        ]
        assert await _osv_rows(db_session, target.cve) == set()

    async def test_related_ids_are_never_requested_and_contribute_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        related = [RELATED, "openSUSE-SU-2099:0002-1", "CGA-fict-0001", "a/b"]
        server.bodies[target.cve_id] = {
            "affected": [],
            "aliases": [ALIAS_2],
            "related": related,
        }
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, _package("other"))
        for record_id in related[:3]:
            server.bodies[record_id] = _alias_body(
                target.cve_id,
                _package("related-pkg"),
                references=[{"type": "ADVISORY", "url": URL_3}],
            )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert server.requested_ids == [target.cve_id, ALIAS_2]
        assert logs == []
        [payload] = ingestion.payloads
        assert payload.resolved_packages == ["other"]
        assert ingestion.references[0]["upstream"] == []
        assert await _osv_rows(db_session, target.cve) == {_package_row("other")}

    async def test_equal_replacement_is_unchanged(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS

    async def test_other_scopes_are_never_touched(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        db_session.add(
            CVEAffectedVersion(
                cve_id=target.cve.id, source_container="cna", product="kept"
            )
        )
        await db_session.flush()
        server.bodies[target.cve_id] = {"affected": []}

        await fetcher.fetch_single(target.cve_id, db_session)

        products = await db_session.scalars(
            select(CVEAffectedVersion.product).where(
                CVEAffectedVersion.cve_id == target.cve.id
            )
        )
        assert products.all() == ["kept"]


@pytest.mark.integration
class TestConflictKey:
    async def test_live_mirror_repositories_give_distinct_entries(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = load_record_fixture("cve_git_mirror_repos")

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        # The record's `related` IDs are never requested.
        assert server.requested_ids == [target.cve_id]
        rows = await _osv_rows(db_session, target.cve)
        assert {row[4] for row in rows} == {
            "https://git.example.invalid/mirror/4",
            "https://sourceware.org/git/glibc.git",
        }
        assert len(rows) == 2 * len({row[5:] for row in rows})

    async def test_same_name_in_two_ecosystems_and_two_packages_with_equal_bounds(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {"aliases": [ALIAS, ALIAS_2]}
        server.bodies[ALIAS] = _alias_body(
            target.cve_id, _package("setuptools", "PyPI"), _package("other", "PyPI")
        )
        server.bodies[ALIAS_2] = _alias_body(
            target.cve_id, _package("setuptools", "Bitnami")
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _osv_rows(db_session, target.cve) == {
            _package_row("setuptools", "PyPI"),
            _package_row("other", "PyPI"),
            _package_row("setuptools", "Bitnami"),
        }

    async def test_identical_entries_from_two_aliases_collapse(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(*GIT_BODY_EVENTS), _git(*GIT_BODY_EVENTS)]}],
            "aliases": [ALIAS, ALIAS_2],
        }
        for record_id in (ALIAS, ALIAS_2):
            server.bodies[record_id] = _alias_body(target.cve_id, _package("example"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS
        count = await db_session.scalars(
            select(CVEAffectedVersion.id).where(
                CVEAffectedVersion.cve_id == target.cve.id
            )
        )
        assert len(count.all()) == 2

    @pytest.mark.parametrize(
        "second",
        [
            _package("example", "PyPI", "pkg:pypi/example"),
            _package("example", events=(("introduced", "0"), ("last_affected", "1.0"))),
        ],
        ids=["differing_purl", "differing_inclusiveness"],
    )
    async def test_same_key_with_differing_content_fails_before_any_write(
        self,
        second: dict[str, Any],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {"aliases": [ALIAS, ALIAS_2]}
        server.bodies[ALIAS] = _alias_body(target.cve_id, _package("example"))
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, second)

        with capture_logs() as logs, pytest.raises(ValidationError):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == 0
        assert logs == []
        assert await _osv_rows(db_session, target.cve) == set()


# ---------------------------------------------------------------------------
# External identifiers
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalIdentifiers:
    async def test_whitelisted_single_cve_aliases_are_emitted_with_their_url(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        ghsa, pysec, rustsec = (
            "GHSA-8hfj-j24r-96c4",
            "PYSEC-2025-49",
            "RUSTSEC-2023-0034",
        )
        server.bodies[target.cve_id] = {"aliases": [ghsa, pysec, rustsec]}
        server.bodies[ghsa] = _retargeted(
            "alias_ghsa_semver", "CVE-2022-24785", target.cve_id
        )
        server.bodies[pysec] = _retargeted(
            "alias_pysec", "CVE-2025-47273", target.cve_id
        )
        server.bodies[rustsec] = _retargeted(
            "alias_rustsec", "CVE-2023-26964", target.cve_id
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert ingestion.payloads[0].external_identifiers == [
            ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.GHSA,
                identifier=ghsa,
                url=f"https://github.com/advisories/{ghsa}",
            ),
            ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.PYSEC,
                identifier=pysec,
                url=f"https://osv.dev/vulnerability/{pysec}",
            ),
            ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.RUSTSEC,
                identifier=rustsec,
                url=f"https://rustsec.org/advisories/{rustsec}",
            ),
        ]
        assert await _identifiers(db_session, target.cve) == {
            ("GHSA", ghsa, f"https://github.com/advisories/{ghsa}"),
            ("PYSEC", pysec, f"https://osv.dev/vulnerability/{pysec}"),
            ("RUSTSEC", rustsec, f"https://rustsec.org/advisories/{rustsec}"),
        }

    async def test_excluded_prefixes_are_not_emitted_but_their_data_is_used(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        aliases = ["GO-2024-2687", "BIT-golang-2023-45288", "CURL-CVE-2023-38545"]
        server.bodies[target.cve_id] = {"aliases": aliases}
        for record_id, name, real in (
            ("GO-2024-2687", "alias_go", "CVE-2023-45288"),
            ("BIT-golang-2023-45288", "alias_bit", "CVE-2023-45288"),
            ("CURL-CVE-2023-38545", "alias_curl_no_package", "CVE-2023-38545"),
        ):
            server.bodies[record_id] = _retargeted(name, real, target.cve_id)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        [payload] = ingestion.payloads
        assert "external_identifiers" not in payload.model_fields_set
        assert await _identifiers(db_session, target.cve) == set()
        assert payload.resolved_packages == ["stdlib", "golang.org/x/net", "golang"]
        rows = await _osv_rows(db_session, target.cve)
        assert {row[1] for row in rows} == {
            *payload.resolved_packages,
            None,  # the CURL record's entry has no package
        }

    async def test_unknown_prefix_is_not_emitted(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        unknown = "ASB-A-299477569"
        server.bodies[target.cve_id] = {"aliases": [unknown, "GHSA"]}
        server.bodies[unknown] = _alias_body(target.cve_id, _package("android"))
        server.bodies["GHSA"] = _alias_body(target.cve_id, _package("no-dash"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert "external_identifiers" not in ingestion.payloads[0].model_fields_set

    async def test_omitted_alias_deletes_no_identifier(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {"references": [{"url": URL_3}]}

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}

    async def test_identical_candidates_from_two_aliases_collapse(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {"aliases": [ALIAS, ALIAS]}
        server.bodies[ALIAS] = _alias_body(target.cve_id, _package("example"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert server.requested_ids == [target.cve_id, ALIAS, ALIAS]
        assert len(ingestion.payloads[0].external_identifiers or ()) == 2
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}

    async def test_differing_candidates_fail_before_any_write(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OSV derives every identifier field from the requested ID, so the
        policy is substituted to prove that the fetcher passes every
        candidate to the payload and never resolves a conflict itself."""
        server.bodies[target.cve_id] = {"aliases": [ALIAS, ALIAS_2]}
        for record_id in (ALIAS, ALIAS_2):
            server.bodies[record_id] = _alias_body(target.cve_id)

        def external_identifier(
            record_id: str, record: Any, cve_id: str
        ) -> ExternalIdentifierEntry:
            return ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.GHSA,
                identifier=ALIAS,
                url=f"https://advisory.example.invalid/{record_id}",
            )

        monkeypatch.setattr(
            osv_vulnerability_record, "external_identifier", external_identifier
        )

        with pytest.raises(ValidationError):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == 0
        assert await _identifiers(db_session, target.cve) == set()


# ---------------------------------------------------------------------------
# Applicability (Algorithm step 6)
# ---------------------------------------------------------------------------

GHSA_35JH_CVES: Final = ["CVE-2021-23337", "CVE-2026-4800"]
"""The CVE aliases OSV serves for `GHSA-35jh-r3h4-6jhm`, which GitHub
assigns to CVE-2021-23337 only."""


def _non_applicable_body(aliases: list[str]) -> dict[str, Any]:
    """An alias record listing `aliases` that would contribute every kind of
    data if it applied, including values that would fail the payload."""
    return {
        "aliases": aliases,
        "affected": [
            _package("non-applicable", versions=["2.0"]),
            _package("e" * 2049, "E" * 51, f"pkg:pypi/{SECRET}\x00"),
        ],
        "references": [{"type": "FIX", "url": URL_3}],
    }


@pytest.mark.integration
class TestApplicability:
    async def test_applicable_alias_contributes_every_kind_of_data(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {"aliases": [ALIAS]}
        server.bodies[ALIAS] = _alias_body(
            target.cve_id,
            _package("example"),
            references=[{"type": "FIX", "url": URL_3}],
        )
        server.bodies[ALIAS]["aliases"] += [ALIAS_2, "CURL-CVE-2099-0001"]

        await fetcher.fetch_single(target.cve_id, db_session)

        [payload] = ingestion.payloads
        assert payload.resolved_packages == ["example"]
        assert ingestion.references[0]["upstream"] == [
            AutomaticReferenceInput(url=URL_3, explicit_type=ReferenceType.PATCH)
        ]
        assert await _osv_rows(db_session, target.cve) == {_package_row("example")}
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}

    @pytest.mark.parametrize(
        "aliases",
        [
            None,
            [],
            [ALIAS_2, "CURL-CVE-2099-0001"],
            [OTHER_CVE],
            ["target", OTHER_CVE],
            [OTHER_CVE, "target"],
            ["target", "target"],
            GHSA_35JH_CVES,
        ],
        ids=[
            "absent",
            "empty",
            "no_cve",
            "other_cve",
            "two_cves",
            "two_cves_reversed",
            "repeated_cve",
            "ghsa_35jh_shape",
        ],
    )
    async def test_non_applicable_alias_is_observed_but_contributes_nothing(
        self,
        aliases: list[str] | None,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        """The record is a succeeded sub-request: no guard and no WARNING,
        and the `osv` replacement carries only the Phase 1 entries. Its
        inadmissible values fail nothing because they are never used."""
        await _seed(db_session, target, fetcher, server)
        listed = [target.cve_id if a == "target" else a for a in aliases or ()]
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(*GIT_BODY_EVENTS)]}],
            "aliases": [ALIAS],
            "references": [{"type": "WEB", "url": URL_4}],
        }
        server.bodies[ALIAS] = _non_applicable_body(listed)
        if aliases is None:
            del server.bodies[ALIAS]["aliases"]

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert server.requested_ids == [target.cve_id, ALIAS]
        assert logs == []
        payload = ingestion.payloads[-1]
        assert payload.model_fields_set == {"affected_version_operations"}
        assert ingestion.references[-1]["upstream"] == [
            AutomaticReferenceInput(url=URL_4)
        ]
        # The seeded alias row is replaced by the Phase 1 entries only.
        assert await _osv_rows(db_session, target.cve) == {_git_row(None, "c1", False)}
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}
        persisted = await _references(db_session, target.ticket)
        assert URL_3 not in persisted

    async def test_live_multi_cve_records_contribute_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        """CVE-2023-4863: its GHSA and ASB records list two CVEs even after
        retargeting one to the processed CVE; its `CVE-2023-5129` alias is
        never requested; the other aliases have no record (HTTP 404)."""
        cve_body = load_record_fixture("cve_multi_cve_aliases")
        server.bodies[target.cve_id] = cve_body
        for record_id, name in (
            ("GHSA-j7hp-h8jx-5ppr", "alias_ghsa_multi_cve"),
            ("ASB-A-299477569", "alias_asb_no_purl"),
        ):
            server.bodies[record_id] = _retargeted(name, "CVE-2023-4863", target.cve_id)

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        sub_requests = [a for a in cve_body["aliases"] if not a.startswith("CVE-")]
        assert server.requested_ids == [target.cve_id, *sub_requests]
        assert "CVE-2023-5129" in cve_body["aliases"]
        assert [entry["reason"] for entry in _skips(logs)] == ["not_found"] * 4
        [payload] = ingestion.payloads
        assert payload.model_fields_set == {"affected_version_operations"}
        assert await _identifiers(db_session, target.cve) == set()
        phase1 = osv_vulnerability_record.parse_cve_record(cve_body)
        assert [c.url for c in ingestion.references[0]["upstream"]] == [
            c.url for c in osv_vulnerability_record.reference_candidates(phase1)
        ]
        assert {row[4] for row in await _osv_rows(db_session, target.cve)} == {
            "https://github.com/webmproject/libwebp"
        }


# ---------------------------------------------------------------------------
# References, package candidates, and results
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReferences:
    async def test_source_then_phase1_then_applicable_aliases_in_declared_order(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        refs = [f"https://advisory.example.invalid/ref/{n}" for n in range(12)]
        server.bodies[target.cve_id] = {
            "aliases": [ALIAS, "GHSA-fict-0404-dddd", ALIAS_3, ALIAS_2, ALIAS_4],
            "related": [RELATED],
            "references": [
                {"type": "FIX", "url": refs[0]},
                {"type": "WEB", "url": refs[1]},
                {"type": "ADVISORY"},
                {"type": None, "url": refs[2]},
            ],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id,
            references=[
                {"type": "REPORT", "url": refs[3]},
                {"type": "INTRODUCED", "url": refs[4]},
            ],
        )
        # Not applicable: lists another CVE.
        server.bodies[ALIAS_3] = _alias_body(
            OTHER_CVE, references=[{"type": "ADVISORY", "url": refs[10]}]
        )
        server.bodies[ALIAS_2] = _alias_body(
            target.cve_id,
            references=[
                {"type": "ARTICLE", "url": refs[5]},
                {"type": "PACKAGE", "url": refs[6]},
            ],
        )
        server.bodies[ALIAS_4] = _alias_body(
            target.cve_id,
            references=[
                {"type": "EVIDENCE", "url": refs[7]},
                {"type": "GIT", "url": refs[8]},
                {"type": "fix", "url": refs[9]},
            ],
        )
        server.bodies[RELATED] = _alias_body(
            target.cve_id, references=[{"type": "ADVISORY", "url": refs[11]}]
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        source_url = SOURCE_URL.format(cve_id=target.cve_id)
        assert call["ticket_id"] == target.ticket.id  # type: ignore[union-attr]
        assert call["cve_id"] == target.cve_id
        assert call["source"] == NAME
        assert call["source_reference"] == AutomaticReferenceInput(
            url=source_url, title="OSV", explicit_type=ReferenceType.ADVISORY
        )
        assert call["upstream"] == [
            AutomaticReferenceInput(url=refs[0], explicit_type=ReferenceType.PATCH),
            AutomaticReferenceInput(url=refs[1]),
            AutomaticReferenceInput(url=refs[2]),
            AutomaticReferenceInput(url=refs[3], explicit_type=ReferenceType.ISSUE),
            AutomaticReferenceInput(url=refs[4]),
            AutomaticReferenceInput(url=refs[5], explicit_type=ReferenceType.ARTICLE),
            AutomaticReferenceInput(url=refs[6]),
            AutomaticReferenceInput(url=refs[7]),
            AutomaticReferenceInput(url=refs[8]),
            AutomaticReferenceInput(url=refs[9]),
        ]
        assert all(entry.upstream_tags is None for entry in call["upstream"])
        persisted = await _references(db_session, target.ticket)
        assert persisted[source_url] == ("OSV", "advisory", NAME)
        assert persisted[refs[0]] == (None, "patch", NAME)
        assert persisted[refs[3]] == (None, "issue", NAME)
        assert persisted[refs[5]] == (None, "article", NAME)
        assert len(persisted) == 11

    async def test_live_records_keep_the_documented_order(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = load_record_fixture("cve_git_ranges")
        server.bodies["GHSA-jfh8-c2jp-5v3q"] = _retargeted(
            "alias_ghsa_ecosystem", "CVE-2021-44228", target.cve_id
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        expected = [
            reference["url"]
            for name in ("cve_git_ranges", "alias_ghsa_ecosystem")
            for reference in load_record_fixture(name)["references"]
        ]
        assert [entry.url for entry in ingestion.references[0]["upstream"]] == expected
        # The record's three `related` IDs are never requested.
        assert server.requested_ids == [target.cve_id, "GHSA-jfh8-c2jp-5v3q"]
        assert _skips(logs) == []

    async def test_nul_in_a_reference_url_skips_that_candidate_only(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {
            "affected": [],
            "references": [
                {"type": "FIX", "url": f"{URL_1}?{SECRET}\x00"},
                {"type": f"FIX{SECRET}\x00", "url": URL_2},
            ],
        }

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert await _references(db_session, target.ticket) == {
            SOURCE_URL.format(cve_id=target.cve_id): ("OSV", "advisory", NAME),
            URL_2: (None, None, NAME),
        }
        assert logs == [
            {
                "event": "automatic_reference_rejected",
                "log_level": "warning",
                "cve_id": target.cve_id,
                "source": NAME,
                "reason": "control_character",
            }
        ]
        _assert_no_raw_value(logs, SECRET)


@pytest.mark.integration
class TestResults:
    async def test_payload_omits_every_global_field(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {
            "summary": SECRET,
            "details": PERSONAL,
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T00:00:00Z",
            "withdrawn": "2026-01-03T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            "credits": [{"name": PERSONAL}],
            "affected": [],
            "aliases": [ALIAS],
        }
        server.bodies[ALIAS] = _alias_body(target.cve_id, _package("example"))

        await fetcher.fetch_single(target.cve_id, db_session)

        [payload] = ingestion.payloads
        assert payload.model_fields_set == {
            "affected_version_operations",
            "external_identifiers",
            "resolved_packages",
        }

    async def test_upsert_cve_receives_the_canonical_id_and_enum_source(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[str, object]] = []
        real = cve_service.upsert_cve

        async def spy(
            db: AsyncSession, cve_id: str, source: Any, payload: CVEIngestPayload
        ) -> Any:
            calls.append((cve_id, source))
            return await real(db, cve_id, source, payload)

        monkeypatch.setattr(cve_service, "upsert_cve", spy)
        server.bodies[target.cve_id] = {"affected": []}

        await fetcher.fetch_single(target.cve_id, db_session)

        assert calls == [(target.cve_id, CVESourceType.OSV)]
        assert calls[0][1] is CVESourceType.OSV

    async def test_resolved_packages_are_the_deduplicated_applicable_alias_names(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {
            "aliases": [ALIAS, ALIAS_3, ALIAS_2],
            "related": [RELATED],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id, _package("zeta"), _package("alpha", "npm")
        )
        server.bodies[ALIAS_3] = _alias_body(None, _package("no-cve-pkg"))
        server.bodies[ALIAS_2] = _alias_body(
            target.cve_id, _package("alpha"), _package(None), _package("beta")
        )
        server.bodies[RELATED] = _alias_body(target.cve_id, _package("related-pkg"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.payloads[0].resolved_packages == ["zeta", "alpha", "beta"]
        assert result.post_ingest == PostIngestTasks(
            ticket_id=str(target.ticket.id),  # type: ignore[union-attr]
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["alpha", "beta", "zeta"],
        )

    async def test_related_records_give_no_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        body = load_record_fixture("cve_references_only")
        server.bodies[target.cve_id] = body
        for record_id in body["related"]:
            server.bodies[record_id] = {
                "affected": [{"package": {"name": "suse-example"}}],
                "related": [target.cve_id],
            }

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert server.requested_ids == [target.cve_id]
        # An empty replacement of an empty scope changes nothing.
        assert result == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert "resolved_packages" not in ingestion.payloads[0].model_fields_set

    async def test_no_package_candidate_is_updated_without_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {
            "affected": [{"ranges": [_git(*GIT_BODY_EVENTS)]}],
            "aliases": [ALIAS_3],
        }
        server.bodies[ALIAS_3] = _alias_body(target.cve_id, {}, references=[])

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert "resolved_packages" not in ingestion.payloads[0].model_fields_set
        assert result == CVEFetchResult(UpsertAction.UPDATED, None)

    async def test_unchanged_without_handoff_and_repeat_is_idempotent(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {"references": [{"url": URL_1}]}

        first = await fetcher.fetch_single(target.cve_id, db_session)
        references = await _references(db_session, target.ticket)
        second = await fetcher.fetch_single(target.cve_id, db_session)

        assert first == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert second == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert await _references(db_session, target.ticket) == references
        assert len(references) == 2

    async def test_unchanged_with_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == ["example"]

    async def test_upsert_action_is_passed_through_unmodified(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real = cve_service.upsert_cve

        async def created(
            db: AsyncSession, cve_id: str, source: Any, payload: CVEIngestPayload
        ) -> Any:
            result = await real(db, cve_id, source, payload)
            return result.model_copy(update={"action": UpsertAction.CREATED})

        monkeypatch.setattr(cve_service, "upsert_cve", created)
        server.bodies[target.cve_id] = {"affected": []}

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.CREATED, None)

    async def test_success_status_is_written_in_the_session(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {"affected": []}

        await fetcher.fetch_single(target.cve_id, db_session)

        status_value = await db_session.scalar(
            select(CVESource.status).where(
                CVESource.cve_id == target.cve.id, CVESource.source == "osv"
            )
        )
        assert status_value == CVESourceFetchStatus.SUCCESS

    async def test_fetch_single_records_no_metric(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)

        assert (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        ) == (0, 0, 0, 0)

    async def test_ticketless_cve_gets_one_ingestion_ticket(
        self,
        db_session: AsyncSession,
        ticketless: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[ticketless.cve_id] = {
            "affected": [{"ranges": [_git(*GIT_BODY_EVENTS)]}]
        }

        result = await fetcher.fetch_single(ticketless.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UPDATED, None)
        tickets = (
            await db_session.scalars(
                select(Ticket).where(Ticket.cve_id == ticketless.cve.id)
            )
        ).all()
        assert len(tickets) == 1
        assert await ticket_events(db_session, tickets[0]) == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, ticketless.cve_id, None, None),
        ]
        assert await _osv_rows(db_session, ticketless.cve) == {
            _git_row(None, "c1", False)
        }


# ---------------------------------------------------------------------------
# Log privacy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLogPrivacy:
    async def test_a_full_fetch_logs_only_bounded_skip_events(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = {
            "summary": SECRET,
            "credits": [{"name": PERSONAL, "contact": [PERSONAL]}],
            "aliases": [
                ALIAS,
                "x/\x00" + SECRET,
                f"CVE-{SECRET}",
                ALIAS_2,
                ALIAS_3,
                ALIAS_4,
            ],
            "related": [RELATED, SECRET],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id,
            _package("example"),
            credits=[{"name": PERSONAL}],
            details=SECRET,
        )
        server.responses[ALIAS_2] = status(500, f"{SECRET} {PERSONAL}".encode())
        server.responses[ALIAS_3] = raising(httpx.ConnectError(f"{SECRET} {PERSONAL}"))
        server.responses[ALIAS_4] = status(
            200, f'{{"references": [{{"url": ["{PERSONAL}"]}}]}}'.encode()
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert logs == [
            _skip(target.cve_id, "unsafe_id", record_id=None),
            _skip(target.cve_id, "http_status", record_id=ALIAS_2, status_code=500),
            _skip(target.cve_id, "transport", record_id=ALIAS_3),
            _skip(target.cve_id, "invalid_body", record_id=ALIAS_4, status_code=200),
        ]
        for entry in logs:
            assert set(entry) <= SKIP_KEYS
        _assert_no_raw_value(logs, SECRET, PERSONAL, "Alice")
