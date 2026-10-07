"""Tests for `SyncOsvAdvisories.fetch_single()`
(backend/app/services/tickets/sync_osv_advisories.py).

Owning specifications:

- docs/features/tickets/cve-sync-osv.md (Algorithm steps 1-17; Field
  Mapping; GIT Range Event Parsing; Response Validation, including External
  String Admissibility; OSV Reference Type Mapping; External Identifier
  Policy; `fetch_single` Method; Error Handling, `fetch_single()` table,
  data preservation; Post-Ingest Package Candidates; `CompletenessGuardError`).
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
their CVE alias retargeted where the External Identifier Policy guard is
exercised) or minimal fictional bodies. The throttle sleep is recorded,
never slept. Outcome tests that end before any database work use a session
that fails on any use, and spies on `cve_service.upsert_cve()` and
`reference_service.upsert_references()` prove no mutation was attempted;
they are unit tests. Ingestion tests run the real `upsert_cve()` and
`upsert_references()` on `db_session`, rolled back at teardown. All
identifiers and texts are fictional.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Iterable, Mapping
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
RELATED: Final = "SUSE-SU-2099:0001-1"
RELATED_2: Final = "openSUSE-SU-2099:0002-1"

SKIP_KEYS: Final = frozenset(
    {
        "event",
        "log_level",
        "cve_id",
        "fetcher_name",
        "record_kind",
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
    """The recorded step-16 sleeps: each delay, and how many requests the
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
    record_kind: str = "alias",
    record_id: str | None = ALIAS,
    status_code: int | None = None,
) -> dict[str, Any]:
    """The exact expected skip WARNING."""
    expected: dict[str, Any] = {
        "event": OSV_SUBREQUEST_SKIPPED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "record_kind": record_kind,
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
"""Every failed-sub-request response kind (step 11), its WARNING reason,
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
            {"affected": None, "references": None, "aliases": None, "related": None},
            {"references": [], "aliases": [], "related": []},
            {"withdrawn": "2026-01-01T00:00:00Z", "details": PERSONAL},
        ],
        ids=["empty", "unconsumed_only", "null_fields", "empty_arrays", "withdrawn"],
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
            {"related": [1]},
            {"references": [{"url": [SECRET]}]},
            {"affected": [{"ranges": [{"type": "GIT", "events": [{SECRET: "x"}]}]}]},
            {"affected": [{"ranges": [{"type": "GIT", "repo": [SECRET]}]}]},
        ],
        ids=[
            "array_root",
            "string_root",
            "aliases_string",
            "related_integer",
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


def _listing(server: OsvServer, *, aliases: list[str], related: list[str]) -> str:
    """Serve a Phase 1 record listing only `aliases` and `related`."""
    cve_id = fictional_cve_id()
    server.bodies[cve_id] = {"aliases": aliases, "related": related}
    return cve_id


@pytest.mark.unit
class TestFailedSubRequests:
    @pytest.mark.parametrize("record_kind", ["alias", "related"])
    @pytest.mark.parametrize(
        ("responder", "reason", "code"), FAILED_RESPONSES, ids=FAILED_IDS
    )
    async def test_each_failure_kind_is_one_bounded_skip_and_triggers_the_guard(
        self,
        record_kind: str,
        responder: Any,
        reason: str,
        code: int | None,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        listed = {"aliases": [ALIAS], "related": []}
        if record_kind == "related":
            listed = {"aliases": [], "related": [ALIAS]}
        cve_id = _listing(server, **listed)
        server.responses[ALIAS] = responder

        with capture_logs() as logs, pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS]
        assert logs == [
            _skip(cve_id, reason, record_kind=record_kind, status_code=code)
        ]
        _assert_no_raw_value(logs, SECRET)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("record_kind", ["alias", "related"])
    @pytest.mark.parametrize("record_id", UNSAFE_IDS)
    async def test_unsafe_id_is_never_requested_nor_logged(
        self,
        record_kind: str,
        record_id: str,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
        throttle: Throttle,
    ) -> None:
        listed = {"aliases": [record_id], "related": []}
        if record_kind == "related":
            listed = {"aliases": [], "related": [record_id]}
        cve_id = _listing(server, **listed)

        with capture_logs() as logs, pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id]
        assert throttle.delays == []
        assert logs == [
            _skip(cve_id, "unsafe_id", record_kind=record_kind, record_id=None)
        ]
        if record_id:
            _assert_no_raw_value(logs, record_id)
        assert ingestion.calls == 0

    async def test_every_request_addresses_one_segment_on_the_osv_host(
        self, fetcher: SyncOsvAdvisories, server: OsvServer
    ) -> None:
        safe = ["GHSA-fict-0003-cccc", "PYSEC-2099-1", "SUSE-SU-2099:0003-1", "A.b_c"]
        cve_id = _listing(
            server, aliases=[*UNSAFE_IDS[:6], *safe[:2]], related=[*UNSAFE_IDS, *safe]
        )
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
        cve_id = _listing(server, aliases=[ALIAS, "..", ALIAS_2], related=[RELATED])
        server.responses[ALIAS] = status(503)
        server.responses[ALIAS_2] = raising(httpx.ConnectError("refused"))
        server.responses[RELATED] = status(200, b"{")

        with capture_logs() as logs, pytest.raises(CompletenessGuardError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS, ALIAS_2, RELATED]
        assert [entry["reason"] for entry in logs] == [
            "http_status",
            "unsafe_id",
            "transport",
            "invalid_body",
        ]
        assert ingestion.calls == 0
        assert str(raised.value) == "Every OSV alias and related sub-request failed"
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)

    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    @pytest.mark.parametrize("record_kind", ["alias", "related"])
    async def test_whole_run_signal_in_a_sub_request_is_never_absorbed(
        self,
        record_kind: str,
        signal: BaseException,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        listed = {"aliases": [ALIAS, ALIAS_2], "related": []}
        if record_kind == "related":
            listed = {"aliases": [], "related": [ALIAS, ALIAS_2]}
        cve_id = _listing(server, **listed)

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
        cve_id = _listing(server, aliases=[ALIAS], related=[])
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
# Throttle (Algorithm step 16)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestThrottle:
    async def test_class_default_separates_every_request_outside_a_run(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, aliases=[ALIAS, "..", ALIAS_2], related=[RELATED])
        for record_id in (ALIAS, ALIAS_2, RELATED):
            server.responses[record_id] = status(503)
        assert fetcher.config is None

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_ids == [cve_id, ALIAS, ALIAS_2, RELATED]
        # One delay between each consecutive pair; none for the unsafe ID.
        assert throttle.after == [1, 2, 3]
        assert throttle.delays == [0.2, 0.2, 0.2]
        assert SyncOsvAdvisories.default_request_delay == 0.2

    async def test_run_snapshot_delay_applies_inside_a_run(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        throttle: Throttle,
    ) -> None:
        cve_id = _listing(server, aliases=[ALIAS], related=[RELATED, RELATED_2])
        for record_id in (ALIAS, RELATED, RELATED_2):
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
        cve_id = _listing(server, aliases=["a/b"], related=[])

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

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
        cve_id = _listing(server, aliases=[ALIAS], related=[])
        server.bodies[ALIAS] = _alias_body(cve_id, affected)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        # A payload failure, not a failed sub-request: no skip WARNING.
        assert logs == []
        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)

    async def test_nul_in_a_related_package_name_fails_the_cve_before_any_write(
        self,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = _listing(server, aliases=[], related=[RELATED])
        server.bodies[RELATED] = {"affected": [{"package": {"name": NUL}}]}

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert logs == []
        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)

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
        cve_id = _listing(server, aliases=[ALIAS], related=[])
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
            "aliases": [ALIAS, "a/b"],
            "related": [RELATED],
            "references": [{"url": URL_4}],
        }
        server.responses[ALIAS] = status(500)
        server.responses[RELATED] = status(403)
        calls = ingestion.calls

        with pytest.raises(CompletenessGuardError):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == calls
        assert await _osv_rows(db_session, target.cve) == SEEDED_ROWS
        assert await _identifiers(db_session, target.cve) == {SEEDED_IDENTIFIER}
        assert await _references(db_session, target.ticket) == references

    @pytest.mark.parametrize("survivor", ["alias", "related"])
    @pytest.mark.parametrize("outcome", ["success", "not_found"])
    async def test_one_success_or_404_prevents_the_guard(
        self,
        survivor: str,
        outcome: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        survivor_id = ALIAS_2 if survivor == "alias" else RELATED_2
        server.bodies[target.cve_id] = {
            "aliases": [ALIAS, *([ALIAS_2] if survivor == "alias" else [])],
            "related": [RELATED, *([RELATED_2] if survivor == "related" else [])],
        }
        server.responses[ALIAS] = status(503)
        server.responses[RELATED] = raising(httpx.ReadTimeout("timed out"))
        if outcome == "success":
            server.bodies[survivor_id] = {}

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert isinstance(result, CVEFetchResult)
        [payload] = ingestion.payloads
        # A failed alias leaves the scope unobserved.
        assert "affected_version_operations" not in payload.model_fields_set
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
        server.bodies[target.cve_id] = {
            "affected": [],
            "aliases": [ALIAS_2, ALIAS],
            "related": [RELATED],
        }
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, _package("other"))
        server.responses[ALIAS] = responder
        server.bodies[RELATED] = {"affected": [{"package": {"name": "related-pkg"}}]}

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        payload = ingestion.payloads[-1]
        assert "affected_version_operations" not in payload.model_fields_set
        # The succeeded records still contribute their additive data.
        assert payload.resolved_packages == ["other", "related-pkg"]
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
        ("responder", "reason", "code"), FAILED_RESPONSES[:3], ids=FAILED_IDS[:3]
    )
    async def test_related_failure_does_not_affect_the_scope(
        self,
        responder: Any,
        reason: str,
        code: int | None,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        await _seed(db_session, target, fetcher, server)
        server.bodies[target.cve_id] = {
            "affected": [],
            "aliases": [ALIAS_2],
            "related": [RELATED, "a/b"],
        }
        server.bodies[ALIAS_2] = _alias_body(target.cve_id, _package("other"))
        server.responses[RELATED] = responder

        await fetcher.fetch_single(target.cve_id, db_session)

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
        body = load_record_fixture("cve_git_mirror_repos")
        body["related"] = []
        server.bodies[target.cve_id] = body

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
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

    async def test_excluded_records_are_not_emitted_but_their_data_is_used(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        mismatched = "GHSA-jfh8-c2jp-5v3q"
        multi = "GHSA-j7hp-h8jx-5ppr"
        cve_alias = fictional_cve_id()
        aliases = [
            mismatched,
            multi,
            "GO-2024-2687",
            "BIT-golang-2023-45288",
            "CURL-CVE-2023-38545",
            cve_alias,
        ]
        server.bodies[target.cve_id] = {"aliases": aliases}
        # The single CVE alias names another CVE: the guard excludes it.
        server.bodies[mismatched] = load_record_fixture("alias_ghsa_ecosystem")
        # Two CVE aliases after retargeting one: the guard excludes it.
        server.bodies[multi] = _retargeted(
            "alias_ghsa_multi_cve", "CVE-2023-4863", target.cve_id
        )
        for record_id, name in (
            ("GO-2024-2687", "alias_go"),
            ("BIT-golang-2023-45288", "alias_bit"),
        ):
            server.bodies[record_id] = _retargeted(
                name, "CVE-2023-45288", target.cve_id
            )
        server.bodies["CURL-CVE-2023-38545"] = _retargeted(
            "alias_curl_no_package", "CVE-2023-38545", target.cve_id
        )
        server.bodies[cve_alias] = _alias_body(target.cve_id, _package("cve-pkg"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        [payload] = ingestion.payloads
        assert "external_identifiers" not in payload.model_fields_set
        assert await _identifiers(db_session, target.cve) == set()
        assert payload.resolved_packages == [
            "org.apache.logging.log4j:log4j-core",
            "com.guicedee.services:log4j-core",
            "org.xbib.elasticsearch:log4j",
            "libwebp-sys2",
            "electron",
            "stdlib",
            "golang.org/x/net",
            "golang",
            "cve-pkg",
        ]
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
# References, package candidates, and results
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReferences:
    async def test_source_then_phase1_alias_and_related_in_declared_order(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        refs = [f"https://advisory.example.invalid/ref/{n}" for n in range(12)]
        server.bodies[target.cve_id] = {
            "aliases": [ALIAS, "GHSA-fict-0404-dddd", ALIAS_2],
            "related": [RELATED, "SUSE-SU-2099:0500-1", RELATED_2],
            "references": [
                {"type": "FIX", "url": refs[0]},
                {"type": "WEB", "url": refs[1]},
                {"type": "ADVISORY"},
                {"type": None, "url": refs[2]},
            ],
        }
        server.responses["SUSE-SU-2099:0500-1"] = status(500)
        server.bodies[ALIAS] = _alias_body(
            target.cve_id,
            references=[
                {"type": "REPORT", "url": refs[3]},
                {"type": "INTRODUCED", "url": refs[4]},
            ],
        )
        server.bodies[ALIAS_2] = _alias_body(
            target.cve_id,
            references=[
                {"type": "ARTICLE", "url": refs[5]},
                {"type": "PACKAGE", "url": refs[6]},
            ],
        )
        server.bodies[RELATED] = {
            "references": [
                {"type": "ADVISORY", "url": refs[7]},
                {"type": "EVIDENCE", "url": refs[8]},
                {"type": "GIT", "url": refs[9]},
            ]
        }
        server.bodies[RELATED_2] = {
            "references": [
                {"type": "DISCUSSION", "url": refs[10]},
                {"type": "fix", "url": refs[11]},
            ]
        }

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
            AutomaticReferenceInput(url=refs[7], explicit_type=ReferenceType.ADVISORY),
            AutomaticReferenceInput(url=refs[8]),
            AutomaticReferenceInput(url=refs[9]),
            AutomaticReferenceInput(url=refs[10]),
            AutomaticReferenceInput(url=refs[11]),
        ]
        assert all(entry.upstream_tags is None for entry in call["upstream"])
        persisted = await _references(db_session, target.ticket)
        assert persisted[source_url] == ("OSV", "advisory", NAME)
        assert persisted[refs[0]] == (None, "patch", NAME)
        assert persisted[refs[3]] == (None, "issue", NAME)
        assert persisted[refs[5]] == (None, "article", NAME)
        assert persisted[refs[7]] == (None, "advisory", NAME)
        assert len(persisted) == 13

    async def test_live_records_keep_the_documented_order(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        cve_body = load_record_fixture("cve_git_ranges")
        server.bodies[target.cve_id] = cve_body
        server.bodies["GHSA-jfh8-c2jp-5v3q"] = load_record_fixture(
            "alias_ghsa_ecosystem"
        )
        server.bodies["SUSE-SU-2021:4096-1"] = load_record_fixture("related_suse")
        server.bodies["openSUSE-SU-2024:11666-1"] = load_record_fixture(
            "related_opensuse_reference_without_url"
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        expected = [
            reference["url"]
            for name in (
                "cve_git_ranges",
                "alias_ghsa_ecosystem",
                "related_suse",
                "related_opensuse_reference_without_url",
            )
            for reference in load_record_fixture(name)["references"]
            if reference.get("url") is not None
        ]
        assert [entry.url for entry in ingestion.references[0]["upstream"]] == expected
        # openSUSE-SU-2021:1577-1 has no fixture: an authoritative 404 skip.
        assert _skips(logs) == [
            _skip(
                target.cve_id,
                "not_found",
                record_kind="related",
                record_id="openSUSE-SU-2021:1577-1",
                status_code=404,
            )
        ]

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

    async def test_resolved_packages_is_the_deduplicated_alias_then_related_union(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
        ingestion: Ingestion,
    ) -> None:
        server.bodies[target.cve_id] = {
            "aliases": [ALIAS, ALIAS_2],
            "related": [RELATED, RELATED_2],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id, _package("zeta"), _package("alpha", "npm")
        )
        server.bodies[ALIAS_2] = _alias_body(
            target.cve_id, _package("alpha"), _package(None)
        )
        server.bodies[RELATED] = {
            "affected": [
                {"package": {"name": "zeta"}},
                {"package": {"name": "suse-pkg"}},
                {},
            ]
        }
        server.bodies[RELATED_2] = {"affected": [{"package": {"name": "alpha"}}]}

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.payloads[0].resolved_packages == ["zeta", "alpha", "suse-pkg"]
        assert result.post_ingest == PostIngestTasks(
            ticket_id=str(target.ticket.id),  # type: ignore[union-attr]
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["alpha", "suse-pkg", "zeta"],
        )

    async def test_related_package_names_alone_give_a_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncOsvAdvisories,
        server: OsvServer,
    ) -> None:
        server.bodies[target.cve_id] = load_record_fixture("cve_references_only")
        server.bodies["SUSE-SU-2015:0546-1"] = load_record_fixture("related_suse")

        result = await fetcher.fetch_single(target.cve_id, db_session)

        # An empty replacement of an empty scope changes nothing.
        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == [
            "storm",
            "venv-openstack-monasca",
        ]

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
            "related": [RELATED],
        }
        server.bodies[RELATED] = {"affected": [{}], "references": []}

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
            "aliases": [ALIAS, "x/\x00" + SECRET, ALIAS_2],
            "related": [RELATED, RELATED_2],
        }
        server.bodies[ALIAS] = _alias_body(
            target.cve_id,
            _package("example"),
            credits=[{"name": PERSONAL}],
            details=SECRET,
        )
        server.responses[ALIAS_2] = status(500, f"{SECRET} {PERSONAL}".encode())
        server.responses[RELATED] = raising(httpx.ConnectError(f"{SECRET} {PERSONAL}"))
        server.responses[RELATED_2] = status(
            200, f'{{"references": [{{"url": ["{PERSONAL}"]}}]}}'.encode()
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert logs == [
            _skip(target.cve_id, "unsafe_id", record_id=None),
            _skip(target.cve_id, "http_status", record_id=ALIAS_2, status_code=500),
            _skip(
                target.cve_id,
                "transport",
                record_kind="related",
                record_id=RELATED,
            ),
            _skip(
                target.cve_id,
                "invalid_body",
                record_kind="related",
                record_id=RELATED_2,
                status_code=200,
            ),
        ]
        for entry in logs:
            assert set(entry) <= SKIP_KEYS
        _assert_no_raw_value(logs, SECRET, PERSONAL, "Alice")
