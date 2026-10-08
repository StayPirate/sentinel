"""Tests for `SyncGhsaAdvisories.fetch_single()`, the token handling, and the
next-page URL check (backend/app/services/tickets/sync_ghsa_advisories.py).

Owning specifications:

- docs/features/tickets/cve-sync-ghsa.md (Fetcher Definition; Algorithm
  steps 1, 5, and 6.e; `fetch_single(cve_id)`; Field Mapping; Response
  Validation, including the candidate skip event and External String
  Admissibility; Error Handling, the `fetch_single()` table and Sanitized
  error messages; Metrics).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  `fetch_single` Signaling Convention; Retry Policy for `fetch_single`;
  Error Categorization).
- docs/features/platform/fetcher-infrastructure.md (Error Message
  Sanitization; BaseFetcher HTTP Client Integration, HTTP Client Ownership
  Rule) and docs/features/platform/networking.md (Redirect Policy; Celery
  Retry Classification).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Typed result; External String Admissibility).

HTTP is the in-process `GhsaServer` of `tests/support/ghsa.py`, injected as
the fetcher's HTTP client, serving the sanitized live fixtures (retargeted
to the processed CVE-ID where they must match) or minimal fictional
advisories. `GITHUB_TOKEN` is set explicitly on `app.config.settings` by
every test to a fictional value. Outcome tests that end before any database
work use a session that fails on any use, and spies on
`cve_service.upsert_cve()` and `reference_service.upsert_references()` prove
no mutation was attempted; they are unit tests. Ingestion tests run the real
`upsert_cve()` and `upsert_references()` on `db_session`, rolled back at
teardown. The periodic `execute()` is tested in
`test_sync_ghsa_advisories_execute.py`. All identifiers and texts are
fictional, except the public advisory and CVE identifiers of the live
fixtures.
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
from pydantic import SecretStr, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.config import Settings
from app.config import settings as app_settings
from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_source import CVESource
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, fetcher_execution, reference_service
from app.services.base_cve_fetcher import CVEFetchResult, CVENotInSource
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import CVEIngestPayload, PostIngestTasks, UpsertAction
from app.services.http_client import is_infrastructure_failure, is_retryable_condition
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import sync_ghsa_advisories as sync_module
from app.services.tickets.sync_ghsa_advisories import (
    AUTHENTICATION_FAILED,
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
    TOKEN_NOT_CONFIGURED,
    UNTRUSTED_NEXT_URL,
    GhsaResponseError,
    SyncGhsaAdvisories,
    _is_trusted_next_url,
    _next_page_url,
)
from tests.support.cve_ingest import SKIP_EVENT, SKIP_EVENT_KEYS
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.ghsa import (
    ADVISORIES_URL,
    AUTH_401_FIXTURE,
    LIVE_NEXT_LINK,
    LIVE_NEXT_PREV_LINK,
    SINGLE_EMPTY_FIXTURE,
    SINGLE_REVIEWED_FIXTURE,
    GhsaServer,
    load_advisory_fixture,
    load_list_fixture,
    load_raw_fixture,
    raising,
    status,
)
from tests.support.ghsa import body as json_body
from tests.support.ticket_mutations import EventRow, ticket_events

NAME: Final = "sync_ghsa_advisories"
TOKEN: Final = "fictional-github-token-0001"
"""A fictional `GITHUB_TOKEN`; never a real token shape."""
OTHER_TOKEN: Final = "fictional-github-token-0002"
GHSA_ID: Final = "GHSA-fict-0001-aaaa"
HTML_URL: Final = f"https://github.com/advisories/{GHSA_ID}"
REPO: Final = "https://git.example.invalid/example/project"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
SECRET: Final = "Example-Secret-Upstream-Value"
"""An upstream value that must never reach a log record or an error."""
CREDIT_LOGIN: Final = "example-researcher"
"""The fictional credited login of every sanitized fixture."""
INGESTION_COMMENT: Final = "CVE ingested from GitHub Advisory Database"
ABSENT: Final = object()
"""Marks a member removed from an advisory."""

SINGLE_PARAMS: Final = {"type": "reviewed", "is_withdrawn": "false"}


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

    upserts: list[tuple[str, CVESourceType, CVEIngestPayload]] = field(
        default_factory=list
    )
    references: list[dict[str, Any]] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return len(self.upserts) + len(self.references)


@pytest.fixture
def ingestion(monkeypatch: pytest.MonkeyPatch) -> Ingestion:
    spy = Ingestion()
    real_upsert = cve_service.upsert_cve
    real_references = reference_service.upsert_references

    async def upsert_cve(
        db: AsyncSession, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> Any:
        spy.upserts.append((cve_id, source, payload))
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


@pytest.fixture(autouse=True)
def github_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test sets the token itself, never relying on the environment."""
    monkeypatch.setattr(app_settings, "github_token", SecretStr(TOKEN))


@pytest.fixture
def server() -> GhsaServer:
    return GhsaServer()


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Every throttle sleep of the module, recorded instead of slept."""
    recorded: list[float] = []

    async def sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    return recorded


@pytest.fixture
async def fetcher(server: GhsaServer) -> AsyncIterator[SyncGhsaAdvisories]:
    instance = SyncGhsaAdvisories()
    instance._http_client = server.client()
    try:
        yield instance
    finally:
        await instance._teardown_http_client()


@dataclass
class Target:
    cve: CVE
    ticket: Ticket

    @property
    def cve_id(self) -> str:
        return self.cve.cve_id


@pytest.fixture
async def target(db_session: AsyncSession) -> Target:
    """A CVE with its `Analysis` Ticket and the default CVSS version the
    trusted-external batch reads."""
    if await db_session.get(SystemSetting, "default_cvss_version") is None:
        db_session.add(SystemSetting(key="default_cvss_version", value="3.1"))
    cve = CVE(cve_id=fictional_cve_id())
    db_session.add(cve)
    await db_session.flush()
    ticket = Ticket(status="Analysis", cve_id=cve.id)
    db_session.add(ticket)
    await db_session.flush()
    return Target(cve, ticket)


# ---------------------------------------------------------------------------
# Advisory builders and persisted-state readers
# ---------------------------------------------------------------------------


def _advisory(cve_id: object, **members: Any) -> dict[str, Any]:
    """A minimal fictional advisory; `ABSENT` removes a member."""
    advisory: dict[str, Any] = {"ghsa_id": GHSA_ID, "html_url": HTML_URL}
    if cve_id is not ABSENT:
        advisory["cve_id"] = cve_id
    for key, value in members.items():
        if value is ABSENT:
            advisory.pop(key, None)
        else:
            advisory[key] = value
    return advisory


def _retargeted(name: str, cve_id: str) -> dict[str, Any]:
    """A live advisory fixture whose `cve_id` names `cve_id` instead."""
    if name == SINGLE_REVIEWED_FIXTURE:
        advisory: dict[str, Any] = copy.deepcopy(load_list_fixture(name)[0])
    else:
        advisory = copy.deepcopy(load_advisory_fixture(name))
    advisory["cve_id"] = cve_id
    return advisory


def _vulnerability(
    name: str | None, ecosystem: str = "npm", version_range: str | None = "< 1.0"
) -> dict[str, Any]:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "vulnerable_version_range": version_range,
    }


async def _ghsa_rows(db: AsyncSession, cve: CVE) -> set[tuple[Any, ...]]:
    rows = await db.execute(
        select(
            CVEAffectedVersion.vendor,
            CVEAffectedVersion.product,
            CVEAffectedVersion.package_name,
            CVEAffectedVersion.ecosystem,
            CVEAffectedVersion.repo,
            CVEAffectedVersion.version,
            CVEAffectedVersion.version_type,
            CVEAffectedVersion.version_end,
            CVEAffectedVersion.version_end_inclusive,
        ).where(
            CVEAffectedVersion.cve_id == cve.id,
            CVEAffectedVersion.source_container == "ghsa",
        )
    )
    return {tuple(row) for row in rows}


def _ghsa_row(
    name: str | None,
    ecosystem: str | None,
    repo: str | None,
    version: str | None,
    version_end: str | None,
    inclusive: bool | None,
) -> tuple[Any, ...]:
    return (None, name, name, ecosystem, repo, version, None, version_end, inclusive)


async def _identifiers(db: AsyncSession, cve: CVE) -> set[tuple[str, str, str | None]]:
    rows = await db.execute(
        select(
            CVEExternalIdentifier.source,
            CVEExternalIdentifier.identifier,
            CVEExternalIdentifier.url,
        ).where(CVEExternalIdentifier.cve_id == cve.id)
    )
    return {(source, identifier, url) for source, identifier, url in rows}


async def _cwes(db: AsyncSession, cve: CVE) -> set[tuple[str, str]]:
    rows = await db.execute(
        select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
    )
    return {(cwe_id, source) for cwe_id, source in rows}


async def _assessments(db: AsyncSession, cve: CVE) -> set[tuple[str, str, str]]:
    rows = await db.execute(
        select(
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.vector_string,
        ).where(CVECVSSAssessment.cve_id == cve.id)
    )
    return {(provider, version, vector) for provider, version, vector in rows}


async def _references(
    db: AsyncSession, ticket: Ticket
) -> list[tuple[str, str | None, str | None, str]]:
    """Every reference of the Ticket as (url, title, type, source)."""
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.title,
            TicketReference.type,
            TicketReference.source,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return sorted((url, title, kind, source) for url, title, kind, source in rows)


async def _source_status(db: AsyncSession, cve: CVE) -> str | None:
    value: str | None = await db.scalar(
        select(CVESource.status).where(
            CVESource.cve_id == cve.id, CVESource.source == "ghsa"
        )
    )
    return value


async def _row_count(db: AsyncSession, model: Any, cve: CVE) -> int:
    count = await db.scalar(
        select(func.count()).select_from(model).where(model.cve_id == cve.id)
    )
    return int(count or 0)


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        assert "\\x00" not in rendered, entry
        for value in (TOKEN, "Bearer", SECRET, CREDIT_LOGIN, *values):
            assert value not in rendered, entry


def _serve(server: GhsaServer, cve_id: str, *advisories: Any) -> None:
    server.singles[cve_id] = list(advisories)


# ---------------------------------------------------------------------------
# Token handling (Algorithm step 1; `fetch_single(cve_id)` step 1)
# ---------------------------------------------------------------------------

_UNSET_TOKEN: Final = cast(SecretStr, Settings.model_fields["github_token"].default)
"""The configuration default when `GITHUB_TOKEN` is unset."""


@pytest.mark.unit
class TestTokenGuard:
    def test_unset_token_is_the_empty_default(self) -> None:
        assert _UNSET_TOKEN.get_secret_value() == ""
        # The fetcher reads the process configuration these tests patch.
        assert vars(sync_module)["settings"] is app_settings

    @pytest.mark.parametrize(
        "token", [SecretStr(""), _UNSET_TOKEN], ids=["empty", "unset"]
    )
    @pytest.mark.parametrize(
        "cve_id", ["CVE-2099-0001", "not-a-cve-id"], ids=["valid", "malformed"]
    )
    async def test_fetch_single_raises_the_unchained_token_error_first(
        self,
        token: SecretStr,
        cve_id: str,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(app_settings, "github_token", token)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert (
            str(raised.value) == TOKEN_NOT_CONFIGURED == "GITHUB_TOKEN not configured"
        )
        assert raised.value.__cause__ is None
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)
        # The guard precedes the CVE-ID check and every request.
        assert server.requests == []
        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "token", [SecretStr(""), _UNSET_TOKEN], ids=["empty", "unset"]
    )
    async def test_execute_raises_before_the_cursor_read_and_any_request(
        self,
        token: SecretStr,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(app_settings, "github_token", token)

        async def derived_cursor(session: AsyncSession, name: str) -> Any:
            raise AssertionError("the cursor was read before the token guard")

        monkeypatch.setattr(fetcher_execution, "get_derived_cursor", derived_cursor)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await fetcher.execute(NO_SESSION)

        assert str(raised.value) == TOKEN_NOT_CONFIGURED
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert server.requests == []
        assert logs == []

    async def test_token_is_read_at_call_time_for_every_request(
        self,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = fictional_cve_id()
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)
        monkeypatch.setattr(app_settings, "github_token", SecretStr(OTHER_TOKEN))

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.authorization_headers == [
            f"Bearer {TOKEN}",
            f"Bearer {OTHER_TOKEN}",
        ]


# ---------------------------------------------------------------------------
# Request shape and client configuration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_one_get_with_the_documented_query_and_headers(
        self,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        sleeps: list[float],
    ) -> None:
        cve_id = fictional_cve_id()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        [request] = server.requests
        assert request.method == "GET"
        assert (request.url.scheme, request.url.host, request.url.port) == (
            "https",
            "api.github.com",
            None,
        )
        assert request.url.path == "/advisories"
        assert str(request.url.copy_with(query=None)) == ADVISORIES_URL
        assert dict(request.url.params) == {"cve_id": cve_id, **SINGLE_PARAMS}
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert server.single_requests == [request]
        # One request, no throttle.
        assert sleeps == []

    async def test_production_client_carries_no_token_and_follows_no_redirect(
        self,
    ) -> None:
        assert SyncGhsaAdvisories.http_client_options == {}
        instance = SyncGhsaAdvisories()
        try:
            client = instance.http_client
            assert client.follow_redirects is False
            assert "authorization" not in client.headers
            assert TOKEN not in repr(dict(client.headers))
        finally:
            await instance._teardown_http_client()

    async def test_fetch_single_never_closes_the_client(
        self, fetcher: SyncGhsaAdvisories, server: GhsaServer
    ) -> None:
        client = fetcher._http_client
        assert client is not None

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(fictional_cve_id(), NO_SESSION)

        assert fetcher._http_client is client
        assert not client.is_closed


# ---------------------------------------------------------------------------
# CVENotInSource before any mutation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMissingBeforeMutation:
    @pytest.mark.parametrize(
        "cve_id",
        [
            "CVE-2099-1",
            "cve-2099-0001",
            "CVE-2099-0001 ",
            "",
            "CVE-2099-" + "1" * 12,
            "CVE-2099-0001\x00",
        ],
        ids=["short", "lowercase", "trailing_space", "empty", "over_long", "nul"],
    )
    async def test_malformed_requested_cve_id_is_missing_without_http(
        self,
        cve_id: str,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert ingestion.calls == 0

    async def test_live_empty_array_is_missing(
        self,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        """Unknown, withdrawn-only, and unreviewed-only CVE-IDs were all
        answered with this body live."""
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = status(
            200, load_raw_fixture(SINGLE_EMPTY_FIXTURE)
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert len(server.requests) == 1
        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "first_cve_id",
        [
            None,
            ABSENT,
            "CVE-24-1",
            "GHSA-fict-0001-aaaa",
            20990001,
            ["CVE-2099-0001"],
            "",
            "other",
            "CVE-2099-0001\x00",
        ],
        ids=[
            "null",
            "absent",
            "short_year",
            "ghsa_id",
            "integer",
            "list",
            "empty",
            "different",
            "nul",
        ],
    )
    async def test_unusable_first_cve_id_is_missing(
        self,
        first_cve_id: object,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        value = fictional_cve_id() if first_cve_id == "other" else first_cve_id
        # A later advisory naming the requested CVE is never considered.
        _serve(
            server,
            cve_id,
            _advisory(value, summary=SECRET),
            _advisory(cve_id),
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert logs == []


# ---------------------------------------------------------------------------
# Error propagation and classification (`fetch_single()` error table)
# ---------------------------------------------------------------------------


async def _raised(
    fetcher: SyncGhsaAdvisories, server: GhsaServer, responder: Any
) -> BaseException:
    cve_id = fictional_cve_id()
    server.single_responses[cve_id] = responder
    with pytest.raises(
        (httpx.HTTPError, ValueError, GhsaResponseError, FetcherError)
    ) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    assert [request.url.params.get("cve_id") for request in server.requests] == [cve_id]
    return raised.value


@pytest.mark.unit
class TestErrorPropagation:
    async def test_401_is_the_chained_authentication_error(
        self, fetcher: SyncGhsaAdvisories, server: GhsaServer, ingestion: Ingestion
    ) -> None:
        error = await _raised(
            fetcher, server, status(401, load_raw_fixture(AUTH_401_FIXTURE))
        )

        assert type(error) is FetcherError
        assert str(error) == AUTHENTICATION_FAILED == "GitHub API authentication failed"
        assert isinstance(error.__cause__, httpx.HTTPStatusError)
        assert error.__cause__.response.status_code == 401
        assert TOKEN not in str(error.__cause__)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [400, 403, 404, 405, 410, 422])
    async def test_other_4xx_is_the_unwrapped_non_retryable_status_error(
        self,
        code: int,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(code, SECRET.encode()))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    async def test_429_and_5xx_are_unwrapped_and_retryable(
        self, code: int, fetcher: SyncGhsaAdvisories, server: GhsaServer
    ) -> None:
        error = await _raised(fetcher, server, status(code))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert is_retryable_condition(error)

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self, code: int, fetcher: SyncGhsaAdvisories, server: GhsaServer
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            status(code, headers={"Location": f"{ADVISORIES_URL}?cve_id=CVE-2099-1"}),
        )

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("timed out"),
            httpx.ReadTimeout("timed out"),
            httpx.RemoteProtocolError("closed"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_transport_error_propagates_unwrapped_and_retryable(
        self, error: Exception, fetcher: SyncGhsaAdvisories, server: GhsaServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)

    @pytest.mark.parametrize("code", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_fixed_error_that_never_reads_the_body(
        self,
        code: int,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        error = await _raised(
            fetcher,
            server,
            lambda request: httpx.Response(
                code, json=[_advisory(cve_id, summary=SECRET)], request=request
            ),
        )

        assert type(error) is GhsaResponseError
        assert str(error) == "GitHub Advisory API returned an unexpected response"
        assert error.__cause__ is None
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "content",
        [b"", b"{", b"[", f"<html>{SECRET}</html>".encode(), b"\xff\xfe\xfd"],
        ids=["empty", "truncated", "unterminated_array", "html", "invalid_utf8"],
    )
    async def test_unparseable_json_is_non_retryable(
        self,
        content: bytes,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(200, content))

        assert isinstance(error, ValueError)
        assert SECRET not in str(error)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    async def test_undecodable_body_is_non_retryable(
        self, fetcher: SyncGhsaAdvisories, server: GhsaServer, ingestion: Ingestion
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        )

        assert isinstance(error, httpx.DecodingError)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "document",
        [{"cve_id": "CVE-2099-0001"}, SECRET, 1, None, True],
        ids=["object", "string", "number", "null", "boolean"],
    )
    async def test_non_array_root_is_a_fixed_non_retryable_error(
        self,
        document: Any,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, json_body(document))

        assert type(error) is GhsaResponseError
        assert SECRET not in str(error)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "first",
        ["CVE-2099-0001", 1, None, [], ["CVE-2099-0001"]],
        ids=["string", "number", "null", "empty_list", "list"],
    )
    async def test_non_object_first_element_is_a_fixed_non_retryable_error(
        self,
        first: Any,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, json_body([first, {"cve_id": None}]))

        assert type(error) is GhsaResponseError
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "members",
        [
            {"ghsa_id": ABSENT},
            {"ghsa_id": None},
            {"html_url": ABSENT},
            {"html_url": 1},
            {"summary": [SECRET]},
            {"published_at": SECRET},
            {"updated_at": "2026-02-30T00:00:00Z"},
            {"references": SECRET},
            {"references": [{"url": SECRET}]},
            {"cwes": [{"cwe_id": 79}]},
            {"cwes": [{"name": SECRET}]},
            {"cvss_severities": {"cvss_v3": {"vector_string": 3.1}}},
            {"vulnerabilities": [{"package": {"name": SECRET}}]},
            {"vulnerabilities": [{"package": {"ecosystem": None, "name": "x"}}]},
            {"vulnerabilities": SECRET},
        ],
        ids=[
            "ghsa_id_absent",
            "ghsa_id_null",
            "html_url_absent",
            "html_url_number",
            "summary_list",
            "published_at_text",
            "updated_at_invalid_date",
            "references_string",
            "reference_object",
            "cwe_id_number",
            "cwe_id_absent",
            "vector_number",
            "ecosystem_absent",
            "ecosystem_null",
            "vulnerabilities_string",
        ],
    )
    async def test_schema_mismatch_is_non_retryable_and_hides_the_input(
        self,
        members: dict[str, Any],
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _advisory(cve_id, **members))

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_whole_run_signal_propagates_unchanged(
        self,
        signal: BaseException,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()

        def respond(request: httpx.Request) -> httpx.Response:
            raise signal

        server.single_responses[cve_id] = respond

        with pytest.raises(type(signal)) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is signal
        assert ingestion.calls == 0


# ---------------------------------------------------------------------------
# Next-page URL check (Algorithm step 6.e)
# ---------------------------------------------------------------------------


def _link_url(link: str, rel: str = "next") -> str:
    url: str = httpx.Response(200, headers={"Link": link}).links[rel]["url"]
    return url


UNTRUSTED_NEXT_URLS: Final = [
    "https://advisory.example.invalid/advisories?after=x",
    "https://api.github.com.evil.example/advisories?after=x",
    "https://evil.example/https://api.github.com/advisories",
    "http://api.github.com/advisories?after=x",
    "https://user@api.github.com/advisories?after=x",
    "https://user:secret@api.github.com/advisories",
    "https://api.github.com:443/advisories?after=x",
    "https://api.github.com:8443/advisories?after=x",
    "https://api.github.com:/advisories",
    "https://api.github.com/advisories/x?after=x",
    "https://api.github.com/advisories/",
    "https://api.github.com/repos?after=x",
    "https://api.github.com/advisories?after=x#x",
    "https://api.github.com/advisories#",
    "https://api.github.com/advisories?after=x y",
    "https://api.github.com/advisories?after=x\ty",
    "https://api.github.com/advisories?after=x\x01",
    "https://api.github.com/advisories?after=x\x7f",
    " https://api.github.com/advisories",
    "https://API.GITHUB.COM/advisories?after=x",
    "https://Api.github.com/advisories",
    "https://api.github.com/ADVISORIES",
    "//api.github.com/advisories",
    "/advisories?after=x",
    "https://[api.github.com/advisories",
    "",
]
UNTRUSTED_NEXT_IDS: Final = [
    "foreign_host",
    "suffix_host",
    "host_in_path",
    "http",
    "userinfo",
    "userinfo_password",
    "port_443",
    "port_8443",
    "empty_port",
    "sub_path",
    "trailing_slash",
    "other_path",
    "fragment",
    "bare_fragment",
    "space",
    "tab",
    "control",
    "delete",
    "leading_space",
    "uppercase_host",
    "mixed_case_host",
    "uppercase_path",
    "scheme_relative",
    "relative",
    "invalid_ipv6",
    "empty",
]


@pytest.mark.unit
class TestNextUrlCheck:
    @pytest.mark.parametrize(
        "url",
        [
            _link_url(LIVE_NEXT_LINK),
            _link_url(LIVE_NEXT_PREV_LINK),
            ADVISORIES_URL,
            f"{ADVISORIES_URL}?after=cursor-1",
        ],
        ids=["live_first_page", "live_second_page", "no_query", "fake_cursor"],
    )
    def test_trusted_urls(self, url: str) -> None:
        assert _is_trusted_next_url(url) is True

    @pytest.mark.parametrize("url", UNTRUSTED_NEXT_URLS, ids=UNTRUSTED_NEXT_IDS)
    def test_untrusted_urls(self, url: str) -> None:
        assert _is_trusted_next_url(url) is False

    def test_live_link_keeps_the_query_unchanged(self) -> None:
        url = _link_url(LIVE_NEXT_LINK)
        response = httpx.Response(200, headers={"Link": LIVE_NEXT_LINK})

        assert _next_page_url(response) == url
        assert "modified=%3E%3D2026-09-23T22%3A00%3A34Z" in url
        assert "&after=" in url

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Link": f'<{ADVISORIES_URL}?before=x>; rel="prev"'},
            {"Link": "garbage"},
            {"Link": f"<{ADVISORIES_URL}?after=x>"},
            {"Link": f'<{ADVISORIES_URL}?after=x>; rel="last"'},
        ],
        ids=["absent", "prev_only", "garbage", "no_rel", "last_only"],
    )
    def test_no_next_link_ends_pagination(self, headers: dict[str, str]) -> None:
        assert _next_page_url(httpx.Response(200, headers=headers)) is None

    @pytest.mark.parametrize(
        "url", UNTRUSTED_NEXT_URLS[:14], ids=UNTRUSTED_NEXT_IDS[:14]
    )
    def test_untrusted_next_link_raises_the_unchained_error(self, url: str) -> None:
        response = httpx.Response(200, headers={"Link": f'<{url}>; rel="next"'})

        with pytest.raises(FetcherError) as raised:
            _next_page_url(response)

        assert str(raised.value) == UNTRUSTED_NEXT_URL
        assert raised.value.__cause__ is None
        assert url not in str(raised.value)


# ---------------------------------------------------------------------------
# Ingestion with the real upsert_cve() and upsert_references()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestion:
    async def test_live_advisory_is_ingested_completely(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        advisory = _retargeted(SINGLE_REVIEWED_FIXTURE, target.cve_id)
        _serve(server, target.cve_id, advisory)

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert isinstance(result, CVEFetchResult)
        assert result.action is UpsertAction.UPDATED
        # Maven coordinates fail the common package-name heuristic, so the
        # live advisory yields no handoff.
        assert result.post_ingest is None
        assert ingestion.upserts[0][2].resolved_packages == [
            "org.apache.logging.log4j:log4j-core",
            "org.ops4j.pax.logging:pax-logging-log4j2",
        ]
        [(cve_id, source, _)] = ingestion.upserts
        assert (cve_id, source) == (target.cve_id, CVESourceType.GHSA)
        assert source is CVESourceType.GHSA
        html_url = advisory["html_url"]
        assert await _identifiers(db_session, target.cve) == {
            ("GHSA", "GHSA-jfh8-c2jp-5v3q", html_url)
        }
        assert await _cwes(db_session, target.cve) == {
            ("CWE-20", "GitHub"),
            ("CWE-400", "GitHub"),
            ("CWE-502", "GitHub"),
            ("CWE-917", "GitHub"),
        }
        repo = "https://github.com/apache/logging-log4j2"
        core = "org.apache.logging.log4j:log4j-core"
        assert await _ghsa_rows(db_session, target.cve) == {
            _ghsa_row(core, "Maven", repo, "2.13.0", "2.15.0", False),
            _ghsa_row(core, "Maven", repo, "2.4", "2.12.2", False),
            _ghsa_row(core, "Maven", repo, "2.0-beta9", "2.3.1", False),
            _ghsa_row(
                "org.ops4j.pax.logging:pax-logging-log4j2",
                "Maven",
                repo,
                "1.8.0",
                "1.9.2",
                False,
            ),
        }
        # The v3 vector carries the Temporal metric `E:H`: skipped with the
        # one bounded `upsert_cve()` warning, without failing the advisory.
        assert await _assessments(db_session, target.cve) == set()
        [skip] = _events(logs, SKIP_EVENT)
        assert skip["reason"] == "invalid_vector"
        assert skip["cve_id"] == target.cve_id
        assert set(skip) <= SKIP_EVENT_KEYS
        _assert_private(logs, advisory["cvss_severities"]["cvss_v3"]["vector_string"])
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )

    async def test_package_names_are_the_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(server, target.cve_id, _retargeted("advisory_v3_v4", target.cve_id))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(
            UpsertAction.UPDATED,
            PostIngestTasks(
                ticket_id=str(target.ticket.id),
                cpe_matches=[],
                affected_cpes=[],
                vendor_products=[],
                resolved_packages=["socket.io"],
            ),
        )

    async def test_source_reference_first_and_no_duplicate_of_the_html_url(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        advisory = _retargeted(SINGLE_REVIEWED_FIXTURE, target.cve_id)
        html_url = advisory["html_url"]
        assert html_url in advisory["references"]
        _serve(server, target.cve_id, advisory)

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        assert call["ticket_id"] == target.ticket.id
        assert call["cve_id"] == target.cve_id
        assert call["source"] == NAME
        assert call["source_reference"] == AutomaticReferenceInput(
            url=html_url,
            title="GitHub Advisory",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert [entry.url for entry in call["upstream"]] == advisory["references"]
        assert all(
            entry.title is None
            and entry.explicit_type is None
            and entry.upstream_tags is None
            for entry in call["upstream"]
        )
        persisted = await _references(db_session, target.ticket)
        assert [row[0] for row in persisted] == sorted(set(advisory["references"]))
        assert (html_url, "GitHub Advisory", "advisory", NAME) in persisted

    async def test_only_the_first_advisory_is_processed(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        second = _advisory(
            target.cve_id,
            ghsa_id="GHSA-fict-0002-bbbb",
            html_url="https://github.com/advisories/GHSA-fict-0002-bbbb",
            vulnerabilities=[_vulnerability("second-package")],
        )
        _serve(
            server,
            target.cve_id,
            _advisory(target.cve_id, vulnerabilities=[_vulnerability("first")]),
            second,
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert len(ingestion.upserts) == 1
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == ["first"]
        assert await _identifiers(db_session, target.cve) == {
            ("GHSA", GHSA_ID, HTML_URL)
        }

    @pytest.mark.parametrize(
        "packages", [[], ["example-pkg"]], ids=["no_handoff", "handoff"]
    )
    async def test_new_cve_is_created_with_a_new_ticket(
        self,
        packages: list[str],
        db_session: AsyncSession,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(
            server,
            cve_id,
            _advisory(
                cve_id,
                summary="Fictional title",
                references=[URL_1],
                vulnerabilities=[_vulnerability(name) for name in packages]
                if packages
                else ABSENT,
            ),
        )

        result = await fetcher.fetch_single(cve_id, db_session)

        cve = await db_session.scalar(select(CVE).where(CVE.cve_id == cve_id))
        assert cve is not None
        assert cve.title == "Fictional title"
        [ticket] = (
            await db_session.scalars(select(Ticket).where(Ticket.cve_id == cve.id))
        ).all()
        assert result == CVEFetchResult(
            UpsertAction.CREATED,
            PostIngestTasks(
                ticket_id=str(ticket.id),
                cpe_matches=[],
                affected_cpes=[],
                vendor_products=[],
                resolved_packages=packages,
            )
            if packages
            else None,
        )
        assert ticket.status == "New"
        assert await ticket_events(db_session, ticket) == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve_id, None, None),
        ]
        assert [row[0] for row in await _references(db_session, ticket)] == [
            URL_1,
            HTML_URL,
        ]

    async def test_updated_without_handoff_then_unchanged(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        """An empty `vulnerabilities` array is an observed empty `ghsa`
        replacement without package candidates."""
        _serve(server, target.cve_id, _advisory(target.cve_id, vulnerabilities=[]))

        first = await fetcher.fetch_single(target.cve_id, db_session)
        second = await fetcher.fetch_single(target.cve_id, db_session)

        assert first == CVEFetchResult(UpsertAction.UPDATED, None)
        assert second == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert await _ghsa_rows(db_session, target.cve) == set()

    async def test_unchanged_with_handoff_is_idempotent(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _advisory(
                target.cve_id,
                vulnerabilities=[_vulnerability("example"), _vulnerability("example")],
                references=[URL_1],
            ),
        )
        await fetcher.fetch_single(target.cve_id, db_session)
        references = await _references(db_session, target.ticket)
        rows = await _ghsa_rows(db_session, target.cve)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == ["example"]
        assert await _references(db_session, target.ticket) == references
        assert await _ghsa_rows(db_session, target.cve) == rows
        assert rows == {_ghsa_row("example", "npm", None, None, "1.0", False)}

    async def test_absent_vulnerabilities_emit_no_scope_and_no_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _advisory(target.cve_id, vulnerabilities=[_vulnerability("kept")]),
        )
        await fetcher.fetch_single(target.cve_id, db_session)
        _serve(server, target.cve_id, _advisory(target.cve_id))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UNCHANGED, None)
        payload = ingestion.upserts[-1][2]
        assert "affected_version_operations" not in payload.model_fields_set
        assert await _ghsa_rows(db_session, target.cve) == {
            _ghsa_row("kept", "npm", None, None, "1.0", False)
        }

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            (
                "advisory_erlang",
                {
                    _ghsa_row(
                        "ash",
                        "Hex",
                        "https://github.com/ash-project/ash",
                        "3.0.0",
                        "3.29.3",
                        False,
                    )
                },
            ),
            (
                "advisory_empty_source_location",
                {
                    _ghsa_row(
                        "org.apache.logging.log4j:log4j-core",
                        "Maven",
                        None,
                        "2.13.0",
                        "2.16.0",
                        False,
                    ),
                    _ghsa_row(
                        "org.ops4j.pax.logging:pax-logging-log4j2",
                        "Maven",
                        None,
                        "1.8.0",
                        "1.9.2",
                        False,
                    ),
                    _ghsa_row(
                        "org.apache.logging.log4j:log4j-core",
                        "Maven",
                        None,
                        "2.4.0",
                        "2.12.2",
                        False,
                    ),
                    _ghsa_row(
                        "org.apache.logging.log4j:log4j-core",
                        "Maven",
                        None,
                        None,
                        "2.3.1",
                        False,
                    ),
                },
            ),
        ],
        ids=["erlang_hex", "empty_source_location"],
    )
    async def test_live_affected_versions(
        self,
        name: str,
        expected: set[tuple[Any, ...]],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(server, target.cve_id, _retargeted(name, target.cve_id))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _ghsa_rows(db_session, target.cve) == expected

    async def test_fetch_single_never_commits_and_records_no_metric(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        commits: list[None] = []

        async def commit() -> None:
            commits.append(None)

        monkeypatch.setattr(db_session, "commit", commit)
        _serve(
            server,
            target.cve_id,
            _retargeted("advisory_v3_v4", target.cve_id),
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert commits == []
        assert (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        ) == (0, 0, 0, 0)
        assert not result._consumed


# ---------------------------------------------------------------------------
# CVSS with the real upsert_cve() (partial extraction)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCvss:
    async def test_valid_v3_and_v4_persist(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        advisory = _retargeted("advisory_v3_v4", target.cve_id)
        _serve(server, target.cve_id, advisory)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        severities = advisory["cvss_severities"]
        assert await _assessments(db_session, target.cve) == {
            ("GitHub", "3.1", severities["cvss_v3"]["vector_string"]),
            ("GitHub", "4.0", severities["cvss_v4"]["vector_string"]),
        }
        assert _events(logs, SKIP_EVENT) == []

    async def test_live_non_base_v4_is_skipped_once(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        advisory = _retargeted("advisory_v4_non_base", target.cve_id)
        _serve(server, target.cve_id, advisory)

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == set()
        assert await _cwes(db_session, target.cve) == {("CWE-295", "GitHub")}
        assert [entry["reason"] for entry in _events(logs, SKIP_EVENT)] == [
            "invalid_vector"
        ]
        _assert_private(logs, advisory["cvss_severities"]["cvss_v4"]["vector_string"])

    @pytest.mark.parametrize(
        "vector",
        [
            f"CVSS:3.1/AV:N/{SECRET}",
            "CVSS:9.9/AV:N",
            "CVSS:3.1/AV:N/AC:L",
            V31 + "/AV:N" * 40,
            f"{V31}\x00",
        ],
        ids=["malformed", "unknown_prefix", "incomplete", "over_200", "nul"],
    )
    async def test_rejected_v3_is_skipped_once_and_the_v4_sibling_persists(
        self,
        vector: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        if "/AV:N/AV:N" in vector:
            assert len(vector) > 200
        _serve(
            server,
            target.cve_id,
            _advisory(
                target.cve_id,
                cvss_severities={
                    "cvss_v3": {"vector_string": vector, "score": 9.9},
                    "cvss_v4": {"vector_string": V40, "score": 9.3},
                },
            ),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == {("GitHub", "4.0", V40)}
        skips = _events(logs, SKIP_EVENT)
        assert [entry["reason"] for entry in skips] == ["invalid_vector"]
        assert all(set(entry) <= SKIP_EVENT_KEYS for entry in skips)
        _assert_private(logs, vector.rstrip("\x00"))
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )

    @pytest.mark.parametrize(
        "cvss_v3", [None, {"vector_string": None}, {"vector_string": ""}]
    )
    async def test_absent_vectors_log_nothing(
        self,
        cvss_v3: Any,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _advisory(target.cve_id, cvss_severities={"cvss_v3": cvss_v3}),
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == set()
        assert logs == []


# ---------------------------------------------------------------------------
# Bounded fetcher WARNINGs (Response Validation; Version range parsing rules)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFetcherWarnings:
    async def test_each_rejected_cwe_and_unrecognized_range_logs_one_bounded_event(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        bad_ranges = [f">= 1.0, >= 2.0 {SECRET}", "~> 1.0", "< 1.0 < 2.0"]
        _serve(
            server,
            target.cve_id,
            _advisory(
                target.cve_id,
                cwes=[
                    {"cwe_id": "CWE-79"},
                    {"cwe_id": f"CWE-0 {SECRET}"},
                    {"cwe_id": "NVD-CWE-Other"},
                    {"cwe_id": "CWE-79\x00"},
                ],
                vulnerabilities=[
                    _vulnerability("ok", version_range=">= 1.0, < 2.0"),
                    *(_vulnerability("bad", version_range=r) for r in bad_ranges),
                ],
            ),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        skipped = {
            "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
            "log_level": "warning",
            "cve_id": target.cve_id,
            "fetcher_name": NAME,
            "reason": "invalid_cwe",
        }
        unrecognized = {
            "event": GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
            "log_level": "warning",
            "cve_id": target.cve_id,
            "fetcher_name": NAME,
        }
        assert logs == [skipped] * 3 + [unrecognized] * 3
        _assert_private(logs, *bad_ranges, "NVD-CWE-Other")
        assert await _cwes(db_session, target.cve) == {("CWE-79", "GitHub")}
        # An unrecognized range keeps its package with NULL version fields.
        assert await _ghsa_rows(db_session, target.cve) == {
            _ghsa_row("ok", "npm", None, "1.0", "2.0", False),
            _ghsa_row("bad", "npm", None, None, None, None),
        }


# ---------------------------------------------------------------------------
# External String Admissibility (on-demand outcomes)
# ---------------------------------------------------------------------------

NUL: Final = f"{SECRET}\x00"


def _with_nul(cve_id: str, field_name: str) -> dict[str, Any]:
    """An advisory whose `field_name` value contains U+0000."""
    vulnerability = _vulnerability("example", "npm", ">= 1.0, < 2.0")
    members: dict[str, Any] = {"vulnerabilities": [vulnerability]}
    if field_name in {"summary", "description", "ghsa_id", "html_url"}:
        members[field_name] = NUL
    elif field_name in {"published_at", "updated_at"}:
        members[field_name] = "2026-01-01T00:00:00Z\x00"
    elif field_name == "source_code_location":
        members[field_name] = f"https://git.example.invalid/{NUL}"
    elif field_name == "package_name":
        vulnerability["package"]["name"] = NUL
    elif field_name == "ecosystem":
        vulnerability["package"]["ecosystem"] = NUL
    elif field_name == "version":
        vulnerability["vulnerable_version_range"] = f">= {NUL}, < 2.0"
    else:
        assert field_name == "version_end"
        vulnerability["vulnerable_version_range"] = f">= 1.0, < {NUL}"
    return _advisory(cve_id, **members)


PAYLOAD_NUL_FIELDS: Final = [
    "summary",
    "description",
    "ghsa_id",
    "html_url",
    "published_at",
    "updated_at",
    "source_code_location",
    "package_name",
    "ecosystem",
    "version",
    "version_end",
]


@pytest.mark.unit
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize("field_name", PAYLOAD_NUL_FIELDS)
    async def test_nul_in_a_payload_value_fails_before_any_write(
        self,
        field_name: str,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _with_nul(cve_id, field_name))

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert logs == []

    @pytest.mark.parametrize(
        ("members", "vulnerability"),
        [
            ({}, _vulnerability("example", "E" * 51)),
            ({"source_code_location": REPO + "/" + "r" * (2048 - len(REPO))}, None),
            ({"ghsa_id": "G" * 101}, None),
            ({}, _vulnerability("e" * 2049)),
            ({"html_url": HTML_URL + "/" + "h" * (2048 - len(HTML_URL))}, None),
        ],
        ids=[
            "ecosystem_51",
            "source_code_location_2049",
            "ghsa_id_101",
            "package_name_2049",
            "html_url_2049",
        ],
    )
    async def test_over_long_value_fails_before_any_write(
        self,
        members: dict[str, Any],
        vulnerability: dict[str, Any] | None,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(
            server,
            cve_id,
            _advisory(
                cve_id,
                vulnerabilities=[vulnerability or _vulnerability("example")],
                **members,
            ),
        )

        with pytest.raises(ValidationError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0


@pytest.mark.integration
class TestAdmissibilityBounds:
    async def test_bounds_are_inclusive(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        repo = REPO + "/" + "r" * (2047 - len(REPO))
        assert len(repo) == 2048
        ghsa_id = "GHSA-" + "g" * 95
        _serve(
            server,
            target.cve_id,
            _advisory(
                target.cve_id,
                ghsa_id=ghsa_id,
                source_code_location=repo,
                vulnerabilities=[_vulnerability("n" * 2048, "E" * 50)],
            ),
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _ghsa_rows(db_session, target.cve) == {
            _ghsa_row("n" * 2048, "E" * 50, repo, None, "1.0", False)
        }
        assert {row[1] for row in await _identifiers(db_session, target.cve)} == {
            ghsa_id
        }

    async def test_nul_in_a_cwe_or_reference_skips_only_that_candidate(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _advisory(
                target.cve_id,
                cwes=[{"cwe_id": "CWE-79\x00"}, {"cwe_id": "CWE-352"}],
                references=[f"{URL_1}?{NUL}", URL_2],
            ),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _cwes(db_session, target.cve) == {("CWE-352", "GitHub")}
        assert [row[0] for row in await _references(db_session, target.ticket)] == [
            URL_2,
            HTML_URL,
        ]
        assert [(entry["event"], entry.get("reason")) for entry in logs] == [
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_cwe"),
            ("automatic_reference_rejected", "control_character"),
        ]
        _assert_private(logs)

    async def test_nul_failure_writes_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        _serve(server, target.cve_id, _with_nul(target.cve_id, "package_name"))

        with pytest.raises(ValidationError):
            await fetcher.fetch_single(target.cve_id, db_session)

        for model in (CVEAffectedVersion, CVEExternalIdentifier, CVECWE, CVESource):
            assert await _row_count(db_session, model, target.cve) == 0
        assert await _references(db_session, target.ticket) == []


# ---------------------------------------------------------------------------
# Log privacy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLogPrivacy:
    async def test_a_full_fetch_logs_no_upstream_text_credit_or_token(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncGhsaAdvisories,
        server: GhsaServer,
    ) -> None:
        advisory = _retargeted("advisory_v4_non_base", target.cve_id)
        advisory["summary"] = SECRET
        advisory["description"] = f"{SECRET} {CREDIT_LOGIN}"
        advisory["cwes"].append({"cwe_id": f"CWE-x {SECRET}"})
        advisory["vulnerabilities"].append(
            _vulnerability(SECRET, "pip", f"~> {SECRET}")
        )
        _serve(server, target.cve_id, advisory)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert {entry["event"] for entry in logs} == {
            SKIP_EVENT,
            CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
            GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
        }
        _assert_private(logs, advisory["ghsa_id"], "Fictional")
