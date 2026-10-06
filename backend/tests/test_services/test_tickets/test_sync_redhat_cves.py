"""Tests for `SyncRedhatCves.fetch_single()` and the class contract
(backend/app/services/tickets/sync_redhat_cves.py).

Owning specifications:

- docs/features/tickets/cve-sync-redhat.md (Fetcher Definition; Algorithm;
  Field Mapping; Response Validation, including External String
  Admissibility and the Candidate skip event; `fetch_single` method; Error
  Handling, `fetch_single()` table, extractable data, partial extraction,
  data preservation, and sanitized messages).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  Automatic Reference Caller Contract; `CVEFetchResult`; `fetch_single`
  Signaling Convention; Retry Policy and Error Categorization; CVE Source
  Type Identity; both registry accessors; Default catch_up Implementation;
  Canonical Payload Producer Obligations).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention,
  Class Name Derivation, BaseFetcher HTTP Client Integration) and
  docs/features/platform/networking.md (Infrastructure Failure
  Classification; Celery Retry Classification; Redirect Policy).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Typed result and Concrete compliance; External String Admissibility).

HTTP is the in-process `RedhatServer` of `tests/support/redhat.py`, injected
as the fetcher's HTTP client, serving the sanitized live fixtures under
fictional CVE-IDs or minimal fictional bodies. Outcome tests that end before
any database work use a session that fails on any use, and spies on
`cve_service.upsert_cve()` and `reference_service.upsert_references()` prove
no mutation was attempted; they are unit tests. Ingestion tests run the real
`upsert_cve()` and `upsert_references()` on `db_session`, rolled back at
teardown. All identifiers are fictional.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, cast

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_source import CVESource
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    get_catch_up_fetchers,
)
from app.services.cve_ingest import CVEIngestPayload, PostIngestTasks, UpsertAction
from app.services.http_client import (
    is_infrastructure_failure,
    is_retryable_condition,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import redhat_cve_record
from app.services.tickets.sync_redhat_cves import (
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    RedhatResponseError,
    SyncRedhatCves,
)
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.redhat import (
    RedhatServer,
    load_cve_fixture,
    raising,
    redhat_cve_url,
)

NAME: Final = "sync_redhat_cves"
SOURCE_URL: Final = "https://access.redhat.com/security/cve/{cve_id}"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2: Final = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
BUGZILLA_URL: Final = "https://bugzilla.example.invalid/show_bug.cgi?id=1"
SECRET: Final = "Example-Secret-Upstream-Value"
"""An upstream value that must never reach a log record."""

SKIP_KEYS: Final = frozenset({"event", "log_level", "cve_id", "fetcher_name", "reason"})


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _NoSession:
    """A session that fails the test on any use."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used before extractable data")


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
def server() -> RedhatServer:
    return RedhatServer()


@pytest.fixture
async def fetcher(server: RedhatServer) -> AsyncIterator[SyncRedhatCves]:
    instance = SyncRedhatCves()
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
    """A published CVE with its `Analysis` Ticket and the default CVSS
    version the trusted-external batch reads."""
    if await db_session.get(SystemSetting, "default_cvss_version") is None:
        db_session.add(SystemSetting(key="default_cvss_version", value="3.1"))
    cve = CVE(cve_id=fictional_cve_id())
    db_session.add(cve)
    await db_session.flush()
    ticket = Ticket(status="Analysis", cve_id=cve.id)
    db_session.add(ticket)
    await db_session.flush()
    return Target(cve, ticket)


def _serve(server: RedhatServer, cve_id: str, body: Any) -> None:
    server.bodies[cve_id] = body


def _fixture(name: str) -> dict[str, Any]:
    return load_cve_fixture(name)


async def _assessments(db: AsyncSession, cve: CVE) -> set[tuple[str, str, str]]:
    rows = await db.execute(
        select(
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.vector_string,
        ).where(CVECVSSAssessment.cve_id == cve.id)
    )
    return {(provider, version, vector) for provider, version, vector in rows}


async def _cwes(db: AsyncSession, cve: CVE) -> set[tuple[str, str]]:
    rows = await db.execute(
        select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
    )
    return {(cwe_id, source) for cwe_id, source in rows}


async def _references(
    db: AsyncSession, ticket: Ticket
) -> dict[str, tuple[str | None, str | None, str]]:
    """Every reference of the Ticket: URL -> (title, type, source)."""
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.title,
            TicketReference.type,
            TicketReference.source,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return {url: (title, kind, source) for url, title, kind, source in rows}


async def _row_counts(db: AsyncSession, target: Target) -> tuple[int, int, int, int]:
    counts = []
    for model, column, value in (
        (CVECVSSAssessment, CVECVSSAssessment.cve_id, target.cve.id),
        (CVECWE, CVECWE.cve_id, target.cve.id),
        (TicketReference, TicketReference.ticket_id, target.ticket.id),
        (CVESource, CVESource.cve_id, target.cve.id),
    ):
        counts.append(
            int(
                await db.scalar(
                    select(func.count()).select_from(model).where(column == value)
                )
                or 0
            )
        )
    return cast(tuple[int, int, int, int], tuple(counts))


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_no_raw_value(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        assert "\\x00" not in rendered, entry
        for value in values:
            assert value not in rendered, entry


# ---------------------------------------------------------------------------
# Outcomes before any database work
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
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert ingestion.calls == 0

    async def test_404_is_missing_and_requests_the_documented_url_once(
        self, fetcher: SyncRedhatCves, server: RedhatServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert [request.method for request in server.requests] == ["GET"]
        assert server.requested_urls == [redhat_cve_url(cve_id)]
        assert server.requested_urls == [
            f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
        ]
        assert ingestion.calls == 0

    async def test_404_body_is_not_consumed(
        self, fetcher: SyncRedhatCves, server: RedhatServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = lambda request: httpx.Response(
            404, content=b"\x00not json"
        )

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"name": "CVE-2099-0001", "threat_severity": "Low", "details": ["x"]},
            {"cvss3": {"cvss3_scoring_vector": None}, "cvss": {}},
            {"cvss3": {"cvss3_scoring_vector": " "}, "cwe": None, "references": []},
            {"references": ["\n\r\n \n"], "bugzilla": {"url": ""}},
            {"package_state": [{"package_name": None}, {"package_name": "a/b"}]},
            {"affected_release": [{"package": "example-0:1.0-1.el9"}]},
        ],
        ids=[
            "empty",
            "unconsumed_only",
            "null_vectors",
            "blank_values",
            "blank_references_and_bugzilla",
            "filtered_packages",
            "affected_release_only",
        ],
    )
    async def test_200_without_extractable_data_is_missing(
        self,
        body: dict[str, Any],
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, body)

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0

    async def test_only_rejected_values_are_missing_after_their_skip_events(
        self, fetcher: SyncRedhatCves, server: RedhatServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(
            server,
            cve_id,
            {
                "cvss3": {"cvss3_scoring_vector": f"{SECRET}/AV:N"},
                "cwe": f"CWE-1 {SECRET}",
            },
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert logs == [
            {
                "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                "log_level": "warning",
                "cve_id": cve_id,
                "fetcher_name": NAME,
                "reason": "invalid_vector",
            },
            {
                "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                "log_level": "warning",
                "cve_id": cve_id,
                "fetcher_name": NAME,
                "reason": "invalid_cwe",
            },
        ]


# ---------------------------------------------------------------------------
# Error propagation and classification
# ---------------------------------------------------------------------------


async def _raised(
    fetcher: SyncRedhatCves, server: RedhatServer, responder: Any
) -> BaseException:
    cve_id = fictional_cve_id()
    server.responses[cve_id] = responder
    with pytest.raises((httpx.HTTPError, ValueError, RedhatResponseError)) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    return raised.value


@pytest.mark.unit
class TestErrorPropagation:
    @pytest.mark.parametrize("status", [400, 401, 403, 405, 410, 422])
    async def test_other_4xx_is_an_unwrapped_non_retryable_status_error(
        self,
        status: int,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(
            fetcher, server, lambda request: httpx.Response(status, text=SECRET)
        )

        assert type(error) is httpx.HTTPStatusError
        assert isinstance(error, httpx.HTTPStatusError)
        assert error.response.status_code == status
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    async def test_429_is_an_unwrapped_retryable_non_infrastructure_error(
        self, fetcher: SyncRedhatCves, server: RedhatServer
    ) -> None:
        error = await _raised(fetcher, server, lambda request: httpx.Response(429))

        assert isinstance(error, httpx.HTTPStatusError)
        assert error.response.status_code == 429
        assert is_retryable_condition(error)
        assert not is_infrastructure_failure(error)

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    async def test_5xx_is_an_unwrapped_retryable_infrastructure_error(
        self, status: int, fetcher: SyncRedhatCves, server: RedhatServer
    ) -> None:
        error = await _raised(fetcher, server, lambda request: httpx.Response(status))

        assert isinstance(error, httpx.HTTPStatusError)
        assert error.response.status_code == status
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
        self, error: Exception, fetcher: SyncRedhatCves, server: RedhatServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)
        assert is_infrastructure_failure(raised)

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self, status: int, fetcher: SyncRedhatCves, server: RedhatServer
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = lambda request: httpx.Response(
            status, headers={"Location": redhat_cve_url(fictional_cve_id())}
        )

        with pytest.raises(httpx.HTTPStatusError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value.response.status_code == status
        assert server.requested_cve_ids == [cve_id]
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)

    @pytest.mark.parametrize("status", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_non_retryable_error_without_upstream_data(
        self,
        status: int,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            lambda request: httpx.Response(status, json={"cwe": "CWE-79", SECRET: 1}),
        )

        assert type(error) is RedhatResponseError
        assert str(error) == "Red Hat Security Data API returned an unexpected status"
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "content", [b"", b"{", b"<html>Service</html>", b"\xff\xfe"]
    )
    async def test_unparseable_json_is_non_retryable(
        self,
        content: bytes,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(
            fetcher, server, lambda request: httpx.Response(200, content=content)
        )

        assert isinstance(error, ValueError)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "body",
        [
            [{"cwe": "CWE-79"}],
            "CWE-79",
            {"cwe": ["CWE-79", SECRET]},
            {"references": SECRET},
            {"package_state": [{"package_name": [SECRET]}]},
            {"cvss3": {"cvss3_scoring_vector": [SECRET]}},
        ],
        ids=[
            "array_root",
            "string_root",
            "cwe_list",
            "references_string",
            "package_list",
            "vector_list",
        ],
    )
    async def test_schema_mismatch_is_non_retryable_and_hides_the_input(
        self,
        body: Any,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
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
        instance = SyncRedhatCves()
        try:
            assert instance.http_client.follow_redirects is False
        finally:
            await instance._teardown_http_client()
        assert SyncRedhatCves.http_client_options == {}


# ---------------------------------------------------------------------------
# Ingestion: payload, results, and references (real upsert_cve)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPayload:
    async def test_full_record_sets_only_the_three_child_fields(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_full_v3"))

        await fetcher.fetch_single(target.cve_id, db_session)

        [payload] = ingestion.payloads
        assert payload.model_fields_set == {
            "cvss_assessments",
            "cwe_classifications",
            "resolved_packages",
        }
        assert [
            (entry.provider_name, entry.vector_string)
            for entry in payload.cvss_assessments or ()
        ] == [("Red Hat", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")]
        assert [
            (entry.cwe_id, entry.source) for entry in payload.cwe_classifications or ()
        ] == [("CWE-364", "Red Hat")]
        assert payload.resolved_packages == ["openssh"]

    @pytest.mark.parametrize(
        ("body", "fields"),
        [
            ({"cvss3": {"cvss3_scoring_vector": V31}}, {"cvss_assessments"}),
            ({"cwe": "CWE-79"}, {"cwe_classifications"}),
            ({"package_state": [{"package_name": "example"}]}, {"resolved_packages"}),
            ({"references": [URL_1]}, set()),
            ({"bugzilla": {"url": BUGZILLA_URL}}, set()),
        ],
        ids=["cvss", "cwe", "packages", "references", "bugzilla"],
    )
    async def test_unobserved_fields_are_omitted(
        self,
        body: dict[str, Any],
        fields: set[str],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(server, target.cve_id, body)

        await fetcher.fetch_single(target.cve_id, db_session)

        [payload] = ingestion.payloads
        assert payload.model_fields_set == fields

    async def test_upsert_cve_receives_the_canonical_id_and_enum_source(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
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
        _serve(server, target.cve_id, {"cwe": "CWE-79"})

        await fetcher.fetch_single(target.cve_id, db_session)

        assert calls == [(target.cve_id, CVESourceType.REDHAT)]
        assert calls[0][1] is CVESourceType.REDHAT


@pytest.mark.integration
class TestResults:
    async def test_v3_only_is_updated_with_a_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_full_v3"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert isinstance(result, CVEFetchResult)
        assert result.action is UpsertAction.UPDATED
        assert result.post_ingest == PostIngestTasks(
            ticket_id=str(target.ticket.id),
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["openssh"],
        )
        assert await _assessments(db_session, target.cve) == {
            ("Red Hat", "3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
        }
        assert await _cwes(db_session, target.cve) == {("CWE-364", "Red Hat")}

    async def test_v2_only_is_stored(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_v2_only"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == {
            ("Red Hat", "2.0", "AV:N/AC:L/Au:N/C:P/I:N/A:N")
        }
        assert await _cwes(db_session, target.cve) == {("CWE-805", "Red Hat")}
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == [
            "openssl",
            "openssl097a",
            "openssl098e",
        ]

    async def test_v3_and_v2_coexist_as_two_assessments(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_v2_v3"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == {
            ("Red Hat", "3.0", "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            ("Red Hat", "2.0", "AV:L/AC:M/Au:N/C:C/I:C/A:C"),
        }

    async def test_neither_vector_is_unchanged_without_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_no_cvss"))

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert await _assessments(db_session, target.cve) == set()
        assert await _cwes(db_session, target.cve) == set()

    async def test_updated_without_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"cvss": {"cvss_scoring_vector": V2}})

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UPDATED, None)

    async def test_unchanged_with_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"package_state": [{"package_name": "example"}]})

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is not None
        assert result.post_ingest.resolved_packages == ["example"]

    async def test_handoff_follows_the_build_post_ingest_filter(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        # Kept by the step-9 filter, rejected by the handoff heuristic.
        _serve(server, target.cve_id, {"package_state": [{"package_name": "a b:c"}]})

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.payloads[0].resolved_packages == ["a b:c"]
        assert result == CVEFetchResult(UpsertAction.UNCHANGED, None)

    async def test_draft_status_is_stored(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            {"cvss3": {"cvss3_scoring_vector": V31, "status": "draft"}},
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == {("Red Hat", "3.1", V31)}

    async def test_repeat_is_unchanged_without_duplicates(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_v2_only"))
        first = await fetcher.fetch_single(target.cve_id, db_session)
        counts = await _row_counts(db_session, target)
        references = await _references(db_session, target.ticket)

        second = await fetcher.fetch_single(target.cve_id, db_session)

        assert first.action is UpsertAction.UPDATED
        assert second.action is UpsertAction.UNCHANGED
        assert second.post_ingest == first.post_ingest
        assert await _row_counts(db_session, target) == counts
        assert counts == (1, 1, len(references), 1)
        assert await _references(db_session, target.ticket) == references

    async def test_success_status_is_written_in_the_session(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"cwe": "CWE-79"})

        await fetcher.fetch_single(target.cve_id, db_session)

        status = await db_session.scalar(
            select(CVESource.status).where(
                CVESource.cve_id == target.cve.id, CVESource.source == "redhat"
            )
        )
        assert status == CVESourceFetchStatus.SUCCESS

    async def test_fetch_single_records_no_metric(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_full_v3"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        ) == (0, 0, 0, 0)


@pytest.mark.integration
class TestReferences:
    async def test_source_then_lines_then_bugzilla(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            {
                "references": [f"{URL_2}\r\n\r\n{URL_1}\n", " \n", URL_1],
                "bugzilla": {"url": BUGZILLA_URL, "description": "Fictional flaw"},
            },
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        source_url = SOURCE_URL.format(cve_id=target.cve_id)
        assert call["ticket_id"] == target.ticket.id
        assert call["cve_id"] == target.cve_id
        assert call["source"] == NAME
        assert call["source_reference"] == AutomaticReferenceInput(
            url=source_url, title="Red Hat", explicit_type=ReferenceType.ADVISORY
        )
        assert call["upstream"] == [
            AutomaticReferenceInput(url=URL_2),
            AutomaticReferenceInput(url=URL_1),
            AutomaticReferenceInput(url=URL_1),
            AutomaticReferenceInput(
                url=BUGZILLA_URL,
                title="Fictional flaw",
                explicit_type=ReferenceType.ISSUE,
            ),
        ]
        assert await _references(db_session, target.ticket) == {
            source_url: ("Red Hat", "advisory", NAME),
            URL_2: (None, None, NAME),
            URL_1: (None, None, NAME),
            BUGZILLA_URL: ("Fictional flaw", "issue", NAME),
        }

    async def test_live_record_references_are_classified(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_no_cvss"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == {
            SOURCE_URL.format(cve_id=target.cve_id): ("Red Hat", "advisory", NAME),
            "https://www.cve.org/CVERecord?id=CVE-2005-3623": (None, None, NAME),
            "https://nvd.nist.gov/vuln/detail/CVE-2005-3623": (
                None,
                "advisory",
                NAME,
            ),
            "https://bugzilla.redhat.com/show_bug.cgi?id=1617825": (
                "security flaw",
                "issue",
                NAME,
            ),
        }

    @pytest.mark.parametrize(
        "body",
        [
            {"cwe": "CWE-79"},
            {"cvss3": {"cvss3_scoring_vector": V31}},
            {"package_state": [{"package_name": "example"}]},
            {"cwe": "CWE-79", "references": ["\n"], "bugzilla": {"url": " "}},
        ],
        ids=["cwe", "cvss", "packages", "blank_references_and_empty_bugzilla"],
    )
    async def test_called_with_the_source_reference_when_upstream_is_empty(
        self,
        body: dict[str, Any],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(server, target.cve_id, body)

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        assert call["source"] == NAME
        assert call["upstream"] == []
        assert await _references(db_session, target.ticket) == {
            SOURCE_URL.format(cve_id=target.cve_id): ("Red Hat", "advisory", NAME)
        }

    async def test_empty_bugzilla_url_is_skipped(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            {"references": [URL_1], "bugzilla": {"url": "", "description": "x"}},
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.references[0]["upstream"] == [
            AutomaticReferenceInput(url=URL_1)
        ]

    async def test_lone_carriage_return_line_is_rejected_by_the_url_boundary(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"references": [f"{URL_1}\n{URL_2}\r"]})

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert set(await _references(db_session, target.ticket)) == {
            SOURCE_URL.format(cve_id=target.cve_id),
            URL_1,
        }
        assert [entry["reason"] for entry in logs] == ["control_character"]


@pytest.mark.integration
class TestPartialExtraction:
    async def test_invalid_vector_is_skipped_with_one_bounded_warning(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        raw = f"CVSS:3.1/AV:N/{SECRET}"
        _serve(
            server,
            target.cve_id,
            {
                "cvss3": {"cvss3_scoring_vector": raw},
                "cvss": {"cvss_scoring_vector": V2},
                "cwe": "CWE-79",
                "package_state": [{"package_name": "example"}],
            },
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == {("Red Hat", "2.0", V2)}
        assert await _cwes(db_session, target.cve) == {("CWE-79", "Red Hat")}
        assert logs == [
            {
                "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                "log_level": "warning",
                "cve_id": target.cve_id,
                "fetcher_name": NAME,
                "reason": "invalid_vector",
            }
        ]
        _assert_no_raw_value(logs, raw, SECRET)

    async def test_non_base_vector_is_skipped(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            {"cvss3": {"cvss3_scoring_vector": V31 + "/E:P"}, "cwe": "CWE-79"},
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == set()
        assert [entry["reason"] for entry in logs] == ["invalid_vector"]

    async def test_invalid_cwe_is_skipped_and_other_data_continues(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        raw = f"CWE-200->CWE-284 {SECRET}"
        _serve(
            server,
            target.cve_id,
            {"cvss3": {"cvss3_scoring_vector": V31}, "cwe": raw},
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == {("Red Hat", "3.1", V31)}
        assert await _cwes(db_session, target.cve) == set()
        assert logs == [
            {
                "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
                "log_level": "warning",
                "cve_id": target.cve_id,
                "fetcher_name": NAME,
                "reason": "invalid_cwe",
            }
        ]
        _assert_no_raw_value(logs, raw, SECRET)

    async def test_absent_values_log_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            {
                "cvss3": {"cvss3_scoring_vector": ""},
                "cvss": {"cvss_scoring_vector": None},
                "references": [URL_1],
            },
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert logs == []


@pytest.mark.integration
class TestDataPreservation:
    async def test_missing_fields_and_a_later_404_delete_no_red_hat_data(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, _fixture("cve_v2_v3") | {"cwe": "CWE-362"})
        await fetcher.fetch_single(target.cve_id, db_session)
        assessments = await _assessments(db_session, target.cve)
        cwes = await _cwes(db_session, target.cve)
        references = await _references(db_session, target.ticket)
        assert len(assessments) == 2
        assert cwes == {("CWE-362", "Red Hat")}

        # A later response omits CVSS, CWE, and every reference.
        _serve(server, target.cve_id, {"package_state": [{"package_name": "kernel"}]})
        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert await _assessments(db_session, target.cve) == assessments
        assert await _cwes(db_session, target.cve) == cwes
        assert await _references(db_session, target.ticket) == references

        # A later 404.
        del server.bodies[target.cve_id]
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == assessments
        assert await _cwes(db_session, target.cve) == cwes
        assert await _references(db_session, target.ticket) == references

    async def test_empty_or_null_vector_retains_the_persisted_assessment(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"cvss3": {"cvss3_scoring_vector": V31}})
        await fetcher.fetch_single(target.cve_id, db_session)

        _serve(
            server,
            target.cve_id,
            {"cvss3": {"cvss3_scoring_vector": None}, "cwe": "CWE-79"},
        )
        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == {("Red Hat", "3.1", V31)}


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalStringAdmissibility:
    async def test_package_name_with_nul_fails_the_item_before_any_write(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
        ingestion: Ingestion,
    ) -> None:
        name = f"{SECRET}\x00"
        _serve(
            server,
            target.cve_id,
            {
                "cvss3": {"cvss3_scoring_vector": V31},
                "references": [URL_1],
                "package_state": [{"package_name": "example"}, {"package_name": name}],
            },
        )
        before = await _row_counts(db_session, target)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == 0
        assert await _row_counts(db_session, target) == before == (0, 0, 0, 0)
        assert SECRET not in str(raised.value)
        assert logs == []
        assert not is_retryable_condition(raised.value)

    @pytest.mark.parametrize("field", ["cvss3", "cvss"])
    async def test_vector_with_nul_is_an_invalid_vector_skip(
        self,
        field: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        vector = V31 if field == "cvss3" else V2
        _serve(
            server,
            target.cve_id,
            {field: {f"{field}_scoring_vector": vector + "\x00"}, "cwe": "CWE-79"},
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert await _assessments(db_session, target.cve) == set()
        assert await _cwes(db_session, target.cve) == {("CWE-79", "Red Hat")}
        assert [entry["reason"] for entry in logs] == ["invalid_vector"]
        _assert_no_raw_value(logs, vector)

    async def test_cwe_with_nul_is_an_invalid_cwe_skip(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, {"cwe": "CWE-79\x00", "references": [URL_1]})

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert await _cwes(db_session, target.cve) == set()
        assert [entry["reason"] for entry in logs] == ["invalid_cwe"]
        _assert_no_raw_value(logs, "CWE-79")

    @pytest.mark.parametrize(
        ("body", "rejected", "reason"),
        [
            (
                {"references": [f"{URL_2}?{SECRET}\x00\n{URL_1}"]},
                URL_2,
                "control_character",
            ),
            (
                {"references": [URL_1], "bugzilla": {"url": f"{BUGZILLA_URL}\x00"}},
                BUGZILLA_URL,
                "control_character",
            ),
            (
                {
                    "references": [URL_1],
                    "bugzilla": {"url": BUGZILLA_URL, "description": f"{SECRET}\x00"},
                },
                BUGZILLA_URL,
                "invalid_metadata",
            ),
        ],
        ids=["reference_line", "bugzilla_url", "bugzilla_description"],
    )
    async def test_reference_candidate_with_nul_is_skipped(
        self,
        body: dict[str, Any],
        rejected: str,
        reason: str,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncRedhatCves,
        server: RedhatServer,
    ) -> None:
        _serve(server, target.cve_id, body)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        references = await _references(db_session, target.ticket)
        assert set(references) == {SOURCE_URL.format(cve_id=target.cve_id), URL_1}
        assert not any(url.startswith(rejected) for url in references)
        assert logs == [
            {
                "event": "automatic_reference_rejected",
                "log_level": "warning",
                "cve_id": target.cve_id,
                "source": NAME,
                "reason": reason,
            }
        ]
        _assert_no_raw_value(logs, SECRET, rejected)


# ---------------------------------------------------------------------------
# Class contract and concrete compliance
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcreteCompliance:
    def test_properties_match_the_specification(self) -> None:
        assert SyncRedhatCves.name == NAME
        assert SyncRedhatCves.cve_source_type is CVESourceType.REDHAT
        assert SyncRedhatCves.cve_source_type.value == "redhat"
        assert SyncRedhatCves.description == "Sync CVE data from Red Hat Security API"
        assert SyncRedhatCves.default_schedule == "0 3 * * *"
        assert SyncRedhatCves.default_request_delay == 2.0
        assert SyncRedhatCves.source_reference_url_pattern == SOURCE_URL
        assert SyncRedhatCves.Settings is None
        assert SyncRedhatCves.queue is None
        assert SyncRedhatCves.http_client_options == {}

    def test_capability_flags(self) -> None:
        assert SyncRedhatCves.supports_fetch_single is True
        assert SyncRedhatCves.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncRedhatCves.__dict__
        assert "abstract" not in SyncRedhatCves.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncRedhatCves.__name__ == "SyncRedhatCves"

    def test_fetch_single_and_execute_are_overridden(self) -> None:
        assert "fetch_single" in SyncRedhatCves.__dict__
        assert SyncRedhatCves.fetch_single is not BaseCVEFetcher.fetch_single
        assert "execute" in SyncRedhatCves.__dict__
        assert SyncRedhatCves.execute is not BaseFetcher.execute
        assert inspect.iscoroutinefunction(SyncRedhatCves.fetch_single)
        assert inspect.iscoroutinefunction(SyncRedhatCves.execute)
        assert (
            inspect.get_annotations(SyncRedhatCves.fetch_single, eval_str=True)[
                "return"
            ]
            is CVEFetchResult
        )

    def test_catch_up_is_the_inherited_default(self) -> None:
        assert "catch_up" not in SyncRedhatCves.__dict__
        assert SyncRedhatCves.catch_up is BaseCVEFetcher.catch_up

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncRedhatCves
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.REDHAT] is SyncRedhatCves
        assert get_all_cve_source_types()["redhat"] is SyncRedhatCves

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["redhat"] is SyncRedhatCves
        assert get_catch_up_fetchers()[NAME] is SyncRedhatCves

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        assert not hasattr(BaseCVEFetcher, "_get_active_ticket_cve_ids")

    def test_payload_constants_are_the_red_hat_provider(self) -> None:
        assert redhat_cve_record.PROVIDER_NAME == "Red Hat"

    def test_fixture_bodies_round_trip_as_json(self) -> None:
        """The fake server serves every fixture as served live."""
        body = _fixture("cve_full_v3")

        assert json.loads(httpx.Response(200, json=body).content) == body
