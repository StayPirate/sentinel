"""Tests for `SyncEpssScores.fetch_single()` and the class contract
(backend/app/services/tickets/sync_epss_scores.py and
backend/app/services/tickets/epss_score_record.py).

Owning specifications:

- docs/features/tickets/cve-sync-epss.md (Fetcher Definition; Algorithm
  steps 1-8, including External String Admissibility and the on-demand
  exclusion of the staleness check; Field Mapping; `fetch_single` method;
  Error Handling, `fetch_single()` table, data preservation, and sanitized
  messages).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `CVEFetchResult`; `fetch_single` Signaling Convention; Retry Policy and
  Error Categorization; CVE Source Type Identity; both registry accessors;
  Default catch_up Implementation).
- docs/features/tickets/cve-service.md (Primary Entry Point: `upsert_cve()`,
  the audit label table and Ticket Creation Decision; Child Persistence
  Matrix, the `epss_score` row; UpsertResult) and
  docs/features/tickets/ticket-priority.md (Exploitation Level; Decision
  Table; Automatic Refresh; Audit).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention,
  Class Name Derivation, BaseFetcher HTTP Client Integration) and
  docs/features/platform/networking.md (Infrastructure Failure
  Classification; Celery Retry Classification; Redirect Policy).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Typed result and Concrete compliance; External String Admissibility).

HTTP is the in-process `EpssServer` of `tests/support/epss.py`, injected as
the fetcher's HTTP client, serving the live fixtures under fictional
CVE-IDs or minimal fictional bodies. Outcome tests that end before any
database work use a session that fails on any use, and a spy on
`cve_service.upsert_cve()` proves no mutation was attempted; they are unit
tests. Ingestion tests run the real `upsert_cve()` on `db_session`, rolled
back at teardown. All identifiers are fictional.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any, Final, cast

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.services import cve_service
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
    FetcherError,
    get_catch_up_fetchers,
)
from app.services.cve_ingest import CVEIngestPayload, EPSSEntry, UpsertAction
from app.services.http_client import (
    is_infrastructure_failure,
    is_retryable_condition,
)
from app.services.tickets import sync_epss_scores as sync_module
from app.services.tickets.sync_epss_scores import (
    EPSS_DATA_STALE_EVENT,
    EPSS_URL,
    EpssResponseError,
    SyncEpssScores,
)
from tests.support.epss import (
    EpssServer,
    Responder,
    body,
    entry_for,
    envelope,
    epss_url,
    load_raw_fixture,
    raising,
    scored_entry,
    status,
)
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.ticket_mutations import EventRow, ticket_events

NAME: Final = "sync_epss_scores"
SECRET: Final = "Example-Secret-Upstream-Value"
"""An upstream value that must never reach an exception message."""

INGESTION_COMMENT: Final = "CVE ingested from FIRST.org EPSS"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _NoSession:
    """A session that fails the test on any use."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used before ingestion")


NO_SESSION: Final = cast(AsyncSession, _NoSession())


@dataclass
class Ingestion:
    """Spy on `cve_service.upsert_cve()`; calls through."""

    calls: list[tuple[str, CVESourceType, CVEIngestPayload]] = field(
        default_factory=list
    )

    @property
    def payloads(self) -> list[CVEIngestPayload]:
        return [payload for _, _, payload in self.calls]


@pytest.fixture
def ingestion(monkeypatch: pytest.MonkeyPatch) -> Ingestion:
    spy = Ingestion()
    real_upsert = cve_service.upsert_cve

    async def upsert_cve(
        db: AsyncSession, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> Any:
        spy.calls.append((cve_id, source, payload))
        return await real_upsert(db, cve_id, source, payload)

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
    return spy


@pytest.fixture
def server() -> EpssServer:
    return EpssServer()


@pytest.fixture
async def fetcher(server: EpssServer) -> AsyncIterator[SyncEpssScores]:
    instance = SyncEpssScores()
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
    """A published CVE with its `Analysis` Ticket: NULL severity, no KEV,
    SSVC, or EPSS evidence, no override, and NULL `priority_auto`."""
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


def _serve(server: EpssServer, cve_id: str, **fields: str) -> None:
    server.entries[cve_id] = entry_for(cve_id, **fields)


async def _score(db: AsyncSession, cve: CVE) -> tuple[float, float, date] | None:
    row = (
        await db.execute(
            select(
                CVEEPSSScore.score, CVEEPSSScore.percentile, CVEEPSSScore.assessed_at
            ).where(CVEEPSSScore.cve_id == cve.id)
        )
    ).one_or_none()
    return None if row is None else (row[0], row[1], row[2])


async def _row_counts(db: AsyncSession, cve: CVE) -> tuple[int, int]:
    """(`CVEEPSSScore` rows, `CVESource` rows) of one CVE."""
    counts = []
    for model in (CVEEPSSScore, CVESource):
        counts.append(
            int(
                await db.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.cve_id == cve.id)
                )
                or 0
            )
        )
    return counts[0], counts[1]


async def _priority_auto(db: AsyncSession, ticket: Ticket) -> str | None:
    value: str | None = await db.scalar(
        select(Ticket.priority_auto).where(Ticket.id == ticket.id)
    )
    return value


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


# ---------------------------------------------------------------------------
# Request and outcomes before any database work
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_one_get_with_only_the_cve_query_parameter(
        self, fetcher: SyncEpssScores, server: EpssServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        [request] = server.requests
        assert request.method == "GET"
        assert str(request.url) == epss_url(cve_id)
        assert str(request.url) == f"https://api.first.org/data/v1/epss?cve={cve_id}"
        assert request.url.params.multi_items() == [("cve", cve_id)]
        assert EPSS_URL == "https://api.first.org/data/v1/epss"

    async def test_production_client_follows_no_redirect(self) -> None:
        instance = SyncEpssScores()
        try:
            assert instance.http_client.follow_redirects is False
        finally:
            await instance._teardown_http_client()
        assert SyncEpssScores.http_client_options == {}


@pytest.mark.unit
class TestStalenessReference:
    def test_reference_is_the_current_utc_date(self) -> None:
        before = datetime.now(UTC).date()
        today = sync_module._utc_today()
        after = datetime.now(UTC).date()

        assert type(today) is date
        assert today in {before, after}


@pytest.mark.unit
class TestMissingBeforeMutation:
    @pytest.mark.parametrize(
        "cve_id",
        ["CVE-2099-1", "cve-2099-48001", "CVE-2099-48001 ", "", "CVE-2099-" + "1" * 12],
        ids=["short", "lowercase", "trailing_space", "empty", "over_long"],
    )
    async def test_malformed_cve_id_is_missing_without_http(
        self,
        cve_id: str,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert ingestion.calls == []

    async def test_live_unscored_response_is_missing_without_writes(
        self, fetcher: SyncEpssScores, server: EpssServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = lambda request: httpx.Response(
            200, content=load_raw_fixture("unscored"), request=request
        )

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_cve_ids == [cve_id]
        assert ingestion.calls == []

    async def test_minimal_empty_data_is_missing_without_writes(
        self, fetcher: SyncEpssScores, server: EpssServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = body({"data": []})

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == []


# ---------------------------------------------------------------------------
# Error propagation and classification
# ---------------------------------------------------------------------------


async def _raised(
    fetcher: SyncEpssScores, server: EpssServer, responder: Responder
) -> BaseException:
    cve_id = fictional_cve_id()
    server.responses[cve_id] = responder
    with pytest.raises((httpx.HTTPError, ValueError)) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    assert server.requested_cve_ids == [cve_id]
    return raised.value


def _entry(**fields: Any) -> dict[str, Any]:
    """A fictional `data[0]` object with `fields` replaced (a `None` value
    removes the member)."""
    entry: dict[str, Any] = entry_for("CVE-2099-48001")
    for name, value in fields.items():
        if value is None:
            del entry[name]
        else:
            entry[name] = value
    return entry


DATA_QUALITY_BODIES: Final[list[tuple[str, Any, str | None]]] = [
    ("score_above_one", envelope(_entry(epss="1.000000001")), "1.000000001"),
    ("score_far_above_one", envelope(_entry(epss="2.5")), "2.5"),
    ("percentile_above_one", envelope(_entry(percentile="1.000000001")), "1.000000001"),
    ("percentile_negative", envelope(_entry(percentile="-0.100000000")), "-0.1"),
    ("score_letters", envelope(_entry(epss="abc")), "abc"),
    ("score_exponent", envelope(_entry(epss="1e-3")), "1e-3"),
    ("score_leading_space", envelope(_entry(epss=" 0.5")), " 0.5"),
    ("score_negative", envelope(_entry(epss="-0.1")), "-0.1"),
    ("score_nan", envelope(_entry(epss="NaN")), "NaN"),
    ("score_trailing_dot", envelope(_entry(epss="0.")), None),
    ("score_empty", envelope(_entry(epss="")), None),
    ("percentile_upstream_text", envelope(_entry(percentile=SECRET)), SECRET),
    ("date_month_13", envelope(_entry(date="2026-13-01")), "2026-13-01"),
    ("date_february_30", envelope(_entry(date="2026-02-30")), "2026-02-30"),
    ("date_slashes", envelope(_entry(date="2026/10/06")), "2026/10/06"),
    ("date_epoch", envelope(_entry(date="1791303947")), "1791303947"),
    ("date_timestamp", envelope(_entry(date="2026-10-06T00:00:00")), "T00:00:00"),
    ("missing_epss", envelope(_entry(epss=None)), None),
    ("missing_percentile", envelope(_entry(percentile=None)), None),
    ("missing_date", envelope(_entry(date=None)), None),
    ("number_epss", envelope(_entry(epss=0.5)), None),
    ("number_percentile", envelope(_entry(percentile=0.5)), None),
    ("null_date", {"data": [{**_entry(), "date": None}]}, None),
    (
        "two_entries",
        envelope(_entry(), entry_for("CVE-2099-48002", percentile=SECRET)),
        SECRET,
    ),
    ("data_missing", {"status": "OK", "total": 0}, None),
    ("data_object", {"data": _entry()}, None),
    ("data_string_item", {"data": [SECRET]}, SECRET),
    ("array_root", [_entry()], None),
    ("string_root", SECRET, SECRET),
    ("null_root", None, None),
]


@pytest.mark.unit
class TestErrorPropagation:
    @pytest.mark.parametrize("code", [400, 401, 403, 404, 405, 410, 422])
    async def test_other_4xx_is_an_unwrapped_non_retryable_status_error(
        self,
        code: int,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(code, SECRET.encode()))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not isinstance(error, FetcherError)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == []

    async def test_429_is_an_unwrapped_retryable_non_infrastructure_error(
        self, fetcher: SyncEpssScores, server: EpssServer, ingestion: Ingestion
    ) -> None:
        error = await _raised(fetcher, server, status(429))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == 429
        assert is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == []

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    async def test_5xx_is_an_unwrapped_retryable_infrastructure_error(
        self,
        code: int,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(code))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert is_retryable_condition(error)
        assert is_infrastructure_failure(error)
        assert ingestion.calls == []

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
        self, error: Exception, fetcher: SyncEpssScores, server: EpssServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)
        assert is_infrastructure_failure(raised)

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self,
        code: int,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        server.responses[cve_id] = lambda request: httpx.Response(
            code, headers={"Location": epss_url(fictional_cve_id())}, request=request
        )

        with pytest.raises(httpx.HTTPStatusError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value.response.status_code == code
        assert server.requested_cve_ids == [cve_id]
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)
        assert ingestion.calls == []

    @pytest.mark.parametrize("code", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_non_retryable_error_without_upstream_data(
        self,
        code: int,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        # A valid envelope under another 2xx status is still not ingested.
        server.responses[cve_id] = lambda request: httpx.Response(
            code, json=envelope(entry_for(cve_id, percentile=SECRET)), request=request
        )

        with pytest.raises(EpssResponseError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requested_cve_ids == [cve_id]
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)
        assert ingestion.calls == []

    @pytest.mark.parametrize(
        "content", [b"", b"{", b"<html>Service</html>", b"\xff\xfe"]
    )
    async def test_non_json_body_is_a_non_retryable_decoding_error(
        self,
        content: bytes,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(200, content))

        assert isinstance(error, ValueError)
        assert not isinstance(error, ValidationError)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == []

    @pytest.mark.parametrize(
        ("value", "rendered"),
        [(value, rendered) for _, value, rendered in DATA_QUALITY_BODIES],
        ids=[name for name, _, _ in DATA_QUALITY_BODIES],
    )
    async def test_data_quality_error_is_non_retryable_and_hides_the_input(
        self,
        value: Any,
        rendered: str | None,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        # `httpx` sends no body for `json=None`; a JSON `null` root is raw.
        responder = status(200, b"null") if value is None else body(value)

        error = await _raised(fetcher, server, responder)

        assert isinstance(error, ValidationError)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        if rendered is not None:
            assert rendered not in str(error)
            assert rendered not in repr(error)
        assert ingestion.calls == []

    async def test_upper_bound_values_are_accepted(
        self,
        fetcher: SyncEpssScores,
        server: EpssServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, epss="1", percentile="1.000000000", date="2026-10-06")
        payloads: list[CVEIngestPayload] = []

        async def upsert_cve(
            db: AsyncSession, cve: str, source: CVESourceType, payload: Any
        ) -> Any:
            payloads.append(payload)
            return SimpleNamespace(action=UpsertAction.UNCHANGED)

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)

        await fetcher.fetch_single(cve_id, NO_SESSION)

        assert [payload.epss_score for payload in payloads] == [
            EPSSEntry(score=1.0, percentile=1.0, assessed_at=date(2026, 10, 6))
        ]


# ---------------------------------------------------------------------------
# Result pass-through (stubbed upsert_cve)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResultPassThrough:
    @pytest.mark.parametrize("action", list(UpsertAction), ids=str)
    async def test_returns_the_upsert_action_unmodified_without_handoff(
        self,
        action: UpsertAction,
        fetcher: SyncEpssScores,
        server: EpssServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id)

        async def upsert_cve(
            db: AsyncSession, cve: str, source: CVESourceType, payload: Any
        ) -> Any:
            return SimpleNamespace(action=action)

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)

        result = await fetcher.fetch_single(cve_id, NO_SESSION)

        assert type(result) is CVEFetchResult
        assert result.action is action
        assert result.post_ingest is None

    async def test_upsert_exception_propagates_unchanged(
        self,
        fetcher: SyncEpssScores,
        server: EpssServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id)
        error = RuntimeError(SECRET)

        async def upsert_cve(
            db: AsyncSession, cve: str, source: CVESourceType, payload: Any
        ) -> Any:
            raise error

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)

        with pytest.raises(RuntimeError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is error


# ---------------------------------------------------------------------------
# Ingestion: payload and results (real upsert_cve)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPayload:
    async def test_payload_sets_only_the_converted_epss_score(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        # The live `scored` entry, served under a fictional CVE-ID.
        server.entries[target.cve_id] = {**scored_entry(), "cve": target.cve_id}

        await fetcher.fetch_single(target.cve_id, db_session)

        [(cve_id, source, payload)] = ingestion.calls
        assert cve_id == target.cve_id
        assert source is CVESourceType.EPSS
        assert payload.model_fields_set == {"epss_score"}
        assert payload.epss_score == EPSSEntry(
            score=0.99506, percentile=0.99945, assessed_at=date(2026, 10, 6)
        )
        assert payload.cvss_assessments is None
        assert payload.kev_data is None
        assert payload.resolved_packages is None


@pytest.mark.integration
class TestResults:
    async def test_new_score_is_updated_without_handoff(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            epss="0.004300000",
            percentile="0.250000000",
            date="2026-10-05",
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UPDATED, None)
        assert await _score(db_session, target.cve) == (
            0.0043,
            0.25,
            date(2026, 10, 5),
        )
        status_value = await db_session.scalar(
            select(CVESource.status).where(
                CVESource.cve_id == target.cve.id, CVESource.source == "epss"
            )
        )
        assert status_value == CVESourceFetchStatus.SUCCESS

    async def test_repeat_equal_content_is_unchanged(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        _serve(server, target.cve_id)
        first = await fetcher.fetch_single(target.cve_id, db_session)
        stored = await _score(db_session, target.cve)

        second = await fetcher.fetch_single(target.cve_id, db_session)

        assert first.action is UpsertAction.UPDATED
        assert second == CVEFetchResult(UpsertAction.UNCHANGED, None)
        assert await _score(db_session, target.cve) == stored
        assert await _row_counts(db_session, target.cve) == (1, 1)

    @pytest.mark.parametrize(
        ("changed", "expected"),
        [
            ({"epss": "0.600000000"}, (0.6, 0.5, date(2026, 10, 6))),
            ({"percentile": "0.700000000"}, (0.5, 0.7, date(2026, 10, 6))),
            ({"date": "2026-10-07"}, (0.5, 0.5, date(2026, 10, 7))),
        ],
        ids=["score", "percentile", "assessed_at"],
    )
    async def test_each_changed_value_is_updated(
        self,
        changed: dict[str, str],
        expected: tuple[float, float, date],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        _serve(server, target.cve_id)
        await fetcher.fetch_single(target.cve_id, db_session)
        _serve(server, target.cve_id, **changed)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UPDATED, None)
        assert await _score(db_session, target.cve) == expected
        assert await _row_counts(db_session, target.cve) == (1, 1)

    async def test_later_empty_response_retains_the_score(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(server, target.cve_id, epss="0.010000000", percentile="0.300000000")
        await fetcher.fetch_single(target.cve_id, db_session)
        stored = await _score(db_session, target.cve)
        assert stored is not None

        del server.entries[target.cve_id]
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(target.cve_id, db_session)

        assert len(ingestion.calls) == 1
        assert await _score(db_session, target.cve) == stored

    async def test_fetch_single_has_no_run_side_effect(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A stale date: a staleness check would warn.
        _serve(server, target.cve_id, date="2026-09-01")
        monkeypatch.setattr(sync_module, "_utc_today", lambda: date(2026, 10, 6))
        sleeps: list[float] = []
        checks: list[date] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        async def forbidden() -> None:
            raise AssertionError("fetch_single() must not end the transaction")

        monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
        monkeypatch.setattr(fetcher, "_check_staleness", checks.append)
        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)
        client = fetcher._http_client
        assert client is not None

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        ) == (0, 0, 0, 0)
        assert sleeps == []
        assert checks == []
        assert _events(logs, EPSS_DATA_STALE_EVENT) == []
        assert fetcher._http_client is client
        assert not client.is_closed


# ---------------------------------------------------------------------------
# Ticket priority and Ticket creation through upsert_cve()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketEffects:
    async def test_percentile_at_threshold_sets_p3_with_one_system_event(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        assert target.ticket is not None
        _serve(server, target.cve_id, epss="0.010000000", percentile="0.950000000")

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _priority_auto(db_session, target.ticket) == "P3"
        assert await ticket_events(db_session, target.ticket) == [
            EventRow("priority_changed", None, None, "P3", None, None)
        ]

    async def test_percentile_just_below_threshold_keeps_null_priority(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        assert target.ticket is not None
        # The EPSS probability score is not a priority input.
        _serve(server, target.cve_id, epss="0.999000000", percentile="0.949900000")

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _priority_auto(db_session, target.ticket) is None
        assert await ticket_events(db_session, target.ticket) == []

    async def test_ticketless_cve_gets_one_ingestion_ticket(
        self,
        db_session: AsyncSession,
        ticketless: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
    ) -> None:
        _serve(server, ticketless.cve_id)

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
        assert await _score(db_session, ticketless.cve) == (
            0.5,
            0.5,
            date(2026, 10, 6),
        )


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "fields",
        [
            {"epss": "0.5\x00"},
            {"epss": "\x00"},
            {"percentile": "0.\x005"},
            {"percentile": "\x000.5"},
            {"date": "2026-10-06\x00"},
            {"date": "2026-10\x00-06"},
        ],
        ids=[
            "epss_end",
            "epss_whole",
            "percentile_middle",
            "percentile_start",
            "date_end",
            "date_middle",
        ],
    )
    async def test_nul_is_a_data_quality_failure_without_writes(
        self,
        fields: dict[str, str],
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncEpssScores,
        server: EpssServer,
        ingestion: Ingestion,
    ) -> None:
        server.entries[target.cve_id] = {**entry_for(target.cve_id), **fields}
        before = await _row_counts(db_session, target.cve)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert ingestion.calls == []
        assert await _row_counts(db_session, target.cve) == before == (0, 0)
        assert "\\x00" not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert not is_infrastructure_failure(raised.value)
        assert logs == []


# ---------------------------------------------------------------------------
# Class contract and concrete compliance
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcreteCompliance:
    def test_properties_match_the_specification(self) -> None:
        assert SyncEpssScores.name == NAME
        assert SyncEpssScores.cve_source_type is CVESourceType.EPSS
        assert SyncEpssScores.cve_source_type.value == "epss"
        assert SyncEpssScores.description == "Sync EPSS scores from FIRST.org"
        assert SyncEpssScores.default_schedule == "0 14 * * *"
        assert SyncEpssScores.default_request_delay == 0.2
        assert SyncEpssScores.source_reference_url_pattern is None
        assert SyncEpssScores.Settings is None
        assert SyncEpssScores.queue is None
        assert SyncEpssScores.http_client_options == {}

    def test_capability_flags_are_inherited_and_enabled(self) -> None:
        assert SyncEpssScores.supports_fetch_single is True
        assert SyncEpssScores.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncEpssScores.__dict__
        assert "abstract" not in SyncEpssScores.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncEpssScores.__name__ == "SyncEpssScores"

    def test_fetch_single_and_execute_are_overridden(self) -> None:
        assert "fetch_single" in SyncEpssScores.__dict__
        assert SyncEpssScores.fetch_single is not BaseCVEFetcher.fetch_single
        assert "execute" in SyncEpssScores.__dict__
        assert SyncEpssScores.execute is not BaseFetcher.execute
        assert inspect.iscoroutinefunction(SyncEpssScores.fetch_single)
        assert inspect.iscoroutinefunction(SyncEpssScores.execute)
        assert (
            inspect.get_annotations(SyncEpssScores.fetch_single, eval_str=True)[
                "return"
            ]
            is CVEFetchResult
        )

    def test_catch_up_is_the_inherited_default(self) -> None:
        assert "catch_up" not in SyncEpssScores.__dict__
        assert SyncEpssScores.catch_up is BaseCVEFetcher.catch_up

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncEpssScores
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.EPSS] is SyncEpssScores
        assert get_all_cve_source_types()["epss"] is SyncEpssScores

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["epss"] is SyncEpssScores
        assert get_catch_up_fetchers()[NAME] is SyncEpssScores

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        assert not hasattr(BaseCVEFetcher, "_get_active_ticket_cve_ids")
        assert not hasattr(BaseCVEFetcher, "_check_staleness")
