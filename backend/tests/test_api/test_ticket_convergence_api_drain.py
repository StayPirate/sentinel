"""End-to-end tests for the API transaction owner's Ticket convergence drain
(`drain_ticket_convergence_after_commit`, backend/app/api/dependencies.py,
mounted on every `/api/v1` router in backend/app/main.py) through the
production `app.database.get_db`.

Owning specifications:

- docs/features/tickets/ticket-service.md (Ticket Convergence: automatic
  registration paths; Publication policies; Publication failure logging;
  Architectural Test Requirement 11, publication part).
- docs/features/tickets/ticket-mutations.md (Transaction-Local Ticket
  Convergence Registration, steps 4-5: detach after a successful commit,
  discard on rollback).
- docs/conventions.md (API Transaction Dependency Scope; Transaction
  Hygiene Rules: no publication before commit or under a lock).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff > Publication policies (automatic API owner),
  Control signals and security, Structural absences: the generic
  post-commit callback contract is unchanged).

Representative endpoints that register an effect: `POST .../reopen` and
`POST .../revert-duplicate` (manual-zone exits), a track-status change
that regresses a `Resolved` Ticket, and a SUSE CVSS update whose new score
makes a Product eligible again and so regresses a `Resolved` Ticket.

The requests run through the real `get_db()` (its commit, rollback, and
generic post-commit callback loop with its `post_commit_callback_failed`
log): `app.database.async_session_factory` is replaced by a factory whose
sessions join the per-test `db_session` connection with
`join_transaction_mode="create_savepoint"`, so every request commit is a
savepoint release inside the outer test transaction, rolled back at
teardown. A connection-level savepoint around a first request lets the
identical request run again from the identical state, so the success
responses with and without a broker failure are compared byte for byte.
One representative test (reopen) instead commits for real on independent
connections to prove that commit and row-lock release precede the
attempt. The broker call (`task_publication.publish_task`) is substituted
by a recorder.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

from app import database
from app.core.enums import PackageStatus, Role, SessionCreationReason, TicketStatus
from app.database import get_db
from app.main import app
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import task_publication, ticket_service
from app.services.session_service import create_session
from tests.support.suse_cvss import V31_CRITICAL, V31_MEDIUM
from tests.support.ticket_api import (
    INTERNAL_ERROR,
    CommittedApp,
    force_production_error_page,
    locator,
)

Factory = Callable[..., Awaitable[Any]]

BROKER_URL = "amqp://sentinel-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker URL carried by the injected error."""

FEATURE_EVENTS = {
    "ticket_convergence_publication_failed",
    "ticket_convergence_dispatch_failed",
    "post_commit_callback_failed",
}
"""The feature-owned and generic callback events these tests account for."""

_DEFAULT_VERSION = "3.1"
_THRESHOLD = Decimal("9.0")
"""Between the SUSE 4.8 (Medium) and 9.8 (Critical) scores
(cvss-scoring.md, Eligibility Score Resolution)."""

_SUPPORTED = datetime.now(UTC).date() + timedelta(days=365)
"""A General Support end after any evaluation date of the run: in support."""


# ---------------------------------------------------------------------------
# Publication recorder and request-session recorder
# ---------------------------------------------------------------------------


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    on_call: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        if self.on_call is not None:
            await self.on_call(call)
        if self.error is not None:
            raise self.error

    def ticket_ids(self) -> list[tuple[str, str]]:
        return [(c["task_name"], c["kwargs"]["ticket_id"]) for c in self.calls]


@pytest.fixture
def publish(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


class _RequestSessions:
    """Stands in for `app.database.async_session_factory`, recording every
    request session that the real `get_db()` opens."""

    def __init__(self, inner: async_sessionmaker[AsyncSession]) -> None:
        self._inner = inner
        self.sessions: list[AsyncSession] = []

    def __call__(self) -> AsyncSession:
        session = self._inner()
        self.sessions.append(session)
        return session

    def any_in_transaction(self) -> bool:
        return any(session.in_transaction() for session in self.sessions)


def _feature_logs(
    logs: list[MutableMapping[str, Any]],
) -> list[MutableMapping[str, Any]]:
    return [log for log in logs if log["event"] in FEATURE_EVENTS]


def _publication_failed(ticket_id: uuid.UUID) -> dict[str, Any]:
    """The one sanitized automatic publication-failure event: only
    `ticket_id` and the closed cause (the bound request correlation is
    merged by the logging configuration, not by the emitting call)."""
    return {
        "event": "ticket_convergence_publication_failed",
        "log_level": "error",
        "ticket_id": str(ticket_id),
        "cause": "broker_operational_error",
    }


# ---------------------------------------------------------------------------
# Savepoint-joined application (real `get_db`)
# ---------------------------------------------------------------------------


@dataclass
class _Request:
    """One representative mutation that registers a convergence effect."""

    method: str
    url: str
    ticket_id: uuid.UUID
    status_code: int
    """The normal success status of the endpoint."""
    final: TicketStatus
    """The Ticket's persisted status after the mutation."""
    json: dict[str, Any] | None = None


@dataclass
class _Api:
    client: AsyncClient
    actor: User
    db: AsyncSession
    connection: AsyncConnection
    sessions: _RequestSessions

    async def send(self, request: _Request) -> httpx.Response:
        await self.db.commit()
        return await self.client.request(request.method, request.url, json=request.json)

    async def replay(self, request: _Request) -> httpx.Response:
        """Send `request`, then roll its committed effects back to the
        pre-request state so the identical request can run again."""
        await self.db.commit()
        savepoint = await self.connection.begin_nested()
        try:
            return await self.client.request(
                request.method, request.url, json=request.json
            )
        finally:
            await savepoint.rollback()

    async def status(self, ticket_id: uuid.UUID) -> str:
        value: str = (
            await self.db.execute(select(Ticket.status).where(Ticket.id == ticket_id))
        ).scalar_one()
        return value


@pytest_asyncio.fixture
async def api(
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    system_setting_factory: Factory,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[_Api]:
    """A vulnerability-analyst client served by the production `get_db()`
    over sessions joined to `db_session`'s connection (see the module
    docstring). `redis_client` isolates the session liveness cache."""
    assert get_db not in app.dependency_overrides
    await system_setting_factory(key="default_cvss_version", value=_DEFAULT_VERSION)
    actor: User = await user_factory(username="dana.va", email="dana.va@example.test")
    await user_role_factory(user_id=actor.id, role=Role.VULNERABILITY_ANALYST.value)
    created = await create_session(
        db_session,
        actor,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None
    await db_session.commit()
    connection = db_session.bind
    assert isinstance(connection, AsyncConnection)
    sessions = _RequestSessions(
        async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
    )
    monkeypatch.setattr(database, "async_session_factory", sessions)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        headers={"Authorization": f"Bearer {created.token}"},
    ) as client:
        yield _Api(client, actor, db_session, connection, sessions)


@pytest.fixture
def scenarios(
    api: _Api,
    db_session: AsyncSession,
    ticket_factory: Factory,
    cve_factory: Factory,
    product_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
) -> dict[str, Callable[[], Awaitable[_Request]]]:
    """Builders of the representative registering mutations."""

    async def reopen() -> _Request:
        """An `Ignored` CVE-less Ticket without packages: the exit's gate
        result is `Analysis` (tickets.md, Reopen Ticket)."""
        ticket: Ticket = await ticket_factory(status=TicketStatus.IGNORED.value)
        return _Request(
            "POST",
            f"/api/v1/tickets/{locator(ticket)}/reopen",
            ticket.id,
            200,
            TicketStatus.ANALYSIS,
        )

    async def revert() -> _Request:
        target: Ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.DUPLICATED.value, duplicate_of_id=target.id
        )
        return _Request(
            "POST",
            f"/api/v1/tickets/{locator(ticket)}/revert-duplicate",
            ticket.id,
            200,
            TicketStatus.ANALYSIS,
        )

    async def track() -> _Request:
        """A `Resolved` CVE-less `High` Ticket whose only track is
        `not_affected` with one in-support eligible Product; moving the
        track back to `analysis` fails the Analyzed gate (tickets.md,
        Gates): a `Resolved` regression."""
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            severity_manual="High",
            assignee_id=api.actor.id,
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        row = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.NOT_AFFECTED.value
        )
        await ticket_package_product_factory(
            ticket_package_track_id=row.id,
            product_id=(await product_factory(general_support_end_date=_SUPPORTED)).id,
        )
        return _Request(
            "PATCH",
            f"/api/v1/tickets/{locator(ticket)}/packages/{package.id}/tracks/{row.id}",
            ticket.id,
            200,
            TicketStatus.ANALYSIS,
            json={"status": "analysis"},
        )

    async def cvss() -> _Request:
        """A `Resolved` Ticket whose CVE has the SUSE 4.8 assessment and
        whose `fixed` track's only in-support Product (threshold 9.0) is
        ineligible. Updating the assessment to 9.8 makes the Product
        eligible without a release, so resolution is no longer complete:
        a `Resolved` regression to `Analyzed` (cvss-scoring.md; tickets.md,
        Gates). The update keeps the assessment ID, so the 200 response is
        reproducible."""
        cve = await cve_factory(severity="Medium")
        db_session.add(
            CVECVSSAssessment(
                cve_id=cve.id, provider_name="SUSE", **V31_MEDIUM.columns()
            )
        )
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            cve_id=cve.id,
            assignee_id=api.actor.id,
            priority_auto="P4",
        )
        product = await product_factory(
            cvss_threshold=_THRESHOLD, general_support_end_date=_SUPPORTED
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        row = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.FIXED.value
        )
        await ticket_package_product_factory(
            ticket_package_track_id=row.id, product_id=product.id, eligible=False
        )
        return _Request(
            "POST",
            f"/api/v1/cves/{cve.cve_id}/cvss/suse",
            ticket.id,
            200,
            TicketStatus.ANALYZED,
            json={"vector_string": V31_CRITICAL.canonical},
        )

    return {"reopen": reopen, "revert": revert, "track": track, "cvss": cvss}


SCENARIOS = ["reopen", "revert", "track", "cvss"]


# ---------------------------------------------------------------------------
# Publication after commit
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestApiDrainPublication:
    @pytest.mark.parametrize("name", SCENARIOS)
    async def test_registering_mutation_publishes_once_after_commit(
        self,
        api: _Api,
        scenarios: dict[str, Callable[[], Awaitable[_Request]]],
        publish: _Publish,
        name: str,
    ) -> None:
        """The success response is returned, the Ticket's committed status
        is the mutation's result, and exactly one root convergence task is
        published for the internal Ticket UUID, while no request session
        is in a transaction (the request transaction has committed)."""
        request = await scenarios[name]()
        in_transaction: list[bool] = []

        async def _at_publication(call: dict[str, Any]) -> None:
            in_transaction.append(api.sessions.any_in_transaction())

        publish.on_call = _at_publication

        with capture_logs() as logs:
            response = await api.send(request)

        assert response.status_code == request.status_code, response.text
        assert publish.ticket_ids() == [
            ("run_ticket_convergence", str(request.ticket_id))
        ]
        assert set(publish.calls[0]) == {"task_name", "kwargs", "task_id"}
        assert uuid.UUID(publish.calls[0]["task_id"]).version == 7
        assert in_transaction == [False]
        assert await api.status(request.ticket_id) == request.final.value
        assert _feature_logs(logs) == []

    @pytest.mark.parametrize("name", SCENARIOS)
    async def test_broker_operational_error_keeps_the_success_response_identical(
        self,
        api: _Api,
        scenarios: dict[str, Callable[[], Awaitable[_Request]]],
        publish: _Publish,
        name: str,
    ) -> None:
        """The same request from the same state, first with a submitted
        publication, then with `acceptance_unconfirmed`: identical status
        and body bytes, the committed mutation retained, exactly one
        sanitized `ticket_convergence_publication_failed`, and no generic
        `post_commit_callback_failed` (the adapter absorbs the error)."""
        request = await scenarios[name]()

        with capture_logs() as submitted_logs:
            submitted = await api.replay(request)
        publish.error = BrokerOperationalError(f"{BROKER_URL} connection refused")
        with capture_logs(processors=[merge_contextvars]) as failed_logs:
            failed = await api.send(request)

        assert submitted.status_code == request.status_code, submitted.text
        assert (failed.status_code, failed.content) == (
            submitted.status_code,
            submitted.content,
        )
        assert (
            publish.ticket_ids()
            == [("run_ticket_convergence", str(request.ticket_id))] * 2
        )
        assert await api.status(request.ticket_id) == request.final.value
        assert _feature_logs(submitted_logs) == []
        assert _feature_logs(failed_logs) == [
            {
                **_publication_failed(request.ticket_id),
                "request_id": failed.headers["X-Request-ID"],
            }
        ]
        rendered = repr(failed_logs) + failed.text
        for fragment in (
            "fictional-secret",
            "broker.example.test",
            "connection refused",
        ):
            assert fragment not in rendered

    async def test_non_operational_exception_follows_the_generic_callback_contract(
        self,
        api: _Api,
        scenarios: dict[str, Callable[[], Awaitable[_Request]]],
        publish: _Publish,
    ) -> None:
        """A programming error escaping the adapter is not converted into
        `acceptance_unconfirmed`: `get_db()` logs its unchanged generic
        `post_commit_callback_failed`, the committed mutation and its
        success response are unchanged, and no publication-failure event
        is emitted. The drain is route-independent, so one representative
        endpoint suffices (the adapter's propagation is proven in
        `test_ticket_convergence_publication.py`)."""
        request = await scenarios["reopen"]()

        submitted = await api.replay(request)
        publish.error = RuntimeError("fictional programming error")
        with capture_logs() as logs:
            failed = await api.send(request)

        assert submitted.status_code == request.status_code, submitted.text
        assert (failed.status_code, failed.content) == (
            submitted.status_code,
            submitted.content,
        )
        assert len(publish.calls) == 2
        assert await api.status(request.ticket_id) == request.final.value
        assert _feature_logs(logs) == [
            {
                "event": "post_commit_callback_failed",
                "log_level": "error",
                "exc_info": True,
            }
        ]


# ---------------------------------------------------------------------------
# No publication without a committed registration
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestApiDrainWithoutCommittedEffect:
    async def test_rejected_request_publishes_nothing(
        self, api: _Api, ticket_factory: Factory, publish: _Publish
    ) -> None:
        """Reopen of a Ticket that is not `Ignored` fails before any
        registration and rolls back: nothing is published."""
        ticket: Ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value)

        with capture_logs() as logs:
            response = await api.send(
                _Request(
                    "POST",
                    f"/api/v1/tickets/{locator(ticket)}/reopen",
                    ticket.id,
                    409,
                    TicketStatus.ANALYSIS,
                )
            )

        assert response.status_code == 409
        assert publish.calls == []
        assert _feature_logs(logs) == []

    async def test_registered_effect_of_a_rolled_back_request_is_discarded(
        self,
        api: _Api,
        scenarios: dict[str, Callable[[], Awaitable[_Request]]],
        publish: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The reopen registers its effect, then the handler's final
        assembly fails: `get_db()` rolls back, runs no callback, and the
        effect is never published."""
        request = await scenarios["reopen"]()
        registered: list[bool] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> Any:
            registered.append(True)
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        with capture_logs() as logs:
            response = await api.send(request)

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert registered == [True]
        assert publish.calls == []
        assert _feature_logs(logs) == []
        assert await api.status(request.ticket_id) == TicketStatus.IGNORED.value

    async def test_request_without_registration_publishes_nothing(
        self, api: _Api, ticket_factory: Factory, publish: _Publish
    ) -> None:
        ticket: Ticket = await ticket_factory(status=TicketStatus.RESOLVED.value)

        response = await api.send(
            _Request(
                "GET",
                f"/api/v1/tickets/{locator(ticket)}",
                ticket.id,
                200,
                TicketStatus.RESOLVED,
            )
        )

        assert response.status_code == 200
        assert publish.calls == []


# ---------------------------------------------------------------------------
# Commit and lock release precede the attempt (independent connections)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def committed(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient, _RequestSessions]]:
    """Committed rows (deleted explicitly) and a client served by the
    production `get_db()` over pooled sessions of the test engine."""
    assert get_db not in app.dependency_overrides
    world = CommittedApp(db_session_factory)
    owns_setting = False
    sessions = _RequestSessions(real_session_factory)
    monkeypatch.setattr(database, "async_session_factory", sessions)
    try:
        db = await world.session()
        if await db.get(SystemSetting, "default_cvss_version") is None:
            db.add(SystemSetting(key="default_cvss_version", value=_DEFAULT_VERSION))
            owns_setting = True
        await db.commit()
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            yield world, client, sessions
    finally:
        await world.cleanup()
        if owns_setting:
            db = await world.session()
            await db.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await db.commit()


@pytest.mark.e2e
class TestApiDrainOrdering:
    async def test_reopen_publishes_after_commit_and_ticket_lock_release(
        self,
        committed: tuple[CommittedApp, AsyncClient, _RequestSessions],
        publish: _Publish,
    ) -> None:
        """Inside the publisher an independent connection acquires the
        Ticket lock `NOWAIT` and observes the committed reopen result,
        while the request session is no longer in a transaction."""
        world, client, sessions = committed
        _, headers = await world.va_headers()
        ticket = await world.ticket(status=TicketStatus.IGNORED.value)
        probe = await world.session()
        observed: list[tuple[str, bool]] = []

        async def _at_publication(call: dict[str, Any]) -> None:
            status: str = (
                await probe.execute(
                    select(Ticket.status)
                    .where(Ticket.id == ticket.id)
                    .with_for_update(nowait=True)
                )
            ).scalar_one()
            await probe.rollback()
            observed.append((status, sessions.any_in_transaction()))

        publish.on_call = _at_publication

        response = await client.post(
            f"/api/v1/tickets/{locator(ticket)}/reopen", headers=headers
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["status"] == "analysis"
        assert publish.ticket_ids() == [("run_ticket_convergence", str(ticket.id))]
        assert observed == [(TicketStatus.ANALYSIS.value, False)]
        assert sessions.sessions
