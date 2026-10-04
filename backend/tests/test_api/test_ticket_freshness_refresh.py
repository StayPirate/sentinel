"""End-to-end tests for the automatic CVE freshness refresh of manual Ticket
creation with a CVE (`POST /api/v1/tickets`) and CVE association
(`POST /api/v1/tickets/{ticket_id}/associate-cve`), through the production
`app.database.get_db()`.

Owning specifications:

- docs/features/tickets/ticket-service.md (`create_ticket` step 11,
  Post-commit freshness, Audit events; `associate_cve` step 14 and the
  no-eligible-source and best-effort paragraphs; Architectural Test
  Requirements 13 and 19);
- docs/features/tickets/cve-service.md (Fetch Orchestration: Transactional
  Preparation, Database-Free Publication, Callers and Ordering);
- docs/features/tickets/tickets.md (Create Ticket; Associate CVE; CVE
  Resolution Behavior);
- docs/conventions.md (Transaction Hygiene Rules: no network I/O before
  commit or under a lock);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Audit
  Trail Testing);
- issue #800 decision D4 (`cve_fetch_no_eligible_source` INFO with `cve_id`
  and `trigger`; `cve_fetch_publication_unconfirmed` WARNING with `cve_id`,
  `sources_failed`, and `trigger`).

The requests run through the real `get_db()` (its commit, rollback, and
post-commit callback loop): `app.database.async_session_factory` is
replaced by a `RecordingSessions` whose sessions join the per-test
`db_session` connection with `join_transaction_mode="create_savepoint"`, so
every request commit is a savepoint release inside the outer test
transaction, rolled back at teardown; request commits, rollbacks, and
publications share one ordered event list. A connection-level savepoint
around a first request lets the identical request run again from the
identical state, so success responses with and without a publication
failure are compared. One representative test (associate) instead commits
for real on independent connections to prove that commit and CVE/Ticket
lock release precede publication.

Every test empties both fetcher registries under
`isolated_fetcher_registries` and defines its own test-only CVE fetchers.
The broker is never reached (`task_publication.publish_task` is a recorder)
and the pending-marker client is `ScriptedRedis` or forbidden. The
service-level preparation matrix lives in
`tests/test_services/test_cve_freshness_preparation.py` and
`tests/test_services/test_ticket_freshness_composition.py`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app import database
from app.core.enums import CVESourceType, Role, SessionCreationReason, TicketStatus
from app.core.identifiers import format_ticket_id
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import task_publication
from app.services.session_service import create_session
from tests.support.cve_catch_up import (
    Publications,
    RecordingSessions,
    define_cve_fetcher,
)
from tests.support.cve_ingest import lock_not_available
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.fetch_single_cve import (
    MARKER_UNAVAILABLE,
    TASK,
    ScriptedRedis,
    assert_private_logs,
    events_named,
    fictional_cve_id,
    forbid_redis,
    pending_key,
)
from tests.support.ticket_api import (
    INTERNAL_ERROR,
    CommittedApp,
    force_production_error_page,
)
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import EventRow, status_event, ticket_events_by_id

Factory = Callable[..., Awaitable[Any]]

NO_ELIGIBLE = "cve_fetch_no_eligible_source"
UNCONFIRMED = "cve_fetch_publication_unconfirmed"
CALLBACK_FAILED = "post_commit_callback_failed"

SECRET = "amqp://fresh-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker detail carried by injected errors."""

DEFAULT_VERSION = "3.1"

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
GHSA = CVESourceType.GHSA
KEV = CVESourceType.KEV

OPERATIONS = ["create", "associate"]
TRIGGERS = {"create": "ticket_create", "associate": "cve_associate"}
"""The `trigger` log value of each workflow (issue #800, D4)."""


@pytest.fixture(autouse=True)
def _exact_registry(isolated_fetcher_registries: None) -> None:
    """Both registries empty; `isolated_fetcher_registries` restores them."""
    clear_fetcher_registries()


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> Publications:
    recorder = Publications()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


def _lifecycle(events: list[str]) -> list[str]:
    """The request-transaction outcomes and publications, in order (the
    recorded explicit flushes are irrelevant here)."""
    return [
        e for e in events if e in ("commit", "rollback") or e.startswith("publish:")
    ]


def _assoc_events(actor: User, cve_id: str) -> list[EventRow]:
    """An active VA's association of a CVE without assessments to an
    unassigned, severity-less `New` Ticket: auto-assignment and its
    promotion precede `cve_associated`; no severity or priority change
    (ticket-service.md, `associate_cve` Audit events)."""
    return [
        EventRow("assignment", actor.id, None, actor.username, None, None),
        status_event("New", "Analysis"),
        EventRow("cve_associated", actor.id, None, cve_id, None, None),
    ]


# ---------------------------------------------------------------------------
# Savepoint-joined application (real `get_db`)
# ---------------------------------------------------------------------------


@dataclass
class _Operation:
    """One prepared create-with-CVE or associate request."""

    name: str
    cve_id: str
    method_url: str
    expected_status: int
    ticket_id: uuid.UUID | None = None
    """The associated Ticket (known before the request) for `associate`."""


@dataclass
class _Api:
    client: AsyncClient
    actor: User
    db: AsyncSession
    connection: AsyncConnection
    sessions: RecordingSessions
    events: list[str]

    async def fetcher(
        self,
        source: CVESourceType,
        *,
        enabled: bool | None = True,
        refetchable: bool = True,
        queue: str | None = None,
    ) -> str:
        """Register a test-only CVE fetcher owning `source` and flush its
        `FetcherConfig`; `enabled=None` creates no configuration row."""
        probe = define_cve_fetcher(
            source=source, supports=refetchable, fetcher_queue=queue
        )
        if enabled is not None:
            self.db.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
            await self.db.flush()
        return probe.name

    async def prepare(self, name: str) -> _Operation:
        """A new CVE-ID (a placeholder is created) and, for `associate`, an
        unassigned severity-less CVE-less `New` Ticket."""
        cve_id = fictional_cve_id()
        if name == "create":
            return _Operation(name, cve_id, "/api/v1/tickets", 201)
        ticket = Ticket(status=TicketStatus.NEW.value)
        self.db.add(ticket)
        await self.db.flush()
        return _Operation(
            name,
            cve_id,
            f"/api/v1/tickets/{format_ticket_id(ticket.sequence_id)}/associate-cve",
            200,
            ticket.id,
        )

    async def _post(self, operation: _Operation) -> httpx.Response:
        return await self.client.post(
            operation.method_url, json={"cve_id": operation.cve_id}
        )

    async def send(self, operation: _Operation) -> httpx.Response:
        await self.db.commit()
        self.events.clear()
        return await self._post(operation)

    async def replay(self, operation: _Operation) -> httpx.Response:
        """Send the request, then roll its committed effects back to the
        pre-request state so the identical request can run again."""
        await self.db.commit()
        savepoint = await self.connection.begin_nested()
        try:
            return await self._post(operation)
        finally:
            await savepoint.rollback()
            self.events.clear()

    async def ticket_uuid(
        self, operation: _Operation, response: httpx.Response
    ) -> uuid.UUID:
        if operation.ticket_id is not None:
            return operation.ticket_id
        sequence = int(response.json()["data"]["ticket_id"].removeprefix("SNTL-"))
        value: uuid.UUID = (
            await self.db.execute(
                select(Ticket.id).where(Ticket.sequence_id == sequence)
            )
        ).scalar_one()
        return value

    def expected_events(self, operation: _Operation) -> list[EventRow]:
        if operation.name == "create":
            return creation_events(
                creator_id=self.actor.id,
                assignee_username=self.actor.username,
                cve_id=operation.cve_id,
            )
        return _assoc_events(self.actor, operation.cve_id)

    async def counts(self) -> tuple[int, int, int]:
        """`(tickets, cves, ticket audit events)` visible to the test."""
        row = (
            await self.db.execute(
                select(
                    select(func.count()).select_from(Ticket).scalar_subquery(),
                    select(func.count()).select_from(CVE).scalar_subquery(),
                    select(func.count())
                    .select_from(TicketAuditEvent)
                    .scalar_subquery(),
                )
            )
        ).one()
        return (row[0], row[1], row[2])

    def any_in_transaction(self) -> bool:
        return any(session.in_transaction() for session in self.sessions.opened)


@pytest_asyncio.fixture
async def api(
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    system_setting_factory: Factory,
    redis_client: redis_asyncio.Redis,
    published: Publications,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[_Api]:
    """A vulnerability-analyst client served by the production `get_db()`
    over recorded sessions joined to `db_session`'s connection (see the
    module docstring). `redis_client` isolates the session liveness
    cache."""
    assert get_db not in app.dependency_overrides
    await system_setting_factory(key="default_cvss_version", value=DEFAULT_VERSION)
    actor: User = await user_factory(username="frank.va", email="frank.va@example.test")
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
    events: list[str] = []
    sessions = RecordingSessions(
        async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
        events,
    )
    monkeypatch.setattr(database, "async_session_factory", sessions)
    published.events = events
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        headers={"Authorization": f"Bearer {created.token}"},
    ) as client:
        yield _Api(client, actor, db_session, connection, sessions, events)


# ---------------------------------------------------------------------------
# B1: registration and publication strictly after the commit
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestPublicationAfterCommit:
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_each_enabled_source_is_published_only_after_the_commit(
        self,
        api: _Api,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
    ) -> None:
        """The ordinary `201`/`200` response; the request commits first, then
        the registered effect publishes `fetch_single_cve` for every enabled
        refetchable source (queue preserved, `None` omitted) with the
        canonical CVE-ID, while no request session is in a transaction; a
        disabled and a non-refetchable source are not published
        (cve-service.md, Callers and Ordering; ticket-service.md,
        `create_ticket` step 11 / `associate_cve` step 14)."""
        nvd = await api.fetcher(NVD)
        mitre = await api.fetcher(MITRE, queue="git")
        await api.fetcher(GHSA, enabled=False)
        await api.fetcher(KEV, refetchable=False)
        operation = await api.prepare(name)
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        in_transaction: list[bool] = []

        async def _at_publication(call: dict[str, Any]) -> None:
            in_transaction.append(api.any_in_transaction())

        published.before = _at_publication

        with capture_logs() as logs:
            response = await api.send(operation)

        assert response.status_code == operation.expected_status, response.text
        assert response.json()["data"]["cve"]["cve_id"] == operation.cve_id
        assert _lifecycle(api.events) == [
            "commit",
            f"publish:{TASK}",
            f"publish:{TASK}",
        ]
        mitre_token, nvd_token = redis.values("set")
        assert published.calls == [
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": mitre,
                    "cve_id": operation.cve_id,
                    "source": "mitre",
                    "token": mitre_token,
                },
                "queue": "git",
            },
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": nvd,
                    "cve_id": operation.cve_id,
                    "source": "nvd",
                    "token": nvd_token,
                },
                "queue": None,
            },
        ]
        assert in_transaction == [False, False]
        ticket_id = await api.ticket_uuid(operation, response)
        assert await ticket_events_by_id(api.db, ticket_id) == api.expected_events(
            operation
        )
        assert events_named(logs, NO_ELIGIBLE) == []
        assert events_named(logs, UNCONFIRMED) == []
        assert events_named(logs, CALLBACK_FAILED) == []


# ---------------------------------------------------------------------------
# B3: publication failure after commit is best effort
# ---------------------------------------------------------------------------


def _masked(operation: _Operation, response: httpx.Response) -> Any:
    """The response body; a creation's `ticket_id` comes from a
    non-transactional sequence and differs between the two runs."""
    body = response.json()
    if operation.name == "create":
        body["data"]["ticket_id"] = "SNTL-masked"
    return body


@pytest.mark.e2e
class TestPublicationFailureIsBestEffort:
    @pytest.mark.parametrize("failure", ["broker", "redis-set"])
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_failure_keeps_the_ordinary_response_and_committed_events(
        self,
        api: _Api,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        failure: str,
    ) -> None:
        """The same request from the same state, first with a confirmed
        publication, then failing: the identical status and body, and the
        committed audit events. A raising publication is logged once as the
        sanitized `cve_fetch_publication_unconfirmed` WARNING
        (ticket-service.md, Post-commit freshness; `associate_cve`
        best-effort paragraph); Redis unavailable at the marker `SET` fails
        open and still publishes (cve-service.md, Database-Free
        Publication)."""
        await api.fetcher(NVD)
        operation = await api.prepare(name)
        ScriptedRedis().install(monkeypatch)
        baseline = await api.replay(operation)
        published.calls.clear()
        if failure == "broker":
            published.errors[TASK] = BrokerOperationalError(f"refused {SECRET}")
            redis = ScriptedRedis()
        else:
            redis = ScriptedRedis(
                set_results={
                    pending_key(operation.cve_id, "nvd"): RedisConnectionError(SECRET)
                }
            )
        redis.install(monkeypatch)

        with capture_logs() as logs:
            response = await api.send(operation)

        assert baseline.status_code == operation.expected_status, baseline.text
        assert response.status_code == baseline.status_code
        assert _masked(operation, response) == _masked(operation, baseline)
        assert SECRET not in response.text
        assert _lifecycle(api.events) == ["commit", f"publish:{TASK}"]
        assert [c["kwargs"]["source"] for c in published.calls] == ["nvd"]
        ticket_id = await api.ticket_uuid(operation, response)
        assert await ticket_events_by_id(api.db, ticket_id) == api.expected_events(
            operation
        )
        unconfirmed = events_named(logs, UNCONFIRMED)
        marker = events_named(logs, MARKER_UNAVAILABLE)
        if failure == "broker":
            assert unconfirmed == [
                {
                    "event": UNCONFIRMED,
                    "log_level": "warning",
                    "cve_id": operation.cve_id,
                    "sources_failed": ["nvd"],
                    "trigger": TRIGGERS[name],
                }
            ]
            assert marker == []
        else:
            assert unconfirmed == []
            assert [entry["log_level"] for entry in marker] == ["warning"]
        tokens = [str(token) for token in redis.values("set")]
        assert_private_logs(
            [*unconfirmed, *marker], *tokens, "fictional-secret", "amqp", "refused"
        )
        assert events_named(logs, CALLBACK_FAILED) == []


# ---------------------------------------------------------------------------
# B4: no eligible source keeps the ordinary mutation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNoEligibleSource:
    @pytest.mark.parametrize("roster", ["empty", "all-disabled"])
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_no_eligible_source_commits_with_one_info_and_no_io(
        self,
        api: _Api,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        roster: str,
    ) -> None:
        """An empty fetch-single registry or an all-disabled roster is the
        expected no-eligible-source outcome: the ordinary `201`/`200`, the
        committed audit events, exactly one `cve_fetch_no_eligible_source`
        INFO, and zero Redis and Celery I/O (ticket-service.md, Post-commit
        freshness; `associate_cve` no-eligible-source paragraph)."""
        if roster == "all-disabled":
            await api.fetcher(NVD, enabled=False)
            await api.fetcher(GHSA, enabled=False)
            await api.fetcher(KEV, refetchable=False)
        operation = await api.prepare(name)
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs:
            response = await api.send(operation)

        assert response.status_code == operation.expected_status, response.text
        assert response.json()["data"]["cve"]["cve_id"] == operation.cve_id
        assert _lifecycle(api.events) == ["commit"]
        ticket_id = await api.ticket_uuid(operation, response)
        assert await ticket_events_by_id(api.db, ticket_id) == api.expected_events(
            operation
        )
        infos = events_named(logs, NO_ELIGIBLE)
        assert infos == [
            {
                "event": NO_ELIGIBLE,
                "log_level": "info",
                "cve_id": operation.cve_id,
                "trigger": TRIGGERS[name],
            }
        ]
        assert_private_logs(infos)
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# B5: a bootstrap invariant failure rolls the mutation back
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestBootstrapInvariantFailure:
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_missing_configuration_row_rolls_back_to_the_generic_500(
        self,
        api: _Api,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
    ) -> None:
        """A registered refetchable fetcher without its `FetcherConfig` row
        is a bootstrap invariant failure: it escapes, `get_db()` rolls back
        the Ticket, the placeholder CVE, the association, and every audit
        event, and nothing is published (ticket-service.md, Post-commit
        freshness: unexpected bootstrap-invariant errors roll back)."""
        await api.fetcher(NVD, enabled=None)
        await api.fetcher(GHSA)
        operation = await api.prepare(name)
        force_production_error_page(monkeypatch)
        attempts = forbid_redis(monkeypatch)
        before = await api.counts()

        response = await api.send(operation)

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert _lifecycle(api.events) == ["rollback"]
        assert await api.counts() == before
        assert (
            await api.db.scalar(select(CVE.id).where(CVE.cve_id == operation.cve_id))
            is None
        )
        if operation.ticket_id is not None:
            ticket = (
                await api.db.execute(
                    select(Ticket.status, Ticket.assignee_id, Ticket.cve_id).where(
                        Ticket.id == operation.ticket_id
                    )
                )
            ).one()
            assert tuple(ticket) == (TicketStatus.NEW.value, None, None)
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# B2: commit and CVE/Ticket lock release precede publication (committed)
# ---------------------------------------------------------------------------


class _CommittedWorld(CommittedApp):
    """`CommittedApp` that also owns committed CVE, `FetcherConfig`, and
    `default_cvss_version` rows, deleted explicitly by `cleanup()`."""

    def __init__(self, factory: Callable[[], Awaitable[AsyncSession]]) -> None:
        super().__init__(factory)
        self.cve_ids: list[uuid.UUID] = []
        self.fetcher_names: list[str] = []
        self.owns_setting = False

    async def ensure_default_setting(self) -> None:
        db = await self.session()
        if await db.get(SystemSetting, "default_cvss_version") is None:
            db.add(SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION))
            self.owns_setting = True
        await db.commit()

    async def cve(self) -> CVE:
        db = await self.session()
        cve = CVE(cve_id=fictional_cve_id())
        db.add(cve)
        await db.flush()
        self.cve_ids.append(cve.id)
        await db.commit()
        return cve

    async def fetcher(self, source: CVESourceType) -> str:
        probe = define_cve_fetcher(source=source)
        db = await self.session()
        db.add(FetcherConfig(fetcher_name=probe.name, enabled=True))
        self.fetcher_names.append(probe.name)
        await db.commit()
        return probe.name

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
        finally:
            db = await self.session()
            await db.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
            await db.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name.in_(self.fetcher_names)
                )
            )
            if self.owns_setting:
                await db.execute(
                    delete(SystemSetting).where(
                        SystemSetting.key == "default_cvss_version"
                    )
                )
            await db.commit()


@pytest_asyncio.fixture
async def committed(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[_CommittedWorld, AsyncClient, RecordingSessions]]:
    """Committed rows (deleted explicitly) and a client served by the
    production `get_db()` over pooled sessions of the test engine."""
    assert get_db not in app.dependency_overrides
    world = _CommittedWorld(db_session_factory)
    sessions = RecordingSessions(real_session_factory)
    monkeypatch.setattr(database, "async_session_factory", sessions)
    try:
        await world.ensure_default_setting()
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            yield world, client, sessions
    finally:
        await world.cleanup()


@pytest.mark.e2e
class TestCommittedLockRelease:
    async def test_association_publishes_after_commit_and_root_lock_release(
        self,
        committed: tuple[_CommittedWorld, AsyncClient, RecordingSessions],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Inside the publisher an independent connection takes the CVE
        `FOR NO KEY UPDATE NOWAIT` and the Ticket `FOR UPDATE NOWAIT` and
        observes the committed association, while no request session is in
        a transaction (cve-service.md, Callers and Ordering: no Redis or
        Celery I/O while the CVE or Ticket lock is held)."""
        world, client, sessions = committed
        actor, headers = await world.va_headers()
        nvd = await world.fetcher(NVD)
        cve = await world.cve()
        ticket = await world.ticket(status=TicketStatus.NEW.value)
        probe = await world.session()
        ScriptedRedis().install(monkeypatch)
        observed: list[tuple[bool, bool, uuid.UUID | None, bool]] = []

        async def _at_publication(call: dict[str, Any]) -> None:
            cve_locked = await lock_not_available(
                probe,
                select(CVE.id)
                .where(CVE.id == cve.id)
                .with_for_update(key_share=True, nowait=True),
            )
            ticket_locked = await lock_not_available(
                probe,
                select(Ticket.id)
                .where(Ticket.id == ticket.id)
                .with_for_update(nowait=True),
            )
            associated = await probe.scalar(
                select(Ticket.cve_id).where(Ticket.id == ticket.id)
            )
            await probe.rollback()
            observed.append(
                (
                    cve_locked,
                    ticket_locked,
                    associated,
                    any(s.in_transaction() for s in sessions.opened),
                )
            )

        published.before = _at_publication

        response = await client.post(
            f"/api/v1/tickets/{format_ticket_id(ticket.sequence_id)}/associate-cve",
            json={"cve_id": cve.cve_id},
            headers=headers,
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["cve"]["cve_id"] == cve.cve_id
        assert [
            (c["kwargs"]["fetcher_name"], c["kwargs"]["source"])
            for c in published.calls
        ] == [(nvd, "nvd")]
        assert observed == [(False, False, cve.id, False)]
        assert sessions.opened
        events = await ticket_events_by_id(probe, ticket.id)
        await probe.rollback()
        assert events == _assoc_events(actor, cve.cve_id)
