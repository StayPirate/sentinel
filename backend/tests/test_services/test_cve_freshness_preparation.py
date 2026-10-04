"""Tests for the automatic freshness preparation
`cve_service.prepare_freshness_refresh()` and the mode guards of the shared
preparation boundary `cve_service._prepare_on_demand_fetch()`
(backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (Fetch Orchestration:
  `trigger_on_demand_fetch()` — Transactional Preparation, Database-Free
  Publication, `FetchDispatchResult`, Callers and Ordering; Exceptions;
  Transaction Ownership);
- docs/features/tickets/ticket-audit-log.md (CVE refetch preparation and
  publication create no audit event);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Redis
  Strategy);
- issue #800 decision D4 (`cve_fetch_no_eligible_source` INFO with
  `cve_id` and `trigger`; `cve_fetch_publication_unconfirmed` WARNING with
  `cve_id`, `sources_failed`, and `trigger`).

The preparation runs inside a caller-owned transaction: each test plays the
`create_ticket()` / `associate_cve()` caller on `db_session`, locking the CVE
`FOR NO KEY UPDATE` and then the Ticket `FOR UPDATE` (or inserting the
Ticket) before calling it, so the preparation's re-locks are
same-transaction no-ops. The post-commit ordering tests drive the real
`app.database.get_db()` over a session joined to the `db_session`
connection. Every test empties both fetcher registries under
`isolated_fetcher_registries` and defines its own test-only CVE fetchers.
The broker is never reached (`task_publication.publish_task` is a
recorder) and Redis is `ScriptedRedis` behind `_new_redis_client`. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app import database
from app.core.enums import CVESourceType, Scope
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import cve_service, task_publication
from app.services.cve_service import (
    CVEIdFormatError,
    FetchDispatchResult,
    OnDemandFetchTrigger,
    _PreparationMode,
    _prepare_on_demand_fetch,
    prepare_freshness_refresh,
)
from app.services.fetcher_execution import FetcherConfigMissingError
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_catch_up import (
    Publications,
    RecordingSessions,
    define_cve_fetcher,
)
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.fetch_single_cve import (
    TASK,
    NoDatabaseAccess,
    ScriptedRedis,
    assert_private_logs,
    events_named,
    fictional_cve_id,
    forbid_redis,
)
from tests.support.ticket_mutations import StatementRecorder

NO_ELIGIBLE = "cve_fetch_no_eligible_source"
UNCONFIRMED = "cve_fetch_publication_unconfirmed"
"""The two preparation/publication events (issue #800, D4)."""

POST_COMMIT_CALLBACKS = "post_commit_callbacks"
"""The `AsyncSession.info` key of registered post-commit callbacks."""

SECRET = "amqp://fresh-user:fictional-secret@broker.example.test:5672//"

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
GHSA = CVESourceType.GHSA
OSV = CVESourceType.OSV
KEV = CVESourceType.KEV

Callback = Callable[[], Awaitable[None]]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _exact_registry(isolated_fetcher_registries: None) -> None:
    """Both registries empty; `isolated_fetcher_registries` restores them."""
    clear_fetcher_registries()


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> Publications:
    recorder = Publications()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


class _DispatchSpy:
    """Records every `FetchDispatchResult` the real
    `trigger_on_demand_fetch()` returns to the registered effect."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.results: list[FetchDispatchResult] = []
        real = cve_service.trigger_on_demand_fetch

        async def spy(
            cve_id: str,
            dispatch_sources: Sequence[tuple[str, str, str | None]],
            disabled_sources: Sequence[str] = (),
        ) -> FetchDispatchResult:
            result = await real(cve_id, dispatch_sources, disabled_sources)
            self.results.append(result)
            return result

        monkeypatch.setattr(cve_service, "trigger_on_demand_fetch", spy)


async def _fetcher(
    db: AsyncSession,
    source: CVESourceType,
    *,
    enabled: bool | None = True,
    refetchable: bool = True,
    queue: str | None = None,
) -> str:
    """Register a test-only CVE fetcher owning `source` and flush its
    `FetcherConfig`; `enabled=None` creates no configuration row."""
    probe = define_cve_fetcher(source=source, supports=refetchable, fetcher_queue=queue)
    if enabled is not None:
        db.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
        await db.flush()
    return probe.name


async def _held_roots(
    db: AsyncSession, *, confidential: bool = False, fresh: bool = False
) -> tuple[CVE, Ticket]:
    """Play the create/associate caller: the CVE root is locked
    `FOR NO KEY UPDATE`, then its Ticket is either inserted in the same
    transaction (`fresh`, as `create_ticket()`) or an existing one is locked
    `FOR UPDATE` (as `associate_cve()`)."""
    cve = CVE(cve_id=fictional_cve_id())
    db.add(cve)
    await db.flush()
    if not fresh:
        ticket = Ticket(status="Analysis", cve_id=cve.id, is_confidential=confidential)
        db.add(ticket)
        await db.flush()
    await db.execute(
        select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
    )
    if fresh:
        ticket = Ticket(status="New", cve_id=cve.id, is_confidential=confidential)
        db.add(ticket)
        await db.flush()
    else:
        await db.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )
    return cve, ticket


def _callbacks(db: AsyncSession) -> list[Callback]:
    callbacks: list[Callback] = db.info.get(POST_COMMIT_CALLBACKS, [])
    return callbacks


async def _ticket_event_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count(TicketAuditEvent.id))) or 0)


def _writes(statements: Sequence[str]) -> list[str]:
    """Every data-changing statement (savepoint bookkeeping excluded)."""
    return [
        s
        for s in statements
        if s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGuards:
    async def test_refetch_trigger_is_rejected_before_any_io(
        self, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refetch trigger belongs to `refetch_cve()`; the automatic
        entry point rejects it as a caller violation (cve-service.md,
        Callers and Ordering)."""
        attempts = forbid_redis(monkeypatch)
        db = MagicMock(spec=AsyncSession)

        with NoDatabaseAccess() as observed, pytest.raises(ValueError, match="refetch"):
            await prepare_freshness_refresh(
                db, cve_id="CVE-2099-0001", trigger=OnDemandFetchTrigger.REFETCH
            )

        assert observed.statements == []
        assert db.method_calls == []
        assert attempts() == 0
        assert published.calls == []

    @pytest.mark.parametrize(
        "cve_id",
        [
            pytest.param("cve-2099-0001", id="lowercase"),
            pytest.param("CVE-2099-" + "1" * 12, id="overlength-21"),
        ],
    )
    async def test_malformed_cve_id_raises_format_error_before_database_work(
        self, cve_id: str, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Transactional Preparation step 1: the input-only CVE-ID format
        guard precedes database work and raises `CVEIdFormatError`."""
        attempts = forbid_redis(monkeypatch)
        db = MagicMock(spec=AsyncSession)

        with NoDatabaseAccess() as observed, pytest.raises(CVEIdFormatError):
            await prepare_freshness_refresh(
                db, cve_id=cve_id, trigger=OnDemandFetchTrigger.CVE_ASSOCIATE
            )

        assert observed.statements == []
        assert db.method_calls == []
        assert attempts() == 0
        assert published.calls == []

    @pytest.mark.parametrize(
        ("mode", "caller", "source", "reason"),
        [
            pytest.param(
                _PreparationMode.CONSUMER, None, None, "caller", id="consumer-no-caller"
            ),
            pytest.param(
                _PreparationMode.AUTOMATIC,
                TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
                None,
                "caller",
                id="automatic-with-caller",
            ),
            pytest.param(
                _PreparationMode.AUTOMATIC,
                None,
                "nvd",
                "broadcast",
                id="automatic-source",
            ),
        ],
    )
    async def test_preparation_mode_mismatch_raises_value_error(
        self,
        mode: _PreparationMode,
        caller: TicketCaller | None,
        source: str | None,
        reason: str,
    ) -> None:
        """The mode is explicit: consumer preparation requires a caller,
        automatic preparation has none and always broadcasts (cve-service.md,
        Transactional Preparation step 3; issue #800, D2)."""
        db = MagicMock(spec=AsyncSession)

        with NoDatabaseAccess() as observed, pytest.raises(ValueError, match=reason):
            await _prepare_on_demand_fetch(
                db, "CVE-2099-0001", mode=mode, source=source, caller=caller
            )

        assert observed.statements == []
        assert db.method_calls == []


# ---------------------------------------------------------------------------
# No eligible source
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoEligibleSource:
    @pytest.mark.parametrize("roster", ["empty-registry", "all-disabled"])
    async def test_no_eligible_source_logs_once_and_registers_nothing(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        roster: str,
    ) -> None:
        """An empty fetch-single registry or an all-disabled broadcast is
        logged once as INFO and registers no publication; the Ticket
        mutation continues (cve-service.md, Transactional Preparation step
        5; issue #800, D4)."""
        if roster == "all-disabled":
            await _fetcher(db_session, NVD, enabled=False)
            await _fetcher(db_session, GHSA, enabled=False)
            await _fetcher(db_session, KEV, refetchable=False)
        cve, _ticket = await _held_roots(db_session)
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs:
            await prepare_freshness_refresh(
                db_session,
                cve_id=cve.cve_id,
                trigger=OnDemandFetchTrigger.CVE_ASSOCIATE,
            )

        infos = events_named(logs, NO_ELIGIBLE)
        assert infos == [
            {
                "event": NO_ELIGIBLE,
                "log_level": "info",
                "cve_id": cve.cve_id,
                "trigger": "cve_associate",
            }
        ]
        assert_private_logs(infos)
        assert _callbacks(db_session) == []
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# Eligible roster: registration and the post-commit effect
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRegisteredEffect:
    @pytest.mark.parametrize("fresh", [False, True], ids=["existing", "fresh-ticket"])
    async def test_eligible_roster_registers_one_effect_publishing_enabled_sources(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        fresh: bool,
    ) -> None:
        """Exactly one database-free effect is registered, with no Redis or
        Celery I/O, no write, and no audit event before it runs; invoked
        after commit it publishes exactly the enabled refetchable sources
        for the canonical CVE-ID and reports the disabled ones
        (cve-service.md, Transactional Preparation steps 5-7; Database-Free
        Publication; ticket-audit-log.md)."""
        nvd = await _fetcher(db_session, NVD)
        mitre = await _fetcher(db_session, MITRE, queue="git")
        await _fetcher(db_session, GHSA, enabled=False)
        await _fetcher(db_session, KEV, refetchable=False)
        cve, _ticket = await _held_roots(db_session, fresh=fresh)
        events_before = await _ticket_event_count(db_session)
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs, StatementRecorder(db_session) as recorder:
            await prepare_freshness_refresh(
                db_session,
                cve_id=cve.cve_id,
                trigger=OnDemandFetchTrigger.TICKET_CREATE,
            )

        [effect] = _callbacks(db_session)
        assert events_named(logs, NO_ELIGIBLE) == []
        assert events_named(logs, UNCONFIRMED) == []
        assert attempts() == 0
        assert published.calls == []
        assert _writes(recorder.statements) == []
        assert await _ticket_event_count(db_session) == events_before == 0

        await db_session.commit()
        client = ScriptedRedis()
        client.install(monkeypatch)
        spy = _DispatchSpy(monkeypatch)
        await effect()

        assert spy.results == [
            FetchDispatchResult(
                sources_enqueued=["mitre", "nvd"],
                sources_already_pending=[],
                sources_disabled=["ghsa"],
                sources_failed=[],
            )
        ]
        tokens = client.values("set")
        assert published.calls == [
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": mitre,
                    "cve_id": cve.cve_id,
                    "source": "mitre",
                    "token": tokens[0],
                },
                "queue": "git",
            },
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": nvd,
                    "cve_id": cve.cve_id,
                    "source": "nvd",
                    "token": tokens[1],
                },
                "queue": None,
            },
        ]

    async def test_publication_failure_in_effect_logs_once_and_does_not_raise(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After commit publication is best effort: an unconfirmed
        publication is logged once with the calling workflow's `trigger`
        and the effect returns normally (cve-service.md, Callers and
        Ordering; issue #800, D4)."""
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, OSV)
        cve, _ticket = await _held_roots(db_session)
        await prepare_freshness_refresh(
            db_session, cve_id=cve.cve_id, trigger=OnDemandFetchTrigger.TICKET_CREATE
        )
        [effect] = _callbacks(db_session)
        await db_session.commit()
        ScriptedRedis().install(monkeypatch)

        async def _fail_nvd(call_options: dict[str, Any]) -> None:
            if call_options["kwargs"]["source"] == "nvd":
                raise RuntimeError(f"fictional refusal {SECRET}")

        published.before = _fail_nvd

        with capture_logs() as logs:
            await effect()  # returns normally: the failure is not raised

        assert [k["source"] for k in published.published(TASK)] == ["nvd", "osv"]
        warnings = events_named(logs, UNCONFIRMED)
        assert warnings == [
            {
                "event": UNCONFIRMED,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "sources_failed": ["nvd"],
                "trigger": "ticket_create",
            }
        ]
        assert "fictional-secret" not in repr(logs)
        assert_private_logs(warnings, "fictional-secret")

    async def test_confidential_ticket_registers_without_accessibility_evaluation(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The automatic callers already made their own locked-current
        decision (or created the Ticket); the preparation has no caller and
        does not evaluate accessibility, so a confidential Ticket still
        registers (cve-service.md, Transactional Preparation step 3)."""
        await _fetcher(db_session, NVD)
        cve, _ticket = await _held_roots(db_session, confidential=True)
        forbid_redis(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            await prepare_freshness_refresh(
                db_session,
                cve_id=cve.cve_id,
                trigger=OnDemandFetchTrigger.CVE_ASSOCIATE,
            )

        assert len(_callbacks(db_session)) == 1
        for statement in recorder.statements:
            assert "ticket_access_grant" not in statement
            assert "ticket_package_maintainer" not in statement

    async def test_missing_configuration_row_propagates_without_registration(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A registered fetcher without its `FetcherConfig` row is a
        bootstrap invariant failure that propagates (and rolls back the
        caller's mutation); nothing is registered (cve-service.md,
        Transactional Preparation step 4; Callers and Ordering)."""
        await _fetcher(db_session, NVD, enabled=None)
        await _fetcher(db_session, GHSA)
        cve, _ticket = await _held_roots(db_session)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(FetcherConfigMissingError):
            await prepare_freshness_refresh(
                db_session,
                cve_id=cve.cve_id,
                trigger=OnDemandFetchTrigger.TICKET_CREATE,
            )

        assert _callbacks(db_session) == []
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# get_db(): the effect runs only after commit, never after rollback
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPostCommitOrdering:
    @pytest.fixture
    def request_sessions(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> RecordingSessions:
        """`get_db()` sessions joined to the `db_session` connection in
        `create_savepoint` mode; their `commit` and `rollback` are recorded
        into the shared event list."""
        assert isinstance(db_session.bind, AsyncConnection)
        factory = async_sessionmaker(
            bind=db_session.bind,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        sessions = RecordingSessions(factory)
        monkeypatch.setattr(database, "async_session_factory", sessions)
        return sessions

    async def test_effect_never_runs_after_the_request_rollback(
        self,
        db_session: AsyncSession,
        request_sessions: RecordingSessions,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`get_db()` never runs the registered effect after a rollback
        (cve-service.md, Callers and Ordering; `prepare_freshness_refresh()`
        Q3). The commit-then-publish order is proven end to end by
        `tests/test_api/test_ticket_freshness_refresh.py`."""
        await _fetcher(db_session, NVD)
        cve = CVE(cve_id=fictional_cve_id())
        db_session.add(cve)
        await db_session.flush()
        ScriptedRedis().install(monkeypatch)
        published.events = request_sessions.events
        request = database.get_db()
        session = await anext(request)
        await session.execute(
            select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
        )
        session.add(Ticket(status="New", cve_id=cve.id))
        await session.flush()
        request_sessions.events.clear()

        await prepare_freshness_refresh(
            session, cve_id=cve.cve_id, trigger=OnDemandFetchTrigger.TICKET_CREATE
        )
        assert len(_callbacks(session)) == 1

        failure = RuntimeError("fictional handler failure")
        with pytest.raises(RuntimeError) as raised:
            await request.athrow(failure)
        assert raised.value is failure
        assert request_sessions.events == ["rollback"]
        assert published.calls == []


# ---------------------------------------------------------------------------
# Caller-held ORM state
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCallerState:
    async def test_relock_does_not_refresh_caller_loaded_state(
        self,
        db_session: AsyncSession,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """For the automatic callers step 2 is a same-transaction re-lock of
        roots the caller already holds (cve-service.md, Transactional
        Preparation step 3). Only key columns are selected, so the re-lock
        does not refresh the caller's loaded `CVE` and `Ticket` instances:
        their unflushed in-memory values survive. `no_autoflush` keeps those
        values out of the database, so a refreshing re-lock would load the
        persisted `NULL`s over them."""
        await _fetcher(db_session, NVD)
        cve, ticket = await _held_roots(db_session)
        pending_title = "Pending caller title"
        pending_release = datetime(2099, 6, 1, 12, 0, tzinfo=UTC)
        forbid_redis(monkeypatch)

        with db_session.no_autoflush:
            cve.title = pending_title
            ticket.coordinated_release_at = pending_release
            await prepare_freshness_refresh(
                db_session,
                cve_id=cve.cve_id,
                trigger=OnDemandFetchTrigger.CVE_ASSOCIATE,
            )

        assert cve.title == pending_title
        assert ticket.coordinated_release_at == pending_release
        assert len(_callbacks(db_session)) == 1
        assert published.calls == []
