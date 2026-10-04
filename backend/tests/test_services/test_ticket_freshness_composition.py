"""Composition tests of the automatic CVE freshness refresh inside
`ticket_service.create_ticket()` and `ticket_service.associate_cve()`
(backend/app/services/ticket_service.py), both calling
`cve_service.prepare_freshness_refresh()` last.

Owning specifications:

- docs/features/tickets/ticket-service.md (`create_ticket` step 11,
  Post-commit freshness, Audit events; `associate_cve` step 14 and the
  no-eligible-source and best-effort paragraphs; Architectural Test
  Requirements 13, 15, and 19);
- docs/features/tickets/cve-service.md (Fetch Orchestration: Transactional
  Preparation, Callers and Ordering; RESERVED CVEs > Crash recovery);
- docs/features/tickets/tickets.md (CVE Resolution Behavior);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Ticket
  Accessibility > Locked mutations; Audit Trail Testing; Concurrency
  Testing).

The preparation's own matrix (no-eligible logging, registration, publication
failure in the effect, re-lock without refresh) is proven by
`tests/test_services/test_cve_freshness_preparation.py`, and the HTTP
composition through the real `get_db()` by
`tests/test_api/test_ticket_freshness_refresh.py`. This module proves the
two call sites: rollback of the whole mutation on preparation failure,
commit failure and pre-commit cancellation of the real `get_db()`
transaction without publication, placeholder-only-when-needed, the
ingestion exclusion, the locked-current denial without registration, the
unchanged audit contracts, and the accepted commit-to-publication crash gap.

Every test empties both fetcher registries under
`isolated_fetcher_registries` and defines its own test-only CVE fetchers.
The broker is never reached (`task_publication.publish_task` is a recorder)
and the pending-marker client is `ScriptedRedis` or forbidden. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import OperationalError as DatabaseOperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app import database
from app.core.enums import CVESourceType, Role, Scope, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.database import Base
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import cve_service, task_publication
from app.services.fetcher_execution import FetcherConfigMissingError
from app.services.ticket_service import (
    TicketCreationSource,
    associate_cve,
    create_ticket,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_catch_up import (
    Publications,
    RecordingSessions,
    define_cve_fetcher,
)
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    Assessment,
    CVEBuilder,
    eligibility,
    priority_event,
    severity_event,
    ticket_state,
)
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.fetch_single_cve import (
    TASK,
    ScriptedRedis,
    events_named,
    fictional_cve_id,
    forbid_redis,
)
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_creation import creation_events, ingestion_comment
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `cve_with`, and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]
Callback = Callable[[], Awaitable[None]]

NO_ELIGIBLE = "cve_fetch_no_eligible_source"
POST_COMMIT_CALLBACKS = "post_commit_callbacks"
"""The `AsyncSession.info` key of registered post-commit callbacks."""

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
GHSA = CVESourceType.GHSA

OPERATIONS = ["create", "associate"]
WAIT = 5


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


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> None:
    """The persisted `default_cvss_version` the association chain reads."""
    await system_setting_factory(key="default_cvss_version", value=DEFAULT_VERSION)


async def _fetcher(
    db: AsyncSession,
    source: CVESourceType,
    *,
    enabled: bool | None = True,
    queue: str | None = None,
) -> str:
    """Register a test-only refetchable CVE fetcher owning `source` and
    flush its `FetcherConfig`; `enabled=None` creates no configuration row."""
    probe = define_cve_fetcher(source=source, fetcher_queue=queue)
    if enabled is not None:
        db.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
        await db.flush()
    return probe.name


async def _enabled_roster(db: AsyncSession) -> None:
    """Two enabled refetchable sources (one on the `git` queue) and one
    disabled source."""
    await _fetcher(db, NVD)
    await _fetcher(db, MITRE, queue="git")
    await _fetcher(db, GHSA, enabled=False)


def _callbacks(db: AsyncSession) -> list[Callback]:
    callbacks: list[Callback] = db.info.get(POST_COMMIT_CALLBACKS, [])
    return callbacks


async def _manual_create(db: AsyncSession, actor: User, cve_id: str) -> Ticket:
    """A manual create-with-CVE, as the POST handler calls it."""
    return await create_ticket(
        db, acting_user_id=actor.id, cve_id=cve_id, source=TicketCreationSource.MANUAL
    )


async def _associate(
    db: AsyncSession, ticket_id: uuid.UUID, cve_id: str, actor: User
) -> Ticket:
    """An association, as the POST handler calls it."""
    return await associate_cve(
        db,
        ticket_id=ticket_id,
        cve_id=cve_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


async def _run(
    db: AsyncSession,
    name: str,
    actor: User,
    cve_id: str,
    ticket_factory: TicketFactory,
) -> Ticket:
    """Run `name` for `cve_id`; `associate` targets a new unassigned
    severity-less CVE-less `New` Ticket."""
    if name == "create":
        return await _manual_create(db, actor, cve_id)
    ticket = await ticket_factory(status=TicketStatus.NEW.value)
    return await _associate(db, ticket.id, cve_id, actor)


async def _count(db: AsyncSession, model: type[Any]) -> int:
    return int(await db.scalar(select(func.count()).select_from(model)) or 0)


async def _run_effect(effect: Callback, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run a registered effect as `get_db()` would after its commit."""
    ScriptedRedis().install(monkeypatch)
    await effect()


def _published_sources(published: Publications) -> list[tuple[str, str]]:
    return [
        (kwargs["cve_id"], kwargs["source"]) for kwargs in published.published(TASK)
    ]


async def _association_state(db: AsyncSession, ticket_id: uuid.UUID) -> tuple[Any, ...]:
    """Everything an association may change on one Ticket: `(status,
    assignee, priority_auto, priority_override, severity_manual)`, `cve_id`,
    the Product occurrences' `(eligible, is_eligible_override)`, and the
    audit events."""
    return (
        await ticket_state(db, ticket_id),
        await db.scalar(select(Ticket.cve_id).where(Ticket.id == ticket_id)),
        await eligibility(db, ticket_id),
        await ticket_events_by_id(db, ticket_id),
    )


# ---------------------------------------------------------------------------
# B5: preparation and registration failures roll the whole mutation back
# ---------------------------------------------------------------------------


FAILURES = ["missing-configuration", "database", "registration"]


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestPreparationFailureRollsBack:
    @pytest.mark.parametrize("failure", FAILURES)
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_failure_escapes_and_nothing_persists_after_rollback(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        failure: str,
    ) -> None:
        """A registered refetchable fetcher without its `FetcherConfig` row
        (`FetcherConfigMissingError`), a database error during preparation,
        and a registration error escape unchanged; after the caller's
        rollback no Ticket, placeholder CVE, association, or audit event
        persists, and nothing was registered or published (ticket-service.md,
        `create_ticket` Q6 / `associate_cve` Q6 and Post-commit freshness;
        testing-strategy.md, On-Demand CVE Refetch)."""
        actor = await va_user()
        reached: list[bool] = []
        if failure == "missing-configuration":
            await _fetcher(db_session, NVD, enabled=None)
            await _fetcher(db_session, GHSA)
            expected: type[Exception] = FetcherConfigMissingError
        else:
            await _fetcher(db_session, NVD)
            error: Exception
            if failure == "database":
                error = DatabaseOperationalError(
                    "SELECT fetcher_config", {}, Exception("fictional outage")
                )
                expected = DatabaseOperationalError
                target = "_fetcher_enabled_states"
            else:
                error = RuntimeError("fictional registration failure")
                expected = RuntimeError
                target = "register_post_commit_callback"

            def _raise(*args: Any, **kwargs: Any) -> Any:
                reached.append(True)
                raise error

            async def _raise_async(*args: Any, **kwargs: Any) -> Any:
                _raise()

            monkeypatch.setattr(
                cve_service,
                target,
                _raise_async if failure == "database" else _raise,
            )
        ticket_id = (
            (await ticket_factory(status=TicketStatus.NEW.value)).id
            if name == "associate"
            else None
        )
        cve_id = fictional_cve_id()
        attempts = forbid_redis(monkeypatch)
        before = (
            await _count(db_session, Ticket),
            await _count(db_session, CVE),
            await _count(db_session, TicketAuditEvent),
        )

        operation = (
            _manual_create(db_session, actor, cve_id)
            if ticket_id is None
            else _associate(db_session, ticket_id, cve_id, actor)
        )

        async with rollback_test_scope(db_session):
            with pytest.raises(expected):
                await operation
            assert _callbacks(db_session) == []

        if failure != "missing-configuration":
            assert reached == [True]
        assert (
            await _count(db_session, Ticket),
            await _count(db_session, CVE),
            await _count(db_session, TicketAuditEvent),
        ) == before
        assert (
            await db_session.scalar(select(CVE.id).where(CVE.cve_id == cve_id)) is None
        )
        if ticket_id is not None:
            row = (
                await db_session.execute(
                    select(Ticket.status, Ticket.assignee_id, Ticket.cve_id).where(
                        Ticket.id == ticket_id
                    )
                )
            ).one()
            assert tuple(row) == (TicketStatus.NEW.value, None, None)
        assert attempts() == 0
        assert published.calls == []

    async def test_populated_association_rolls_back_every_chain_effect(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CVE with a SUSE 9.8 assessment associated to a `Medium` `P4`
        Ticket with an ineligible automatic Product: before step 14 the
        association hands the severity over, makes the Product eligible, and
        refreshes the priority to `P2`. The preparation then fails
        (`FetcherConfigMissingError`), and after the caller's rollback the
        severity, priority, Product eligibility, association, and audit
        events are all unchanged (ticket-service.md, `associate_cve` step 14
        and Q6; testing-strategy.md, On-Demand CVE Refetch: atomic
        association, CVSS handover, Product, reconciliation, audit, and
        registration)."""
        await _fetcher(db_session, NVD, enabled=None)
        actor = await va_user()
        cve = await cve_with(Assessment("9.8"), severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=Severity.MEDIUM,
            priority_auto="P4",
        )
        await tree(ticket, products=(Prod(eligible=False),))
        # The caller's rollback expires the ORM instances: keep their keys.
        ticket_id, cve_pk, cve_id = ticket.id, cve.id, cve.cve_id
        attempts = forbid_redis(monkeypatch)
        before = await _association_state(db_session, ticket_id)
        at_preparation: list[tuple[Any, ...]] = []
        prepare = cve_service.prepare_freshness_refresh

        async def _observed(db: AsyncSession, **kwargs: Any) -> None:
            at_preparation.append(await _association_state(db, ticket_id))
            await prepare(db, **kwargs)

        monkeypatch.setattr(cve_service, "prepare_freshness_refresh", _observed)

        async with rollback_test_scope(db_session):
            with pytest.raises(FetcherConfigMissingError):
                await _associate(db_session, ticket_id, cve_id, actor)
            assert _callbacks(db_session) == []

        assert before == (
            (TicketStatus.NEW.value, None, "P4", None, "Medium"),
            None,
            [(False, False)],
            [],
        )
        [(state, associated, products, events)] = at_preparation
        assert (state[2], state[4]) == ("P2", None)
        assert associated == cve_pk
        assert products == [(True, False)]
        assert {
            "cve_associated",
            "severity_changed",
            "product_eligibility_changed",
            "priority_changed",
        } <= {event.event_type for event in events}
        assert await _association_state(db_session, ticket_id) == before
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# B6: a placeholder only when needed; the refresh is always prepared
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestPlaceholderOnlyWhenNeeded:
    @pytest.mark.parametrize("kind", ["new", "existing-placeholder", "populated"])
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_refresh_is_prepared_for_every_cve_kind(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        kind: str,
    ) -> None:
        """A new CVE-ID creates exactly one placeholder; an existing
        placeholder and an existing populated CVE with CVSS assessments
        create no CVE row and keep their data. Each registers exactly one
        refresh publishing the canonical CVE-ID (cve-service.md, Callers and
        Ordering; ticket-service.md, `create_ticket` step 11, `associate_cve`
        step 14)."""
        await _fetcher(db_session, NVD)
        actor = await va_user()
        cve_id = fictional_cve_id()
        assessments: list[tuple[Any, ...]] = []
        if kind != "new":
            cve: CVE = await cve_factory(
                cve_id=cve_id,
                **(
                    {"title": "Example populated CVE", "severity": "Critical"}
                    if kind == "populated"
                    else {}
                ),
            )
            if kind == "populated":
                await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="NVD")
                assessments = [
                    tuple(row)
                    for row in (
                        await db_session.execute(
                            select(CVECVSSAssessment.__table__).where(
                                CVECVSSAssessment.cve_id == cve.id
                            )
                        )
                    ).all()
                ]
        cves_before = await _count(db_session, CVE)

        ticket = await _run(db_session, name, actor, cve_id, ticket_factory)

        rows = (
            await db_session.execute(
                select(CVE.id, CVE.title).where(CVE.cve_id == cve_id)
            )
        ).all()
        assert len(rows) == 1
        assert await _count(db_session, CVE) == cves_before + (
            1 if kind == "new" else 0
        )
        assert ticket.cve_id == rows[0].id
        if kind == "populated":
            assert rows[0].title == "Example populated CVE"
            assert [
                tuple(row)
                for row in (
                    await db_session.execute(
                        select(CVECVSSAssessment.__table__).where(
                            CVECVSSAssessment.cve_id == rows[0].id
                        )
                    )
                ).all()
            ] == assessments
        [effect] = _callbacks(db_session)
        assert published.calls == []

        await _run_effect(effect, monkeypatch)

        assert _published_sources(published) == [(cve_id, "nvd")]


# ---------------------------------------------------------------------------
# B7: ingestion creation never prepares a refresh
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestionCreation:
    @pytest.mark.parametrize("roster", ["enabled", "empty"])
    async def test_ingestion_creation_registers_nothing_and_logs_nothing(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        roster: str,
    ) -> None:
        """`source = cve_ingestion` skips step 11: with an enabled
        refetchable roster nothing is registered, and with an empty registry
        no `cve_fetch_no_eligible_source` is logged; zero Redis and Celery
        I/O (ticket-service.md, `create_ticket` step 11)."""
        if roster == "enabled":
            await _enabled_roster(db_session)
        cve: CVE = await cve_factory(cve_id=fictional_cve_id())
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs:
            ticket = await create_ticket(
                db_session,
                acting_user_id=None,
                cve_id=cve.cve_id,
                source=TicketCreationSource.CVE_INGESTION,
                ingestion_source=NVD,
            )

        assert await ticket_events_by_id(db_session, ticket.id) == creation_events(
            creator_id=None, comment=ingestion_comment(NVD), cve_id=cve.cve_id
        )
        assert _callbacks(db_session) == []
        assert events_named(logs, NO_ELIGIBLE) == []
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# B9 / B10: ATR 13 and 19 audit contracts unchanged by the refresh
# ---------------------------------------------------------------------------


async def _assert_effect_adds_no_event(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    published: Publications,
    monkeypatch: pytest.MonkeyPatch,
    cve_id: str,
) -> None:
    """The one registered effect publishes the enabled sources and creates
    no audit event (ticket-audit-log.md: refetch preparation and publication
    create no event)."""
    events = await ticket_events_by_id(db, ticket_id)
    [effect] = _callbacks(db)
    await db.commit()

    await _run_effect(effect, monkeypatch)

    assert _published_sources(published) == [(cve_id, "mitre"), (cve_id, "nvd")]
    assert await ticket_events_by_id(db, ticket_id) == events


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAuditContractsUnchanged:
    @pytest.mark.parametrize(
        ("kind", "priority"),
        [
            pytest.param("evidence", "P1", id="evidence"),
            pytest.param("rejected", "P3", id="rejected"),
        ],
    )
    async def test_manual_creation_order_is_unchanged_with_an_enabled_roster(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        priority: str,
    ) -> None:
        """ATR 13 and 19: `ticket_created`, the assignment, `cve_associated`,
        and the final system `priority_changed`, exactly as without a
        refresh. `Critical` with KEV is `P1`; a locked-current `REJECTED`
        CVE (`High`, `P3`) keeps the ordinary sequence with no automatic
        `CVE rejected` effect and still prepares the refresh (ticket-service.md,
        `create_ticket` Audit events and the `REJECTED` paragraph;
        ticket-priority.md, Decision Table)."""
        await _enabled_roster(db_session)
        actor = await va_user()
        if kind == "evidence":
            cve: CVE = await cve_factory(cve_id=fictional_cve_id(), severity="Critical")
            await cve_kev_entry_factory(cve_id=cve.id)
        else:
            cve = await cve_factory(
                cve_id=fictional_cve_id(),
                cve_state="REJECTED",
                date_rejected=datetime(2099, 3, 4, tzinfo=UTC),
                severity="High",
            )

        ticket = await _manual_create(db_session, actor, cve.cve_id)

        assert await ticket_events_by_id(db_session, ticket.id) == creation_events(
            creator_id=actor.id,
            assignee_username=actor.username,
            cve_id=cve.cve_id,
            priority=priority,
        )
        assert ticket.status == TicketStatus.ANALYSIS.value
        await _assert_effect_adds_no_event(
            db_session, ticket.id, published, monkeypatch, cve.cve_id
        )

    @pytest.mark.parametrize("kind", ["populated", "rejected"])
    async def test_association_order_is_unchanged_with_an_enabled_roster(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        """ATR 19 and the `associate_cve` Audit events: auto-assignment and
        its promotion precede `cve_associated`, then the system severity
        handover and the system `priority_changed`, exactly as without a
        refresh; a locked-current `REJECTED` CVE gets no automatic rejection
        effect and still prepares the refresh."""
        await _enabled_roster(db_session)
        actor = await va_user()
        if kind == "populated":
            cve = await cve_with(Assessment("9.8"), severity=None)
            ticket = await cveless(
                ticket_factory,
                status=TicketStatus.NEW,
                severity=Severity.MEDIUM,
                priority_auto="P4",
            )
            chain = [severity_event("Medium", "Critical"), priority_event("P4", "P2")]
        else:
            cve = await cve_factory(
                cve_id=fictional_cve_id(),
                cve_state="REJECTED",
                date_rejected=datetime(2099, 3, 4, tzinfo=UTC),
                severity=None,
            )
            await cve_cvss_assessment_factory(
                cve_id=cve.id,
                provider_name="SUSE",
                cvss_version=DEFAULT_VERSION,
                score=Decimal("7.5"),
            )
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            chain = [severity_event(None, "High"), priority_event(None, "P3")]

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert await ticket_events_by_id(db_session, ticket.id) == [
            EventRow("assignment", actor.id, None, actor.username, None, None),
            status_event("New", "Analysis"),
            EventRow("cve_associated", actor.id, None, cve.cve_id, None, None),
            *chain,
        ]
        await _assert_effect_adds_no_event(
            db_session, ticket.id, published, monkeypatch, cve.cve_id
        )


# ---------------------------------------------------------------------------
# B5: commit failure and pre-commit cancellation of the request transaction
# ---------------------------------------------------------------------------


@pytest.fixture
def request_sessions(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> RecordingSessions:
    """`get_db()` sessions joined to the `db_session` connection in
    `create_savepoint` mode; their `flush`, `commit`, and `rollback` are
    recorded."""
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


def _commit_then_raise(failure: BaseException) -> Callable[[AsyncSession], None]:
    """A `RecordingSessions` hook: the (recorded) commit completes, then
    `failure` is raised, so the caller cannot know the outcome."""

    def hook(session: AsyncSession) -> None:
        commit = session.commit

        async def committed_then_raise() -> None:
            await commit()
            raise failure

        session.commit = committed_then_raise  # type: ignore[method-assign]

    return hook


def _count_dispatches(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the CVE-ID of every `trigger_on_demand_fetch()` call, which
    only the registered effect makes."""
    calls: list[str] = []
    real = cve_service.trigger_on_demand_fetch

    async def spy(cve_id: str, *args: Any, **kwargs: Any) -> Any:
        calls.append(cve_id)
        return await real(cve_id, *args, **kwargs)

    monkeypatch.setattr(cve_service, "trigger_on_demand_fetch", spy)
    return calls


async def _run_in(
    session: AsyncSession, actor: User, cve_id: str, target: Ticket | None
) -> None:
    """A manual create-with-CVE when `target` is `None`, else its
    association."""
    if target is None:
        await _manual_create(session, actor, cve_id)
    else:
        await _associate(session, target.id, cve_id, actor)


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestRequestTransactionEnd:
    @pytest.mark.parametrize("commit", ["failed-commit", "ambiguous-commit"])
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_commit_failure_never_runs_the_registered_effect(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        request_sessions: RecordingSessions,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        commit: str,
    ) -> None:
        """The mutation registers its effect in the real `get_db()`
        transaction; a definitely failed commit and a commit whose outcome is
        ambiguous (it completes, then raises) both propagate through
        `get_db()`'s rollback, and the effect never runs: zero Redis commands
        and zero publication attempts (cve-service.md, Transactional
        Preparation: commit failure; Callers and Ordering; ticket-service.md,
        Post-commit freshness)."""
        await _enabled_roster(db_session)
        actor = await va_user()
        target = (
            await ticket_factory(status=TicketStatus.NEW.value)
            if name == "associate"
            else None
        )
        failure = DatabaseOperationalError(
            "COMMIT", {}, Exception("server closed the connection")
        )
        if commit == "failed-commit":
            request_sessions.failures["commit"] = failure
        else:
            request_sessions.hooks.append(_commit_then_raise(failure))
        attempts = forbid_redis(monkeypatch)
        dispatches = _count_dispatches(monkeypatch)
        request = database.get_db()
        session = await anext(request)
        await _run_in(session, actor, fictional_cve_id(), target)
        assert len(_callbacks(session)) == 1
        request_sessions.events.clear()

        with pytest.raises(DatabaseOperationalError) as raised:
            await anext(request)

        assert raised.value is failure
        assert [e for e in request_sessions.events if e != "flush"] == [
            "commit",
            "rollback",
        ]
        assert dispatches == []
        assert attempts() == 0
        assert published.calls == []

    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_cancellation_after_registration_never_runs_the_effect(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        request_sessions: RecordingSessions,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
    ) -> None:
        """The request task is cancelled after the effect is registered and
        before `get_db()` commits. `asyncio.CancelledError` is not an
        `Exception`, so `get_db()` neither commits nor runs its post-commit
        callbacks; the session closes and the mutation does not persist.
        Zero Redis commands and zero publication attempts (cve-service.md,
        Transactional Preparation: post-registration cancellation before
        commit). The dependency is entered as FastAPI does, through
        `asynccontextmanager`."""
        await _enabled_roster(db_session)
        actor = await va_user()
        target = (
            await ticket_factory(status=TicketStatus.NEW.value)
            if name == "associate"
            else None
        )
        cve_id = fictional_cve_id()
        attempts = forbid_redis(monkeypatch)
        dispatches = _count_dispatches(monkeypatch)
        registered = asyncio.Event()
        callbacks: list[int] = []

        async def _request() -> None:
            async with asynccontextmanager(database.get_db)() as session:
                await _run_in(session, actor, cve_id, target)
                callbacks.append(len(_callbacks(session)))
                registered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(_request())
        await asyncio.wait_for(registered.wait(), timeout=WAIT)
        request_sessions.events.clear()
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=WAIT)

        assert done == {task}
        assert task.cancelled()
        assert callbacks == [1]
        assert "commit" not in request_sessions.events
        [session] = request_sessions.opened
        assert not session.in_transaction()
        assert (
            await db_session.scalar(select(CVE.id).where(CVE.cve_id == cve_id)) is None
        )
        assert dispatches == []
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# B11: the accepted commit-to-publication crash gap
# ---------------------------------------------------------------------------


async def _row_counts(db: AsyncSession) -> dict[str, int]:
    """The row count of every application table."""
    counts: dict[str, int] = {}
    for table in Base.metadata.sorted_tables:
        counts[table.name] = int(
            await db.scalar(select(func.count()).select_from(table)) or 0
        )
    return counts


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestCrashGap:
    @pytest.mark.parametrize("name", OPERATIONS)
    async def test_crash_after_commit_leaves_only_the_mutation_rows(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        ticket_factory: TicketFactory,
        name: str,
    ) -> None:
        """The process stops after the caller's commit, before the
        registered effect runs: the committed Ticket and placeholder CVE
        remain, and no outbox, durable job, progress, or `FetcherRun` row
        exists anywhere (cve-service.md, RESERVED CVEs > Crash recovery;
        Callers and Ordering; ticket-service.md, Post-commit freshness)."""
        await _enabled_roster(db_session)
        actor = await va_user()
        target = (
            await ticket_factory(status=TicketStatus.NEW.value)
            if name == "associate"
            else None
        )
        cve_id = fictional_cve_id()
        before = await _row_counts(db_session)

        if target is None:
            ticket = await _manual_create(db_session, actor, cve_id)
        else:
            ticket = await _associate(db_session, target.id, cve_id, actor)
        assert len(_callbacks(db_session)) == 1
        await db_session.commit()
        db_session.info.pop(POST_COMMIT_CALLBACKS)  # the effect never runs

        after = await _row_counts(db_session)
        changed = {
            table: after[table] - before[table]
            for table in after
            if after[table] != before[table]
        }
        assert changed == {
            "cve": 1,
            **({"ticket": 1} if name == "create" else {}),
            "ticket_audit_event": 3,
        }
        committed = (
            await db_session.execute(
                select(Ticket.cve_id, CVE.cve_id)
                .join(CVE, CVE.id == Ticket.cve_id)
                .where(Ticket.id == ticket.id)
            )
        ).one()
        assert committed[1] == cve_id


# ---------------------------------------------------------------------------
# B8: ATR 15 — locked-current denial registers and publishes nothing
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns committed `FetcherConfig` rows and
    an independent `probe` session."""

    probe: AsyncSession

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        super().__init__(factory, session)
        self.fetcher_names: list[str] = []

    async def fetcher(self, source: CVESourceType) -> str:
        probe = define_cve_fetcher(source=source)
        self.session.add(FetcherConfig(fetcher_name=probe.name, enabled=True))
        await self.session.commit()
        self.fetcher_names.append(probe.name)
        return probe.name

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
        finally:
            await self.session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name.in_(self.fetcher_names)
                )
            )
            await self.session.commit()


@pytest.fixture
async def world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_World]:
    created = _World(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        yield created
    finally:
        await created.cleanup()


@pytest.mark.integration
class TestLockedCurrentDenial:
    async def test_visibility_lost_before_the_ticket_lock_registers_nothing(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `restricted_analyst` passes the preliminary locator check; an
        independent session holding the Ticket lock makes the Ticket
        confidential and commits while the association waits on that lock.
        The locked-current decision wins: `TicketNotFoundError`, no
        freshness registration, no configuration read, and zero Redis and
        Celery I/O (ticket-service.md, ATR 15; testing-strategy.md, Ticket
        Accessibility > Locked mutations). The complete loss matrix is
        `tests/test_services/test_associate_cve_atomicity.py`
        (`TestLockedCurrentAccessibility`)."""
        user = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        cve = await world.cve()
        await world.fetcher(NVD)
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        sequence = await world.probe.scalar(
            select(Ticket.sequence_id).where(Ticket.id == ticket.id)
        )
        await world.probe.rollback()
        locator = f"SNTL-{sequence}"
        a = await world.open_session()
        b = await world.open_session()
        attempts = forbid_redis(monkeypatch)

        assert (await resolve_ticket_locator(a, locator, caller)).id == ticket.id
        await b.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )
        await b.execute(
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True)
        )
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a,
                associate_cve(
                    a,
                    ticket_id=ticket.id,
                    cve_id=cve.cve_id,
                    acting_user_id=user.id,
                    caller=caller,
                    evaluation_date=EVAL,
                ),
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert _callbacks(a) == []
        assert not any("fetcher_config" in s for s in recorder.statements)
        assert [
            w
            for w in recorder.writes()
            if not w.startswith(("SAVEPOINT", "RELEASE SAVEPOINT", "ROLLBACK"))
        ] == []
        assert attempts() == 0
        assert published.calls == []
        await a.rollback()
        associated = await world.probe.scalar(
            select(Ticket.cve_id).where(Ticket.id == ticket.id)
        )
        await world.probe.rollback()
        assert associated is None
