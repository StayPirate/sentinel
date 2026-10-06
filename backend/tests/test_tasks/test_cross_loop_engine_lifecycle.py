"""Regression tests: pooled connections must not cross Celery
event-loop boundaries.

See `docs/conventions.md` (Cross-loop pooled connection lifecycle) and
`docs/features/platform/testing-strategy.md` (Cross-Loop Engine
Lifecycle) for the contract under test.

A process-lifetime SQLAlchemy engine using the default pooled
connection implementation must not let a connection survive the
`asyncio.run()` event loop that checked it out — SQLAlchemy documents
this explicitly (see "Using multiple asyncio event loops",
https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html). Before
the fix (awaiting `engine.dispose()` before the invocation's
`asyncio.run()` loop closes), a second sequential invocation of the
real synchronous Celery wrapper — the scenario a long-lived prefork
worker child repeats indefinitely — reproduces SQLAlchemy's cross-loop
`RuntimeError`/`InterfaceError`.

Every test in this module is Tier 2 (integration): each exercises a
real pooled engine against the shared test PostgreSQL server. None
requires a Celery broker or worker process — the failure is a
SQLAlchemy/asyncio event-loop invariant, reproducible directly by
calling the production synchronous entry point twice in the same test
process.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from structlog.typing import EventDict

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.celery_app import celery_app
from app.core.enums import CVESourceType, PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, task_publication, ticket_mutations
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
)
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.cve_ingest import UpsertAction
from app.services.cvss_recalculation import (
    COMPLETED_EVENT,
    FAILED_EVENT,
    RECALCULATE_CVSS_DERIVED_STATE_TASK,
)
from app.services.cvss_recalculation_coordination import LEASE_KEY
from app.services.package_service import (
    PackageRecordsOutcome,
    ProductEligibilityRecalculationResult,
    ProductRecalculationReason,
)
from app.services.packages import (
    product_catalog_backfill,
    product_eligibility_recalculation,
)
from app.tasks import cve_tasks, cvss_tasks, package_tasks, session_cleanup
from app.tasks import fetchers as fetchers_module
from tests.support.cve_catch_up import FakeTask, RetryRequested
from tests.support.cvss_recalculation import admit_lease, capture_events, runner_events


@pytest.mark.integration
def test_cleanup_sessions_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `cleanup_sessions`
    synchronous wrapper — each its own `asyncio.run()` event loop —
    both succeed against one shared, pooled engine.

    A dedicated engine (not the session-scoped `_engine` used by the
    rest of the suite) is required here: this test needs a pool that
    is genuinely reused and disposed across two independent event
    loops, which must not be entangled with the connection pytest-
    asyncio's own long-lived loop holds open via `_engine`/`db_session`
    for the remainder of the test session.
    """
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(session_cleanup, "engine", dedicated_engine)
    monkeypatch.setattr(session_cleanup, "async_session_factory", dedicated_factory)

    try:
        # First invocation: opens its own event loop, deletes zero
        # eligible sessions, commits, and — per the fix — disposes the
        # pool before this loop closes.
        first_result = session_cleanup._cleanup_sessions_sync()

        # Second invocation: a brand-new event loop. Before the fix,
        # the pool would still hold a connection bound to the first
        # (now-closed) loop, and checking it out here would raise
        # `RuntimeError: ... attached to a different loop`.
        second_result = session_cleanup._cleanup_sessions_sync()
    finally:
        asyncio.run(dedicated_engine.dispose())

    assert isinstance(first_result, int)
    assert isinstance(second_result, int)


@pytest.mark.integration
def test_run_fetcher_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `run_fetcher` synchronous
    wrapper — each its own `asyncio.run()` event loop — both succeed
    against one shared, pooled engine.

    Unlike `cleanup_sessions` (a single session per invocation),
    `run_fetcher_async` opens at least two independent sessions per
    invocation: the acquisition session in `app/tasks/fetchers.py`, and
    the settings/cursor/execution/finalization sessions
    `BaseFetcher.run()` opens via the module-level
    `async_session_factory` reference in `app/services/base_fetcher.py`
    (see that module's docstring under "run() lifecycle"). Both module
    references are redirected to the same dedicated pooled engine so
    the fix's disposal must reclaim every connection this richer,
    multi-session invocation shape can check out — not just the single
    one `cleanup_sessions` exercises.
    """
    fetcher_name = "test_cross_loop_probe_fetcher"

    class _FakeRequest:
        timelimit = (3600, 3420)

    class _FakeTask:
        """Minimal stand-in for the bound Celery Task instance (`self`),
        carrying only the `request.timelimit` attribute
        `_run_fetcher_sync` reads."""

        request = _FakeRequest()

    class _ProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Cross-loop lifecycle regression probe (no-op execute)"
        default_schedule = "0 * * * *"

        async def execute(self, session: AsyncSession) -> None:
            pass

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> None:
        async with dedicated_factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name))
            await session.commit()
        # Drain the seeding connection from the pool before the first
        # real invocation opens its own event loop below — otherwise
        # the pool would hand out a connection bound to *this* loop,
        # a setup artifact unrelated to the fix under test.
        await dedicated_engine.dispose()

    async def _cleanup() -> None:
        async with dedicated_factory() as session:
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()
        await dedicated_engine.dispose()

    monkeypatch.setattr(fetchers_module, "engine", dedicated_engine)
    monkeypatch.setattr(fetchers_module, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(base_fetcher_module, "async_session_factory", dedicated_factory)

    try:
        asyncio.run(_seed_and_drain())

        # First invocation: opens its own event loop, acquires and
        # executes the run, and — per the fix — disposes the pool
        # before this loop closes.
        fetchers_module._run_fetcher_sync(_FakeTask(), fetcher_name)

        # Second invocation: a brand-new event loop. Before the fix,
        # the pool would still hold a connection bound to the first
        # (now-closed) loop, and checking it out here would raise
        # `RuntimeError: ... attached to a different loop`.
        fetchers_module._run_fetcher_sync(_FakeTask(), fetcher_name)
    finally:
        FETCHER_REGISTRY.pop(fetcher_name, None)
        asyncio.run(_cleanup())


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries")
def test_run_catch_up_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `run_catch_up` synchronous
    wrapper — each its own `asyncio.run()` event loop — both succeed
    against one shared, pooled engine.

    `run_catch_up_async` opens two sessions per invocation through the
    module-level `async_session_factory` reference in
    `app/tasks/fetchers.py`: the enabled read, then the caller-owned
    session passed to `catch_up()`. The test-only fetcher's `catch_up()`
    runs a trivial query through that session, so both sessions check a
    connection out of the dedicated pool on every invocation. Celery
    retries are also new invocations in the same worker child, so the
    same disposal protects them.
    """
    fetcher_name = f"test_cross_loop_catch_up_probe_{uuid4().hex}"
    probe_ticket_id = str(uuid4())
    executed: list[str] = []

    class _FakeRequest:
        retries = 0

    class _FakeTask:
        """Minimal stand-in for the bound Celery Task instance (`self`),
        carrying only what `_run_catch_up_sync` reads."""

        request = _FakeRequest()

        def retry(self, **kwargs: object) -> BaseException:
            raise AssertionError(f"run_catch_up must not retry: {kwargs!r}")

    class _CatchUpProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Cross-loop lifecycle regression probe (SELECT 1 catch-up)"
        default_schedule = "0 * * * *"
        participates_in_catch_up = True

        async def execute(self, session: AsyncSession) -> None:
            pass

        async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
            await session.execute(text("SELECT 1"))
            executed.append(ticket_id)

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> None:
        async with dedicated_factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name))
            await session.commit()
        # Drain the seeding connection so the first real invocation does
        # not receive a connection bound to this setup loop.
        await dedicated_engine.dispose()

    async def _cleanup() -> None:
        async with dedicated_factory() as session:
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()
        await dedicated_engine.dispose()

    monkeypatch.setattr(fetchers_module, "engine", dedicated_engine)
    monkeypatch.setattr(fetchers_module, "async_session_factory", dedicated_factory)

    try:
        asyncio.run(_seed_and_drain())

        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        fetchers_module._run_catch_up_sync(_FakeTask(), fetcher_name, probe_ticket_id)

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        fetchers_module._run_catch_up_sync(_FakeTask(), fetcher_name, probe_ticket_id)
    finally:
        asyncio.run(_cleanup())

    assert executed == [probe_ticket_id, probe_ticket_id]


@dataclass(frozen=True, slots=True)
class _EligibilitySeed:
    """Committed rows of the `re_evaluate_product_eligibility` regressions."""

    product_id: UUID
    ticket_id: UUID
    owns_setting: bool


async def _seed_eligibility_candidate(
    factory: async_sessionmaker[AsyncSession],
) -> _EligibilitySeed:
    """Commit one candidate: a CVE-less `High` `Analysis` Ticket whose only
    occurrence of a catalog Product without lifecycle dates or threshold is
    seeded `false`, so the first successful recalculation changes it to
    `true` (one write, event, and commit) and a later one is a no-op."""
    suffix = uuid4().hex[:10]
    async with factory() as session:
        owns_setting = await session.get(SystemSetting, "default_cvss_version") is None
        if owns_setting:
            session.add(SystemSetting(key="default_cvss_version", value="3.1"))
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"EP {suffix}",
            cpe=f"cpe:/o:example:product:{suffix}",
            catalog_last_seen_at=datetime.now(UTC),
        )
        ticket = Ticket(
            status=TicketStatus.ANALYSIS.value, severity_manual=Severity.HIGH.value
        )
        session.add_all([product, ticket])
        await session.flush()
        package = TicketPackage(ticket_id=ticket.id, package_name=f"fictional-{suffix}")
        session.add(package)
        await session.flush()
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{suffix}:Update",
            status=PackageStatus.ANALYSIS.value,
        )
        session.add(track)
        await session.flush()
        session.add(
            TicketPackageProduct(
                ticket_package_track_id=track.id, product_id=product.id, eligible=False
            )
        )
        await session.commit()
        return _EligibilitySeed(product.id, ticket.id, owns_setting)


async def _read_and_delete_eligibility_candidate(
    factory: async_sessionmaker[AsyncSession], seed: _EligibilitySeed
) -> tuple[list[bool], list[str]]:
    """Return the committed occurrence eligibility and audit event types,
    then delete every seeded row in FK-safe order."""
    packages = select(TicketPackage.id).where(TicketPackage.ticket_id == seed.ticket_id)
    tracks = select(TicketPackageTrack.id).where(
        TicketPackageTrack.ticket_package_id.in_(packages)
    )
    async with factory() as session:
        eligible = list(
            (
                await session.execute(
                    select(TicketPackageProduct.eligible).where(
                        TicketPackageProduct.ticket_package_track_id.in_(tracks)
                    )
                )
            ).scalars()
        )
        events = list(
            (
                await session.execute(
                    select(TicketAuditEvent.event_type).where(
                        TicketAuditEvent.ticket_id == seed.ticket_id
                    )
                )
            ).scalars()
        )
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id == seed.ticket_id
            ),
            delete(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(tracks)
            ),
            delete(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id == seed.ticket_id),
            delete(Ticket).where(Ticket.id == seed.ticket_id),
            delete(Product).where(Product.id == seed.product_id),
        ):
            await session.execute(statement)
        if seed.owns_setting:
            await session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
        await session.commit()
    return eligible, events


@pytest.mark.integration
def test_re_evaluate_product_eligibility_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `re_evaluate_product_eligibility`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    succeed against one shared, pooled engine.

    Each invocation opens the read-only candidate-selection session and one
    per-Ticket session through the module-level `async_session_factory`
    reference in `app/tasks/package_tasks.py`. The seeded candidate makes
    the first invocation lock, write, audit, and commit, and the second
    lock and read it as a converged no-op, so both check real connections
    out of the dedicated pool.
    """
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> _EligibilitySeed:
        seed = await _seed_eligibility_candidate(dedicated_factory)
        # Drain the seeding connection so the first real invocation does
        # not receive a connection bound to this setup loop.
        await dedicated_engine.dispose()
        return seed

    async def _cleanup(seed: _EligibilitySeed) -> tuple[list[bool], list[str]]:
        committed = await _read_and_delete_eligibility_candidate(
            dedicated_factory, seed
        )
        await dedicated_engine.dispose()
        return committed

    monkeypatch.setattr(package_tasks, "engine", dedicated_engine)
    monkeypatch.setattr(package_tasks, "async_session_factory", dedicated_factory)

    seed = asyncio.run(_seed_and_drain())
    try:
        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        package_tasks._re_evaluate_product_eligibility_sync(
            str(seed.product_id), "threshold"
        )

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        package_tasks._re_evaluate_product_eligibility_sync(
            str(seed.product_id), "threshold"
        )
    finally:
        committed = asyncio.run(_cleanup(seed))

    assert committed == ([True], ["product_eligibility_changed"])


@pytest.mark.integration
def test_re_evaluate_product_eligibility_wrapper_survives_a_failed_event_loop(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first invocation that fails after using pooled connections (the
    per-Ticket call raises `SoftTimeLimitExceeded` after its real writes)
    still disposes the pool, so the next invocation in a new event loop
    succeeds and recalculates the rolled-back Ticket."""
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    real_service = package_service.recalculate_product_eligibility_for_ticket
    interrupted: list[UUID] = []

    async def _interrupt_first_call(
        db: AsyncSession,
        ticket_id: UUID,
        catalog_product_id: UUID,
        reason: ProductRecalculationReason,
        evaluation_date: date | None = None,
    ) -> ProductEligibilityRecalculationResult:
        result = await real_service(
            db, ticket_id, catalog_product_id, reason, evaluation_date=evaluation_date
        )
        if not interrupted:
            interrupted.append(ticket_id)
            raise SoftTimeLimitExceeded()
        return result

    async def _seed_and_drain() -> _EligibilitySeed:
        seed = await _seed_eligibility_candidate(dedicated_factory)
        await dedicated_engine.dispose()
        return seed

    async def _cleanup(seed: _EligibilitySeed) -> tuple[list[bool], list[str]]:
        committed = await _read_and_delete_eligibility_candidate(
            dedicated_factory, seed
        )
        await dedicated_engine.dispose()
        return committed

    monkeypatch.setattr(package_tasks, "engine", dedicated_engine)
    monkeypatch.setattr(package_tasks, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(
        product_eligibility_recalculation,
        "recalculate_product_eligibility_for_ticket",
        _interrupt_first_call,
    )

    seed = asyncio.run(_seed_and_drain())
    try:
        with pytest.raises(SoftTimeLimitExceeded):
            package_tasks._re_evaluate_product_eligibility_sync(
                str(seed.product_id), "threshold"
            )

        package_tasks._re_evaluate_product_eligibility_sync(
            str(seed.product_id), "threshold"
        )
    finally:
        committed = asyncio.run(_cleanup(seed))

    assert interrupted == [seed.ticket_id]
    assert committed == ([True], ["product_eligibility_changed"])


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries")
def test_run_ticket_convergence_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `run_ticket_convergence`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    succeed against one shared, pooled engine.

    Each invocation opens the read-only enumeration session through the
    module-level `async_session_factory` reference in
    `app/tasks/package_tasks.py`, so it checks a real connection out of the
    dedicated pool. The innermost domain work is trivial: the Ticket UUID
    has no package marker, and the roster holds only a test-only
    participating fetcher whose publication goes to a substituted
    `task_publication.publish_task`. Celery retries are new invocations in
    the same worker child, so the same disposal protects them. Nothing is
    written, so no cleanup is needed beyond disposing the engine.
    """
    fetcher_name = f"test_cross_loop_convergence_probe_{uuid4().hex}"
    probe_ticket_id = str(uuid4())
    published: list[dict[str, object]] = []

    class _FakeRequest:
        retries = 0

    class _FakeTask:
        """Minimal stand-in for the bound Celery Task instance (`self`),
        carrying only what `_run_ticket_convergence_sync` reads."""

        request = _FakeRequest()

        def retry(self, **kwargs: object) -> BaseException:
            raise AssertionError(f"run_ticket_convergence must not retry: {kwargs!r}")

    FETCHER_REGISTRY.clear()

    class _ConvergenceProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Cross-loop lifecycle regression probe (convergence roster)"
        default_schedule = "0 * * * *"
        participates_in_catch_up = True

        async def execute(self, session: AsyncSession) -> None:
            pass

        async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
            pass

    async def _publish(task_name: str, **options: object) -> None:
        published.append({"task_name": task_name, **options})

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(package_tasks, "engine", dedicated_engine)
    monkeypatch.setattr(package_tasks, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(task_publication, "publish_task", _publish)

    try:
        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        package_tasks._run_ticket_convergence_sync(_FakeTask(), probe_ticket_id)

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        package_tasks._run_ticket_convergence_sync(_FakeTask(), probe_ticket_id)
    finally:
        asyncio.run(dedicated_engine.dispose())

    assert (
        published
        == [
            {
                "task_name": "run_catch_up",
                "kwargs": {"fetcher_name": fetcher_name, "ticket_id": probe_ticket_id},
                "queue": None,
            }
        ]
        * 2
    )


@pytest.mark.integration
def test_backfill_product_catalog_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `backfill_product_catalog`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    succeed against one shared, pooled engine.

    Each invocation opens the read-only pair-selection session and one
    per-pair session through the module-level `async_session_factory`
    reference in `app/tasks/package_tasks.py`. One committed active Ticket
    with an included package marker makes the real selection return a
    pair; only the innermost domain operation, `add_package_to_ticket()`,
    is replaced by a trivial query on the pair session, so both sessions
    check real connections out of the dedicated pool. The shared HTTP
    client is an in-process transport that is never called. The seeded
    rows are deleted explicitly on their own event loop.
    """
    package_name = f"fictional-backfill-{uuid4().hex[:10]}"
    probed: list[tuple[UUID, str]] = []

    async def _trivial_addition(db: AsyncSession, **kwargs: object) -> object:
        await db.execute(text("SELECT 1"))
        ticket_id = kwargs["ticket_id"]
        assert isinstance(ticket_id, UUID)
        probed.append((ticket_id, str(kwargs["package_name"])))
        return SimpleNamespace(outcome=PackageRecordsOutcome.PACKAGE_TREE_NO_OP)

    def _unused_client(name: str, **options: object) -> httpx.AsyncClient:
        def _refuse(request: httpx.Request) -> httpx.Response:
            raise AssertionError("the trivial addition performs no request")

        return httpx.AsyncClient(transport=httpx.MockTransport(_refuse))

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> UUID:
        async with dedicated_factory() as session:
            ticket = Ticket(
                status=TicketStatus.ANALYSIS.value, severity_manual=Severity.HIGH.value
            )
            session.add(ticket)
            await session.flush()
            session.add(TicketPackage(ticket_id=ticket.id, package_name=package_name))
            await session.commit()
            ticket_id = ticket.id
        # Drain the seeding connection so the first real invocation does
        # not receive a connection bound to this setup loop.
        await dedicated_engine.dispose()
        return ticket_id

    async def _cleanup(ticket_id: UUID) -> None:
        async with dedicated_factory() as session:
            await session.execute(
                delete(TicketPackage).where(TicketPackage.ticket_id == ticket_id)
            )
            await session.execute(delete(Ticket).where(Ticket.id == ticket_id))
            await session.commit()
        await dedicated_engine.dispose()

    monkeypatch.setattr(package_tasks, "engine", dedicated_engine)
    monkeypatch.setattr(package_tasks, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(
        product_catalog_backfill, "add_package_to_ticket", _trivial_addition
    )
    monkeypatch.setattr(product_catalog_backfill, "create_http_client", _unused_client)

    ticket_id = asyncio.run(_seed_and_drain())
    try:
        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        package_tasks._backfill_product_catalog_sync()

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        package_tasks._backfill_product_catalog_sync()
    finally:
        asyncio.run(_cleanup(ticket_id))

    assert [pair for pair in probed if pair[0] == ticket_id] == [
        (ticket_id, package_name)
    ] * 2


class _CountingEngine:
    """Delegates `dispose()` to a real engine and counts the awaits."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self.disposals = 0

    async def dispose(self) -> None:
        self.disposals += 1
        await self._engine.dispose()


def _resolve_ticket_packages_probe(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
    *,
    fail_first: BaseException | None,
) -> list[tuple[UUID, str]]:
    """Replace only the innermost domain operation of each package unit,
    `add_package_to_ticket()`, by a trivial query on the unit session
    (raising `fail_first` once, after the query, if given); the shared HTTP
    client is an in-process transport that is never called."""
    probed: list[tuple[UUID, str]] = []
    pending = [fail_first] if fail_first is not None else []

    async def _trivial_addition(db: AsyncSession, **kwargs: object) -> object:
        await db.execute(text("SELECT 1"))
        ticket_id = kwargs["ticket_id"]
        assert isinstance(ticket_id, UUID)
        probed.append((ticket_id, str(kwargs["package_name"])))
        if pending:
            raise pending.pop()
        return SimpleNamespace(outcome=PackageRecordsOutcome.PACKAGE_TREE_NO_OP)

    def _unused_client(name: str, **options: object) -> httpx.AsyncClient:
        def _refuse(request: httpx.Request) -> httpx.Response:
            raise AssertionError("the trivial addition performs no request")

        return httpx.AsyncClient(transport=httpx.MockTransport(_refuse))

    monkeypatch.setattr(cve_tasks, "async_session_factory", factory)
    monkeypatch.setattr(package_service, "add_package_to_ticket", _trivial_addition)
    monkeypatch.setattr(package_service, "create_http_client", _unused_client)
    return probed


@pytest.mark.integration
def test_resolve_ticket_packages_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `resolve_ticket_packages`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    succeed against one shared, pooled engine and return `None`.

    Each invocation validates its primitive arguments, resolves two direct
    package names, and opens one package session per name through the
    module-level `async_session_factory` reference in
    `app/tasks/cve_tasks.py`. The trivial addition and the unit commit
    check real connections out of the dedicated pool. Nothing is written,
    so no cleanup is needed beyond disposing the engine. The engine is
    disposed exactly once per invocation.
    """
    ticket_id = uuid4()
    names = sorted(f"fictional-resolve-{uuid4().hex[:10]}" for _ in range(2))
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    counting = _CountingEngine(dedicated_engine)
    monkeypatch.setattr(cve_tasks, "engine", counting)
    probed = _resolve_ticket_packages_probe(
        monkeypatch, dedicated_factory, fail_first=None
    )
    resolve: Callable[..., object] = cve_tasks._resolve_ticket_packages_sync

    try:
        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        first = resolve(str(ticket_id), [], [], [], list(names))
        assert counting.disposals == 1

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        second = resolve(str(ticket_id), [], [], [], list(names))
        assert counting.disposals == 2
    finally:
        asyncio.run(dedicated_engine.dispose())

    assert (first, second) == (None, None)
    assert probed == [(ticket_id, name) for name in names] * 2


@pytest.mark.integration
@pytest.mark.parametrize(
    "make_error",
    [
        pytest.param(lambda: RuntimeError("fictional unit failure"), id="runtime"),
        pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    ],
)
def test_resolve_ticket_packages_wrapper_survives_a_failed_event_loop(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
    make_error: Callable[[], BaseException],
) -> None:
    """A first invocation whose package unit fails after using a pooled
    connection still disposes the pool exactly once and propagates the
    same exception object, so the next invocation in a new event loop
    succeeds."""
    error = make_error()
    ticket_id = uuid4()
    name = f"fictional-resolve-{uuid4().hex[:10]}"
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    counting = _CountingEngine(dedicated_engine)
    monkeypatch.setattr(cve_tasks, "engine", counting)
    probed = _resolve_ticket_packages_probe(
        monkeypatch, dedicated_factory, fail_first=error
    )
    resolve: Callable[..., object] = cve_tasks._resolve_ticket_packages_sync

    try:
        with pytest.raises(type(error)) as raised:
            cve_tasks._resolve_ticket_packages_sync(str(ticket_id), [], [], [], [name])
        assert raised.value is error
        assert counting.disposals == 1

        result = resolve(str(ticket_id), [], [], [], [name])
        assert counting.disposals == 2
    finally:
        asyncio.run(dedicated_engine.dispose())

    assert result is None
    assert probed == [(ticket_id, name)] * 2


def _define_fetch_single_probe(
    fetched: list[str], *, fail_first: BaseException | None
) -> str:
    """Register a test-only fetch-single CVE fetcher whose `fetch_single()`
    is the trivial innermost operation: a `SELECT 1` on the attempt session
    (raising `fail_first` once, after the query, if given), then an
    `unchanged` result without a package handoff."""
    _CVE_SOURCE_TYPE_MAP.pop(CVESourceType.NVD, None)
    probe_name = f"test_cross_loop_fetch_single_{uuid4().hex[:12]}"
    pending = [fail_first] if fail_first is not None else []

    class _FetchSingleProbeFetcher(BaseCVEFetcher):
        name = probe_name
        description = "Cross-loop lifecycle regression probe (SELECT 1 fetch)"
        default_schedule = "0 * * * *"
        cve_source_type = CVESourceType.NVD

        async def execute(self, session: AsyncSession) -> None:
            pass

        async def fetch_single(
            self, cve_id: str, session: AsyncSession
        ) -> CVEFetchResult:
            await session.execute(text("SELECT 1"))
            fetched.append(cve_id)
            if pending:
                raise pending.pop()
            return CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)

    return probe_name


@dataclass(frozen=True, slots=True)
class _FetchSingleSeed:
    """Committed rows of the `fetch_single_cve` regressions."""

    fetcher_name: str
    cve_uuid: UUID
    cve_id: str


def _fetch_single_dedicated_engine(
    _engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    fetcher_name: str,
) -> tuple[AsyncEngine, _CountingEngine, _FetchSingleSeed]:
    """Point the wrapper (and the isolated status writer) at a dedicated
    pooled engine, then commit the `FetcherConfig` row and the CVE and drain
    the seeding connection so the first real attempt does not receive a
    connection bound to this setup loop."""
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    counting = _CountingEngine(dedicated_engine)
    monkeypatch.setattr(cve_tasks, "engine", counting)
    monkeypatch.setattr(cve_tasks, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", dedicated_factory
    )

    async def _seed_and_drain() -> _FetchSingleSeed:
        async with dedicated_factory() as session:
            cve = CVE(cve_id=f"CVE-2099-{uuid4().int % 10**8:08d}")
            session.add_all([FetcherConfig(fetcher_name=fetcher_name), cve])
            await session.commit()
            seed = _FetchSingleSeed(fetcher_name, cve.id, cve.cve_id)
        await dedicated_engine.dispose()
        return seed

    return dedicated_engine, counting, asyncio.run(_seed_and_drain())


def _cleanup_fetch_single(engine: AsyncEngine, seed: _FetchSingleSeed) -> None:
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _cleanup() -> None:
        async with factory() as session:
            await session.execute(delete(CVE).where(CVE.id == seed.cve_uuid))
            await session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name == seed.fetcher_name
                )
            )
            await session.commit()
        await engine.dispose()

    asyncio.run(_cleanup())


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries", "redis_client")
def test_fetch_single_cve_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `fetch_single_cve`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    succeed against one shared, pooled engine and return `None`.

    Each attempt opens its one session through the module-level
    `async_session_factory` reference in `app/tasks/cve_tasks.py`: the
    enabled and CVE prechecks, the test-only fetcher's `SELECT 1`, the flush,
    and the `commit_and_dispatch()` commit check real connections out of the
    dedicated pool. The pending-marker client targets the worker Redis
    database (`redis_client`); the payload's marker is absent, so renewal
    and release are no-ops. The engine is disposed exactly once per attempt.
    """
    fetched: list[str] = []
    fetcher_name = _define_fetch_single_probe(fetched, fail_first=None)
    dedicated_engine, counting, seed = _fetch_single_dedicated_engine(
        _engine, monkeypatch, fetcher_name
    )
    token = secrets.token_urlsafe(32)
    fetch: Callable[..., object] = cve_tasks._fetch_single_cve_sync

    try:
        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        first = fetch(FakeTask(), seed.fetcher_name, seed.cve_id, "nvd", token)
        assert counting.disposals == 1

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        second = fetch(FakeTask(), seed.fetcher_name, seed.cve_id, "nvd", token)
        assert counting.disposals == 2
    finally:
        _cleanup_fetch_single(dedicated_engine, seed)

    assert (first, second) == (None, None)
    assert fetched == [seed.cve_id] * 2


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries", "redis_client")
def test_fetch_single_cve_wrapper_survives_a_retried_event_loop(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first attempt whose fetch fails retryably after using a pooled
    connection rolls back, disposes the pool exactly once, and raises what
    `self.retry()` returns; the retry attempt, a new event loop in the same
    process, succeeds."""
    fetched: list[str] = []
    error = httpx.ConnectError("fictional refusal")
    fetcher_name = _define_fetch_single_probe(fetched, fail_first=error)
    dedicated_engine, counting, seed = _fetch_single_dedicated_engine(
        _engine, monkeypatch, fetcher_name
    )
    token = secrets.token_urlsafe(32)
    first_attempt = FakeTask(retries=0)

    try:
        with pytest.raises(RetryRequested):
            cve_tasks._fetch_single_cve_sync(
                first_attempt, seed.fetcher_name, seed.cve_id, "nvd", token
            )
        first_attempt.retry.assert_called_once_with(exc=error, countdown=5)
        assert counting.disposals == 1

        retry: Callable[..., object] = cve_tasks._fetch_single_cve_sync
        result = retry(
            FakeTask(retries=1), seed.fetcher_name, seed.cve_id, "nvd", token
        )
        assert counting.disposals == 2
    finally:
        _cleanup_fetch_single(dedicated_engine, seed)

    assert result is None
    assert fetched == [seed.cve_id] * 2


@dataclass(frozen=True, slots=True)
class _RecalculationSeed:
    """Committed rows of the `recalculate_cvss_derived_state` regressions."""

    cve_uuid: UUID
    setting_original: str | None


async def _seed_recalculation(
    factory: async_sessionmaker[AsyncSession],
) -> _RecalculationSeed:
    """Persist `default_cvss_version = 3.1` (remembering a previous value)
    and commit one CVE, so each delivery adopts, passes the stale check,
    and runs one unit. The runner visits every persisted CVE, so the worker
    database must hold no other committed CVE."""
    async with factory() as session:
        population = select(func.count()).select_from(CVE)
        assert (await session.execute(population)).scalar_one() == 0, (
            "the worker database holds CVEs"
        )
        setting = await session.get(SystemSetting, "default_cvss_version")
        original = setting.value if setting is not None else None
        if setting is None:
            session.add(SystemSetting(key="default_cvss_version", value="3.1"))
        else:
            setting.value = "3.1"
        cve = CVE(cve_id=f"CVE-2099-{uuid4().int % 10**8:08d}")
        session.add(cve)
        await session.commit()
        return _RecalculationSeed(cve.id, original)


async def _cleanup_recalculation(
    factory: async_sessionmaker[AsyncSession], seed: _RecalculationSeed
) -> None:
    async with factory() as session:
        await session.execute(delete(CVE).where(CVE.id == seed.cve_uuid))
        if seed.setting_original is None:
            await session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
        else:
            setting = await session.get(SystemSetting, "default_cvss_version")
            assert setting is not None
            setting.value = seed.setting_original
        await session.commit()


def _admit_recalculation(redis_url: str) -> str:
    """Acquire the lease for a fresh canonical task ID on its own event
    loop, as the manual admission does."""

    async def _admit() -> str:
        client = redis_asyncio.Redis.from_url(redis_url, decode_responses=True)
        try:
            return await admit_lease(client)
        finally:
            await client.aclose()

    return asyncio.run(_admit())


def _recalculation_lease(redis_url: str) -> str | None:
    async def _read() -> str | None:
        client = redis_asyncio.Redis.from_url(redis_url, decode_responses=True)
        try:
            value: str | None = await client.get(LEASE_KEY)
            return value
        finally:
            await client.aclose()

    return asyncio.run(_read())


class _DisposalSpy:
    """Counts `dispose()` awaits of one engine, in the order of the
    captured events; the workflow disposes its factory's bind, so the
    engine itself (not a module reference) is observed."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, engine: AsyncEngine) -> None:
        self.order: list[str] = []
        dispose = AsyncEngine.dispose

        async def _dispose(self_: AsyncEngine, close: bool = True) -> None:
            if self_ is engine:
                self.order.append("dispose")
            await dispose(self_, close)

        monkeypatch.setattr(AsyncEngine, "dispose", _dispose)

    @property
    def disposals(self) -> int:
        return self.order.count("dispose")

    def record(self, logger: object, method: str, event_dict: EventDict) -> EventDict:
        """A structlog processor interleaving events with disposals."""
        self.order.append(str(event_dict["event"]))
        return event_dict


def _recalculation_probe(
    monkeypatch: pytest.MonkeyPatch, *, fail_first: BaseException | None
) -> list[UUID]:
    """Replace only the innermost domain operation of each unit,
    `ticket_mutations.recalculate_cvss_chain()`, by a trivial query on the
    unit session (raising `fail_first` once, after the query, if given)
    that classifies the unit `unchanged`. Nothing is registered, so the
    drain publishes nothing."""
    probed: list[UUID] = []
    pending = [fail_first] if fail_first is not None else []

    async def _trivial_chain(db: AsyncSession, **kwargs: object) -> object:
        await db.execute(text("SELECT 1"))
        cve_id = kwargs["cve_id"]
        assert isinstance(cve_id, UUID)
        probed.append(cve_id)
        if pending:
            raise pending.pop()
        return SimpleNamespace(
            classification=ticket_mutations.CVSSChainClassification.UNCHANGED
        )

    async def _refuse(task_name: str, **options: object) -> None:
        raise AssertionError("the trivial unit registers no convergence effect")

    monkeypatch.setattr(ticket_mutations, "recalculate_cvss_chain", _trivial_chain)
    monkeypatch.setattr(task_publication, "publish_task", _refuse)
    return probed


def _recalculation_dedicated_engine(
    _engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession], _RecalculationSeed]:
    """Point the wrapper's module-level `async_session_factory` at a
    dedicated pooled engine, then commit the seed and drain the seeding
    connection so the first real delivery does not receive a connection
    bound to this setup loop."""
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(cvss_tasks, "async_session_factory", dedicated_factory)

    async def _seed_and_drain() -> _RecalculationSeed:
        seed = await _seed_recalculation(dedicated_factory)
        await dedicated_engine.dispose()
        return seed

    return dedicated_engine, dedicated_factory, asyncio.run(_seed_and_drain())


def _finish_recalculation(
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    seed: _RecalculationSeed,
) -> None:
    async def _cleanup() -> None:
        await _cleanup_recalculation(factory, seed)
        await engine.dispose()

    asyncio.run(_cleanup())


def _deliver_recalculation(task_id: str) -> object:
    """One delivery of the real registered task with `task_id` as
    `task.request.id`, through Celery's eager tracer (which sends the real
    `task_prerun`/`task_postrun` correlation signals)."""
    task = celery_app.tasks[RECALCULATE_CVSS_DERIVED_STATE_TASK]
    return task.apply(args=["3.1"], task_id=task_id, throw=True).result


def _terminal_events(logs: list[EventDict]) -> list[tuple[str, str | None]]:
    return [
        (str(entry["event"]), entry.get("celery_task_id"))
        for entry in runner_events(logs)
        if entry["event"] in {COMPLETED_EVENT, FAILED_EVENT}
    ]


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_recalculate_cvss_derived_state_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    _redis_test_url: str,  # noqa: PT019 — value used below (lease admission)
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential deliveries of the real `recalculate_cvss_derived_state`
    synchronous wrapper — each its own `asyncio.run()` event loop — both
    complete against one shared, pooled engine and return `None`.

    Each delivery's lease is admitted on its own loop with a fresh UUIDv4
    task ID. The workflow derives its fenced connection from the factory's
    bind (the dedicated pooled engine): the fence, the setting read, the
    watermark and page reads, and the trivial unit query check real
    connections out of the dedicated pool. The workflow, not the wrapper,
    awaits `engine.dispose()` exactly once per delivery, after its terminal
    event (issue #836 U4)."""
    probed = _recalculation_probe(monkeypatch, fail_first=None)
    dedicated_engine, dedicated_factory, seed = _recalculation_dedicated_engine(
        _engine, monkeypatch
    )
    disposal = _DisposalSpy(monkeypatch, dedicated_engine)
    first_id = _admit_recalculation(_redis_test_url)

    try:
        with capture_events(disposal.record) as logs:
            # First invocation: its own event loop; the workflow disposes
            # the pool before the loop closes.
            first = _deliver_recalculation(first_id)
            assert disposal.disposals == 1
            second_id = _admit_recalculation(_redis_test_url)

            # Second invocation: a brand-new event loop. Without disposal
            # the pool would hand out a connection bound to the first
            # (closed) loop.
            second = _deliver_recalculation(second_id)
            assert disposal.disposals == 2
        delivered = list(disposal.order)
    finally:
        _finish_recalculation(dedicated_engine, dedicated_factory, seed)

    assert (first, second) == (None, None)
    assert probed == [seed.cve_uuid] * 2
    assert _terminal_events(logs) == [
        (COMPLETED_EVENT, first_id),
        (COMPLETED_EVENT, second_id),
    ]
    assert [step for step in delivered if step in {COMPLETED_EVENT, "dispose"}] == [
        COMPLETED_EVENT,
        "dispose",
    ] * 2
    assert _recalculation_lease(_redis_test_url) is None


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_recalculate_cvss_derived_state_wrapper_survives_a_failed_event_loop(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    _redis_test_url: str,  # noqa: PT019 — value used below (lease admission)
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first delivery whose unit fails after using a pooled connection
    (the trivial chain raises `TypeError` after its query) terminates
    `failed`, still disposes the pool exactly once, and the wrapper
    propagates the same exception object; the next delivery, a new event
    loop in the same process, completes."""
    error = TypeError("fictional unit failure")
    probed = _recalculation_probe(monkeypatch, fail_first=error)
    dedicated_engine, dedicated_factory, seed = _recalculation_dedicated_engine(
        _engine, monkeypatch
    )
    disposal = _DisposalSpy(monkeypatch, dedicated_engine)
    first_id = _admit_recalculation(_redis_test_url)

    try:
        with capture_events(disposal.record) as logs:
            with pytest.raises(TypeError) as raised:
                _deliver_recalculation(first_id)
            assert raised.value is error
            assert disposal.disposals == 1
            second_id = _admit_recalculation(_redis_test_url)

            result = _deliver_recalculation(second_id)
            assert disposal.disposals == 2
        delivered = list(disposal.order)
    finally:
        _finish_recalculation(dedicated_engine, dedicated_factory, seed)

    assert result is None
    assert probed == [seed.cve_uuid] * 2
    assert _terminal_events(logs) == [
        (FAILED_EVENT, first_id),
        (COMPLETED_EVENT, second_id),
    ]
    assert [
        step for step in delivered if step in {FAILED_EVENT, COMPLETED_EVENT, "dispose"}
    ] == [FAILED_EVENT, "dispose", COMPLETED_EVENT, "dispose"]
    assert _recalculation_lease(_redis_test_url) is None
