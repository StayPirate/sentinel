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
from dataclasses import dataclass
from datetime import UTC, date, datetime
from uuid import UUID, uuid4

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.services.base_fetcher as base_fetcher_module
from app.core.enums import PackageStatus, Severity, TicketStatus
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, task_publication
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.package_service import (
    ProductEligibilityRecalculationResult,
    ProductRecalculationReason,
)
from app.services.packages import product_eligibility_recalculation
from app.tasks import fetchers as fetchers_module
from app.tasks import package_tasks, session_cleanup


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
