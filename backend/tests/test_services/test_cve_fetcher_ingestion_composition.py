"""The complete CVE ingestion transaction finalized by a CVE fetcher: the
real `cve_service.upsert_cve()` and `reference_service.upsert_references()`
inside a test-only `fetch_single()`, finalized by the default
`BaseCVEFetcher.catch_up()` through the real `run_catch_up_async` workflow
(backend/app/services/base_cve_fetcher.py, backend/app/tasks/fetchers.py).

Owning specifications:

- docs/features/platform/cve-fetcher-infrastructure.md (Per-CVE
  Finalization; Session Lifecycle for API-based CVE Fetchers: "The helper
  commits the session, releases the CVE and Ticket roots ..." and the
  `resolve_ticket_packages` handoff; Default `catch_up()` implementation).
- docs/features/tickets/cve-service.md (Post-Commit Package-Candidate
  Handoff; CVE Upsert Serialization; Complete `upsert_cve()` Composition,
  the `REJECTED -> PUBLISHED` reopen of an `Ignored` Ticket).
- docs/features/tickets/ticket-service.md (`reopen_from_ignored()`
  CVE-ingestion composition: the reopen registers one Ticket convergence
  effect).
- docs/features/packages/package-service.md (Post-ingest CVE package
  resolution: Idempotency, delivery, and recovery).
- docs/features/platform/testing-strategy.md (CVE Ingestion and Ticket
  Composition: phase order through the sole commit and post-commit effects;
  rollback, definite commit failure, and pre-commit cancellation publish
  nothing; successful commit releases locks before publication; no HTTP,
  Redis, Celery, or DNS while CVE/Ticket locks are held. Post-Ingest Package
  Resolution, last bullet: publication failure and a simulated
  commit-to-enqueue crash leave no invented durable progress, and a later
  full invocation recovers without duplicating committed state). Issue #786
  decision D5 assigned those two clauses to the publisher's tests.

Every test ingests a republication: a committed `REJECTED` `High` CVE whose
`Ignored` Ticket is reopened by `upsert_cve()` when the payload carries
`PUBLISHED`, so the Ticket convergence registration is produced by
ingestion itself, never registered by the test. The payload carries one
direct package-name candidate, so the finalizer also publishes the package
handoff.

The harness is `tests/support/cve_catch_up.py`: the workflow and isolated
status sessions are recording substitutes over `real_session_factory`
sharing one ordered event list with the publication substitute and the
drain spy. Lock probes use the independent `probe` session of an
`IngestionWorld` (`SELECT ... FOR UPDATE NOWAIT`, `lock_not_available()`).
Recovery reuses the post-ingest resolution harness
(`tests/support/post_ingest_resolution.py`): the in-process SMELT fake and
the committed-state observation. Committed rows are deleted explicitly at
teardown. All identifiers, names, and hosts are fictional.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import celery
import celery.app.task
import pytest
import redis
import redis.asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import CVESourceFetchStatus, CveState, Severity, TicketStatus
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import (
    HANDOFF_PUBLICATION_FAILED_EVENT,
    CVEFetchResult,
)
from app.services.cve_ingest import CVEIngestPayload
from app.services.package_service import (
    parse_post_ingest_arguments,
    run_post_ingest_package_resolution,
)
from app.services.reference_service import AutomaticReferenceInput
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    CONVERGE,
    RESOLVE,
    CatchUpHarness,
    CVEProbe,
    Step,
    counters,
    fetcher_run_count,
    install_harness,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld, lock_not_available
from tests.support.no_outbound import OutboundGuard
from tests.support.package_addition import codestream
from tests.support.package_records_races import IBS_REF
from tests.support.post_ingest_resolution import (
    Committed,
    Smelt,
    added,
    both,
    committed,
    created_tree,
    current_product,
    install_environment,
    package_names,
    resolves,
)
from tests.support.ticket_mutations import status_event

pytest_plugins = ["tests.support.no_outbound_fixtures"]
"""Provides the `no_outbound` fixture."""

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

SessionFactory = Callable[[], Awaitable[AsyncSession]]

REJECTED_AT = datetime(2099, 3, 4, tzinfo=UTC)
IGNORED = TicketStatus.IGNORED.value
ANALYSIS = TicketStatus.ANALYSIS.value
PACKAGE_EVENTS = frozenset({"package_added", "package_maintainer_added"})

_SOURCE_URL = "https://nvd.example.test/vuln/detail/{cve_id}"
_UPSTREAM_URL = "https://vendor.example.test/advisory/0001"


class _CommitFailureError(Exception):
    """An injected definite commit failure."""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def harness(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    installed = install_harness(monkeypatch, real_session_factory)
    try:
        yield installed
    finally:
        await installed.cleanup()


@pytest.fixture
def broker_and_cache(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Failing substitutes at the Celery publication and Redis command
    boundaries; each blocked call is recorded before it raises. The
    finalizer's broker call is `task_publication.publish_task`, which the
    harness substitutes, so any real broker call is a violation."""
    attempts: list[str] = []

    def forbid(name: str) -> Callable[..., Any]:
        def _call(*args: Any, **kwargs: Any) -> Any:
            attempts.append(name)
            raise AssertionError(f"{name} called during ingestion")

        return _call

    async def forbid_async(*args: Any, **kwargs: Any) -> Any:
        attempts.append("asyncio.Redis.execute_command")
        raise AssertionError("asyncio.Redis.execute_command called during ingestion")

    monkeypatch.setattr(celery.Celery, "send_task", forbid("Celery.send_task"))
    monkeypatch.setattr(celery.app.task.Task, "apply_async", forbid("Task.apply_async"))
    monkeypatch.setattr(redis.Redis, "execute_command", forbid("Redis.execute_command"))
    monkeypatch.setattr(redis.asyncio.Redis, "execute_command", forbid_async)
    return attempts


# ---------------------------------------------------------------------------
# The republication and its scripted ingestion
# ---------------------------------------------------------------------------


@dataclass
class _Republication:
    """A committed `REJECTED` `High` CVE with its `Ignored` Ticket, and the
    observations of the ingestion that republishes it."""

    cve: CVE
    ticket: Ticket
    package: str
    tokens: list[CVEFetchResult] = field(default_factory=list)
    locked_in_fetch: list[tuple[bool, bool]] = field(default_factory=list)
    at_publication: list[tuple[str, bool, tuple[bool, bool]]] = field(
        default_factory=list
    )

    @property
    def payload(self) -> CVEIngestPayload:
        return CVEIngestPayload(
            cve_state=CveState.PUBLISHED, resolved_packages=[self.package]
        )


async def _republication(world: IngestionWorld) -> _Republication:
    cve = await world.cve_in(
        state=CveState.REJECTED, date_rejected=REJECTED_AT, severity=Severity.HIGH
    )
    ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.IGNORED)
    (package,) = package_names("resolved")
    return _Republication(cve, ticket, package)


async def _root_locks_held(
    world: IngestionWorld, cve_id: uuid.UUID, ticket_id: uuid.UUID
) -> tuple[bool, bool]:
    """Whether another transaction holds the CVE and the Ticket row lock,
    probed `FOR UPDATE NOWAIT` from the independent probe session."""
    return (
        await lock_not_available(
            world.probe,
            select(CVE.id).where(CVE.id == cve_id).with_for_update(nowait=True),
        ),
        await lock_not_available(
            world.probe,
            select(Ticket.id)
            .where(Ticket.id == ticket_id)
            .with_for_update(nowait=True),
        ),
    )


def _ingest(
    world: IngestionWorld,
    probe: CVEProbe,
    target: _Republication,
    *,
    fail_after_references: BaseException | None = None,
) -> Step:
    """`fetch_single()` composing the real ingestion (cve-fetcher-
    infrastructure.md, the inline Session Lifecycle template): upsert,
    automatic references, then the token with the pure handoff."""

    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        fetcher = probe.fetcher
        payload = target.payload
        result = await cve_service.upsert_cve(
            session, cve_id, fetcher.cve_source_type, payload
        )
        probe.events.append("upsert")
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            fetcher.name,
            AutomaticReferenceInput(url=_SOURCE_URL.format(cve_id=cve_id)),
            [AutomaticReferenceInput(url=_UPSTREAM_URL, title="Vendor advisory")],
        )
        probe.events.append("references")
        target.locked_in_fetch.append(
            await _root_locks_held(world, target.cve.id, target.ticket.id)
        )
        if fail_after_references is not None:
            raise fail_after_references
        token = CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, payload)
        )
        target.tokens.append(token)
        return token

    return step


def _observe_publications(
    world: IngestionWorld, harness: CatchUpHarness, target: _Republication
) -> None:
    """Record, at each publication, whether the catch-up session is still in
    a transaction and whether either root lock is still held."""

    async def before(call: dict[str, Any]) -> None:
        target.at_publication.append(
            (
                call["task_name"],
                harness.catch_up_session.in_transaction(),
                await _root_locks_held(world, target.cve.id, target.ticket.id),
            )
        )

    harness.published.before = before


async def _cve_state(
    factory: async_sessionmaker[AsyncSession], cve_id: uuid.UUID
) -> tuple[str, datetime | None]:
    async with factory() as session:
        row = (
            await session.execute(
                select(CVE.cve_state, CVE.date_rejected).where(CVE.id == cve_id)
            )
        ).one()
    return row[0], row[1]


async def _ticket_status(
    factory: async_sessionmaker[AsyncSession], ticket_id: uuid.UUID
) -> str:
    async with factory() as session:
        status: str = (
            await session.execute(select(Ticket.status).where(Ticket.id == ticket_id))
        ).scalar_one()
    return status


async def _reference_urls(
    factory: async_sessionmaker[AsyncSession], ticket_id: uuid.UUID
) -> set[str]:
    async with factory() as session:
        rows = await session.scalars(
            select(TicketReference.url).where(TicketReference.ticket_id == ticket_id)
        )
        return set(rows.all())


def _broker_round_trip(kwargs: dict[str, Any]) -> dict[str, Any]:
    """The task arguments as a JSON-serializing broker delivers them."""
    delivered: dict[str, Any] = json.loads(json.dumps(kwargs))
    return delivered


async def _resolve(
    factory: async_sessionmaker[AsyncSession], kwargs: dict[str, Any]
) -> None:
    """One full `resolve_ticket_packages` workflow invocation with the
    delivered primitive arguments."""
    arguments = parse_post_ingest_arguments(**kwargs)
    await run_post_ingest_package_resolution(
        ticket_id=arguments.ticket_id,
        cpe_matches=arguments.cpe_matches,
        affected_cpes=arguments.affected_cpes,
        vendor_products=arguments.vendor_products,
        resolved_packages=arguments.resolved_packages,
        session_factory=factory,
    )


# ---------------------------------------------------------------------------
# Phase order, lock release, and no external I/O under the root locks
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestionFinalization:
    async def test_one_phase_order_through_the_sole_commit_and_post_commit_effects(
        self,
        world: IngestionWorld,
        harness: CatchUpHarness,
        no_outbound: OutboundGuard,
        broker_and_cache: list[str],
    ) -> None:
        """Upsert, references, flush, the finalizer's sole commit, then the
        convergence registered by the reopen and only then the package
        handoff. Both root locks are held during the fetch and released
        before the first publication; no HTTP, DNS, Redis, or Celery call
        happens at any point of the catch-up."""
        target = await _republication(world)
        probe = await harness.fetcher()
        probe.step = _ingest(world, probe, target)
        _observe_publications(world, harness, target)

        await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert harness.events[0] == "fetch_single"
        start = harness.events.index("upsert")
        assert harness.events[start:] == [
            "upsert",
            "references",
            "flush",
            "commit_and_dispatch",
            "commit",
            "drain",
            f"publish:{CONVERGE}",
            f"publish:{RESOLVE}",
        ]
        assert "rollback" not in harness.events
        assert harness.status.opened == []
        assert probe.flushed_at_finalization == [True]
        # The convergence is the one registered by the reopen itself.
        assert harness.published.published(CONVERGE) == [
            {"ticket_id": str(target.ticket.id)}
        ]
        (handoff,) = harness.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(target.ticket.id)
        assert handoff["resolved_packages"] == [target.package]
        # Locks held while ingesting; released before every publication.
        assert target.locked_in_fetch == [(True, True)]
        assert target.at_publication == [
            (CONVERGE, False, (False, False)),
            (RESOLVE, False, (False, False)),
        ]
        assert no_outbound.attempts == []
        assert broker_and_cache == []
        # The committed ingestion.
        assert await _cve_state(harness.factory, target.cve.id) == ("PUBLISHED", None)
        assert await _ticket_status(harness.factory, target.ticket.id) == ANALYSIS
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _reference_urls(harness.factory, target.ticket.id) == {
            _SOURCE_URL.format(cve_id=target.cve.cve_id),
            _UPSTREAM_URL,
        }
        assert counters(probe.fetcher) == (0, 0, 0, 0)

    @pytest.mark.parametrize(
        "path", ["rollback", "pre-commit-cancellation", "commit-failure"]
    )
    async def test_uncommitted_ingestion_publishes_neither_effect(
        self, world: IngestionWorld, harness: CatchUpHarness, path: str
    ) -> None:
        """A pre-commit error (rolled back), a pre-commit cancellation, and a
        definitely failed commit discard the reopen's registration and the
        handoff: nothing is drained or published and nothing is committed
        but, after the rollback, the isolated `failure` status."""
        target = await _republication(world)
        probe = await harness.fetcher()
        error: BaseException = {
            "rollback": RuntimeError("example reference failure"),
            "pre-commit-cancellation": asyncio.CancelledError(),
            "commit-failure": _CommitFailureError(),
        }[path]
        if path == "commit-failure":
            harness.sessions.failures["commit"] = error
            probe.step = _ingest(world, probe, target)
        else:
            probe.step = _ingest(world, probe, target, fail_after_references=error)

        with pytest.raises(type(error)) as raised:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert raised.value is error
        assert target.locked_in_fetch == [(True, True)]
        assert harness.published.calls == []
        assert "drain" not in harness.events
        assert await _cve_state(harness.factory, target.cve.id) == (
            "REJECTED",
            REJECTED_AT,
        )
        assert await _ticket_status(harness.factory, target.ticket.id) == IGNORED
        assert await _reference_urls(harness.factory, target.ticket.id) == set()
        state = await source_state(harness.factory, target.cve.id)
        if path == "rollback":
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE
        else:
            assert state is None
            assert harness.status.opened == []


# ---------------------------------------------------------------------------
# Publication failure and commit-to-enqueue crash recovery (issue #786 D5;
# package-service.md, Idempotency, delivery, and recovery)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHandoffLossRecovery:
    async def _assert_no_package_progress(
        self,
        world: IngestionWorld,
        harness: CatchUpHarness,
        target: _Republication,
        redis_client: redis.asyncio.Redis,
    ) -> Committed:
        """The committed ingestion is intact and nothing beyond it exists:
        no package row or association, no package audit event, no Redis key,
        and no `FetcherRun`."""
        state = await committed(world, target.ticket.id, target.package)
        assert state.ticket == (ANALYSIS, None)
        assert state.trees == {target.package: None}
        assert state.maintainers == []
        assert status_event(IGNORED, ANALYSIS) in state.events
        assert not {event.event_type for event in state.events} & PACKAGE_EVENTS
        assert await _cve_state(harness.factory, target.cve.id) == ("PUBLISHED", None)
        source = await source_state(harness.factory, target.cve.id)
        assert source is not None
        assert source.status == CVESourceFetchStatus.SUCCESS
        assert await redis_client.keys("*") == []
        assert await fetcher_run_count(harness.factory, harness.names[-1]) == 0
        return state

    async def _assert_recovery(
        self,
        world: IngestionWorld,
        harness: CatchUpHarness,
        target: _Republication,
        before: Committed,
        kwargs: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A later full invocation with the same primitive arguments creates
        the package once; a second one duplicates nothing."""
        product = await current_product(world)
        smelt = Smelt(
            {target.package: resolves(codestream(IBS_REF, "SLE_15", product.cpe))}
        )
        smelt.install(monkeypatch)
        harness.published.errors.clear()
        recovered = Committed(
            before.ticket,
            [*before.events, added(target.package)],
            {target.package: created_tree(product)},
            [],
        )

        await _resolve(harness.factory, kwargs)
        first = await committed(world, target.ticket.id, target.package)
        await _resolve(harness.factory, kwargs)

        assert first == recovered
        assert await committed(world, target.ticket.id, target.package) == recovered
        assert smelt.requests == both(target.package) * 2

    async def test_handoff_broker_failure_leaves_no_progress_and_is_recoverable(
        self,
        world: IngestionWorld,
        harness: CatchUpHarness,
        redis_client: redis.asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        install_environment(monkeypatch)
        target = await _republication(world)
        probe = await harness.fetcher()
        probe.step = _ingest(world, probe, target)
        harness.published.errors[RESOLVE] = BrokerOperationalError(
            "example broker outage"
        )

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert [entry["event"] for entry in logs if entry["log_level"] == "error"] == [
            HANDOFF_PUBLICATION_FAILED_EVENT
        ]
        assert [call["task_name"] for call in harness.published.calls] == [
            CONVERGE,
            RESOLVE,
        ]
        before = await self._assert_no_package_progress(
            world, harness, target, redis_client
        )
        (attempted,) = harness.published.published(RESOLVE)

        await self._assert_recovery(
            world,
            harness,
            target,
            before,
            _broker_round_trip(attempted),
            monkeypatch,
        )

    @pytest.mark.parametrize("crash_at", [CONVERGE, RESOLVE])
    async def test_commit_to_enqueue_crash_leaves_no_progress_and_is_recoverable(
        self,
        world: IngestionWorld,
        harness: CatchUpHarness,
        redis_client: redis.asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        crash_at: str,
    ) -> None:
        """The process is lost (simulated by cancellation) while enqueueing
        right after the commit: at the first post-commit publication, or at
        the handoff itself. The handoff never reaches the broker; recovery
        uses the same primitive arguments the finalizer derives from the
        committed token."""
        install_environment(monkeypatch)
        target = await _republication(world)
        probe = await harness.fetcher()
        probe.step = _ingest(world, probe, target)
        harness.published.errors[crash_at] = asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        attempted = [call["task_name"] for call in harness.published.calls]
        assert attempted == (
            [CONVERGE] if crash_at == CONVERGE else [CONVERGE, RESOLVE]
        )
        assert "rollback" not in harness.events
        assert harness.status.opened == []
        before = await self._assert_no_package_progress(
            world, harness, target, redis_client
        )
        (token,) = target.tokens
        assert token.post_ingest is not None
        arguments = dataclasses.asdict(token.post_ingest)
        if crash_at == RESOLVE:
            assert harness.published.published(RESOLVE) == [arguments]

        await self._assert_recovery(
            world,
            harness,
            target,
            before,
            _broker_round_trip(arguments),
            monkeypatch,
        )
