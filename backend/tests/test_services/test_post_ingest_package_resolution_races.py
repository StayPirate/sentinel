"""Independent-session and delivery tests for the post-ingest CVE
package-resolution workflow `package_service.run_post_ingest_package_resolution()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (Post-ingest CVE package
  resolution: Per-package workflow and transactions — no unlocked
  Ticket-status precheck, `active_ticket_only` termination; Idempotency,
  delivery, and recovery; Resource lifecycle on cancellation).
- docs/features/platform/testing-strategy.md (Post-Ingest Package
  Resolution: duplicate, concurrent, and reordered full invocations
  converge; worker loss and an unprocessed suffix leave no durable progress
  or automatic retry, and a later full invocation recovers without
  duplicating committed state; Concurrency Testing).
- Issue #786 decision D5: the publication-failure and simulated
  commit-to-enqueue-crash clauses exercise the publisher
  (`commit_and_dispatch()`) and are not tested here.

Every racing operation happens while one invocation is deterministically
held inside a SMELT request (a `Pause` or a barrier of the `Smelt` fake);
the Ticket lock then serializes the units. The harness, conventions, and
defaults are those of `tests/test_services/test_post_ingest_package_resolution.py`
(`tests/support/post_ingest_resolution.py`). Expected values are transcribed
from the specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import Role, TicketStatus
from app.services.package_service import (
    ValidatedCPEMatch,
)
from tests.support.package_addition import (
    Pause,
    codestream,
    maintained,
    maintainership,
    reply,
)
from tests.support.package_records import (
    maintainer_event,
)
from tests.support.package_records_races import (
    IBS_REF,
    WAIT,
    Factory,
    committed_world,
)
from tests.support.post_ingest_resolution import (
    ANALYSIS,
    CLIENT_NAME,
    COMPLETED,
    MARKER,
    Additions,
    Answer,
    Committed,
    Publish,
    Sessions,
    Smelt,
    added,
    arrive,
    assert_private,
    both,
    commit_package,
    committed,
    completed,
    created_tree,
    current_product,
    failed,
    held_response,
    http_events,
    inactive,
    install_additions,
    install_environment,
    package_names,
    record_disposals,
    record_publications,
    resolve,
    resolves,
    seed_ticket,
    seeded_tree,
    set_status,
    workflow_logs,
)
from tests.support.suse_cvss_races import CommittedWorld

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    async with committed_world(db_session_factory) as created:
        yield created


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    install_environment(monkeypatch)


@pytest.fixture(autouse=True)
def published(monkeypatch: pytest.MonkeyPatch) -> Publish:
    return record_publications(monkeypatch)


@pytest.fixture
def disposals(monkeypatch: pytest.MonkeyPatch) -> list[AsyncEngine]:
    return record_disposals(monkeypatch)


@pytest.fixture
def sessions(real_session_factory: async_sessionmaker[AsyncSession]) -> Sessions:
    return Sessions(real_session_factory)


@pytest.fixture
def additions(monkeypatch: pytest.MonkeyPatch) -> Additions:
    return install_additions(monkeypatch)


# ---------------------------------------------------------------------------
# Inactive termination between packages (no unlocked precheck)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInactiveRace:
    @pytest.mark.parametrize(
        "status", [TicketStatus.RESOLVED, TicketStatus.IGNORED], ids=str
    )
    async def test_ticket_inactivated_between_packages_stops_the_invocation(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        published: Publish,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """`a` commits; while `b` waits on its maintained request an
        independent session makes the Ticket inactive. Under the Ticket lock
        `b` commits nothing (rolled back and closed), `c` is never
        requested, and one `inactive` event replaces `completed`."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await seed_ticket(world)
        p1, p2, p3 = [await current_product(world) for _ in range(3)]
        a, b, c = package_names("a", "b", "c")
        pause = Pause()
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: Answer(
                    held_response(
                        pause, maintained(codestream(IBS_REF, "SLE_15", p2.cpe))
                    ),
                    reply(200, maintainership(m.email)),
                ),
                c: resolves(codestream(IBS_REF, "SLE_15", p3.cpe)),
            },
            sessions.events,
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(resolve(sessions, ticket.id, a, b, c))
            try:
                await arrive(pause, task)
                await set_status(world, ticket, status.value)
            finally:
                pause.release.set()
            await asyncio.wait_for(task, timeout=WAIT)

        assert sessions.events == [
            *http_events(a),
            ("commit", "0"),
            ("close", "0"),
            *http_events(b),
            ("rollback", "1"),
            ("close", "1"),
        ]
        assert workflow_logs(logs) == [
            inactive(ticket.id, 3, package_tree_changed=1, not_attempted=1)
        ]
        assert smelt.closed() == [True]
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (status.value, None),
            [added(a)],
            {a: created_tree(p1), b: None, c: None},
            [],
        )
        assert published.calls == []
        assert_private(logs, a, b, c, m.email)


# ---------------------------------------------------------------------------
# Cancellation (Resource lifecycle)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCancellation:
    async def test_cancellation_during_a_smelt_request_propagates_after_cleanup(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The workflow task is cancelled while `b` waits on its maintained
        request: cancellation propagates, `a` stays committed, the shared
        client and `b`'s session are closed, and no event is logged."""
        ticket = await seed_ticket(world)
        p1, p2 = await current_product(world), await current_product(world)
        a, b = package_names("a", "b")
        pause = Pause()
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: Answer(
                    held_response(
                        pause, maintained(codestream(IBS_REF, "SLE_15", p2.cpe))
                    )
                ),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(resolve(sessions, ticket.id, a, b))
            await arrive(pause, task)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert task.cancelled()
        assert smelt.closed() == [True]
        assert sessions.closed == [True, True]
        assert sessions.of(1) == ["close"]
        assert workflow_logs(logs) == []
        assert await committed(world, ticket.id, a, b) == Committed(
            (ANALYSIS, None), [added(a)], {a: created_tree(p1), b: None}, []
        )


# ---------------------------------------------------------------------------
# Idempotency, delivery, and recovery
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdempotencyAndRecovery:
    async def test_duplicate_sequential_delivery_is_a_complete_no_op(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The second delivery repeats both requests but creates no row,
        association, or event."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await seed_ticket(world)
        product = await current_product(world)
        (a,) = package_names("a")
        smelt = Smelt(
            {a: resolves(codestream(IBS_REF, "SLE_15", product.cpe), emails=(m.email,))}
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(Sessions(real_session_factory), ticket.id, a)
            after_first = await committed(world, ticket.id, a)
            await resolve(Sessions(real_session_factory), ticket.id, a)

        assert smelt.requests == both(a) * 2
        assert workflow_logs(logs) == [
            completed(ticket.id, 1, package_tree_changed=1),
            completed(ticket.id, 1, package_tree_no_op=1),
        ]
        assert after_first == Committed(
            (ANALYSIS, None),
            [maintainer_event(a, m), added(a)],
            {a: created_tree(product)},
            [(a, m.id)],
        )
        assert await committed(world, ticket.id, a) == after_first

    async def test_reordered_delivery_processes_the_same_order_and_converges(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        additions: Additions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The two deliveries carry the same three candidates through
        different sources and list orders (affected-entry CPE, vendor/product
        raw-product fallback, NVD CPE, direct name): both process `a`, `b`,
        `c` in that order; the second is a complete no-op."""
        ticket = await seed_ticket(world)
        p1, p2, p3 = [await current_product(world) for _ in range(3)]
        a, b, c = package_names("a", "b", "c")

        def cpe(name: str) -> str:
            return f"cpe:2.3:a:fictional_vendor:{name}:1.0:*:*:*:*:*:*:*"

        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: resolves(codestream(IBS_REF, "SLE_15", p3.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(
                Sessions(real_session_factory),
                ticket.id,
                c,
                affected_cpes=(cpe(a),),
                vendor_products=(("Fictional Vendor", b),),
            )
            first = await committed(world, ticket.id, a, b, c)
            await resolve(
                Sessions(real_session_factory),
                ticket.id,
                a,
                cpe_matches=(ValidatedCPEMatch(cpe(c), True, None),),
                vendor_products=(("Fictional Vendor", b),),
            )

        order = [call["package_name"] for call in additions.calls]
        assert order == [a, b, c, a, b, c]
        assert workflow_logs(logs) == [
            completed(ticket.id, 3, package_tree_changed=3),
            completed(ticket.id, 3, package_tree_no_op=3),
        ]
        assert first == Committed(
            (ANALYSIS, None),
            [added(a), added(b), added(c)],
            {a: created_tree(p1), b: created_tree(p2), c: created_tree(p3)},
            [],
        )
        assert await committed(world, ticket.id, a, b, c) == first

    async def test_concurrent_deliveries_converge_without_duplicates(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        published: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two invocations over the same payload are both held in `a`'s
        maintainership request, then serialize on the Ticket lock: each
        tree row, association, and event exists exactly once, each
        invocation used its own one client, and both complete with one
        package-tree change, one maintainer-only unit, and two no-ops in
        total."""
        m1, m2 = [await world.user(role=Role.RESTRICTED_ANALYST) for _ in range(2)]
        ticket = await seed_ticket(world)
        p1, p2 = await current_product(world), await current_product(world)
        a, b = package_names("a", "b")
        await commit_package(world, ticket, b, tree=((IBS_REF, p2),))
        both_arrived = asyncio.Event()
        arrivals: list[str] = []

        async def barrier(request: httpx.Request) -> httpx.Response:
            arrivals.append(a)
            if len(arrivals) == 2:
                both_arrived.set()
            await asyncio.wait_for(both_arrived.wait(), timeout=WAIT)
            return httpx.Response(200, json=maintainership(m1.email))

        smelt = Smelt(
            {
                a: Answer(
                    reply(200, maintained(codestream(IBS_REF, "SLE_15", p1.cpe))),
                    barrier,
                ),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe), emails=(m2.email,)),
            }
        )
        names = smelt.install(monkeypatch)

        with capture_logs() as logs:
            await asyncio.wait_for(
                asyncio.gather(
                    resolve(Sessions(real_session_factory), ticket.id, b, a),
                    resolve(Sessions(real_session_factory), ticket.id, a, b),
                ),
                timeout=WAIT * 4,
            )

        assert names == [CLIENT_NAME] * 2
        assert smelt.closed() == [True, True]
        assert arrivals == [a, a]
        assert sorted(smelt.requests) == sorted(both(a) * 2 + both(b) * 2)
        terminals = workflow_logs(logs)
        assert [e["event"] for e in terminals] == [COMPLETED, COMPLETED]
        assert {
            key: sum(e[key] for e in terminals)
            for key in ("package_tree_changed", "maintainer_only", "package_tree_no_op")
        } == {"package_tree_changed": 1, "maintainer_only": 1, "package_tree_no_op": 2}
        state = await committed(world, ticket.id, a, b)
        assert sorted(state.events, key=repr) == sorted(
            [maintainer_event(a, m1), added(a), maintainer_event(b, m2)], key=repr
        )
        assert state.trees == {a: created_tree(p1), b: seeded_tree(p2)}
        assert state.maintainers == sorted([(a, m1.id), (b, m2.id)])
        assert published.calls == []

    async def test_unprocessed_suffix_is_recovered_by_a_later_full_delivery(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        additions: Additions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A terminal failure in `b` leaves `a` committed and `b`, `c`
        unprocessed (no durable progress or retry). A later full delivery
        re-resolves the complete payload: `a` is a no-op and `b`, `c` are
        created, with no duplicated row or event."""
        ticket = await seed_ticket(world)
        p1, p2, p3 = [await current_product(world) for _ in range(3)]
        a, b, c = package_names("a", "b", "c")
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: resolves(codestream(IBS_REF, "SLE_15", p3.cpe)),
            }
        )
        smelt.install(monkeypatch)
        additions.after[b] = RuntimeError(MARKER)

        with capture_logs() as logs:
            with pytest.raises(RuntimeError):
                await resolve(Sessions(real_session_factory), ticket.id, a, b, c)
            interrupted = await committed(world, ticket.id, a, b, c)
            await resolve(Sessions(real_session_factory), ticket.id, a, b, c)

        assert interrupted.trees == {a: created_tree(p1), b: None, c: None}
        assert workflow_logs(logs) == [
            failed(
                ticket.id,
                "package",
                "RuntimeError",
                3,
                package_tree_changed=1,
                not_attempted=1,
            ),
            completed(ticket.id, 3, package_tree_changed=2, package_tree_no_op=1),
        ]
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (ANALYSIS, None),
            [added(a), added(b), added(c)],
            {a: created_tree(p1), b: created_tree(p2), c: created_tree(p3)},
            [],
        )

    async def test_worker_loss_mid_run_is_recovered_by_a_later_delivery(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A delivery cancelled while `b` waits on SMELT (simulated worker
        loss) keeps `a` committed and nothing of `b`; a later delivery
        creates `b` and leaves `a` unchanged."""
        ticket = await seed_ticket(world)
        p1, p2 = await current_product(world), await current_product(world)
        a, b = package_names("a", "b")
        pause = Pause()
        held = held_response(pause, maintained(codestream(IBS_REF, "SLE_15", p2.cpe)))
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: Answer(held),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(
                resolve(Sessions(real_session_factory), ticket.id, a, b)
            )
            await arrive(pause, task)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=WAIT)
            lost = await committed(world, ticket.id, a, b)
            smelt.answers[b] = resolves(codestream(IBS_REF, "SLE_15", p2.cpe))
            await resolve(Sessions(real_session_factory), ticket.id, a, b)

        assert lost.trees == {a: created_tree(p1), b: None}
        assert workflow_logs(logs) == [
            completed(ticket.id, 2, package_tree_changed=1, package_tree_no_op=1)
        ]
        assert await committed(world, ticket.id, a, b) == Committed(
            (ANALYSIS, None),
            [added(a), added(b)],
            {a: created_tree(p1), b: created_tree(p2)},
            [],
        )
