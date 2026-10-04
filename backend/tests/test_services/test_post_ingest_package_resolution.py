"""Integration tests for the post-ingest CVE package-resolution workflow
`package_service.run_post_ingest_package_resolution()`
(backend/app/services/package_service.py): empty and failed candidate
resolution, package units, the outcome table, terminal failures, the
locked inactive check, and control signals.

Owning specifications:

- docs/features/packages/package-service.md (Post-ingest CVE package
  resolution: Deterministic candidate resolution; Per-package workflow and
  transactions with its outcome table; Resource lifecycle; Audit and
  observability; `add_package_to_ticket()` `audit_comment`,
  `active_ticket_only`, and `allow_excluded_reresolution`; Architectural
  Test Requirement bullets "Maintainership acquisition" and "Package audit
  comments").
- docs/features/tickets/ticket-audit-log.md (`package_added` with
  `user_id = NULL` and the `CVE package resolution` comment;
  `package_maintainer_added`; the workflow creates no event of its own).
- docs/features/platform/testing-strategy.md (Post-Ingest Package
  Resolution; Concurrency Testing: explicit cleanup of committed rows;
  Audit Trail Testing).
- Issue #786 decisions D2 (the workflow events carry only the Ticket UUID,
  bounded counts, and a bounded cause or category) and D3 (a failing
  rollback while handling an expected or isolated outcome fails the task).

Independent-session races, duplicate, concurrent, and reordered deliveries,
and recovery after worker loss or an unprocessed suffix are in
`tests/test_services/test_post_ingest_package_resolution_races.py`; the
shared harness is `tests/support/post_ingest_resolution.py`.

The workflow owns its sessions, so it receives a recording `Sessions`
factory over `real_session_factory` (one session per package, in
processing order) whose `commit`, `rollback`, and `close` are recorded in
one ordered event list shared with the `Smelt` fake. Every test seeds a
`CommittedWorld` whose rows are deleted explicitly at teardown. SMELT is the
in-process fake behind the substituted `package_service.create_http_client()`;
creating a client without installing it fails the test.
`task_publication.publish_task` is substituted by a recorder.

Unless a test states otherwise: a Ticket is a committed unassigned CVE-less
`Analysis` Ticket with `severity_manual = High`; a catalog Product is in
General Support on `EVAL` with a `NULL` threshold and is published in the
current snapshot, so a created occurrence is eligible; maintainers are
active `restricted_analyst` Users; the payload carries only direct package
names. Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import PackageStatus, Role, TicketStatus, WorkflowType
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.services import (
    package_service,
    ticket_convergence_registry,
    ticket_mutations,
)
from app.services.cpe_mapping import CPEMappingLoadError
from app.services.package_service import (
    SYSTEM_INVOCATION,
    ValidatedCPEMatch,
)
from app.services.ticket_audit_log import TicketAuditLog
from tests.support.package_addition import (
    codestream,
    fail,
    maintained,
    not_found,
    reply,
)
from tests.support.package_records import (
    NEW_TRACK,
    SEEDED_AT,
    Tree,
    maintainer_event,
    new_occurrence,
)
from tests.support.package_records_races import (
    GIT_REF,
    IBS_REF,
    Factory,
    committed_world,
)
from tests.support.post_ingest_resolution import (
    ABSENT,
    ANALYSIS,
    ANALYZED,
    CLIENT_NAME,
    CVE_RESOLUTION,
    EMPTY,
    EXCLUDED,
    MARKER,
    NO_MATCH,
    Additions,
    Answer,
    Committed,
    Publish,
    Sessions,
    Smelt,
    added,
    assert_private,
    both,
    commit_package,
    committed,
    completed,
    count_rows,
    created_tree,
    current_product,
    database_failure,
    fail_on,
    failed,
    http_events,
    inactive,
    install_additions,
    install_environment,
    package_failed,
    package_names,
    partial,
    record_disposals,
    record_publications,
    resolve,
    resolves,
    rollback_raises,
    seed_ticket,
    seeded_tree,
    single,
    workflow_logs,
)
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import status_event

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
# Empty final set and resolver failure (Deterministic candidate resolution)
# ---------------------------------------------------------------------------

EMPTY_PAYLOADS: list[Any] = [
    pytest.param({}, id="every-list-empty"),
    pytest.param(
        {"names": ("x", "-fictional", "fictional-", "pkgé", "..")},
        id="only-invalid-names",
    ),
    pytest.param(
        {
            "cpe_matches": (
                ValidatedCPEMatch(f"cpe:/a:fictional:{MARKER}", True, None),
            ),
            "affected_cpes": ("not-a-cpe",),
        },
        id="only-malformed-cpes",
    ),
    pytest.param(
        {"vendor_products": (("fictional", "*"), ("-", "-"))},
        id="only-non-concrete-pairs",
    ),
]


@pytest.mark.integration
class TestEmptyAndResolverFailure:
    @pytest.mark.parametrize("payload", EMPTY_PAYLOADS)
    async def test_empty_final_set_succeeds_without_session_client_or_request(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        published: Publish,
        disposals: list[AsyncEngine],
        monkeypatch: pytest.MonkeyPatch,
        payload: dict[str, Any],
    ) -> None:
        ticket = await seed_ticket(world)
        before = await committed(world, ticket.id)
        smelt = Smelt({})
        names = smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(
                sessions,
                ticket.id,
                *payload.get("names", ()),
                cpe_matches=payload.get("cpe_matches", ()),
                affected_cpes=payload.get("affected_cpes", ()),
                vendor_products=payload.get("vendor_products", ()),
            )

        assert workflow_logs(logs) == [single(EMPTY, ticket.id)]
        assert sessions.sessions == []
        assert names == []
        assert smelt.requests == []
        assert published.calls == []
        assert disposals == []
        assert (
            await committed(world, ticket.id)
            == before
            == Committed((ANALYSIS, None), [], {}, [])
        )
        assert_private(logs)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: CPEMappingLoadError(f"/fictional/{MARKER}.json", MARKER),
                id="mapping-load-error",
            ),
            pytest.param(lambda: RuntimeError(MARKER), id="unexpected"),
        ],
    )
    @pytest.mark.parametrize(
        "resolver", ["resolve_cpe_packages", "resolve_vendor_product"]
    )
    async def test_resolver_failure_terminates_before_any_package_unit(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        published: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
        resolver: str,
    ) -> None:
        """Valid direct names accompany the failing resolver input: no
        package session, client, SMELT request, or mutation, so no
        committed prefix exists; the failure carries only the cause."""
        ticket = await seed_ticket(world)
        error = make_error()

        def _failing(*_args: str) -> set[str]:
            raise error

        monkeypatch.setattr(package_service, resolver, _failing)
        smelt = Smelt({})
        names = smelt.install(monkeypatch)
        a, b = package_names("a", "b")

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await resolve(
                sessions,
                ticket.id,
                a,
                b,
                affected_cpes=("cpe:2.3:a:example:alpha:1:*:*:*:*:*:*:*",),
                vendor_products=(("example", "beta"),),
            )

        assert raised.value is error
        assert workflow_logs(logs) == [
            failed(ticket.id, "resolution", type(error).__name__, 0)
        ]
        assert sessions.sessions == []
        assert names == []
        assert smelt.requests == []
        assert published.calls == []
        assert await committed(world, ticket.id, a, b) == Committed(
            (ANALYSIS, None), [], {a: None, b: None}, []
        )
        assert_private(logs, a, b)


# ---------------------------------------------------------------------------
# Successful package units (Per-package workflow and transactions)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSuccessfulUnits:
    async def test_each_package_commits_in_its_own_session_as_a_system_unit(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        additions: Additions,
        published: Publish,
        disposals: list[AsyncEngine],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Candidates `c`, `a`, `b` are processed as `a`, `b`, `c`: `a` is a
        package-tree change, `b` a complete-tree no-op, and `c` a
        maintainer-only mutation (one `package_maintainer_added`, no
        `package_added`, assignment, or status change). Each unit receives
        a fresh session and the one shared client as a system invocation
        with the exact comment, active-only mode, and the excluded-package
        guard, and is committed and closed before the next package's first
        request. One `completed` event, no publication, no `FetcherRun`,
        and no engine disposal."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await seed_ticket(world)
        p1, p2, p3 = [await current_product(world) for _ in range(3)]
        a, b, c = package_names("a", "b", "c")
        await commit_package(world, ticket, b, tree=((IBS_REF, p2),))
        await commit_package(world, ticket, c, tree=((IBS_REF, p3),))
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: resolves(codestream(IBS_REF, "SLE_15", p3.cpe), emails=(m.email,)),
            },
            sessions.events,
        )
        names = smelt.install(monkeypatch)
        runs_before = await count_rows(world, FetcherRun)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, c, a, b)

        assert names == [CLIENT_NAME]
        (client,) = smelt.fake.clients
        assert client.is_closed
        assert [call["package_name"] for call in additions.calls] == [a, b, c]
        assert all(
            (
                call["ticket_id"],
                call["acting_user_id"],
                call["caller"],
                call["audit_comment"],
                call["active_ticket_only"],
                call["allow_excluded_reresolution"],
                call["http_client"],
            )
            == (ticket.id, None, SYSTEM_INVOCATION, CVE_RESOLUTION, True, False, client)
            for call in additions.calls
        )
        assert [call["db"] for call in additions.calls] == sessions.sessions
        assert len({id(s) for s in sessions.sessions}) == 3
        assert sessions.closed == [True, True, True]
        assert sessions.events == [
            *http_events(a),
            ("commit", "0"),
            ("close", "0"),
            *http_events(b),
            ("commit", "1"),
            ("close", "1"),
            *http_events(c),
            ("commit", "2"),
            ("close", "2"),
        ]
        assert workflow_logs(logs) == [
            completed(
                ticket.id,
                3,
                package_tree_changed=1,
                package_tree_no_op=1,
                maintainer_only=1,
            )
        ]
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (ANALYSIS, None),
            [added(a), maintainer_event(c, m)],
            {a: created_tree(p1), b: seeded_tree(p2), c: seeded_tree(p3)},
            [(c, m.id)],
        )
        assert published.calls == []
        assert disposals == []
        assert await count_rows(world, FetcherRun) == runs_before
        assert_private(logs, a, b, c, m.email, m.username)

    async def test_candidates_from_every_source_reach_one_unit_each(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        additions: Additions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The same package name produced by an NVD CPE, an affected-entry
        CPE, a vendor/product pair (raw-product fallback), and a direct name
        is one candidate; an invalid resolver result never reaches SMELT."""
        ticket = await seed_ticket(world)
        product = await current_product(world)
        (a,) = package_names("a")
        cpe = f"cpe:2.3:a:fictional_vendor:{a}:1.0:*:*:*:*:*:*:*"
        smelt = Smelt({a: resolves(codestream(IBS_REF, "SLE_15", product.cpe))})
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(
                sessions,
                ticket.id,
                a,
                cpe_matches=(ValidatedCPEMatch(cpe, False, None),),
                affected_cpes=(cpe, "cpe:2.3:a:fictional_vendor:-x-:1:*:*:*:*:*:*:*"),
                vendor_products=(("Fictional Vendor", a),),
            )

        assert smelt.requests == both(a)
        assert [call["package_name"] for call in additions.calls] == [a]
        assert workflow_logs(logs) == [completed(ticket.id, 1, package_tree_changed=1)]
        assert (await committed(world, ticket.id, a)).trees == {
            a: created_tree(product)
        }
        assert_private(logs, a)

    async def test_analyzed_regression_registers_and_publishes_no_convergence(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        published: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A new `ANALYSIS` track on an `Analyzed` Ticket regresses it to
        `Analysis` through ordinary reconciliation, but registers no Ticket
        convergence effect and publishes nothing (issue #786, Convergence)."""
        ticket = await seed_ticket(world, status=TicketStatus.ANALYZED)
        p1, p2 = await current_product(world), await current_product(world)
        existing, a = package_names("existing", "a")
        await commit_package(
            world,
            ticket,
            existing,
            tree=((IBS_REF, p1),),
            status=PackageStatus.NOT_AFFECTED,
        )
        smelt = Smelt({a: resolves(codestream(IBS_REF, "SLE_15", p2.cpe))})
        smelt.install(monkeypatch)
        registered: list[uuid.UUID] = []
        real_register = ticket_convergence_registry.register_ticket_convergence

        def _register(session: AsyncSession, ticket_id: uuid.UUID) -> None:
            registered.append(ticket_id)
            real_register(session, ticket_id)

        monkeypatch.setattr(ticket_mutations, "register_ticket_convergence", _register)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, a)

        assert workflow_logs(logs) == [completed(ticket.id, 1, package_tree_changed=1)]
        state = await committed(world, ticket.id, a)
        assert (state.ticket, state.events, state.trees) == (
            (ANALYSIS, None),
            [added(a), status_event(ANALYZED, ANALYSIS)],
            {a: created_tree(p2)},
        )
        assert registered == []
        assert published.calls == []


# ---------------------------------------------------------------------------
# Expected and isolated outcomes (the outcome table)
# ---------------------------------------------------------------------------

OUTCOMES = [
    "excluded",
    "no-match",
    "targets-unresolved",
    "catalog-not-ready",
    "smelt-unavailable-http",
    "smelt-unavailable-transport",
]


@pytest.mark.integration
class TestOutcomeTable:
    @pytest.mark.parametrize("outcome", OUTCOMES)
    async def test_outcome_is_rolled_back_logged_and_followed_by_the_next_package(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        published: Publish,
        monkeypatch: pytest.MonkeyPatch,
        outcome: str,
    ) -> None:
        """The first package `a` has the outcome; its session is rolled back
        and closed before the second package `b` is requested, and `b`
        commits its tree. An expected skip (excluded, no match) completes
        normally; an isolated failure logs its cause (and the bounded SMELT
        category) and makes the invocation partial.

        `excluded` is a committed directly excluded marker for which SMELT
        resolves a target and a maintainer: the locked guard skips it
        without completing descendants or associating the maintainer.
        `catalog-not-ready` starts without any Product; `b`'s maintained
        request publishes the first current Product."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await seed_ticket(world)
        a, b = package_names("a", "b")
        products: list[Product] = []
        if outcome == "catalog-not-ready":
            assert await count_rows(world, Product) == 0

            async def ready_then_resolve(request: httpx.Request) -> httpx.Response:
                products.append(await current_product(world))
                return httpx.Response(
                    200,
                    json=maintained(codestream(IBS_REF, "SLE_15", products[0].cpe)),
                )

            second = Answer(ready_then_resolve)
        else:
            products.append(await current_product(world))
            second = resolves(codestream(IBS_REF, "SLE_15", products[0].cpe))
        if outcome == "excluded":
            await commit_package(world, ticket, a, excluded=True)
        first = {
            "excluded": resolves(
                codestream(IBS_REF, "SLE_15", products[0].cpe if products else ABSENT),
                emails=(m.email,),
            ),
            "no-match": Answer(reply(404, not_found(MARKER))),
            "targets-unresolved": resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "catalog-not-ready": resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "smelt-unavailable-http": Answer(
                reply(500, {"status": "error", "data": MARKER})
            ),
            "smelt-unavailable-transport": Answer(
                fail(httpx.ConnectError(f"https://smelt.example.test/{MARKER}"))
            ),
        }[outcome]
        smelt = Smelt({a: first, b: second}, sessions.events)
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, b, a)

        per_package = {
            "excluded": single(EXCLUDED, ticket.id),
            "no-match": single(NO_MATCH, ticket.id),
            "targets-unresolved": package_failed(
                ticket.id, "PackageTargetsUnresolvedError"
            ),
            "catalog-not-ready": package_failed(
                ticket.id, "ProductCatalogNotReadyError"
            ),
            "smelt-unavailable-http": package_failed(
                ticket.id, "SmeltUnavailableError", "http_status"
            ),
            "smelt-unavailable-transport": package_failed(
                ticket.id, "SmeltUnavailableError", "transport"
            ),
        }[outcome]
        terminal = {
            "excluded": completed(ticket.id, 2, package_tree_changed=1, excluded=1),
            "no-match": completed(ticket.id, 2, package_tree_changed=1, no_match=1),
        }.get(outcome, partial(ticket.id, 2, package_tree_changed=1, package_failed=1))
        first_requests = (
            http_events(a) if outcome == "excluded" else http_events(a, "maintained")
        )
        assert sessions.events == [
            *first_requests,
            ("rollback", "0"),
            ("close", "0"),
            *http_events(b),
            ("commit", "1"),
            ("close", "1"),
        ]
        assert workflow_logs(logs) == [per_package, terminal]
        assert smelt.closed() == [True]
        assert await committed(world, ticket.id, a, b) == Committed(
            (ANALYSIS, None),
            [added(b)],
            {
                a: Tree(SEEDED_AT, {}, {}) if outcome == "excluded" else None,
                b: created_tree(products[0]),
            },
            [],
        )
        assert published.calls == []
        assert_private(logs, a, b, m.email, m.username)

    async def test_only_expected_skips_and_no_ops_complete_without_partial(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No-match, excluded, and no-op outcomes alone produce `completed`
        with their counts and no mutation or audit event."""
        ticket = await seed_ticket(world)
        product = await current_product(world)
        a, b, c = package_names("a", "b", "c")
        await commit_package(world, ticket, b, excluded=True)
        await commit_package(world, ticket, c, tree=((IBS_REF, product),))
        answer = resolves(codestream(IBS_REF, "SLE_15", product.cpe))
        smelt = Smelt({a: Answer(reply(404, not_found(a))), b: answer, c: answer})
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, a, b, c)

        assert workflow_logs(logs) == [
            single(NO_MATCH, ticket.id),
            single(EXCLUDED, ticket.id),
            completed(ticket.id, 3, package_tree_no_op=1, no_match=1, excluded=1),
        ]
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (ANALYSIS, None),
            [],
            {a: None, b: Tree(SEEDED_AT, {}, {}), c: seeded_tree(product)},
            [],
        )


# ---------------------------------------------------------------------------
# Terminal failures (outcome table: unexpected errors; issue #786 D3)
# ---------------------------------------------------------------------------

TERMINAL_FAILURES = ["database", "commit", "audit", "delegated", "programming"]


@pytest.mark.integration
class TestTerminalFailures:
    @pytest.mark.parametrize("failure", TERMINAL_FAILURES)
    async def test_unexpected_error_rolls_back_the_unit_and_fails_the_task(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        additions: Additions,
        published: Publish,
        disposals: list[AsyncEngine],
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The second of three packages fails: `database` and `commit`
        inject a driver error into its flush or commit, `audit` makes its
        `package_added` write fail, `delegated` raises from the delegated
        service before any request, and `programming` raises a `TypeError`
        after the real locked writes. The unit is rolled back and closed,
        one `failed` event preserves the earlier outcome and the
        not-attempted remainder, the exception propagates unchanged, `a`
        stays committed, and `c` is never requested."""
        ticket = await seed_ticket(world)
        p1, p2, p3 = [await current_product(world) for _ in range(3)]
        a, b, c = package_names("a", "b", "c")
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: resolves(codestream(IBS_REF, "SLE_15", p3.cpe)),
            },
            sessions.events,
        )
        smelt.install(monkeypatch)
        error: BaseException
        if failure == "database":
            sessions.hooks[1] = lambda s: fail_on(s, "before_flush")
            error_type: type[BaseException] = OperationalError
        elif failure == "commit":
            sessions.hooks[1] = lambda s: fail_on(s, "before_commit")
            error_type = OperationalError
        elif failure == "audit":
            error = RuntimeError(MARKER)
            error_type = RuntimeError
            real_log = TicketAuditLog.log_event

            async def _failing_audit(session: AsyncSession, **kwargs: Any) -> None:
                if kwargs["new_value"] == b:
                    raise error
                await real_log(session, **kwargs)

            monkeypatch.setattr(TicketAuditLog, "log_event", _failing_audit)
        elif failure == "delegated":
            error = RuntimeError(MARKER)
            error_type = RuntimeError
            additions.before[b] = error
        else:
            error = TypeError(MARKER)
            error_type = TypeError
            additions.after[b] = error

        with capture_logs() as logs, pytest.raises(error_type) as raised:
            await resolve(sessions, ticket.id, a, b, c)

        if failure in {"audit", "delegated", "programming"}:
            assert raised.value is error
        b_requests = [] if failure == "delegated" else http_events(b)
        b_unit = ["commit"] if failure == "commit" else []
        assert sessions.events == [
            *http_events(a),
            ("commit", "0"),
            ("close", "0"),
            *b_requests,
            *[(op, "1") for op in [*b_unit, "rollback", "close"]],
        ]
        assert len(sessions.sessions) == 2
        assert smelt.closed() == [True]
        assert workflow_logs(logs) == [
            failed(
                ticket.id,
                "package",
                error_type.__name__,
                3,
                package_tree_changed=1,
                not_attempted=1,
            )
        ]
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (ANALYSIS, None), [added(a)], {a: created_tree(p1), b: None, c: None}, []
        )
        assert published.calls == []
        assert disposals == []
        assert_private(logs, a, b, c)

    @pytest.mark.parametrize("outcome", ["excluded", "no-match", "targets-unresolved"])
    async def test_failing_rollback_of_an_expected_or_isolated_outcome_fails(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
        outcome: str,
    ) -> None:
        """Issue #786 D3: the rollback of `a`'s expected or isolated outcome
        raises a driver error, which terminates the task as a database
        failure: no per-package event, `b` is never requested, the session
        is still closed."""
        ticket = await seed_ticket(world)
        product = await current_product(world)
        a, b = package_names("a", "b")
        if outcome == "excluded":
            await commit_package(world, ticket, a, excluded=True)
        first = {
            "excluded": resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            "no-match": Answer(reply(404, not_found(a))),
            "targets-unresolved": resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
        }[outcome]
        smelt = Smelt(
            {a: first, b: resolves(codestream(IBS_REF, "SLE_15", product.cpe))}
        )
        smelt.install(monkeypatch)
        sessions.hooks[0] = rollback_raises(database_failure())

        with capture_logs() as logs, pytest.raises(OperationalError):
            await resolve(sessions, ticket.id, a, b)

        assert workflow_logs(logs) == [
            failed(ticket.id, "package", "OperationalError", 2, not_attempted=1)
        ]
        assert [kind for kind, name in smelt.requests if name == b] == []
        assert sessions.closed == [True]
        assert smelt.closed() == [True]
        assert (await committed(world, ticket.id, b)).trees == {b: None}
        assert_private(logs, a, b)

    async def test_failing_rollback_never_masks_the_primary_commit_failure(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await seed_ticket(world)
        product = await current_product(world)
        (a,) = package_names("a")
        smelt = Smelt({a: resolves(codestream(IBS_REF, "SLE_15", product.cpe))})
        smelt.install(monkeypatch)
        rollback_error = RuntimeError("fictional rollback failure")

        def _hook(session: AsyncSession) -> None:
            fail_on(session, "before_commit")
            rollback_raises(rollback_error)(session)

        sessions.hooks[0] = _hook

        with capture_logs() as logs, pytest.raises(OperationalError):
            await resolve(sessions, ticket.id, a)

        assert workflow_logs(logs) == [
            failed(ticket.id, "package", "OperationalError", 1)
        ]
        assert sessions.closed == [True]
        assert (await committed(world, ticket.id, a)).trees == {a: None}


# ---------------------------------------------------------------------------
# Inactive termination (no unlocked precheck)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInactiveTermination:
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.RESOLVED, TicketStatus.IGNORED, TicketStatus.DUPLICATED],
        ids=str,
    )
    async def test_inactive_ticket_is_detected_only_under_the_lock(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """There is no unlocked status precheck: for a Ticket inactive from
        the start, the first package's SMELT requests are made (diagnostic
        only), then the locked skip terminates without mutation, audit, or
        maintainer association, and the second package is never
        requested."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        original = await seed_ticket(world)
        ticket = await seed_ticket(
            world,
            status=status,
            duplicate_of=original.id if status is TicketStatus.DUPLICATED else None,
        )
        product = await current_product(world)
        a, b = package_names("a", "b")
        answer = resolves(codestream(IBS_REF, "SLE_15", product.cpe), emails=(m.email,))
        smelt = Smelt({a: answer, b: answer})
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, a, b)

        assert smelt.requests == both(a)
        assert workflow_logs(logs) == [inactive(ticket.id, 2, not_attempted=1)]
        assert sessions.closed == [True]
        assert await committed(world, ticket.id, a, b) == Committed(
            (status.value, None), [], {a: None, b: None}, []
        )

    async def test_inactive_after_an_isolated_failure_is_not_partial(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`inactive` is the only terminal event even when an earlier
        package had an isolated failure; the counts preserve it."""
        ticket = await seed_ticket(world, status=TicketStatus.RESOLVED)
        product = await current_product(world)
        a, b = package_names("a", "b")
        smelt = Smelt(
            {
                a: Answer(reply(500, {"status": "error", "data": MARKER})),
                b: resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await resolve(sessions, ticket.id, a, b)

        assert workflow_logs(logs) == [
            package_failed(ticket.id, "SmeltUnavailableError", "http_status"),
            inactive(ticket.id, 2, package_failed=1),
        ]


# ---------------------------------------------------------------------------
# Control signals (outcome table, last row)
# ---------------------------------------------------------------------------

SIGNALS = [
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


@pytest.mark.integration
class TestControlSignals:
    @pytest.mark.parametrize("make_signal", SIGNALS)
    async def test_signal_inside_a_unit_propagates_after_cleanup(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        additions: Additions,
        published: Publish,
        disposals: list[AsyncEngine],
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """`b` raises the signal after its locked writes: the signal
        propagates unchanged, `b` is closed without commit, `a` stays
        committed, `c` is never attempted, the shared client is closed, and
        no workflow event is logged."""
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
        signal = make_signal()
        additions.after[b] = signal

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await resolve(sessions, ticket.id, a, b, c)

        assert raised.value is signal
        assert smelt.requests == [*both(a), *both(b)]
        assert sessions.of(1) == ["close"]
        assert sessions.closed == [True, True]
        assert smelt.closed() == [True]
        assert workflow_logs(logs) == []
        assert await committed(world, ticket.id, a, b, c) == Committed(
            (ANALYSIS, None), [added(a)], {a: created_tree(p1), b: None, c: None}, []
        )
        assert published.calls == []
        assert disposals == []

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_signal_from_an_isolated_rollback_propagates(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        ticket = await seed_ticket(world)
        product = await current_product(world)
        a, b = package_names("a", "b")
        smelt = Smelt(
            {
                a: Answer(reply(404, not_found(a))),
                b: resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            }
        )
        smelt.install(monkeypatch)
        signal = make_signal()
        sessions.hooks[0] = rollback_raises(signal)

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await resolve(sessions, ticket.id, a, b)

        assert raised.value is signal
        assert workflow_logs(logs) == []
        assert smelt.requests == [("maintained", a)]
        assert sessions.closed == [True]
        assert smelt.closed() == [True]

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_signal_from_a_resolver_propagates_before_any_unit(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """A control signal during candidate resolution is not a resolver
        failure: no `failed` event, no session, client, or request."""
        ticket = await seed_ticket(world)
        signal = make_signal()

        def _raising(*_args: str) -> set[str]:
            raise signal

        monkeypatch.setattr(package_service, "resolve_cpe_packages", _raising)
        smelt = Smelt({})
        names = smelt.install(monkeypatch)
        (a,) = package_names("a")

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await resolve(
                sessions,
                ticket.id,
                a,
                affected_cpes=("cpe:2.3:a:example:alpha:1:*:*:*:*:*:*:*",),
            )

        assert raised.value is signal
        assert workflow_logs(logs) == []
        assert sessions.sessions == []
        assert names == []
        assert smelt.requests == []

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_signal_from_a_commit_propagates_without_a_failed_event(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """`a`'s commit raises the signal: it propagates unchanged, `a` is
        not committed, `b` is never requested, and the session and client
        are closed."""
        ticket = await seed_ticket(world)
        p1, p2 = await current_product(world), await current_product(world)
        a, b = package_names("a", "b")
        smelt = Smelt(
            {
                a: resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
            }
        )
        smelt.install(monkeypatch)
        signal = make_signal()

        def _commit_raises(session: AsyncSession) -> None:
            async def _commit() -> None:
                raise signal

            setattr(session, "commit", _commit)  # noqa: B010

        sessions.hooks[0] = _commit_raises

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await resolve(sessions, ticket.id, a, b)

        assert raised.value is signal
        assert workflow_logs(logs) == []
        assert smelt.requests == both(a)
        assert sessions.closed == [True]
        assert smelt.closed() == [True]
        assert await committed(world, ticket.id, a, b) == Committed(
            (ANALYSIS, None), [], {a: None, b: None}, []
        )

    async def test_signal_from_the_rollback_of_a_terminal_failure_propagates(
        self,
        world: CommittedWorld,
        sessions: Sessions,
        additions: Additions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unexpected unit error whose rollback raises
        `SoftTimeLimitExceeded`: the signal wins, without a `failed`
        event, and the session and client are closed."""
        ticket = await seed_ticket(world)
        product = await current_product(world)
        (a,) = package_names("a")
        smelt = Smelt({a: resolves(codestream(IBS_REF, "SLE_15", product.cpe))})
        smelt.install(monkeypatch)
        additions.after[a] = RuntimeError(MARKER)
        signal = SoftTimeLimitExceeded()
        sessions.hooks[0] = rollback_raises(signal)

        with capture_logs() as logs, pytest.raises(SoftTimeLimitExceeded) as raised:
            await resolve(sessions, ticket.id, a)

        assert raised.value is signal
        assert workflow_logs(logs) == []
        assert sessions.closed == [True]
        assert smelt.closed() == [True]
        assert await committed(world, ticket.id, a) == Committed(
            (ANALYSIS, None), [], {a: None}, []
        )


@pytest.mark.integration
async def test_git_track_creation_publishes_nothing(
    world: CommittedWorld,
    sessions: Sessions,
    published: Publish,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A unit that creates both an IBS and a Git track commits them with
    one `package_added` and still publishes nothing: the workflow detaches
    no post-commit effect of its own (issue #786, Convergence)."""
    ticket = await seed_ticket(world)
    p1, p2 = await current_product(world), await current_product(world)
    (a,) = package_names("a")
    smelt = Smelt(
        {
            a: resolves(
                codestream(IBS_REF, "SLE_15", p1.cpe),
                codestream(GIT_REF, "SLFO", p2.cpe),
            )
        }
    )
    smelt.install(monkeypatch)

    await resolve(sessions, ticket.id, a)

    assert await committed(world, ticket.id, a) == Committed(
        (ANALYSIS, None),
        [added(a)],
        {
            a: Tree(
                None,
                {
                    IBS_REF: NEW_TRACK[WorkflowType.IBS],
                    GIT_REF: NEW_TRACK[WorkflowType.GIT],
                },
                {
                    (IBS_REF, p1.id): new_occurrence(True),
                    (GIT_REF, p2.id): new_occurrence(True),
                },
            )
        },
        [],
    )
    assert published.calls == []
