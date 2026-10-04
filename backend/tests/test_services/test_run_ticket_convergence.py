"""Integration tests for the Ticket convergence workflow
`package_service.run_ticket_convergence()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`run_ticket_convergence()`
  workflow, unit isolation as aligned by the K10 option (b) refinement;
  Concurrency Control: internal re-resolution racing with exclusion;
  Architectural Test Requirement bullets "Ticket convergence workflow",
  "Maintainership acquisition" (convergence path), "Package audit
  comments", and the convergence half of "Concurrent direct mutations").
- docs/features/packages/package-model.md (IBS Workflow Applicability and
  Convergence > Ticket Convergence; Acceleration and permanent recovery
  ownership).
- docs/features/packages/package-maintainership.md (Acquisition Workflow >
  Invocation boundary; Recovery and Accepted Limitations; Testing
  Requirements: package-tree no-op acquisition for Ticket convergence).
- docs/features/platform/fetcher-infrastructure.md (Per-Ticket Catch-Up:
  Post-commit enqueue and queue routing, Invocation points).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff: the convergence per-package owner; Concurrency
  Testing: explicit cleanup of committed rows).
- docs/features/tickets/ticket-audit-log.md (`package_added` with the
  `Ticket convergence` comment and `user_id = NULL`;
  `package_maintainer_added`; the workflow creates no event of its own).

The workflow owns its sessions, so it receives a recording factory over
`real_session_factory` (index 0 is the enumeration session, then one
session per package unit), and every test seeds a `CommittedWorld` whose
rows are deleted explicitly at teardown. SMELT is the in-process
`PackageSmelt` fake, routed per package name, behind the substituted
`create_http_client()`; `task_publication.publish_task` is substituted by
a recorder; the fetcher registries are isolated and emptied, so the
catch-up roster contains only the probe fetchers a test defines.

Unless a test states otherwise: a Ticket is the committed unassigned
CVE-less `Analysis` Ticket with `severity_manual = High`; a catalog
Product is in General Support on `EVAL` with a `NULL` threshold and is
published in the current snapshot (`SNAPSHOT_AT`), so a created
occurrence is eligible; maintainers are active `restricted_analyst`
Users. Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
from celery import Celery
from celery.exceptions import OperationalError as BrokerOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from redis.asyncio import Redis
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.services import package_service, task_publication
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.package_service import (
    TICKET_CONVERGENCE_HTTP_CLIENT_NAME,
    PackageAddedComment,
    TicketConvergencePhase,
    restore_ticket_package,
    run_ticket_convergence,
    ticket_convergence_failure_phase,
)
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition
from tests.support.package_addition import (
    MAINTAINED_PATH,
    PackageSmelt,
    Pause,
    Respond,
    codestream,
    maintained,
    maintainership,
    not_found,
    publish,
    reply,
)
from tests.support.package_exclusion import (
    MARKER_NOW,
    SEEDED_AT,
    Direction,
    Level,
    committed_path,
    patch_marker_now,
    path_call,
    path_event,
)
from tests.support.package_records import (
    NEW_TRACK,
    OccurrenceState,
    TrackState,
    Tree,
    maintainer_event,
    maintainers,
    new_occurrence,
    package_added_event,
    package_tree,
    seed_occurrence,
    seed_package,
    seed_track,
    ticket_row,
)
from tests.support.package_records_races import (
    GIT_REF,
    IBS_REF,
    WAIT,
    Factory,
    committed_world,
    path_tree,
    world_product,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss import assignment_event
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)

LogEntry = MutableMapping[str, Any]

CONVERGENCE: PackageAddedComment = "Ticket convergence"
"""The canonical `package_added` comment of a convergence unit."""

ABSENT = "cpe:/o:example:absent:1"
"""A CPE that no catalog Product carries."""

ANALYSIS = TicketStatus.ANALYSIS.value
RESOLVED = TicketStatus.RESOLVED.value

COMPLETED = "ticket_convergence_completed"
PARTIAL = "ticket_convergence_completed_with_package_failures"
PACKAGE_FAILED = "ticket_convergence_package_failed"
PUBLICATION_FAILED = "ticket_convergence_publication_failed"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every creation reads."""
    async with committed_world(db_session_factory) as created:
        yield created


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is `EVAL`, an exclusion sets `MARKER_NOW`, and
    both SMELT clients build their URLs from the fictional test origin."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    patch_marker_now(monkeypatch)
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


@pytest.fixture(autouse=True)
def _empty_roster(isolated_fetcher_registries: None) -> None:
    """The catch-up roster contains only the probe fetchers a test defines."""
    FETCHER_REGISTRY.clear()


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call as
    `{"task_name": ..., **options}`; `fail` selects the error of a call."""

    events: list[tuple[str, str]] | None = None
    fail: Callable[[dict[str, Any]], BaseException | None] | None = None
    on_call: Callable[[dict[str, Any]], Awaitable[None]] | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        if self.events is not None:
            self.events.append(("publish", task_name))
        if self.on_call is not None:
            await self.on_call(call)
        error = self.fail(call) if self.fail is not None else None
        if error is not None:
            raise error

    def of(self, task_name: str) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["task_name"] == task_name]


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


class _Sessions:
    """Session factory passed to the workflow: delegates to the real
    factory and records every session it opens (index 0 is enumeration,
    then one per package unit). `hooks[index]` instruments one session
    before the workflow uses it; `events` receives `("commit", index)` after
    each successful commit."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.hooks: dict[int, Callable[[AsyncSession], None]] = {}
        self.events: list[tuple[str, str]] | None = None

    def __call__(self) -> AsyncSession:
        index = len(self.sessions)
        session = self._factory()
        events = self.events
        if events is not None:

            def _committed(_session: Session) -> None:
                events.append(("commit", str(index)))

            event.listen(session.sync_session, "after_commit", _committed)
        if index in self.hooks:
            self.hooks[index](session)
        self.sessions.append(session)
        return session

    def maker(self) -> async_sessionmaker[AsyncSession]:
        return cast(async_sessionmaker[AsyncSession], self)


@pytest.fixture
def sessions(real_session_factory: async_sessionmaker[AsyncSession]) -> _Sessions:
    return _Sessions(real_session_factory)


def _database_failure() -> OperationalError:
    return OperationalError(
        "fictional statement", None, Exception("fictional connection reset")
    )


def _fail_on(session: AsyncSession, event_name: str) -> None:
    """Make `event_name` of the session raise a driver-level error."""

    def _raise(*_args: Any) -> None:
        raise _database_failure()

    event.listen(session.sync_session, event_name, _raise)


# ---------------------------------------------------------------------------
# Fake SMELT routed per package
# ---------------------------------------------------------------------------


def _package_of(request: httpx.Request) -> str:
    segments = request.url.path.split("/")
    return segments[-1] if MAINTAINED_PATH in request.url.path else segments[-2]


@dataclass
class _Answer:
    """The responses for one package name."""

    maintained: Respond
    maintainership: Respond = field(
        default_factory=lambda: reply(200, maintainership())
    )


def _resolves(*entries: dict[str, Any], emails: tuple[str, ...] = ()) -> _Answer:
    return _Answer(
        reply(200, maintained(*entries)), reply(200, maintainership(*emails))
    )


class _Smelt:
    """A `PackageSmelt` whose responses are chosen by the package name of
    each request; `events` receives `("http", "<kind>:<package>")`."""

    def __init__(
        self,
        answers: dict[str, _Answer],
        events: list[tuple[str, str]] | None = None,
    ) -> None:
        self.answers = answers
        self.events = events
        self.fake = PackageSmelt(
            maintained=self._route("maintained"),
            maintainership=self._route("maintainership"),
        )

    def _route(self, kind: str) -> Respond:
        async def respond(request: httpx.Request) -> httpx.Response:
            name = _package_of(request)
            if self.events is not None:
                self.events.append(("http", f"{kind}:{name}"))
            answer = self.answers[name]
            response = getattr(answer, kind)(request)
            if inspect.isawaitable(response):
                response = await response
            return cast(httpx.Response, response)

        return respond

    @property
    def requests(self) -> list[tuple[str, str]]:
        """`(kind, package)` of every request, in order."""
        return [(kind, _package_of(r)) for kind, r in self.fake.requests]

    def install(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        """Make `create_http_client()` return a client of this fake; return
        the list of requested client names."""
        names: list[str] = []

        def _factory(name: str, **overrides: Any) -> httpx.AsyncClient:
            names.append(name)
            return self.fake.client()

        monkeypatch.setattr(package_service, "create_http_client", _factory)
        return names


def _both(name: str) -> list[tuple[str, str]]:
    return [("maintained", name), ("maintainership", name)]


# ---------------------------------------------------------------------------
# Committed seeding and observation
# ---------------------------------------------------------------------------


def _names(*tags: str) -> list[str]:
    suffix = uuid.uuid4().hex[:8]
    return [f"fictional-{tag}-{suffix}" for tag in tags]


async def _ticket(
    world: CommittedWorld,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    is_confidential: bool = False,
) -> Ticket:
    return await world.ticket(
        cve_id=None,
        status=status,
        severity_manual=Severity.HIGH,
        is_confidential=is_confidential,
    )


async def _current_product(world: CommittedWorld) -> Product:
    """A committed catalog Product published in the current snapshot."""
    product = await world_product(world)
    await publish(world.session, product)
    await world.session.commit()
    return product


async def _publish_product(world: CommittedWorld, product_id: uuid.UUID) -> None:
    product = await world.session.get(Product, product_id)
    assert product is not None
    await publish(world.session, product)
    await world.session.commit()


async def _package(
    world: CommittedWorld,
    ticket: Ticket,
    name: str,
    *,
    excluded: bool = False,
    tree: tuple[tuple[str, Product], ...] = (),
    status: PackageStatus = PackageStatus.ANALYSIS,
) -> uuid.UUID:
    """Commit a package marker with an optional complete tree."""
    package = await seed_package(world.session, ticket.id, name, excluded=excluded)
    for reference, product in tree:
        track = await seed_track(world.session, package, reference, status=status)
        await seed_occurrence(world.session, track, product)
    await world.session.commit()
    return package.id


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket `(status, assignee)`, its events, the trees of
    the given packages, and every maintainer association."""

    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]
    trees: dict[str, Tree | None]
    maintainers: list[tuple[str, uuid.UUID]]


async def _committed(
    world: CommittedWorld, ticket_id: uuid.UUID, *names: str
) -> _Committed:
    probe = await world.open_session()
    state = _Committed(
        await ticket_row(probe, ticket_id),
        await ticket_events_by_id(probe, ticket_id),
        {name: await package_tree(probe, ticket_id, name) for name in names},
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


async def _count(world: CommittedWorld, model: type[Any]) -> int:
    probe = await world.open_session()
    count = (await probe.execute(select(func.count()).select_from(model))).scalar_one()
    await probe.rollback()
    return count


def _created(product: Product) -> Tree:
    """An included marker completed with a new `IBS_REF` track holding one
    new eligible occurrence (package-service.md, Record Creation Logic)."""
    return Tree(
        None,
        {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
        {(IBS_REF, product.id): new_occurrence(True)},
    )


def _seeded_tree(reference: str, product: Product, deleted_at: Any = None) -> Tree:
    """A seeded `ANALYSIS`/`PENDING` track with one eligible occurrence."""
    return Tree(
        deleted_at,
        {reference: TrackState("ibs", "ANALYSIS", "PENDING", None)},
        {(reference, product.id): OccurrenceState(True, False, None, None)},
    )


EMPTY_TREE = Tree(None, {}, {})
"""A package marker without tracks."""


def _convergence_logs(logs: list[LogEntry]) -> list[LogEntry]:
    return [e for e in logs if str(e["event"]).startswith("ticket_convergence")]


def _completed(
    ticket_id: uuid.UUID,
    *,
    packages: int,
    converged: int,
    failed: int = 0,
    stale: int = 0,
    catch_ups: int = 0,
) -> LogEntry:
    return {
        "event": PARTIAL if failed else COMPLETED,
        "log_level": "warning" if failed else "info",
        "ticket_id": str(ticket_id),
        "packages": packages,
        "packages_converged": converged,
        "packages_failed": failed,
        "packages_stale": stale,
        "catch_ups_dispatched": catch_ups,
    }


def _package_failed(ticket_id: uuid.UUID, name: str, cause: str) -> LogEntry:
    return {
        "event": PACKAGE_FAILED,
        "log_level": "warning",
        "ticket_id": str(ticket_id),
        "package_name": name,
        "cause": cause,
    }


# ---------------------------------------------------------------------------
# Catch-up roster probes
# ---------------------------------------------------------------------------


def _participant(fetcher_name: str, fetcher_queue: str | None) -> None:
    """Register a participating fetcher with the given class `queue`."""

    class _Participant(BaseFetcher):
        name = fetcher_name
        description = "Ticket convergence roster probe"
        default_schedule = "0 * * * *"
        queue = fetcher_queue
        participates_in_catch_up = True

        async def execute(self, session: AsyncSession) -> None:
            raise AssertionError("never executed")

        async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
            raise AssertionError("never executed")


def _non_participant(fetcher_name: str) -> None:
    class _NonParticipant(BaseFetcher):
        name = fetcher_name
        description = "Ticket convergence roster probe (no catch-up)"
        default_schedule = "0 * * * *"

        async def execute(self, session: AsyncSession) -> None:
            raise AssertionError("never executed")


def _roster_names(*tags: str) -> list[str]:
    suffix = uuid.uuid4().hex[:8]
    return [f"test_convergence_roster_{tag}_{suffix}" for tag in tags]


def _catch_up(name: str, ticket_id: uuid.UUID, queue: str | None) -> dict[str, Any]:
    return {
        "task_name": "run_catch_up",
        "kwargs": {"fetcher_name": name, "ticket_id": str(ticket_id)},
        "queue": queue,
    }


# ---------------------------------------------------------------------------
# Enumeration, delegated resolution, audit, and structural absences
# (package-service.md, `run_ticket_convergence()` steps 1-2; package-model.md,
# Ticket Convergence phase 2; package-maintainership.md, Invocation boundary)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEnumerationAndResolution:
    async def test_every_marker_is_re_resolved_in_name_order_through_one_client(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Three package markers committed out of name order: `a` without a
        tree (SMELT now resolves one track with maintainer M1), `b`
        directly excluded with a complete tree (maintainer M2), and `c`
        included with a complete tree (maintainer M3). Every name is
        enumerated once, including the soft-deleted marker, in name order;
        each unit performs both SMELT requests through the one shared
        client of the invocation, which is closed at the end; each unit
        commits in its own session. Only `package_added` (`NULL` user,
        `Ticket convergence`) and `package_maintainer_added` events are
        created, `b` keeps its marker without a restoration event, the
        package-tree no-ops of `b` and `c` add their maintainers, and no
        `FetcherRun`, Redis, or broker work occurs."""
        brokered: list[str] = []

        async def _redis(*args: Any, **kwargs: Any) -> Any:
            brokered.append("redis")
            raise AssertionError("the workflow must perform no Redis I/O")

        def _broker(*args: Any, **kwargs: Any) -> Any:
            brokered.append("broker")
            raise AssertionError("the workflow publishes only through publish_task")

        monkeypatch.setattr(Redis, "execute_command", _redis)
        monkeypatch.setattr(Celery, "send_task", _broker)
        m1, m2, m3 = [await world.user(role=Role.RESTRICTED_ANALYST) for _ in range(3)]
        ticket = await _ticket(world)
        p1, p2, p3 = [await _current_product(world) for _ in range(3)]
        a, b, c = _names("a", "b", "c")
        await _package(world, ticket, c, tree=((IBS_REF, p3),))
        await _package(world, ticket, a)
        await _package(world, ticket, b, excluded=True, tree=((IBS_REF, p2),))
        smelt = _Smelt(
            {
                a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe), emails=(m1.email,)),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe), emails=(m2.email,)),
                c: _resolves(codestream(IBS_REF, "SLE_15", p3.cpe), emails=(m3.email,)),
            }
        )
        names = smelt.install(monkeypatch)
        runs_before = await _count(world, FetcherRun)

        with capture_logs() as logs:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert names == [TICKET_CONVERGENCE_HTTP_CLIENT_NAME]
        assert len(smelt.fake.clients) == 1
        assert smelt.fake.clients[0].is_closed
        assert smelt.requests == [*_both(a), *_both(b), *_both(c)]
        assert len({id(s) for s in sessions.sessions}) == 4
        assert _convergence_logs(logs) == [
            _completed(ticket.id, packages=3, converged=3)
        ]
        assert await _committed(world, ticket.id, a, b, c) == _Committed(
            (ANALYSIS, None),
            [
                maintainer_event(a, m1),
                package_added_event(a, None, CONVERGENCE),
                maintainer_event(b, m2),
                maintainer_event(c, m3),
            ],
            {
                a: _created(p1),
                b: _seeded_tree(IBS_REF, p2, deleted_at=SEEDED_AT),
                c: _seeded_tree(IBS_REF, p3),
            },
            sorted([(a, m1.id), (b, m2.id), (c, m3.id)]),
        )
        assert await _count(world, FetcherRun) == runs_before
        assert brokered == []
        assert published.calls == []

    async def test_a_soft_deleted_marker_gains_a_latent_association(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On a confidential Ticket, a directly excluded package gains the
        maintainer M's association, but it grants M (effective scope
        `non_confidential`) no visibility until an authorized restore
        clears the marker; the workflow itself never restores."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, is_confidential=True)
        product = await _current_product(world)
        (name,) = _names("excluded")
        package_id = await _package(
            world, ticket, name, excluded=True, tree=((IBS_REF, product),)
        )
        smelt = _Smelt(
            {
                name: _resolves(
                    codestream(IBS_REF, "SLE_15", product.cpe), emails=(m.email,)
                )
            }
        )
        smelt.install(monkeypatch)

        async def visible_to_m() -> bool:
            probe = await world.open_session()
            found = (
                await probe.execute(
                    select(Ticket.id).where(
                        Ticket.id == ticket.id,
                        ticket_visibility_condition(
                            TicketCaller.authenticated(m.id, Scope.NON_CONFIDENTIAL)
                        ),
                    )
                )
            ).scalar_one_or_none()
            await probe.rollback()
            return found is not None

        await run_ticket_convergence(
            ticket_id=ticket.id, session_factory=sessions.maker()
        )

        state = await _committed(world, ticket.id, name)
        assert state.maintainers == [(name, m.id)]
        assert state.trees[name] == _seeded_tree(IBS_REF, product, deleted_at=SEEDED_AT)
        assert state.events == [maintainer_event(name, m)]
        assert not await visible_to_m()

        restorer = await world.open_session()
        await restore_ticket_package(
            restorer,
            ticket_id=ticket.id,
            package_id=package_id,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            evaluation_date=EVAL,
        )
        await restorer.commit()

        assert await visible_to_m()

    @pytest.mark.parametrize("case", ["missing-ticket", "no-package"])
    async def test_no_marker_is_a_resolution_no_op_that_still_dispatches(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        """A missing Ticket or one without any package marker performs no
        SMELT request and creates no HTTP client; the roster is still
        published and completion is logged."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        ticket_id = (
            uuid.uuid7() if case == "missing-ticket" else (await _ticket(world)).id
        )
        smelt = _Smelt({})
        names = smelt.install(monkeypatch)

        with capture_logs() as logs:
            await run_ticket_convergence(
                ticket_id=ticket_id, session_factory=sessions.maker()
            )

        assert names == []
        assert smelt.requests == []
        assert len(sessions.sessions) == 1
        assert published.calls == [_catch_up(fetcher, ticket_id, None)]
        assert _convergence_logs(logs) == [
            _completed(ticket_id, packages=0, converged=0, catch_ups=1)
        ]

    async def test_enumeration_failure_escapes_with_its_phase(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A database failure that prevents reliable enumeration escapes to
        the wrapper before any SMELT request or catch-up publication."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        ticket = await _ticket(world)
        (name,) = _names("a")
        await _package(world, ticket, name)
        sessions.hooks[0] = lambda s: _fail_on(s, "do_orm_execute")
        smelt = _Smelt({})
        names = smelt.install(monkeypatch)

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert ticket_convergence_failure_phase(raised.value) == "package_enumeration"
        assert names == []
        assert published.calls == []
        assert _convergence_logs(logs) == []


# ---------------------------------------------------------------------------
# Unit isolation (package-service.md, `run_ticket_convergence()` workflow:
# package-specific failures isolated, `TicketNotMutableError` stale,
# database and infrastructure failures escape; #781 K10 option (b))
# ---------------------------------------------------------------------------

ISOLATED = [
    "smelt-unavailable",
    "package-not-found",
    "targets-unresolved",
    "catalog-not-ready",
    "invalid-package-name",
]
"""The package-specific resolution and validation failures of one unit."""


@pytest.mark.integration
class TestUnitIsolation:
    @pytest.mark.parametrize("failure", ISOLATED)
    async def test_package_specific_failure_is_isolated_and_logged(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The first unit fails with the documented exception: it is rolled
        back, logged once with exactly `ticket_id`, `package_name`, and the
        exception class as `cause` (no exception text), and the next
        package commits its tree. The roster is still published and the
        completion is a WARNING with the counts.

        `catalog-not-ready` starts with no Product at all; the second
        unit's maintained request publishes the first current Product, so
        that unit passes the readiness gate. `invalid-package-name` is a
        persisted `..` marker, which cannot form one URL path segment and
        fails before any request."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, "git")
        ticket = await _ticket(world)
        failing, succeeding = (
            ["..", *_names("b")]
            if failure == "invalid-package-name"
            else _names("a", "b")
        )
        await _package(world, ticket, failing)
        await _package(world, ticket, succeeding)
        products: list[Product] = []
        if failure == "catalog-not-ready":
            assert await _count(world, Product) == 0

            async def ready_then_resolve(request: httpx.Request) -> httpx.Response:
                products.append(await _current_product(world))
                return httpx.Response(
                    200,
                    json=maintained(codestream(IBS_REF, "SLE_15", products[0].cpe)),
                )

            second = _Answer(ready_then_resolve)
        else:
            products.append(await _current_product(world))
            second = _resolves(codestream(IBS_REF, "SLE_15", products[0].cpe))
        first = {
            "smelt-unavailable": _Answer(
                reply(500, {"status": "error", "data": "fictional-secret-detail"})
            ),
            "package-not-found": _Answer(reply(404, not_found(failing))),
            "targets-unresolved": _resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "catalog-not-ready": _resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "invalid-package-name": _Answer(reply(500, {})),
        }[failure]
        cause = {
            "smelt-unavailable": "SmeltUnavailableError",
            "package-not-found": "PackageNotFoundInSmeltError",
            "targets-unresolved": "PackageTargetsUnresolvedError",
            "catalog-not-ready": "ProductCatalogNotReadyError",
            "invalid-package-name": "ValueError",
        }[failure]
        smelt = _Smelt({failing: first, succeeding: second})
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        failing_requests = (
            [] if failure == "invalid-package-name" else [("maintained", failing)]
        )
        assert smelt.requests == [*failing_requests, *_both(succeeding)]
        assert _convergence_logs(logs) == [
            _package_failed(ticket.id, failing, cause),
            _completed(ticket.id, packages=2, converged=1, failed=1, catch_ups=1),
        ]
        assert "fictional-secret-detail" not in repr(logs)
        assert published.calls == [_catch_up(fetcher, ticket.id, "git")]
        assert await _committed(world, ticket.id, failing, succeeding) == _Committed(
            (ANALYSIS, None),
            [package_added_event(succeeding, None, CONVERGENCE)],
            {
                failing: EMPTY_TREE,
                succeeding: _created(products[0]),
            },
            [],
        )

    async def test_manual_zone_re_entry_is_a_stale_no_op(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An independent session moves the Ticket to `Ignored` while the
        first unit waits on its maintained request. That unit and the next
        one raise `TicketNotMutableError` under the Ticket lock: both are
        rolled back as stale no-ops, neither is logged or counted as a
        package failure, the completion is INFO, and the roster is still
        published."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        product = await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b)
        pause = Pause()
        body = maintained(codestream(IBS_REF, "SLE_15", product.cpe))

        async def held(request: httpx.Request) -> httpx.Response:
            await pause.hold()
            return httpx.Response(200, json=body)

        smelt = _Smelt(
            {
                a: _Answer(held, reply(200, maintainership(m.email))),
                b: _resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(
                run_ticket_convergence(
                    ticket_id=ticket.id, session_factory=sessions.maker()
                )
            )
            try:
                await _arrive(pause, task)
                concurrent = await world.open_session()
                await concurrent.execute(
                    update(Ticket)
                    .where(Ticket.id == ticket.id)
                    .values(status=TicketStatus.IGNORED.value)
                )
                await concurrent.commit()
            finally:
                pause.release.set()
            await asyncio.wait_for(task, timeout=WAIT)

        assert smelt.requests == [*_both(a), *_both(b)]
        assert _convergence_logs(logs) == [
            _completed(ticket.id, packages=2, converged=0, stale=2, catch_ups=1)
        ]
        assert published.calls == [_catch_up(fetcher, ticket.id, None)]
        assert await _committed(world, ticket.id, a, b) == _Committed(
            (TicketStatus.IGNORED.value, None),
            [],
            {a: EMPTY_TREE, b: EMPTY_TREE},
            [],
        )

    @pytest.mark.parametrize("point", ["before-commit", "during-commit"])
    async def test_database_failure_escapes_without_undoing_earlier_units(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
    ) -> None:
        """A driver error in the second unit, raised by its flush before the
        commit or by the commit itself, escapes with the
        `package_resolution` phase. The first unit stays committed, the
        failing unit's writes are rolled back, the third package is never
        attempted, the error is not logged as a package failure, and no
        catch-up is published."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        ticket = await _ticket(world)
        p1, p2, p3 = [await _current_product(world) for _ in range(3)]
        a, b, c = _names("a", "b", "c")
        for name in (a, b, c):
            await _package(world, ticket, name)
        smelt = _Smelt(
            {
                a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: _resolves(codestream(IBS_REF, "SLE_15", p3.cpe)),
            }
        )
        smelt.install(monkeypatch)
        event_name = "before_flush" if point == "before-commit" else "before_commit"
        sessions.hooks[2] = lambda s: _fail_on(s, event_name)

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert ticket_convergence_failure_phase(raised.value) == "package_resolution"
        assert smelt.requests == [*_both(a), *_both(b)]
        assert _convergence_logs(logs) == []
        assert published.calls == []
        assert await _committed(world, ticket.id, a, b, c) == _Committed(
            (ANALYSIS, None),
            [package_added_event(a, None, CONVERGENCE)],
            {
                a: _created(p1),
                b: EMPTY_TREE,
                c: EMPTY_TREE,
            },
            [],
        )


async def _arrive(pause: Pause, task: asyncio.Task[Any]) -> None:
    """Wait until the paused request reaches the fake; fail with the
    workflow's own error if it finishes first."""
    arrived = asyncio.ensure_future(pause.arrived.wait())
    try:
        await asyncio.wait(
            {arrived, task}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        arrived.cancel()
    if task.done():
        task.result()
        raise AssertionError("the workflow finished before its paused request")
    assert pause.arrived.is_set(), "the workflow never reached its paused request"


# ---------------------------------------------------------------------------
# Per-unit drain (package-service.md, `run_ticket_convergence()` step 2;
# testing-strategy.md, Ticket Convergence Publication Handoff > Publication
# policies: the convergence per-package owner)
# ---------------------------------------------------------------------------


async def _regressing_world(
    world: CommittedWorld,
) -> tuple[Ticket, str, str, dict[str, _Answer], Product]:
    """A `Resolved` Ticket with `a`, a marker whose re-resolution creates an
    `ANALYSIS` track (a `Resolved` regression that registers one
    convergence effect), and `b`, a complete `NOT_AFFECTED` tree that
    converges as a no-op."""
    ticket = await _ticket(world, status=TicketStatus.RESOLVED)
    p1, p2 = await _current_product(world), await _current_product(world)
    a, b = _names("a", "b")
    await _package(world, ticket, a)
    await _package(
        world, ticket, b, tree=((IBS_REF, p2),), status=PackageStatus.NOT_AFFECTED
    )
    answers = {
        a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
        b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
    }
    return ticket, a, b, answers, p1


def _regressed(a: str, p1: Product) -> tuple[list[EventRow], Tree]:
    """The committed events and tree of the regressing unit `a`."""
    return (
        [package_added_event(a, None, CONVERGENCE), status_event(RESOLVED, ANALYSIS)],
        _created(p1),
    )


@pytest.mark.integration
class TestUnitDrain:
    async def test_publication_follows_the_unit_commit_and_precedes_the_next_package(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The regressing unit commits, its session is no longer in a
        transaction and the Ticket row is unlocked, its registered effect
        is published as the root `run_ticket_convergence` task, and only
        then does the next package make its first SMELT request."""
        ticket, a, b, answers, p1 = await _regressing_world(world)
        events: list[tuple[str, str]] = []
        sessions.events = events
        published.events = events
        observed: list[tuple[str, bool]] = []

        async def check_released(call: dict[str, Any]) -> None:
            probe = await world.open_session()
            status = (
                await probe.execute(
                    select(Ticket.status)
                    .where(Ticket.id == ticket.id)
                    .with_for_update(nowait=True)
                )
            ).scalar_one()
            await probe.rollback()
            observed.append((status, sessions.sessions[1].in_transaction()))

        published.on_call = check_released
        _Smelt(answers, events).install(monkeypatch)

        with capture_logs() as logs:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert events == [
            ("http", f"maintained:{a}"),
            ("http", f"maintainership:{a}"),
            ("commit", "1"),
            ("publish", "run_ticket_convergence"),
            ("http", f"maintained:{b}"),
            ("http", f"maintainership:{b}"),
            ("commit", "2"),
        ]
        (call,) = published.calls
        assert call["kwargs"] == {"ticket_id": str(ticket.id)}
        assert uuid.UUID(call["task_id"]).version == 7
        assert observed == [(ANALYSIS, False)]
        assert _convergence_logs(logs) == [
            _completed(ticket.id, packages=2, converged=2)
        ]
        expected_events, expected_tree = _regressed(a, p1)
        state = await _committed(world, ticket.id, a)
        assert (state.ticket, state.events, state.trees) == (
            (ANALYSIS, None),
            expected_events,
            {a: expected_tree},
        )

    async def test_broker_operational_error_is_absorbed_once_and_work_continues(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A broker operational error of the drained publication emits
        exactly one `ticket_convergence_publication_failed` ERROR with the
        closed cause and no exception text; the committed unit and the
        completion counts are unchanged, the next package proceeds, and the
        roster is published."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        ticket, a, b, answers, p1 = await _regressing_world(world)
        published.fail = lambda call: (
            BrokerOperationalError("amqp://user:secret@broker.example.test down")
            if call["task_name"] == "run_ticket_convergence"
            else None
        )
        smelt = _Smelt(answers)
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert smelt.requests == [*_both(a), *_both(b)]
        assert _convergence_logs(logs) == [
            {
                "event": PUBLICATION_FAILED,
                "log_level": "error",
                "ticket_id": str(ticket.id),
                "cause": "broker_operational_error",
            },
            _completed(ticket.id, packages=2, converged=2, catch_ups=1),
        ]
        assert "secret" not in repr(logs)
        assert [c["task_name"] for c in published.calls] == [
            "run_ticket_convergence",
            "run_catch_up",
        ]
        expected_events, expected_tree = _regressed(a, p1)
        state = await _committed(world, ticket.id, a)
        assert (state.events, state.trees) == (expected_events, {a: expected_tree})

    async def test_non_operational_drain_exception_escapes_after_the_commit(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A non-operational exception of the drained publication escapes
        unchanged with the `package_convergence_drain` phase: the committed
        unit is not rolled back or reclassified, no publication-failure,
        package-failure, or completion log is emitted, the next package is
        never attempted, and no catch-up is published."""
        (fetcher,) = _roster_names("only")
        _participant(fetcher, None)
        ticket, a, _b, answers, p1 = await _regressing_world(world)
        error = RuntimeError("fictional programming error")
        published.fail = lambda call: (
            error if call["task_name"] == "run_ticket_convergence" else None
        )
        smelt = _Smelt(answers)
        smelt.install(monkeypatch)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await run_ticket_convergence(
                ticket_id=ticket.id, session_factory=sessions.maker()
            )

        assert raised.value is error
        assert (
            ticket_convergence_failure_phase(raised.value)
            == "package_convergence_drain"
        )
        assert smelt.requests == _both(a)
        assert _convergence_logs(logs) == []
        assert [c["task_name"] for c in published.calls] == ["run_ticket_convergence"]
        expected_events, expected_tree = _regressed(a, p1)
        assert await _committed(world, ticket.id, a) == _Committed(
            (ANALYSIS, None), expected_events, {a: expected_tree}, []
        )


# ---------------------------------------------------------------------------
# Catch-up roster (package-service.md, `run_ticket_convergence()` step 4;
# fetcher-infrastructure.md, Post-commit enqueue and Invocation points)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCatchUpRoster:
    async def test_every_participant_is_published_in_name_order_with_its_queue(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only participating fetchers are published, in fetcher-name order
        (registered out of order), each `run_catch_up` carrying the
        primitive `fetcher_name` and `ticket_id` and its class `queue`
        (`git` or `None`, the latter left to `publish_task()` to omit),
        after the last package unit and even when a unit failed."""
        first, second, silent = _roster_names("a", "b", "c")
        _participant(second, "git")
        _non_participant(silent)
        _participant(first, None)
        ticket = await _ticket(world)
        product = await _current_product(world)
        failing, succeeding = _names("a", "b")
        await _package(world, ticket, failing)
        await _package(world, ticket, succeeding)
        events: list[tuple[str, str]] = []
        published.events = events
        _Smelt(
            {
                failing: _Answer(reply(404, not_found(failing))),
                succeeding: _resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            },
            events,
        ).install(monkeypatch)

        await run_ticket_convergence(
            ticket_id=ticket.id, session_factory=sessions.maker()
        )

        assert published.calls == [
            _catch_up(first, ticket.id, None),
            _catch_up(second, ticket.id, "git"),
        ]
        assert events[-2:] == [("publish", "run_catch_up")] * 2
        assert all(kind == "http" for kind, _ in events[:-2])

    async def test_dispatch_failures_aggregate_after_the_last_attempt(
        self, sessions: _Sessions, published: _Publish
    ) -> None:
        """An earlier publication failure does not stop later attempts; all
        failures are raised together as one `ExceptionGroup` with the
        `catch_up_dispatch` phase after the last attempt, and no completion
        is logged."""
        first, second, third = _roster_names("a", "b", "c")
        for name in (third, first, second):
            _participant(name, None)
        errors = {
            first: BrokerOperationalError("fictional broker outage"),
            third: RuntimeError("fictional serialization failure"),
        }
        published.fail = lambda call: errors.get(call["kwargs"]["fetcher_name"])
        ticket_id = uuid.uuid7()

        with capture_logs() as logs, pytest.raises(ExceptionGroup) as raised:
            await run_ticket_convergence(
                ticket_id=ticket_id, session_factory=sessions.maker()
            )

        assert [c["kwargs"]["fetcher_name"] for c in published.calls] == [
            first,
            second,
            third,
        ]
        assert list(raised.value.exceptions) == [errors[first], errors[third]]
        assert ticket_convergence_failure_phase(raised.value) == "catch_up_dispatch"
        assert [e["event"] for e in _convergence_logs(logs)] == [
            "ticket_convergence_catch_up_dispatch_failed"
        ] * 2
        assert all(
            e["log_level"] == "warning" and e["ticket_id"] == str(ticket_id)
            for e in _convergence_logs(logs)
        )
        assert [(e["fetcher_name"], e["cause"]) for e in _convergence_logs(logs)] == [
            (first, "OperationalError"),
            (third, "RuntimeError"),
        ]
        assert "fictional" not in repr(logs)

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_control_signals_propagate_immediately(
        self,
        sessions: _Sessions,
        published: _Publish,
        make_signal: Callable[[], BaseException],
    ) -> None:
        first, second = _roster_names("a", "b")
        _participant(first, None)
        _participant(second, None)
        signal = make_signal()
        published.fail = lambda call: signal
        ticket_id = uuid.uuid7()

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await run_ticket_convergence(
                ticket_id=ticket_id, session_factory=sessions.maker()
            )

        assert raised.value is signal
        assert len(published.calls) == 1
        assert _convergence_logs(logs) == []


# ---------------------------------------------------------------------------
# Concurrency (package-service.md, `run_ticket_convergence()` workflow:
# concurrent invocations; Concurrency Control: internal re-resolution
# beneath a concurrently committed exclusion)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrency:
    async def test_concurrent_duplicate_workflows_converge(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two workflows for the same Ticket are both held in the first
        package's maintainership request, then serialize on the Ticket
        lock: each package tree, association, and event exists exactly
        once, and both workflows complete."""
        m1, m2 = [await world.user(role=Role.RESTRICTED_ANALYST) for _ in range(2)]
        ticket = await _ticket(world)
        p1, p2 = await _current_product(world), await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b, tree=((IBS_REF, p2),))
        both_arrived = asyncio.Event()
        arrivals: list[str] = []

        async def barrier(request: httpx.Request) -> httpx.Response:
            arrivals.append("a")
            if len(arrivals) == 2:
                both_arrived.set()
            await asyncio.wait_for(both_arrived.wait(), timeout=WAIT)
            return httpx.Response(200, json=maintainership(m1.email))

        smelt = _Smelt(
            {
                a: _Answer(
                    reply(200, maintained(codestream(IBS_REF, "SLE_15", p1.cpe))),
                    barrier,
                ),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe), emails=(m2.email,)),
            }
        )
        names = smelt.install(monkeypatch)
        first, second = _Sessions(real_session_factory), _Sessions(real_session_factory)

        with capture_logs() as logs:
            await asyncio.wait_for(
                asyncio.gather(
                    run_ticket_convergence(
                        ticket_id=ticket.id, session_factory=first.maker()
                    ),
                    run_ticket_convergence(
                        ticket_id=ticket.id, session_factory=second.maker()
                    ),
                ),
                timeout=WAIT * 4,
            )

        assert names == [TICKET_CONVERGENCE_HTTP_CLIENT_NAME] * 2
        assert arrivals == ["a", "a"]
        assert sorted(smelt.requests) == sorted(_both(a) * 2 + _both(b) * 2)
        assert (
            _convergence_logs(logs)
            == [_completed(ticket.id, packages=2, converged=2)] * 2
        )
        state = await _committed(world, ticket.id, a, b)
        assert sorted(state.events, key=repr) == sorted(
            [
                maintainer_event(a, m1),
                package_added_event(a, None, CONVERGENCE),
                maintainer_event(b, m2),
            ],
            key=repr,
        )
        assert state.trees == {
            a: _created(p1),
            b: _seeded_tree(IBS_REF, p2),
        }
        assert state.maintainers == sorted([(a, m1.id), (b, m2.id)])

    async def test_re_resolution_proceeds_beneath_an_exclusion_committed_during_io(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """While the target package's unit waits on its maintainership
        request (holding no row lock), an active VA excludes that package
        through the direct exclusion operation and commits. Released, the
        unit proceeds in re-resolution mode beneath the committed marker:
        it adds the missing occurrence, the new Git track, and the
        maintainer, and the marker stays exactly as the exclusion set it,
        with no restoration event. A pin package keeps the Ticket in
        `Analysis` and converges as a no-op."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        pin = await committed_path(world, ticket)
        target = await committed_path(world, ticket)
        p1 = await _product_id(world, target.id)
        await _publish_product(world, await _product_id(world, pin.id))
        await _publish_product(world, p1)
        p2, p3 = await _current_product(world), await _current_product(world)
        reference = target.subject["track"]
        pause = Pause()

        async def held(request: httpx.Request) -> httpx.Response:
            await pause.hold()
            return httpx.Response(200, json=maintainership(m.email))

        smelt = _Smelt(
            {
                pin.subject["package"]: _resolves(
                    codestream(
                        pin.subject["track"], "SLE_15", pin.subject["product_cpe"]
                    )
                ),
                target.subject["package"]: _Answer(
                    reply(
                        200,
                        maintained(
                            codestream(
                                reference,
                                "SLE_15",
                                target.subject["product_cpe"],
                                p2.cpe,
                            ),
                            codestream(GIT_REF, "SLFO", p3.cpe),
                        ),
                    ),
                    held,
                ),
            }
        )
        smelt.install(monkeypatch)
        excluder = await world.open_session()

        with capture_logs() as logs:
            task = asyncio.create_task(
                run_ticket_convergence(
                    ticket_id=ticket.id, session_factory=sessions.maker()
                )
            )
            try:
                await _arrive(pause, task)

                async def exclude() -> None:
                    await path_call(
                        excluder, Level.PACKAGE, Direction.EXCLUDE, target, actor
                    )
                    await excluder.commit()

                await asyncio.wait_for(exclude(), timeout=WAIT)
                assert not task.done()
            finally:
                pause.release.set()
            await asyncio.wait_for(task, timeout=WAIT)

        pkg = target.subject["package"]
        assert _convergence_logs(logs) == [
            _completed(ticket.id, packages=2, converged=2)
        ]
        expected_tree = path_tree(
            target, package=MARKER_NOW, track=None, product=None, product_id=p1
        )
        assert await _committed(world, ticket.id, pkg) == _Committed(
            (ANALYSIS, actor.id),
            [
                assignment_event(actor),
                path_event(Level.PACKAGE, Direction.EXCLUDE, target, actor),
                maintainer_event(pkg, m),
                package_added_event(pkg, None, CONVERGENCE),
            ],
            {
                pkg: Tree(
                    MARKER_NOW,
                    expected_tree.tracks | {GIT_REF: NEW_TRACK[WorkflowType.GIT]},
                    expected_tree.occurrences
                    | {
                        (reference, p2.id): new_occurrence(True),
                        (GIT_REF, p3.id): new_occurrence(True),
                    },
                )
            },
            [(pkg, m.id)],
        )


async def _product_id(world: CommittedWorld, occurrence_id: uuid.UUID) -> uuid.UUID:
    """The catalog Product of a committed occurrence."""
    product_id = (
        await world.session.execute(
            select(TicketPackageProduct.product_id).where(
                TicketPackageProduct.id == occurrence_id
            )
        )
    ).scalar_one()
    await world.session.commit()
    return product_id


@pytest.mark.unit
class TestFailurePhase:
    def test_unmarked_exception_reports_unknown(self) -> None:
        assert ticket_convergence_failure_phase(RuntimeError("x")) == "unknown"

    def test_first_recorded_phase_is_kept(self) -> None:
        """An exception keeps the phase where it first escaped, even if an
        outer layer marks it again."""
        error = RuntimeError("x")
        package_service._mark_phase(error, TicketConvergencePhase.DRAIN)
        package_service._mark_phase(error, TicketConvergencePhase.CATCH_UP_DISPATCH)

        assert ticket_convergence_failure_phase(error) == "package_convergence_drain"
