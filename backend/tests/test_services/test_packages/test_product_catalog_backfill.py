"""Integration tests for the Product catalog backfill workflow
`run_product_catalog_backfill()`
(backend/app/services/packages/product_catalog_backfill.py).

Owning specifications:

- docs/features/packages/product-catalog.md (Product Catalog Backfill:
  selection and order, per-pair transactions and the pair outcome table,
  the convergence/commit paragraph, lifecycle, completion line, and log
  privacy).
- docs/features/packages/package-service.md (`add_package_to_ticket()`:
  `audit_comment`, `active_ticket_only`, `allow_excluded_reresolution`,
  Product catalog backfill exclusion behavior; Architectural Test
  Requirement bullets "Maintainership acquisition" and "Package audit
  comments").
- docs/features/packages/package-maintainership.md (Testing Requirements:
  backfill acquisition on package-tree no-ops while preserving its locked
  inactive-Ticket skip).
- docs/features/tickets/ticket-audit-log.md (`package_added` with
  `user_id = NULL` and the `Product catalog backfill` comment;
  `package_maintainer_added`; the workflow creates no event of its own).
- docs/features/platform/fetcher-infrastructure.md (`SoftTimeLimitExceeded`
  handling convention) and docs/features/platform/testing-strategy.md
  (Concurrency Testing: explicit cleanup of committed rows; Audit Trail
  Testing).

The workflow owns its sessions, so it receives a recording factory over
`real_session_factory` (index 0 is the selection session, then one session
per pair), and every test seeds a `CommittedWorld` whose rows are deleted
explicitly at teardown. The selection is system-wide by design, so the
completion counts cover every committed active pair of the (per-worker)
test database; each test owns all of them. SMELT is the in-process
`PackageSmelt` fake, routed per package name, behind the substituted
`create_http_client()` of the backfill module; `task_publication.publish_task`
is substituted by a recorder, and the orchestrator's own client factory
fails the test if a pair does not use the shared client.

Unless a test states otherwise: a Ticket is a committed unassigned
CVE-less `Analysis` Ticket with `severity_manual = High`; a catalog Product
is in General Support on `EVAL` with a `NULL` threshold and is published in
the current snapshot (`SNAPSHOT_AT`), so a created occurrence is eligible;
maintainers are active `restricted_analyst` Users. Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import AsyncIterator, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Role,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.services import (
    package_service,
    task_publication,
    ticket_convergence_registry,
    ticket_mutations,
)
from app.services.package_service import (
    SYSTEM_INVOCATION,
    AddPackageResult,
    PackageAddedComment,
)
from app.services.packages import product_catalog_backfill
from app.services.packages.product_catalog_backfill import (
    ProductCatalogBackfillSummary,
    run_product_catalog_backfill,
)
from app.services.ticket_convergence_registry import (
    detach_ticket_convergence_effects,
)
from tests.support.package_addition import (
    MAINTAINED_PATH,
    PackageSmelt,
    Pause,
    Respond,
    codestream,
    fail,
    maintained,
    maintainership,
    not_found,
    publish,
    reply,
)
from tests.support.package_records import (
    NEW_TRACK,
    SEEDED_AT,
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
    world_product,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)

LogEntry = MutableMapping[str, Any]

BACKFILL: PackageAddedComment = "Product catalog backfill"
"""The canonical `package_added` comment of a backfill pair."""

CLIENT_NAME = "backfill_product_catalog"
COMPLETED = "product_catalog_backfill_completed"
PAIR_FAILED = "product_catalog_backfill_pair_failed"

ABSENT = "cpe:/o:example:absent:1"
"""A CPE that no catalog Product carries."""

MARKER = "Example-Confidential-Backfill-Value"
"""A value that must never reach a log."""

ANALYSIS = TicketStatus.ANALYSIS.value
ANALYZED = TicketStatus.ANALYZED.value


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
    """The service's UTC date is `EVAL`; SMELT URLs use the fictional test
    origin; a pair that creates its own client instead of using the
    invocation's shared client fails the test."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)

    def _own_client(name: str, **overrides: Any) -> httpx.AsyncClient:
        raise AssertionError("a backfill pair must use the shared HTTP client")

    monkeypatch.setattr(package_service, "create_http_client", _own_client)


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})


@pytest.fixture(autouse=True)
def published(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


class _Sessions:
    """Session factory passed to the workflow: delegates to the real factory
    and records every session it opens (index 0 is the selection, then one
    per pair). `hooks[index]` instruments one session before use."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.hooks: dict[int, Callable[[AsyncSession], None]] = {}

    def __call__(self) -> AsyncSession:
        index = len(self.sessions)
        session = self._factory()
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
    return OperationalError("fictional statement", None, Exception(MARKER))


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
    each request. `on_request` runs before every response."""

    def __init__(self, answers: dict[str, _Answer]) -> None:
        self.answers = answers
        self.on_request: Callable[[], None] | None = None
        self.fake = PackageSmelt(
            maintained=self._route("maintained"),
            maintainership=self._route("maintainership"),
        )

    def _route(self, kind: str) -> Respond:
        async def respond(request: httpx.Request) -> httpx.Response:
            if self.on_request is not None:
                self.on_request()
            answer = self.answers[_package_of(request)]
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
        """Make the backfill's `create_http_client()` return a client of this
        fake; return the list of requested client names."""
        names: list[str] = []

        def _factory(name: str, **overrides: Any) -> httpx.AsyncClient:
            names.append(name)
            return self.fake.client()

        monkeypatch.setattr(product_catalog_backfill, "create_http_client", _factory)
        return names


def _both(name: str) -> list[tuple[str, str]]:
    return [("maintained", name), ("maintainership", name)]


def _held(pause: Pause, body: dict[str, Any]) -> Respond:
    """Hold the request on `pause`, then answer HTTP 200 with `body`."""

    async def respond(request: httpx.Request) -> httpx.Response:
        await pause.hold()
        return httpx.Response(200, json=body)

    return respond


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
# Committed seeding and observation
# ---------------------------------------------------------------------------


def _names(*tags: str) -> list[str]:
    suffix = uuid.uuid4().hex[:8]
    return [f"fictional-{tag}-{suffix}" for tag in tags]


async def _ticket(
    world: CommittedWorld,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    ticket_id: uuid.UUID | None = None,
    duplicate_of: uuid.UUID | None = None,
) -> Ticket:
    """A committed CVE-less `High` Ticket, optionally with a fixed UUID."""
    ticket = Ticket(
        status=status.value,
        severity_manual=Severity.HIGH.value,
        duplicate_of_id=duplicate_of,
    )
    if ticket_id is not None:
        ticket.id = ticket_id
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


async def _current_product(world: CommittedWorld) -> Product:
    """A committed catalog Product published in the current snapshot."""
    product = await world_product(world)
    await publish(world.session, product)
    await world.session.commit()
    return product


async def _package(
    world: CommittedWorld,
    ticket: Ticket,
    name: str,
    *,
    excluded: bool = False,
    tree: tuple[tuple[str, Product], ...] = (),
    status: PackageStatus = PackageStatus.ANALYSIS,
    delivery: DeliveryStatus = DeliveryStatus.PENDING,
) -> None:
    """Commit a package marker with an optional complete IBS tree."""
    package = await seed_package(world.session, ticket.id, name, excluded=excluded)
    for reference, product in tree:
        track = await seed_track(
            world.session, package, reference, status=status, delivery=delivery
        )
        await seed_occurrence(world.session, track, product)
    await world.session.commit()


async def _set_status(world: CommittedWorld, ticket: Ticket, status: str) -> None:
    """Commit a Ticket status change from an independent session."""
    concurrent = await world.open_session()
    await concurrent.execute(
        update(Ticket).where(Ticket.id == ticket.id).values(status=status)
    )
    await concurrent.commit()


async def _exclude(world: CommittedWorld, ticket: Ticket, name: str) -> None:
    """Commit a direct package exclusion marker from an independent session."""
    concurrent = await world.open_session()
    await concurrent.execute(
        update(TicketPackage)
        .where(TicketPackage.ticket_id == ticket.id, TicketPackage.package_name == name)
        .values(deleted_at=SEEDED_AT)
    )
    await concurrent.commit()


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


async def _product_count(world: CommittedWorld) -> int:
    probe = await world.open_session()
    count = (
        await probe.execute(select(func.count()).select_from(Product))
    ).scalar_one()
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


def _seeded_tree(product: Product) -> Tree:
    """A seeded `ANALYSIS`/`PENDING` `IBS_REF` track with one eligible
    occurrence."""
    return Tree(
        None,
        {IBS_REF: TrackState("ibs", "ANALYSIS", "PENDING", None)},
        {(IBS_REF, product.id): OccurrenceState(True, False, None, None)},
    )


EMPTY_TREE = Tree(None, {}, {})
"""An included package marker without tracks."""


def _backfill_logs(logs: list[LogEntry]) -> list[LogEntry]:
    return [e for e in logs if str(e["event"]).startswith("product_catalog_backfill")]


def _completed(
    *,
    candidates: int,
    record_creating: int = 0,
    no_op: int = 0,
    skipped_inactive: int = 0,
    skipped_excluded: int = 0,
    failed: int = 0,
) -> LogEntry:
    return {
        "event": COMPLETED,
        "log_level": "info",
        "candidates": candidates,
        "record_creating": record_creating,
        "no_op": no_op,
        "skipped_inactive": skipped_inactive,
        "skipped_excluded": skipped_excluded,
        "failed": failed,
    }


def _summary(entry: LogEntry) -> ProductCatalogBackfillSummary:
    """The summary that a completion line reports."""
    return ProductCatalogBackfillSummary(
        candidates=entry["candidates"],
        record_creating=entry["record_creating"],
        no_op=entry["no_op"],
        skipped_inactive=entry["skipped_inactive"],
        skipped_excluded=entry["skipped_excluded"],
        failed=entry["failed"],
    )


def _pair_failed(
    ticket_id: uuid.UUID, name: str, cause: str, category: str | None = None
) -> LogEntry:
    entry: LogEntry = {
        "event": PAIR_FAILED,
        "log_level": "warning",
        "ticket_id": str(ticket_id),
        "package_name": name,
        "cause": cause,
    }
    if category is not None:
        entry["category"] = category
    return entry


async def _backfill(sessions: _Sessions) -> ProductCatalogBackfillSummary:
    return await run_product_catalog_backfill(session_factory=sessions.maker())


# ---------------------------------------------------------------------------
# Selection (product-catalog.md, Product Catalog Backfill step 1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSelection:
    async def test_only_active_tickets_and_included_markers_are_selected_in_order(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Three active Tickets are committed in descending UUID order and
        the first one's markers out of name order; excluded markers and
        `Resolved`, `Ignored`, and `Duplicated` Tickets are committed too.
        Every selected pair is processed once, by ascending Ticket UUID and
        then package name in Unicode code-point order (upper case before
        lower case, `-` before `.` before `_`), each through the invocation's
        one shared client in its own session, as a system invocation with
        the backfill comment, active-ticket-only mode, and public
        exclusion semantics. The selection session is no longer in a
        transaction when the first SMELT request is made. Nothing else
        is ever requested. The catalog is ready, so every pair fails as
        not found in SMELT without writing anything."""
        await _current_product(world)
        first_id, second_id, third_id = sorted(uuid.uuid4() for _ in range(3))
        third = await _ticket(world, status=TicketStatus.ANALYZED, ticket_id=third_id)
        second = await _ticket(world, status=TicketStatus.NEW, ticket_id=second_id)
        first = await _ticket(world, ticket_id=first_id)
        suffix = uuid.uuid4().hex[:8]
        first_names = [
            f"alpha_{suffix}",
            f"Zeta-{suffix}",
            f"alpha.{suffix}",
            f"Beta-{suffix}",
            f"alpha-{suffix}",
        ]
        for name in first_names:
            await _package(world, first, name)
        await _package(world, first, f"excluded-{suffix}", excluded=True)
        await _package(world, second, f"New-{suffix}")
        await _package(world, second, f"excluded-{suffix}", excluded=True)
        await _package(world, third, f"Analyzed-{suffix}")
        resolved = await _ticket(world, status=TicketStatus.RESOLVED)
        ignored = await _ticket(world, status=TicketStatus.IGNORED)
        duplicated = await _ticket(
            world, status=TicketStatus.DUPLICATED, duplicate_of=first.id
        )
        for inactive in (resolved, ignored, duplicated):
            await _package(world, inactive, f"inactive-{suffix}")
        expected = [
            *[
                (first.id, name)
                for name in [
                    f"Beta-{suffix}",
                    f"Zeta-{suffix}",
                    f"alpha-{suffix}",
                    f"alpha.{suffix}",
                    f"alpha_{suffix}",
                ]
            ],
            (second.id, f"New-{suffix}"),
            (third.id, f"Analyzed-{suffix}"),
        ]
        smelt = _Smelt(
            {name: _Answer(reply(404, not_found(name))) for _, name in expected}
        )
        selection_open: list[bool] = []
        smelt.on_request = lambda: selection_open.append(
            sessions.sessions[0].in_transaction()
        )
        names = smelt.install(monkeypatch)
        calls: list[dict[str, Any]] = []
        real = package_service.add_package_to_ticket

        async def spy(db: AsyncSession, **kwargs: Any) -> AddPackageResult:
            calls.append({"db": db, **kwargs})
            return await real(db, **kwargs)

        monkeypatch.setattr(product_catalog_backfill, "add_package_to_ticket", spy)

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert smelt.requests == [("maintained", name) for _, name in expected]
        assert selection_open[0] is False
        assert names == [CLIENT_NAME]
        (client,) = smelt.fake.clients
        assert client.is_closed
        assert [(c["ticket_id"], c["package_name"]) for c in calls] == expected
        assert all(
            (
                c["acting_user_id"],
                c["caller"],
                c["audit_comment"],
                c["active_ticket_only"],
                c["allow_excluded_reresolution"],
                c["http_client"],
            )
            == (None, SYSTEM_INVOCATION, BACKFILL, True, False, client)
            for c in calls
        )
        assert [c["db"] for c in calls] == sessions.sessions[1:]
        assert len({id(s) for s in sessions.sessions}) == 1 + len(expected)
        assert _backfill_logs(logs) == [
            *[
                _pair_failed(ticket_id, name, "PackageNotFoundInSmeltError")
                for ticket_id, name in expected
            ],
            _completed(candidates=7, failed=7),
        ]
        assert summary == ProductCatalogBackfillSummary(7, 0, 0, 0, 0, 7)
        assert published.calls == []

    async def test_no_candidate_pair_opens_no_client_and_completes_with_zeros(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only inactive Tickets with included markers, an active Ticket
        whose only marker is excluded, and an active Ticket without any
        marker: no HTTP client, SMELT request, or pair session, and one
        completion line with zero counts."""
        (name,) = _names("pkg")
        active = await _ticket(world)
        await _package(world, active, name, excluded=True)
        await _ticket(world, status=TicketStatus.NEW)
        for status in (TicketStatus.RESOLVED, TicketStatus.IGNORED):
            await _package(world, await _ticket(world, status=status), name)
        duplicated = await _ticket(
            world, status=TicketStatus.DUPLICATED, duplicate_of=active.id
        )
        await _package(world, duplicated, name)
        smelt = _Smelt({})
        names = smelt.install(monkeypatch)

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert names == []
        assert smelt.requests == []
        assert len(sessions.sessions) == 1
        assert _backfill_logs(logs) == [_completed(candidates=0)]
        assert summary == ProductCatalogBackfillSummary(0, 0, 0, 0, 0, 0)
        assert published.calls == []

    async def test_selection_failure_escapes_without_a_completion_line(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await _ticket(world)
        (name,) = _names("a")
        await _package(world, ticket, name)
        sessions.hooks[0] = lambda s: _fail_on(s, "do_orm_execute")
        smelt = _Smelt({})
        names = smelt.install(monkeypatch)

        with capture_logs() as logs, pytest.raises(OperationalError):
            await _backfill(sessions)

        assert names == []
        assert len(sessions.sessions) == 1
        assert _backfill_logs(logs) == []

    async def test_client_creation_failure_escapes_before_any_pair(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await _ticket(world)
        (name,) = _names("a")
        await _package(world, ticket, name)
        error = RuntimeError("fictional client configuration failure")

        def _failing(name: str, **overrides: Any) -> httpx.AsyncClient:
            raise error

        monkeypatch.setattr(product_catalog_backfill, "create_http_client", _failing)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await _backfill(sessions)

        assert raised.value is error
        assert len(sessions.sessions) == 1
        assert _backfill_logs(logs) == []


# ---------------------------------------------------------------------------
# Pair outcomes (Product Catalog Backfill steps 2 and 4; the convergence and
# commit paragraph; idempotency paragraph)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPairOutcomes:
    async def test_missing_products_and_an_omitted_track_are_created_by_the_system(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An existing `AFFECTED`/`IN_PROGRESS` IBS track gains a missing
        Product, and a previously omitted Git track is created with its
        Product: one system `package_added` with the backfill comment, the
        existing track keeps its affectedness and delivery, the unassigned
        Ticket stays unassigned, and nothing is published."""
        await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world)
        p1, p2, p3 = [await _current_product(world) for _ in range(3)]
        (a,) = _names("a")
        await _package(
            world,
            ticket,
            a,
            tree=((IBS_REF, p1),),
            status=PackageStatus.AFFECTED,
            delivery=DeliveryStatus.IN_PROGRESS,
        )
        smelt = _Smelt(
            {
                a: _resolves(
                    codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
                    codestream(GIT_REF, "SLFO", p3.cpe),
                )
            }
        )
        names = smelt.install(monkeypatch)

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert names == [CLIENT_NAME]
        assert [c.is_closed for c in smelt.fake.clients] == [True]
        assert smelt.requests == _both(a)
        assert _backfill_logs(logs) == [_completed(candidates=1, record_creating=1)]
        assert summary == ProductCatalogBackfillSummary(1, 1, 0, 0, 0, 0)
        assert await _committed(world, ticket.id, a) == _Committed(
            (ANALYSIS, None),
            [package_added_event(a, None, BACKFILL)],
            {
                a: Tree(
                    None,
                    {
                        IBS_REF: TrackState("ibs", "AFFECTED", "IN_PROGRESS", None),
                        GIT_REF: NEW_TRACK[WorkflowType.GIT],
                    },
                    {
                        (IBS_REF, p1.id): OccurrenceState(True, False, None, None),
                        (IBS_REF, p2.id): new_occurrence(True),
                        (GIT_REF, p3.id): new_occurrence(True),
                    },
                )
            },
            [],
        )
        assert published.calls == []

    async def test_analyzed_regression_registers_and_publishes_no_convergence(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """#785 D3: a backfill pair that creates a new `ANALYSIS` track on an
        `Analyzed` Ticket regresses it to `Analysis` through normal
        reconciliation, but registers no Ticket convergence effect and
        publishes nothing."""
        ticket = await _ticket(world, status=TicketStatus.ANALYZED)
        p1, p2 = await _current_product(world), await _current_product(world)
        (a,) = _names("a")
        await _package(
            world, ticket, a, tree=((IBS_REF, p1),), status=PackageStatus.NOT_AFFECTED
        )
        smelt = _Smelt(
            {
                a: _resolves(
                    codestream(IBS_REF, "SLE_15", p1.cpe),
                    codestream(GIT_REF, "SLFO", p2.cpe),
                )
            }
        )
        smelt.install(monkeypatch)
        registered: list[uuid.UUID] = []
        real_register = ticket_convergence_registry.register_ticket_convergence

        def _register(session: AsyncSession, ticket_id: uuid.UUID) -> None:
            registered.append(ticket_id)
            real_register(session, ticket_id)

        monkeypatch.setattr(ticket_mutations, "register_ticket_convergence", _register)

        summary = await _backfill(sessions)

        assert summary == ProductCatalogBackfillSummary(1, 1, 0, 0, 0, 0)
        state = await _committed(world, ticket.id, a)
        assert (state.ticket, state.events) == (
            (ANALYSIS, None),
            [package_added_event(a, None, BACKFILL), status_event(ANALYZED, ANALYSIS)],
        )
        tree = state.trees[a]
        assert tree is not None
        assert tree.tracks[GIT_REF] == NEW_TRACK[WorkflowType.GIT]
        assert registered == []
        assert detach_ticket_convergence_effects(sessions.sessions[1]) == ()
        assert published.calls == []

    async def test_package_tree_no_op_acquires_maintainership_and_counts_as_no_op(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two complete package trees: `a` gains the association of the
        maintainer M (one system `package_maintainer_added`, no
        `package_added`, no assignment or reconciliation), `b` is a pure
        no-op; both are no-op pairs."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        p1, p2 = await _current_product(world), await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a, tree=((IBS_REF, p1),))
        await _package(world, ticket, b, tree=((IBS_REF, p2),))
        smelt = _Smelt(
            {
                a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe), emails=(m.email,)),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert smelt.requests == [*_both(a), *_both(b)]
        assert _backfill_logs(logs) == [_completed(candidates=2, no_op=2)]
        assert summary == ProductCatalogBackfillSummary(2, 0, 2, 0, 0, 0)
        assert await _committed(world, ticket.id, a, b) == _Committed(
            (ANALYSIS, None),
            [maintainer_event(a, m)],
            {a: _seeded_tree(p1), b: _seeded_tree(p2)},
            [(a, m.id)],
        )
        assert m.email not in repr(logs)

    async def test_repeated_backfill_is_idempotent(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A second invocation with unchanged SMELT data repeats both
        requests but creates no row, association, or event."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        product = await _current_product(world)
        (a,) = _names("a")
        await _package(world, ticket, a)
        smelt = _Smelt(
            {
                a: _resolves(
                    codestream(IBS_REF, "SLE_15", product.cpe), emails=(m.email,)
                )
            }
        )
        smelt.install(monkeypatch)

        first = await _backfill(_Sessions(real_session_factory))
        after_first = await _committed(world, ticket.id, a)
        second = await _backfill(_Sessions(real_session_factory))

        assert first == ProductCatalogBackfillSummary(1, 1, 0, 0, 0, 0)
        assert second == ProductCatalogBackfillSummary(1, 0, 1, 0, 0, 0)
        assert smelt.requests == _both(a) * 2
        assert after_first == _Committed(
            (ANALYSIS, None),
            [maintainer_event(a, m), package_added_event(a, None, BACKFILL)],
            {a: _created(product)},
            [(a, m.id)],
        )
        assert await _committed(world, ticket.id, a) == after_first

    @pytest.mark.parametrize(
        "status", [TicketStatus.RESOLVED, TicketStatus.IGNORED], ids=str
    )
    async def test_ticket_inactive_under_the_lock_is_skipped_without_mutation(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An independent session makes the selected Ticket inactive while
        its pair waits on the maintained request. Both SMELT requests still
        complete (diagnostic only), but under the Ticket lock the pair is
        skipped: no tree, maintainer association, event, or publication,
        counted as skipped-inactive."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        product = await _current_product(world)
        (a,) = _names("a")
        await _package(world, ticket, a)
        pause = Pause()
        smelt = _Smelt(
            {
                a: _Answer(
                    _held(
                        pause, maintained(codestream(IBS_REF, "SLE_15", product.cpe))
                    ),
                    reply(200, maintainership(m.email)),
                )
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(_backfill(sessions))
            try:
                await _arrive(pause, task)
                await _set_status(world, ticket, status.value)
            finally:
                pause.release.set()
            summary = await asyncio.wait_for(task, timeout=WAIT)

        assert smelt.requests == _both(a)
        assert _backfill_logs(logs) == [_completed(candidates=1, skipped_inactive=1)]
        assert summary == ProductCatalogBackfillSummary(1, 0, 0, 1, 0, 0)
        assert await _committed(world, ticket.id, a) == _Committed(
            (status.value, None), [], {a: EMPTY_TREE}, []
        )
        assert published.calls == []

    async def test_exclusion_committed_after_selection_is_an_expected_skip(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An independent session excludes package `a` while its pair waits
        on the maintained request. The locked guard raises
        `PackageAlreadyExcludedError`: the pair is rolled back without a
        failure warning and counted as skipped-excluded (the fetched
        maintainer is not associated), and the next package `b` is still
        processed."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        p1, p2 = await _current_product(world), await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b)
        pause = Pause()
        smelt = _Smelt(
            {
                a: _Answer(
                    _held(pause, maintained(codestream(IBS_REF, "SLE_15", p1.cpe))),
                    reply(200, maintainership(m.email)),
                ),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(_backfill(sessions))
            try:
                await _arrive(pause, task)
                await _exclude(world, ticket, a)
            finally:
                pause.release.set()
            summary = await asyncio.wait_for(task, timeout=WAIT)

        assert smelt.requests == [*_both(a), *_both(b)]
        assert _backfill_logs(logs) == [
            _completed(candidates=2, record_creating=1, skipped_excluded=1)
        ]
        assert summary == ProductCatalogBackfillSummary(2, 1, 0, 0, 1, 0)
        assert not sessions.sessions[1].in_transaction()
        assert await _committed(world, ticket.id, a, b) == _Committed(
            (ANALYSIS, None),
            [package_added_event(b, None, BACKFILL)],
            {a: Tree(SEEDED_AT, {}, {}), b: _created(p2)},
            [],
        )
        assert published.calls == []


# ---------------------------------------------------------------------------
# Pair-level failures (Product Catalog Backfill pair outcome table: failed;
# log privacy)
# ---------------------------------------------------------------------------

FAILURES = [
    "smelt-unavailable-http",
    "smelt-unavailable-transport",
    "package-not-found",
    "targets-unresolved",
    "catalog-not-ready",
    "invalid-package-name",
    "database",
    "commit",
]
"""Failures of the first pair; each is isolated and counted as failed."""


@pytest.mark.integration
class TestPairFailures:
    @pytest.mark.parametrize("failure", FAILURES)
    async def test_pair_failure_is_isolated_logged_once_and_counted(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The first pair fails: it is rolled back (no tree, association,
        or event), logged once with exactly the Ticket UUID, the package
        name, the exception class, and for SMELT unavailability the bounded
        category, and counted as failed; the next pair still commits its
        tree. No log carries the SMELT body, a maintainer email, a URL, or
        exception text.

        `catalog-not-ready` starts with no Product at all; the second
        pair's maintained request publishes the first current Product.
        `invalid-package-name` is a persisted `..` marker, which cannot form
        one URL path segment and fails before any request. `database` and
        `commit` inject a driver error into the first pair's flush or
        commit after successful SMELT I/O."""
        m = await world.user(role=Role.RESTRICTED_ANALYST)
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
            assert await _product_count(world) == 0

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
        own = (
            await _current_product(world) if failure in {"database", "commit"} else None
        )
        first = {
            "smelt-unavailable-http": _Answer(
                reply(500, {"status": "error", "data": MARKER})
            ),
            "smelt-unavailable-transport": _Answer(
                fail(httpx.ConnectError(f"https://smelt.example.test/{MARKER}"))
            ),
            "package-not-found": _Answer(reply(404, not_found(MARKER))),
            "targets-unresolved": _resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "catalog-not-ready": _resolves(codestream(IBS_REF, "SLE_15", ABSENT)),
            "invalid-package-name": _Answer(reply(500, {})),
            "database": _resolves(
                codestream(IBS_REF, "SLE_15", own.cpe if own else ABSENT),
                emails=(m.email,),
            ),
            "commit": _resolves(
                codestream(IBS_REF, "SLE_15", own.cpe if own else ABSENT),
                emails=(m.email,),
            ),
        }[failure]
        expected_failure = {
            "smelt-unavailable-http": _pair_failed(
                ticket.id, failing, "SmeltUnavailableError", "http_status"
            ),
            "smelt-unavailable-transport": _pair_failed(
                ticket.id, failing, "SmeltUnavailableError", "transport"
            ),
            "package-not-found": _pair_failed(
                ticket.id, failing, "PackageNotFoundInSmeltError"
            ),
            "targets-unresolved": _pair_failed(
                ticket.id, failing, "PackageTargetsUnresolvedError"
            ),
            "catalog-not-ready": _pair_failed(
                ticket.id, failing, "ProductCatalogNotReadyError"
            ),
            "invalid-package-name": _pair_failed(ticket.id, failing, "ValueError"),
            "database": _pair_failed(ticket.id, failing, "OperationalError"),
            "commit": _pair_failed(ticket.id, failing, "OperationalError"),
        }[failure]
        if failure == "database":
            sessions.hooks[1] = lambda s: _fail_on(s, "before_flush")
        elif failure == "commit":
            sessions.hooks[1] = lambda s: _fail_on(s, "before_commit")
        smelt = _Smelt({failing: first, succeeding: second})
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        failing_requests = {
            "invalid-package-name": [],
            "database": _both(failing),
            "commit": _both(failing),
        }.get(failure, [("maintained", failing)])
        assert smelt.requests == [*failing_requests, *_both(succeeding)]
        assert _backfill_logs(logs) == [
            expected_failure,
            _completed(candidates=2, record_creating=1, failed=1),
        ]
        assert summary == ProductCatalogBackfillSummary(2, 1, 0, 0, 0, 1)
        for forbidden in (MARKER, m.email, "smelt.example.test", "https://"):
            assert forbidden not in repr(logs)
        assert [c.is_closed for c in smelt.fake.clients] == [True]
        assert not sessions.sessions[1].in_transaction()
        assert await _committed(world, ticket.id, failing, succeeding) == _Committed(
            (ANALYSIS, None),
            [package_added_event(succeeding, None, BACKFILL)],
            {failing: EMPTY_TREE, succeeding: _created(products[0])},
            [],
        )
        assert published.calls == []

    async def test_later_failure_does_not_roll_back_earlier_pairs(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The second of three pairs fails in its commit: the first stays
        committed, the second is rolled back, the third commits."""
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
        sessions.hooks[2] = lambda s: _fail_on(s, "before_commit")

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert _backfill_logs(logs) == [
            _pair_failed(ticket.id, b, "OperationalError"),
            _completed(candidates=3, record_creating=2, failed=1),
        ]
        assert summary == ProductCatalogBackfillSummary(3, 2, 0, 0, 0, 1)
        assert await _committed(world, ticket.id, a, b, c) == _Committed(
            (ANALYSIS, None),
            [
                package_added_event(a, None, BACKFILL),
                package_added_event(c, None, BACKFILL),
            ],
            {a: _created(p1), b: EMPTY_TREE, c: _created(p3)},
            [],
        )


# ---------------------------------------------------------------------------
# Whole-run signals (pair outcome table, last row; fetcher-infrastructure.md,
# `SoftTimeLimitExceeded` handling convention)
# ---------------------------------------------------------------------------

SIGNALS = [
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


@pytest.mark.integration
class TestControlSignals:
    @pytest.mark.parametrize("make_signal", SIGNALS)
    async def test_signal_inside_a_pair_propagates_after_cleanup(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """The second pair raises the signal after its locked writes: the
        signal propagates unchanged, that pair is rolled back and its
        session closed, the first pair stays committed, the third is never
        attempted, the shared client is closed, and no failure or
        completion line is logged."""
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
        signal = make_signal()
        real = package_service.add_package_to_ticket

        async def interrupting(db: AsyncSession, **kwargs: Any) -> AddPackageResult:
            result = await real(db, **kwargs)
            if kwargs["package_name"] == b:
                raise signal
            return result

        monkeypatch.setattr(
            product_catalog_backfill, "add_package_to_ticket", interrupting
        )

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await _backfill(sessions)

        assert raised.value is signal
        assert smelt.requests == [*_both(a), *_both(b)]
        assert len(sessions.sessions) == 3
        assert not sessions.sessions[2].in_transaction()
        assert [client.is_closed for client in smelt.fake.clients] == [True]
        assert _backfill_logs(logs) == []
        assert await _committed(world, ticket.id, a, b, c) == _Committed(
            (ANALYSIS, None),
            [package_added_event(a, None, BACKFILL)],
            {a: _created(p1), b: EMPTY_TREE, c: EMPTY_TREE},
            [],
        )
        assert published.calls == []

    async def test_cancellation_during_a_smelt_request_propagates_after_cleanup(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The workflow task is cancelled while its second pair waits on the
        maintained request: cancellation propagates, the first pair stays
        committed, the shared client and the pair session are closed, and
        no completion line is logged."""
        ticket = await _ticket(world)
        p1, p2 = await _current_product(world), await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b)
        pause = Pause()
        smelt = _Smelt(
            {
                a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: _Answer(
                    _held(pause, maintained(codestream(IBS_REF, "SLE_15", p2.cpe)))
                ),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(_backfill(sessions))
            await _arrive(pause, task)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert task.cancelled()
        assert [client.is_closed for client in smelt.fake.clients] == [True]
        assert not sessions.sessions[2].in_transaction()
        assert _backfill_logs(logs) == []
        assert await _committed(world, ticket.id, a, b) == _Committed(
            (ANALYSIS, None),
            [package_added_event(a, None, BACKFILL)],
            {a: _created(p1), b: EMPTY_TREE},
            [],
        )


# ---------------------------------------------------------------------------
# Completion line (Product Catalog Backfill: six counts)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCompletionLine:
    async def test_mixed_run_reports_exact_counts(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Five pairs over three Tickets in UUID order: on the first Ticket,
        `a` creates a tree, `b` is a no-op, and `c` is not found in SMELT;
        while the second Ticket's pair `d` waits on its maintained request,
        an independent session resolves that Ticket and excludes the third
        Ticket's package `e`. The completion line and the returned summary
        carry one count of every outcome."""
        first_id, second_id, third_id = sorted(uuid.uuid4() for _ in range(3))
        first = await _ticket(world, ticket_id=first_id)
        second = await _ticket(world, ticket_id=second_id)
        third = await _ticket(world, ticket_id=third_id)
        p1, p2, p3, p4 = [await _current_product(world) for _ in range(4)]
        a, b, c, d, e = _names("a", "b", "c", "d", "e")
        await _package(world, first, a)
        await _package(world, first, b, tree=((IBS_REF, p2),))
        await _package(world, first, c)
        await _package(world, second, d)
        await _package(world, third, e)
        pause = Pause()
        smelt = _Smelt(
            {
                a: _resolves(codestream(IBS_REF, "SLE_15", p1.cpe)),
                b: _resolves(codestream(IBS_REF, "SLE_15", p2.cpe)),
                c: _Answer(reply(404, not_found(c))),
                d: _Answer(
                    _held(pause, maintained(codestream(IBS_REF, "SLE_15", p3.cpe)))
                ),
                e: _resolves(codestream(IBS_REF, "SLE_15", p4.cpe)),
            }
        )
        smelt.install(monkeypatch)

        with capture_logs() as logs:
            task = asyncio.create_task(_backfill(sessions))
            try:
                await _arrive(pause, task)
                await _set_status(world, second, TicketStatus.RESOLVED.value)
                await _exclude(world, third, e)
            finally:
                pause.release.set()
            summary = await asyncio.wait_for(task, timeout=WAIT)

        completed = _completed(
            candidates=5,
            record_creating=1,
            no_op=1,
            skipped_inactive=1,
            skipped_excluded=1,
            failed=1,
        )
        assert _backfill_logs(logs) == [
            _pair_failed(first.id, c, "PackageNotFoundInSmeltError"),
            completed,
        ]
        assert summary == _summary(completed)
        assert smelt.requests == [
            *_both(a),
            *_both(b),
            ("maintained", c),
            *_both(d),
            *_both(e),
        ]
        assert (await _committed(world, first.id, a, b, c)).trees == {
            a: _created(p1),
            b: _seeded_tree(p2),
            c: EMPTY_TREE,
        }
        assert (await _committed(world, second.id, d)).trees == {d: EMPTY_TREE}
        assert (await _committed(world, third.id, e)).trees == {
            e: Tree(SEEDED_AT, {}, {})
        }
        assert published.calls == []


# ---------------------------------------------------------------------------
# Overlapping invocations (Product Catalog Backfill: overlapping tasks are
# safe; testing-strategy.md, Concurrency Testing)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverlappingInvocations:
    async def test_concurrent_invocations_converge_without_duplicates(
        self,
        world: CommittedWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two invocations over the same committed pairs are both held in
        the first pair's maintainership request, then serialize on the
        Ticket lock: each tree row, association, and event exists exactly
        once, each invocation used its own one client, and both complete
        (one creates the tree, the other observes it as a no-op)."""
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

        with capture_logs() as logs:
            summaries = await asyncio.wait_for(
                asyncio.gather(
                    _backfill(_Sessions(real_session_factory)),
                    _backfill(_Sessions(real_session_factory)),
                ),
                timeout=WAIT * 4,
            )

        assert names == [CLIENT_NAME] * 2
        assert len(smelt.fake.clients) == 2
        assert all(client.is_closed for client in smelt.fake.clients)
        assert arrivals == ["a", "a"]
        assert sorted(smelt.requests) == sorted(_both(a) * 2 + _both(b) * 2)
        assert sorted(summaries, key=lambda s: s.record_creating) == [
            ProductCatalogBackfillSummary(2, 0, 2, 0, 0, 0),
            ProductCatalogBackfillSummary(2, 1, 1, 0, 0, 0),
        ]
        assert sorted(
            (e["record_creating"], e["no_op"]) for e in _backfill_logs(logs)
        ) == [(0, 2), (1, 1)]
        state = await _committed(world, ticket.id, a, b)
        assert sorted(state.events, key=repr) == sorted(
            [
                maintainer_event(a, m1),
                package_added_event(a, None, BACKFILL),
                maintainer_event(b, m2),
            ],
            key=repr,
        )
        assert state.trees == {a: _created(p1), b: _seeded_tree(p2)}
        assert state.maintainers == sorted([(a, m1.id), (b, m2.id)])
        assert published.calls == []


# ---------------------------------------------------------------------------
# Failed-pair rollback (Product Catalog Backfill pair outcome table: failed;
# whole-run signals)
# ---------------------------------------------------------------------------


def _rollback_raises(error: BaseException) -> Callable[[AsyncSession], None]:
    """Hook making the session's explicit rollback raise `error`; the session
    is still closed (and its transaction discarded) by its context manager."""

    def _install(session: AsyncSession) -> None:
        async def _rollback() -> None:
            raise error

        setattr(session, "rollback", _rollback)  # noqa: B010

    return _install


@pytest.mark.integration
class TestFailedPairRollback:
    async def test_a_failing_rollback_keeps_the_original_pair_failure(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The first pair fails with `PackageNotFoundInSmeltError` and its
        rollback then raises a driver error: the pair is still counted and
        logged with its original cause, and the next pair commits."""
        ticket = await _ticket(world)
        product = await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b)
        smelt = _Smelt(
            {
                a: _Answer(reply(404, not_found(a))),
                b: _resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            }
        )
        smelt.install(monkeypatch)
        sessions.hooks[1] = _rollback_raises(_database_failure())

        with capture_logs() as logs:
            summary = await _backfill(sessions)

        assert _backfill_logs(logs) == [
            _pair_failed(ticket.id, a, "PackageNotFoundInSmeltError"),
            _completed(candidates=2, record_creating=1, failed=1),
        ]
        assert summary == ProductCatalogBackfillSummary(2, 1, 0, 0, 0, 1)
        assert MARKER not in repr(logs)
        assert await _committed(world, ticket.id, a, b) == _Committed(
            (ANALYSIS, None),
            [package_added_event(b, None, BACKFILL)],
            {a: EMPTY_TREE, b: _created(product)},
            [],
        )

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_a_whole_run_signal_during_rollback_propagates(
        self,
        world: CommittedWorld,
        sessions: _Sessions,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """A whole-run signal raised by the failed pair's rollback is never
        absorbed: it propagates, no later pair runs, and no completion line
        is logged."""
        ticket = await _ticket(world)
        product = await _current_product(world)
        a, b = _names("a", "b")
        await _package(world, ticket, a)
        await _package(world, ticket, b)
        smelt = _Smelt(
            {
                a: _Answer(reply(404, not_found(a))),
                b: _resolves(codestream(IBS_REF, "SLE_15", product.cpe)),
            }
        )
        smelt.install(monkeypatch)
        signal = make_signal()
        sessions.hooks[1] = _rollback_raises(signal)

        with capture_logs() as logs, pytest.raises(type(signal)):
            await _backfill(sessions)

        assert _backfill_logs(logs) == []
        assert smelt.requests == [("maintained", a)]
        assert [c.is_closed for c in smelt.fake.clients] == [True]
