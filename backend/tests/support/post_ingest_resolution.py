"""Shared helpers for the post-ingest CVE package-resolution workflow tests.

`package_service.run_post_ingest_package_resolution()` owns one fresh
session and transaction per package and one shared HTTP client per
invocation (package-service.md, Post-ingest CVE package resolution). These
helpers provide:

- `install_environment()`: the service date `EVAL`, the fictional SMELT
  origin, and an HTTP-client factory that fails unless a test installs the
  SMELT fake; `record_publications()`, `record_disposals()`, and
  `install_additions()` (a spy on the delegated `add_package_to_ticket()`
  that can raise for one package before or after its real locked writes);
- `Sessions`, a recording session factory over a real `async_sessionmaker`
  that appends each `commit`, `rollback`, and `close` to an ordered event
  list, and `Smelt`, a `PackageSmelt` fake routed per package name that
  appends each request to the same list, so a test proves that a unit was
  finished before the next package's first request;
- committed seeding and observation on a `CommittedWorld`
  (`tests/support/suse_cvss_races.py`), whose rows the consumer deletes at
  teardown;
- the exact expected workflow events (package-service.md, Audit and
  observability; issue #786 decision D2) and `assert_private()`.

Consumers: `tests/test_services/test_post_ingest_package_resolution.py` and
`tests/test_services/test_post_ingest_package_resolution_races.py`.

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test. All
values are fictional.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.config import settings
from app.core.enums import PackageStatus, Severity, TicketStatus, WorkflowType
from app.models.product import Product
from app.models.ticket import Ticket
from app.services import package_service, task_publication
from app.services.package_service import (
    AddPackageResult,
    PackageAddedComment,
    ValidatedCPEMatch,
    run_post_ingest_package_resolution,
)
from tests.support.package_addition import (
    MAINTAINED_PATH,
    PackageSmelt,
    Pause,
    Respond,
    maintained,
    maintainership,
    publish,
    reply,
)
from tests.support.package_records import (
    NEW_TRACK,
    OccurrenceState,
    TrackState,
    Tree,
    maintainers,
    new_occurrence,
    package_added_event,
    package_tree,
    seed_occurrence,
    seed_package,
    seed_track,
    ticket_row,
)
from tests.support.package_records_races import IBS_REF, WAIT, world_product
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import EVAL, EventRow, ticket_events_by_id

LogEntry = MutableMapping[str, Any]
Event = tuple[str, ...]

CVE_RESOLUTION: PackageAddedComment = "CVE package resolution"
"""The canonical `package_added` comment of a post-ingest package unit."""

CLIENT_NAME = "resolve_ticket_packages"

EMPTY = "ticket_package_resolution_empty"
NO_MATCH = "ticket_package_resolution_no_match"
EXCLUDED = "ticket_package_resolution_excluded"
INACTIVE = "ticket_package_resolution_inactive"
PACKAGE_FAILED = "ticket_package_resolution_package_failed"
PARTIAL = "ticket_package_resolution_partial"
COMPLETED = "ticket_package_resolution_completed"
FAILED = "ticket_package_resolution_failed"

COUNT_KEYS = (
    "packages",
    "package_tree_changed",
    "package_tree_no_op",
    "maintainer_only",
    "no_match",
    "excluded",
    "package_failed",
    "not_attempted",
)
"""The aggregate counts of a terminal event (issue #786 D2)."""

ALLOWED_KEYS = frozenset(
    {"event", "log_level", "ticket_id", "phase", "cause", "category", *COUNT_KEYS}
)
"""The only fields a workflow event may carry (package-service.md, Audit
and observability; the task-bound `celery_task_id` is merged by the
logging configuration, not by the workflow)."""

ABSENT = "cpe:/o:example:absent:1"
"""A CPE that no catalog Product carries."""

MARKER = "Example-Confidential-Resolution-Value"
"""A value that must never reach a workflow event."""

ANALYSIS = TicketStatus.ANALYSIS.value
ANALYZED = TicketStatus.ANALYZED.value

# ---------------------------------------------------------------------------
# Environment and recorders
# ---------------------------------------------------------------------------


def install_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is `EVAL`; SMELT URLs use the fictional test
    origin; creating an HTTP client fails the test unless the test installs
    a `Smelt`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)

    def _no_client(name: str, **overrides: Any) -> httpx.AsyncClient:
        raise AssertionError("no HTTP client may be created")

    monkeypatch.setattr(package_service, "create_http_client", _no_client)


@dataclass
class Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})


def record_publications(monkeypatch: pytest.MonkeyPatch) -> Publish:
    """Substitute `task_publication.publish_task` by a recorder."""
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


def record_disposals(monkeypatch: pytest.MonkeyPatch) -> list[AsyncEngine]:
    """Record every `AsyncEngine.dispose()` awaited during the test."""
    recorded: list[AsyncEngine] = []
    real = AsyncEngine.dispose

    async def _dispose(self: AsyncEngine, close: bool = True) -> None:
        recorded.append(self)
        await real(self, close)

    monkeypatch.setattr(AsyncEngine, "dispose", _dispose)
    return recorded


class Sessions:
    """Session factory passed to the workflow: delegates to the real factory,
    records every session it opens (one per package), and appends
    `(operation, index)` to `events` for each `commit`, `rollback`, and
    `close`. `hooks[index]` instruments one session afterwards."""

    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        events: list[Event] | None = None,
    ) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.closed: list[bool] = []
        self.hooks: dict[int, Callable[[AsyncSession], None]] = {}
        self.events: list[Event] = [] if events is None else events

    def __call__(self) -> AsyncSession:
        index = len(self.sessions)
        session = self._factory()
        self.closed.append(False)
        for operation in ("commit", "rollback", "close"):
            self._record(session, index, operation)
        if index in self.hooks:
            self.hooks[index](session)
        self.sessions.append(session)
        return session

    def _record(self, session: AsyncSession, index: int, operation: str) -> None:
        original = getattr(session, operation)

        async def recorded() -> None:
            self.events.append((operation, str(index)))
            if operation == "close":
                self.closed[index] = True
            await original()

        setattr(session, operation, recorded)

    def maker(self) -> async_sessionmaker[AsyncSession]:
        return cast(async_sessionmaker[AsyncSession], self)

    def of(self, index: int) -> list[str]:
        """The recorded operations of session `index`, in order."""
        return [e[0] for e in self.events if e[0] != "http" and e[1] == str(index)]


def database_failure() -> OperationalError:
    return OperationalError("fictional statement", None, Exception(MARKER))


def fail_on(session: AsyncSession, event_name: str) -> None:
    """Make `event_name` of the session raise a driver-level error."""

    def _raise(*_args: Any) -> None:
        raise database_failure()

    event.listen(session.sync_session, event_name, _raise)


def rollback_raises(error: BaseException) -> Callable[[AsyncSession], None]:
    """Hook making the session's explicit rollback raise `error`; the session
    is still closed (and its transaction discarded) by its context manager."""

    def _install(session: AsyncSession) -> None:
        async def _rollback() -> None:
            raise error

        setattr(session, "rollback", _rollback)  # noqa: B010

    return _install


# ---------------------------------------------------------------------------
# Fake SMELT routed per package
# ---------------------------------------------------------------------------


def package_of(request: httpx.Request) -> str:
    segments = request.url.path.split("/")
    return segments[-1] if MAINTAINED_PATH in request.url.path else segments[-2]


@dataclass
class Answer:
    """The responses for one package name."""

    maintained: Respond
    maintainership: Respond = field(
        default_factory=lambda: reply(200, maintainership())
    )


def resolves(*entries: dict[str, Any], emails: tuple[str, ...] = ()) -> Answer:
    return Answer(reply(200, maintained(*entries)), reply(200, maintainership(*emails)))


class Smelt:
    """A `PackageSmelt` whose responses are chosen by the package name of
    each request. Every request appends `("http", kind, package)` to
    `events`; `on_request` is awaited before every response."""

    def __init__(
        self, answers: dict[str, Answer], events: list[Event] | None = None
    ) -> None:
        self.answers = answers
        self.events: list[Event] = [] if events is None else events
        self.on_request: Callable[[str, str], Awaitable[None]] | None = None
        self.fake = PackageSmelt(
            maintained=self._route("maintained"),
            maintainership=self._route("maintainership"),
        )

    def _route(self, kind: str) -> Respond:
        async def respond(request: httpx.Request) -> httpx.Response:
            package = package_of(request)
            self.events.append(("http", kind, package))
            if self.on_request is not None:
                await self.on_request(kind, package)
            response = getattr(self.answers[package], kind)(request)
            if inspect.isawaitable(response):
                response = await response
            return cast(httpx.Response, response)

        return respond

    @property
    def requests(self) -> list[tuple[str, str]]:
        """`(kind, package)` of every request, in order."""
        return [(kind, package_of(r)) for kind, r in self.fake.requests]

    def install(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        """Make `package_service.create_http_client()` return a client of
        this fake; return the list of requested client names."""
        names: list[str] = []

        def _factory(name: str, **overrides: Any) -> httpx.AsyncClient:
            names.append(name)
            return self.fake.client()

        monkeypatch.setattr(package_service, "create_http_client", _factory)
        return names

    def closed(self) -> list[bool]:
        return [client.is_closed for client in self.fake.clients]


def both(name: str) -> list[tuple[str, str]]:
    return [("maintained", name), ("maintainership", name)]


def http_events(name: str, *kinds: str) -> list[Event]:
    return [("http", kind, name) for kind in kinds or ("maintained", "maintainership")]


def held_response(pause: Pause, body: dict[str, Any]) -> Respond:
    """Hold the request on `pause`, then answer HTTP 200 with `body`."""

    async def respond(request: httpx.Request) -> httpx.Response:
        await pause.hold()
        return httpx.Response(200, json=body)

    return respond


async def arrive(pause: Pause, task: asyncio.Task[Any]) -> None:
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
# Delegation spy
# ---------------------------------------------------------------------------


@dataclass
class Additions:
    """Records every `add_package_to_ticket()` call of the workflow and
    raises `before[name]` (instead of calling it) or `after[name]` (after
    its real locked writes) for that package."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    before: dict[str, BaseException] = field(default_factory=dict)
    after: dict[str, BaseException] = field(default_factory=dict)


def install_additions(monkeypatch: pytest.MonkeyPatch) -> Additions:
    """Substitute the workflow's `add_package_to_ticket()` by an `Additions`
    spy around the real orchestrator."""
    spy = Additions()
    real = package_service.add_package_to_ticket

    async def _add(db: AsyncSession, **kwargs: Any) -> AddPackageResult:
        spy.calls.append({"db": db, **kwargs})
        name = kwargs["package_name"]
        if name in spy.before:
            raise spy.before.pop(name)
        result = await real(db, **kwargs)
        if name in spy.after:
            raise spy.after.pop(name)
        return result

    monkeypatch.setattr(package_service, "add_package_to_ticket", _add)
    return spy


# ---------------------------------------------------------------------------
# Committed seeding and observation
# ---------------------------------------------------------------------------


def package_names(*tags: str) -> list[str]:
    suffix = uuid.uuid4().hex[:8]
    return [f"fictional-{tag}-{suffix}" for tag in tags]


async def seed_ticket(
    world: CommittedWorld,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    duplicate_of: uuid.UUID | None = None,
) -> Ticket:
    """A committed CVE-less `High` Ticket."""
    ticket = Ticket(
        status=status.value,
        severity_manual=Severity.HIGH.value,
        duplicate_of_id=duplicate_of,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


async def current_product(world: CommittedWorld) -> Product:
    """A committed catalog Product published in the current snapshot."""
    product = await world_product(world)
    await publish(world.session, product)
    await world.session.commit()
    return product


async def commit_package(
    world: CommittedWorld,
    ticket: Ticket,
    name: str,
    *,
    excluded: bool = False,
    tree: tuple[tuple[str, Product], ...] = (),
    status: PackageStatus = PackageStatus.ANALYSIS,
) -> None:
    """Commit a package marker with an optional complete IBS tree."""
    package = await seed_package(world.session, ticket.id, name, excluded=excluded)
    for reference, product in tree:
        track = await seed_track(world.session, package, reference, status=status)
        await seed_occurrence(world.session, track, product)
    await world.session.commit()


async def set_status(world: CommittedWorld, ticket: Ticket, status: str) -> None:
    """Commit a Ticket status change from an independent session."""
    concurrent = await world.open_session()
    await concurrent.execute(
        update(Ticket).where(Ticket.id == ticket.id).values(status=status)
    )
    await concurrent.commit()


@dataclass(frozen=True, slots=True)
class Committed:
    """The committed Ticket `(status, assignee)`, its events, the trees of
    the given packages, and every maintainer association."""

    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]
    trees: dict[str, Tree | None]
    maintainers: list[tuple[str, uuid.UUID]]


async def committed(
    world: CommittedWorld, ticket_id: uuid.UUID, *names: str
) -> Committed:
    probe = await world.open_session()
    state = Committed(
        await ticket_row(probe, ticket_id),
        await ticket_events_by_id(probe, ticket_id),
        {name: await package_tree(probe, ticket_id, name) for name in names},
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


async def count_rows(world: CommittedWorld, model: type[Any]) -> int:
    probe = await world.open_session()
    count = (await probe.execute(select(func.count()).select_from(model))).scalar_one()
    await probe.rollback()
    return int(count)


def created_tree(product: Product) -> Tree:
    """An included marker with a new `IBS_REF` track holding one new
    eligible occurrence (package-service.md, Record Creation Logic)."""
    return Tree(
        None,
        {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
        {(IBS_REF, product.id): new_occurrence(True)},
    )


def seeded_tree(product: Product) -> Tree:
    """A seeded `ANALYSIS`/`PENDING` `IBS_REF` track with one eligible
    occurrence."""
    return Tree(
        None,
        {IBS_REF: TrackState("ibs", "ANALYSIS", "PENDING", None)},
        {(IBS_REF, product.id): OccurrenceState(True, False, None, None)},
    )


def added(name: str) -> EventRow:
    """The system `package_added` of a post-ingest unit."""
    return package_added_event(name, None, CVE_RESOLUTION)


# ---------------------------------------------------------------------------
# Invocation and expected events
# ---------------------------------------------------------------------------


async def resolve(
    sessions: Sessions,
    ticket_id: uuid.UUID,
    *names: str,
    cpe_matches: tuple[ValidatedCPEMatch, ...] = (),
    affected_cpes: tuple[str, ...] = (),
    vendor_products: tuple[tuple[str, str], ...] = (),
) -> None:
    await run_post_ingest_package_resolution(
        ticket_id=ticket_id,
        cpe_matches=cpe_matches,
        affected_cpes=affected_cpes,
        vendor_products=vendor_products,
        resolved_packages=names,
        session_factory=sessions.maker(),
    )


def workflow_logs(logs: list[LogEntry]) -> list[LogEntry]:
    return [e for e in logs if str(e["event"]).startswith("ticket_package_resolution_")]


def count_fields(packages: int, **counts: int) -> dict[str, int]:
    values = dict.fromkeys(COUNT_KEYS, 0)
    values["packages"] = packages
    assert set(counts) <= set(COUNT_KEYS)
    values.update(counts)
    return values


def terminal_event(
    name: str, level: str, ticket_id: uuid.UUID, packages: int, **counts: int
) -> LogEntry:
    return {
        "event": name,
        "log_level": level,
        "ticket_id": str(ticket_id),
        **count_fields(packages, **counts),
    }


def completed(ticket_id: uuid.UUID, packages: int, **counts: int) -> LogEntry:
    return terminal_event(COMPLETED, "info", ticket_id, packages, **counts)


def partial(ticket_id: uuid.UUID, packages: int, **counts: int) -> LogEntry:
    return terminal_event(PARTIAL, "warning", ticket_id, packages, **counts)


def inactive(ticket_id: uuid.UUID, packages: int, **counts: int) -> LogEntry:
    return terminal_event(INACTIVE, "info", ticket_id, packages, **counts)


def failed(
    ticket_id: uuid.UUID, phase: str, cause: str, packages: int, **counts: int
) -> LogEntry:
    return {
        "event": FAILED,
        "log_level": "error",
        "ticket_id": str(ticket_id),
        "phase": phase,
        "cause": cause,
        **count_fields(packages, **counts),
    }


def single(name: str, ticket_id: uuid.UUID) -> LogEntry:
    return {"event": name, "log_level": "info", "ticket_id": str(ticket_id)}


def package_failed(
    ticket_id: uuid.UUID, cause: str, category: str | None = None
) -> LogEntry:
    entry: LogEntry = {
        "event": PACKAGE_FAILED,
        "log_level": "warning",
        "ticket_id": str(ticket_id),
        "cause": cause,
    }
    if category is not None:
        entry["category"] = category
    return entry


def assert_private(logs: list[LogEntry], *secrets: str) -> None:
    """Workflow events carry only permitted fields and none of `secrets`,
    `MARKER`, a URL, or a CPE (issue #786 D2)."""
    entries = workflow_logs(logs)
    assert all(set(entry) <= ALLOWED_KEYS for entry in entries)
    text = repr(entries)
    for forbidden in (MARKER, "https://", "smelt.example.test", "cpe:", *secrets):
        assert forbidden not in text
