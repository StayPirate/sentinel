"""Shared harness for the all-CVE CVSS recalculation runner tests
(`run_cvss_derived_state_recalculation()`,
backend/app/services/cvss_recalculation.py).

Consumers:

- `tests/test_services/test_cvss_recalculation.py` (pagination,
  coordination, transactions, publication handoff, errors, counters, and
  connection ownership);
- `tests/test_services/test_cvss_recalculation_races.py` (concurrency and
  races against independent holder transactions);
- `tests/test_services/test_cvss_recalculation_domain.py` (the
  default-version domain matrix through the runner).

The runner visits every persisted CVE, so a consumer commits its complete
population and deletes it explicitly (testing-strategy.md, Concurrency
Testing): the worker database holds no other committed CVE. Consumers wrap
`recalculation_harness()` in their own fixture, as the `CommittedWorld`
consumers do, instead of sharing a conftest fixture.

The fenced connection is borrowed (umbrella #833 P9, issue #836 U3): it
comes from a dedicated `NullPool` engine on the worker test database, as in
`test_cvss_recalculation_coordination_fence.py`, never from the shared
test engine's pool, and the factory passed to the workflow is bound to it.
Teardown proves that the connection has no open transaction, closes it
(ending its backend session), deletes the committed rows, and proves the
execution fence is free. Correlation follows U7: the workflow never binds
`celery_task_id`, so `task_correlation()` binds it as the `task_prerun`
signal does.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, TypeVar

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import BigInteger, bindparam, delete, event, func, insert, select, text
from sqlalchemy import update as sql_update
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from structlog.contextvars import bound_contextvars, merge_contextvars
from structlog.testing import capture_logs
from structlog.typing import EventDict, Processor

from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import (
    cvss_recalculation,
    task_publication,
    ticket_convergence_publication,
    ticket_mutations,
)
from app.services.cvss_recalculation_coordination import (
    EXECUTION_FENCE_ID,
    LEASE_KEY,
    LeaseAcquireOutcome,
    acquire_lease,
)
from app.services.ticket_convergence_publication import RUN_TICKET_CONVERGENCE_TASK
from tests.support.cvss_chain import Assessment
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    RELEASED_AT,
    Prod,
)

T = TypeVar("T")

TARGET = "3.1"
"""The persisted `default_cvss_version` and run target of the consumers."""

SETTING_KEY = "default_cvss_version"

LEAK_MARKER = "FICTIONAL-SECRET-MARKER-0836"
"""Planted in every injected exception's text; no event may carry it."""

_DEADLINE = 5.0
_POLL_INTERVAL = 0.01

_FENCE_ID = bindparam("fence_id", EXECUTION_FENCE_ID, type_=BigInteger)

_FENCE_HOLDERS = text(
    "SELECT pid FROM pg_locks "
    "WHERE locktype = 'advisory' AND granted AND mode = 'ExclusiveLock' "
    "AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
    "AND classid::bigint = :fence_id >> 32 "
    "AND objid::bigint = :fence_id & 4294967295 "
    "AND objsubid = 1"
).bindparams(_FENCE_ID)
"""The backend PIDs holding the session-level fence (the fence test query):
a bigint advisory key is reported as its high and low 32 bits with
`objsubid` 1."""

_TRY_XACT_LOCK = text("SELECT pg_try_advisory_xact_lock(:fence_id)").bindparams(
    _FENCE_ID
)

_NON_ADVISORY_LOCKS = text(
    "SELECT locktype, mode FROM pg_locks "
    "WHERE pid = :pid AND locktype <> 'advisory' ORDER BY locktype, mode"
)
"""Every lock of a backend other than the fence: a backend with no open
transaction holds none (no virtual transaction ID, relation, or tuple
lock)."""

_VECTORS = {
    "3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
}


# ---------------------------------------------------------------------------
# Injected failures
# ---------------------------------------------------------------------------


class _FictionalDriverError(Exception):
    """A driver exception carrying a SQLSTATE, as asyncpg's does."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(f"fictional driver failure {LEAK_MARKER}")
        self.sqlstate = sqlstate


def database_error(
    error_class: type[DBAPIError] = OperationalError,
    *,
    sqlstate: str = "08006",
    invalidated: bool = False,
) -> DBAPIError:
    """A `DBAPIError` subclass instance whose statement and driver text
    carry `LEAK_MARKER`."""
    return error_class(
        f"UPDATE cve SET severity = 'Critical' /* {LEAK_MARKER} */",
        None,
        _FictionalDriverError(sqlstate),
        connection_invalidated=invalidated,
    )


def deadlock(*, invalidated: bool = False) -> DBAPIError:
    """A `40P01` (`deadlock_detected`) `DBAPIError`; isolable only on a
    still-valid connection (Error Taxonomy)."""
    return database_error(sqlstate="40P01", invalidated=invalidated)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


@contextmanager
def task_correlation(task_id: str) -> Iterator[None]:
    """Bind `celery_task_id` as the `task_prerun` signal does (U7), and
    restore the previous context afterwards."""
    with bound_contextvars(celery_task_id=task_id):
        yield


@contextmanager
def capture_events(*processors: Processor) -> Iterator[list[EventDict]]:
    """Capture every structlog event with the bound correlation merged in;
    `processors` run before the capture (for example to interleave events
    with a spy's sequence)."""
    with capture_logs(processors=[merge_contextvars, *processors]) as logs:
        yield logs


def runner_events(logs: Sequence[EventDict]) -> list[dict[str, Any]]:
    """The runner and coordination events (`cvss_recalculation_*`)."""
    return [
        dict(entry)
        for entry in logs
        if str(entry["event"]).startswith("cvss_recalculation_")
    ]


def counters(
    changed: int = 0, unchanged: int = 0, skipped: int = 0, failed: int = 0
) -> dict[str, int]:
    """The six run counters, with the specified derivations
    `succeeded = changed + unchanged` and
    `processed = succeeded + skipped + failed` (Outcome Classification)."""
    succeeded = changed + unchanged
    return {
        "changed": changed,
        "unchanged": unchanged,
        "skipped": skipped,
        "failed": failed,
        "succeeded": succeeded,
        "processed": succeeded + skipped + failed,
    }


def completed_run(
    task_id: str, watermark: uuid.UUID, **counts: int
) -> list[dict[str, Any]]:
    """The exact runner event sequence of a delivery that adopted, started
    at `watermark`, and terminated `completed` with `counts` (Logging;
    Coordination Logging)."""
    correlation = {"celery_task_id": task_id, "target_version": TARGET}
    run = {**correlation, "watermark": str(watermark)}
    return [
        {"event": cvss_recalculation.ADOPTED_EVENT, "log_level": "info", **correlation},
        {
            "event": cvss_recalculation.STARTED_EVENT,
            "log_level": "info",
            **run,
            **counters(),
        },
        {
            "event": cvss_recalculation.COMPLETED_EVENT,
            "log_level": "info",
            **run,
            **counters(**counts),
        },
    ]


# ---------------------------------------------------------------------------
# Spies
# ---------------------------------------------------------------------------

Hook = Callable[[int], Awaitable[None]]
"""An awaited hook receiving the zero-based call index; it may raise."""


class ManualClock:
    """The controlled renewal-checkpoint clock (`_monotonic`, U9)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingSessionMaker(async_sessionmaker[AsyncSession]):
    """A factory bound to the borrowed connection that records every
    session the workflow creates and whether the connection had an open
    transaction at that moment."""

    def __init__(self, connection: AsyncConnection) -> None:
        super().__init__(bind=connection, expire_on_commit=False)
        self.connection = connection
        self.created: list[tuple[AsyncSession, bool]] = []

    def __call__(self, **local_kw: Any) -> AsyncSession:
        in_transaction = self.connection.in_transaction()
        session = super().__call__(**local_kw)
        self.created.append((session, in_transaction))
        return session


class ChainSpy:
    """Wraps `ticket_mutations.recalculate_cvss_chain()`, which the workflow
    calls through the module object, recording each unit's session and
    keyword arguments. `before[i]` runs before the real chain of call `i`
    and `after[i]` after it returned (inside the unit transaction, before
    the workflow commits); either may raise."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[dict[str, Any]] = []
        self.sessions: list[AsyncSession] = []
        self.before: dict[int, Hook] = {}
        self.after: dict[int, Hook] = {}
        original = ticket_mutations.recalculate_cvss_chain

        async def _chain(db: AsyncSession, **kwargs: Any) -> Any:
            index = len(self.calls)
            self.calls.append(kwargs)
            self.sessions.append(db)
            if (hook := self.before.get(index)) is not None:
                await hook(index)
            result = await original(db, **kwargs)
            if (hook := self.after.get(index)) is not None:
                await hook(index)
            return result

        monkeypatch.setattr(ticket_mutations, "recalculate_cvss_chain", _chain)

    @property
    def cve_ids(self) -> list[uuid.UUID]:
        return [call["cve_id"] for call in self.calls]

    def is_unit(self, session: AsyncSession) -> bool:
        return any(session is unit for unit in self.sessions)


class DrainSpy:
    """Wraps the runner's post-commit `drain_ticket_convergence()`.
    `before[i]` runs before the real drain of unit `i` (a raising hook is a
    drain exception) and `after[i]` after it, at the unit boundary."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls = 0
        self.before: dict[int, Hook] = {}
        self.after: dict[int, Hook] = {}
        original = ticket_convergence_publication.drain_ticket_convergence

        async def _drain(session: AsyncSession) -> None:
            index = self.calls
            self.calls += 1
            if (hook := self.before.get(index)) is not None:
                await hook(index)
            await original(session)
            if (hook := self.after.get(index)) is not None:
                await hook(index)

        monkeypatch.setattr(cvss_recalculation, "drain_ticket_convergence", _drain)


@dataclass
class PublishRecorder:
    """Substitute for `task_publication.publish_task` (the broker call);
    `errors` maps a Ticket UUID string to the exception its publication
    raises."""

    calls: list[str] = field(default_factory=list)
    errors: dict[str, BaseException] = field(default_factory=dict)
    on_call: Callable[[str], Awaitable[None]] | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        assert task_name == RUN_TICKET_CONVERGENCE_TASK
        ticket_id: str = options["kwargs"]["ticket_id"]
        self.calls.append(ticket_id)
        if self.on_call is not None:
            await self.on_call(ticket_id)
        if (error := self.errors.get(ticket_id)) is not None:
            raise error


class ConnectionStatements:
    """Records the statements and parameters of one connection only."""

    def __init__(self, connection: AsyncConnection) -> None:
        sync_connection = connection.sync_connection
        assert sync_connection is not None
        self._target = sync_connection
        self.statements: list[tuple[str, Any]] = []

    def _record(self, *args: Any) -> None:
        self.statements.append((args[2], args[3]))

    def __enter__(self) -> ConnectionStatements:
        event.listen(self._target, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._target, "before_cursor_execute", self._record)

    def pages(self) -> list[tuple[str, Any]]:
        """The keyset page reads (`SELECT cve.id, cve.cve_id ... ORDER BY
        cve.id LIMIT`), in execution order."""
        return [
            (statement, parameters)
            for statement, parameters in self.statements
            if statement.startswith("SELECT cve.id, cve.cve_id \nFROM cve")
            and "ORDER BY cve.id \n LIMIT" in statement
        ]


# ---------------------------------------------------------------------------
# Committed population
# ---------------------------------------------------------------------------


def _assessment_severity(score: Decimal) -> str:
    if score >= Decimal("9.0"):
        return "critical"
    if score >= Decimal("7.0"):
        return "high"
    if score >= Decimal("4.0"):
        return "medium"
    return "low"


class RecalculationWorld(CommittedWorld):
    """Committed rows of one runner test on independent connections of the
    dedicated engine, deleted explicitly at teardown and restricted to the
    IDs the test created. The `default_cvss_version` row is created only
    when absent and removed only when this world created it; otherwise its
    original value is restored."""

    def __init__(self, engine: AsyncEngine, connection: AsyncConnection) -> None:
        self._engine = engine
        self._connections = [connection]
        super().__init__(
            self._open_session, AsyncSession(bind=connection, expire_on_commit=False)
        )
        self._setting_created = False
        self._setting_original: str | None = None

    @classmethod
    async def create(cls, engine: AsyncEngine) -> RecalculationWorld:
        return cls(engine, await engine.connect())

    async def _open_session(self) -> AsyncSession:
        connection = await self._engine.connect()
        self._connections.append(connection)
        return AsyncSession(bind=connection, expire_on_commit=False)

    async def read(self, reader: Callable[[AsyncSession], Awaitable[T]]) -> T:
        """Run `reader` on the world session, then end its transaction.

        A successful read ends with a commit: a rollback would expire the
        ORM rows this world returned (`expire_on_commit=False` does not
        cover it), and a later attribute access would then load lazily."""
        try:
            value = await reader(self.session)
        except BaseException:
            await self.session.rollback()
            raise
        await self.session.commit()
        return value

    # -- setting ------------------------------------------------------------

    async def ensure_setting(self, value: str) -> None:
        current = await self.read(_setting_value)
        if current is None:
            self.session.add(SystemSetting(key=SETTING_KEY, value=value))
            self._setting_created = True
            await self.session.commit()
            return
        self._setting_original = current
        await self.set_setting(value)

    async def set_setting(self, value: str) -> None:
        """Write the setting directly and commit (no setting audit)."""
        await self.session.execute(
            sql_update(SystemSetting)
            .where(SystemSetting.key == SETTING_KEY)
            .values(value=value)
        )
        await self.session.commit()

    async def delete_setting(self) -> None:
        await self.session.execute(
            delete(SystemSetting).where(SystemSetting.key == SETTING_KEY)
        )
        await self.session.commit()

    async def setting(self) -> str | None:
        return await self.read(_setting_value)

    # -- CVEs ---------------------------------------------------------------

    async def bulk_cves(self, count: int) -> list[uuid.UUID]:
        """Insert `count` ticketless CVEs without assessments in one
        statement; returns their IDs in ascending order."""
        prefix = uuid.uuid4().int % 10**6
        ids = [uuid.uuid7() for _ in range(count)]
        self.cve_ids.extend(ids)
        await self.session.execute(
            insert(CVE),
            [
                {"id": cve_id, "cve_id": f"CVE-2099-{prefix:06d}{n:05d}"}
                for n, cve_id in enumerate(ids)
            ],
        )
        await self.session.commit()
        return sorted(ids)

    async def scored_cve(
        self,
        *assessments: Assessment,
        severity: Severity | None = None,
        cve_uuid: uuid.UUID | None = None,
    ) -> CVE:
        """One CVE with the given assessments and persisted `severity`."""
        cve = CVE(
            cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}",
            severity=severity.value if severity else None,
        )
        if cve_uuid is not None:
            cve.id = cve_uuid
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        for assessment in assessments:
            score = Decimal(assessment.score)
            self.session.add(
                CVECVSSAssessment(
                    cve_id=cve.id,
                    provider_name=assessment.provider,
                    cvss_version=assessment.version,
                    score=score,
                    severity=_assessment_severity(score),
                    vector_string=_VECTORS.get(
                        assessment.version, f"CVSS:{assessment.version}/AV:N"
                    ),
                )
            )
        await self.session.commit()
        return cve

    async def set_cve_severity(self, cve_id: uuid.UUID, severity: str | None) -> None:
        await self.session.execute(
            sql_update(CVE).where(CVE.id == cve_id).values(severity=severity)
        )
        await self.session.commit()

    async def delete_cve(self, cve_id: uuid.UUID) -> None:
        await self.session.execute(delete(CVE).where(CVE.id == cve_id))
        await self.session.commit()

    async def cve_count(self) -> int:
        return await self.read(_cve_count)

    # -- Tickets ------------------------------------------------------------

    async def analyst(self, *, active: bool = True) -> User:
        """A committed `vulnerability_analyst` User."""
        user = await self.user(role=Role.VULNERABILITY_ANALYST)
        if not active:
            await self.session.execute(
                sql_update(User).where(User.id == user.id).values(active=False)
            )
            await self.session.commit()
        return user

    async def track(
        self,
        ticket: Ticket,
        *,
        status: PackageStatus,
        products: Sequence[Prod] = (Prod(),),
    ) -> None:
        """One package with one track and its Product occurrences; an
        in-support Product's General Support ends after `EVAL`, an EOL
        Product's before it."""
        now = datetime.now(UTC)
        suffix = uuid.uuid4().hex[:10]
        package = TicketPackage(
            ticket_id=ticket.id, package_name=f"fictional-recalc-{suffix}"
        )
        self.session.add(package)
        await self.session.flush()
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{suffix}:Update",
            status=status.value,
        )
        self.session.add(track)
        await self.session.flush()
        for spec in products:
            name = uuid.uuid4().hex[:10]
            gs_end = None
            if spec.lifecycle:
                gs_end = BEFORE_EVAL if spec.eol else AFTER_EVAL
            product = Product(
                name=f"Example Product {name}",
                version="1",
                display_name=f"EP {name}",
                cpe=f"cpe:/o:example:product:{name}",
                catalog_last_seen_at=now,
                cvss_threshold=spec.threshold,
                general_support_end_date=gs_end,
            )
            self.session.add(product)
            await self.session.flush()
            self.product_ids.append(product.id)
            self.session.add(
                TicketPackageProduct(
                    ticket_package_track_id=track.id,
                    product_id=product.id,
                    eligible=spec.eligible,
                    is_eligible_override=spec.override,
                    released_at=RELEASED_AT if spec.released else None,
                    deleted_at=now if spec.excluded else None,
                )
            )
        await self.session.commit()

    async def regressing_ticket(
        self, *, cve_severity: Severity = Severity.MEDIUM, assignee_active: bool = True
    ) -> tuple[CVE, Ticket, User]:
        """A `Resolved` Ticket that the default-version chain at `3.1`
        regresses to `Analyzed` and registers one convergence effect for:
        its CVE has one SUSE 3.1 `9.8` assessment, and its FIXED track's
        only Product (threshold 9.0, not released) becomes eligible, so
        resolution is no longer complete (the chain test precedent). With
        the default stale `Medium` severity, the unit also changes the
        severity and the automatic priority (`P4` to `P2`); an inactive
        assignee is sanitized."""
        cve = await self.scored_cve(Assessment("9.8"), severity=cve_severity)
        assignee = await self.analyst(active=assignee_active)
        ticket = await self.ticket(
            cve_id=cve.id,
            status=TicketStatus.RESOLVED,
            priority_auto="P4" if cve_severity is Severity.MEDIUM else "P2",
            assignee_id=assignee.id,
        )
        await self.track(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(eligible=False, threshold=Decimal("9.0")),),
        )
        return cve, ticket, assignee

    # -- teardown -----------------------------------------------------------

    async def _restore_setting(self) -> None:
        if self._setting_created:
            await self.delete_setting()
        elif self._setting_original is not None:
            if await self.setting() is None:
                self.session.add(
                    SystemSetting(key=SETTING_KEY, value=self._setting_original)
                )
                await self.session.commit()
            else:
                await self.set_setting(self._setting_original)

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
            await self._restore_setting()
        finally:
            for session in self._sessions:
                await session.close()
            await self.session.close()
            for connection in self._connections:
                await connection.close()


async def _setting_value(session: AsyncSession) -> str | None:
    return (
        await session.execute(
            select(SystemSetting.value).where(SystemSetting.key == SETTING_KEY)
        )
    ).scalar_one_or_none()


async def _cve_count(session: AsyncSession) -> int:
    return (await session.execute(select(func.count()).select_from(CVE))).scalar_one()


# ---------------------------------------------------------------------------
# Lease and fence
# ---------------------------------------------------------------------------


async def admit_lease(client: redis_asyncio.Redis, target_version: str = TARGET) -> str:
    """Acquire the lease for a fresh canonical task ID, as the manual
    admission does; returns that task ID."""
    task_id = str(uuid.uuid4())
    outcome = await acquire_lease(
        client, task_id=task_id, target_version=target_version
    )
    assert outcome is LeaseAcquireOutcome.ACQUIRED
    return task_id


async def fence_holders(observer: AsyncConnection) -> list[int]:
    """The backend PIDs holding the execution fence."""
    result = await observer.execute(_FENCE_HOLDERS)
    return list(result.scalars())


async def non_advisory_locks(observer: AsyncConnection, pid: int) -> list[str]:
    """Every lock other than the fence held by backend `pid`."""
    result = await observer.execute(_NON_ADVISORY_LOCKS, {"pid": pid})
    return [f"{row.locktype}:{row.mode}" for row in result]


async def wait_until_fence_free(engine: AsyncEngine) -> None:
    """Bounded poll on a fresh connection: a closed or terminated backend
    releases its locks when it exits, which PostgreSQL completes
    asynchronously."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE
    async with engine.connect() as probe:
        while True:
            granted = bool((await probe.execute(_TRY_XACT_LOCK)).scalar_one())
            await probe.rollback()
            if granted:
                return
            assert loop.time() < deadline, "the execution fence was never released"
            await asyncio.sleep(_POLL_INTERVAL)


async def terminate_backend(observer: AsyncConnection, pid: int) -> None:
    """`pg_terminate_backend()` on `pid` only, then wait until the backend
    has exited."""
    terminated: bool = (
        await observer.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
    ).scalar_one()
    assert terminated is True
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE
    while (
        await observer.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"),
            {"pid": pid},
        )
    ).scalar_one():
        assert loop.time() < deadline, f"backend {pid} did not exit"
        await asyncio.sleep(_POLL_INTERVAL)


def connection_pid(connection: AsyncConnection) -> int:
    """The backend PID of a connection, read from the driver without a
    round trip (the `backend_pid()` precedent)."""
    sync_connection = connection.sync_connection
    assert sync_connection is not None
    driver = sync_connection.connection.driver_connection
    assert driver is not None
    pid: int = driver.get_server_pid()
    return pid


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

_Workflow = Callable[[str, str, async_sessionmaker[AsyncSession]], Awaitable[object]]


@dataclass
class RecalculationHarness:
    """One runner test's borrowed fenced connection, its recording factory,
    an autocommit observer connection, the committed world, the worker
    Redis client, the controlled clock, and the substituted publisher."""

    engine: AsyncEngine
    connection: AsyncConnection
    factory: RecordingSessionMaker
    observer: AsyncConnection
    world: RecalculationWorld
    redis: redis_asyncio.Redis
    clock: ManualClock
    published: PublishRecorder
    pid: int
    borrowed: list[AsyncConnection] = field(default_factory=list)

    async def admit(self, target_version: str = TARGET) -> str:
        return await admit_lease(self.redis, target_version)

    async def run(
        self,
        task_id: str,
        *,
        target_version: str = TARGET,
        factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> object:
        """Run the workflow under the bound task correlation; returns what
        the workflow returned."""
        workflow: _Workflow = cvss_recalculation.run_cvss_derived_state_recalculation
        with task_correlation(task_id):
            return await workflow(target_version, task_id, factory or self.factory)

    async def borrow(self) -> RecordingSessionMaker:
        """A further borrowed connection and factory (a second delivery)."""
        connection = await self.engine.connect()
        self.borrowed.append(connection)
        return RecordingSessionMaker(connection)

    async def fence_holders(self) -> list[int]:
        return await fence_holders(self.observer)

    async def lease(self) -> str | None:
        value: str | None = await self.redis.get(LEASE_KEY)
        return value


@asynccontextmanager
async def recalculation_harness(
    url: URL, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[RecalculationHarness]:
    """Build the harness on a dedicated `NullPool` engine for `url`.

    Installs the controlled clock, a fixed `_utc_today()` of `EVAL`, and the
    substituted publisher, and persists `default_cvss_version = TARGET`.
    Teardown proves the borrowed connection has no open transaction, closes
    every connection (ending its backend session), deletes the committed
    rows, and proves the execution fence is free."""
    engine = create_async_engine(url, poolclass=NullPool)
    connections: list[AsyncConnection] = []
    world: RecalculationWorld | None = None
    harness: RecalculationHarness | None = None
    open_transaction = False
    try:
        connection = await engine.connect()
        connections.append(connection)
        observer = await (await engine.connect()).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        connections.append(observer)
        world = await RecalculationWorld.create(engine)
        assert await world.cve_count() == 0, "the worker database holds CVEs"
        await world.ensure_setting(TARGET)
        clock = ManualClock()
        published = PublishRecorder()
        monkeypatch.setattr(cvss_recalculation, "_monotonic", clock)
        monkeypatch.setattr(cvss_recalculation, "_utc_today", lambda: EVAL)
        monkeypatch.setattr(task_publication, "publish_task", published)
        harness = RecalculationHarness(
            engine=engine,
            connection=connection,
            factory=RecordingSessionMaker(connection),
            observer=observer,
            world=world,
            redis=redis_client,
            clock=clock,
            published=published,
            pid=connection_pid(connection),
        )
        yield harness
        open_transaction = any(
            not borrowed.closed
            and not borrowed.invalidated
            and borrowed.in_transaction()
            for borrowed in (connection, *harness.borrowed)
        )
    finally:
        if harness is not None:
            connections.extend(harness.borrowed)
        for opened in connections:
            if opened.closed:
                continue
            if not opened.invalidated:
                await opened.invalidate()
            await opened.close()
        if world is not None:
            await world.cleanup()
        await wait_until_fence_free(engine)
        await engine.dispose()
    assert not open_transaction, "a borrowed connection kept an open transaction"
