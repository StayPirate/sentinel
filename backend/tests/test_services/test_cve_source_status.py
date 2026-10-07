"""Tests for `cve_service.get_cve_source_status()` (per-CVE source status).

Owning specifications: docs/features/tickets/cve-service.md (CVE Read and
Accessibility Boundary; Service Read Contracts; CVE Source Status, all
subsections; Transaction Ownership; Exceptions); docs/api-spec.md (CVE
Identifier Resolution; CVE Accessibility Check; Infrastructure Dependency
Errors); docs/features/identity/rbac.md (Scope and Confidential Ticket
Visibility); docs/features/platform/testing-strategy.md (CVE and Source
Reads > Per-CVE source status and KEV projection; Redis Strategy;
Application-Owned Redis Operations; Concurrency Testing).

The service owns its read session. Most tests hand it a session factory
bound to the `db_session` connection in `create_savepoint` mode, so the
service observes the rows the test flushed and the per-test rollback still
discards them. The independent-session races instead commit through
`db_session_factory` sessions, hand the service a factory bound to another
independent connection, and delete their committed rows explicitly.

Every test defines its own CVE fetchers under `isolated_fetcher_registries`
after clearing both registries, so the registry content is exact. Tests
whose overlay set is non-empty request `redis_client`, which redirects the
pending-marker URL to the worker's Redis database; Redis failures replace
the `_new_redis_client` boundary instead of stopping Redis.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final, cast
from unittest.mock import MagicMock

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from sqlalchemy.sql import Executable
from structlog.testing import capture_logs

from app.core.enums import (
    CVESourceDerivedStatus,
    CVESourceType,
    FetcherRunStatus,
    Scope,
)
from app.core.exceptions import CVENotFoundError
from app.models.cve import CVE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import cve_service
from app.services.base_cve_fetcher import BaseCVEFetcher
from app.services.cve_ingest import CVEIngestPayload, KEVEntry
from app.services.cve_service import (
    KEV_FETCHER_NAME,
    CVESourceStatusEntry,
    CVESourceStatusResult,
    fetch_pending_key,
    get_cve_source_status,
    upsert_cve,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.cve_source_status import (
    clear_fetcher_registries,
    define_cve_fetcher,
    define_kev_fetcher,
)

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
CREATED: Final = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
FETCHED: Final = datetime(2099, 3, 5, 8, 30, tzinfo=UTC)
FIRST_FAILED: Final = datetime(2099, 3, 2, 6, 15, tzinfo=UTC)
KEV_UPDATED: Final = datetime(2099, 3, 4, 10, 0, tzinfo=UTC)
ONE_US: Final = timedelta(microseconds=1)
RUN_DURATION: Final = timedelta(minutes=5)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")
OVERLAY_WARNING: Final = "cve_source_pending_overlay_unavailable"
_ROW: Final[dict[str, Any]] = {"status": "success", "fetched_at": FETCHED}

SUCCESS: Final = CVESourceDerivedStatus.SUCCESS
FAILURE: Final = CVESourceDerivedStatus.FAILURE
MISSING: Final = CVESourceDerivedStatus.MISSING
PENDING: Final = CVESourceDerivedStatus.PENDING
NOT_ATTEMPTED: Final = CVESourceDerivedStatus.NOT_ATTEMPTED


def _restricted(user: User | uuid.UUID) -> TicketCaller:
    user_id = user if isinstance(user, uuid.UUID) else user.id
    return TicketCaller.authenticated(user_id, Scope.NON_CONFIDENTIAL)


def _random_cve_id() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10**9:09d}"


# ---------------------------------------------------------------------------
# Test-only CVE fetchers
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Registry:
    """Defines test-only CVE fetchers into the (cleared) registries."""

    def define(
        self, source: CVESourceType, *, refetchable: bool = True
    ) -> type[BaseCVEFetcher]:
        return define_cve_fetcher(source, refetchable=refetchable)

    def kev(self) -> type[BaseCVEFetcher]:
        return define_kev_fetcher()


@pytest.fixture
def registry(isolated_fetcher_registries: None) -> _Registry:
    """Both registries cleared; the fixture restores them at teardown."""
    clear_fetcher_registries()
    return _Registry()


# ---------------------------------------------------------------------------
# Service session and Redis boundary observation
# ---------------------------------------------------------------------------


class _ObservedSession(AsyncSession):
    """Records `execute`, `flush`, `commit`, and `close` into the shared
    `info["journal"]`, and consumes one pending `info["hooks"]` callable
    after a statement returns."""

    def _journal(self) -> list[str]:
        journal: list[str] = self.info["journal"]
        return journal

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        result = await super().execute(*args, **kwargs)
        self._journal().append("execute")
        hooks: list[Callable[[], Awaitable[None]]] = self.info["hooks"]
        if hooks:
            await hooks.pop(0)()
        return result

    async def flush(self, *args: Any, **kwargs: Any) -> None:
        self._journal().append("flush")
        await super().flush(*args, **kwargs)

    async def commit(self) -> None:
        self._journal().append("commit")
        await super().commit()

    async def close(self) -> None:
        await super().close()
        self._journal().append("close")


@dataclasses.dataclass
class _Service:
    """Calls the service with an observed session factory; `journal` and
    `hooks` are shared by every session it opens."""

    factory: async_sessionmaker[AsyncSession]
    journal: list[str]
    hooks: list[Callable[[], Awaitable[None]]]

    @classmethod
    def on(cls, connection: AsyncConnection, **session_options: Any) -> _Service:
        journal: list[str] = []
        hooks: list[Callable[[], Awaitable[None]]] = []
        factory = async_sessionmaker(
            bind=connection,
            class_=_ObservedSession,
            expire_on_commit=False,
            info={"journal": journal, "hooks": hooks},
            **session_options,
        )
        return cls(factory, journal, hooks)

    async def status(
        self, cve_id: str, caller: TicketCaller = ANONYMOUS_CALLER
    ) -> CVESourceStatusResult:
        return await get_cve_source_status(cve_id, caller, session_factory=self.factory)


@pytest.fixture
def service(db_session: AsyncSession) -> _Service:
    """Service sessions joined to the `db_session` connection: they observe
    the test's flushed rows inside their own savepoint, which their close
    rolls back."""
    assert isinstance(db_session.bind, AsyncConnection)
    return _Service.on(db_session.bind, join_transaction_mode="create_savepoint")


class _RedisSpy:
    """A pending-overlay client: records its calls into `journal`, returns
    `values` (or delegates to `delegate`), or raises `error` from `mget`."""

    def __init__(
        self,
        journal: list[str],
        *,
        values: dict[str, str] | None = None,
        delegate: redis_asyncio.Redis | None = None,
        error: Exception | None = None,
    ) -> None:
        self.journal = journal
        self.values = values or {}
        self.delegate = delegate
        self.error = error
        self.mget_calls: list[list[str]] = []

    async def mget(self, keys: Sequence[str]) -> list[str | None]:
        self.journal.append("mget")
        self.mget_calls.append(list(keys))
        if self.error is not None:
            raise self.error
        if self.delegate is not None:
            values: list[str | None] = await self.delegate.mget(list(keys))
            return values
        return [self.values.get(key) for key in keys]

    async def aclose(self) -> None:
        self.journal.append("aclose")
        if self.delegate is not None:
            await self.delegate.aclose()


def _install_redis(monkeypatch: pytest.MonkeyPatch, spy: _RedisSpy) -> list[int]:
    """Replace the client factory; returns a one-element creation counter."""
    created = [0]

    def _factory() -> _RedisSpy:
        created[0] += 1
        return spy

    monkeypatch.setattr(cve_service, "_new_redis_client", _factory)
    return created


def _forbid_redis(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    spy = MagicMock(side_effect=AssertionError("no Redis client may be created"))
    monkeypatch.setattr(cve_service, "_new_redis_client", spy)
    return spy


async def _mark_pending(
    redis_client: redis_asyncio.Redis, cve_id: str, *sources: str
) -> None:
    for source in sources:
        await redis_client.set(fetch_pending_key(cve_id, source), "1")


class _StatementRecorder:
    """Records every statement the engine sends, except savepoint control."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self._statements: list[str] = []

    @property
    def statements(self) -> list[str]:
        return [
            s
            for s in self._statements
            if not s.lstrip().upper().startswith(("SAVEPOINT", "RELEASE", "ROLLBACK"))
        ]

    def _record(self, *args: Any) -> None:
        self._statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


def _entry(
    source: str,
    status: CVESourceDerivedStatus,
    fetched_at: datetime | None = None,
    first_failed_at: datetime | None = None,
    *,
    registered: bool = True,
    refetchable: bool = True,
    enabled: bool = True,
) -> CVESourceStatusEntry:
    return CVESourceStatusEntry(
        source=source,
        status=status,
        fetched_at=fetched_at,
        first_failed_at=first_failed_at,
        registered=registered,
        refetchable=refetchable,
        enabled=enabled,
    )


def _historical(
    source: str,
    status: CVESourceDerivedStatus,
    fetched_at: datetime,
    first_failed_at: datetime | None = None,
) -> CVESourceStatusEntry:
    return _entry(
        source,
        status,
        fetched_at,
        first_failed_at,
        registered=False,
        refetchable=False,
        enabled=False,
    )


# Persisted status -> (CVESource columns, expected durable entry timestamps).
_DURABLE_ROWS: Final[dict[str, dict[str, Any] | None]] = {
    "success": {"status": "success", "fetched_at": FETCHED},
    "failure": {
        "status": "failure",
        "fetched_at": FETCHED,
        "first_failed_at": FIRST_FAILED,
    },
    "missing": {"status": "missing", "fetched_at": FETCHED},
    "none": None,
}
_DURABLE_STATUS: Final = {
    "success": SUCCESS,
    "failure": FAILURE,
    "missing": MISSING,
    "none": NOT_ATTEMPTED,
}


def _durable_timestamps(case: str) -> tuple[datetime | None, datetime | None]:
    row = _DURABLE_ROWS[case]
    if row is None:
        return None, None
    return row["fetched_at"], row.get("first_failed_at")


# ---------------------------------------------------------------------------
# Identity resolution and accessibility
# ---------------------------------------------------------------------------

MALFORMED_CVE_IDS: Final = [
    pytest.param("cve-2099-10001", id="lowercase"),
    pytest.param("CVE-2099-" + "1" * 12, id="overlength-21"),
    pytest.param("", id="empty"),
    pytest.param(" CVE-2099-10001", id="leading-space"),
    pytest.param("CVE-2099-10001 ", id="trailing-space"),
    pytest.param("CVE-2099-100", id="three-digit-sequence"),
    pytest.param("018f0e2a-7b1c-7cde-8f00-000000000001", id="uuid"),
]


@pytest.mark.integration
class TestIdentityAndAccess:
    @pytest.mark.parametrize("cve_id", MALFORMED_CVE_IDS)
    async def test_malformed_identifier_raises_without_any_session_or_redis(
        self,
        registry: _Registry,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        cve_id: str,
    ) -> None:
        registry.define(CVESourceType.NVD)
        await cve_factory(cve_id="CVE-2099-10001")
        session_factory = MagicMock(side_effect=AssertionError("no session"))
        redis_factory = _forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError):
            await get_cve_source_status(
                cve_id, ALL_SCOPE, session_factory=session_factory
            )

        session_factory.assert_not_called()
        redis_factory.assert_not_called()

    async def test_twenty_character_identifier_is_resolved(
        self, service: _Service, registry: _Registry, cve_factory: Factory
    ) -> None:
        cve_id = "CVE-2099-" + "1" * 11
        await cve_factory(cve_id=cve_id)

        result = await service.status(cve_id)

        assert result == CVESourceStatusResult(entries=())

    async def test_missing_and_inaccessible_are_indistinguishable(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_factory: Factory,
        cve_source_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No source row and no Redis lookup ever follow a denial."""
        registry.define(CVESourceType.NVD)
        registry.kev()
        confidential: CVE = await cve_factory(cve_id=_random_cve_id())
        await ticket_factory(cve_id=confidential.id, is_confidential=True)
        await cve_source_factory(cve_id=confidential.id, source="nvd")
        user: User = await user_factory()
        redis_factory = _forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError) as missing:
            await service.status("CVE-2099-99999", ALL_SCOPE)
        for caller in (ANONYMOUS_CALLER, _restricted(user)):
            with pytest.raises(CVENotFoundError) as denied:
                await service.status(confidential.cve_id, caller)
            assert type(denied.value) is type(missing.value)
            assert str(denied.value) == str(missing.value)
            assert denied.value.args == missing.value.args

        redis_factory.assert_not_called()

    @pytest.mark.parametrize("caller", ["anonymous", "restricted", "scope-all"])
    async def test_ticketless_cve_is_always_visible(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        user_factory: Factory,
        caller: str,
    ) -> None:
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await cve_source_factory(cve_id=cve.id, source="legacy_source", **_ROW)
        callers = {
            "anonymous": ANONYMOUS_CALLER,
            "restricted": _restricted(await user_factory()),
            "scope-all": ALL_SCOPE,
        }

        result = await service.status(cve.cve_id, callers[caller])

        assert result.entries == (_historical("legacy_source", SUCCESS, FETCHED),)

    @pytest.mark.parametrize(
        "path", ["non-confidential-anonymous", "non-confidential", "scope-all", "grant"]
    )
    async def test_associated_cve_is_visible_through_a_qualifying_path(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_factory: Factory,
        cve_source_factory: Factory,
        path: str,
    ) -> None:
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        ticket: Ticket = await ticket_factory(
            cve_id=cve.id, is_confidential=path in ("scope-all", "grant")
        )
        await cve_source_factory(cve_id=cve.id, source="legacy_source", **_ROW)
        user: User = await user_factory()
        if path == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        caller = {
            "non-confidential-anonymous": ANONYMOUS_CALLER,
            "non-confidential": _restricted(user),
            "scope-all": TicketCaller.authenticated(user.id, Scope.ALL),
            "grant": _restricted(user),
        }[path]

        result = await service.status(cve.cve_id, caller)

        assert result.entries == (_historical("legacy_source", SUCCESS, FETCHED),)


# ---------------------------------------------------------------------------
# Independent-session races (committed state decides)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits rows through an independent session and deletes them at
    teardown in FK-safe order (testing-strategy.md, Concurrency Testing).
    `CVESource` and `CVEKEVEntry` rows go with their CVE (`ON DELETE
    CASCADE`)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []

    async def user(self) -> User:
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"fictional.cvestatus.{suffix}",
            email=f"cvestatus.{suffix}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        await self.session.commit()
        return user

    async def cve(self) -> CVE:
        cve = CVE(cve_id=_random_cve_id())
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        await self.session.commit()
        return cve

    async def ticket(self, cve: CVE | None, *, is_confidential: bool) -> Ticket:
        ticket = Ticket(is_confidential=is_confidential, cve_id=cve.id if cve else None)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return ticket

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        await self.session.rollback()
        for statement in (
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@dataclasses.dataclass(frozen=True)
class _Race:
    """The committed world, a writer session, and a service whose sessions
    run on their own independent connection."""

    world: _CommittedWorld
    writer: AsyncSession
    service: _Service


@pytest.fixture
async def race(
    registry: _Registry, db_session_factory: SessionFactory
) -> AsyncIterator[_Race]:
    world = _CommittedWorld(await db_session_factory())
    reader = await db_session_factory()
    assert isinstance(reader.bind, AsyncConnection)
    try:
        yield _Race(world, await db_session_factory(), _Service.on(reader.bind))
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _add_source(cve: CVE) -> Executable:
    return insert(CVESource).values(
        cve_id=cve.id, source="legacy_source", status="success", fetched_at=FETCHED
    )


@dataclasses.dataclass(frozen=True)
class _Loss:
    cve: CVE
    caller: TicketCaller
    change: Executable


LOSS_CASES: Final = ["confidentiality", "grant", "association"]


async def _prepare_loss(world: _CommittedWorld, case: str) -> _Loss:
    cve = await world.cve()
    if case == "confidentiality":
        user = await world.user()
        ticket = await world.ticket(cve, is_confidential=False)
        change: Executable = (
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True)
        )
        return _Loss(cve, _restricted(user), change)
    if case == "grant":
        user, granter = await world.user(), await world.user()
        ticket = await world.ticket(cve, is_confidential=True)
        await world.grant(ticket, user, granter)
        change = delete(TicketAccessGrant).where(
            TicketAccessGrant.ticket_id == ticket.id
        )
        return _Loss(cve, _restricted(user), change)
    assert case == "association"
    ticket = await world.ticket(None, is_confidential=True)
    change = update(Ticket).where(Ticket.id == ticket.id).values(cve_id=cve.id)
    return _Loss(cve, ANONYMOUS_CALLER, change)


@dataclasses.dataclass(frozen=True)
class _Gain:
    cve: CVE
    caller: TicketCaller
    change: Executable


GAIN_CASES: Final = ["declassification", "grant"]


async def _prepare_gain(world: _CommittedWorld, case: str) -> _Gain:
    user, granter = await world.user(), await world.user()
    cve = await world.cve()
    ticket = await world.ticket(cve, is_confidential=True)
    if case == "declassification":
        change: Executable = (
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=False)
        )
    else:
        assert case == "grant"
        change = insert(TicketAccessGrant).values(
            ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
        )
    return _Gain(cve, _restricted(user), change)


@pytest.mark.integration
class TestIndependentSessionRaces:
    """A writer session commits an access change before the call: the one
    protected selection reflects the committed state. A change committed
    right after that selection is not observed by the in-flight call, which
    returns its coherent pre-change view; the next call observes it."""

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_before_the_selection(
        self, race: _Race, case: str
    ) -> None:
        loss = await _prepare_loss(race.world, case)
        await _commit(race.writer, _add_source(loss.cve))
        before = await race.service.status(loss.cve.cve_id, loss.caller)
        assert before.entries == (_historical("legacy_source", SUCCESS, FETCHED),)

        await _commit(race.writer, loss.change)

        with pytest.raises(CVENotFoundError):
            await race.service.status(loss.cve.cve_id, loss.caller)

    @pytest.mark.parametrize("case", GAIN_CASES)
    async def test_access_acquired_before_the_selection_is_observed_whole(
        self, race: _Race, case: str
    ) -> None:
        gain = await _prepare_gain(race.world, case)
        with pytest.raises(CVENotFoundError):
            await race.service.status(gain.cve.cve_id, gain.caller)

        await _commit(race.writer, gain.change, _add_source(gain.cve))

        after = await race.service.status(gain.cve.cve_id, gain.caller)
        assert after.entries == (_historical("legacy_source", SUCCESS, FETCHED),)

    @pytest.mark.parametrize("case", LOSS_CASES)
    async def test_access_lost_after_the_selection_is_not_mixed_in(
        self, race: _Race, case: str
    ) -> None:
        loss = await _prepare_loss(race.world, case)

        async def change() -> None:
            await _commit(race.writer, loss.change, _add_source(loss.cve))

        race.service.hooks.append(change)
        result = await race.service.status(loss.cve.cve_id, loss.caller)

        assert race.service.journal == ["execute", "close"]
        assert result == CVESourceStatusResult(entries=())
        with pytest.raises(CVENotFoundError):
            await race.service.status(loss.cve.cve_id, loss.caller)


# ---------------------------------------------------------------------------
# Roster: registered, historical, enabled, refetchable, ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRoster:
    async def test_registered_sources_without_rows_are_not_attempted(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        registry.define(CVESourceType.NVD)
        registry.define(CVESourceType.OSV, refetchable=False)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry("nvd", NOT_ATTEMPTED),
            _entry("osv", NOT_ATTEMPTED, refetchable=False),
        )

    async def test_historical_sources_keep_their_persisted_status_and_no_overlay(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """A retired identity and an unregistered `CVESourceType` value are
        both historical; their pending markers are never consulted."""
        registry.define(CVESourceType.NVD)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await cve_source_factory(
            cve_id=cve.id,
            source="legacy_source",
            status="failure",
            fetched_at=FETCHED,
            first_failed_at=FIRST_FAILED,
        )
        await cve_source_factory(
            cve_id=cve.id, source="ghsa", status="missing", fetched_at=FETCHED
        )
        await _mark_pending(redis_client, cve.cve_id, "legacy_source", "ghsa")

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _historical("ghsa", MISSING, FETCHED),
            _historical("legacy_source", FAILURE, FETCHED, FIRST_FAILED),
            _entry("nvd", NOT_ATTEMPTED),
        )

    async def test_unregistered_kev_row_is_historical(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
    ) -> None:
        """The KEV data-table derivation applies to the registered `kev`
        entry only; without it, a persisted `kev` row is historical."""
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await cve_source_factory(cve_id=cve.id, source="kev", **_ROW)

        result = await service.status(cve.cve_id)

        assert result.entries == (_historical("kev", SUCCESS, FETCHED),)

    async def test_enabled_is_independent_of_refetchable(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        fetcher_config_factory: Factory,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """Disabled refetchable, enabled non-refetchable, and a registered
        source whose `FetcherConfig` row is absent (bootstrap fallback
        `enabled = true`). Configuration of unrelated fetchers is ignored."""
        nvd = registry.define(CVESourceType.NVD)
        osv = registry.define(CVESourceType.OSV, refetchable=False)
        registry.define(CVESourceType.MITRE)
        await fetcher_config_factory(fetcher_name=nvd.name, enabled=False)
        await fetcher_config_factory(fetcher_name=osv.name, enabled=True)
        await fetcher_config_factory(fetcher_name="unrelated_fetcher", enabled=False)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry("mitre", NOT_ATTEMPTED),
            _entry("nvd", NOT_ATTEMPTED, enabled=False),
            _entry("osv", NOT_ATTEMPTED, refetchable=False),
        )

    async def test_code_point_order_with_one_entry_per_identity(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """Rows are inserted in neither order. Code-point order puts `nvd` <
        `nvd2` < `nvd_2` ('2' < '_'); the registered `nvd` with a row
        appears once."""
        registry.define(CVESourceType.OSV, refetchable=False)
        registry.define(CVESourceType.NVD)
        registry.kev()
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        for source in ("zz_retired", "nvd_2", "nvd", "a_retired", "nvd2"):
            await cve_source_factory(cve_id=cve.id, source=source, **_ROW)

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _historical("a_retired", SUCCESS, FETCHED),
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
            _entry("nvd", SUCCESS, FETCHED),
            _historical("nvd2", SUCCESS, FETCHED),
            _historical("nvd_2", SUCCESS, FETCHED),
            _entry("osv", NOT_ATTEMPTED, refetchable=False),
            _historical("zz_retired", SUCCESS, FETCHED),
        )


# ---------------------------------------------------------------------------
# Durable status and the pending overlay
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDurableStatusAndPendingOverlay:
    @pytest.mark.parametrize("marker", [False, True], ids=["durable", "pending"])
    @pytest.mark.parametrize("persisted", list(_DURABLE_ROWS))
    async def test_enabled_registered_source(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        redis_client: redis_asyncio.Redis,
        persisted: str,
        marker: bool,
    ) -> None:
        """A marker yields `pending` over every durable status and keeps the
        last completed timestamps (null without a row)."""
        registry.define(CVESourceType.NVD)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        row = _DURABLE_ROWS[persisted]
        if row is not None:
            await cve_source_factory(cve_id=cve.id, source="nvd", **row)
        if marker:
            await _mark_pending(redis_client, cve.cve_id, "nvd")

        result = await service.status(cve.cve_id)

        expected = PENDING if marker else _DURABLE_STATUS[persisted]
        assert result.entries == (
            _entry("nvd", expected, *_durable_timestamps(persisted)),
        )

    @pytest.mark.parametrize("persisted", list(_DURABLE_ROWS))
    async def test_disabled_registered_source_suppresses_the_overlay(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        persisted: str,
    ) -> None:
        nvd = registry.define(CVESourceType.NVD)
        await fetcher_config_factory(fetcher_name=nvd.name, enabled=False)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        row = _DURABLE_ROWS[persisted]
        if row is not None:
            await cve_source_factory(cve_id=cve.id, source="nvd", **row)
        await _mark_pending(redis_client, cve.cve_id, "nvd")
        redis_factory = _forbid_redis(monkeypatch)

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry(
                "nvd",
                _DURABLE_STATUS[persisted],
                *_durable_timestamps(persisted),
                enabled=False,
            ),
        )
        redis_factory.assert_not_called()

    async def test_kev_marker_is_never_looked_up_or_overlaid(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        registry.kev()
        registry.define(CVESourceType.NVD)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await _mark_pending(redis_client, cve.cve_id, "kev", "nvd")
        spy = _RedisSpy([], delegate=cve_service._new_redis_client())
        _install_redis(monkeypatch, spy)

        result = await service.status(cve.cve_id)

        assert spy.mget_calls == [[fetch_pending_key(cve.cve_id, "nvd")]]
        assert result.entries == (
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
            _entry("nvd", PENDING),
        )

    async def test_aggregate_overlay_reads_every_eligible_marker_in_one_mget(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only the registered enabled non-KEV sources are looked up, in one
        `MGET`; a marker of another CVE does not apply; the client is
        closed."""
        registry.kev()
        registry.define(CVESourceType.NVD)
        registry.define(CVESourceType.MITRE)
        registry.define(CVESourceType.OSV, refetchable=False)
        redhat = registry.define(CVESourceType.REDHAT)
        await fetcher_config_factory(fetcher_name=redhat.name, enabled=False)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        other: CVE = await cve_factory(cve_id=_random_cve_id())
        await cve_source_factory(cve_id=cve.id, source="mitre", **_ROW)
        await cve_source_factory(cve_id=cve.id, source="legacy_source", **_ROW)
        await _mark_pending(redis_client, cve.cve_id, "mitre", "osv", "redhat")
        await _mark_pending(redis_client, other.cve_id, "nvd")
        journal: list[str] = []
        spy = _RedisSpy(journal, delegate=cve_service._new_redis_client())
        created = _install_redis(monkeypatch, spy)

        result = await service.status(cve.cve_id)

        assert created == [1]
        assert journal == ["mget", "aclose"]
        assert spy.mget_calls == [
            [fetch_pending_key(cve.cve_id, s) for s in ("mitre", "nvd", "osv")]
        ]
        assert result.entries == (
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
            _historical("legacy_source", SUCCESS, FETCHED),
            _entry("mitre", PENDING, FETCHED),
            _entry("nvd", NOT_ATTEMPTED),
            _entry("osv", PENDING, refetchable=False),
            _entry("redhat", NOT_ATTEMPTED, enabled=False),
        )


# ---------------------------------------------------------------------------
# Redis graceful degradation and Redis I/O placement
# ---------------------------------------------------------------------------


class _FictionalResponseError(ResponseError):
    """A `ResponseError` subclass, as raised for a server-side error."""


REDIS_ERRORS: Final = [
    pytest.param(RedisError("fictional failure"), id="RedisError"),
    pytest.param(RedisConnectionError("fictional refusal"), id="ConnectionError"),
    pytest.param(RedisTimeoutError("fictional timeout"), id="TimeoutError"),
    pytest.param(ResponseError("fictional reply"), id="ResponseError"),
    pytest.param(
        _FictionalResponseError("fictional reply"), id="ResponseError-subclass"
    ),
]


@pytest.mark.integration
class TestRedisDegradation:
    @pytest.mark.parametrize("error", REDIS_ERRORS)
    async def test_redis_error_returns_the_complete_durable_view(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_run_factory: Factory,
        fetcher_config_factory: Factory,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        error: RedisError,
    ) -> None:
        """Every source falls back to its durable status, including those
        whose marker exists; no exception escapes; one warning without the
        error text; the client is still closed."""
        registry.kev()
        registry.define(CVESourceType.NVD)
        registry.define(CVESourceType.MITRE)
        registry.define(CVESourceType.OSV, refetchable=False)
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=CREATED + timedelta(days=1) - RUN_DURATION,
            finished_at=CREATED + timedelta(days=1),
        )
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        await cve_source_factory(cve_id=cve.id, source="nvd", **_ROW)
        await cve_source_factory(
            cve_id=cve.id,
            source="mitre",
            status="failure",
            fetched_at=FETCHED,
            first_failed_at=FIRST_FAILED,
        )
        await cve_source_factory(cve_id=cve.id, source="legacy_source", **_ROW)
        await _mark_pending(redis_client, cve.cve_id, "nvd", "mitre", "osv")
        journal: list[str] = []
        _install_redis(monkeypatch, _RedisSpy(journal, error=error))

        with capture_logs() as logs:
            result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry("kev", MISSING, CREATED + timedelta(days=1), refetchable=False),
            _historical("legacy_source", SUCCESS, FETCHED),
            _entry("mitre", FAILURE, FETCHED, FIRST_FAILED),
            _entry("nvd", SUCCESS, FETCHED),
            _entry("osv", NOT_ATTEMPTED, refetchable=False),
        )
        assert all(entry.status is not PENDING for entry in result.entries)
        assert journal == ["mget", "aclose"]
        warnings = [log for log in logs if log["event"] == OVERLAY_WARNING]
        assert warnings == [
            {
                "event": OVERLAY_WARNING,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "error_type": type(error).__name__,
            }
        ]
        assert str(error) not in repr(logs)

    async def test_failure_after_a_successful_overlay_is_never_mixed(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The same markers yield the full overlay while Redis answers and
        the full durable view when it fails: no entry keeps a pending
        observation from a lookup that failed."""
        registry.define(CVESourceType.NVD)
        registry.define(CVESourceType.MITRE)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await _mark_pending(redis_client, cve.cve_id, "nvd", "mitre")
        overlaid = await service.status(cve.cve_id)
        _install_redis(monkeypatch, _RedisSpy([], error=RedisConnectionError()))

        durable = await service.status(cve.cve_id)

        assert overlaid.entries == (_entry("mitre", PENDING), _entry("nvd", PENDING))
        assert durable.entries == (
            _entry("mitre", NOT_ATTEMPTED),
            _entry("nvd", NOT_ATTEMPTED),
        )

    @pytest.mark.parametrize("scenario", ["empty-registry", "kev-only", "all-disabled"])
    async def test_no_redis_client_without_an_eligible_source(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
    ) -> None:
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        await cve_source_factory(cve_id=cve.id, source="legacy_source", **_ROW)
        expected = [_historical("legacy_source", SUCCESS, FETCHED)]
        if scenario == "kev-only":
            registry.kev()
            expected.insert(0, _entry("kev", NOT_ATTEMPTED, refetchable=False))
        if scenario == "all-disabled":
            for source in (CVESourceType.NVD, CVESourceType.OSV):
                fetcher = registry.define(source)
                await fetcher_config_factory(fetcher_name=fetcher.name, enabled=False)
            expected += [
                _entry(s, NOT_ATTEMPTED, enabled=False) for s in ("nvd", "osv")
            ]
        redis_factory = _forbid_redis(monkeypatch)

        result = await service.status(cve.cve_id)

        assert result.entries == tuple(expected)
        redis_factory.assert_not_called()

    async def test_durable_session_is_closed_before_any_redis_io(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One statement, no flush or commit, the session closed (its
        transaction ended), and only then the Redis client created and
        queried."""
        registry.define(CVESourceType.NVD)
        cve: CVE = await cve_factory(cve_id=_random_cve_id())
        spy = _RedisSpy(service.journal)
        sessions: list[AsyncSession] = []
        original = service.factory

        def _factory() -> AsyncSession:
            session = original()
            sessions.append(session)
            return session

        def _client() -> _RedisSpy:
            assert sessions, "the durable session must precede Redis"
            assert not sessions[0].in_transaction()
            service.journal.append("client")
            return spy

        monkeypatch.setattr(cve_service, "_new_redis_client", _client)

        result = await get_cve_source_status(
            cve.cve_id,
            ANONYMOUS_CALLER,
            session_factory=cast(async_sessionmaker[AsyncSession], _factory),
        )

        assert service.journal == ["execute", "close", "client", "mget", "aclose"]
        assert len(sessions) == 1
        assert result.entries == (_entry("nvd", NOT_ATTEMPTED),)


# ---------------------------------------------------------------------------
# One coherent, read-only observation
# ---------------------------------------------------------------------------


async def _persisted_state(db: AsyncSession) -> tuple[Any, ...]:
    """Row counts and latest modification instants of the touched tables."""
    counts = [
        select(func.count()).select_from(model).scalar_subquery()
        for model in (
            CVE,
            CVESource,
            CVEKEVEntry,
            FetcherConfig,
            FetcherRun,
            Ticket,
            TicketAuditEvent,
            FetcherAuditEvent,
        )
    ]
    stamps = [
        select(func.max(model.updated_at)).scalar_subquery()
        for model in (CVE, CVESource, CVEKEVEntry, FetcherConfig, Ticket)
    ]
    return tuple((await db.execute(select(*counts, *stamps))).one())


@pytest.mark.integration
class TestCoherentReadOnlyObservation:
    async def test_one_read_only_statement_without_any_write(
        self,
        db_session: AsyncSession,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_source_factory: Factory,
        cve_kev_entry_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CVE, Ticket accessibility, every `CVESource` row, the
        `FetcherConfig` rows, `CVEKEVEntry`, and the KEV run all come from
        one `SELECT` without a row lock; nothing is flushed, committed, or
        written."""
        registry.kev()
        nvd = registry.define(CVESourceType.NVD)
        await fetcher_config_factory(fetcher_name=nvd.name, enabled=False)
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME, enabled=False)
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=FETCHED - RUN_DURATION,
            finished_at=FETCHED,
        )
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        await cve_kev_entry_factory(cve_id=cve.id, updated_at=KEV_UPDATED)
        for source in ("nvd", "legacy_source", "kev"):
            await cve_source_factory(cve_id=cve.id, source=source, **_ROW)
        before = await _persisted_state(db_session)
        _forbid_redis(monkeypatch)

        with _StatementRecorder(db_session) as recorder:
            result = await service.status(cve.cve_id, ALL_SCOPE)

        assert result.entries == (
            _entry("kev", SUCCESS, KEV_UPDATED, refetchable=False, enabled=False),
            _historical("legacy_source", SUCCESS, FETCHED),
            _entry("nvd", SUCCESS, FETCHED, enabled=False),
        )
        assert len(recorder.statements) == 1
        statement = recorder.statements[0].upper()
        assert statement.lstrip().startswith(("SELECT", "WITH"))
        for row_lock in ROW_LOCKS:
            assert row_lock not in statement
        assert service.journal == ["execute", "close"]
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()
        assert await _persisted_state(db_session) == before


# ---------------------------------------------------------------------------
# KEV projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestKEVProjection:
    @pytest.mark.parametrize("vestigial", [None, "success", "failure", "missing"])
    async def test_entry_yields_success_with_its_updated_at(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_source_factory: Factory,
        vestigial: str | None,
    ) -> None:
        """Whatever vestigial `CVESource("kev")` row exists is not
        consulted."""
        registry.kev()
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        await cve_kev_entry_factory(cve_id=cve.id, updated_at=KEV_UPDATED)
        if vestigial is not None:
            await cve_source_factory(
                cve_id=cve.id,
                source="kev",
                status=vestigial,
                fetched_at=FETCHED,
                first_failed_at=FIRST_FAILED if vestigial == "failure" else None,
            )

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry("kev", SUCCESS, KEV_UPDATED, refetchable=False),
        )

    @pytest.mark.parametrize("writer", [CVESourceType.KEV, CVESourceType.MITRE])
    async def test_entry_from_any_writer_yields_success(
        self,
        db_session: AsyncSession,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        ticket_factory: Factory,
        writer: CVESourceType,
    ) -> None:
        """Evidence persisted by `upsert_cve()` for the dedicated KEV source
        and for MITRE (the CISA-ADP container path) is reported alike under
        the registered `kev` entry."""
        registry.kev()
        registry.define(CVESourceType.MITRE, refetchable=False)
        cve_id = _random_cve_id()
        cve: CVE = await cve_factory(cve_id=cve_id)
        await ticket_factory(cve_id=cve.id)
        await upsert_cve(
            db_session,
            cve_id,
            writer,
            CVEIngestPayload(kev_data=KEVEntry(date_added=date(2099, 1, 15))),
        )
        kev_updated_at = (
            await db_session.execute(
                select(CVEKEVEntry.updated_at).where(CVEKEVEntry.cve_id == cve.id)
            )
        ).scalar_one()

        result = await service.status(cve_id)

        kev, mitre = result.entries
        assert kev == _entry("kev", SUCCESS, kev_updated_at, refetchable=False)
        assert (mitre.source, mitre.status) == (
            "mitre",
            SUCCESS if writer is CVESourceType.MITRE else NOT_ATTEMPTED,
        )

    async def test_no_entry_and_no_successful_run_is_not_attempted(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
    ) -> None:
        """Including a vestigial `CVESource("kev", "success")` row and a
        successful run of another fetcher after the CVE."""
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        await fetcher_run_factory(status="success", finished_at=FETCHED)
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        await cve_source_factory(cve_id=cve.id, source="kev", **_ROW)

        result = await service.status(cve.cve_id)

        assert result.entries == (_entry("kev", NOT_ATTEMPTED, refetchable=False),)

    @pytest.mark.parametrize(
        ("started", "finished", "expected"),
        [
            pytest.param(
                -2 * RUN_DURATION,
                -RUN_DURATION,
                NOT_ATTEMPTED,
                id="run-before-creation",
            ),
            pytest.param(
                -RUN_DURATION, RUN_DURATION, NOT_ATTEMPTED, id="created-mid-run"
            ),
            pytest.param(
                -ONE_US, RUN_DURATION, NOT_ATTEMPTED, id="started-just-before-creation"
            ),
            pytest.param(timedelta(0), RUN_DURATION, MISSING, id="started-at-creation"),
            pytest.param(ONE_US, RUN_DURATION, MISSING, id="started-after-creation"),
        ],
    )
    async def test_successful_run_start_boundary_against_cve_creation(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
        started: timedelta,
        finished: timedelta,
        expected: CVESourceDerivedStatus,
    ) -> None:
        """Only a run that started at or after the CVE's creation proves
        absence; a CVE created while the run was in progress is not
        `missing` even though the run finished after it."""
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        finished_at = CREATED + finished
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=CREATED + started,
            finished_at=finished_at,
        )
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)

        result = await service.status(cve.cve_id)

        fetched_at = finished_at if expected is MISSING else None
        assert result.entries == (
            _entry("kev", expected, fetched_at, refetchable=False),
        )

    @pytest.mark.parametrize(
        "status",
        [
            FetcherRunStatus.PARTIAL,
            FetcherRunStatus.FAILURE,
            FetcherRunStatus.QUEUED,
            FetcherRunStatus.RUNNING,
        ],
    )
    async def test_non_success_runs_never_prove_absence(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
        status: FetcherRunStatus,
    ) -> None:
        """A later non-success run neither proves absence on its own nor
        supersedes an earlier qualifying-or-not successful run."""
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status=status.value,
            started_at=CREATED + timedelta(days=1),
            finished_at=CREATED + timedelta(days=2),
        )
        alone: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)

        assert (await service.status(alone.cve_id)).entries == (
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
        )

        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=CREATED - timedelta(days=1) - RUN_DURATION,
            finished_at=CREATED - timedelta(days=1),
        )
        assert (await service.status(alone.cve_id)).entries == (
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
        )

    async def test_latest_successful_run_is_selected_by_finished_at_then_id(
        self,
        db_session: AsyncSession,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
    ) -> None:
        """The latest `finished_at` wins over a larger id and over insertion
        order; between two successful runs sharing the latest `finished_at`,
        `id DESC` selects the larger id, observable through the selected
        run's `started_at`."""
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        latest = CREATED + timedelta(days=3)
        smaller_id, larger_id = sorted((uuid.uuid4(), uuid.uuid4()))
        await fetcher_run_factory(
            id=larger_id,
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=CREATED - timedelta(days=1) - RUN_DURATION,
            finished_at=CREATED - timedelta(days=1),
        )
        await fetcher_run_factory(
            id=smaller_id,
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=latest - RUN_DURATION,
            finished_at=latest,
        )
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)

        assert (await service.status(cve.cve_id)).entries == (
            _entry("kev", MISSING, latest, refetchable=False),
        )

        # Inserted smaller id first: only the larger id's run, which started
        # before the CVE existed, yields `not_attempted`.
        tied_smaller_id, tied_larger_id = sorted((uuid.uuid4(), uuid.uuid4()))
        for run_id, started_at in (
            (tied_smaller_id, CREATED),
            (tied_larger_id, CREATED - ONE_US),
        ):
            await fetcher_run_factory(
                id=run_id,
                fetcher_name=KEV_FETCHER_NAME,
                status="success",
                started_at=started_at,
                finished_at=latest + timedelta(hours=1),
            )
        tied = (
            await db_session.execute(
                select(func.count()).where(
                    FetcherRun.fetcher_name == KEV_FETCHER_NAME,
                    FetcherRun.finished_at == latest + timedelta(hours=1),
                )
            )
        ).scalar_one()
        assert tied == 2

        assert (await service.status(cve.cve_id)).entries == (
            _entry("kev", NOT_ATTEMPTED, refetchable=False),
        )

    @pytest.mark.parametrize("evidence", ["entry", "run"])
    async def test_disabled_kev_still_derives_its_status(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
        evidence: str,
    ) -> None:
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME, enabled=False)
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=FETCHED - RUN_DURATION,
            finished_at=FETCHED,
        )
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        if evidence == "entry":
            await cve_kev_entry_factory(cve_id=cve.id, updated_at=KEV_UPDATED)

        result = await service.status(cve.cve_id)

        expected = (
            _entry("kev", SUCCESS, KEV_UPDATED, refetchable=False, enabled=False)
            if evidence == "entry"
            else _entry("kev", MISSING, FETCHED, refetchable=False, enabled=False)
        )
        assert result.entries == (expected,)

    async def test_retained_entry_after_catalog_removal_stays_success(
        self,
        service: _Service,
        registry: _Registry,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
    ) -> None:
        """A later fully successful catalog run without the CVE does not
        turn a retained entry into `missing`."""
        registry.kev()
        await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
        cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
        await cve_kev_entry_factory(cve_id=cve.id, updated_at=KEV_UPDATED)
        await fetcher_run_factory(
            fetcher_name=KEV_FETCHER_NAME,
            status="success",
            started_at=KEV_UPDATED + timedelta(days=30) - RUN_DURATION,
            finished_at=KEV_UPDATED + timedelta(days=30),
        )

        result = await service.status(cve.cve_id)

        assert result.entries == (
            _entry("kev", SUCCESS, KEV_UPDATED, refetchable=False),
        )
