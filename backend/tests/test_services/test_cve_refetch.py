"""Tests for the manual refetch orchestration `cve_service.refetch_cve()`
(backend/app/services/cve_service.py): the consumer mode of the
transactional preparation followed by database-free publication.

Owning specifications:

- docs/features/tickets/cve-service.md (Fetch Orchestration:
  `trigger_on_demand_fetch()` — Transactional Preparation, Database-Free
  Publication, `FetchDispatchResult`, Callers and Ordering; Exceptions;
  Transaction Ownership);
- docs/features/tickets/cve-tracking.md (Re-fetch Endpoint: source
  semantics, the four result lists, dispatch-only opt-out from
  `TICKET_NOT_MUTABLE`, access check behavior);
- docs/features/identity/rbac.md (Scope and Confidential Ticket Visibility);
- docs/features/tickets/ticket-audit-log.md (CVE refetch preparation and
  publication create no audit event);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Ticket
  Accessibility > Canonical predicate and Locked mutations; Concurrency
  Testing; Redis Strategy);
- issue #800 decision D4 (the `cve_fetch_publication_unconfirmed` WARNING
  carries only `cve_id`, `sources_failed`, and `trigger`).

Most tests hand the service a session factory joined to the `db_session`
connection in `create_savepoint` mode, so the service sees the rows the test
flushed and the per-test rollback discards them. Lock order, lock release,
commit failure, and the locked-current accessibility races instead commit
their rows through `db_session_factory` sessions, hand the service a
pre-opened independent session (its backend PID is known), and delete the
committed rows explicitly at teardown.

Every test empties both fetcher registries under
`isolated_fetcher_registries` and defines its own test-only CVE fetchers, so
the fetch-single roster is exact. The broker is never reached:
`task_publication.publish_task` is a recorder (or, for queue routing, the
real `publish_task` runs over a substituted `celery_app.send_task`). Redis is
either `ScriptedRedis` behind `_new_redis_client` or, where marker state
matters, the worker Redis database through `redis_client`. Expected values
are transcribed from the specifications, never computed with the module
under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import MagicMock, call

import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.exc import OperationalError as DatabaseOperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.celery_app import celery_app
from app.core.enums import CVESourceType, Role, Scope, TicketStatus
from app.core.exceptions import CVENotFoundError
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.services import task_publication
from app.services.cve_service import (
    CVEFetchFailedError,
    CVEInvalidSourceError,
    CVESourceDisabledError,
    FetchDispatchResult,
    refetch_cve,
)
from app.services.fetcher_execution import FetcherConfigMissingError
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_catch_up import Publications, define_cve_fetcher
from tests.support.cve_ingest import is_root_lock, lock_not_available, root_lock_order
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.database import assert_lock_wait
from tests.support.fetch_single_cve import (
    TASK,
    NoDatabaseAccess,
    ScriptedRedis,
    assert_private_logs,
    events_named,
    fictional_cve_id,
    forbid_redis,
    pending_key,
)
from tests.support.suse_cvss_races import (
    VISIBILITY_LOSSES,
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

UNCONFIRMED = "cve_fetch_publication_unconfirmed"
"""The WARNING of a non-empty `sources_failed` (issue #800, D4)."""

POST_COMMIT_CALLBACKS = "post_commit_callbacks"
"""The `AsyncSession.info` key of registered post-commit callbacks."""

SECRET = "amqp://refetch-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker detail carried by injected errors."""

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
KERNEL = CVESourceType.KERNEL
REDHAT = CVESourceType.REDHAT
GHSA = CVESourceType.GHSA
OSV = CVESourceType.OSV
KEV = CVESourceType.KEV
EPSS = CVESourceType.EPSS

SCOPE_ALL = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _exact_registry(isolated_fetcher_registries: None) -> None:
    """Both registries empty; `isolated_fetcher_registries` restores them."""
    clear_fetcher_registries()


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> Publications:
    recorder = Publications()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture
def scripted_redis(monkeypatch: pytest.MonkeyPatch) -> ScriptedRedis:
    client = ScriptedRedis()
    client.install(monkeypatch)
    return client


@pytest.fixture
def service_sessions(db_session: AsyncSession) -> async_sessionmaker[AsyncSession]:
    """Service sessions joined to the `db_session` connection: they observe
    the test's flushed rows inside their own savepoint."""
    assert isinstance(db_session.bind, AsyncConnection)
    return async_sessionmaker(
        bind=db_session.bind,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def _restricted(user: User | uuid.UUID) -> TicketCaller:
    user_id = user if isinstance(user, uuid.UUID) else user.id
    return TicketCaller.authenticated(user_id, Scope.NON_CONFIDENTIAL)


def _failing_for(sources: set[str], error: Exception) -> Any:
    """A `Publications.before` hook raising `error` for `sources`."""

    async def before(call_options: dict[str, Any]) -> None:
        if call_options["kwargs"]["source"] in sources:
            raise error

    return before


def _published_sources(published: Publications) -> list[str]:
    return [kwargs["source"] for kwargs in published.published(TASK)]


async def _fetcher(
    db: AsyncSession,
    source: CVESourceType,
    *,
    enabled: bool | None = True,
    refetchable: bool = True,
    queue: str | None = None,
) -> str:
    """Register a test-only CVE fetcher owning `source` and flush its
    `FetcherConfig`; `enabled=None` creates no configuration row."""
    probe = define_cve_fetcher(source=source, supports=refetchable, fetcher_queue=queue)
    if enabled is not None:
        db.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
        await db.flush()
    return probe.name


async def _cve(db: AsyncSession) -> CVE:
    cve = CVE(cve_id=fictional_cve_id())
    db.add(cve)
    await db.flush()
    return cve


async def _ticket(
    db: AsyncSession,
    cve: CVE | None,
    *,
    confidential: bool = False,
    status: TicketStatus = TicketStatus.ANALYSIS,
    duplicate_of: Ticket | None = None,
) -> Ticket:
    ticket = Ticket(
        status=status.value,
        cve_id=cve.id if cve is not None else None,
        is_confidential=confidential,
        duplicate_of_id=duplicate_of.id if duplicate_of is not None else None,
    )
    db.add(ticket)
    await db.flush()
    return ticket


async def _refetch(
    factory: async_sessionmaker[AsyncSession],
    cve_id: str,
    *,
    source: str | None = None,
    caller: TicketCaller = SCOPE_ALL,
) -> FetchDispatchResult:
    return await refetch_cve(
        cve_id=cve_id, source=source, caller=caller, session_factory=factory
    )


# ---------------------------------------------------------------------------
# Malformed path identity: no I/O at all
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMalformedIdentity:
    @pytest.mark.parametrize(
        "cve_id",
        [
            pytest.param("cve-2099-0001", id="lowercase"),
            pytest.param("CVE-2099-" + "1" * 12, id="overlength-21"),
            pytest.param("", id="empty"),
            pytest.param("0190a3c2-7d1e-7a4b-9c3d-2e5f6a7b8c9d", id="uuid"),
        ],
    )
    async def test_malformed_cve_id_is_not_found_without_any_io(
        self,
        cve_id: str,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A malformed path `{cve_id}` is indistinguishable from a missing
        CVE (cve-service.md, Exceptions; Caller Validation Responsibility)
        and is rejected before any database, Redis, or Celery I/O
        (Transactional Preparation, step 1)."""
        attempts = forbid_redis(monkeypatch)
        factory = MagicMock(side_effect=AssertionError("no session may be opened"))

        with NoDatabaseAccess() as observed, pytest.raises(CVENotFoundError):
            await _refetch(cast(async_sessionmaker[AsyncSession], factory), cve_id)

        assert observed.statements == []
        assert observed.checkouts == 0
        assert factory.call_count == 0
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# Missing and inaccessible CVEs (rbac.md canonical predicate)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    async def test_missing_cve_is_not_found_without_dispatch(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """cve-service.md, Transactional Preparation step 3: a missing CVE
        raises `CVENotFoundError`, with zero Redis and Celery I/O."""
        await _fetcher(db_session, NVD)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError):
            await _refetch(service_sessions, fictional_cve_id())

        assert attempts() == 0
        assert published.calls == []

    async def test_inaccessible_cve_is_not_found_without_dispatch(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CVE whose associated Ticket is confidential is inaccessible to
        an authenticated `non_confidential` caller with no grant and no
        maintainership (rbac.md, Scope and Confidential Ticket Visibility)."""
        await _fetcher(db_session, NVD)
        cve = await _cve(db_session)
        await _ticket(db_session, cve, confidential=True)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError):
            await _refetch(
                service_sessions, cve.cve_id, caller=_restricted(uuid.uuid4())
            )

        assert attempts() == 0
        assert published.calls == []

    @pytest.mark.parametrize(
        "path",
        ["ticketless", "non-confidential", "scope-all", "grant", "maintainer"],
    )
    async def test_accessible_cve_is_published(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
        user_factory: Factory,
        path: str,
    ) -> None:
        """A ticketless CVE and a CVE with a non-confidential Ticket are
        accessible; a confidential Ticket is accessible through scope
        `all`, an explicit grant, or included-package maintainership
        (rbac.md, Scope and Confidential Ticket Visibility; cve-service.md,
        CVE Read and Accessibility Boundary)."""
        await _fetcher(db_session, NVD)
        cve = await _cve(db_session)
        user = await user_factory(username="analyst-alice", email="alice@example.com")
        caller = _restricted(user)
        if path == "non-confidential":
            await _ticket(db_session, cve)
        elif path != "ticketless":
            ticket = await _ticket(db_session, cve, confidential=True)
            if path == "scope-all":
                caller = TicketCaller.authenticated(user.id, Scope.ALL)
            elif path == "grant":
                granter = await user_factory(
                    username="analyst-bob", email="bob@example.com"
                )
                db_session.add(
                    TicketAccessGrant(
                        ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
                    )
                )
            else:
                package = TicketPackage(ticket_id=ticket.id, package_name="fictional-a")
                db_session.add(package)
                await db_session.flush()
                db_session.add(
                    TicketPackageMaintainer(
                        ticket_package_id=package.id, user_id=user.id
                    )
                )
            await db_session.flush()

        result = await _refetch(service_sessions, cve.cve_id, caller=caller)

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd"],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=[],
        )
        assert _published_sources(published) == ["nvd"]


# ---------------------------------------------------------------------------
# Source and enabled-state matrix
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSourceMatrix:
    @pytest.mark.parametrize(
        "case", ["unknown-string", "deregistered-source-value", "not-refetchable"]
    )
    async def test_explicit_source_without_fetch_single_is_invalid(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        """An explicit source that is not a registered CVE source with
        `supports_fetch_single = True` raises `CVEInvalidSourceError`
        (cve-service.md, Transactional Preparation step 5; Exceptions;
        cve-tracking.md, 422 `CVE_INVALID_SOURCE`)."""
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, EPSS, refetchable=False)
        cve = await _cve(db_session)
        source = {
            "unknown-string": "fictional_source",
            "deregistered-source-value": OSV.value,
            "not-refetchable": EPSS.value,
        }[case]
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVEInvalidSourceError):
            await _refetch(service_sessions, cve.cve_id, source=source)

        assert attempts() == 0
        assert published.calls == []

    async def test_explicit_disabled_source_is_disabled_error(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """cve-service.md, Transactional Preparation step 5: an explicit
        registered refetchable but disabled source raises
        `CVESourceDisabledError` (409 `FETCHER_DISABLED`), even when another
        source is enabled."""
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, GHSA, enabled=False)
        cve = await _cve(db_session)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVESourceDisabledError):
            await _refetch(service_sessions, cve.cve_id, source=GHSA.value)

        assert attempts() == 0
        assert published.calls == []

    async def test_explicit_enabled_source_publishes_only_that_source(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """The prepared set after explicit source selection is that one
        source: other enabled and disabled sources appear in no list
        (cve-service.md, `FetchDispatchResult`; cve-tracking.md, Re-fetch
        Endpoint)."""
        await _fetcher(db_session, NVD)
        ghsa = await _fetcher(db_session, GHSA)
        await _fetcher(db_session, OSV, enabled=False)
        cve = await _cve(db_session)

        result = await _refetch(service_sessions, cve.cve_id, source=GHSA.value)

        assert result == FetchDispatchResult(
            sources_enqueued=["ghsa"],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=[],
        )
        [kwargs] = published.published(TASK)
        assert kwargs["fetcher_name"] == ghsa
        assert kwargs["cve_id"] == cve.cve_id
        assert kwargs["source"] == "ghsa"
        assert [key for _, key, _ in scripted_redis.commands] == [
            pending_key(cve.cve_id, "ghsa")
        ]

    async def test_broadcast_reports_disabled_and_publishes_only_enabled(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """Broadcast retains disabled refetchable sources for the result and
        prepares only enabled ones; a registered non-refetchable source is
        outside the broadcast set (cve-service.md, Transactional
        Preparation step 5; `FetchDispatchResult`, `sources_disabled`)."""
        await _fetcher(db_session, OSV)
        await _fetcher(db_session, REDHAT, enabled=False)
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, GHSA, enabled=False)
        await _fetcher(db_session, KEV, refetchable=False)
        cve = await _cve(db_session)

        result = await _refetch(service_sessions, cve.cve_id)

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd", "osv"],
            sources_already_pending=[],
            sources_disabled=["ghsa", "redhat"],
            sources_failed=[],
        )
        assert _published_sources(published) == ["nvd", "osv"]
        assert [key for _, key, _ in scripted_redis.commands] == [
            pending_key(cve.cve_id, "nvd"),
            pending_key(cve.cve_id, "osv"),
        ]

    @pytest.mark.parametrize(
        "roster", ["all-disabled", "empty-registry", "only-non-refetchable"]
    )
    async def test_broadcast_without_enabled_refetchable_source_fails(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        roster: str,
    ) -> None:
        """No enabled refetchable source, including an empty fetch-single
        registry, is `CVEFetchFailedError` (cve-service.md, Transactional
        Preparation step 5; cve-tracking.md, 503 `CVE_FETCH_FAILED`)."""
        if roster == "all-disabled":
            await _fetcher(db_session, NVD, enabled=False)
            await _fetcher(db_session, GHSA, enabled=False)
        elif roster == "only-non-refetchable":
            await _fetcher(db_session, KEV, refetchable=False)
        cve = await _cve(db_session)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVEFetchFailedError):
            await _refetch(service_sessions, cve.cve_id)

        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# Validation order and the bootstrap invariant
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestValidationOrder:
    @pytest.mark.parametrize(
        "later",
        ["invalid-source", "disabled-source", "missing-config", "no-enabled-source"],
    )
    async def test_inaccessible_cve_is_not_found_before_source_validation(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        later: str,
    ) -> None:
        """Source existence, refetch capability, configuration, and enabled
        state are evaluated only after accessibility succeeds
        (cve-tracking.md, Access check behavior step 3; cve-service.md,
        Transactional Preparation step 4)."""
        source: str | None = None
        if later == "invalid-source":
            await _fetcher(db_session, NVD)
            source = "fictional_source"
        elif later == "disabled-source":
            await _fetcher(db_session, NVD, enabled=False)
            source = NVD.value
        elif later == "missing-config":
            await _fetcher(db_session, NVD, enabled=None)
        cve = await _cve(db_session)
        await _ticket(db_session, cve, confidential=True)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError):
            await _refetch(
                service_sessions,
                cve.cve_id,
                source=source,
                caller=_restricted(uuid.uuid4()),
            )

        assert attempts() == 0
        assert published.calls == []

    async def test_missing_cve_with_empty_registry_is_not_found(
        self,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The missing CVE is reported before the no-eligible-source outcome
        (cve-service.md, Transactional Preparation steps 3 and 4)."""
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVENotFoundError):
            await _refetch(service_sessions, fictional_cve_id())

        assert attempts() == 0
        assert published.calls == []

    async def test_explicit_unknown_source_is_invalid_before_configuration_read(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only the applicable `FetcherConfig` rows are read: an unknown
        explicit source is invalid even though another registered
        refetchable fetcher lacks its configuration row (cve-service.md,
        Transactional Preparation steps 4 and 5)."""
        await _fetcher(db_session, NVD, enabled=None)
        cve = await _cve(db_session)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(CVEInvalidSourceError):
            await _refetch(service_sessions, cve.cve_id, source="fictional_source")

        assert attempts() == 0
        assert published.calls == []

    @pytest.mark.parametrize("explicit", [False, True], ids=["broadcast", "explicit"])
    async def test_registered_fetcher_without_configuration_row_propagates(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        explicit: bool,
    ) -> None:
        """A registered fetcher without its required `FetcherConfig` row is
        a bootstrap invariant failure: `FetcherConfigMissingError`
        propagates and nothing is published (cve-service.md, Transactional
        Preparation step 4; `refetch_cve()` Q6)."""
        await _fetcher(db_session, NVD, enabled=None)
        await _fetcher(db_session, GHSA)
        cve = await _cve(db_session)
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(FetcherConfigMissingError):
            await _refetch(
                service_sessions, cve.cve_id, source=NVD.value if explicit else None
            )

        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# Publication outcomes
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPublicationOutcomes:
    async def test_partial_publication_failure_logs_one_sanitized_warning(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """A raising publication is unconfirmed (`sources_failed`); the
        refetch logs exactly one WARNING with only the canonical CVE-ID,
        the failed sources, and `trigger = refetch` (cve-service.md,
        Database-Free Publication; issue #800, D4)."""
        for source in (NVD, GHSA, OSV):
            await _fetcher(db_session, source)
        cve = await _cve(db_session)
        published.before = _failing_for(
            {"ghsa", "osv"}, BrokerOperationalError(f"refused {SECRET}")
        )

        with capture_logs() as logs:
            result = await _refetch(service_sessions, cve.cve_id)

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd"],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=["ghsa", "osv"],
        )
        warnings = events_named(logs, UNCONFIRMED)
        assert warnings == [
            {
                "event": UNCONFIRMED,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "sources_failed": ["ghsa", "osv"],
                "trigger": "refetch",
            }
        ]
        tokens = [str(token) for token in scripted_redis.values("set")]
        rendered = repr(logs)
        for fragment in (*tokens, "fictional-secret", "broker.example.test", "amqp"):
            assert fragment not in rendered
        assert_private_logs(warnings, *tokens, "fictional-secret")

    async def test_confirmed_publication_logs_nothing(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """No WARNING when `sources_failed` is empty (issue #800, D4)."""
        await _fetcher(db_session, NVD)
        cve = await _cve(db_session)

        with capture_logs() as logs:
            result = await _refetch(service_sessions, cve.cve_id)

        assert result.sources_enqueued == ["nvd"]
        assert result.sources_failed == []
        assert events_named(logs, UNCONFIRMED) == []

    async def test_every_publication_unconfirmed_still_returns_the_result(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """Mapping an all-unconfirmed result to `503 CELERY_UNAVAILABLE` is
        the endpoint's contract; the service returns the result normally
        (cve-service.md, Database-Free Publication; `refetch_cve()` Q4)."""
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, MITRE, queue="git")
        cve = await _cve(db_session)
        published.before = _failing_for({"nvd", "mitre"}, RuntimeError("fictional"))

        with capture_logs() as logs:
            result = await _refetch(service_sessions, cve.cve_id)

        assert result == FetchDispatchResult(
            sources_enqueued=[],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=["mitre", "nvd"],
        )
        warnings = events_named(logs, UNCONFIRMED)
        assert [entry["sources_failed"] for entry in warnings] == [["mitre", "nvd"]]

    @pytest.mark.parametrize("pending", [False, True], ids=["new", "pending"])
    async def test_explicit_success_is_in_exactly_one_accepted_list(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        redis_client: redis_asyncio.Redis,
        published: Publications,
        pending: bool,
    ) -> None:
        """cve-tracking.md, Re-fetch Endpoint: with an explicit `source`,
        success contains that one source in exactly one of
        `sources_enqueued` and `sources_already_pending`."""
        await _fetcher(db_session, MITRE, queue="git")
        await _fetcher(db_session, NVD)
        cve = await _cve(db_session)
        if pending:
            await redis_client.set(pending_key(cve.cve_id, "mitre"), "fictional-owner")

        result = await _refetch(service_sessions, cve.cve_id, source=MITRE.value)

        expected = (["mitre"], []) if not pending else ([], ["mitre"])
        assert (result.sources_enqueued, result.sources_already_pending) == expected
        assert result.sources_disabled == []
        assert result.sources_failed == []
        assert _published_sources(published) == ([] if pending else ["mitre"])

    async def test_fetcher_queue_is_preserved_and_none_is_omitted(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        scripted_redis: ScriptedRedis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Task identity is `fetcher_cls.name`; `queue=fetcher_cls.queue` is
        passed when non-`None` and omitted otherwise (cve-service.md,
        Database-Free Publication; testing-strategy.md, On-Demand CVE
        Refetch). The real `publish_task` runs over a substituted
        `celery_app.send_task`."""
        git = await _fetcher(db_session, KERNEL, queue="git")
        default = await _fetcher(db_session, NVD)
        cve = await _cve(db_session)
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        result = await _refetch(service_sessions, cve.cve_id)

        assert result.sources_enqueued == ["kernel", "nvd"]
        kernel_token, nvd_token = scripted_redis.values("set")
        assert send_task.call_args_list == [
            call(
                TASK,
                kwargs={
                    "fetcher_name": git,
                    "cve_id": cve.cve_id,
                    "source": "kernel",
                    "token": kernel_token,
                },
                ignore_result=True,
                queue="git",
            ),
            call(
                TASK,
                kwargs={
                    "fetcher_name": default,
                    "cve_id": cve.cve_id,
                    "source": "nvd",
                    "token": nvd_token,
                },
                ignore_result=True,
            ),
        ]


# ---------------------------------------------------------------------------
# Dispatch only: Ticket status opt-out, no audit, no row change
# ---------------------------------------------------------------------------


async def _snapshot(db: AsyncSession, cve: CVE, ticket: Ticket) -> dict[str, Any]:
    """Every persisted column of the CVE, its Ticket, its `CVESource` rows,
    and every `FetcherConfig` row, plus the audit event counts."""

    async def rows(statement: Select[Any]) -> list[dict[str, Any]]:
        return [dict(row._mapping) for row in (await db.execute(statement)).all()]

    return {
        "cve": await rows(select(CVE.__table__).where(CVE.id == cve.id)),
        "ticket": await rows(select(Ticket.__table__).where(Ticket.id == ticket.id)),
        "sources": await rows(
            select(CVESource.__table__)
            .where(CVESource.cve_id == cve.id)
            .order_by(CVESource.source)
        ),
        "configs": await rows(
            select(FetcherConfig.__table__).order_by(FetcherConfig.fetcher_name)
        ),
        "ticket_events": await db.scalar(select(func.count(TicketAuditEvent.id))),
        "fetcher_events": await db.scalar(select(func.count(FetcherAuditEvent.id))),
    }


@pytest.mark.integration
class TestDispatchOnly:
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=lambda s: s.value
    )
    async def test_ignored_or_duplicated_ticket_is_accepted(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
        status: TicketStatus,
    ) -> None:
        """The dispatch-only refetch opts out of `ensure_ticket_operable()`
        and never produces `TICKET_NOT_MUTABLE` (cve-service.md,
        Transactional Preparation; cve-tracking.md, Re-fetch Endpoint)."""
        await _fetcher(db_session, NVD)
        cve = await _cve(db_session)
        target = (
            await _ticket(db_session, None)
            if status is TicketStatus.DUPLICATED
            else None
        )
        await _ticket(db_session, cve, status=status, duplicate_of=target)

        result = await _refetch(service_sessions, cve.cve_id)

        assert result.sources_enqueued == ["nvd"]
        assert _published_sources(published) == ["nvd"]

    async def test_refetch_changes_no_row_and_creates_no_audit_event(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """Refetch changes no CVE, Ticket, source status, or fetcher
        configuration and creates no audit row (cve-service.md,
        Transactional Preparation; ticket-audit-log.md, CVE refetch
        preparation and publication)."""
        await _fetcher(db_session, NVD)
        await _fetcher(db_session, GHSA, enabled=False)
        cve = await _cve(db_session)
        ticket = await _ticket(db_session, cve, confidential=True)
        db_session.add(
            CVESource(
                cve_id=cve.id,
                source="nvd",
                status="success",
                fetched_at=datetime(2099, 3, 5, 8, 30, tzinfo=UTC),
            )
        )
        await db_session.flush()
        before = await _snapshot(db_session, cve, ticket)

        result = await _refetch(service_sessions, cve.cve_id)

        assert result.sources_enqueued == ["nvd"]
        assert result.sources_disabled == ["ghsa"]
        # The snapshot includes both audit event counts: the delta is zero.
        assert await _snapshot(db_session, cve, ticket) == before


# ---------------------------------------------------------------------------
# Independent sessions: committed world and the service session factory
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns committed `FetcherConfig` rows and
    an independent `probe` session observing committed state and locks."""

    probe: AsyncSession

    def __init__(self, factory: SessionFactory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self.fetcher_names: list[str] = []

    async def fetcher(
        self,
        source: CVESourceType,
        *,
        enabled: bool = True,
        queue: str | None = None,
    ) -> str:
        probe = define_cve_fetcher(source=source, fetcher_queue=queue)
        self.session.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
        await self.session.commit()
        self.fetcher_names.append(probe.name)
        return probe.name

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
        finally:
            await self.session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name.in_(self.fetcher_names)
                )
            )
            await self.session.commit()


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[_World]:
    created = _World(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        yield created
    finally:
        await created.cleanup()


class _Sessions:
    """The refetch `session_factory`: hands out pre-opened independent
    sessions in order (their backend PIDs are known before the refetch
    starts), records `commit` and `close` into `events`, and can make
    `commit` raise."""

    def __init__(
        self, *sessions: AsyncSession, events: list[str] | None = None
    ) -> None:
        self._pending = list(sessions)
        self.events: list[str] = [] if events is None else events
        self.handed: list[AsyncSession] = []
        self.closed: list[AsyncSession] = []
        self.commit_error: BaseException | None = None
        self.commit_first = False

    def __call__(self) -> AsyncSession:
        session = self._pending.pop(0)
        close = session.close
        commit = session.commit

        async def _recording_close() -> None:
            await close()
            self.closed.append(session)
            self.events.append("close")

        async def _recording_commit() -> None:
            self.events.append("commit")
            if self.commit_error is not None:
                if self.commit_first:
                    await commit()
                raise self.commit_error
            await commit()

        session.close = _recording_close  # type: ignore[method-assign]
        session.commit = _recording_commit  # type: ignore[method-assign]
        self.handed.append(session)
        return session

    @property
    def factory(self) -> async_sessionmaker[AsyncSession]:
        return cast(async_sessionmaker[AsyncSession], self)


class _ObservedRedis(ScriptedRedis):
    """`ScriptedRedis` awaiting `on_set` before answering each `SET`."""

    def __init__(self, on_set: Callable[[], Awaitable[None]]) -> None:
        super().__init__()
        self._on_set = on_set

    async def set(self, key: str, value: str, **options: object) -> bool | None:
        await self._on_set()
        return await super().set(key, value, **options)


def _cve_lock(cve: CVE) -> Select[Any]:
    """The CVE root lock taken `NOWAIT` (conflicts with the refetch's
    `FOR NO KEY UPDATE`)."""
    return (
        select(CVE.id)
        .where(CVE.id == cve.id)
        .with_for_update(key_share=True, nowait=True)
    )


def _ticket_lock(ticket: Ticket) -> Select[Any]:
    return select(Ticket.id).where(Ticket.id == ticket.id).with_for_update(nowait=True)


def _assert_no_owner_state(session: AsyncSession) -> None:
    """The refetch registered no post-commit callback and its session is
    closed (cve-service.md, Callers and Ordering)."""
    assert POST_COMMIT_CALLBACKS not in session.info
    assert not session.in_transaction()
    assert len(session.identity_map) == 0


@pytest.mark.integration
class TestLockOrderAndRelease:
    async def test_locks_cve_then_ticket_before_accessibility_and_configuration(
        self,
        world: _World,
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """The CVE `FOR NO KEY UPDATE`, then the Ticket `FOR UPDATE`, then
        the accessibility evaluation, and only then the `FetcherConfig`
        read; no write (cve-service.md, Transactional Preparation steps 2-4;
        docs/conventions.md, Cross-Domain Root Lock Order)."""
        user = await world.user(role=Role.RESTRICTED_ANALYST)
        granter = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve()
        ticket = await world.ticket(cve_id=cve.id, is_confidential=True)
        await world.grant(ticket, user, granter)
        await world.fetcher(NVD)
        session = await world.open_session()
        sessions = _Sessions(session)

        with SessionStatementRecorder(session) as recorder:
            result = await refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=_restricted(user),
                session_factory=sessions.factory,
            )

        assert result.sources_enqueued == ["nvd"]
        statements = recorder.statements
        assert root_lock_order(statements) == ["cve", "ticket"]
        assert is_root_lock(statements[0], "cve")
        assert is_root_lock(statements[1], "ticket")
        assert len(recorder.row_locks()) == 2
        accessibility = next(
            i for i, s in enumerate(statements) if "ticket_access_grant" in s
        )
        configuration = next(
            i for i, s in enumerate(statements) if "FROM fetcher_config" in s
        )
        assert 1 < accessibility < configuration
        assert recorder.writes() == []

    async def test_cve_root_lock_holder_blocks_refetch_until_it_commits(
        self,
        world: _World,
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """An independent session holding the CVE `FOR NO KEY UPDATE`
        blocks the refetch's CVE lock; after it commits the refetch
        publishes (cve-service.md, Transactional Preparation step 2)."""
        cve = await world.cve()
        await world.ticket(cve_id=cve.id)
        await world.fetcher(NVD)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        await holder.execute(
            select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
        )

        task = world.start(
            session,
            refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=SCOPE_ALL,
                session_factory=sessions.factory,
            ),
        )
        await assert_lock_wait(task, waiter=session, blocked_by=holder)
        assert published.calls == []
        await holder.commit()
        result = await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert result.sources_enqueued == ["nvd"]

    async def test_ticket_lock_wait_happens_while_holding_the_cve_lock(
        self,
        world: _World,
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """While the refetch waits for the Ticket held by an independent
        session, the CVE root is already locked by the refetch: the CVE is
        locked first (cve-service.md, Transactional Preparation step 2)."""
        cve = await world.cve()
        ticket = await world.ticket(cve_id=cve.id)
        await world.fetcher(NVD)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        await holder.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )

        task = world.start(
            session,
            refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=SCOPE_ALL,
                session_factory=sessions.factory,
            ),
        )
        await assert_lock_wait(task, waiter=session, blocked_by=holder)
        assert await lock_not_available(world.probe, _cve_lock(cve))
        await holder.commit()
        result = await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert result.sources_enqueued == ["nvd"]
        assert not await lock_not_available(world.probe, _cve_lock(cve))

    async def test_commit_close_and_lock_release_precede_redis_and_broker(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """At every Redis `SET` and every broker publication, the refetch
        session has committed and closed and an independent session takes
        the CVE and Ticket locks `NOWAIT`; no post-commit callback is
        registered (cve-service.md, Callers and Ordering; Transaction
        Ownership)."""
        cve = await world.cve()
        ticket = await world.ticket(cve_id=cve.id, is_confidential=True)
        await world.fetcher(NVD)
        await world.fetcher(MITRE, queue="git")
        session = await world.open_session()
        events: list[str] = []
        sessions = _Sessions(session, events=events)
        observed: list[tuple[bool, bool, bool, bool]] = []

        async def _observe() -> None:
            observed.append(
                (
                    await lock_not_available(world.probe, _cve_lock(cve)),
                    await lock_not_available(world.probe, _ticket_lock(ticket)),
                    session.in_transaction(),
                    session in sessions.closed,
                )
            )

        async def _at_set() -> None:
            events.append("redis:set")
            await _observe()

        async def _at_publication(call_options: dict[str, Any]) -> None:
            await _observe()

        _ObservedRedis(_at_set).install(monkeypatch)
        published.events = events
        published.before = _at_publication

        result = await refetch_cve(
            cve_id=cve.cve_id,
            source=None,
            caller=SCOPE_ALL,
            session_factory=sessions.factory,
        )

        assert result.sources_enqueued == ["mitre", "nvd"]
        assert events == [
            "commit",
            "close",
            "redis:set",
            f"publish:{TASK}",
            "redis:set",
            f"publish:{TASK}",
        ]
        assert observed == [(False, False, False, True)] * 4
        assert sessions.handed == sessions.closed == [session]
        _assert_no_owner_state(session)

    @pytest.mark.parametrize(
        "committed", [False, True], ids=["failed-commit", "ambiguous-commit"]
    )
    async def test_commit_failure_propagates_without_publication(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        committed: bool,
    ) -> None:
        """A definitely failed commit and a commit whose outcome is
        ambiguous both propagate unchanged with zero Redis and Celery I/O;
        the session is closed and the locks released (cve-service.md,
        Transactional Preparation; Callers and Ordering)."""
        cve = await world.cve()
        ticket = await world.ticket(cve_id=cve.id)
        await world.fetcher(NVD)
        session = await world.open_session()
        sessions = _Sessions(session)
        failure = DatabaseOperationalError(
            "COMMIT", {}, Exception("server closed the connection")
        )
        sessions.commit_error = failure
        sessions.commit_first = committed
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs, pytest.raises(DatabaseOperationalError) as raised:
            await refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=SCOPE_ALL,
                session_factory=sessions.factory,
            )

        assert raised.value is failure
        assert attempts() == 0
        assert published.calls == []
        assert events_named(logs, UNCONFIRMED) == []
        assert sessions.events == ["commit", "close"]
        assert not await lock_not_available(world.probe, _cve_lock(cve))
        assert not await lock_not_available(world.probe, _ticket_lock(ticket))

    async def test_cancellation_while_waiting_for_the_cve_lock_publishes_nothing(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The refetch is cancelled while it waits for the CVE lock held by
        an independent session: the cancellation propagates, the service
        session is closed without committing and holds no transaction or
        lock, and there is no Redis command and no publication attempt, even
        after the holder commits (cve-service.md, Transactional Preparation:
        cancellation before commit; Callers and Ordering)."""
        cve = await world.cve()
        await world.ticket(cve_id=cve.id)
        await world.fetcher(NVD)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        attempts = forbid_redis(monkeypatch)
        await holder.execute(
            select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
        )

        task = world.start(
            session,
            refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=SCOPE_ALL,
                session_factory=sessions.factory,
            ),
        )
        await assert_lock_wait(task, waiter=session, blocked_by=holder)
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=WAIT)
        await holder.commit()

        assert done == {task}
        assert task.cancelled()
        assert sessions.events == ["close"]
        assert sessions.handed == sessions.closed == [session]
        _assert_no_owner_state(session)
        assert not await lock_not_available(world.probe, _cve_lock(cve))
        assert attempts() == 0
        assert published.calls == []


# ---------------------------------------------------------------------------
# Locked-current accessibility races
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller can access the CVE through exactly one
    path. An independent session holds a root lock and removes that path;
    the refetch is proven blocked, the holder commits, and the refetch must
    be denied from the locked-current state with zero Redis and Celery I/O
    (testing-strategy.md, On-Demand CVE Refetch; Ticket Accessibility >
    Locked mutations; cve-tracking.md, Access check behavior)."""

    @pytest.mark.parametrize("loss", VISIBILITY_LOSSES)
    async def test_visibility_lost_while_waiting_is_not_found(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
    ) -> None:
        user, cve, ticket, statements = await prepare_loss(world, loss)
        await world.fetcher(NVD)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        attempts = forbid_redis(monkeypatch)
        for statement in statements:
            await holder.execute(statement)

        with SessionStatementRecorder(session) as recorder:
            task = world.start(
                session,
                refetch_cve(
                    cve_id=cve.cve_id,
                    source=None,
                    caller=_restricted(user),
                    session_factory=sessions.factory,
                ),
            )
            await assert_lock_wait(task, waiter=session, blocked_by=holder)
            await holder.commit()
            with pytest.raises(CVENotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert attempts() == 0
        assert published.calls == []
        assert recorder.writes() == []
        assert not any("fetcher_config" in s for s in recorder.statements)
        assert sessions.closed == [session]
        _assert_no_owner_state(session)
        assert not await lock_not_available(world.probe, _ticket_lock(ticket))

    async def test_lost_visibility_wins_over_explicit_disabled_source(
        self,
        world: _World,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The locked-current accessibility denial precedes the enabled-state
        validation: a stale earlier decision would surface
        `CVESourceDisabledError` instead (cve-tracking.md, Access check
        behavior step 3)."""
        user, cve, _ticket_row, statements = await prepare_loss(
            world, "confidentiality-set"
        )
        await world.fetcher(GHSA, enabled=False)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        attempts = forbid_redis(monkeypatch)
        for statement in statements:
            await holder.execute(statement)

        task = world.start(
            session,
            refetch_cve(
                cve_id=cve.cve_id,
                source=GHSA.value,
                caller=_restricted(user),
                session_factory=sessions.factory,
            ),
        )
        await assert_lock_wait(task, waiter=session, blocked_by=holder)
        await holder.commit()
        with pytest.raises(CVENotFoundError):
            await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert attempts() == 0
        assert published.calls == []

    async def test_visibility_gained_while_waiting_publishes(
        self,
        world: _World,
        published: Publications,
        scripted_redis: ScriptedRedis,
    ) -> None:
        """Converse: the caller cannot access the CVE when the refetch
        starts, an independent session holding the Ticket makes it
        non-confidential, and the refetch publishes from the locked-current
        state (testing-strategy.md, Ticket Accessibility: loss and
        acquisition of visibility)."""
        user = await world.user(role=Role.RESTRICTED_ANALYST)
        cve = await world.cve()
        ticket = await world.ticket(cve_id=cve.id, is_confidential=True)
        await world.fetcher(NVD)
        holder = await world.open_session()
        session = await world.open_session()
        sessions = _Sessions(session)
        await holder.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )
        await holder.execute(
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=False)
        )

        task = world.start(
            session,
            refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=_restricted(user),
                session_factory=sessions.factory,
            ),
        )
        await assert_lock_wait(task, waiter=session, blocked_by=holder)
        await holder.commit()
        result = await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd"],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=[],
        )
        assert _published_sources(published) == ["nvd"]
        assert sessions.closed == [session]
