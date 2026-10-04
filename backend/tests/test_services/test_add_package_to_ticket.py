"""Single-session service integration tests for the package addition
orchestrator `package_service.add_package_to_ticket()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (Architecture: Transaction
  ownership, Acting user convention, Consumer caller context and Ticket
  accessibility, Module invariant: I/O-then-Lock pattern; Auto-Assignment
  Rule; `add_package_to_ticket()` steps 1-8 and 10, Idempotency, Escaping
  exceptions, Public error precedence, Error handling; Service Exceptions;
  Architectural Test Requirement: Atomic consumer accessibility (the
  single-session parts), Maintainership acquisition, Package creation
  concurrency and result truth (single-session outcomes), Package audit
  comments).
- docs/features/packages/package-model.md (Interaction with
  add_package_to_ticket; Adding Packages to a Ticket, public precedence
  2-11 and Idempotency; SMELT Query for Package Resolution).
- docs/features/packages/product-catalog.md (Catalog Readiness and
  Freshness).
- docs/features/packages/package-maintainership.md (Acquisition Workflow >
  Invocation boundary; Security and Privacy; Testing Requirements).
- docs/features/platform/testing-strategy.md (Service Functions; Audit
  Trail Testing).

The locked boundary `add_package_records()` is covered by
`tests/test_services/test_add_package_records.py`,
`tests/test_services/test_add_package_records_scope.py`, and
`tests/test_services/test_add_package_records_atomicity.py`; here only its
composition is tested. The SMELT clients are covered by
`tests/test_services/test_packages/`. Independent-session races of the
orchestrator (preliminary and locked-current accessibility, concurrent
additions) are covered by
`tests/test_services/test_add_package_to_ticket_races.py`, and the
orchestrator path of Architectural Test Requirement 4 by
`tests/test_services/test_new_to_analysis_promotion.py`. The two
access-loss tests below change the Ticket inside the fake SMELT responder
of the same session: they prove the precedence of the locked-current check
and of an external failure, not concurrency.

Unless a test states otherwise: `SMELT_API_URL` is the fictional test
origin and SMELT is the in-process `PackageSmelt` fake
(`tests/support/package_addition.py`); the `default_cvss_version` setting
is `3.1`; the service's UTC date is the controlled `EVAL`; a Ticket is
CVE-less with `severity_manual = High`; a catalog Product is in General
Support with a `NULL` threshold, so a created occurrence is eligible; and
a Product a test expects to match is published in the current catalog
snapshot (`SNAPSHOT_AT`). A consumer call uses an active VA with effective
scope `all`. Expected values are transcribed from the specifications,
never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from dataclasses import dataclass, fields
from datetime import timedelta
from typing import Any

import httpx
import pytest
from celery import Celery
from celery.app.task import Task
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import PackageStatus, Role, Scope, TicketStatus, WorkflowType
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    HTTP_CLIENT_NAME,
    PARTIAL_RESOLUTION_EVENT,
    SYSTEM_INVOCATION,
    AddPackageResult,
    CreatedTrack,
    PackageAddedComment,
    PackageAlreadyExcludedError,
    PackageNotFoundInSmeltError,
    PackageRecordsOutcome,
    PackageServiceError,
    PackageTargetsUnresolvedError,
    ProductCatalogNotReadyError,
    ResolvedTrackData,
    SmeltUnavailableError,
    add_package_to_ticket,
)
from app.services.packages.smelt_maintained import (
    UNKNOWN_PROCESS_EVENT,
    UNSUPPORTED_PROCESS_EVENT,
)
from app.services.packages.smelt_maintainership import ACQUISITION_UNAVAILABLE_EVENT
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.package_addition import (
    HISTORICAL_AT,
    SNAPSHOT_AT,
    PackageSmelt,
    Respond,
    add,
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
    SKIPPED,
    Tree,
    assert_no_effects,
    catalog_product,
    changed,
    maintainer_event,
    maintainers,
    new_occurrence,
    outcome,
    package_added_event,
    package_tree,
    seed_occurrence,
    seed_package,
    seed_track,
    seed_user,
    snapshot,
    ticket_row,
    track_ids,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss import assignment_event
from tests.support.ticket_mutations import (
    EVAL,
    StatementRecorder,
    TicketFactory,
    VAUser,
    cveless,
    status_event,
    ticket_events,
)
from tests.support.track_status import Spy

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

GrantFactory = Callable[..., Awaitable[Any]]
Logs = list[MutableMapping[str, Any]]

PKG = "fictional-libexample"
IBS_REF = "Fictional:Product:15-SP7:Update"
IBS_REF_2 = "Fictional:Product:16.0:Update"
GIT_REF = "fictional/slfo-1.1"
SLFO_IBS_REF = "Fictional:SLFO-IBS:1.0"
UNKNOWN_REF = "Fictional:Unclassified:1"

ABSENT_1 = "cpe:/o:example:absent:1"
ABSENT_2 = "cpe:/o:example:absent:2"
ABSENT_3 = "cpe:/o:example:absent:3"
"""CPEs that no catalog Product carries."""

MARKER = "fictional-private-marker-7f3a"
"""A private string placed in SMELT bodies and exception messages."""

SMELT_HOST = "smelt.example.test"

NEW = TicketStatus.NEW
ANALYSIS = TicketStatus.ANALYSIS
RESOLVED = TicketStatus.RESOLVED
IGNORED = TicketStatus.IGNORED
DUPLICATED = TicketStatus.DUPLICATED

LOCK_MARKERS = ("FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR KEY SHARE")

BOTH = ["maintained", "maintainership"]
"""The two SMELT requests of an invocation whose targets resolved."""


@pytest.fixture(autouse=True)
def _clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is the controlled `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def _smelt_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both SMELT clients build their URLs from the fictional test origin."""
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


@pytest.fixture(autouse=True)
async def _default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _current(db: AsyncSession, count: int = 1) -> list[Product]:
    """`count` catalog Products published in the current snapshot."""
    products = [await catalog_product(db) for _ in range(count)]
    await publish(db, *products)
    return products


async def _assert_catalog_not_ready(db: AsyncSession) -> None:
    """Precondition: no Product exists, so `MAX(catalog_last_seen_at)` is
    `NULL` (product-catalog.md, Catalog Readiness and Freshness)."""
    count = (await db.execute(select(func.count()).select_from(Product))).scalar_one()
    assert count == 0


async def _historical(db: AsyncSession) -> Product:
    """A catalog Product retained from an earlier snapshot."""
    product = await catalog_product(db)
    await publish(db, product, at=HISTORICAL_AT)
    return product


def _consumer(actor: User, scope: Scope = Scope.ALL) -> TicketCaller:
    return TicketCaller.authenticated(actor.id, scope)


def _events(logs: Logs) -> list[str]:
    return [log["event"] for log in logs]


def _patch_factory(monkeypatch: pytest.MonkeyPatch, smelt: PackageSmelt) -> list[str]:
    """Make `create_http_client()` return a client of `smelt`; return the
    list of requested client names."""
    names: list[str] = []

    def _factory(name: str, **overrides: Any) -> httpx.AsyncClient:
        names.append(name)
        return smelt.client()

    monkeypatch.setattr(package_service, "create_http_client", _factory)
    return names


class _Timeline(StatementRecorder):
    """A `StatementRecorder` that also appends `("sql", statement)` to the
    shared `events` list in which `PackageSmelt` records its requests."""

    def __init__(self, db: AsyncSession, events: list[tuple[str, str]]) -> None:
        super().__init__(db)
        self.events = events

    def _record(self, *args: Any) -> None:
        super()._record(*args)
        self.events.append(("sql", args[2]))


@dataclass(frozen=True, slots=True)
class Blocked:
    """A rejected invocation: its exception, logs, and SQL statements."""

    error: Exception
    logs: Logs
    statements: list[str]


async def _assert_blocked(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[AddPackageResult]],
    *,
    smelt: PackageSmelt,
    error: type[Exception],
    kinds: Sequence[str] = ("maintained",),
    ticket_ids: tuple[uuid.UUID, ...],
    delegated: bool = False,
) -> Blocked:
    """Run the call, expect `error`, and assert the zero-side-effect
    contract: exactly the SMELT requests `kinds`; no write statement, no
    `auto_assign_actor()` or `reconcile_ticket_status()` call, no
    convergence registration, no `package_target_resolution_partial`
    warning, and an unchanged `snapshot()` of every given Ticket. Unless
    `delegated`, `add_package_records()` is never entered and no row lock
    is taken."""
    before = await snapshot(db, *ticket_ids)
    assert before[-1] == ()
    records = Spy(monkeypatch, "add_package_records")
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")

    with (
        capture_logs() as logs,
        StatementRecorder(db) as recorder,
        pytest.raises(error) as raised,
    ):
        await run()

    assert smelt.kinds == list(kinds)
    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert len(records.calls) == (1 if delegated else 0)
    if not delegated:
        assert recorder.row_locks() == []
    assert PARTIAL_RESOLUTION_EVENT not in _events(logs)
    assert await snapshot(db, *ticket_ids) == before
    return Blocked(raised.value, logs, recorder.statements)


# ---------------------------------------------------------------------------
# Input validation before any I/O (package-service.md, `add_package_to_ticket()`
# Q6; Acting user convention; package-model.md, SMELT Query for Package
# Resolution: one URL path segment)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInputValidation:
    """Each violation raises `ValueError` before any SQL statement, HTTP
    client creation, or SMELT request."""

    @staticmethod
    async def _assert_rejected(
        db: AsyncSession, monkeypatch: pytest.MonkeyPatch, match: str, **kwargs: Any
    ) -> None:
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", ABSENT_1))
        names = _patch_factory(monkeypatch, smelt)
        arguments: dict[str, Any] = {"ticket_id": uuid.uuid4(), "package_name": PKG}
        arguments.update(kwargs)

        with StatementRecorder(db) as recorder, pytest.raises(ValueError, match=match):
            await add_package_to_ticket(db, **arguments)

        assert recorder.statements == []
        assert names == []
        assert smelt.requests == []

    @pytest.mark.parametrize(
        "case",
        [
            "system-with-actor",
            "system-without-comment",
            "system-with-unknown-comment",
            "consumer-without-actor",
            "consumer-of-another-user",
            "anonymous-consumer",
            "consumer-with-comment",
            "consumer-with-unknown-comment",
        ],
    )
    async def test_inconsistent_invocation_raises_before_any_io(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, case: str
    ) -> None:
        actor, other = uuid.uuid4(), uuid.uuid4()
        consumer = TicketCaller.authenticated(actor, Scope.ALL)
        cases: dict[str, tuple[uuid.UUID | None, object, str | None, str]] = {
            "system-with-actor": (
                actor,
                SYSTEM_INVOCATION,
                "CVE package resolution",
                "no acting user",
            ),
            "system-without-comment": (
                None,
                SYSTEM_INVOCATION,
                None,
                "requires its canonical comment",
            ),
            "system-with-unknown-comment": (
                None,
                SYSTEM_INVOCATION,
                "Manual package addition",
                "unsupported package_added comment",
            ),
            "consumer-without-actor": (
                None,
                consumer,
                None,
                "must identify the acting user",
            ),
            "consumer-of-another-user": (
                actor,
                TicketCaller.authenticated(other, Scope.ALL),
                None,
                "must identify the acting user",
            ),
            "anonymous-consumer": (
                actor,
                ANONYMOUS_CALLER,
                None,
                "must identify the acting user",
            ),
            "consumer-with-comment": (
                actor,
                consumer,
                "CVE package resolution",
                "has no audit comment",
            ),
            "consumer-with-unknown-comment": (
                actor,
                consumer,
                "free text",
                "unsupported package_added comment",
            ),
        }
        acting_user_id, caller, comment, match = cases[case]

        await self._assert_rejected(
            db_session,
            monkeypatch,
            match,
            acting_user_id=acting_user_id,
            caller=caller,
            audit_comment=comment,
        )

    @pytest.mark.parametrize("package_name", ["", ".", ".."])
    @pytest.mark.parametrize("context", ["user", "system"])
    async def test_package_name_without_one_path_segment_raises_before_any_io(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        package_name: str,
        context: str,
    ) -> None:
        actor = uuid.uuid4()
        await self._assert_rejected(
            db_session,
            monkeypatch,
            "single URL path segment",
            package_name=package_name,
            acting_user_id=actor if context == "user" else None,
            caller=(
                TicketCaller.authenticated(actor, Scope.ALL)
                if context == "user"
                else SYSTEM_INVOCATION
            ),
            audit_comment=None if context == "user" else "Ticket convergence",
        )


# ---------------------------------------------------------------------------
# Public precedence 2: preliminary accessibility (package-service.md step 1;
# package-model.md, Adding Packages to a Ticket)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPreliminaryAccessibility:
    async def test_missing_ticket_raises_not_found_before_any_smelt_request(
        self, db_session: AsyncSession, va_user: VAUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        actor = await va_user()
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        missing = uuid.uuid4()

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, missing, PKG, smelt, actor=actor),
            smelt=smelt,
            error=TicketNotFoundError,
            kinds=(),
            ticket_ids=(),
        )

        assert len(blocked.statements) == 1

    async def test_inaccessible_confidential_ticket_raises_not_found_before_smelt(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `restricted_analyst` (`non_confidential` scope, no grant, no
        included maintained package) is denied by the single lock-free
        preliminary read, although SMELT would return its own email."""
        caller = await seed_user(
            db_session,
            email="fictional.caller@example.com",
            roles=(Role.RESTRICTED_ANALYST,),
        )
        ticket = await cveless(ticket_factory, status=NEW, is_confidential=True)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=["fictional.caller@example.com"],
        )

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(
                db_session,
                ticket.id,
                PKG,
                smelt,
                actor=caller,
                scope=Scope.NON_CONFIDENTIAL,
            ),
            smelt=smelt,
            error=TicketNotFoundError,
            kinds=(),
            ticket_ids=(ticket.id,),
        )

        assert len(blocked.statements) == 1
        assert blocked.statements[0].lstrip().upper().startswith("SELECT")

    @pytest.mark.parametrize("path", ["scope-all", "explicit-grant"])
    async def test_accessible_confidential_ticket_proceeds(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        path: str,
    ) -> None:
        assignee = await va_user()
        caller = (
            await va_user()
            if path == "scope-all"
            else await seed_user(db_session, roles=(Role.RESTRICTED_ANALYST,))
        )
        ticket = await cveless(
            ticket_factory,
            status=ANALYSIS,
            is_confidential=True,
            assignee_id=assignee.id,
        )
        if path == "explicit-grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=caller.id, granted_by_id=assignee.id
            )
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        result = await add(
            db_session,
            ticket.id,
            PKG,
            smelt,
            actor=caller,
            scope=Scope.ALL if path == "scope-all" else Scope.NON_CONFIDENTIAL,
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        assert smelt.kinds == BOTH

    async def test_system_call_skips_preliminary_accessibility(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """A system invocation applies no consumer visibility: on a
        confidential Ticket it reaches SMELT with no preceding statement."""
        ticket = await cveless(ticket_factory, status=ANALYSIS, is_confidential=True)
        (product,) = await _current(db_session)
        events: list[tuple[str, str]] = []
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe), events=events
        )

        with _Timeline(db_session, events):
            result = await add(db_session, ticket.id, PKG, smelt)

        assert outcome(result) == changed(1, 0, 1, 0)
        assert events[0] == ("http", "maintained")

    async def test_system_call_on_missing_ticket_fails_at_the_lock_after_io(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, uuid.uuid4(), PKG, smelt),
            smelt=smelt,
            error=TicketNotFoundError,
            kinds=BOTH,
            ticket_ids=(),
            delegated=True,
        )


# ---------------------------------------------------------------------------
# Public precedence 3: maintained-package availability before readiness
# (package-service.md steps 2-3; package-model.md, SMELT Query for Package
# Resolution: Envelope and error handling, Entry validation, Processing 1)
# ---------------------------------------------------------------------------

UNAVAILABLE: dict[str, tuple[Respond, str, int | None, str | None]] = {
    "http-500": (
        reply(500, {"status": "error", "data": "Internal error"}),
        "http_status",
        500,
        None,
    ),
    "http-200-jsend-error": (
        reply(200, {"status": "error", "data": "Package not found"}),
        "envelope",
        200,
        None,
    ),
    "http-200-jsend-fail": (
        reply(200, {"status": "fail", "data": {}}),
        "envelope",
        200,
        None,
    ),
    "http-404-without-jsend-error": (
        reply(404, {"detail": "Not Found"}),
        "envelope",
        404,
        None,
    ),
    "transport": (
        fail(httpx.ConnectError("connection refused")),
        "transport",
        None,
        "ConnectError",
    ),
    "invalid-json": (
        lambda request: httpx.Response(200, content=b"{not json"),
        "envelope",
        200,
        "JSONDecodeError",
    ),
    "schema-invalid-entry": (
        reply(200, maintained({"codestream": {"name": IBS_REF}, "targets": []})),
        "schema",
        200,
        None,
    ),
}
"""Maintained responder, and the expected `category`, `status_code`, and
`error_type` of `SmeltUnavailableError`."""


@pytest.mark.integration
class TestMaintainedUnavailable:
    @pytest.mark.parametrize("case", list(UNAVAILABLE))
    async def test_unavailable_precedes_catalog_readiness(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        """No Product exists (the catalog is not ready), yet the invalid
        maintained response raises `SmeltUnavailableError` with its bounded
        reason and no maintainership request."""
        respond, category, status_code, error_type = UNAVAILABLE[case]
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _assert_catalog_not_ready(db_session)
        smelt = PackageSmelt(
            maintained=respond, maintainership=reply(200, maintainership())
        )

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=SmeltUnavailableError,
            ticket_ids=(ticket.id,),
        )

        error = blocked.error
        assert isinstance(error, SmeltUnavailableError)
        assert isinstance(error, PackageServiceError)
        assert (error.category, error.status_code, error.error_type) == (
            category,
            status_code,
            error_type,
        )
        assert str(error) == "SMELT is unavailable."
        assert error.__cause__ is None
        assert error.__suppress_context__ is True
        # The only statement is the consumer's preliminary read: no
        # readiness or catalog read precedes or follows the failure.
        assert len(blocked.statements) == 1
        assert "catalog_last_seen_at" not in blocked.statements[0]


# ---------------------------------------------------------------------------
# Public precedence 4: catalog readiness before not-found and
# targets-unresolved (product-catalog.md, Catalog Readiness and Freshness)
# ---------------------------------------------------------------------------

NOT_READY: dict[str, Respond] = {
    "http-404-not-found": reply(404, not_found(PKG)),
    "http-200-empty-data": reply(200, maintained()),
    "all-cpes-unmatched": reply(
        200, maintained(codestream(IBS_REF, "SLE_15", ABSENT_1, ABSENT_2))
    ),
    "all-codestreams-skipped": reply(
        200,
        maintained(
            codestream(SLFO_IBS_REF, "SLFO_IBS", ABSENT_1),
            codestream(UNKNOWN_REF, "UNKNOWN", ABSENT_2),
        ),
    ),
}


@pytest.mark.integration
class TestCatalogNotReady:
    @pytest.mark.parametrize("case", list(NOT_READY))
    async def test_readiness_precedes_not_found_and_targets_unresolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _assert_catalog_not_ready(db_session)
        smelt = PackageSmelt(
            maintained=NOT_READY[case], maintainership=reply(200, maintainership())
        )

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=ProductCatalogNotReadyError,
            ticket_ids=(ticket.id,),
        )

        assert str(blocked.error) == "Product catalog is not ready."


# ---------------------------------------------------------------------------
# Public precedence 5-6: not-found, then targets-unresolved, on a ready
# catalog (package-model.md, SMELT Query for Package Resolution, Processing
# 3 and 6-7)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPackageNotFound:
    @pytest.mark.parametrize(
        "respond",
        [reply(404, not_found(PKG)), reply(200, maintained())],
        ids=["http-404-not-found", "http-200-empty-data"],
    )
    async def test_zero_codestreams_raise_package_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        respond: Respond,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _current(db_session)
        smelt = PackageSmelt(
            maintained=respond, maintainership=reply(200, maintainership())
        )

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=PackageNotFoundInSmeltError,
            ticket_ids=(ticket.id,),
        )

        assert str(blocked.error) == "Package not found in SMELT."


UNRESOLVED: dict[str, Callable[[Product, Product], list[dict[str, Any]]]] = {
    "all-cpes-unmatched": lambda current, historical: [
        codestream(IBS_REF, "SLE_15", ABSENT_1),
        codestream(GIT_REF, "SLFO", ABSENT_2, ABSENT_3),
    ],
    "all-codestreams-skipped": lambda current, historical: [
        codestream(SLFO_IBS_REF, "SLFO_IBS", current.cpe),
        codestream(UNKNOWN_REF, "UNKNOWN", current.cpe),
    ],
    "only-historical-products-match": lambda current, historical: [
        codestream(IBS_REF, "SLE_15", historical.cpe),
    ],
    "cpe-differs-only-by-case": lambda current, historical: [
        codestream(IBS_REF, "SLE_15", current.cpe.upper()),
    ],
}
"""Maintained entries built from a current and a historical Product. A
skipped codestream is never matched, even when its CPE is current."""


@pytest.mark.integration
class TestTargetsUnresolved:
    @pytest.mark.parametrize("case", list(UNRESOLVED))
    async def test_no_current_target_raises_targets_unresolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (current,) = await _current(db_session)
        historical = await _historical(db_session)
        smelt = PackageSmelt.ok(*UNRESOLVED[case](current, historical))

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=PackageTargetsUnresolvedError,
            ticket_ids=(ticket.id,),
        )

        assert str(blocked.error) == "Package targets could not be resolved."


# ---------------------------------------------------------------------------
# Public precedence 7-11: after the external phase (package-model.md, Adding
# Packages to a Ticket; package-service.md steps 7-8)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockedPhasePrecedence:
    @pytest.mark.parametrize("context", ["user", "system"])
    @pytest.mark.parametrize("status", [IGNORED, DUPLICATED], ids=str)
    async def test_manual_zone_ticket_is_rejected_after_both_requests(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
        status: TicketStatus,
    ) -> None:
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=status)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=TicketNotMutableError,
            kinds=BOTH,
            ticket_ids=(ticket.id,),
            delegated=True,
        )

    async def test_public_add_of_excluded_package_is_rejected_after_both_requests(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The unassigned `New` Ticket would be assigned and the new
        Product created; SMELT validly returns an active User's email. The
        locked guard rejects before any record or association."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        p1, p2 = await _current(db_session, 2)
        package = await seed_package(db_session, ticket.id, PKG, excluded=True)
        await seed_occurrence(
            db_session, await seed_track(db_session, package, IBS_REF), p1
        )
        await seed_user(db_session, email="maint.excluded@example.com")
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            emails=["maint.excluded@example.com"],
        )

        blocked = await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=PackageAlreadyExcludedError,
            kinds=BOTH,
            ticket_ids=(ticket.id,),
            delegated=True,
        )

        assert ACQUISITION_UNAVAILABLE_EVENT not in _events(blocked.logs)
        assert await maintainers(db_session, ticket.id) == []

    async def test_access_lost_during_io_is_denied_by_the_locked_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The preliminary read succeeds; the Ticket becomes confidential
        while maintainership is requested. The locked-current check raises
        `TicketNotFoundError` with no local effect, although SMELT returns
        the caller's own email (unpersisted data cannot authorize)."""
        caller = await seed_user(
            db_session,
            email="fictional.caller@example.com",
            roles=(Role.RESTRICTED_ANALYST,),
        )
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (product,) = await _current(db_session)

        async def _revoke(request: httpx.Request) -> httpx.Response:
            ticket.is_confidential = True
            await db_session.flush()
            return httpx.Response(
                200, json=maintainership("fictional.caller@example.com")
            )

        smelt = PackageSmelt(
            maintained=reply(
                200, maintained(codestream(IBS_REF, "SLE_15", product.cpe))
            ),
            maintainership=_revoke,
        )
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        with pytest.raises(TicketNotFoundError):
            await add(
                db_session,
                ticket.id,
                PKG,
                smelt,
                actor=caller,
                scope=Scope.NON_CONFIDENTIAL,
            )

        assert smelt.kinds == BOTH
        assert (assign.calls, reconcile.calls) == ([], [])
        assert await package_tree(db_session, ticket.id, PKG) is None
        assert await maintainers(db_session, ticket.id) == []
        assert await ticket_events(db_session, ticket) == []
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS.value, None)
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_access_lost_before_an_external_failure_keeps_the_external_error(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
    ) -> None:
        """No extra lookup replaces the external error with 404."""
        caller = await seed_user(db_session, roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _current(db_session)

        async def _revoke_then_fail(request: httpx.Request) -> httpx.Response:
            ticket.is_confidential = True
            await db_session.flush()
            return httpx.Response(500)

        smelt = PackageSmelt(
            maintained=_revoke_then_fail,
            maintainership=reply(200, maintainership()),
        )

        with pytest.raises(SmeltUnavailableError):
            await add(
                db_session,
                ticket.id,
                PKG,
                smelt,
                actor=caller,
                scope=Scope.NON_CONFIDENTIAL,
            )

        assert smelt.kinds == ["maintained"]


# ---------------------------------------------------------------------------
# Target resolution (package-model.md, SMELT Query for Package Resolution:
# Entry validation, Consumed fields, Processing 4-7, partial warning;
# package-service.md step 6)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTargetResolution:
    """The Ticket is an assigned `Analysis` Ticket and the call is user-
    attributed by its assignee, so no other warning or event occurs."""

    @staticmethod
    async def _setup(
        ticket_factory: TicketFactory, va_user: VAUser
    ) -> tuple[User, Ticket]:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        return actor, ticket

    async def test_partial_resolution_logs_one_warning_with_unmatched_cpes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unmatched CPEs are ignored; a codestream without a match creates
        no track; the single warning lists the distinct unmatched CPEs in
        first-seen order across codestreams and carries nothing else."""
        actor, ticket = await self._setup(ticket_factory, va_user)
        m1, m2, m3 = await _current(db_session, 3)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", m1.cpe, ABSENT_1, m2.cpe, ABSENT_2),
            codestream(GIT_REF, "SLFO", ABSENT_2, ABSENT_3, m3.cpe),
            codestream(IBS_REF_2, "SLE_15", ABSENT_1),
        )
        records = Spy(monkeypatch, "add_package_records")

        with capture_logs() as logs:
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert logs == [
            {
                "event": PARTIAL_RESOLUTION_EVENT,
                "log_level": "warning",
                "package_name": PKG,
                "unmatched_cpes": [ABSENT_1, ABSENT_2, ABSENT_3],
            }
        ]
        assert list(records.calls[0][1]["tracks"]) == [
            ResolvedTrackData(IBS_REF, WorkflowType.IBS, (m1.id, m2.id)),
            ResolvedTrackData(GIT_REF, WorkflowType.GIT, (m3.id,)),
        ]
        assert outcome(result) == changed(2, 0, 3, 0)
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {
                IBS_REF: NEW_TRACK[WorkflowType.IBS],
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, m1.id): new_occurrence(True),
                (IBS_REF, m2.id): new_occurrence(True),
                (GIT_REF, m3.id): new_occurrence(True),
            },
        )

    async def test_full_match_logs_nothing(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor, ticket = await self._setup(ticket_factory, va_user)
        p1, p2 = await _current(db_session, 2)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe))

        with capture_logs() as logs:
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(1, 0, 2, 0)
        assert logs == []

    async def test_exact_cpe_match_is_case_sensitive(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor, ticket = await self._setup(ticket_factory, va_user)
        (product,) = await _current(db_session)
        variant = product.cpe.upper()
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            codestream(IBS_REF_2, "SLE_15", variant),
        )

        with capture_logs() as logs:
            await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {(IBS_REF, product.id): new_occurrence(True)},
        )
        assert [log["unmatched_cpes"] for log in logs] == [[variant]]

    async def test_duplicate_cpes_within_a_codestream_collapse(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor, ticket = await self._setup(ticket_factory, va_user)
        p, q = await _current(db_session, 2)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p.cpe, p.cpe, q.cpe, p.cpe)
        )
        records = Spy(monkeypatch, "add_package_records")

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert list(records.calls[0][1]["tracks"]) == [
            ResolvedTrackData(IBS_REF, WorkflowType.IBS, (p.id, q.id))
        ]
        assert outcome(result) == changed(1, 0, 2, 0)

    async def test_same_cpe_under_two_codestreams_maps_each_workflow(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """One track per codestream; `SLE_15` persists `ibs` and `SLFO`
        persists `git`."""
        actor, ticket = await self._setup(ticket_factory, va_user)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            codestream(GIT_REF, "SLFO", product.cpe),
        )

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(2, 0, 2, 0)
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {
                IBS_REF: NEW_TRACK[WorkflowType.IBS],
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, product.id): new_occurrence(True),
                (GIT_REF, product.id): new_occurrence(True),
            },
        )

    async def test_skipped_codestreams_create_no_track_and_no_partial_warning(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """`SLFO_IBS` and `UNKNOWN` entries carrying a current CPE are
        skipped with their own warnings; their targets are neither matched
        nor reported as unmatched."""
        actor, ticket = await self._setup(ticket_factory, va_user)
        skipped, supported = await _current(db_session, 2)
        smelt = PackageSmelt.ok(
            codestream(SLFO_IBS_REF, "SLFO_IBS", skipped.cpe),
            codestream(IBS_REF, "SLE_15", supported.cpe),
            codestream(UNKNOWN_REF, "UNKNOWN", skipped.cpe),
        )

        with capture_logs() as logs:
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {(IBS_REF, supported.id): new_occurrence(True)},
        )
        assert _events(logs) == [UNSUPPORTED_PROCESS_EVENT, UNKNOWN_PROCESS_EVENT]

    async def test_historical_product_is_not_matched_while_a_current_one_is(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor, ticket = await self._setup(ticket_factory, va_user)
        historical = await _historical(db_session)
        wall_clock = await catalog_product(db_session)
        (current,) = await _current(db_session)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", historical.cpe, wall_clock.cpe, current.cpe)
        )

        with capture_logs() as logs:
            await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {(IBS_REF, current.id): new_occurrence(True)},
        )
        assert [log["unmatched_cpes"] for log in logs] == [
            [historical.cpe, wall_clock.cpe]
        ]


# ---------------------------------------------------------------------------
# Maintainership composition (package-maintainership.md, Acquisition
# Workflow > Invocation boundary; package-service.md step 7, Architectural
# Test Requirement: Maintainership acquisition)
# ---------------------------------------------------------------------------

MAINTAINERSHIP_FAILURES: dict[str, tuple[Respond, str]] = {
    "http-500": (
        reply(500, maintainership("maint.failed@example.com", MARKER)),
        "http_status",
    ),
    "transport": (
        fail(httpx.ConnectError(f"{MARKER} {SMELT_TEST_API_URL}")),
        "transport",
    ),
    "http-404-envelope": (
        reply(404, {"status": "error", "data": f"Package {MARKER} not found"}),
        "package_missing",
    ),
    "malformed-body": (
        reply(
            200,
            {
                "status": "success",
                "data": [
                    {
                        "codestream": {"name": MARKER},
                        "users": [
                            {"username": MARKER, "email": "maint.failed@example.com"}
                        ],
                        "groups": None,
                    }
                ],
            },
        ),
        "schema",
    ),
    "invalid-json": (
        lambda request: httpx.Response(200, content=MARKER.encode()),
        "envelope",
    ),
}
"""Maintainership responder and its expected warning `category`."""


@pytest.mark.integration
class TestMaintainership:
    async def test_exact_active_email_creates_an_association(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """SMELT emails are lowercased; only the exactly matching active
        User is associated, with one system `package_maintainer_added`."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        matched = await seed_user(db_session, email="maint.exact@example.com")
        await seed_user(db_session, email="maint.dormant@example.com", active=False)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=[
                "Maint.Exact@Example.COM",
                "maint.dormant@example.com",
                "maint.unknown@example.com",
                None,
            ],
        )

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await maintainers(db_session, ticket.id) == [(PKG, matched.id)]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, matched),
            package_added_event(PKG, actor),
        ]

    @pytest.mark.parametrize("case", list(MAINTAINERSHIP_FAILURES))
    async def test_failure_yields_no_association_and_the_tree_is_created(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        respond, category = MAINTAINERSHIP_FAILURES[case]
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        await seed_user(db_session, email="maint.failed@example.com")
        (product,) = await _current(db_session)
        smelt = PackageSmelt(
            maintained=reply(
                200, maintained(codestream(IBS_REF, "SLE_15", product.cpe))
            ),
            maintainership=respond,
        )
        records = Spy(monkeypatch, "add_package_records")

        with capture_logs() as logs:
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert smelt.kinds == BOTH
        assert records.calls[0][1]["maintainer_emails"] == frozenset()
        assert outcome(result) == changed(1, 0, 1, 0)
        assert await maintainers(db_session, ticket.id) == []
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]
        assert [(log["event"], log["category"]) for log in logs] == [
            (ACQUISITION_UNAVAILABLE_EVENT, category)
        ]
        rendered = repr(logs)
        for secret in ["maint.failed@example.com", MARKER, SMELT_HOST]:
            assert secret not in rendered

    @pytest.mark.parametrize("shape", ["ibs-only", "git-only", "mixed", "no-op"])
    async def test_every_resolved_invocation_requests_maintainership_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        shape: str,
    ) -> None:
        """Including a package-tree no-op, which still acquires a new
        association (`maintainer_only`)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        p1, p2 = await _current(db_session, 2)
        maintainer = await seed_user(db_session, email="maint.once@example.com")
        entries = {
            "ibs-only": [codestream(IBS_REF, "SLE_15", p1.cpe)],
            "git-only": [codestream(GIT_REF, "SLFO", p1.cpe)],
            "mixed": [
                codestream(IBS_REF, "SLE_15", p1.cpe),
                codestream(GIT_REF, "SLFO", p2.cpe),
            ],
            "no-op": [codestream(IBS_REF, "SLE_15", p1.cpe)],
        }[shape]
        if shape == "no-op":
            package = await seed_package(db_session, ticket.id, PKG)
            await seed_occurrence(
                db_session, await seed_track(db_session, package, IBS_REF), p1
            )
        smelt = PackageSmelt.ok(*entries, emails=["maint.once@example.com"])

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert smelt.kinds == BOTH
        assert result.outcome is (
            PackageRecordsOutcome.MAINTAINER_ONLY
            if shape == "no-op"
            else PackageRecordsOutcome.PACKAGE_TREE_CHANGED
        )
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]

    async def test_maintainer_only_outcome_keeps_counts_and_adds_no_field(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On an unassigned `Analysis` Ticket an active VA's association-
        only mutation neither assigns nor reconciles."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (product,) = await _current(db_session)
        package = await seed_package(db_session, ticket.id, PKG)
        await seed_occurrence(
            db_session, await seed_track(db_session, package, IBS_REF), product
        )
        maintainer = await seed_user(db_session, email="maint.only@example.com")
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=["maint.only@example.com"],
        )
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert result == AddPackageResult(
            outcome=PackageRecordsOutcome.MAINTAINER_ONLY,
            tracks_created=0,
            tracks_skipped=1,
            products_created=0,
            products_skipped=1,
            created_tracks=(),
        )
        assert [f.name for f in fields(result)] == [
            "outcome",
            "tracks_created",
            "tracks_skipped",
            "products_created",
            "products_skipped",
            "created_tracks",
        ]
        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS.value, None)
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer)
        ]


# ---------------------------------------------------------------------------
# Delegation and result (package-service.md steps 8 and 10; package-model.md,
# Adding Packages to a Ticket step 5; Interaction with add_package_to_ticket)
# ---------------------------------------------------------------------------

CONTEXTS: dict[str, tuple[PackageAddedComment | None, bool, bool]] = {
    "public": (None, False, False),
    "post-ingest": ("CVE package resolution", True, False),
    "backfill": ("Product catalog backfill", True, False),
    "convergence": ("Ticket convergence", False, True),
}
"""`(audit_comment, active_ticket_only, allow_excluded_reresolution)` of
each caller context (package-service.md, `add_package_to_ticket()`)."""

SHAPES: dict[str, list[tuple[str, str, WorkflowType, int]]] = {
    "ibs-only": [
        (IBS_REF, "SLE_15", WorkflowType.IBS, 2),
        (IBS_REF_2, "SLE_15", WorkflowType.IBS, 1),
    ],
    "git-only": [(GIT_REF, "SLFO", WorkflowType.GIT, 1)],
    "mixed": [
        (IBS_REF, "SLE_15", WorkflowType.IBS, 2),
        (GIT_REF, "SLFO", WorkflowType.GIT, 1),
    ],
}
"""`(codestream, maintenance process, workflow_type, Product count)`."""


@pytest.mark.integration
class TestDelegationAndResult:
    @pytest.mark.parametrize("context", list(CONTEXTS))
    async def test_parameters_reach_the_locked_boundary_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        comment, active_ticket_only, reresolution = CONTEXTS[context]
        assignee = await va_user()
        actor = assignee if context == "public" else None
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        p1, p2, p3 = await _current(db_session, 3)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
            emails=[
                "Maint.Delegate@Example.com",
                "maint.delegate@example.com",
                "maint.other@example.com",
            ],
        )
        records = Spy(monkeypatch, "add_package_records")

        result = await add(
            db_session,
            ticket.id,
            PKG,
            smelt,
            actor=actor,
            comment=comment or "CVE package resolution",
            active_ticket_only=active_ticket_only,
            reresolution=reresolution,
        )

        ((args, kwargs),) = records.calls
        assert args == (db_session,)
        assert list(kwargs.pop("tracks")) == [
            ResolvedTrackData(IBS_REF, WorkflowType.IBS, (p1.id, p2.id)),
            ResolvedTrackData(GIT_REF, WorkflowType.GIT, (p3.id,)),
        ]
        assert kwargs == {
            "ticket_id": ticket.id,
            "package_name": PKG,
            "maintainer_emails": frozenset(
                {"maint.delegate@example.com", "maint.other@example.com"}
            ),
            "acting_user_id": actor.id if actor else None,
            "caller": _consumer(actor) if actor else SYSTEM_INVOCATION,
            "audit_comment": comment,
            "active_ticket_only": active_ticket_only,
            "allow_excluded_reresolution": reresolution,
        }
        assert outcome(result) == changed(2, 0, 3, 0)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor, comment)
        ]

    @pytest.mark.parametrize("shape", list(SHAPES))
    async def test_result_reports_counts_and_created_tracks(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        shape: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        spec = SHAPES[shape]
        products = {ref: await _current(db_session, n) for ref, _, _, n in spec}
        smelt = PackageSmelt.ok(
            *(
                codestream(ref, process, *(p.cpe for p in products[ref]))
                for ref, process, _, _ in spec
            )
        )

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        ids = await track_ids(db_session, ticket.id, PKG)
        assert outcome(result) == changed(len(spec), 0, sum(n for *_, n in spec), 0)
        assert sorted(result.created_tracks, key=lambda c: c.reference) == sorted(
            (CreatedTrack(ids[ref], ref, wf) for ref, _, wf, _ in spec),
            key=lambda c: c.reference,
        )

    async def test_new_product_under_existing_track_reports_no_created_track(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        p1, p2 = await _current(db_session, 2)
        package = await seed_package(db_session, ticket.id, PKG)
        await seed_occurrence(
            db_session, await seed_track(db_session, package, IBS_REF), p1
        )
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe))

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(0, 1, 1, 1)
        assert result.created_tracks == ()

    @pytest.mark.parametrize(
        "comment", ["CVE package resolution", "Product catalog backfill"]
    )
    async def test_active_ticket_only_skip_follows_both_requests(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        comment: PackageAddedComment,
    ) -> None:
        ticket = await cveless(ticket_factory, status=RESOLVED)
        (product,) = await _current(db_session)
        await seed_user(db_session, email="maint.skipped@example.com")
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=["maint.skipped@example.com"],
        )

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add(
                db_session,
                ticket.id,
                PKG,
                smelt,
                comment=comment,
                active_ticket_only=True,
            ),
            ticket_ids=(ticket.id,),
        )

        assert result == SKIPPED
        assert smelt.kinds == BOTH

    async def test_convergence_completes_beneath_an_excluded_package(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Re-resolution mode creates the missing descendants and the
        association without clearing the package marker."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        p1, p2, p3 = await _current(db_session, 3)
        package = await seed_package(db_session, ticket.id, PKG, excluded=True)
        await seed_occurrence(
            db_session, await seed_track(db_session, package, IBS_REF), p1
        )
        maintainer = await seed_user(db_session, email="maint.converge@example.com")
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
            emails=["maint.converge@example.com"],
        )

        result = await add(
            db_session,
            ticket.id,
            PKG,
            smelt,
            comment="Ticket convergence",
            reresolution=True,
        )

        ids = await track_ids(db_session, ticket.id, PKG)
        assert outcome(result) == changed(1, 1, 2, 1)
        assert result.created_tracks == (
            CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),
        )
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            SEEDED_AT,
            {
                IBS_REF: NEW_TRACK[WorkflowType.IBS],
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, p1.id): new_occurrence(True),
                (IBS_REF, p2.id): new_occurrence(True),
                (GIT_REF, p3.id): new_occurrence(True),
            },
        )
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer),
            package_added_event(PKG, comment="Ticket convergence"),
        ]


# ---------------------------------------------------------------------------
# Idempotency (package-service.md, `add_package_to_ticket()` Idempotency;
# package-model.md, Adding Packages to a Ticket, Idempotency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdempotency:
    @pytest.mark.parametrize("context", ["user", "system"])
    async def test_repeat_with_unchanged_data_requests_again_and_changes_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=NEW)
        maintainer = await seed_user(db_session, email="maint.repeat@example.com")
        p1, p2, p3 = await _current(db_session, 3)
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
            emails=["maint.repeat@example.com"],
        )
        first = await add(db_session, ticket.id, PKG, smelt, actor=actor)
        assert outcome(first) == changed(2, 0, 3, 0)
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]

        second = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            ticket_ids=(ticket.id,),
        )

        assert smelt.kinds == BOTH * 2
        assert second == AddPackageResult(
            outcome=PackageRecordsOutcome.PACKAGE_TREE_NO_OP,
            tracks_created=0,
            tracks_skipped=2,
            products_created=0,
            products_skipped=3,
            created_tracks=(),
        )

    @pytest.mark.parametrize(
        ("case", "error"),
        [
            ("smelt-unavailable", SmeltUnavailableError),
            ("package-not-found", PackageNotFoundInSmeltError),
            ("targets-no-longer-current", PackageTargetsUnresolvedError),
        ],
    )
    async def test_repeat_can_fail_a_blocking_gate_without_touching_the_tree(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        error: type[Exception],
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        first = await add(db_session, ticket.id, PKG, smelt, actor=actor)
        assert outcome(first) == changed(1, 0, 1, 0)
        if case == "smelt-unavailable":
            smelt.responses["maintained"] = reply(500, {})
        elif case == "package-not-found":
            smelt.responses["maintained"] = reply(404, not_found(PKG))
        else:
            # A newer snapshot no longer contains the Product.
            await publish(
                db_session,
                await catalog_product(db_session),
                at=SNAPSHOT_AT + timedelta(days=1),
            )

        await _assert_blocked(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            smelt=smelt,
            error=error,
            kinds=[*BOTH, "maintained"],
            ticket_ids=(ticket.id,),
        )


# ---------------------------------------------------------------------------
# Convergence registration and auto-assignment through the orchestrator
# (package-service.md, Auto-Assignment Rule; ticket-mutations.md,
# `reconcile_ticket_status()` step 5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConvergenceRegistration:
    async def test_new_analysis_track_regresses_resolved_and_registers_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=RESOLVED, assignee_id=actor.id)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS.value, actor.id)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor),
            status_event(RESOLVED, ANALYSIS),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_no_op_on_a_resolved_ticket_registers_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=RESOLVED, assignee_id=actor.id)
        (product,) = await _current(db_session)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(
            db_session, package, IBS_REF, status=PackageStatus.NOT_AFFECTED
        )
        await seed_occurrence(db_session, track, product)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add(db_session, ticket.id, PKG, smelt, actor=actor),
            ticket_ids=(ticket.id,),
        )

        assert result is not None
        assert result.outcome is PackageRecordsOutcome.PACKAGE_TREE_NO_OP


@pytest.mark.integration
class TestAutoAssignment:
    async def test_user_attributed_creation_assigns_the_active_va(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert await ticket_row(db_session, ticket.id) == (ANALYSIS.value, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            package_added_event(PKG, actor),
        ]

    async def test_system_creation_never_assigns(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))

        await add(db_session, ticket.id, PKG, smelt, comment="CVE package resolution")

        assert await ticket_row(db_session, ticket.id) == (ANALYSIS.value, None)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, comment="CVE package resolution")
        ]

    # The maintainer-only case is
    # `TestMaintainership.test_maintainer_only_outcome_keeps_counts_and_adds_no_field`.


# ---------------------------------------------------------------------------
# Privacy and the I/O-then-Lock boundary (package-service.md, Module
# invariant: I/O-then-Lock pattern, `add_package_to_ticket()` Q3;
# package-maintainership.md, Security and Privacy; product-catalog.md,
# Catalog Readiness and Freshness)
# ---------------------------------------------------------------------------


MAINTAINED_PRIVATE_FAILURES: dict[str, tuple[Respond, type[Exception]]] = {
    "http-500-body": (
        reply(500, {"status": "error", "data": MARKER}),
        SmeltUnavailableError,
    ),
    "schema-invalid-body": (
        reply(
            200,
            maintained({"codestream": {"name": MARKER, "type": "INVALID"}}),
        ),
        SmeltUnavailableError,
    ),
    "transport-message": (
        fail(httpx.ConnectError(f"{MARKER} {SMELT_TEST_API_URL}")),
        SmeltUnavailableError,
    ),
    "http-404-message": (
        reply(404, {"status": "error", "data": MARKER}),
        PackageNotFoundInSmeltError,
    ),
}
"""Maintained responders carrying `MARKER`, and the expected exception."""


@pytest.mark.integration
class TestPrivacy:
    @pytest.mark.parametrize("case", list(MAINTAINED_PRIVATE_FAILURES))
    async def test_blocking_failure_discloses_no_body_url_or_exception_text(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        case: str,
    ) -> None:
        respond, error = MAINTAINED_PRIVATE_FAILURES[case]
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _current(db_session)
        smelt = PackageSmelt(
            maintained=respond, maintainership=reply(200, maintainership())
        )

        with capture_logs() as logs, pytest.raises(error) as raised:
            await add(db_session, ticket.id, PKG, smelt, actor=actor)

        exception = raised.value
        assert exception.__cause__ is None
        disclosed = [repr(logs), str(exception), repr(exception)]
        if isinstance(exception, SmeltUnavailableError):
            assert exception.__suppress_context__ is True
            disclosed.append(repr(exception.__context__))
        for text in disclosed:
            assert MARKER not in text
            assert SMELT_HOST not in text

    async def test_successful_call_logs_no_email_username_or_url(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """The skip and partial-resolution warnings of the same invocation
        prove that logs are captured."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        matched = await seed_user(db_session, email="maint.logged@example.com")
        inactive = await seed_user(
            db_session, email="maint.dormant.log@example.com", active=False
        )
        (product,) = await _current(db_session)
        emails = [
            "maint.logged@example.com",
            "maint.dormant.log@example.com",
            "maint.unknown.log@example.com",
        ]
        smelt = PackageSmelt.ok(
            codestream(SLFO_IBS_REF, "SLFO_IBS", product.cpe),
            codestream(IBS_REF, "SLE_15", product.cpe, ABSENT_1),
            emails=emails,
        )

        with capture_logs() as logs:
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await maintainers(db_session, ticket.id) == [(PKG, matched.id)]
        assert _events(logs) == [UNSUPPORTED_PROCESS_EVENT, PARTIAL_RESOLUTION_EVENT]
        rendered = repr(logs)
        for secret in [
            *emails,
            "maintainer-1",
            matched.username,
            inactive.username,
            actor.username,
            actor.email,
            SMELT_HOST,
        ]:
            assert secret not in rendered


@pytest.mark.integration
class TestIOThenLock:
    @pytest.mark.parametrize("context", ["user", "system"])
    async def test_no_lock_before_or_during_the_external_phase(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        """Before the first SMELT request only the consumer's single lock-
        free preliminary read runs (none for a system call); the
        orchestrator's own catalog reads are lock-free; every row lock
        belongs to the delegated boundary, entered after maintainership.
        No Redis, broker, or post-commit callback work occurs."""
        brokered: list[str] = []

        async def _redis(*args: Any, **kwargs: Any) -> Any:
            brokered.append("redis")
            raise AssertionError("add_package_to_ticket() must perform no Redis I/O")

        def _broker(*args: Any, **kwargs: Any) -> Any:
            brokered.append("broker")
            raise AssertionError("add_package_to_ticket() must not dispatch a task")

        monkeypatch.setattr(Redis, "execute_command", _redis)
        monkeypatch.setattr(Celery, "send_task", _broker)
        monkeypatch.setattr(Task, "apply_async", _broker)
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=NEW)
        await seed_user(db_session, email="maint.timeline@example.com")
        p1, p2 = await _current(db_session, 2)
        events: list[tuple[str, str]] = []
        smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe),
            codestream(GIT_REF, "SLFO", p2.cpe),
            emails=["maint.timeline@example.com"],
            events=events,
        )
        original = package_service.add_package_records

        async def _records(*args: Any, **kwargs: Any) -> AddPackageResult:
            events.append(("enter", "add_package_records"))
            return await original(*args, **kwargs)

        monkeypatch.setattr(package_service, "add_package_records", _records)

        with _Timeline(db_session, events):
            result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert outcome(result) == changed(2, 0, 2, 0)
        assert [e for e in events if e[0] != "sql"] == [
            ("http", "maintained"),
            ("http", "maintainership"),
            ("enter", "add_package_records"),
        ]
        first_request = events.index(("http", "maintained"))
        entered = events.index(("enter", "add_package_records"))
        before_io = [text for kind, text in events[:first_request] if kind == "sql"]
        assert len(before_io) == (1 if context == "user" else 0)
        orchestrator = [text for kind, text in events[:entered] if kind == "sql"]
        assert orchestrator
        assert all(t.lstrip().upper().startswith("SELECT") for t in orchestrator)
        assert not any(m in t for t in orchestrator for m in LOCK_MARKERS)
        delegated = [text for kind, text in events[entered:] if kind == "sql"]
        assert any(m in t for t in delegated for m in LOCK_MARKERS)
        assert brokered == []
        assert not db_session.info.get("post_commit_callbacks")


# ---------------------------------------------------------------------------
# HTTP client lifecycle (issue #783 decision E8; package-service.md,
# `add_package_to_ticket()` Q1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHttpClientLifecycle:
    async def test_own_client_is_created_once_and_closed_before_the_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        names = _patch_factory(monkeypatch, smelt)
        closed_at_entry: list[list[bool]] = []
        original = package_service.add_package_records

        async def _records(*args: Any, **kwargs: Any) -> AddPackageResult:
            closed_at_entry.append([client.is_closed for client in smelt.clients])
            return await original(*args, **kwargs)

        monkeypatch.setattr(package_service, "add_package_records", _records)

        result = await add_package_to_ticket(
            db_session,
            ticket_id=ticket.id,
            package_name=PKG,
            acting_user_id=actor.id,
            caller=_consumer(actor),
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        assert names == [HTTP_CLIENT_NAME]
        assert smelt.kinds == BOTH
        assert closed_at_entry == [[True]]

    @pytest.mark.parametrize(
        ("respond", "error"),
        [
            (reply(500, {}), SmeltUnavailableError),
            (reply(404, not_found(PKG)), PackageNotFoundInSmeltError),
        ],
        ids=["unavailable", "not-found"],
    )
    async def test_own_client_is_closed_when_a_blocking_error_escapes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        respond: Respond,
        error: type[Exception],
    ) -> None:
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        await _current(db_session)
        smelt = PackageSmelt(maintained=respond)
        names = _patch_factory(monkeypatch, smelt)

        with pytest.raises(error):
            await add_package_to_ticket(
                db_session,
                ticket_id=ticket.id,
                package_name=PKG,
                acting_user_id=None,
                caller=SYSTEM_INVOCATION,
                audit_comment="Ticket convergence",
                allow_excluded_reresolution=True,
            )

        assert names == [HTTP_CLIENT_NAME]
        assert [client.is_closed for client in smelt.clients] == [True]

    async def test_supplied_client_is_used_and_left_open(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory, status=ANALYSIS)
        (product,) = await _current(db_session)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        names = _patch_factory(monkeypatch, smelt)
        client = smelt.client()

        try:
            await add_package_to_ticket(
                db_session,
                ticket_id=ticket.id,
                package_name=PKG,
                acting_user_id=None,
                caller=SYSTEM_INVOCATION,
                audit_comment="CVE package resolution",
                http_client=client,
            )
            assert not client.is_closed
        finally:
            await client.aclose()

        assert names == []
        assert smelt.kinds == BOTH
