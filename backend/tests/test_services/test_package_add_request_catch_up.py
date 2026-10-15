"""Service integration tests for the package-add IBS request catch-up of
`package_service.add_package_to_ticket()` step 9
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`add_package_to_ticket()`
  steps 9-10, Idempotency, Error handling (Step 9); Architectural Test
  Requirement "Package-add request catch-up").
- docs/features/packages/package-model.md (Adding Packages to a Ticket,
  step 4).
- docs/features/packages/ibs-submission-tracking.md (Accelerators >
  Package Addition; Structured Logs: `ibs_request_catch_up_dispatch_failed`).
- docs/conventions.md (Caller-Owned Service Transactions; Transaction
  Hygiene Rules: a post-commit effect runs only after the owner's commit).
- docs/features/platform/testing-strategy.md (Service Functions; Audit
  Trail Testing: the publication path creates no event).

The orchestrator never commits, so each test acts as the caller-owned
transaction owner on `db_session`: it calls `add_package_to_ticket()`,
commits (a savepoint release rolled back at teardown), takes the
registered callbacks with `app.database.detach_post_commit_callbacks()`,
and awaits them, as the post-ingest and Product catalog backfill owners do.
The owners themselves (`get_db()`, post-ingest resolution, Product catalog
backfill, Ticket convergence) are tested in their own modules.

SMELT is the in-process `PackageSmelt` fake; `task_publication.publish_task`
is substituted by a recorder that can raise. Unless a test states
otherwise, a Ticket is CVE-less with `severity_manual = High` and the
call is a system invocation with the `CVE package resolution` comment.
Expected values are transcribed from the specifications
(`tests.support.package_addition.request_catch_up()`), never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from celery.exceptions import OperationalError as BrokerOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import TicketStatus, WorkflowType
from app.core.exceptions import TicketNotMutableError
from app.database import detach_post_commit_callbacks
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import package_service, task_publication
from app.services.package_service import (
    AddPackageResult,
    PackageAlreadyExcludedError,
    PackageRecordsOutcome,
)
from app.services.packages.sync_ibs_requests import SyncIbsRequests
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.package_addition import (
    REQUEST_CATCH_UP_FAILED,
    PackageSmelt,
    add,
    codestream,
    publish,
    request_catch_up,
    request_catch_up_failed,
)
from tests.support.package_records import (
    NEW_TRACK,
    SKIPPED,
    Tree,
    catalog_product,
    new_occurrence,
    package_added_event,
    package_tree,
    seed_occurrence,
    seed_package,
    seed_track,
    seed_user,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.ticket_mutations import (
    EVAL,
    TicketFactory,
    VAUser,
    cveless,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

Logs = list[MutableMapping[str, Any]]

PKG = "fictional-libexample"
IBS_REF = "Fictional:Product:15-SP7:Update"
IBS_REF_2 = "Fictional:Product:16.0:Update"
GIT_REF = "fictional/slfo-1.1"

MARKER = "fictional-private-marker-5c1e"
"""A private string carried by an injected publication error; it must never
reach a log."""

BROKER_URL = f"amqp://sentinel-user:{MARKER}@broker.example.test:5672//"
"""A fictional credential-bearing broker URL carried by the injected error."""

QUEUE = "fictional-ibs-requests"
"""A fictional queue name for the `SyncIbsRequests.queue` substitution."""


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


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call
    and then raising `error`, when set."""

    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})
        if self.error is not None:
            raise self.error


@pytest.fixture(autouse=True)
def published(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


async def _current(db: AsyncSession, count: int = 1) -> list[Product]:
    """`count` catalog Products published in the current snapshot."""
    products = [await catalog_product(db) for _ in range(count)]
    await publish(db, *products)
    return products


async def _audit_event_count(db: AsyncSession) -> int:
    count = (
        await db.execute(select(func.count()).select_from(TicketAuditEvent))
    ).scalar_one()
    return int(count)


def _catch_up_logs(logs: Logs) -> Logs:
    return [
        entry
        for entry in logs
        if entry["event"] in {REQUEST_CATCH_UP_FAILED, "post_commit_callback_failed"}
    ]


async def _committed_callback(
    db: AsyncSession, published: _Publish
) -> Callable[[], Awaitable[None]]:
    """Act as the transaction owner: no publication happened before the
    commit; commit; detach the one registered callback."""
    assert published.calls == []
    await db.commit()
    (callback,) = detach_post_commit_callbacks(db)
    assert published.calls == []
    return callback


async def _ibs_addition(
    db: AsyncSession, ticket_factory: TicketFactory
) -> tuple[uuid.UUID, Product, AddPackageResult]:
    """Add `PKG` with one new IBS track holding one current Product."""
    ticket = await cveless(ticket_factory)
    (product,) = await _current(db)
    smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
    result = await add(db, ticket.id, PKG, smelt)
    return ticket.id, product, result


# ---------------------------------------------------------------------------
# Registration and post-commit publication (step 9)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRegistration:
    @pytest.mark.parametrize(
        "ibs_tracks", [pytest.param(1, id="one-ibs"), pytest.param(2, id="two-ibs")]
    )
    async def test_new_ibs_tracks_register_one_callback_publishing_one_catch_up(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        published: _Publish,
        ibs_tracks: int,
    ) -> None:
        """A user-facing addition creates `ibs_tracks` IBS tracks and one Git
        track. Nothing is published by the call or the commit; exactly one
        callback is registered, and running it after the commit publishes
        exactly one generic `run_catch_up` for `sync_ibs_requests` and the
        Ticket with the default queue, and nothing else. The publication
        creates no audit event: only the delegated `package_added` exists."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        products = await _current(db_session, 3)
        ibs_refs = [IBS_REF, IBS_REF_2][:ibs_tracks]
        smelt = PackageSmelt.ok(
            *[
                codestream(ref, "SLE_15", product.cpe)
                for ref, product in zip(ibs_refs, products[:ibs_tracks], strict=True)
            ],
            codestream(GIT_REF, "SLFO", products[2].cpe),
        )

        result = await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert result.outcome is PackageRecordsOutcome.PACKAGE_TREE_CHANGED
        assert sorted(t.workflow_type for t in result.created_tracks) == sorted(
            [WorkflowType.IBS] * ibs_tracks + [WorkflowType.GIT]
        )
        callback = await _committed_callback(db_session, published)
        events_before = await _audit_event_count(db_session)

        with capture_logs() as logs:
            await callback()

        assert published.calls == [request_catch_up(ticket.id)]
        assert [call["task_name"] for call in published.calls] == ["run_catch_up"]
        assert await _audit_event_count(db_session) == events_before
        assert await ticket_events_by_id(db_session, ticket.id) == [
            package_added_event(PKG, actor)
        ]
        assert _catch_up_logs(logs) == []

    async def test_queue_comes_from_the_registered_fetcher_class(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        published: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The publication carries `SyncIbsRequests.queue`, here a fictional
        queue name instead of the default `None`."""
        monkeypatch.setattr(SyncIbsRequests, "queue", QUEUE)
        ticket_id, _product, _result = await _ibs_addition(db_session, ticket_factory)
        callback = await _committed_callback(db_session, published)

        await callback()

        assert published.calls == [request_catch_up(ticket_id, QUEUE)]

    @pytest.mark.parametrize(
        "case", ["product-only", "git-only", "maintainer-only", "no-op", "inactive"]
    )
    async def test_outcome_without_a_new_ibs_track_registers_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        published: _Publish,
        case: str,
    ) -> None:
        """A Product added below an existing IBS track, a Git-track-only
        creation, a maintainer-only mutation, a complete no-op repeat, and
        the `active_ticket_only` skip of a `Resolved` Ticket register no
        callback and publish nothing, even after the commit."""
        inactive = case == "inactive"
        status = TicketStatus.RESOLVED if inactive else TicketStatus.ANALYSIS
        ticket = await cveless(ticket_factory, status=status)
        p1, p2 = await _current(db_session, 2)
        if case in {"product-only", "maintainer-only", "no-op"}:
            package = await seed_package(db_session, ticket.id, PKG)
            await seed_occurrence(
                db_session, await seed_track(db_session, package, IBS_REF), p1
            )
        emails: list[str] = []
        if case == "maintainer-only":
            await seed_user(db_session, email="maint.catchup@example.com")
            emails.append("maint.catchup@example.com")
        entry = {
            "product-only": codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            "git-only": codestream(GIT_REF, "SLFO", p1.cpe),
            "maintainer-only": codestream(IBS_REF, "SLE_15", p1.cpe),
            "no-op": codestream(IBS_REF, "SLE_15", p1.cpe),
            "inactive": codestream(IBS_REF, "SLE_15", p1.cpe),
        }[case]
        smelt = PackageSmelt.ok(entry, emails=emails)

        result = await add(
            db_session, ticket.id, PKG, smelt, active_ticket_only=inactive
        )

        expected_outcome = {
            "product-only": PackageRecordsOutcome.PACKAGE_TREE_CHANGED,
            "git-only": PackageRecordsOutcome.PACKAGE_TREE_CHANGED,
            "maintainer-only": PackageRecordsOutcome.MAINTAINER_ONLY,
            "no-op": PackageRecordsOutcome.PACKAGE_TREE_NO_OP,
            "inactive": PackageRecordsOutcome.ACTIVE_TICKET_ONLY_SKIPPED,
        }[case]
        assert result.outcome is expected_outcome
        if inactive:
            assert result == SKIPPED
        await db_session.commit()
        assert detach_post_commit_callbacks(db_session) == []
        assert published.calls == []

    @pytest.mark.parametrize("case", ["already-excluded", "not-mutable"])
    async def test_raising_call_registers_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        published: _Publish,
        case: str,
    ) -> None:
        """A public addition that would create a new IBS track raises
        `PackageAlreadyExcludedError` (a directly excluded package) or
        `TicketNotMutableError` (an `Ignored` Ticket) under the lock: no
        callback is registered and nothing is published."""
        actor = await va_user()
        not_mutable = case == "not-mutable"
        status = TicketStatus.IGNORED if not_mutable else TicketStatus.ANALYSIS
        ticket = await cveless(ticket_factory, status=status)
        (product,) = await _current(db_session)
        if case == "already-excluded":
            await seed_package(db_session, ticket.id, PKG, excluded=True)
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        error = TicketNotMutableError if not_mutable else PackageAlreadyExcludedError

        with pytest.raises(error):
            await add(db_session, ticket.id, PKG, smelt, actor=actor)

        assert detach_post_commit_callbacks(db_session) == []
        assert published.calls == []

    async def test_nothing_is_published_before_commit_or_after_a_rollback(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        published: _Publish,
    ) -> None:
        """The call registers its callback but publishes nothing itself; a
        caller that rolls back instead of committing publishes nothing and
        leaves no package tree."""
        ticket_id, _product, result = await _ibs_addition(db_session, ticket_factory)

        assert result.outcome is PackageRecordsOutcome.PACKAGE_TREE_CHANGED
        assert published.calls == []

        await db_session.rollback()

        assert published.calls == []
        assert await package_tree(db_session, ticket_id, PKG) is None


# ---------------------------------------------------------------------------
# Best-effort publication (Error handling (Step 9); Structured Logs)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBestEffortPublication:
    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: BrokerOperationalError(f"{BROKER_URL} connection refused"),
                id="broker-operational",
            ),
            pytest.param(lambda: RuntimeError(MARKER), id="runtime"),
        ],
    )
    async def test_publication_failure_is_logged_once_and_absorbed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        published: _Publish,
        make_error: Callable[[], Exception],
    ) -> None:
        """The callback returns normally (no exception) after exactly one
        `ibs_request_catch_up_dispatch_failed` WARNING carrying only the
        Ticket UUID, the fetcher name, and the exception class (no
        `exc_info`, no exception text); the committed rows and events are
        unchanged and nothing is retried."""
        ticket_id, product, _result = await _ibs_addition(db_session, ticket_factory)
        callback = await _committed_callback(db_session, published)
        error = make_error()
        published.error = error
        events_before = await ticket_events_by_id(db_session, ticket_id)

        with capture_logs() as logs:
            await callback()

        assert published.calls == [request_catch_up(ticket_id)]
        assert _catch_up_logs(logs) == [
            request_catch_up_failed(ticket_id, type(error).__name__)
        ]
        assert MARKER not in repr(logs)
        assert "broker.example.test" not in repr(logs)
        assert await package_tree(db_session, ticket_id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {(IBS_REF, product.id): new_occurrence(True)},
        )
        assert await ticket_events_by_id(db_session, ticket_id) == events_before

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
            pytest.param(asyncio.CancelledError, id="cancelled"),
        ],
    )
    async def test_control_signal_propagates_unchanged_without_the_warning(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        published: _Publish,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """`SoftTimeLimitExceeded`, `MemoryError`, and cancellation raised by
        the publication escape the callback as the same object and are not
        logged as a failed catch-up publication."""
        ticket_id, _product, _result = await _ibs_addition(db_session, ticket_factory)
        callback = await _committed_callback(db_session, published)
        signal = make_signal()
        published.error = signal

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await callback()

        assert raised.value is signal
        assert published.calls == [request_catch_up(ticket_id)]
        assert _catch_up_logs(logs) == []
