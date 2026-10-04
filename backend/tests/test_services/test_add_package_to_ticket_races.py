"""Independent-session tests for the package addition orchestrator
`package_service.add_package_to_ticket()`
(backend/app/services/package_service.py): races across its external SMELT
phase.

Owning specifications:

- docs/features/packages/package-service.md (Module invariant:
  I/O-then-Lock pattern; `add_package_to_ticket()` steps 1-8, Public error
  precedence, Error handling; Concurrency Control, including the public-add
  outcomes; Architectural Test Requirement bullets "Atomic consumer
  accessibility" (external-I/O composition), "Concurrent direct mutations"
  (public add racing with exclusion or restore across the external I/O),
  "Maintainership acquisition" (concurrent calls serialize; external-error
  precedence after preliminary access loss; locked `TICKET_NOT_FOUND`
  after successful I/O), and "Package creation concurrency and result
  truth" (orchestrator level)).
- docs/features/packages/package-model.md (Interaction with
  add_package_to_ticket; Adding Packages to a Ticket, public precedence
  2-11).
- docs/features/packages/package-maintainership.md (Acquisition Workflow >
  Invocation boundary: neither request under a lock; Confidential Ticket
  Visibility; Security and Privacy: fetched, unpersisted maintainer data
  cannot authorize the same invocation; Testing Requirements).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Ticket Accessibility: Locked mutations, External
  I/O and post-commit effects).

The single-session behavior of the orchestrator is covered by
`tests/test_services/test_add_package_to_ticket.py`, and the races of its
locked boundary `add_package_records()` (root lock order, serialized
creation, `active_ticket_only`, re-resolution, and access losses before
the lock) by `tests/test_services/test_add_package_records_atomicity.py`.
This module adds only what exists at the orchestrator level: an
independent session acting while the call is deterministically paused
inside one of its two SMELT requests (a `Pause` of the `PackageSmelt`
fake, held inside the transport handler):

- no row lock is held during either request, for a user-attributed and a
  system call;
- a consumer's access lost during the I/O, followed by a blocking
  external failure, keeps the external error without another Ticket
  lookup; followed by successful I/O, the locked-current check raises
  `TicketNotFoundError` with zero local effects, even when SMELT returns
  the caller's own email;
- a public-mode add (`allow_excluded_reresolution = False`) racing with a
  package, track, or Product exclusion or restore committed during the
  I/O;
- two calls paused in SMELT that then serialize on the Ticket lock.

Every racing operation commits while the call is still paused (its
request arrived and has not been released); only the serialization case
also proves a lock wait (`assert_lock_wait`). Unless a test states
otherwise: `SMELT_API_URL` is the fictional test origin; SMELT returns an
`SLE_15` (`ibs`) codestream for the expected CPEs and a valid
maintainership response; each Ticket is the pinned unassigned CVE-less
`Analysis` Ticket of `tests/support/package_records_races.py` with
`severity_manual = High`; every Product expected to match is published in
the current catalog snapshot (`SNAPSHOT_AT`), is in General Support on the
controlled service date `EVAL`, and has a `NULL` threshold, so a created
occurrence is eligible; a consumer call uses an active VA with effective
scope `all`. Committed rows, including the `default_cvss_version` setting
the test schema lacks, are deleted explicitly at teardown
(testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import Role, Scope, Severity, WorkflowType
from app.core.exceptions import TicketNotFoundError
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    AddPackageResult,
    CreatedTrack,
    PackageAlreadyExcludedError,
    PackageNotFoundInSmeltError,
    PackageRecordsOutcome,
    PackageTargetsUnresolvedError,
    ProductCatalogNotReadyError,
    SmeltUnavailableError,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.database import assert_lock_wait
from tests.support.package_addition import (
    Kind,
    PackageSmelt,
    Pause,
    Respond,
    add,
    codestream,
    maintained,
    maintainership,
    not_found,
    publish,
    reply,
)
from tests.support.package_exclusion import (
    MARKER_NOW,
    Direction,
    Level,
    committed_path,
    markers_by_id,
    patch_marker_now,
    path_call,
    path_event,
    with_target,
)
from tests.support.package_records import (
    NEW_TRACK,
    Tree,
    changed,
    maintainer_event,
    new_occurrence,
    outcome,
    package_added_event,
    track_ids,
)
from tests.support.package_records_races import (
    ANALYSIS,
    CVE_RESOLUTION,
    EXPECTED_OUTCOME,
    GIT_REF,
    IBS_REF,
    KINDS,
    LOSSES,
    WAIT,
    CommittedState,
    Factory,
    MarkerWorld,
    assert_denied_without_effects,
    committed_state,
    committed_world,
    existing_package,
    marker_world,
    path_tree,
    pinned_ticket,
    product_of,
    protected_state,
    sessions_of,
    tree_events,
    with_new_rows,
    world_product,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss import assignment_event
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import EVAL, StatementRecorder
from tests.support.track_status import Spy

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
"""A statement that reads, locks, or writes the `ticket` table itself."""

ABSENT = "cpe:/o:example:absent:1"
"""A CPE that no catalog Product carries."""

BOTH = ["maintained", "maintainership"]
"""The two SMELT requests of an invocation whose targets resolved."""

CONTEXTS = pytest.mark.parametrize("context", ["user", "system"])
PAUSES = pytest.mark.parametrize("pause_at", ["maintained", "maintainership"])


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every creation reads."""
    async with committed_world(db_session_factory) as created:
        yield created


@pytest.fixture(autouse=True)
def _clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """In every session, the service's UTC date is `EVAL` and an exclusion
    sets its marker to `MARKER_NOW`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    patch_marker_now(monkeypatch)


@pytest.fixture(autouse=True)
def _smelt_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both SMELT clients build their URLs from the fictional test origin."""
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _name() -> str:
    return f"fictional-librace-{uuid.uuid4().hex[:10]}"


async def _publish(world: CommittedWorld, *product_ids: uuid.UUID) -> None:
    """Commit the given catalog Products into the current snapshot."""
    products: list[Product] = []
    for product_id in product_ids:
        product = await world.session.get(Product, product_id)
        assert product is not None
        products.append(product)
    await publish(world.session, *products)
    await world.session.commit()


async def _current_product(world: CommittedWorld) -> Product:
    """A committed catalog Product published in the current snapshot."""
    product = await world_product(world)
    await _publish(world, product.id)
    return product


async def _product_count(world: CommittedWorld) -> int:
    probe = await world.open_session()
    count = (
        await probe.execute(select(func.count()).select_from(Product))
    ).scalar_one()
    await probe.rollback()
    return count


async def _track_ids(
    world: CommittedWorld, ticket_id: uuid.UUID, package_name: str
) -> dict[str, uuid.UUID]:
    probe = await world.open_session()
    ids = await track_ids(probe, ticket_id, package_name)
    await probe.rollback()
    return ids


@dataclasses.dataclass(slots=True)
class _Paused:
    """A call held inside its paused SMELT request, and the statements of
    its own session."""

    task: asyncio.Task[AddPackageResult]
    pause: Pause
    recorder: StatementRecorder

    async def finish(self) -> AddPackageResult:
        """Release the request and await the call's result or error."""
        self.pause.release.set()
        return await asyncio.wait_for(self.task, timeout=WAIT)


async def _arrive(pause: Pause, task: asyncio.Task[Any]) -> None:
    """Wait until the request reaches the fake; fail with the call's own
    error if it finishes first."""
    arrived = asyncio.ensure_future(pause.arrived.wait())
    try:
        await asyncio.wait(
            {arrived, task}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        arrived.cancel()
    if task.done():
        task.result()
        raise AssertionError("the call finished before its paused SMELT request")
    assert pause.arrived.is_set(), "the call never reached its SMELT request"


@asynccontextmanager
async def _paused(
    world: CommittedWorld,
    session: AsyncSession,
    smelt: PackageSmelt,
    kind: Kind,
    call: Coroutine[Any, Any, AddPackageResult],
) -> AsyncIterator[_Paused]:
    """Start `call` on `session` with the `kind` request paused and yield
    once it is held there; the call holds no row lock at that point. The
    request is released on exit at the latest."""
    pause = smelt.pause(kind)
    with SessionStatementRecorder(session) as recorder:
        task = world.start(session, call)
        try:
            await _arrive(pause, task)
            assert recorder.row_locks() == []
            yield _Paused(task, pause, recorder)
        finally:
            pause.release.set()


async def _commit_during(
    world: CommittedWorld,
    paused: _Paused,
    session: AsyncSession,
    work: Coroutine[Any, Any, Any],
) -> None:
    """Run `work` on the independent `session` and commit it within the
    bounded wait, while the call stays held in its request."""

    async def run() -> None:
        await work
        await session.commit()

    await asyncio.wait_for(world.start(session, run()), timeout=WAIT)
    assert not paused.pause.release.is_set()
    assert not paused.task.done()


async def _execute(session: AsyncSession, statements: list[Any]) -> None:
    for statement in statements:
        await session.execute(statement)


# ---------------------------------------------------------------------------
# No lock during the external phase (testing-strategy.md, Ticket
# Accessibility: External I/O and post-commit effects; package-service.md,
# Module invariant: I/O-then-Lock pattern; package-maintainership.md,
# Invocation boundary)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoLockDuringExternalIO:
    @CONTEXTS
    @PAUSES
    async def test_independent_session_locks_and_writes_the_ticket_while_paused(
        self, world: CommittedWorld, pause_at: Kind, context: str
    ) -> None:
        """While the call waits on either SMELT request, B takes the Ticket
        `FOR UPDATE` and, for a user-attributed call, the acting User
        `FOR NO KEY UPDATE` (the lifecycle writer lock that conflicts with
        the call's later `FOR SHARE`), writes the Ticket, and commits
        within the bounded wait. Released, the call creates the tree
        normally and takes its first row lock only then."""
        actor = (
            await world.user(role=Role.VULNERABILITY_ANALYST)
            if context == "user"
            else None
        )
        ticket = await pinned_ticket(world)
        product = await _current_product(world)
        pkg = _name()
        smelt = PackageSmelt.ok(codestream(IBS_REF, "SLE_15", product.cpe))
        a = await world.open_session()
        b = await world.open_session()

        async def hold_and_write() -> None:
            await b.execute(
                select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
            )
            if actor is not None:
                await b.execute(
                    select(User.id)
                    .where(User.id == actor.id)
                    .with_for_update(key_share=True)
                )
            await b.execute(
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(severity_manual=Severity.HIGH.value)
            )

        async with _paused(
            world,
            a,
            smelt,
            pause_at,
            add(a, ticket.id, pkg, smelt, actor=actor),
        ) as call:
            await _commit_during(world, call, b, hold_and_write())
            assert call.recorder.row_locks() == []
            result = await call.finish()
        await a.commit()

        assert smelt.kinds == BOTH
        assert outcome(result) == changed(1, 0, 1, 0)
        assert await committed_state(world, ticket.id, pkg) == CommittedState(
            (ANALYSIS, actor.id if actor else None),
            (
                [assignment_event(actor), package_added_event(pkg, actor)]
                if actor
                else [package_added_event(pkg, None, CVE_RESOLUTION)]
            ),
            Tree(
                None,
                {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
                {(IBS_REF, product.id): new_occurrence(True)},
            ),
            [],
        )


# ---------------------------------------------------------------------------
# Access lost during the external phase (testing-strategy.md, Ticket
# Accessibility: External I/O and post-commit effects, Locked mutations;
# package-service.md, Public error precedence; package-model.md, Adding
# Packages to a Ticket)
# ---------------------------------------------------------------------------

FAILURES: dict[str, tuple[type[Exception], Callable[[str], Respond]]] = {
    "smelt-unavailable": (
        SmeltUnavailableError,
        lambda pkg: reply(500, {"status": "error", "data": "Internal error"}),
    ),
    "catalog-not-ready": (
        ProductCatalogNotReadyError,
        lambda pkg: reply(200, maintained(codestream(IBS_REF, "SLE_15", ABSENT))),
    ),
    "package-not-found": (
        PackageNotFoundInSmeltError,
        lambda pkg: reply(404, not_found(pkg)),
    ),
    "targets-unresolved": (
        PackageTargetsUnresolvedError,
        lambda pkg: reply(200, maintained(codestream(IBS_REF, "SLE_15", ABSENT))),
    ),
}
"""The blocking failures after the maintained request, with its responder
for a package name. `catalog-not-ready` runs with no Product at all; the
others with one current Product that the response does not name."""

REQUESTS = ["would-create", "existing-tree", "existing-tree-own-email"]
"""The caller's request, each of which would otherwise reach a different
locked decision. `would-create`: a new package tree, with the caller's own
email in the maintainership response (a package-tree change that would
make the caller its maintainer). `existing-tree`: exactly a committed
tree, no email (a package-tree no-op; for `last-package-excluded` the tree
lies under the excluded maintained package, a would-be
`PackageAlreadyExcludedError`). `existing-tree-own-email`: the same with
the caller's own email (a would-be maintainer-only mutation, or the
excluded-package guard)."""


@pytest.mark.integration
class TestAccessLostDuringExternalIO:
    """A `restricted_analyst` caller (effective scope `non_confidential`)
    can access the Ticket through exactly one path, so its preliminary
    read passes. While its call is paused in SMELT, B removes that path
    and commits."""

    @pytest.mark.parametrize("failure", list(FAILURES))
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_external_failure_keeps_its_error_without_another_lookup(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        failure: str,
    ) -> None:
        """The maintained phase then fails: the documented external error
        is raised, not `TicketNotFoundError`. The only Ticket statement is
        the preliminary read; no maintainership request, row lock, write,
        delegation, assignment, reconciliation, or convergence
        registration occurs."""
        error, respond = FAILURES[failure]
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        pkg = _name()
        if failure == "catalog-not-ready":
            assert await _product_count(world) == 0
        else:
            await _current_product(world)
        smelt = PackageSmelt(
            maintained=respond(pkg),
            maintainership=reply(200, maintainership(user.email)),
        )
        before = await protected_state(world, ticket.id)
        records = Spy(monkeypatch, "add_package_records")
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        async with _paused(
            world,
            a,
            smelt,
            "maintained",
            add(a, ticket.id, pkg, smelt, actor=user, scope=Scope.NON_CONFIDENTIAL),
        ) as call:
            preliminary = list(call.recorder.statements)
            await _commit_during(world, call, b, _execute(b, statements))
            with pytest.raises(error):
                await call.finish()

        recorded = call.recorder.statements
        assert len(preliminary) == 1
        assert TICKET_STATEMENT.search(preliminary[0])
        assert [s for s in recorded if TICKET_STATEMENT.search(s)] == preliminary
        assert smelt.kinds == ["maintained"]
        assert call.recorder.row_locks() == []
        assert_denied_without_effects(call.recorder, a, assign, reconcile)
        assert records.calls == []
        await a.rollback()
        assert await protected_state(world, ticket.id) == before

    @PAUSES
    @pytest.mark.parametrize("request_kind", REQUESTS)
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_successful_io_is_denied_by_the_locked_check(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        request_kind: str,
        pause_at: Kind,
    ) -> None:
        """Both requests then succeed, with the caller's own email where the
        request names it. The delegated boundary raises `TicketNotFoundError`
        from the locked-current state before any operability,
        excluded-package, no-op, idempotency, or maintainer-match decision,
        with zero write, association, event, assignment, reconciliation,
        or convergence registration: the fetched but unpersisted
        maintainer data cannot authorize the invocation."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        if request_kind.startswith("existing-tree"):
            path = await committed_path(
                world, ticket, package_id=await existing_package(world, ticket)
            )
            await _publish(world, await product_of(world, path))
            pkg = path.subject["package"]
            entry = codestream(
                path.subject["track"], "SLE_15", path.subject["product_cpe"]
            )
        else:
            product = await _current_product(world)
            pkg = _name()
            entry = codestream(IBS_REF, "SLE_15", product.cpe)
        emails = [] if request_kind == "existing-tree" else [user.email]
        smelt = PackageSmelt.ok(entry, emails=emails)
        before = await protected_state(world, ticket.id)
        records = Spy(monkeypatch, "add_package_records")
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        async with _paused(
            world,
            a,
            smelt,
            pause_at,
            add(a, ticket.id, pkg, smelt, actor=user, scope=Scope.NON_CONFIDENTIAL),
        ) as call:
            await _commit_during(world, call, b, _execute(b, statements))
            with pytest.raises(TicketNotFoundError):
                await call.finish()

        assert smelt.kinds == BOTH
        assert len(records.calls) == 1
        assert_denied_without_effects(call.recorder, a, assign, reconcile)
        await a.rollback()
        assert await protected_state(world, ticket.id) == before
        state = await committed_state(world, ticket.id, pkg)
        assert (state.ticket, state.events) == ((ANALYSIS, None), [])
        if request_kind == "would-create":
            assert state.tree is None
        if loss == "last-package-excluded":
            assert state.maintainers == [("fictional-race-a", user.id)]


# ---------------------------------------------------------------------------
# Public add racing with exclusion or restore across the external phase
# (package-service.md, Concurrency Control; `add_package_to_ticket()` public
# semantics; Architectural Test Requirement: Concurrent direct mutations)
# ---------------------------------------------------------------------------


def _entries(kind: str, w: MarkerWorld) -> tuple[list[dict[str, Any]], list[str]]:
    """The SMELT data of `KINDS` on the committed path `T1: {P1}`."""
    reference = w.path.subject["track"]
    p1_cpe = w.path.subject["product_cpe"]
    if kind == "tree":
        return (
            [
                codestream(reference, "SLE_15", p1_cpe, w.p2.cpe),
                codestream(GIT_REF, "SLFO", w.p3.cpe),
            ],
            [w.m.email],
        )
    return (
        [codestream(reference, "SLE_15", p1_cpe)],
        [w.m.email] if kind == "maintainer-only" else [],
    )


async def _published_marker_world(
    world: CommittedWorld, *, seeded: Level | None = None, system: bool = False
) -> MarkerWorld:
    """A `MarkerWorld` whose Products P1, P2, and P3 are current."""
    w = await marker_world(world, seeded=seeded, system=system)
    await _publish(world, w.p1, w.p2.id, w.p3.id)
    return w


@pytest.mark.integration
class TestPublicAddRacingAcrossExternalIO:
    """B, the public-mode add (`allow_excluded_reresolution = False`; a
    consumer VA, or the system post-ingest mode), is paused in its
    maintainership request, so the maintained data and the emails are
    fetched. A, an active VA, changes a direct marker through the M2.4
    operation, which assigns the Ticket, and commits. B is then released
    and decides from the committed marker under its Ticket lock."""

    @CONTEXTS
    @pytest.mark.parametrize("kind", KINDS)
    async def test_add_after_an_exclusion_committed_during_io_is_rejected(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        context: str,
    ) -> None:
        """B raises `PackageAlreadyExcludedError` after both requests and
        before any local mutation, even though SMELT returned a matching
        active User's email or a tree to complete: no write, record,
        association, event, assignment, reconciliation, or convergence
        registration."""
        w = await _published_marker_world(world, system=context == "system")
        pkg = w.path.subject["package"]
        entries, emails = _entries(kind, w)
        smelt = PackageSmelt.ok(*entries, emails=emails)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        async with _paused(
            world,
            b,
            smelt,
            "maintainership",
            add(b, w.ticket.id, pkg, smelt, actor=w.actor_b),
        ) as call:
            await _commit_during(
                world,
                call,
                a,
                path_call(a, Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a),
            )
            with pytest.raises(PackageAlreadyExcludedError):
                await call.finish()

        assert smelt.kinds == BOTH
        assert call.recorder.writes() == []
        assert sessions_of(assign, 2) == [a]
        assert sessions_of(reconcile, 1) == [a]
        assert pending_ticket_convergence_effects(b) == ()
        await b.rollback()
        assert await committed_state(world, w.ticket.id, pkg) == CommittedState(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a),
            ],
            path_tree(
                w.path, package=MARKER_NOW, track=None, product=None, product_id=w.p1
            ),
            [],
        )

    @CONTEXTS
    @pytest.mark.parametrize("kind", KINDS)
    async def test_add_after_a_restore_committed_during_io_proceeds(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        context: str,
    ) -> None:
        """The package starts directly excluded, so B would be rejected;
        after A's restore commits during the I/O the guard no longer
        applies and B reaches its locked no-op, maintainer-only, or
        package-tree outcome."""
        w = await _published_marker_world(
            world, seeded=Level.PACKAGE, system=context == "system"
        )
        pkg = w.path.subject["package"]
        entries, emails = _entries(kind, w)
        smelt = PackageSmelt.ok(*entries, emails=emails)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        async with _paused(
            world,
            b,
            smelt,
            "maintainership",
            add(b, w.ticket.id, pkg, smelt, actor=w.actor_b),
        ) as call:
            await _commit_during(
                world,
                call,
                a,
                path_call(a, Level.PACKAGE, Direction.RESTORE, w.path, w.actor_a),
            )
            result = await call.finish()
        await b.commit()

        assert smelt.kinds == BOTH
        assert outcome(result) == EXPECTED_OUTCOME[kind]
        assert sessions_of(reconcile, 1) == ([a, b] if kind == "tree" else [a])
        assert await committed_state(world, w.ticket.id, pkg) == CommittedState(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(Level.PACKAGE, Direction.RESTORE, w.path, w.actor_a),
                *tree_events(kind, w),
            ],
            with_new_rows(
                path_tree(
                    w.path, package=None, track=None, product=None, product_id=w.p1
                ),
                kind,
                w,
            ),
            [(pkg, w.m.id)] if kind != "no-op" else [],
        )

    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    @pytest.mark.parametrize("level", [Level.TRACK, Level.PRODUCT], ids=str)
    async def test_add_racing_with_a_track_or_product_marker_proceeds(
        self,
        world: CommittedWorld,
        level: Level,
        direction: Direction,
    ) -> None:
        """Only the package's direct marker is a guard. After a track or
        Product exclusion or restore commits during the I/O, B completes
        the tree and adds M: the existing (possibly excluded) track and
        occurrence are skips, the new occurrence beneath an excluded track
        is created with `deleted_at = NULL`, and A's marker is left as
        committed."""
        restore = direction is Direction.RESTORE
        w = await _published_marker_world(world, seeded=level if restore else None)
        pkg = w.path.subject["package"]
        entries, emails = _entries("tree", w)
        smelt = PackageSmelt.ok(*entries, emails=emails)
        a = await world.open_session()
        b = await world.open_session()

        async with _paused(
            world,
            b,
            smelt,
            "maintainership",
            add(b, w.ticket.id, pkg, smelt, actor=w.actor_b),
        ) as call:
            await _commit_during(
                world,
                call,
                a,
                path_call(a, level, direction, w.path, w.actor_a),
            )
            result = await call.finish()
        await b.commit()

        assert outcome(result) == changed(1, 1, 2, 1)
        marker = None if restore else MARKER_NOW
        expected = with_target((None, None, None), level, marker)
        probe = await world.open_session()
        assert await markers_by_id(probe, w.path.id) == expected
        await probe.rollback()
        assert await committed_state(world, w.ticket.id, pkg) == CommittedState(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(level, direction, w.path, w.actor_a),
                *tree_events("tree", w),
            ],
            with_new_rows(
                path_tree(
                    w.path,
                    package=None,
                    track=expected[1],
                    product=expected[2],
                    product_id=w.p1,
                ),
                "tree",
                w,
            ),
            [(pkg, w.m.id)],
        )


# ---------------------------------------------------------------------------
# Two calls paused in SMELT, then serialized on the Ticket lock
# (package-service.md, Architectural Test Requirement: Package creation
# concurrency and result truth, Maintainership acquisition;
# package-maintainership.md, Testing Requirements: concurrent invocations)
# ---------------------------------------------------------------------------

SERIALIZED = ["no-op", "maintainer-only", "partial"]
"""The second call's SMELT data against the first call's `IBS_REF: {P1}`
with maintainer M1. `no-op`: the same tree and M1. `maintainer-only`: the
same tree with M1 and the extra M2. `partial`: `IBS_REF: {P1, P2}` plus a
new Git track `GIT_REF: {P3}`, with M1."""


@pytest.mark.integration
class TestConcurrentAdditions:
    @CONTEXTS
    @pytest.mark.parametrize("case", SERIALIZED)
    async def test_calls_paused_in_smelt_serialize_on_the_ticket_lock(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        context: str,
    ) -> None:
        """Both calls are held in their maintainership requests at once.
        The first is released and completes its locked creation, keeping
        its transaction open; the second, released next, is proven blocked
        on the Ticket lock, then reloads the committed first state and
        reports its rows truthfully as skips, creating no duplicate row or
        event."""
        first_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        second_actor = (
            await world.user(role=Role.VULNERABILITY_ANALYST)
            if context == "user"
            else None
        )
        m1 = await world.user(role=Role.RESTRICTED_ANALYST)
        m2 = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await pinned_ticket(world)
        p1, p2, p3 = [await _current_product(world) for _ in range(3)]
        pkg = _name()
        first_smelt = PackageSmelt.ok(
            codestream(IBS_REF, "SLE_15", p1.cpe), emails=[m1.email]
        )
        second_smelt = {
            "no-op": PackageSmelt.ok(
                codestream(IBS_REF, "SLE_15", p1.cpe), emails=[m1.email]
            ),
            "maintainer-only": PackageSmelt.ok(
                codestream(IBS_REF, "SLE_15", p1.cpe), emails=[m1.email, m2.email]
            ),
            "partial": PackageSmelt.ok(
                codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
                codestream(GIT_REF, "SLFO", p3.cpe),
                emails=[m1.email],
            ),
        }[case]
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        first = await world.open_session()
        second = await world.open_session()

        async with (
            _paused(
                world,
                first,
                first_smelt,
                "maintainership",
                add(first, ticket.id, pkg, first_smelt, actor=first_actor),
            ) as first_call,
            _paused(
                world,
                second,
                second_smelt,
                "maintainership",
                add(second, ticket.id, pkg, second_smelt, actor=second_actor),
            ) as second_call,
        ):
            first_result = await first_call.finish()
            second_call.pause.release.set()
            await assert_lock_wait(second_call.task, waiter=second, blocked_by=first)
            await first.commit()
            second_result = await asyncio.wait_for(second_call.task, timeout=WAIT)
        assert pending_ticket_convergence_effects(second) == ()
        await second.commit()

        partial = case == "partial"
        ids = await _track_ids(world, ticket.id, pkg)
        assert (first_smelt.kinds, second_smelt.kinds) == (BOTH, BOTH)
        assert outcome(first_result) == changed(1, 0, 1, 0)
        assert first_result.created_tracks == (
            CreatedTrack(ids[IBS_REF], IBS_REF, WorkflowType.IBS),
        )
        assert (
            outcome(second_result)
            == {
                "no-op": (PackageRecordsOutcome.PACKAGE_TREE_NO_OP, 0, 1, 0, 1),
                "maintainer-only": (PackageRecordsOutcome.MAINTAINER_ONLY, 0, 1, 0, 1),
                "partial": changed(1, 1, 2, 1),
            }[case]
        )
        assert second_result.created_tracks == (
            (CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),) if partial else ()
        )
        if case == "no-op":
            assert second_call.recorder.writes() == []
        # `auto_assign_actor(ticket, acting_user, db)`,
        # `reconcile_ticket_status(ticket, db, ...)`: only a tree change.
        expected_sessions = [first, second] if partial else [first]
        assert sessions_of(assign, 2) == expected_sessions
        assert sessions_of(reconcile, 1) == expected_sessions

        occurrences = {(IBS_REF, p1.id): new_occurrence(True)}
        tracks = {IBS_REF: NEW_TRACK[WorkflowType.IBS]}
        if partial:
            occurrences |= {
                (IBS_REF, p2.id): new_occurrence(True),
                (GIT_REF, p3.id): new_occurrence(True),
            }
            tracks[GIT_REF] = NEW_TRACK[WorkflowType.GIT]
        second_events = {
            "no-op": [],
            "maintainer-only": [maintainer_event(pkg, m2)],
            "partial": [package_added_event(pkg, second_actor, CVE_RESOLUTION)],
        }[case]
        assert await committed_state(world, ticket.id, pkg) == CommittedState(
            (ANALYSIS, first_actor.id),
            [
                assignment_event(first_actor),
                maintainer_event(pkg, m1),
                package_added_event(pkg, first_actor),
                *second_events,
            ],
            Tree(None, tracks, occurrences),
            sorted(
                [(pkg, m1.id)] + ([(pkg, m2.id)] if case == "maintainer-only" else [])
            ),
        )
