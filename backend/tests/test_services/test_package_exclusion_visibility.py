"""Consumer accessibility tests for the package-tree exclusion and
restoration operations (backend/app/services/package_service.py:
`soft_delete_ticket_package[_track|_product]()` and
`restore_ticket_package[_track|_product]()`), part C.

Owning specifications:

- docs/features/packages/package-service.md (Consumer caller context and
  Ticket accessibility; Exclusion and restoration operations steps 2-6;
  Architectural Test Requirement: Atomic consumer accessibility, including
  "A successful package exclusion that removes the actor's own final path
  still returns its ordinary locked-pre-state result").
- docs/features/identity/rbac.md (Scope and Confidential Ticket Visibility:
  four additive branches; the maintainer branch requires
  `TicketPackage.deleted_at IS NULL`; restoring the last qualifying package
  reactivates the retained association without external I/O; track and
  Product exclusion do not affect the predicate; visibility never grants a
  capability).
- docs/api-spec.md (Authorization Chain Evaluation Order, flow 3:
  locked-current accessibility precedes operability, nested ownership,
  state guards, writes, audit, and reconciliation).
- docs/features/platform/testing-strategy.md (Ticket Accessibility:
  canonical predicate rows "Included-package maintainer", "Package exclusion
  and restore", "Track or Product exclusion", "Multiple qualifying
  packages", "Authenticated user with no roles"; Locked mutations, including
  the self-loss case; Concurrency Testing for the committed self-loss case).

The anonymous caller is rejected with `ValueError` before any statement
(`tests/test_services/test_package_exclusion_scope.py`,
`TestCallerValidation`), and a missing Ticket UUID raises
`TicketNotFoundError` at every level and direction (same module,
`TestNestedOwnership`, `missing-ticket`); neither is repeated here. The
races that remove visibility while a call waits for the Ticket lock live in
`tests/test_services/test_package_exclusion_atomicity.py`.

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High` and carries an untouched actionable `ANALYSIS`
"pin" track in a package nobody maintains, so it stays in `Analysis`
whatever the operation does and creates no gate event; each target track
carries one eligible Product in General Support on `EVAL`. A
`restricted_analyst` actor has effective scope `non_confidential` and is
never auto-assigned (not a VA). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, time
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services.package_service import (
    PackageMarkerProjection,
    PackageProjection,
    get_ticket_packages,
)
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition
from tests.support.package_exclusion import (
    DIRECTIONS,
    LEVELS,
    MARKER_NOW,
    Direction,
    Level,
    add_maintainer,
    assert_no_effects,
    change,
    committed_path,
    marker_event,
    markers,
    markers_by_id,
    patch_marker_now,
    path_call,
    path_event,
    with_target,
)
from tests.support.product_eligibility import occurrence_path, only_occurrence
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    ticket_events,
    ticket_events_by_id,
)
from tests.support.track_status import ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

NON_CONFIDENTIAL = Scope.NON_CONFIDENTIAL
PKG_EXCLUDED = NonActionableReason.PACKAGE_EXCLUDED


@pytest.fixture(autouse=True)
def _marker_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every exclusion sets its marker to the controlled `MARKER_NOW`."""
    patch_marker_now(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _restricted(va_user: VAUser) -> User:
    """An active `restricted_analyst` (effective scope `non_confidential`,
    rbac.md, Predefined Roles), never auto-assigned."""
    return await va_user(roles=(Role.RESTRICTED_ANALYST,))


async def _pinned(
    ticket_factory: TicketFactory, tree: TreeBuilder, **overrides: Any
) -> Ticket:
    """A CVE-less High Ticket (default `Analysis`) with the unmaintained
    actionable `ANALYSIS` pin track."""
    ticket = await cveless(ticket_factory, **overrides)
    await tree(ticket, status=PackageStatus.ANALYSIS)
    return ticket


async def _target(
    db: AsyncSession,
    tree: TreeBuilder,
    ticket: Ticket,
    level: Level,
    *,
    seeded: bool,
    package_excluded: bool = False,
) -> TicketPackageProduct:
    """One new package with one `ANALYSIS` track and one Product occurrence;
    `seeded` sets the direct marker of `level`, `package_excluded` the
    package marker regardless of the level."""
    track = await tree(
        ticket,
        status=PackageStatus.ANALYSIS,
        products=(Prod(excluded=seeded and level is Level.PRODUCT),),
        package_excluded=package_excluded or (seeded and level is Level.PACKAGE),
        track_excluded=seeded and level is Level.TRACK,
    )
    return await only_occurrence(db, track)


async def _package_id(db: AsyncSession, occurrence: TicketPackageProduct) -> uuid.UUID:
    """The package of an occurrence."""
    _, package_id, _ = await occurrence_path(db, occurrence)
    return package_id


async def _package_name(db: AsyncSession, package_id: uuid.UUID) -> str:
    """The persisted name of a package."""
    return (
        await db.execute(
            select(TicketPackage.package_name).where(TicketPackage.id == package_id)
        )
    ).scalar_one()


async def _visible(db: AsyncSession, ticket: Ticket, user: User) -> bool:
    """The canonical predicate for `user` with effective scope
    `non_confidential`, evaluated on the current Ticket state."""
    caller = TicketCaller.authenticated(user.id, NON_CONFIDENTIAL)
    return bool(
        (
            await db.execute(
                select(ticket_visibility_condition(caller))
                .select_from(Ticket)
                .where(Ticket.id == ticket.id)
            )
        ).scalar_one()
    )


async def _read(
    db: AsyncSession, ticket: Ticket, user: User
) -> tuple[PackageProjection, ...]:
    """A subsequent protected read: the package tree as `user` with
    effective scope `non_confidential` sees it."""
    return await get_ticket_packages(
        db,
        ticket_id=format_ticket_id(ticket.sequence_id),
        caller=TicketCaller.authenticated(user.id, NON_CONFIDENTIAL),
        evaluation_date=EVAL,
        evaluation_instant=datetime.combine(EVAL, time(12), UTC),
    )


async def _maintainers(db: AsyncSession, package_id: uuid.UUID) -> list[uuid.UUID]:
    """The users associated as maintainers of a package."""
    return list(
        (
            await db.execute(
                select(TicketPackageMaintainer.user_id).where(
                    TicketPackageMaintainer.ticket_package_id == package_id
                )
            )
        ).scalars()
    )


def _seeded(direction: Direction) -> bool:
    """An effective restore needs the target marker set; an exclusion
    needs it clear."""
    return direction is Direction.RESTORE


# ---------------------------------------------------------------------------
# Locked-current accessibility branches
# ---------------------------------------------------------------------------

DENIALS = [
    "no-visibility-path",
    "maintainer-of-excluded-package",
    "ignored",
    "duplicated",
    "wrong-path",
    "guard-violation",
]
"""Inaccessible requests of a `non_confidential` caller on a confidential
Ticket where another user holds a grant and maintains the path's package:

- `no-visibility-path`: otherwise effective;
- `maintainer-of-excluded-package`: the actor maintains only the path's
  package, which is directly excluded (rbac.md: the branch requires
  `deleted_at IS NULL`); for a package restore this is the actor trying to
  restore its own last maintained package;
- `ignored` / `duplicated`: a manual-zone Ticket (would be
  `TicketNotMutableError`);
- `wrong-path`: the deepest locator part is unknown (would be the
  package/track/Product not-found error);
- `guard-violation`: the opposite target marker (would be
  `PackageAlreadyExcludedError` or `PackageNotExcludedError`)."""


@pytest.mark.integration
class TestInaccessibleTicket:
    """package-service.md, Consumer caller context and Ticket accessibility
    and Exclusion and restoration operations steps 3-6; api-spec.md, flow 3
    step 3; testing-strategy.md, Locked mutations (nested-resource,
    operability, idempotency, and no-op decisions never precede the
    denial). Another user's grant or maintainership never qualifies the
    caller. The denial has zero effects (`assert_no_effects`)."""

    @LEVELS
    @DIRECTIONS
    @pytest.mark.parametrize("case", DENIALS)
    async def test_denial_precedes_every_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_access_grant_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        direction: Direction,
        case: str,
    ) -> None:
        actor = await _restricted(va_user)
        other = await va_user()
        status = {
            "ignored": TicketStatus.IGNORED,
            "duplicated": TicketStatus.DUPLICATED,
        }.get(case, TicketStatus.ANALYSIS)
        ticket = await _pinned(
            ticket_factory, tree, status=status, is_confidential=True
        )
        seeded = _seeded(direction) != (case == "guard-violation")
        excluded_package = case == "maintainer-of-excluded-package"
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            level,
            seeded=seeded,
            package_excluded=excluded_package,
        )
        package_id = await _package_id(db_session, occurrence)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=other.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package_id, user_id=other.id
        )
        if excluded_package:
            await ticket_package_maintainer_factory(
                ticket_package_id=package_id, user_id=actor.id
            )
        overrides: dict[str, Any] = {}
        if case == "wrong-path":
            name = {
                Level.PACKAGE: "package_id",
                Level.TRACK: "track_id",
                Level.PRODUCT: "occurrence_id",
            }[level]
            overrides[name] = uuid.uuid4()
        assert await _visible(db_session, ticket, actor) is False

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(
                db_session,
                level,
                direction,
                occurrence,
                actor,
                scope=NON_CONFIDENTIAL,
                **overrides,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotFoundError,
        )


def _branches() -> list[Any]:
    """Every `(branch, level, direction)`. A caller who maintains only the
    path's package cannot restore that package: it is excluded, so the
    branch does not apply (covered by `TestInaccessibleTicket`)."""
    return [
        pytest.param(branch, level, direction, id=f"{branch}-{level}-{direction}")
        for branch in (
            "non-confidential",
            "scope-all",
            "explicit-grant",
            "maintainer-of-path-package",
            "maintainer-of-other-included-package",
        )
        for level in Level
        for direction in Direction
        if not (
            branch == "maintainer-of-path-package"
            and level is Level.PACKAGE
            and direction is Direction.RESTORE
        )
    ]


@pytest.mark.integration
class TestVisibilityBranches:
    """rbac.md, Scope and Confidential Ticket Visibility: each branch is
    independently sufficient for the locked-current check. The operation
    changes only the target marker and records one acting-user event; the
    restricted analyst is not assigned."""

    @pytest.mark.parametrize(("branch", "level", "direction"), _branches())
    async def test_each_branch_permits_the_operation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        branch: str,
        level: Level,
        direction: Direction,
    ) -> None:
        actor = await _restricted(va_user)
        ticket = await _pinned(
            ticket_factory, tree, is_confidential=branch != "non-confidential"
        )
        occurrence = await _target(
            db_session, tree, ticket, level, seeded=_seeded(direction)
        )
        if branch == "explicit-grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        elif branch == "maintainer-of-path-package":
            await ticket_package_maintainer_factory(
                ticket_package_id=await _package_id(db_session, occurrence),
                user_id=actor.id,
            )
        elif branch == "maintainer-of-other-included-package":
            maintained = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=maintained.id, user_id=actor.id
            )
        scope = Scope.ALL if branch == "scope-all" else NON_CONFIDENTIAL
        before = await markers(db_session, occurrence)

        await change(db_session, level, direction, occurrence, actor, scope=scope)

        assert await markers(db_session, occurrence) == with_target(
            before, level, MARKER_NOW if direction is Direction.EXCLUDE else None
        )
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, direction, occurrence, actor)
        ]
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)


# ---------------------------------------------------------------------------
# Canonical predicate rows (testing-strategy.md, Ticket Accessibility)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCanonicalPredicateRows:
    """testing-strategy.md, Ticket Accessibility, canonical predicate rows
    "Included-package maintainer", "Package exclusion and restore", "Track
    or Product exclusion", and "Multiple qualifying packages"; rbac.md,
    Scope and Confidential Ticket Visibility. Access is observed through
    the canonical predicate and through a subsequent protected read or
    mutation by the same caller."""

    async def test_last_package_exclusion_removes_access_and_restore_reactivates(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_maintainer_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The actor maintains only the target package. Its own exclusion
        succeeds with the ordinary result (self-loss), after which the
        predicate, a package-tree read, and a restore by the same actor all
        deny. A scope-`all` VA (already the assignee) restores the package:
        the retained association qualifies again; the restore writes only
        the package marker and its event and never touches the
        maintainer association (no re-acquisition)."""
        actor = await _restricted(va_user)
        restorer = await va_user()
        ticket = await _pinned(
            ticket_factory, tree, is_confidential=True, assignee_id=restorer.id
        )
        await db_session.refresh(ticket, ["sequence_id"])
        occurrence = await _target(
            db_session, tree, ticket, Level.PACKAGE, seeded=False
        )
        package_id = await _package_id(db_session, occurrence)
        await ticket_package_maintainer_factory(
            ticket_package_id=package_id, user_id=actor.id
        )
        package_name = await _package_name(db_session, package_id)
        assert await _visible(db_session, ticket, actor) is True

        excluded = await change(
            db_session,
            Level.PACKAGE,
            Direction.EXCLUDE,
            occurrence,
            actor,
            scope=NON_CONFIDENTIAL,
        )

        assert excluded.target == PackageMarkerProjection(
            package_name, False, PKG_EXCLUDED
        )
        assert await _visible(db_session, ticket, actor) is False
        with pytest.raises(TicketNotFoundError):
            await _read(db_session, ticket, actor)
        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(
                db_session,
                Level.PACKAGE,
                Direction.RESTORE,
                occurrence,
                actor,
                scope=NON_CONFIDENTIAL,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotFoundError,
        )

        with StatementRecorder(db_session) as recorder:
            await change(
                db_session, Level.PACKAGE, Direction.RESTORE, occurrence, restorer
            )

        writes = recorder.writes()
        assert writes
        assert [
            s
            for s in writes
            if not s.lstrip().startswith(
                ("UPDATE ticket_package ", "INSERT INTO ticket_audit_event ")
            )
        ] == []
        assert await _maintainers(db_session, package_id) == [actor.id]
        assert await _visible(db_session, ticket, actor) is True
        packages = await _read(db_session, ticket, actor)
        assert package_id in [p.id for p in packages]
        assert await markers(db_session, occurrence) == (None, None, None)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(
                db_session, Level.PACKAGE, Direction.EXCLUDE, occurrence, actor
            ),
            await marker_event(
                db_session, Level.PACKAGE, Direction.RESTORE, occurrence, restorer
            ),
        ]

    @pytest.mark.parametrize("level", [Level.TRACK, Level.PRODUCT], ids=str)
    async def test_track_or_product_exclusion_keeps_maintainer_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_maintainer_factory: Factory,
        level: Level,
    ) -> None:
        """Excluding the only track (or Product) of the actor's only
        maintained package leaves that package without actionable
        descendants, yet package-wide maintainer visibility remains: the
        predicate holds, the tree is readable, and the actor's next
        mutation (restoring the same record) succeeds."""
        actor = await _restricted(va_user)
        ticket = await _pinned(ticket_factory, tree, is_confidential=True)
        await db_session.refresh(ticket, ["sequence_id"])
        occurrence = await _target(db_session, tree, ticket, level, seeded=False)
        package_id = await _package_id(db_session, occurrence)
        await ticket_package_maintainer_factory(
            ticket_package_id=package_id, user_id=actor.id
        )

        await change(
            db_session,
            level,
            Direction.EXCLUDE,
            occurrence,
            actor,
            scope=NON_CONFIDENTIAL,
        )

        assert await _visible(db_session, ticket, actor) is True
        (package,) = [
            p for p in await _read(db_session, ticket, actor) if p.id == package_id
        ]
        assert (package.actionable, package.non_actionable_reason) == (
            False,
            NonActionableReason.NO_ACTIONABLE_TRACKS,
        )
        await change(
            db_session,
            level,
            Direction.RESTORE,
            occurrence,
            actor,
            scope=NON_CONFIDENTIAL,
        )
        assert await markers(db_session, occurrence) == (None, None, None)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, Direction.EXCLUDE, occurrence, actor),
            await marker_event(db_session, level, Direction.RESTORE, occurrence, actor),
        ]

    async def test_multiple_qualifying_packages(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """The actor maintains two included packages. Excluding the first
        preserves access through the second; excluding the second (an
        authorized self-loss) succeeds and only then removes access."""
        actor = await _restricted(va_user)
        ticket = await _pinned(ticket_factory, tree, is_confidential=True)
        await db_session.refresh(ticket, ["sequence_id"])
        first = await _target(db_session, tree, ticket, Level.PACKAGE, seeded=False)
        second = await _target(db_session, tree, ticket, Level.PACKAGE, seeded=False)
        for occurrence in (first, second):
            await ticket_package_maintainer_factory(
                ticket_package_id=await _package_id(db_session, occurrence),
                user_id=actor.id,
            )

        await change(
            db_session,
            Level.PACKAGE,
            Direction.EXCLUDE,
            first,
            actor,
            scope=NON_CONFIDENTIAL,
        )

        assert await _visible(db_session, ticket, actor) is True
        assert len(await _read(db_session, ticket, actor)) == 3

        result = await change(
            db_session,
            Level.PACKAGE,
            Direction.EXCLUDE,
            second,
            actor,
            scope=NON_CONFIDENTIAL,
        )

        assert (result.target.actionable, result.target.non_actionable_reason) == (
            False,
            PKG_EXCLUDED,
        )
        assert await _visible(db_session, ticket, actor) is False
        with pytest.raises(TicketNotFoundError):
            await _read(db_session, ticket, actor)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(
                db_session, Level.PACKAGE, Direction.EXCLUDE, first, actor
            ),
            await marker_event(
                db_session, Level.PACKAGE, Direction.EXCLUDE, second, actor
            ),
        ]


@pytest.mark.integration
class TestAuthenticatedUserWithNoRoles:
    """testing-strategy.md, Ticket Accessibility row "Authenticated user
    with no roles" and rbac.md, Scope and Confidential Ticket Visibility: a
    role-less user has effective scope `non_confidential` and gains
    visibility through a grant or an included-package maintainership.

    The service checks only locked-current accessibility: every declared
    capability is checked by the API before resource lookup (api-spec.md,
    Authorization Chain Evaluation Order, flow 3 step 1; rbac.md:
    visibility never grants a capability), so the role-less caller's
    missing capability belongs to the endpoint e2e tests, not here. The
    service call succeeds without assignment."""

    @LEVELS
    @DIRECTIONS
    @pytest.mark.parametrize("branch", ["explicit-grant", "maintainer"])
    async def test_visibility_branch_admits_the_role_less_caller(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        level: Level,
        direction: Direction,
        branch: str,
    ) -> None:
        actor = await va_user(roles=())
        ticket = await _pinned(ticket_factory, tree, is_confidential=True)
        occurrence = await _target(
            db_session, tree, ticket, level, seeded=_seeded(direction)
        )
        if branch == "explicit-grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        else:
            maintained = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=maintained.id, user_id=actor.id
            )
        assert await _visible(db_session, ticket, actor) is True

        await change(
            db_session, level, direction, occurrence, actor, scope=NON_CONFIDENTIAL
        )

        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, direction, occurrence, actor)
        ]
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)


# ---------------------------------------------------------------------------
# Self-loss with committed state (testing-strategy.md, Locked mutations)
# ---------------------------------------------------------------------------


@pytest.fixture
async def committed_world(
    db_session_factory: SessionFactory,
) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


@pytest.mark.integration
class TestCommittedSelfLoss:
    """testing-strategy.md, Locked mutations (the converse self-loss case):
    a `restricted_analyst` authorized only through the last included
    maintained package of a confidential Ticket may exclude that package.
    Authorization uses the locked pre-mutation state, the ordinary result
    and event commit, and a subsequent request after commit is not found
    unless another visibility rule applies (package-service.md, Consumer
    caller context and Ticket accessibility; api-spec.md, Authorization
    Chain Evaluation Order). Committed rows are deleted explicitly by
    `CommittedWorld` (testing-strategy.md, Concurrency Testing)."""

    @pytest.mark.parametrize("other_rule", ["none", "explicit-grant"])
    async def test_actor_excludes_its_last_qualifying_package(
        self, committed_world: CommittedWorld, other_rule: str
    ) -> None:
        world = committed_world
        actor = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await world.ticket(
            cve_id=None, is_confidential=True, severity_manual=Severity.HIGH
        )
        await committed_path(world, ticket)
        path = await committed_path(world, ticket)
        await add_maintainer(world, path.package_id, actor)
        if other_rule == "explicit-grant":
            granter = await world.user(role=Role.VULNERABILITY_ANALYST)
            await world.grant(ticket, actor, granter)
        session = await world.open_session()

        result = await path_call(
            session,
            Level.PACKAGE,
            Direction.EXCLUDE,
            path,
            actor,
            scope=NON_CONFIDENTIAL,
        )
        await session.commit()

        assert result.target == PackageMarkerProjection(
            path.subject["package"], False, PKG_EXCLUDED
        )
        assert result.evaluation_date == EVAL
        probe = await world.open_session()
        assert await markers_by_id(probe, path.id) == (MARKER_NOW, None, None)
        assert await ticket_events_by_id(probe, ticket.id) == [
            path_event(Level.PACKAGE, Direction.EXCLUDE, path, actor)
        ]
        assert await ticket_state(probe, ticket) == (TicketStatus.ANALYSIS, None)
        await probe.rollback()

        later = await world.open_session()
        if other_rule == "explicit-grant":
            packages = await _read(later, ticket, actor)
            assert path.package_id in [p.id for p in packages]
            await later.rollback()
            return
        with pytest.raises(TicketNotFoundError):
            await _read(later, ticket, actor)
        await later.rollback()
        with (
            SessionStatementRecorder(later) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await path_call(
                later,
                Level.PACKAGE,
                Direction.RESTORE,
                path,
                actor,
                scope=NON_CONFIDENTIAL,
            )
        assert recorder.writes() == []
        await later.rollback()
        probe = await world.open_session()
        assert await markers_by_id(probe, path.id) == (MARKER_NOW, None, None)
        assert len(await ticket_events_by_id(probe, ticket.id)) == 1
        await probe.rollback()
