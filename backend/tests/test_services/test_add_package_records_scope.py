"""Single-session service integration tests for the package-record creation
boundary `package_service.add_package_records()`
(backend/app/services/package_service.py), part B: caller contract, guards
and their order, and whole-invocation rollback.

Owning specifications:

- docs/features/packages/package-service.md (`add_package_records()`
  parameters, input contract, preconditions, steps 1-9, Exceptions;
  Acting user convention; Consumer caller context and Ticket
  accessibility; Service Exceptions; Ticket-level operability;
  Architectural Test Requirement: Atomic consumer accessibility (the
  single-session consumer-mutation parts), Package audit comments).
- docs/features/packages/package-maintainership.md (Acquisition Workflow >
  Locked mutation: the `active_ticket_only` skip creates no association and
  the unique constraint is the concurrency backstop; Audit event: audit
  failure rolls back the association and the package tree; Security and
  Privacy: unpersisted maintainer data cannot authorize).
- docs/features/packages/package-model.md (Interaction with
  add_package_to_ticket: the public excluded-package guard; Adding
  Packages to a Ticket: failure and outcome precedence 8-11).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary; Cross-Event Ordering, Locking, and Rollback; Testing
  Requirements 7, 12, 24).
- docs/features/platform/testing-strategy.md (Service Functions; Rollback
  Within a Test; Ticket Accessibility: no operability, state, idempotency,
  or no-op decision precedes the locked accessibility denial).

Independent-session lock serialization and the locked-current
accessibility races are covered by
`tests/test_services/test_add_package_records_atomicity.py`.

Unless a test states otherwise: the `default_cvss_version` setting is
`3.1`; the service's UTC date is the controlled `EVAL`; a Ticket is
CVE-less with `severity_manual = High`; and a catalog Product is in
General Support with a `NULL` threshold. Expected values are transcribed
from the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import false, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Role,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    SYSTEM_INVOCATION,
    PackageAlreadyExcludedError,
    PackageRecordsOutcome,
    PackageRecordsResult,
    ResolvedTrackData,
    add_package_records,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.database import rollback_test_scope
from tests.support.package_records import (
    SKIPPED,
    SYSTEM_COMMENTS,
    add_records,
    assert_no_effects,
    catalog_product,
    changed,
    maintainer_event,
    maintainers,
    outcome,
    package_added_event,
    seed_maintainer,
    seed_occurrence,
    seed_package,
    seed_track,
    seed_user,
    snapshot,
    target,
)
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

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

SettingFactory = Callable[..., Awaitable[SystemSetting]]
GrantFactory = Callable[..., Awaitable[Any]]

PKG = "fictional-libexample"
OTHER = "fictional-other"
IBS_REF = "Fictional:Product:15-SP7:Update"
IBS_REF_2 = "Fictional:Product:16.0:Update"
OWN_EMAIL = "fictional.caller@example.com"
"""The email of the consumer caller, offered as a maintainer email."""

NEW = TicketStatus.NEW
ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED
IGNORED = TicketStatus.IGNORED
DUPLICATED = TicketStatus.DUPLICATED


@pytest.fixture(autouse=True)
def _clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is the controlled `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture
async def default_setting(system_setting_factory: SettingFactory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


async def _complete(
    db: AsyncSession, ticket: Ticket, *, excluded: bool = False
) -> tuple[list[ResolvedTrackData], Product]:
    """A persisted package `PKG` (directly excluded when asked) with one
    `ANALYSIS` track and one Product, and the input matching it exactly."""
    package = await seed_package(db, ticket.id, PKG, excluded=excluded)
    track = await seed_track(db, package, IBS_REF)
    product = await catalog_product(db)
    await seed_occurrence(db, track, product)
    return [target(IBS_REF, product)], product


# ---------------------------------------------------------------------------
# Caller contract (package-service.md, `add_package_records()` parameters
# and input contract; Acting user convention)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCallerContract:
    """Each violation raises `ValueError` before any SQL statement, with no
    effect."""

    @staticmethod
    async def _assert_rejected(
        db: AsyncSession, ticket: Ticket, match: str, **kwargs: Any
    ) -> None:
        arguments: dict[str, Any] = {
            "ticket_id": ticket.id,
            "package_name": PKG,
            "maintainer_emails": frozenset({OWN_EMAIL}),
        }
        arguments.update(kwargs)
        with StatementRecorder(db) as recorder, pytest.raises(ValueError, match=match):
            await add_package_records(db, **arguments)
        assert recorder.statements == []
        assert await snapshot(db, ticket.id) == (
            [(NEW.value, None)],
            [[]],
            [[]],
            [[]],
            (),
        )

    @pytest.mark.parametrize(
        "case",
        [
            "system-with-actor",
            "consumer-without-actor",
            "consumer-of-another-user",
            "anonymous-with-actor",
        ],
    )
    async def test_actor_and_context_mismatch(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        case: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        product = await catalog_product(db_session)
        pairings: dict[str, tuple[Any, Any, Any]] = {
            "system-with-actor": (
                actor.id,
                SYSTEM_INVOCATION,
                "CVE package resolution",
            ),
            "consumer-without-actor": (
                None,
                TicketCaller.authenticated(actor.id, Scope.ALL),
                None,
            ),
            "consumer-of-another-user": (
                actor.id,
                TicketCaller.authenticated(other.id, Scope.ALL),
                None,
            ),
            "anonymous-with-actor": (actor.id, ANONYMOUS_CALLER, None),
        }
        acting_user_id, caller, comment = pairings[case]

        await self._assert_rejected(
            db_session,
            ticket,
            "acting user",
            tracks=[target(IBS_REF, product)],
            acting_user_id=acting_user_id,
            caller=caller,
            audit_comment=comment,
        )

    @pytest.mark.parametrize("context", ["user", "system"])
    @pytest.mark.parametrize(
        "case",
        [
            "empty-tracks",
            "empty-product-set",
            "duplicate-product-in-track",
            "duplicate-reference",
        ],
    )
    async def test_invalid_tracks(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        context: str,
        case: str,
    ) -> None:
        """A duplicate Product within one track or a repeated reference is
        rejected. The same catalog Product under two different tracks is
        valid (`test_add_package_records.py`, `TestFirstCreation`)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        p1 = await catalog_product(db_session)
        p2 = await catalog_product(db_session)
        tracks = {
            "empty-tracks": [],
            "empty-product-set": [target(IBS_REF, p1), target(IBS_REF_2)],
            "duplicate-product-in-track": [target(IBS_REF, p1, p2, p1)],
            "duplicate-reference": [target(IBS_REF, p1), target(IBS_REF, p2)],
        }[case]
        match = {
            "empty-tracks": "tracks must not be empty",
            "empty-product-set": "at least one Product",
            "duplicate-product-in-track": "must be distinct",
            "duplicate-reference": "must be distinct",
        }[case]
        user = context == "user"

        await self._assert_rejected(
            db_session,
            ticket,
            match,
            tracks=tracks,
            acting_user_id=actor.id if user else None,
            caller=(
                TicketCaller.authenticated(actor.id, Scope.ALL)
                if user
                else SYSTEM_INVOCATION
            ),
            audit_comment=None if user else "CVE package resolution",
        )

    @pytest.mark.parametrize(
        ("context", "comment"),
        [
            pytest.param("system", None, id="system-without-comment"),
            pytest.param("system", "Manual package addition", id="system-unknown"),
            pytest.param("system", "cve package resolution", id="system-case-variant"),
            pytest.param("user", "Manual package addition", id="user-unknown"),
            *[
                pytest.param("user", c, id=f"user-{c.replace(' ', '-').lower()}")
                for c in SYSTEM_COMMENTS
            ],
        ],
    )
    async def test_audit_comment_outside_the_closed_set_or_actor(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        context: str,
        comment: str | None,
    ) -> None:
        """A system call requires one of the three exact canonical comments;
        a user-attributed call requires `NULL` (ticket-audit-log.md,
        Canonical Automatic Comment Vocabulary)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        product = await catalog_product(db_session)
        user = context == "user"

        await self._assert_rejected(
            db_session,
            ticket,
            "comment",
            tracks=[target(IBS_REF, product)],
            acting_user_id=actor.id if user else None,
            caller=(
                TicketCaller.authenticated(actor.id, Scope.ALL)
                if user
                else SYSTEM_INVOCATION
            ),
            audit_comment=comment,
        )


# ---------------------------------------------------------------------------
# Missing Ticket and locked consumer accessibility (package-service.md,
# step 2 and Consumer caller context and Ticket accessibility;
# package-maintainership.md, Security and Privacy)
# ---------------------------------------------------------------------------

DENIED_WORLDS = [
    "would-create-tree",
    "would-be-maintainer-only",
    "would-be-no-op",
    "excluded-package",
    "manual-zone",
    "active-ticket-only-inactive",
]
"""What the call would otherwise do: create a package tree; add only the
caller's association; be a package-tree no-op; raise
`PackageAlreadyExcludedError`; raise `TicketNotMutableError` (`Ignored`);
or return the `active_ticket_only` skip (`Resolved`)."""


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestTicketGuards:
    @pytest.mark.parametrize("context", ["user", "system"])
    async def test_missing_ticket_raises_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        actor = await va_user() if context == "user" else None
        bystander = await cveless(ticket_factory, status=NEW)
        product = await catalog_product(db_session)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add_records(
                db_session,
                uuid.uuid4(),
                PKG,
                [target(IBS_REF, product)],
                actor=actor,
            ),
            ticket_ids=(bystander.id,),
            error=TicketNotFoundError,
        )

    @pytest.mark.parametrize("world", DENIED_WORLDS)
    async def test_inaccessible_consumer_is_denied_before_every_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        world: str,
    ) -> None:
        """A `restricted_analyst` (`non_confidential` scope, no grant, no
        included maintained package) on a confidential Ticket receives
        `TicketNotFoundError` with zero effects, although its own email is
        offered as a maintainer email: fetched but unpersisted maintainer
        data cannot authorize. No operability, excluded-package,
        `active_ticket_only`, no-op, or idempotency decision precedes the
        denial."""
        caller = await seed_user(
            db_session, email=OWN_EMAIL, roles=(Role.RESTRICTED_ANALYST,)
        )
        status = {"manual-zone": IGNORED, "active-ticket-only-inactive": RESOLVED}
        ticket = await cveless(
            ticket_factory, status=status.get(world, NEW), is_confidential=True
        )
        if world == "would-create-tree":
            tracks = [target(IBS_REF, await catalog_product(db_session))]
        else:
            tracks, _ = await _complete(
                db_session, ticket, excluded=world == "excluded-package"
            )
            if world == "manual-zone":
                tracks.append(target(IBS_REF_2, await catalog_product(db_session)))
        emails = set() if world == "would-be-no-op" else {OWN_EMAIL}

        def call() -> Awaitable[PackageRecordsResult]:
            return add_records(
                db_session,
                ticket.id,
                PKG,
                tracks,
                actor=caller,
                emails=emails,
                scope=Scope.NON_CONFIDENTIAL,
                active_ticket_only=world == "active-ticket-only-inactive",
            )

        await assert_no_effects(
            db_session,
            monkeypatch,
            call,
            ticket_ids=(ticket.id,),
            error=TicketNotFoundError,
        )

        # The rejected call reads no package-tree or maintainer-match state.
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await call()
        assert [
            s
            for s in recorder.statements
            if "FROM ticket_package_track" in s
            or "FROM ticket_package_product" in s
            or '"user".email IN' in s
        ] == []

    @pytest.mark.parametrize(
        "path", ["scope-all", "explicit-grant", "included-maintainer"]
    )
    async def test_accessible_consumer_proceeds(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        path: str,
    ) -> None:
        """Each canonical branch is independently sufficient for the locked
        check of a confidential Ticket (the maintainership branch through
        another included package of the Ticket)."""
        caller = await seed_user(
            db_session,
            email=OWN_EMAIL,
            roles=(
                (Role.VULNERABILITY_ANALYST,)
                if path == "scope-all"
                else (Role.RESTRICTED_ANALYST,)
            ),
        )
        assignee = await va_user()
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
        if path == "included-maintainer":
            other = await seed_package(db_session, ticket.id, OTHER)
            await seed_track(db_session, other, IBS_REF)
            await seed_maintainer(db_session, other, caller)
        product = await catalog_product(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await add_records(
                db_session,
                ticket.id,
                PKG,
                [target(IBS_REF, product)],
                actor=caller,
                emails={OWN_EMAIL},
                scope=Scope.ALL if path == "scope-all" else Scope.NON_CONFIDENTIAL,
            )

        # Control for the denied cases: the statement patterns they exclude
        # do occur in an accessible call.
        assert any('"user".email IN' in s for s in recorder.statements)
        assert any("FROM ticket_package_product" in s for s in recorder.statements)
        assert outcome(result) == changed(1, 0, 1, 0)
        assert (PKG, caller.id) in await maintainers(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, caller),
            package_added_event(PKG, caller),
        ]


# ---------------------------------------------------------------------------
# `active_ticket_only` and operability (package-service.md, Preconditions
# and steps 3-4; package-maintainership.md, Locked mutation step 2)
# ---------------------------------------------------------------------------

CONTEXTS = pytest.mark.parametrize("context", ["user", "system"])


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestActiveTicketOnlyAndOperability:
    @CONTEXTS
    @pytest.mark.parametrize("status", [RESOLVED, IGNORED, DUPLICATED], ids=str)
    async def test_inactive_ticket_is_skipped_before_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
        status: TicketStatus,
    ) -> None:
        """The skip precedes operability (no `TicketNotMutableError` for the
        manual zone), the excluded-package guard, assignment of an
        unassigned Ticket by an active VA, audit, reconciliation, and
        maintainer acquisition; it reports zero counts."""
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=status)
        tracks, _ = await _complete(db_session, ticket, excluded=True)
        tracks.append(target(IBS_REF_2, await catalog_product(db_session)))
        await seed_user(db_session, email="maint.skipped@example.com")

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add_records(
                db_session,
                ticket.id,
                PKG,
                tracks,
                actor=actor,
                emails={"maint.skipped@example.com"},
                comment="Product catalog backfill",
                active_ticket_only=True,
            ),
            ticket_ids=(ticket.id,),
        )

        assert result == SKIPPED

    @CONTEXTS
    @pytest.mark.parametrize("status", [NEW, ANALYSIS, ANALYZED], ids=str)
    async def test_active_ticket_proceeds(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        context: str,
        status: TicketStatus,
    ) -> None:
        actor = await va_user() if context == "user" else None
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory,
            status=status,
            assignee_id=None if status is NEW else assignee.id,
        )

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            actor=actor,
            comment="Product catalog backfill",
            active_ticket_only=True,
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        events = await ticket_events(db_session, ticket)
        assert package_added_event(PKG, actor, "Product catalog backfill") in events

    @CONTEXTS
    @pytest.mark.parametrize("status", [IGNORED, DUPLICATED], ids=str)
    @pytest.mark.parametrize("excluded", [False, True], ids=["included", "excluded"])
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
        status: TicketStatus,
        excluded: bool,
    ) -> None:
        """Without `active_ticket_only`, a manual-zone Ticket raises
        `TicketNotMutableError`, also before the excluded-package guard."""
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=status)
        tracks, _ = await _complete(db_session, ticket, excluded=excluded)
        tracks.append(target(IBS_REF_2, await catalog_product(db_session)))

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add_records(db_session, ticket.id, PKG, tracks, actor=actor),
            ticket_ids=(ticket.id,),
            error=TicketNotMutableError,
        )


# ---------------------------------------------------------------------------
# Public excluded-package guard (package-service.md step 6; package-model.md,
# Interaction with add_package_to_ticket)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestExcludedPackageGuard:
    @CONTEXTS
    @pytest.mark.parametrize(
        "would", ["no-op", "maintainer-only", "tree-change", "tree-and-maintainer"]
    )
    async def test_guard_precedes_every_outcome(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
        would: str,
    ) -> None:
        """Outside re-resolution mode, a directly excluded package raises
        `PackageAlreadyExcludedError` before the no-op or maintainer-only
        outcome and before any record, association, assignment of the
        unassigned Ticket by an active VA, audit, or reconciliation."""
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=NEW)
        tracks, _ = await _complete(db_session, ticket, excluded=True)
        if would.startswith("tree"):
            tracks.append(target(IBS_REF_2, await catalog_product(db_session)))
        await seed_user(db_session, email="maint.guarded@example.com")
        emails = (
            {"maint.guarded@example.com"}
            if would in {"maintainer-only", "tree-and-maintainer"}
            else set()
        )

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add_records(
                db_session, ticket.id, PKG, tracks, actor=actor, emails=emails
            ),
            ticket_ids=(ticket.id,),
            error=PackageAlreadyExcludedError,
        )

    async def test_unknown_catalog_product_raises_and_rolls_back(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """The input contract admits only existing catalog Products; an
        unknown ID raises `ValueError` under the lock, after the
        assignment and the package insert, and the caller's rollback
        leaves no effect."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        known = await catalog_product(db_session)
        await seed_user(db_session, email="maint.unknown.product@example.com")
        ticket_id = ticket.id
        before = await snapshot(db_session, ticket_id)

        async with rollback_test_scope(db_session):
            with pytest.raises(ValueError, match="catalog Product"):
                await add_records(
                    db_session,
                    ticket_id,
                    PKG,
                    [target(IBS_REF, known, uuid.uuid4())],
                    actor=actor,
                    emails={"maint.unknown.product@example.com"},
                )

        assert await snapshot(db_session, ticket_id) == before


# ---------------------------------------------------------------------------
# Whole-invocation rollback (ticket-audit-log.md, Testing Requirements 7 and
# 24, Cross-Event Ordering, Locking, and Rollback; package-service.md,
# Exceptions; package-maintainership.md, Audit event)
# ---------------------------------------------------------------------------

FAILURES = [
    "settings-missing",
    "invalid-default-version",
    "eligibility",
    "tree-flush",
    "audit-maintainer",
    "audit-package-added",
    "reconcile-before",
    "reconcile-after",
    "database",
    "final-flush",
]
"""`settings-missing`: no `default_cvss_version` row. `invalid-default-
version`: a persisted `3.0`, rejected by the Eligibility Score Resolution.
`eligibility`: the shared evaluator fails on the second new occurrence.
`tree-flush`: the flush that inserts the new occurrences fails.
`audit-maintainer`: the second `package_maintainer_added` fails after the
first association and event. `audit-package-added`: `package_added` fails
after every record and association. `reconcile-*`: reconciliation fails
before it runs, or after it changed the status (and, for the regression,
registered its effect). `database`: the first statement of the
reconciliation fails. `final-flush`: the boundary's own flush after
reconciliation fails."""

EXPECTED_ERRORS: dict[str, type[Exception]] = {
    "settings-missing": RequiredSystemSettingMissingError,
    "invalid-default-version": ValueError,
    "database": OperationalError,
}

SCENARIOS = ["user-new-unassigned", "system-resolved-regression"]
"""`user-new-unassigned`: an active VA adds a new package with two tracks to
an unassigned `New` Ticket (assignment, `New -> Analysis`). `system-
resolved-regression`: a CVE package resolution completes a `FIXED` track of
a `Resolved` Ticket with an eligible unreleased Product and a new track
(`Resolved -> Analysis` and one convergence effect). Both acquire two
maintainers."""


async def _scenario(
    db: AsyncSession,
    scenario: str,
    ticket_factory: TicketFactory,
    va_user: VAUser,
) -> tuple[Ticket, User | None, list[ResolvedTrackData], list[User]]:
    low_id, high_id = sorted(uuid.uuid4() for _ in range(2))
    users = [
        await seed_user(db, email="maint.rb.low@example.com", user_id=low_id),
        await seed_user(db, email="maint.rb.high@example.com", user_id=high_id),
    ]
    if scenario == "user-new-unassigned":
        actor: User | None = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        tracks = [
            target(IBS_REF, await catalog_product(db), await catalog_product(db)),
            target(IBS_REF_2, await catalog_product(db)),
        ]
        return ticket, actor, tracks, users
    assignee = await va_user()
    ticket = await cveless(ticket_factory, status=RESOLVED, assignee_id=assignee.id)
    package = await seed_package(db, ticket.id, PKG)
    track = await seed_track(
        db,
        package,
        IBS_REF,
        status=PackageStatus.FIXED,
        delivery=DeliveryStatus.RELEASED,
    )
    released = await catalog_product(db)
    await seed_occurrence(db, track, released, released=True)
    tracks = [
        target(IBS_REF, released, await catalog_product(db)),
        target(IBS_REF_2, await catalog_product(db)),
    ]
    return ticket, None, tracks, users


@pytest.mark.integration
class TestRollback:
    """Every failure propagates unchanged; after the caller's rollback the
    package tree, associations, Ticket status and assignee, events, and
    pending convergence effects equal the pre-call state."""

    @pytest.mark.parametrize("scenario", SCENARIOS)
    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_rolls_back_the_whole_invocation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        system_setting_factory: SettingFactory,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
        failure: str,
    ) -> None:
        if failure != "settings-missing":
            await system_setting_factory(
                key="default_cvss_version",
                value="3.0" if failure == "invalid-default-version" else "3.1",
            )
        ticket, actor, tracks, _ = await _scenario(
            db_session, scenario, ticket_factory, va_user
        )
        ticket_id = ticket.id
        before = await snapshot(db_session, ticket_id)
        assert (before[1], before[3], before[4]) == ([[]], [[]], ())
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_log = TicketAuditLog.log_event
        original_execute = db_session.execute
        original_flush = db_session.flush
        evaluator = evaluate_product_eligibility
        in_reconcile = reconciled = False
        maintainer_events = evaluations = 0

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            nonlocal in_reconcile, reconciled
            if failure == "reconcile-before":
                raise RuntimeError("injected reconciliation failure")
            in_reconcile = True
            await original_reconcile(*args, **kwargs)
            reconciled = True
            if failure == "reconcile-after":
                raise RuntimeError("injected reconciliation failure")

        async def log_event(*args: Any, **kwargs: Any) -> None:
            nonlocal maintainer_events
            event_type = kwargs["event_type"]
            if event_type is TicketAuditEventType.PACKAGE_MAINTAINER_ADDED:
                maintainer_events += 1
                if failure == "audit-maintainer" and maintainer_events == 2:
                    raise RuntimeError("injected audit failure")
            if (
                failure == "audit-package-added"
                and event_type is TicketAuditEventType.PACKAGE_ADDED
            ):
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        def evaluate(**kwargs: Any) -> Any:
            nonlocal evaluations
            evaluations += 1
            if evaluations == 2:
                raise RuntimeError("injected eligibility failure")
            return evaluator(**kwargs)

        async def execute(*args: Any, **kwargs: Any) -> Any:
            if in_reconcile:
                raise OperationalError(
                    "SELECT", None, Exception("injected database failure")
                )
            return await original_execute(*args, **kwargs)

        async def flush(*args: Any, **kwargs: Any) -> None:
            inserting = any(isinstance(o, TicketPackageProduct) for o in db_session.new)
            if (failure == "tree-flush" and inserting) or (
                failure == "final-flush" and reconciled
            ):
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
            if failure == "eligibility":
                monkeypatch.setattr(
                    package_service, "evaluate_product_eligibility", evaluate
                )
            elif failure == "database":
                monkeypatch.setattr(db_session, "execute", execute)
            elif failure in {"tree-flush", "final-flush"}:
                monkeypatch.setattr(db_session, "flush", flush)

            with pytest.raises(EXPECTED_ERRORS.get(failure, RuntimeError)):
                await add_records(
                    db_session,
                    ticket_id,
                    PKG,
                    tracks,
                    actor=actor,
                    emails={"maint.rb.low@example.com", "maint.rb.high@example.com"},
                )

            monkeypatch.undo()
            if scenario == "system-resolved-regression" and reconciled:
                # The regression registered its effect before the failure.
                assert pending_ticket_convergence_effects(db_session) == (
                    TicketConvergenceEffect(ticket_id),
                )

        assert await snapshot(db_session, ticket_id) == before

    @pytest.mark.parametrize("scenario", SCENARIOS)
    async def test_unfailed_scenario_has_the_effects_rolled_back_above(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        system_setting_factory: SettingFactory,
        scenario: str,
    ) -> None:
        """Control for the rollback cases: without a failure each scenario
        creates its records, associations, assignment or regression, and
        events, so the rollback assertions are not vacuous."""
        await system_setting_factory(key="default_cvss_version", value="3.1")
        ticket, actor, tracks, (low, high) = await _scenario(
            db_session, scenario, ticket_factory, va_user
        )
        before = await snapshot(db_session, ticket.id)

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            tracks,
            actor=actor,
            emails={"maint.rb.low@example.com", "maint.rb.high@example.com"},
        )

        assert result.outcome is PackageRecordsOutcome.PACKAGE_TREE_CHANGED
        assert await maintainers(db_session, ticket.id) == sorted(
            [(PKG, low.id), (PKG, high.id)]
        )
        maintainer_events = [maintainer_event(PKG, low), maintainer_event(PKG, high)]
        if actor is not None:
            assert await ticket_events(db_session, ticket) == [
                assignment_event(actor),
                status_event(NEW, ANALYSIS),
                *maintainer_events,
                package_added_event(PKG, actor),
            ]
        else:
            assert await ticket_events(db_session, ticket) == [
                *maintainer_events,
                package_added_event(PKG, comment="CVE package resolution"),
                status_event(RESOLVED, ANALYSIS),
            ]
            assert pending_ticket_convergence_effects(db_session) == (
                TicketConvergenceEffect(ticket.id),
            )
        assert await snapshot(db_session, ticket.id) != before


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestUniqueConstraintBackstop:
    async def test_maintainer_unique_violation_propagates_and_rolls_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The existing-association read is forced to miss a persisted
        association (the residual race the unique constraint protects
        against). The duplicate insert is a database failure, never a skip:
        `IntegrityError` propagates and the caller's rollback discards the
        new track, the assignment, and every event."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        tracks, _ = await _complete(db_session, ticket)
        tracks.append(target(IBS_REF_2, await catalog_product(db_session)))
        existing = await seed_user(db_session, email="maint.backstop@example.com")
        own = (
            await db_session.execute(
                select(TicketPackage).where(
                    TicketPackage.ticket_id == ticket.id,
                    TicketPackage.package_name == PKG,
                )
            )
        ).scalar_one()
        await seed_maintainer(db_session, own, existing)
        ticket_id = ticket.id
        before = await snapshot(db_session, ticket_id)
        original_execute = db_session.execute
        hidden: list[str] = []

        async def execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            if isinstance(statement, Select) and str(statement).startswith(
                "SELECT ticket_package_maintainer.user_id"
            ):
                hidden.append(str(statement))
                statement = statement.where(false())
            return await original_execute(statement, *args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(db_session, "execute", execute)
            with pytest.raises(IntegrityError):
                await add_records(
                    db_session,
                    ticket_id,
                    PKG,
                    tracks,
                    actor=actor,
                    emails={"maint.backstop@example.com"},
                )
            monkeypatch.undo()

        assert len(hidden) == 1
        assert await snapshot(db_session, ticket_id) == before
