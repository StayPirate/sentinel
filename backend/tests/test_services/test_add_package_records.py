"""Single-session service integration tests for the package-record creation
boundary `package_service.add_package_records()`
(backend/app/services/package_service.py), part A: behavior.

Owning specifications:

- docs/features/packages/package-service.md (`add_package_records()`
  steps 1-14, Idempotency, Concurrent outcomes; Auto-Assignment Rule;
  Record Creation Logic; Architectural Test Requirement: Forward and
  Backward transitions, Auto-assignment, Maintainership acquisition (the
  locked-mutation parts), Package creation concurrency and result truth
  (single-session outcomes), Package audit comments, Dimension
  independence).
- docs/features/packages/package-maintainership.md (Add-only acquisition;
  Email Extraction: exact equality against lowercase `User.email`;
  Acquisition Workflow > Locked mutation and Audit event; Security and
  Privacy; Testing Requirements, locked-mutation bullets).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Interaction
  with add_package_to_ticket; Adding Packages to a Ticket; Ticket Events
  for Package Changes).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `package_added`, `package_maintainer_added`; Canonical Automatic Comment
  Vocabulary; Canonical Mutation and No-Event Matrix: "Package-tree
  creation or completion"; Cross-Event Ordering, Locking, and Rollback;
  detail JSONB Schema Contract; Testing Requirements 1-6, 11, 12, 22, 25).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`
  steps 3-5; Transaction-Local Ticket Convergence Registration).
- docs/features/platform/testing-strategy.md (Service Functions; Audit
  Trail Testing).

The caller contract, guards and their order, and whole-invocation rollback
are covered by `tests/test_services/test_add_package_records_scope.py`;
independent-session races by
`tests/test_services/test_add_package_records_atomicity.py`.

Unless a test states otherwise: the `default_cvss_version` setting is
`3.1`; the service's UTC date is the controlled `EVAL`; a Ticket is
CVE-less with `severity_manual = High` (Eligibility Score Resolution: the
`10.0` fallback); and a catalog Product is in General Support on `EVAL`
with a `NULL` threshold, so a created occurrence is eligible. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import date, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import Mock

import pytest
from celery import Celery
from celery.app.task import Task
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    PackageStatus,
    Role,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.user import User
from app.services import package_service
from app.services.cvss import resolve_eligibility_score
from app.services.package_service import (
    CreatedTrack,
    PackageAddedComment,
    PackageRecordsOutcome,
    PackageRecordsResult,
    ResolvedTrackData,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    Assessment,
    CVEBuilder,
    suse_eligibility,
)
from tests.support.no_outbound import OutboundGuard
from tests.support.package_records import (
    NEW_TRACK,
    SEEDED_AT,
    SYSTEM_COMMENTS,
    OccurrenceState,
    TrackState,
    Tree,
    add_records,
    assert_no_effects,
    catalog_product,
    changed,
    maintainer_event,
    maintainers,
    new_occurrence,
    outcome,
    package_added_event,
    package_tree,
    seed_maintainer,
    seed_occurrence,
    seed_package,
    seed_track,
    seed_user,
    target,
    ticket_row,
    track_ids,
)
from tests.support.suse_cvss import assignment_event
from tests.support.ticket_mutations import (
    EVAL,
    RELEASED_AT,
    StatementRecorder,
    TicketFactory,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    unassigned_event,
)
from tests.support.track_status import Spy

pytest_plugins = [
    "tests.support.ticket_mutation_fixtures",
    "tests.support.no_outbound_fixtures",
]
"""Provides the shared `va_user` and `cve_with` fixtures and `no_outbound`."""

PKG = "fictional-libexample"
ANCHOR = "fictional-anchor"
IBS_REF = "Fictional:Product:15-SP7:Update"
IBS_REF_2 = "Fictional:Product:16.0:Update"
GIT_REF = "fictional/slfo-1.1"

ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
NEW = TicketStatus.NEW
RESOLVED = TicketStatus.RESOLVED

PROMOTION = status_event(NEW, ANALYSIS)
"""The system `New -> Analysis` event of the auto-assignment."""

NEXT_DAY = EVAL + timedelta(days=1)


@pytest.fixture(autouse=True)
def _clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is the controlled `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
async def _default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


async def _anchor(db: AsyncSession, ticket: Ticket, status: PackageStatus) -> None:
    """An untouched package `ANCHOR` with one track of `status` and one
    eligible in-support Product (tickets.md gates: an actionable `ANALYSIS`
    track pins `Analysis`; an `AFFECTED` track with that Product allows
    `Analyzed` and blocks `Resolved`)."""
    package = await seed_package(db, ticket.id, ANCHOR)
    track = await seed_track(db, package, "Fictional:Anchor:Update", status=status)
    await seed_occurrence(db, track, await catalog_product(db))


async def _cve_ticket(
    ticket_factory: TicketFactory, cve_with: CVEBuilder, *assessments: Assessment
) -> Ticket:
    """An `Analysis` Ticket of a `High` CVE with the given assessments."""
    cve = await cve_with(*assessments, severity=Severity.HIGH)
    return await ticket_factory(cve_id=cve.id, status=ANALYSIS.value)


# ---------------------------------------------------------------------------
# First creation (package-service.md steps 10-11, 14; package-model.md,
# Adding Packages to a Ticket, step 5)
# ---------------------------------------------------------------------------

SHAPES: dict[str, list[tuple[str, WorkflowType, int]]] = {
    "ibs-only": [(IBS_REF, WorkflowType.IBS, 2), (IBS_REF_2, WorkflowType.IBS, 1)],
    "git-only": [(GIT_REF, WorkflowType.GIT, 1)],
    "mixed": [(IBS_REF, WorkflowType.IBS, 2), (GIT_REF, WorkflowType.GIT, 1)],
}
"""`(reference, workflow_type, Product count)` of each resolved track."""


@pytest.mark.integration
class TestFirstCreation:
    @pytest.mark.parametrize("shape", list(SHAPES))
    async def test_creates_package_tracks_and_products(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        shape: str,
    ) -> None:
        """New tracks start at `ANALYSIS`/`PENDING` with their supplied
        `workflow_type`; every occurrence gets its creation eligibility and
        no override. The new-track signal lists exactly the created tracks
        with their persisted IDs and workflow types."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        spec = SHAPES[shape]
        products = {
            ref: [await catalog_product(db_session) for _ in range(n)]
            for ref, _, n in spec
        }
        tracks = [target(ref, *products[ref], workflow=wf) for ref, wf, _ in spec]

        result = await add_records(db_session, ticket.id, PKG, tracks, actor=actor)

        n_products = sum(n for _, _, n in spec)
        assert outcome(result) == changed(len(spec), 0, n_products, 0)
        ids = await track_ids(db_session, ticket.id, PKG)
        assert sorted(result.created_tracks, key=lambda c: c.reference) == sorted(
            (CreatedTrack(ids[ref], ref, wf) for ref, wf, _ in spec),
            key=lambda c: c.reference,
        )
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {ref: NEW_TRACK[wf] for ref, wf, _ in spec},
            {
                (ref, p.id): new_occurrence(True)
                for ref, _, _ in spec
                for p in products[ref]
            },
        )
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, actor.id)

    async def test_same_catalog_product_under_two_tracks(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """Product distinctness is per track: one catalog Product resolved
        under two codestreams yields one occurrence beneath each track."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        shared = await catalog_product(db_session)
        tracks = [target(IBS_REF, shared), target(IBS_REF_2, shared)]

        result = await add_records(db_session, ticket.id, PKG, tracks, actor=actor)

        assert outcome(result) == changed(2, 0, 2, 0)
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {
                IBS_REF: NEW_TRACK[WorkflowType.IBS],
                IBS_REF_2: NEW_TRACK[WorkflowType.IBS],
            },
            {
                (IBS_REF, shared.id): new_occurrence(True),
                (IBS_REF_2, shared.id): new_occurrence(True),
            },
        )
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]


# ---------------------------------------------------------------------------
# Partial completion and idempotency (package-service.md steps 10-11,
# Idempotency; package-model.md, Adding Packages to a Ticket)
# ---------------------------------------------------------------------------

EXISTING_TRACKS = [
    (PackageStatus.ANALYSIS, DeliveryStatus.PENDING),
    (PackageStatus.AFFECTED, DeliveryStatus.IN_PROGRESS),
    (PackageStatus.FIXED, DeliveryStatus.RELEASED),
    (PackageStatus.NOT_AFFECTED, DeliveryStatus.PENDING),
    (PackageStatus.WONT_FIX, DeliveryStatus.IN_PROGRESS),
]


def _package_writes(recorder: StatementRecorder) -> list[str]:
    """Every recorded `UPDATE` or `DELETE` of a package-tree table."""
    return [
        s
        for s in recorder.writes()
        if s.lstrip().upper().startswith(("UPDATE TICKET_PACKAGE", "DELETE"))
    ]


@pytest.mark.integration
class TestPartialCompletion:
    """The Ticket is an assigned `Analysis` Ticket and the call user-
    attributed by its assignee, so no assignment occurs."""

    async def test_new_track_under_existing_package(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        package = await seed_package(db_session, ticket.id, PKG)
        existing = await seed_track(
            db_session,
            package,
            IBS_REF,
            status=PackageStatus.AFFECTED,
            delivery=DeliveryStatus.IN_PROGRESS,
        )
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, existing, p1, eligible=False)
        p2 = await catalog_product(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await add_records(
                db_session,
                ticket.id,
                PKG,
                [target(IBS_REF, p1), target(GIT_REF, p2, workflow=WorkflowType.GIT)],
                actor=actor,
            )

        ids = await track_ids(db_session, ticket.id, PKG)
        assert outcome(result) == changed(1, 1, 1, 1)
        assert result.created_tracks == (
            CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),
        )
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {
                IBS_REF: TrackState("ibs", "AFFECTED", "IN_PROGRESS", None),
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, p1.id): OccurrenceState(False, False, None, None),
                (GIT_REF, p2.id): new_occurrence(True),
            },
        )
        assert _package_writes(recorder) == []
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]

    @pytest.mark.parametrize(
        ("status", "delivery"), EXISTING_TRACKS, ids=lambda v: str(v)
    )
    async def test_new_product_under_existing_track_keeps_track_state(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        status: PackageStatus,
        delivery: DeliveryStatus,
    ) -> None:
        """The existing track retains its affectedness and delivery and is
        not reported as created; only the new occurrence is written. An
        untouched `ANALYSIS` anchor pins the Ticket at `Analysis`."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        await _anchor(db_session, ticket, PackageStatus.ANALYSIS)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(
            db_session, package, IBS_REF, status=status, delivery=delivery
        )
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, track, p1, released=True)
        p2 = await catalog_product(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await add_records(
                db_session, ticket.id, PKG, [target(IBS_REF, p1, p2)], actor=actor
            )

        assert outcome(result) == changed(0, 1, 1, 1)
        assert result.created_tracks == ()
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: TrackState("ibs", status.value, delivery.value, None)},
            {
                (IBS_REF, p1.id): OccurrenceState(True, False, RELEASED_AT, None),
                (IBS_REF, p2.id): new_occurrence(True),
            },
        )
        assert _package_writes(recorder) == []
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, actor.id)

    async def test_soft_deleted_track_is_skipped_and_never_restored(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """An existing excluded track counts as skipped and keeps its
        marker; a missing Product beneath it is created with
        `deleted_at = NULL` (excluded through the hierarchy)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(
            db_session, package, IBS_REF, status=PackageStatus.AFFECTED, excluded=True
        )
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, track, p1)
        p2 = await catalog_product(db_session)

        result = await add_records(
            db_session, ticket.id, PKG, [target(IBS_REF, p1, p2)], actor=actor
        )

        assert outcome(result) == changed(0, 1, 1, 1)
        assert result.created_tracks == ()
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: TrackState("ibs", "AFFECTED", "PENDING", SEEDED_AT)},
            {
                (IBS_REF, p1.id): OccurrenceState(True, False, None, None),
                (IBS_REF, p2.id): new_occurrence(True),
            },
        )
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]

    async def test_soft_deleted_product_is_skipped_and_never_restored(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(db_session, package, IBS_REF)
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, track, p1, eligible=False, excluded=True)
        p2 = await catalog_product(db_session)

        result = await add_records(
            db_session, ticket.id, PKG, [target(IBS_REF, p1, p2)], actor=actor
        )

        assert outcome(result) == changed(0, 1, 1, 1)
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {
                (IBS_REF, p1.id): OccurrenceState(False, False, None, SEEDED_AT),
                (IBS_REF, p2.id): new_occurrence(True),
            },
        )
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]

    async def test_existing_track_without_products_is_completed(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """An existing track that has no Product occurrence is skipped as a
        track, and every supplied Product is created beneath it."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        package = await seed_package(db_session, ticket.id, PKG)
        await seed_track(db_session, package, IBS_REF)
        p1 = await catalog_product(db_session)

        result = await add_records(
            db_session, ticket.id, PKG, [target(IBS_REF, p1)], actor=actor
        )

        assert outcome(result) == changed(0, 1, 1, 0)
        assert result.created_tracks == ()
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            None,
            {IBS_REF: NEW_TRACK[WorkflowType.IBS]},
            {(IBS_REF, p1.id): new_occurrence(True)},
        )
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]

    async def test_existing_workflow_type_is_never_rewritten(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """A supplied `workflow_type` differing from an existing track's is
        not applied: the track is skipped unchanged."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=actor.id)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(db_session, package, IBS_REF)
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, track, p1)
        p2 = await catalog_product(db_session)

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, p1, p2, workflow=WorkflowType.GIT)],
            actor=actor,
        )

        assert outcome(result) == changed(0, 1, 1, 1)
        tree = await package_tree(db_session, ticket.id, PKG)
        assert tree is not None
        assert tree.tracks == {IBS_REF: NEW_TRACK[WorkflowType.IBS]}


@pytest.mark.integration
class TestIdempotency:
    @pytest.mark.parametrize("context", ["user", "system"])
    async def test_repeated_unchanged_call_is_a_complete_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        """The second call with the same tracks and emails reports every
        record as skipped and has no write, assignment, audit,
        reconciliation, or convergence effect."""
        actor = await va_user() if context == "user" else None
        ticket = await cveless(ticket_factory, status=NEW)
        maintainer = await seed_user(db_session, email="maint.repeat@example.com")
        p1, p2, p3 = [await catalog_product(db_session) for _ in range(3)]
        tracks = [
            target(IBS_REF, p1, p2),
            target(GIT_REF, p3, workflow=WorkflowType.GIT),
        ]
        emails = {"maint.repeat@example.com"}
        first = await add_records(
            db_session, ticket.id, PKG, tracks, actor=actor, emails=emails
        )
        assert outcome(first) == changed(2, 0, 3, 0)
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]

        second = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: add_records(
                db_session, ticket.id, PKG, tracks, actor=actor, emails=emails
            ),
            ticket_ids=(ticket.id,),
        )

        assert second == PackageRecordsResult(
            outcome=PackageRecordsOutcome.PACKAGE_TREE_NO_OP,
            tracks_created=0,
            tracks_skipped=2,
            products_created=0,
            products_skipped=3,
            created_tracks=(),
        )


# ---------------------------------------------------------------------------
# Creation eligibility (package-model.md, Axis 2: Eligibility rules 2-5;
# cvss-scoring.md, Eligibility Score Resolution; package-service.md, Record
# Creation Logic)
# ---------------------------------------------------------------------------


async def _created_eligibility(
    db: AsyncSession,
    ticket: Ticket,
    product: Product,
    *,
    comment: PackageAddedComment = "CVE package resolution",
    reresolution: bool = False,
    package_name: str = PKG,
    reference: str = IBS_REF,
) -> bool:
    """Create one occurrence of `product` by a system call and return its
    persisted `eligible` (asserting no override was set)."""
    result = await add_records(
        db,
        ticket.id,
        package_name,
        [target(reference, product)],
        comment=comment,
        reresolution=reresolution,
    )
    assert result.products_created == 1
    tree = await package_tree(db, ticket.id, package_name)
    assert tree is not None
    state = tree.occurrences[reference, product.id]
    assert (state.is_eligible_override, state.deleted_at) == (False, None)
    return state.eligible


@pytest.mark.integration
class TestCreationEligibility:
    """The database default `eligible = true` is never what a test observes
    as `false`; a `true` expectation is paired with a `false` one over the
    same rule to exclude the default."""

    @pytest.mark.parametrize(
        ("score", "threshold", "expected"),
        [
            pytest.param("0.0", None, True, id="null-threshold-is-zero"),
            pytest.param("7.0", "7.1", False, id="score-below-threshold"),
            pytest.param("7.0", "7.0", True, id="score-equals-threshold"),
            pytest.param("7.0", "6.9", True, id="score-above-threshold"),
        ],
    )
    async def test_canonical_suse_score_at_the_default_version(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        score: str,
        threshold: str | None,
        expected: bool,
    ) -> None:
        """Rules 3-5: the SUSE assessment at the default version `3.1`
        decides; a non-default SUSE version and another provider at the
        default version are ignored."""
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment(score),
            Assessment("10.0", version="3.0"),
            Assessment("10.0", provider="NVD"),
        )
        product = await catalog_product(db_session, threshold=threshold)

        assert await _created_eligibility(db_session, ticket, product) is expected

    @pytest.mark.parametrize(
        ("threshold", "expected"),
        [("9.9", True), ("10.0", True)],
        ids=["below-fallback", "equals-fallback"],
    )
    @pytest.mark.parametrize(
        "case", ["other-suse-version", "other-provider", "no-assessment", "cve-less"]
    )
    async def test_fallback_score_without_a_default_version_suse_assessment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        case: str,
        threshold: str,
        expected: bool,
    ) -> None:
        """Rule 4: without the canonical SUSE assessment at the default
        version the score is `10.0`, including for a CVE-less Ticket; a
        low score of another version or provider is never used."""
        assessments = {
            "other-suse-version": (Assessment("1.0", version="3.0"),),
            "other-provider": (Assessment("1.0", provider="NVD"),),
            "no-assessment": (),
        }
        if case == "cve-less":
            ticket = await cveless(ticket_factory)
        else:
            ticket = await _cve_ticket(ticket_factory, cve_with, *assessments[case])
        product = await catalog_product(db_session, threshold=threshold)

        assert await _created_eligibility(db_session, ticket, product) is expected

    async def test_reactive_support_forces_false(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Rule 2: Reactive Support is `false` despite the `10.0` fallback
        over the implicit `0.0` threshold."""
        ticket = await cveless(ticket_factory)
        product = await catalog_product(db_session, lifecycle="reactive")

        assert await _created_eligibility(db_session, ticket, product) is False

    @pytest.mark.parametrize(
        ("threshold", "expected"), [("6.0", True), ("8.0", False)], ids=str
    )
    @pytest.mark.parametrize("lifecycle", ["none", "eol"])
    async def test_unavailable_or_eol_lifecycle_forces_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        lifecycle: str,
        threshold: str,
        expected: bool,
    ) -> None:
        """Rule 2: a `NULL` lifecycle phase forces neither value, and EOL is
        not a formula input: an EOL Product is still evaluated. The SUSE
        7.0 threshold comparison decides."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        product = await catalog_product(
            db_session, threshold=threshold, lifecycle=lifecycle
        )

        assert await _created_eligibility(db_session, ticket, product) is expected

    @pytest.mark.parametrize(
        ("threshold", "expected"), [("6.0", True), ("8.0", False)], ids=str
    )
    @pytest.mark.parametrize(
        "placement",
        ["excluded-track", "excluded-package-reresolution", "fixed-released-track"],
    )
    async def test_excluded_and_final_parents_are_not_formula_inputs(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        placement: str,
        threshold: str,
        expected: bool,
    ) -> None:
        """Dimension independence: a new occurrence beneath a directly
        excluded track, beneath a directly excluded package (Ticket
        convergence re-resolution), or beneath a `FIXED`/`RELEASED` track
        is evaluated by the same formula (SUSE 7.0 against the threshold)."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        package = await seed_package(
            db_session,
            ticket.id,
            PKG,
            excluded=placement == "excluded-package-reresolution",
        )
        track = await seed_track(
            db_session,
            package,
            IBS_REF,
            status=(
                PackageStatus.FIXED
                if placement == "fixed-released-track"
                else PackageStatus.ANALYSIS
            ),
            delivery=(
                DeliveryStatus.RELEASED
                if placement == "fixed-released-track"
                else DeliveryStatus.PENDING
            ),
            excluded=placement == "excluded-track",
        )
        await seed_occurrence(
            db_session, track, await catalog_product(db_session), released=True
        )
        product = await catalog_product(db_session, threshold=threshold)
        reresolution = placement == "excluded-package-reresolution"

        eligible = await _created_eligibility(
            db_session,
            ticket,
            product,
            comment="Ticket convergence" if reresolution else "CVE package resolution",
            reresolution=reresolution,
        )

        assert eligible is expected

    async def test_one_shared_evaluator_and_one_score_resolution_per_call(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each new occurrence is evaluated by the shared pure evaluator
        with no override, its lifecycle phase on `EVAL`, its threshold, and
        the one Eligibility Score Resolution of the call; the persisted
        value is the evaluator's. Existing occurrences are not evaluated."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        general = await catalog_product(db_session, threshold="6.0")
        reactive = await catalog_product(db_session, lifecycle="reactive")
        unavailable = await catalog_product(
            db_session, threshold="8.0", lifecycle="none"
        )
        eol = await catalog_product(db_session, threshold="9.0", lifecycle="eol")
        existing = await catalog_product(db_session)
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(db_session, package, IBS_REF)
        await seed_occurrence(db_session, track, existing, eligible=False)
        evaluated: list[dict[str, Any]] = []
        resolutions: list[object] = []
        evaluator = evaluate_product_eligibility
        resolver = resolve_eligibility_score

        def _evaluate(**kwargs: Any) -> Any:
            evaluated.append(kwargs)
            return evaluator(**kwargs)

        def _resolve(*args: Any, **kwargs: Any) -> Any:
            resolution = resolver(*args, **kwargs)
            resolutions.append(resolution)
            return resolution

        monkeypatch.setattr(package_service, "evaluate_product_eligibility", _evaluate)
        monkeypatch.setattr(package_service, "resolve_eligibility_score", _resolve)

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [
                target(IBS_REF, existing, general, reactive),
                target(GIT_REF, unavailable, eol, workflow=WorkflowType.GIT),
            ],
        )

        assert outcome(result) == changed(1, 1, 4, 1)
        assert resolutions == [suse_eligibility("7.0")]
        expected_inputs = [
            (LifecyclePhase.GENERAL_SUPPORT, Decimal("6.0")),
            (LifecyclePhase.REACTIVE_SUPPORT, None),
            (None, Decimal("8.0")),
            (LifecyclePhase.EOL, Decimal("9.0")),
        ]
        assert sorted(
            (
                (c["lifecycle_phase"], c["cvss_threshold"])
                for c in evaluated
                if c["is_eligible_override"] is False
                and c["eligibility_score"] == suse_eligibility("7.0")
            ),
            key=repr,
        ) == sorted(expected_inputs, key=repr)
        assert len(evaluated) == 4
        tree = await package_tree(db_session, ticket.id, PKG)
        assert tree is not None
        assert {k[1]: v.eligible for k, v in tree.occurrences.items()} == {
            existing.id: False,
            general.id: True,
            reactive.id: False,
            unavailable.id: False,
            eol.id: False,
        }

    @pytest.mark.parametrize(
        ("clock", "expected_date", "eligible"),
        [
            pytest.param([EVAL], EVAL, True, id="extended-support-day"),
            pytest.param([NEXT_DAY], NEXT_DAY, False, id="reactive-support-day"),
            pytest.param([EVAL, NEXT_DAY], EVAL, True, id="crossing-midnight"),
        ],
    )
    async def test_one_evaluation_date_for_eligibility_and_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        clock: list[date],
        expected_date: date,
        eligible: bool,
    ) -> None:
        """The UTC date is captured once at entry: a Product whose Extended
        Support ends on `EVAL` enters Reactive Support on the next day
        (product-catalog.md, inclusive phase ends). A second clock reading
        would return the next day; only the first governs creation
        eligibility and the reconciliation date."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        product = await catalog_product(db_session, lifecycle="extended-ends-on-eval")
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        assert await _created_eligibility(db_session, ticket, product) is eligible
        assert utc_today.call_count == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": expected_date}
        ]


# ---------------------------------------------------------------------------
# Maintainers (package-maintainership.md, Email Extraction, Acquisition
# Workflow > Locked mutation and Audit event; ticket-audit-log.md, Testing
# Requirement 11)
# ---------------------------------------------------------------------------


async def _package(db: AsyncSession, ticket: Ticket) -> TicketPackage:
    """The persisted `TicketPackage` `PKG` of the Ticket."""
    return (
        await db.execute(
            select(TicketPackage).where(
                TicketPackage.ticket_id == ticket.id,
                TicketPackage.package_name == PKG,
            )
        )
    ).scalar_one()


async def _complete_tree(
    db: AsyncSession, ticket: Ticket
) -> tuple[list[ResolvedTrackData], Product]:
    """A persisted package `PKG` with one `ANALYSIS` track and one Product,
    and the resolved input that matches it exactly."""
    package = await seed_package(db, ticket.id, PKG)
    track = await seed_track(db, package, IBS_REF)
    product = await catalog_product(db)
    await seed_occurrence(db, track, product)
    return [target(IBS_REF, product)], product


MAINTAINER_ONLY = PackageRecordsResult(
    outcome=PackageRecordsOutcome.MAINTAINER_ONLY,
    tracks_created=0,
    tracks_skipped=1,
    products_created=0,
    products_skipped=1,
    created_tracks=(),
)
"""A maintainer-only outcome over `_complete_tree()`: the counts of the
package-tree no-op, unchanged by the associations."""


@pytest.mark.integration
class TestMaintainers:
    async def test_exact_active_matches_in_ascending_user_id_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Only exact lowercase-email matches of active Users are associated,
        whatever their roles; an uppercase variant, an unknown email, and an
        inactive User are skipped. Events follow ascending `User.id`, not
        creation order."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        low_id, high_id = sorted(uuid.uuid4() for _ in range(2))
        high = await seed_user(
            db_session, email="maint.high@example.com", user_id=high_id
        )
        low = await seed_user(
            db_session, email="maint.low@example.com", user_id=low_id, roles=()
        )
        await seed_user(db_session, email="maint.inactive@example.com", active=False)
        await seed_user(db_session, email="maint.case@example.com")
        product = await catalog_product(db_session)

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, product)],
            emails={
                "maint.high@example.com",
                "maint.low@example.com",
                "maint.inactive@example.com",
                "MAINT.CASE@EXAMPLE.COM",
                "maint.unknown@example.com",
            },
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await maintainers(db_session, ticket.id) == [
            (PKG, low.id),
            (PKG, high.id),
        ]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, low),
            maintainer_event(PKG, high),
            package_added_event(PKG, comment="CVE package resolution"),
        ]

    async def test_existing_association_is_retained_and_skipped(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        tracks, _ = await _complete_tree(db_session, ticket)
        existing = await seed_user(db_session, email="maint.existing@example.com")
        package = await _package(db_session, ticket)
        await seed_maintainer(db_session, package, existing)
        new = await seed_user(db_session, email="maint.new@example.com")

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            tracks,
            emails={"maint.existing@example.com", "maint.new@example.com"},
        )

        assert result == MAINTAINER_ONLY
        assert await maintainers(db_session, ticket.id) == sorted(
            [(PKG, existing.id), (PKG, new.id)]
        )
        assert await ticket_events(db_session, ticket) == [maintainer_event(PKG, new)]

    @pytest.mark.parametrize("tree_change", [False, True], ids=["no-op", "new-track"])
    async def test_empty_email_set_removes_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        tree_change: bool,
    ) -> None:
        """A later empty result (no maintainers or a non-blocking failure)
        never removes an association and creates no maintainer event."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        tracks, _ = await _complete_tree(db_session, ticket)
        existing = await seed_user(db_session, email="maint.kept@example.com")
        await seed_maintainer(db_session, await _package(db_session, ticket), existing)
        if tree_change:
            tracks.append(target(IBS_REF_2, await catalog_product(db_session)))
            result = await add_records(db_session, ticket.id, PKG, tracks, emails=())
            assert outcome(result) == changed(1, 1, 1, 1)
            assert await ticket_events(db_session, ticket) == [
                package_added_event(PKG, comment="CVE package resolution")
            ]
        else:
            await assert_no_effects(
                db_session,
                monkeypatch,
                lambda: add_records(db_session, ticket.id, PKG, tracks, emails=()),
                ticket_ids=(ticket.id,),
            )
        assert await maintainers(db_session, ticket.id) == [(PKG, existing.id)]

    async def test_acquisition_after_later_user_creation_and_reactivation(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """A first call finds no active match; after the User is created and
        another reactivated, an unchanged re-invocation associates both as
        a maintainer-only mutation, in ascending `User.id` order."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        low_id, high_id = sorted(uuid.uuid4() for _ in range(2))
        dormant = await seed_user(
            db_session,
            email="maint.dormant@example.com",
            active=False,
            user_id=high_id,
        )
        product = await catalog_product(db_session)
        tracks = [target(IBS_REF, product)]
        emails = {"maint.later@example.com", "maint.dormant@example.com"}

        first = await add_records(db_session, ticket.id, PKG, tracks, emails=emails)
        assert outcome(first) == changed(1, 0, 1, 0)
        assert await maintainers(db_session, ticket.id) == []

        later = await seed_user(
            db_session, email="maint.later@example.com", user_id=low_id
        )
        dormant.active = True
        await db_session.flush()

        second = await add_records(db_session, ticket.id, PKG, tracks, emails=emails)

        assert second == MAINTAINER_ONLY
        assert await maintainers(db_session, ticket.id) == [
            (PKG, later.id),
            (PKG, dormant.id),
        ]
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, comment="CVE package resolution"),
            maintainer_event(PKG, later),
            maintainer_event(PKG, dormant),
        ]

    @pytest.mark.parametrize("context", ["user-unassigned-new", "system-stale-gate"])
    async def test_maintainer_only_mutation_neither_assigns_nor_reconciles(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        context: str,
    ) -> None:
        """`user-unassigned-new`: an active VA on an unassigned `New`
        Ticket would be assigned by a package-tree change. `system-stale-
        gate`: an `Analysis` Ticket whose only track is `NOT_AFFECTED`
        would be reconciled to `Resolved`. The association-only mutation
        does neither, creates no `package_added`, registers no effect, and
        reports the package-tree no-op counts."""
        if context == "user-unassigned-new":
            actor: User | None = await va_user()
            ticket = await cveless(ticket_factory, status=NEW)
            tracks, _ = await _complete_tree(db_session, ticket)
            before: tuple[str, uuid.UUID | None] = (NEW.value, None)
        else:
            actor = None
            assignee = await va_user()
            ticket = await cveless(
                ticket_factory, status=ANALYSIS, assignee_id=assignee.id
            )
            package = await seed_package(db_session, ticket.id, PKG)
            track = await seed_track(
                db_session, package, IBS_REF, status=PackageStatus.NOT_AFFECTED
            )
            product = await catalog_product(db_session)
            await seed_occurrence(db_session, track, product)
            tracks = [target(IBS_REF, product)]
            before = (ANALYSIS.value, assignee.id)
        maintainer = await seed_user(db_session, email="maint.only@example.com")
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            tracks,
            actor=actor,
            emails={"maint.only@example.com"},
        )

        assert result == MAINTAINER_ONLY
        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await ticket_row(db_session, ticket.id) == before
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer)
        ]

    async def test_both_kinds_keep_assignment_and_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A package-tree change together with an association keeps the
        normal auto-assignment, `package_added`, and one reconciliation;
        the maintainer event stays system-attributed."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        maintainer = await seed_user(db_session, email="maint.both@example.com")
        product = await catalog_product(db_session)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, product)],
            actor=actor,
            emails={"maint.both@example.com"},
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        assert len(reconcile.calls) == 1
        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            maintainer_event(PKG, maintainer),
            package_added_event(PKG, actor),
        ]


# ---------------------------------------------------------------------------
# Audit (ticket-audit-log.md, Event Type Contract, Canonical Automatic
# Comment Vocabulary, Cross-Event Ordering; Testing Requirements 1-6, 22, 25)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAudit:
    @pytest.mark.parametrize("context", ["user", *SYSTEM_COMMENTS])
    async def test_package_added_actor_and_comment_per_context(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        context: str,
    ) -> None:
        """Manual addition: the acting user and `comment = NULL`. Each
        automatic context: `user_id = NULL` and its exact canonical
        comment. `new_value` is the package name; `old_value` and `detail`
        are `NULL`."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        actor = assignee if context == "user" else None
        comment: Any = None if context == "user" else context

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            actor=actor,
            comment=comment or "CVE package resolution",
        )

        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor, comment)
        ]

    async def test_order_assignment_maintainers_package_added_then_gate(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """An unassigned `New` Ticket with an `AFFECTED` anchor; the new
        package's only Product is EOL, so its new `ANALYSIS` track is not
        actionable and the final gate is `Analyzed`. Order: assignment,
        `New -> Analysis`, maintainer events by `User.id`, `package_added`,
        then the gate `status_change`."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        await _anchor(db_session, ticket, PackageStatus.AFFECTED)
        low_id, high_id = sorted(uuid.uuid4() for _ in range(2))
        high = await seed_user(db_session, email="maint.b@example.com", user_id=high_id)
        low = await seed_user(db_session, email="maint.a@example.com", user_id=low_id)
        product = await catalog_product(db_session, lifecycle="eol")

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, product)],
            actor=actor,
            emails={"maint.a@example.com", "maint.b@example.com"},
        )

        assert await ticket_row(db_session, ticket.id) == (ANALYZED, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            maintainer_event(PKG, low),
            maintainer_event(PKG, high),
            package_added_event(PKG, actor),
            status_event(ANALYSIS, ANALYZED),
        ]

    @pytest.mark.parametrize(
        ("active", "roles", "reason"),
        [
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), "inactive assignee", id="inactive"
            ),
            pytest.param(
                True, (), "vulnerability_analyst role removed", id="active-non-va"
            ),
        ],
    )
    async def test_order_package_added_then_sanitation_then_gate(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
    ) -> None:
        """An `Analyzed` Ticket assigned to an ineligible User: the new
        `ANALYSIS` track regresses it to `Analysis`, so reconciliation
        clears the assignee. Order: maintainer event, `package_added`, the
        system sanitation `assignment`, then the gate `status_change`."""
        assignee = await seed_user(db_session, active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=ANALYZED, assignee_id=assignee.id)
        await _anchor(db_session, ticket, PackageStatus.AFFECTED)
        maintainer = await seed_user(db_session, email="maint.order@example.com")

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            emails={"maint.order@example.com"},
        )

        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, None)
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer),
            package_added_event(PKG, comment="CVE package resolution"),
            unassigned_event(assignee.username, reason),
            status_event(ANALYZED, ANALYSIS),
        ]

    @pytest.mark.parametrize("repeat", [False, True], ids=["changed", "no-op"])
    async def test_audit_history_is_never_read(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_audit_event_factory: Callable[..., Awaitable[Any]],
        va_user: VAUser,
        repeat: bool,
    ) -> None:
        """Testing Requirement 25: a misleading earlier `package_added` and
        `package_maintainer_added` do not make a missing record or
        association look present; the call only inserts events."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        maintainer = await seed_user(db_session, email="maint.history@example.com")
        for event_type, value, detail in [
            ("package_added", PKG, None),
            ("package_maintainer_added", maintainer.username, {"package": PKG}),
        ]:
            await ticket_audit_event_factory(
                ticket_id=ticket.id,
                event_type=event_type,
                new_value=value,
                comment="CVE package resolution" if detail is None else None,
                detail=detail,
            )
        tracks = [target(IBS_REF, await catalog_product(db_session))]
        emails = {"maint.history@example.com"}
        if repeat:
            await add_records(db_session, ticket.id, PKG, tracks, emails=emails)

        with StatementRecorder(db_session) as recorder:
            result = await add_records(
                db_session, ticket.id, PKG, tracks, emails=emails
            )

        assert result.outcome is (
            PackageRecordsOutcome.PACKAGE_TREE_NO_OP
            if repeat
            else PackageRecordsOutcome.PACKAGE_TREE_CHANGED
        )
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]
        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert recorder.selects_from("ticket_audit_event") == []
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []
        assert bool(audit) is not repeat


# ---------------------------------------------------------------------------
# Gates and assignment (package-service.md, Auto-Assignment Rule and
# Architectural Test Requirement: Forward/Backward transitions,
# Auto-assignment)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGatesAndAssignment:
    async def test_active_va_assigns_and_promotes_an_unassigned_new_ticket(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            actor=actor,
        )

        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            package_added_event(PKG, actor),
        ]

    @pytest.mark.parametrize(
        ("active", "roles"),
        [(True, ()), (False, (Role.VULNERABILITY_ANALYST,))],
        ids=["non-va", "inactive-va"],
    )
    async def test_ineligible_actor_does_not_assign(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        """The mutation proceeds without assignment; reconciliation leaves a
        `New` Ticket unchanged."""
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=NEW)

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            actor=actor,
        )

        assert outcome(result) == changed(1, 0, 1, 0)
        assert await ticket_row(db_session, ticket.id) == (NEW, None)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor)
        ]

    @pytest.mark.parametrize("status", [NEW, ANALYSIS], ids=str)
    @pytest.mark.parametrize("comment", SYSTEM_COMMENTS)
    async def test_system_calls_never_assign(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
        comment: PackageAddedComment,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status)

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            comment=comment,
            reresolution=comment == "Ticket convergence",
        )

        assert await ticket_row(db_session, ticket.id) == (status, None)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, comment=comment)
        ]

    async def test_new_analysis_track_regresses_analyzed(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYZED, assignee_id=actor.id)
        await _anchor(db_session, ticket, PackageStatus.AFFECTED)

        await add_records(
            db_session,
            ticket.id,
            PKG,
            [target(IBS_REF, await catalog_product(db_session))],
            actor=actor,
        )

        assert await ticket_row(db_session, ticket.id) == (ANALYSIS, actor.id)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor),
            status_event(ANALYZED, ANALYSIS),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unreleased_product_under_fixed_track_regresses_resolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        """A CVE Ticket (SUSE 3.1 7.0, so the `FIXED` release condition
        applies) whose `FIXED` track's only eligible Product is released is
        `Resolved`. A new eligible (7.0 against the implicit `0.0`)
        unreleased Product beneath it breaks resolution completeness:
        `Resolved -> Analyzed` and exactly one Ticket convergence effect,
        discarded when the transaction ends (ticket-mutations.md,
        `reconcile_ticket_status()` step 5)."""
        actor = await va_user()
        cve = await cve_with(Assessment("7.0"), severity=Severity.HIGH)
        ticket = await ticket_factory(
            cve_id=cve.id, status=RESOLVED.value, assignee_id=actor.id
        )
        package = await seed_package(db_session, ticket.id, PKG)
        track = await seed_track(
            db_session,
            package,
            IBS_REF,
            status=PackageStatus.FIXED,
            delivery=DeliveryStatus.RELEASED,
        )
        p1 = await catalog_product(db_session)
        await seed_occurrence(db_session, track, p1, released=True)
        p2 = await catalog_product(db_session)

        result = await add_records(
            db_session, ticket.id, PKG, [target(IBS_REF, p1, p2)], actor=actor
        )

        assert outcome(result) == changed(0, 1, 1, 1)
        assert await ticket_row(db_session, ticket.id) == (ANALYZED, actor.id)
        assert await ticket_events(db_session, ticket) == [
            package_added_event(PKG, actor),
            status_event(RESOLVED, ANALYZED),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )
        await db_session.commit()
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Re-resolution mode (package-model.md, Interaction with
# add_package_to_ticket; package-service.md step 6 and Concurrency Control)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReresolutionMode:
    async def test_completes_beneath_an_excluded_package_without_clearing_markers(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """Ticket convergence beneath a directly excluded package with an
        excluded track and an excluded Product creates the missing track,
        occurrences, and association with `deleted_at = NULL`, skips the
        existing records, and leaves every marker unchanged."""
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        package = await seed_package(db_session, ticket.id, PKG, excluded=True)
        excluded_track = await seed_track(db_session, package, IBS_REF, excluded=True)
        included_track = await seed_track(db_session, package, IBS_REF_2)
        p1, p2, p3, p4, p5 = [await catalog_product(db_session) for _ in range(5)]
        await seed_occurrence(db_session, excluded_track, p1)
        await seed_occurrence(db_session, included_track, p2, excluded=True)
        maintainer = await seed_user(db_session, email="maint.converge@example.com")

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [
                target(IBS_REF, p1, p3),
                target(IBS_REF_2, p2, p4),
                target(GIT_REF, p5, workflow=WorkflowType.GIT),
            ],
            emails={"maint.converge@example.com"},
            comment="Ticket convergence",
            reresolution=True,
        )

        ids = await track_ids(db_session, ticket.id, PKG)
        assert outcome(result) == changed(1, 2, 3, 2)
        assert result.created_tracks == (
            CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),
        )
        assert await package_tree(db_session, ticket.id, PKG) == Tree(
            SEEDED_AT,
            {
                IBS_REF: TrackState("ibs", "ANALYSIS", "PENDING", SEEDED_AT),
                IBS_REF_2: NEW_TRACK[WorkflowType.IBS],
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, p1.id): OccurrenceState(True, False, None, None),
                (IBS_REF, p3.id): new_occurrence(True),
                (IBS_REF_2, p2.id): OccurrenceState(True, False, None, SEEDED_AT),
                (IBS_REF_2, p4.id): new_occurrence(True),
                (GIT_REF, p5.id): new_occurrence(True),
            },
        )
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer),
            package_added_event(PKG, comment="Ticket convergence"),
        ]

    async def test_no_op_and_maintainer_only_beneath_an_excluded_package(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assignee = await va_user()
        ticket = await cveless(ticket_factory, status=ANALYSIS, assignee_id=assignee.id)
        package = await seed_package(db_session, ticket.id, PKG, excluded=True)
        track = await seed_track(db_session, package, IBS_REF)
        product = await catalog_product(db_session)
        await seed_occurrence(db_session, track, product)
        tracks = [target(IBS_REF, product)]
        maintainer = await seed_user(db_session, email="maint.latent@example.com")

        def call(emails: set[str]) -> Awaitable[PackageRecordsResult]:
            return add_records(
                db_session,
                ticket.id,
                PKG,
                tracks,
                emails=emails,
                comment="Ticket convergence",
                reresolution=True,
            )

        no_op = await assert_no_effects(
            db_session, monkeypatch, lambda: call(set()), ticket_ids=(ticket.id,)
        )
        assert no_op is not None
        assert no_op.outcome is PackageRecordsOutcome.PACKAGE_TREE_NO_OP
        monkeypatch.undo()
        monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)

        latent = await call({"maint.latent@example.com"})

        assert latent == MAINTAINER_ONLY
        assert await maintainers(db_session, ticket.id) == [(PKG, maintainer.id)]
        assert await ticket_events(db_session, ticket) == [
            maintainer_event(PKG, maintainer)
        ]
        tree = await package_tree(db_session, ticket.id, PKG)
        assert tree is not None
        assert tree.deleted_at == SEEDED_AT


# ---------------------------------------------------------------------------
# No unspecified work (package-service.md step 14 / Module invariant:
# I/O-then-Lock; package-maintainership.md, Security and Privacy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoUnspecifiedWork:
    async def test_no_external_io_and_no_post_commit_registration(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        no_outbound: OutboundGuard,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No network, Redis, or broker operation happens inside the
        function, and nothing is registered for after commit."""
        brokered: list[str] = []

        async def _redis(*args: Any, **kwargs: Any) -> Any:
            brokered.append("redis")
            raise AssertionError("add_package_records() must perform no Redis I/O")

        def _broker(*args: Any, **kwargs: Any) -> Any:
            brokered.append("broker")
            raise AssertionError("add_package_records() must not dispatch a task")

        monkeypatch.setattr(Redis, "execute_command", _redis)
        monkeypatch.setattr(Celery, "send_task", _broker)
        monkeypatch.setattr(Task, "apply_async", _broker)
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=NEW)
        await seed_user(db_session, email="maint.io@example.com")

        result = await add_records(
            db_session,
            ticket.id,
            PKG,
            [
                target(IBS_REF, await catalog_product(db_session)),
                target(
                    GIT_REF,
                    await catalog_product(db_session),
                    workflow=WorkflowType.GIT,
                ),
            ],
            actor=actor,
            emails={"maint.io@example.com"},
        )

        assert outcome(result) == changed(2, 0, 2, 0)
        assert no_outbound.attempts == []
        assert brokered == []
        assert not db_session.info.get("post_commit_callbacks")
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_no_email_or_username_in_logs(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Matched, inactive, and unmatched maintainer emails and usernames
        never reach a log record. The sanitation warning of the same
        invocation proves that logs are captured."""
        assignee = await seed_user(db_session, active=False)
        ticket = await cveless(ticket_factory, status=ANALYZED, assignee_id=assignee.id)
        await _anchor(db_session, ticket, PackageStatus.AFFECTED)
        matched = await seed_user(db_session, email="maint.logged@example.com")
        inactive = await seed_user(
            db_session, email="maint.dormant.log@example.com", active=False
        )
        emails = {
            "maint.logged@example.com",
            "maint.dormant.log@example.com",
            "maint.unknown.log@example.com",
        }

        with capture_logs() as logs:
            await add_records(
                db_session,
                ticket.id,
                PKG,
                [target(IBS_REF, await catalog_product(db_session))],
                emails=emails,
            )

        assert [log["event"] for log in logs] == ["ticket_assignee_sanitized"]
        rendered = repr(logs)
        for secret in [
            *emails,
            matched.username,
            inactive.username,
            assignee.username,
            assignee.email,
        ]:
            assert secret not in rendered
