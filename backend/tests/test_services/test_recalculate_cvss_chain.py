"""Service integration tests for `recalculate_cvss_chain()` and its shared
immediate Product propagation helper
(backend/app/services/ticket_mutations.py, CVSS chain recalculation):
argument guards, the eligibility formula and its boundaries, association
mode, and the default-version state matrix.

Classification, idempotency, rollback, the one evaluation date, and lock
order are in test_recalculate_cvss_chain_atomicity.py.

Owning specifications:

- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`:
  Parameters, Behavior 1-7, Runner-facing classification,
  TicketAuditEvent; CVSS Mutation Authority and Result: propagation
  dispositions; CVSS Status Matrix, default-version paragraph; Contract;
  Architectural Test Requirement: Eligibility formula and boundaries,
  Composed workflows, Automatic priority).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Override
  Model; Continued Updates).
- docs/features/tickets/cvss-scoring.md (Severity Resolution Cascade;
  Eligibility Score Resolution).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `severity_changed`, `product_eligibility_changed`, `priority_changed`;
  Severity value note; Canonical Mutation and No-Event Matrix:
  Default-version severity/eligibility chain, Product eligibility change;
  detail JSONB Schema Contract; Testing Requirements 1-8, 12, 17, 18, 20,
  28).
- docs/features/tickets/ticket-priority.md (Refresh Points: CVE
  association, Default CVSS version change; Testing Requirement 3).

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from decimal import Decimal

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSVersion,
    DeliveryStatus,
    PackageStatus,
    Role,
    Severity,
    TicketStatus,
)
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import settings as settings_service
from app.services.cvss import EligibilityResolution, SeverityResolution
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSChainClassification,
    CVSSChainMode,
    CVSSChainResult,
    CVSSPropagation,
    ProductPropagationSummary,
)
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    FALLBACK,
    Assessment,
    CallCounter,
    CVEBuilder,
    associate,
    cve_severity,
    eligibility,
    label,
    priority_event,
    product_event,
    run_chain,
    severity_event,
    severity_resolution,
    subjects,
    suse_eligibility,
    ticket_state,
    total_ticket_events,
)
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

DEFAULT = CVSSChainMode.DEFAULT_VERSION
ASSOCIATION = CVSSChainMode.ASSOCIATION
CHANGED = CVSSChainClassification.CHANGED
UNCHANGED = CVSSChainClassification.UNCHANGED

SUSE_CRITICAL = Assessment("9.8")
"""A canonical SUSE assessment at the default version: `Critical`, `P2`."""

SUSE_HIGH = Assessment("7.5")
"""A canonical SUSE assessment at the default version: `High`, `P3`."""

T9 = Decimal("9.0")
"""A Product threshold met by 9.8 and 10.0 but not by 7.5."""


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


def _result(
    *,
    mode: CVSSChainMode = DEFAULT,
    classification: CVSSChainClassification = CHANGED,
    severity: SeverityResolution | None,
    eligibility_resolution: EligibilityResolution | None,
    propagation: CVSSPropagation = CVSSPropagation.IMMEDIATE,
    products: tuple[int, int, int] = (0, 0, 0),
    severity_changed: bool,
    reconciled: bool = False,
) -> CVSSChainResult:
    """An expected result with the fixed `EVAL`."""
    examined, skipped, changed = products
    return CVSSChainResult(
        mode=mode,
        classification=classification,
        severity_resolution=severity,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=ProductPropagationSummary(
            examined=examined, override_skipped=skipped, changed=changed
        ),
        severity_changed=severity_changed,
        reconciled=reconciled,
        evaluation_date=EVAL,
    )


# ---------------------------------------------------------------------------
# Argument guards (Q6)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestArgumentGuards:
    async def test_association_without_previous_severity_raises_before_any_statement(
        self, db_session: AsyncSession, cve_with: CVEBuilder
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=None)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="association_previous_severity"),
        ):
            await run_chain(db_session, cve.id, mode=ASSOCIATION)

        assert recorder.statements == []

    @pytest.mark.parametrize(
        "previous",
        [pytest.param(Severity.HIGH, id="label"), pytest.param(None, id="none")],
    )
    async def test_default_version_with_previous_severity_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        previous: Severity | None,
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=None)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="association_previous_severity"),
        ):
            await run_chain(db_session, cve.id, association_previous_severity=previous)

        assert recorder.statements == []
        assert await cve_severity(db_session, cve.id) is None

    async def test_association_with_missing_cve_raises_without_effect(
        self, db_session: AsyncSession
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="CVE"),
        ):
            await run_chain(
                db_session,
                uuid.uuid7(),
                mode=ASSOCIATION,
                association_previous_severity=None,
            )

        assert recorder.writes() == []
        assert await total_ticket_events(db_session) == 0

    async def test_association_with_ticketless_cve_raises_without_effect(
        self, db_session: AsyncSession, cve_with: CVEBuilder
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.LOW)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="Ticket"),
        ):
            await run_chain(
                db_session,
                cve.id,
                mode=ASSOCIATION,
                association_previous_severity=Severity.LOW,
            )

        assert recorder.writes() == []
        assert recorder.selects_from("system_setting") == []
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await total_ticket_events(db_session) == 0


# ---------------------------------------------------------------------------
# Eligibility formula and boundaries through the propagation helper
# ---------------------------------------------------------------------------


async def _new_ticket(
    ticket_factory: TicketFactory,
    cve_id: uuid.UUID,
    *,
    priority: str | None,
    status: TicketStatus = TicketStatus.NEW,
) -> Ticket:
    """An unassigned Ticket of the CVE whose `priority_auto` is `priority`."""
    return await ticket_factory(
        status=status.value, cve_id=cve_id, priority_auto=priority
    )


@pytest.mark.integration
class TestEligibilityFormula:
    """Default-version mode on an unassigned `New` Ticket whose severity and
    priority are already converged, so every event is a Product event."""

    async def test_override_first_precedence_skips_without_change_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P3")
        await tree(
            ticket,
            products=(
                # Automatically eligible (7.5 >= 0.0), overridden to false.
                Prod(eligible=False, override=True),
                # Automatically ineligible (7.5 < 9.9), overridden to true.
                Prod(eligible=True, override=True, threshold=Decimal("9.9")),
                Prod(eligible=False),
            ),
        )

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("7.5", Severity.HIGH),
            eligibility_resolution=suse_eligibility("7.5"),
            products=(3, 2, 1),
            severity_changed=False,
        )
        assert await eligibility(db_session, ticket.id) == [
            (False, True),
            (True, True),
            (True, False),
        ]
        subject = (await subjects(db_session, ticket.id))[2]
        assert await ticket_events(db_session, ticket) == [
            product_event(subject, False, True)
        ]

    async def test_reactive_support_forces_ineligible_for_automatic_records_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        # No assessment: the 10.0 fallback meets every threshold, so only
        # the lifecycle rule can make an automatic record ineligible.
        cve = await cve_with(severity=None)
        ticket = await _new_ticket(ticket_factory, cve.id, priority=None)
        await tree(
            ticket,
            products=(
                Prod(eligible=True, reactive=True),
                Prod(eligible=True, reactive=True, override=True),
                Prod(eligible=False, reactive=True, override=True),
                Prod(eligible=False, threshold=Decimal("9.9")),
            ),
        )

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=None,
            eligibility_resolution=FALLBACK,
            products=(4, 2, 2),
            severity_changed=False,
        )
        assert await eligibility(db_session, ticket.id) == [
            (False, False),
            (True, True),
            (False, True),
            (True, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], True, False),
            product_event(detail[3], False, True),
        ]

    async def test_null_threshold_is_the_implicit_zero(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(Assessment("0.0"), severity=Severity.NONE)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P4")
        await tree(
            ticket,
            products=(
                Prod(eligible=False, threshold=None),
                Prod(eligible=True, threshold=Decimal("0.1")),
                Prod(eligible=False, threshold=Decimal("0.0")),
            ),
        )

        result = await run_chain(db_session, cve.id)

        assert result.eligibility_resolution == suse_eligibility("0.0")
        assert result.products == ProductPropagationSummary(3, 0, 3)
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (False, False),
            (True, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], False, True),
            product_event(detail[1], True, False),
            product_event(detail[2], False, True),
        ]

    async def test_unavailable_lifecycle_is_no_lifecycle_override(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P3")
        # No lifecycle date at all.
        track = await tree(ticket, products=(Prod(eligible=False, lifecycle=False),))
        # Reactive-looking but inconsistent dates (an extended end without a
        # General Support end): the phase is unavailable, not Reactive.
        inconsistent = await product_factory(
            extended_support_end_date=BEFORE_EVAL,
            reactive_support_end_date=AFTER_EVAL,
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=inconsistent.id,
            eligible=False,
        )

        result = await run_chain(db_session, cve.id)

        assert result.products == ProductPropagationSummary(2, 0, 2)
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (True, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], False, True),
            product_event(detail[1], False, True),
        ]

    @pytest.mark.parametrize(
        ("threshold", "old", "new"),
        [
            pytest.param("7.5", False, True, id="score-equals-threshold"),
        ],
    )
    async def test_threshold_boundary(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        threshold: str,
        old: bool,
        new: bool,
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P3")
        await tree(ticket, products=(Prod(eligible=old, threshold=Decimal(threshold)),))

        result = await run_chain(db_session, cve.id)

        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert await eligibility(db_session, ticket.id) == [(new, False)]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], old, new)
        ]

    @pytest.mark.parametrize(
        ("assessments", "severity", "resolution", "expected_eligibility", "priority"),
        [
            pytest.param(
                (
                    Assessment("2.0", version="4.0"),
                    Assessment("5.0", provider="NVD"),
                ),
                # The cascade winner (SUSE at another version) is not the
                # eligibility input.
                severity_resolution("2.0", Severity.LOW, version=CVSSVersion.V4_0),
                FALLBACK,
                True,
                "P4",
                id="severity-cascade-winner-is-not-an-input",
            ),
        ],
    )
    async def test_suse_default_version_score_versus_fallback(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        assessments: tuple[Assessment, ...],
        severity: SeverityResolution,
        resolution: EligibilityResolution,
        expected_eligibility: bool,
        priority: str,
    ) -> None:
        cve = await cve_with(*assessments, severity=severity.label)
        ticket = await _new_ticket(ticket_factory, cve.id, priority=priority)
        start = not expected_eligibility
        await tree(ticket, products=(Prod(eligible=start, threshold=Decimal("6.0")),))

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity,
            eligibility_resolution=resolution,
            products=(1, 0, 1),
            severity_changed=False,
        )
        assert await eligibility(db_session, ticket.id) == [
            (expected_eligibility, False)
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], start, expected_eligibility)
        ]

    async def test_explicit_default_version_overrides_the_setting_for_both(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Converged for the persisted 3.1 setting: Critical, P2, eligible.
        cve = await cve_with(
            Assessment("9.8"),
            Assessment("2.0", version="4.0"),
            severity=Severity.CRITICAL,
        )
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P2")
        await tree(ticket, products=(Prod(eligible=True, threshold=Decimal("5.0")),))

        async def forbidden(_db: AsyncSession) -> str:
            raise AssertionError("the supplied version must be used")

        monkeypatch.setattr(settings_service, "get_default_cvss_version", forbidden)

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve.id, default_cvss_version="4.0")

        assert recorder.selects_from("system_setting") == []
        assert result == _result(
            severity=severity_resolution("2.0", Severity.LOW, version=CVSSVersion.V4_0),
            eligibility_resolution=suse_eligibility("2.0"),
            products=(1, 0, 1),
            severity_changed=True,
        )
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            severity_event("Critical", "Low"),
            product_event(detail[0], True, False),
            priority_event("P2", "P4"),
        ]

    @pytest.mark.parametrize(
        ("assessments", "severity", "start", "threshold", "priority"),
        [
            pytest.param((), None, False, None, None, id="to-eligible"),
            pytest.param(
                (Assessment("1.0"),),
                Severity.LOW,
                True,
                Decimal("5.0"),
                "P4",
                id="to-ineligible",
            ),
        ],
    )
    async def test_eol_exclusion_affectedness_delivery_and_release_are_not_inputs(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        assessments: tuple[Assessment, ...],
        severity: Severity | None,
        start: bool,
        threshold: Decimal | None,
        priority: str | None,
    ) -> None:
        cve = await cve_with(*assessments, severity=severity)
        ticket = await _new_ticket(ticket_factory, cve.id, priority=priority)
        plain = Prod(eligible=start, threshold=threshold)
        for status in PackageStatus:
            await tree(ticket, status=status, products=(plain,))
        await tree(
            ticket,
            products=(
                Prod(eligible=start, threshold=threshold, eol=True),
                Prod(eligible=start, threshold=threshold, excluded=True),
                Prod(eligible=start, threshold=threshold, released=True),
            ),
        )
        await tree(ticket, products=(plain,), package_excluded=True)
        await tree(ticket, products=(plain,), track_excluded=True)
        delivered = await tree(ticket, products=(plain,))
        delivered.delivery_status = DeliveryStatus.RELEASED.value
        await db_session.flush()
        count = len(PackageStatus) + 6

        result = await run_chain(db_session, cve.id)

        assert result.products == ProductPropagationSummary(count, 0, count)
        assert await eligibility(db_session, ticket.id) == [(not start, False)] * count
        assert await ticket_events(db_session, ticket) == [
            product_event(subject, start, not start)
            for subject in await subjects(db_session, ticket.id)
        ]

    async def test_reloads_current_inputs_over_a_stale_identity_map(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P3")
        track = await tree(
            ticket,
            products=(
                Prod(eligible=True),
                Prod(eligible=True, threshold=Decimal("1.0")),
            ),
        )
        first, second = (
            await db_session.execute(
                select(TicketPackageProduct)
                .where(TicketPackageProduct.ticket_package_track_id == track.id)
                .order_by(TicketPackageProduct.id)
            )
        ).scalars()
        # Current values changed behind the session's loaded instances: the
        # first occurrence became a false override, and the second
        # Product's threshold rose above the score.
        await db_session.execute(
            update(TicketPackageProduct)
            .where(TicketPackageProduct.id == first.id)
            .values(eligible=False, is_eligible_override=True)
            .execution_options(synchronize_session=False)
        )
        await db_session.execute(
            update(Product)
            .where(Product.id == second.product_id)
            .values(cvss_threshold=Decimal("8.0"))
            .execution_options(synchronize_session=False)
        )
        assert (first.eligible, first.is_eligible_override) == (True, False)

        result = await run_chain(db_session, cve.id)

        assert result.products == ProductPropagationSummary(2, 1, 1)
        assert await eligibility(db_session, ticket.id) == [
            (False, True),
            (False, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[1], True, False)
        ]

    async def test_event_subject_actor_and_ascending_occurrence_id_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    ) -> None:
        # No assessment: severity stays NULL, priority stays NULL, and the
        # 10.0 fallback makes every automatic occurrence eligible.
        cve = await cve_with(severity=None)
        ticket = await _new_ticket(ticket_factory, cve.id, priority=None)
        alpha = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-alpha"
        )
        beta = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-beta"
        )
        alpha_update = await ticket_package_track_factory(
            ticket_package_id=alpha.id, reference="Example:Alpha:Update"
        )
        beta_update = await ticket_package_track_factory(
            ticket_package_id=beta.id, reference="Example:Beta:Update"
        )
        beta_next = await ticket_package_track_factory(
            ticket_package_id=beta.id, reference="Example:Beta:Next"
        )
        ids = [uuid.uuid7() for _ in range(4)]
        # Creation order differs from UUID order across tracks and packages.
        placements = [
            (ids[2], beta_next, 1),
            (ids[0], beta_update, 2),
            (ids[3], alpha_update, 3),
            (ids[1], alpha_update, 4),
        ]
        for occurrence_id, track, n in placements:
            product = await product_factory(
                name=f"fictional-short-{n}",
                display_name=f"Fictional Server {n}",
                cpe=f"cpe:/o:example:fictional_server:{n}",
            )
            await ticket_package_product_factory(
                id=occurrence_id,
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=False,
            )
        result = await run_chain(db_session, cve.id)

        assert result.products == ProductPropagationSummary(4, 0, 4)

        def subject(track: str, package: str, n: int) -> dict[str, str]:
            return {
                "track": track,
                "package": package,
                "product_name": f"Fictional Server {n}",
                "product_cpe": f"cpe:/o:example:fictional_server:{n}",
                "reason": "cvss",
            }

        assert await ticket_events(db_session, ticket) == [
            product_event(
                subject("Example:Beta:Update", "fictional-beta", 2), False, True
            ),
            product_event(
                subject("Example:Alpha:Update", "fictional-alpha", 4), False, True
            ),
            product_event(
                subject("Example:Beta:Next", "fictional-beta", 1), False, True
            ),
            product_event(
                subject("Example:Alpha:Update", "fictional-alpha", 3), False, True
            ),
        ]


# ---------------------------------------------------------------------------
# Association mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssociationMode:
    """The pre-chain state of `associate_cve()`: a CVE-less Ticket with a
    manual severity is pointed at the CVE and its `severity_manual` cleared
    in the same transaction, under the CVE then Ticket locks."""

    @pytest.mark.parametrize(
        (
            "previous",
            "assessments",
            "persisted",
            "resolution",
            "start",
            "priorities",
        ),
        [
            pytest.param(
                None,
                (SUSE_CRITICAL,),
                None,
                severity_resolution("9.8", Severity.CRITICAL),
                False,
                (None, "P2"),
                id="null-to-derived",
            ),
            pytest.param(
                Severity.HIGH,
                (),
                None,
                None,
                False,
                ("P3", None),
                id="manual-to-derived-null",
            ),
            pytest.param(
                Severity.LOW,
                (SUSE_HIGH,),
                Severity.HIGH,
                severity_resolution("7.5", Severity.HIGH),
                True,
                ("P4", "P3"),
                id="cve-severity-already-derived-but-manual-differs",
            ),
        ],
    )
    async def test_handover_is_one_system_severity_event_then_products_then_priority(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        previous: Severity | None,
        assessments: tuple[Assessment, ...],
        persisted: Severity | None,
        resolution: SeverityResolution | None,
        start: bool,
        priorities: tuple[str | None, str | None],
    ) -> None:
        old_priority, new_priority = priorities
        derived = resolution.label.value if resolution is not None else None
        cve = await cve_with(*assessments, severity=persisted)
        # An inactive assignee and a NOT_AFFECTED tree: a reconciliation
        # would move the Ticket, so none must run.
        assignee = await va_user(active=False)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=label(previous),
            priority_auto=old_priority,
            assignee_id=assignee.id,
        )
        threshold = T9 if start else None
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=start, threshold=threshold),),
        )
        new_eligible = not start
        await associate(db_session, ticket, cve)
        assign = CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_chain(
            db_session,
            cve.id,
            mode=ASSOCIATION,
            association_previous_severity=previous,
        )

        assert result == _result(
            mode=ASSOCIATION,
            severity=resolution,
            eligibility_resolution=(
                FALLBACK if not assessments else suse_eligibility(assessments[0].score)
            ),
            products=(1, 0, 1),
            severity_changed=True,
        )
        assert (assign.calls, reconcile.calls) == ([], [])
        assert await cve_severity(db_session, cve.id) == derived
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            assignee.id,
            new_priority,
            None,
            None,
        )
        assert await eligibility(db_session, ticket.id) == [(new_eligible, False)]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            severity_event(label(previous), derived),
            product_event(detail[0], start, new_eligible),
            priority_event(old_priority, new_priority),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_equal_previous_and_derived_severity_creates_no_severity_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        # The CVE's persisted severity is still NULL, so it is written, but
        # the handover from the equal manual value records nothing.
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            priority_auto="P3",
        )
        await tree(ticket, products=(Prod(eligible=True, threshold=T9),))
        await associate(db_session, ticket, cve)

        result = await run_chain(
            db_session,
            cve.id,
            mode=ASSOCIATION,
            association_previous_severity=Severity.HIGH,
        )

        assert result == _result(
            mode=ASSOCIATION,
            severity=severity_resolution("7.5", Severity.HIGH),
            eligibility_resolution=suse_eligibility("7.5"),
            products=(1, 0, 1),
            severity_changed=False,
        )
        assert await cve_severity(db_session, cve.id) == "High"
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], True, False)
        ]

    async def test_equal_handover_with_converged_state_is_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            priority_auto="P3",
        )
        await tree(ticket, products=(Prod(eligible=True),))
        await associate(db_session, ticket, cve)

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(
                db_session,
                cve.id,
                mode=ASSOCIATION,
                association_previous_severity=Severity.HIGH,
            )

        assert recorder.writes() == []
        assert result == _result(
            mode=ASSOCIATION,
            classification=UNCHANGED,
            severity=severity_resolution("7.5", Severity.HIGH),
            eligibility_resolution=suse_eligibility("7.5"),
            products=(1, 0, 0),
            severity_changed=False,
        )
        assert await ticket_events(db_session, ticket) == []

    async def test_new_ticket_is_neither_assigned_nor_promoted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, severity_manual=Severity.MEDIUM.value
        )
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        await associate(db_session, ticket, cve)

        result = await run_chain(
            db_session,
            cve.id,
            mode=ASSOCIATION,
            association_previous_severity=Severity.MEDIUM,
        )

        assert result.reconciled is False
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            priority_event(None, "P2"),
        ]


# ---------------------------------------------------------------------------
# Default-version state matrix
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDefaultVersionMatrix:
    """The shared stale scenario: the CVE's persisted severity is `Medium`
    while its SUSE default-version assessment derives `Critical` (9.8); the
    Ticket's `priority_auto` is the stale `P4` (expected `P2`); and one
    automatic occurrence with threshold 9.0 is still `false`."""

    async def test_ticketless_cve_receives_severity_only(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            propagation=CVSSPropagation.NOT_APPLICABLE,
            severity_changed=True,
        )
        assert (refresh.calls, reconcile.calls) == ([], [])
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await total_ticket_events(db_session) == 0

    async def test_new_ticket_receives_severity_eligibility_and_priority_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        ticket = await _new_ticket(ticket_factory, cve.id, priority="P4")
        # Gates would resolve this Ticket if it were reconciled.
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False, threshold=T9),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            products=(1, 0, 1),
            severity_changed=True,
        )
        assert reconcile.calls == []
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P2",
            None,
            None,
        )
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize(
        ("status", "track_status", "expected"),
        [
            pytest.param(
                TicketStatus.ANALYSIS,
                PackageStatus.AFFECTED,
                TicketStatus.ANALYZED,
                id="analysis-to-analyzed",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                PackageStatus.NOT_AFFECTED,
                TicketStatus.RESOLVED,
                id="analyzed-to-resolved",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                PackageStatus.AFFECTED,
                TicketStatus.ANALYZED,
                id="resolved-regresses-to-analyzed",
            ),
        ],
    )
    async def test_gate_zone_ticket_reconciles_once_after_every_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        track_status: PackageStatus,
        expected: TicketStatus,
    ) -> None:
        owner = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, priority_auto="P4", assignee_id=owner.id
        )
        await tree(
            ticket,
            status=track_status,
            products=(Prod(eligible=False, threshold=T9),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        assign = CallCounter(monkeypatch, "auto_assign_actor")

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            products=(1, 0, 1),
            severity_changed=True,
            reconciled=True,
        )
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert assign.calls == []
        assert await ticket_state(db_session, ticket.id) == (
            expected,
            owner.id,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        final = [status_event(status, expected)] if expected is not status else []
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            *final,
        ]
        regression = status is TicketStatus.RESOLVED and expected is not status
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),) if regression else ()
        )

    async def test_forward_transition_when_severity_becomes_resolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        # The SUSE assessment exists but the persisted severity is stale NULL.
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(),))

        result = await run_chain(db_session, cve.id)

        assert result.reconciled is True
        assert result.products == ProductPropagationSummary(1, 0, 0)
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED
        assert await ticket_events(db_session, ticket) == [
            severity_event(None, "High"),
            priority_event(None, "P3"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]

    async def test_backward_transition_when_assessments_disappeared(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        # Every assessment was removed out of band; the persisted severity
        # still says High.
        cve = await cve_with(severity=Severity.HIGH)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value, cve_id=cve.id, priority_auto="P3"
        )
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(),))

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=None,
            eligibility_resolution=FALLBACK,
            products=(1, 0, 0),
            severity_changed=True,
            reconciled=True,
        )
        assert await cve_severity(db_session, cve.id) is None
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            severity_event("High", None),
            priority_event("P3", None),
            status_event(TicketStatus.ANALYZED, TicketStatus.ANALYSIS),
        ]

    async def test_resolved_regression_from_one_product_registers_one_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        owner = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            cve_id=cve.id,
            priority_auto="P2",
            assignee_id=owner.id,
        )
        # A FIXED track whose only Product becomes eligible without
        # `released_at`: resolution is no longer complete.
        await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(eligible=False, threshold=T9),),
        )

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            products=(1, 0, 1),
            severity_changed=False,
            reconciled=True,
        )
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            owner.id,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            product_event(detail[0], False, True),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYZED),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    @pytest.mark.parametrize(
        ("active", "roles", "reason"),
        [
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), "inactive assignee", id="inactive"
            ),
        ],
    )
    @pytest.mark.parametrize(
        ("track_status", "expected"),
        [
            pytest.param(PackageStatus.ANALYSIS, TicketStatus.ANALYSIS, id="analysis"),
            pytest.param(PackageStatus.AFFECTED, TicketStatus.ANALYZED, id="analyzed"),
        ],
    )
    async def test_sanitation_follows_gate_inputs_and_priority_and_precedes_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
        track_status: PackageStatus,
        expected: TicketStatus,
    ) -> None:
        assignee = await va_user(active=active, roles=roles)
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            priority_auto="P4",
            assignee_id=assignee.id,
        )
        await tree(
            ticket,
            status=track_status,
            products=(Prod(eligible=False, threshold=T9),),
        )

        result = await run_chain(db_session, cve.id)

        assert result.classification is CHANGED
        assert result.reconciled is True
        assert await ticket_state(db_session, ticket.id) == (
            expected,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        final = (
            [status_event(TicketStatus.ANALYSIS, expected)]
            if expected is not TicketStatus.ANALYSIS
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            unassigned_event(assignee.username, reason),
            *final,
        ]

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_receives_severity_and_priority_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        assignee = await va_user(active=False)
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=status.value,
            cve_id=cve.id,
            priority_auto="P4",
            assignee_id=assignee.id,
        )
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False, threshold=T9),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        assign = CallCounter(monkeypatch, "auto_assign_actor")

        result = await run_chain(db_session, cve.id)

        assert result == _result(
            severity=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            propagation=CVSSPropagation.DEFERRED_UNTIL_REACTIVATION,
            severity_changed=True,
        )
        assert (reconcile.calls, assign.calls) == ([], [])
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            status,
            assignee.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()
