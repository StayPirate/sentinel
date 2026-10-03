"""Single-session service integration tests for the Product-originated
system recalculation
`package_service.recalculate_product_eligibility_for_ticket()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md
  (`recalculate_product_eligibility_for_ticket()`; Acting user convention;
  Record Creation Logic; Concurrency Control; Service Exceptions; Excluded
  and Non-Actionable Records; Architectural Test Requirement: Automatic
  Product eligibility recalculation, Dimension independence).
- docs/features/packages/package-model.md (Axis 2: Eligibility).
- docs/features/tickets/cvss-scoring.md (Eligibility Score Resolution).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`
  step 5; Transaction-Local Ticket Convergence Registration).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `product_eligibility_changed`; detail JSONB Schema Contract; Canonical
  Mutation and No-Event Matrix: "Product eligibility or override ownership
  change"; Cross-Event Ordering, Locking, and Rollback; Testing
  Requirements 1-8, 12, 20, 24, 25).
- docs/features/platform/testing-strategy.md (Service Functions; Audit
  Trail Testing; Rollback Within a Test).

Independent-session lock serialization (audit Testing Requirement 23) is
covered by `tests/test_services/test_recalculate_product_eligibility_atomicity.py`.

Unless a test states otherwise, the catalog Product under recalculation is
in General Support on `EVAL` with a `NULL` threshold, and every occurrence
sits alone on a fresh `ANALYSIS` track of a fresh package, so a gate-zone
Ticket stays at the `Analysis` floor. Expected values are transcribed from
the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import Mock

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    PRODUCT_RECALCULATION_REASONS,
    ProductEligibilityRecalculationResult,
    ProductNotFoundError,
    ProductRecalculationReason,
    recalculate_product_eligibility_for_ticket,
)
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    Assessment,
    CVEBuilder,
    eligibility,
    ticket_state,
)
from tests.support.database import rollback_test_scope
from tests.support.product_eligibility import (
    persisted_occurrence,
    product_subject,
    set_default_version,
)
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
    RELEASED_AT,
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `cve_with` fixtures."""

ProductFactory = Callable[..., Awaitable[Product]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
TrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]
SettingFactory = Callable[..., Awaitable[SystemSetting]]
CatalogBuilder = Callable[..., Awaitable[Product]]
OccurrenceBuilder = Callable[..., Awaitable[TicketPackageProduct]]

NEXT_DAY = EVAL + timedelta(days=1)
AFTER_REACTIVE = REACTIVE_END + timedelta(days=1)
"""The first day after the Reactive Support end of a `reactive` Product:
the Product is EOL (product-catalog.md, Lifecycle Evaluator)."""

LIFECYCLES: dict[str, dict[str, date]] = {
    "general": {"general_support_end_date": AFTER_EVAL},
    "eol": {"general_support_end_date": BEFORE_EVAL},
    "reactive": {
        "general_support_end_date": REACTIVE_GS_END,
        "extended_support_end_date": REACTIVE_EXTENDED_END,
        "reactive_support_end_date": REACTIVE_END,
    },
    "none": {},
    "extended-ends-on-eval": {
        "general_support_end_date": BEFORE_EVAL,
        "extended_support_end_date": EVAL,
        "reactive_support_end_date": AFTER_EVAL,
    },
    "support-ends-on-eval": {"general_support_end_date": EVAL},
}
"""Catalog lifecycle dates. `general`: General Support on `EVAL`. `eol`:
EOL on `EVAL`. `reactive`: Reactive Support on `EVAL`, EOL from
`AFTER_REACTIVE`. `none`: no dates (phase `NULL`). `extended-ends-on-eval`:
Extended Support on `EVAL`, Reactive Support on `NEXT_DAY`.
`support-ends-on-eval`: General Support on `EVAL`, EOL on `NEXT_DAY`."""


@pytest.fixture
async def default_setting(system_setting_factory: SettingFactory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


@pytest.fixture
def catalog(product_factory: ProductFactory) -> CatalogBuilder:
    """Create a catalog Product with a threshold and a `LIFECYCLES` entry."""

    async def _create(
        *,
        threshold: Decimal | None = None,
        lifecycle: str = "general",
        **overrides: Any,
    ) -> Product:
        return await product_factory(
            cvss_threshold=threshold, **LIFECYCLES[lifecycle], **overrides
        )

    return _create


@pytest.fixture
def occurrence(
    ticket_package_factory: PackageFactory,
    ticket_package_track_factory: TrackFactory,
    ticket_package_product_factory: OccurrenceFactory,
) -> OccurrenceBuilder:
    """Create one occurrence of a catalog Product in a Ticket, on the track
    `track_id` or on a fresh track (of `status`) of a fresh package."""

    async def _create(
        ticket: Ticket,
        product: Product,
        *,
        eligible: bool,
        override: bool = False,
        track_id: uuid.UUID | None = None,
        status: PackageStatus = PackageStatus.ANALYSIS,
        occurrence_id: uuid.UUID | None = None,
        released: bool = False,
        excluded: bool = False,
        track_excluded: bool = False,
        package_excluded: bool = False,
    ) -> TicketPackageProduct:
        now = datetime.now(UTC)
        if track_id is None:
            package = await ticket_package_factory(
                ticket_id=ticket.id, deleted_at=now if package_excluded else None
            )
            track = await ticket_package_track_factory(
                ticket_package_id=package.id,
                status=status.value,
                deleted_at=now if track_excluded else None,
            )
            track_id = track.id
        values: dict[str, Any] = {
            "ticket_package_track_id": track_id,
            "product_id": product.id,
            "eligible": eligible,
            "is_eligible_override": override,
            "released_at": RELEASED_AT if released else None,
            "deleted_at": now if excluded else None,
        }
        if occurrence_id is not None:
            values["id"] = occurrence_id
        return await ticket_package_product_factory(**values)

    return _create


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    examined: int, skipped: int, changed: int, *, manual_zone: bool = False
) -> ProductEligibilityRecalculationResult:
    return ProductEligibilityRecalculationResult(
        examined=examined,
        override_skipped=skipped,
        changed=changed,
        manual_zone_skipped=manual_zone,
    )


MANUAL_ZONE_SKIP = _result(0, 0, 0, manual_zone=True)


async def _recalculate(
    db: AsyncSession,
    ticket: Ticket,
    product: Product,
    *,
    reason: ProductRecalculationReason = "threshold",
    evaluation_date: date | None = EVAL,
) -> ProductEligibilityRecalculationResult:
    """Call the boundary as the per-Ticket sub-task would."""
    return await recalculate_product_eligibility_for_ticket(
        db,
        ticket_id=ticket.id,
        catalog_product_id=product.id,
        reason=reason,
        evaluation_date=evaluation_date,
    )


def _value(eligible: bool) -> str:
    return "true" if eligible else "false"


async def _event(
    db: AsyncSession,
    occurrence: TicketPackageProduct,
    old: bool,
    new: bool,
    reason: str = "threshold",
) -> EventRow:
    """The system `product_eligibility_changed` of this boundary
    (ticket-audit-log.md, Event Type Contract and detail JSONB Schema
    Contract: `user_id`, `comment` `NULL`; Product subject plus `reason`;
    no `override_action`)."""
    return EventRow(
        "product_eligibility_changed",
        None,
        _value(old),
        _value(new),
        None,
        {**await product_subject(db, occurrence), "reason": reason},
    )


async def _cve_ticket(
    ticket_factory: TicketFactory,
    cve_with: CVEBuilder,
    *assessments: Assessment,
    **overrides: Any,
) -> Ticket:
    """An `Analysis` Ticket of a `High` CVE with the given assessments."""
    cve = await cve_with(*assessments, severity=Severity.HIGH)
    overrides.setdefault("status", TicketStatus.ANALYSIS.value)
    return await ticket_factory(cve_id=cve.id, **overrides)


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket " in statement and statement.rstrip().endswith("FOR UPDATE")


async def _assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    ticket_id: uuid.UUID,
    run: Callable[[], Awaitable[ProductEligibilityRecalculationResult]],
    *,
    error: type[Exception] | None = None,
) -> tuple[ProductEligibilityRecalculationResult | None, StatementRecorder]:
    """Run the call and assert the zero-side-effect contract: no write, no
    assignment, no reconciliation, no registered convergence effect, and
    unchanged Ticket state, events, and occurrences. Returns the result of
    a non-raising call and the recorded statements."""

    async def snapshot() -> tuple[Any, ...]:
        return (
            await ticket_state(db, ticket_id),
            await ticket_events_by_id(db, ticket_id),
            await eligibility(db, ticket_id),
        )

    before = await snapshot()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: ProductEligibilityRecalculationResult | None = None

    with StatementRecorder(db) as recorder:
        if error is None:
            result = await run()
        else:
            with pytest.raises(error):
                await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await snapshot() == before
    return result, recorder


# ---------------------------------------------------------------------------
# Eligibility inputs (package-model.md, Axis 2: Eligibility;
# cvss-scoring.md, Eligibility Score Resolution)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestCurrentInputs:
    """Each occurrence is seeded with the opposite of its expected value,
    so an effective recalculation changes it with exactly one event."""

    @pytest.mark.parametrize(
        ("threshold", "expected"),
        [
            pytest.param(None, True, id="null-threshold-is-zero"),
            pytest.param(Decimal("7.0"), True, id="threshold-equals-score"),
            pytest.param(Decimal("6.9"), True, id="threshold-below-score"),
            pytest.param(Decimal("7.1"), False, id="threshold-above-score"),
        ],
    )
    async def test_threshold_against_the_suse_default_version_score(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        threshold: Decimal | None,
        expected: bool,
    ) -> None:
        """Rules 3-5 with a SUSE 3.1 score of 7.0: `false` only when the
        score is below the threshold; `NULL` is an implicit `0.0`."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        product = await catalog(threshold=threshold)
        target = await occurrence(ticket, product, eligible=not expected)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (expected, False)
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, target, not expected, expected)
        ]

    @pytest.mark.parametrize(
        ("evaluation_date", "threshold", "seeded", "expected"),
        [
            pytest.param(EVAL, Decimal("4.0"), True, False, id="reactive-forces-false"),
            pytest.param(
                AFTER_REACTIVE,
                Decimal("4.0"),
                False,
                True,
                id="leaving-restores-threshold-true",
            ),
            pytest.param(
                AFTER_REACTIVE,
                Decimal("9.0"),
                False,
                False,
                id="leaving-restores-threshold-false",
            ),
        ],
    )
    async def test_reactive_support_rule(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        evaluation_date: date,
        threshold: Decimal,
        seeded: bool,
        expected: bool,
    ) -> None:
        """Rule 2: Reactive Support forces `false` regardless of a SUSE
        score (7.0) above the threshold. Once the Product leaves Reactive
        Support (EOL is not a formula input), the threshold result applies
        again: `true` for 4.0, and still `false` for 9.0, which is then a
        converged no-op without event or reconciliation. An occurrence of a
        Product without lifecycle data (never EOL) on another `ANALYSIS`
        track anchors the Ticket at the `Analysis` floor once the target
        is EOL."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        product = await catalog(threshold=threshold, lifecycle="reactive")
        target = await occurrence(ticket, product, eligible=seeded)
        await occurrence(ticket, await catalog(lifecycle="none"), eligible=True)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _recalculate(
            db_session,
            ticket,
            product,
            reason="reactive_ltss",
            evaluation_date=evaluation_date,
        )

        changed = seeded != expected
        assert result == _result(1, 0, int(changed))
        assert await persisted_occurrence(db_session, target) == (expected, False)
        assert await ticket_events(db_session, ticket) == (
            [await _event(db_session, target, seeded, expected, "reactive_ltss")]
            if changed
            else []
        )
        assert len(reconcile.calls) == int(changed)

    @pytest.mark.parametrize(
        ("threshold", "expected"),
        [(Decimal("6.0"), True), (Decimal("8.0"), False)],
        ids=["above-threshold", "below-threshold"],
    )
    async def test_null_lifecycle_forces_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        threshold: Decimal,
        expected: bool,
    ) -> None:
        """Rule 2: a `NULL` lifecycle phase activates no rule and forces
        neither value; the SUSE 7.0 threshold comparison decides."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("7.0"))
        product = await catalog(threshold=threshold, lifecycle="none")
        target = await occurrence(ticket, product, eligible=not expected)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (expected, False)

    @pytest.mark.parametrize(
        ("case", "threshold", "expected"),
        [
            pytest.param("cve-less", Decimal("9.9"), True, id="cve-less-fallback"),
            pytest.param(
                "no-suse-default-version",
                Decimal("9.9"),
                True,
                id="other-version-and-provider-ignored-fallback",
            ),
            pytest.param(
                "suse-and-external-default-version",
                Decimal("7.0"),
                False,
                id="external-provider-at-default-version-ignored",
            ),
        ],
    )
    async def test_only_the_suse_default_version_assessment_counts(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        case: str,
        threshold: Decimal,
        expected: bool,
    ) -> None:
        """cvss-scoring.md, Eligibility Score Resolution. Without a SUSE
        assessment at the default version the score is 10.0, including for
        a CVE-less Ticket: a SUSE 4.0 and an external 3.1 assessment of 2.0
        would each keep the Product ineligible. With SUSE 3.1 at 5.0, an
        external 3.1 at 9.8 would make it eligible against 7.0."""
        if case == "cve-less":
            ticket = await cveless(ticket_factory)
        elif case == "no-suse-default-version":
            ticket = await _cve_ticket(
                ticket_factory,
                cve_with,
                Assessment("2.0", version="4.0"),
                Assessment("2.0", provider="Fictional Provider"),
            )
        else:
            ticket = await _cve_ticket(
                ticket_factory,
                cve_with,
                Assessment("5.0"),
                Assessment("9.8", provider="Fictional Provider"),
            )
        product = await catalog(threshold=threshold)
        target = await occurrence(ticket, product, eligible=not expected)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (expected, False)

    @pytest.mark.parametrize(
        ("version", "expected"), [("3.1", False), ("4.0", True)], ids=["3.1", "4.0"]
    )
    async def test_current_default_version_setting_is_honoured(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        version: str,
        expected: bool,
    ) -> None:
        """package-model.md, Axis 2 (Important): the version is the current
        persisted setting, never hardcoded. SUSE 3.1 scores 5.0 and SUSE
        4.0 scores 9.0 against a 7.0 threshold."""
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment("5.0", version="3.1"),
            Assessment("9.0", version="4.0"),
        )
        product = await catalog(threshold=Decimal("7.0"))
        target = await occurrence(ticket, product, eligible=not expected)
        await set_default_version(db_session, version)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (expected, False)

    async def test_eol_catalog_product_is_recalculated(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
    ) -> None:
        """EOL is not a formula input: the CVE-less 10.0 against the
        implicit 0.0 makes the EOL Product's occurrence eligible."""
        ticket = await cveless(ticket_factory)
        product = await catalog(lifecycle="eol")
        target = await occurrence(ticket, product, eligible=False)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (True, False)

    async def test_directly_and_effectively_excluded_occurrences_are_recalculated(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
    ) -> None:
        """package-service.md, step 4: a directly excluded occurrence and
        occurrences beneath an excluded track or package are selected; the
        boundary changes only `eligible`, never an exclusion marker. A
        `New` Ticket keeps the gate out of the way."""
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        product = await catalog()
        low, mid, high = sorted(uuid.uuid4() for _ in range(3))
        targets = [
            await occurrence(
                ticket, product, eligible=False, occurrence_id=high, excluded=True
            ),
            await occurrence(
                ticket, product, eligible=False, occurrence_id=low, track_excluded=True
            ),
            await occurrence(
                ticket,
                product,
                eligible=False,
                occurrence_id=mid,
                package_excluded=True,
            ),
        ]

        with StatementRecorder(db_session) as recorder:
            result = await _recalculate(db_session, ticket, product)

        assert result == _result(3, 0, 3)
        updates = [
            s for s in recorder.statements if s.lstrip().upper().startswith("UPDATE")
        ]
        assert len(updates) == 3
        assert all(
            s.lstrip().startswith("UPDATE ticket_package_product SET eligible=")
            and "deleted_at" not in s
            for s in updates
        )
        assert await eligibility(db_session, ticket.id) == [(True, False)] * 3
        by_id = sorted(targets, key=lambda o: o.id)
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, o, False, True) for o in by_id
        ]

    async def test_every_track_status_is_included(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
    ) -> None:
        """package-service.md, step 4: occurrences under every track status
        are recalculated. A `New` Ticket keeps the gate out of the way
        (ticket-mutations.md, `reconcile_ticket_status()` step 1)."""
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        product = await catalog()
        for status in PackageStatus:
            await occurrence(ticket, product, eligible=False, status=status)

        result = await _recalculate(db_session, ticket, product)

        count = len(PackageStatus)
        assert count == 5
        assert result == _result(count, 0, count)
        assert await eligibility(db_session, ticket.id) == [(True, False)] * count
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            None,
            None,
            "High",
        )


# ---------------------------------------------------------------------------
# One evaluation date (package-service.md, step 5 and step 7)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestSharedEvaluationDate:
    """An assigned CVE-less `High` `Analyzed` Ticket with one `AFFECTED`
    track holding the recalculated Product P (Extended Support on `EVAL`,
    Reactive Support on `NEXT_DAY`) and an eligible unreleased sibling Q of
    another Product (General Support on `EVAL`, EOL on `NEXT_DAY`).

    On `EVAL` P becomes `true` and the actionable Q keeps the track
    incomplete: `Analyzed`. On `NEXT_DAY` P becomes `false` and Q is EOL, so
    the track has no actionable eligible Product: `Resolved` (tickets.md,
    Deterministic Gate Edge Cases). The `Resolved` outcome therefore also
    proves that reconciliation evaluated actionability on `NEXT_DAY`."""

    async def _world(
        self,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        *,
        seeded: bool,
    ) -> tuple[Ticket, Product, TicketPackageProduct]:
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.ANALYZED, assignee_id=assignee.id
        )
        product = await catalog(lifecycle="extended-ends-on-eval")
        target = await occurrence(
            ticket, product, eligible=seeded, status=PackageStatus.AFFECTED
        )
        sibling = await catalog(lifecycle="support-ends-on-eval")
        await occurrence(
            ticket, sibling, eligible=True, track_id=target.ticket_package_track_id
        )
        return ticket, product, target

    @pytest.mark.parametrize(
        ("evaluation_date", "other_date", "seeded", "after"),
        [
            pytest.param(EVAL, NEXT_DAY, False, TicketStatus.ANALYZED, id="eval"),
            pytest.param(NEXT_DAY, EVAL, True, TicketStatus.RESOLVED, id="next-day"),
        ],
    )
    async def test_explicit_date_drives_lifecycle_eligibility_and_gate(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        evaluation_date: date,
        other_date: date,
        seeded: bool,
        after: TicketStatus,
    ) -> None:
        """The controlled clock returns a date on which P's phase differs;
        an explicit `evaluation_date` never reads it."""
        ticket, product, target = await self._world(
            ticket_factory, va_user, catalog, occurrence, seeded=seeded
        )
        utc_today = Mock(return_value=other_date)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _recalculate(
            db_session,
            ticket,
            product,
            reason="reactive_ltss",
            evaluation_date=evaluation_date,
        )

        assert utc_today.call_count == 0
        assert result == _result(1, 0, 1)
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": evaluation_date}
        ]
        assert await persisted_occurrence(db_session, target) == (not seeded, False)
        gate = (
            [status_event(TicketStatus.ANALYZED, after)]
            if after != TicketStatus.ANALYZED
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, target, seeded, not seeded, "reactive_ltss"),
            *gate,
        ]
        assert (await ticket_state(db_session, ticket.id))[0] == after

    @pytest.mark.parametrize(
        "clock",
        [
            pytest.param([NEXT_DAY], id="single-reading"),
            pytest.param([NEXT_DAY, EVAL], id="crossing-a-second-reading"),
        ],
    )
    async def test_omitted_date_is_captured_once_at_entry(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        clock: list[date],
    ) -> None:
        """A second clock reading would return `EVAL` (P eligible, Q
        actionable); only the first reading governs the lifecycle phase,
        eligibility, and reconciliation."""
        ticket, product, target = await self._world(
            ticket_factory, va_user, catalog, occurrence, seeded=True
        )
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _recalculate(
            db_session,
            ticket,
            product,
            reason="reactive_ltss",
            evaluation_date=None,
        )

        assert utc_today.call_count == 1
        assert result == _result(1, 0, 1)
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": NEXT_DAY}
        ]
        assert await persisted_occurrence(db_session, target) == (False, False)
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.RESOLVED


# ---------------------------------------------------------------------------
# Architectural Test Requirement: Automatic Product eligibility
# recalculation
# ---------------------------------------------------------------------------


REGRESSIONS = [
    # (severity, lifecycle, seeded, after, registered)
    pytest.param(
        Severity.HIGH,
        "general",
        False,
        TicketStatus.ANALYZED,
        True,
        id="resolved-to-analyzed",
    ),
    pytest.param(
        None,
        "general",
        False,
        TicketStatus.ANALYSIS,
        True,
        id="resolved-to-analysis",
    ),
    pytest.param(
        Severity.HIGH,
        "reactive",
        True,
        TicketStatus.RESOLVED,
        False,
        id="resolved-stays-resolved",
    ),
]
"""An assigned CVE-less `Resolved` Ticket whose only `AFFECTED` track holds
the recalculated occurrence. `true` makes the track incomplete: with a
resolved severity the gate result is `Analyzed`, without one `Analysis`
(tickets.md, Gate: Analysis -> Analyzed). A Reactive Support `false`
leaves the track without an eligible Product: `Resolved` again, which
registers nothing (ticket-mutations.md, `reconcile_ticket_status()`
step 5)."""


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAutomaticRecalculation:
    async def test_override_records_are_skipped_without_change_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CVE-less 10.0 against the implicit 0.0: both occurrences would
        become `true`. The override keeps its value and marker without an
        event yet counts as examined; the automatic one changes and the
        Ticket reconciles once."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        overridden = await occurrence(ticket, product, eligible=False, override=True)
        automatic = await occurrence(ticket, product, eligible=False)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(2, 1, 1)
        assert await persisted_occurrence(db_session, overridden) == (False, True)
        assert await persisted_occurrence(db_session, automatic) == (True, False)
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, automatic, False, True)
        ]
        assert len(reconcile.calls) == 1

    async def test_only_overrides_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, product, eligible=False, override=True)

        result, _ = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: _recalculate(db_session, ticket, product),
        )

        assert result == _result(1, 1, 0)

    @pytest.mark.parametrize("product_exists", [True, False], ids=["product", "none"])
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_manual_zone_ticket_is_skipped_after_the_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        product_exists: bool,
    ) -> None:
        """package-service.md, steps 1-2: the locked `Ignored` or
        `Duplicated` Ticket returns the manual-zone skip result instead of
        raising `TicketNotMutableError`, with zero counts and no mutation,
        audit event, or reconciliation, before the catalog Product is
        loaded (step 3)."""
        ticket = await cveless(ticket_factory, status=status)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)
        product_id = product.id if product_exists else uuid.uuid4()

        result, recorder = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: recalculate_product_eligibility_for_ticket(
                db_session,
                ticket_id=ticket.id,
                catalog_product_id=product_id,
                reason="threshold",
                evaluation_date=EVAL,
            ),
        )

        assert result == MANUAL_ZONE_SKIP
        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])

    @pytest.mark.parametrize("end", ["commit", "rollback"])
    @pytest.mark.parametrize(
        ("severity", "lifecycle", "seeded", "after", "registered"),
        REGRESSIONS,
    )
    async def test_resolved_ticket_is_processed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        severity: Severity | None,
        lifecycle: str,
        seeded: bool,
        after: TicketStatus,
        registered: bool,
        end: str,
    ) -> None:
        """package-service.md, Preconditions (including `Resolved` lets
        threshold and lifecycle corrections invalidate resolution). A
        `Resolved` regression registers one transaction-local convergence
        effect before the transaction ends; ending the transaction, by
        commit or rollback, discards it (no consumer exists yet)."""
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=severity,
            assignee_id=assignee.id,
        )
        product = await catalog(lifecycle=lifecycle)
        target = await occurrence(
            ticket, product, eligible=seeded, status=PackageStatus.AFFECTED
        )

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await ticket_state(db_session, ticket.id) == (
            after,
            assignee.id,
            None,
            None,
            severity.value if severity else None,
        )
        gate = [status_event(TicketStatus.RESOLVED, after)] if registered else []
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, target, seeded, not seeded),
            *gate,
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),) if registered else ()
        )

        if end == "commit":
            await db_session.commit()
        else:
            await db_session.rollback()

        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_converged_ticket_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Idempotency: every automatic occurrence already holds the
        computed value (`true` for General Support, `false` for Reactive
        Support), so nothing is written, audited, or reconciled."""
        ticket = await cveless(ticket_factory, status=TicketStatus.RESOLVED)
        general = await catalog()
        reactive = await catalog(lifecycle="reactive")
        await occurrence(ticket, general, eligible=True)
        await occurrence(ticket, general, eligible=True, status=PackageStatus.FIXED)
        await occurrence(ticket, reactive, eligible=False)

        general_result, _ = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: _recalculate(db_session, ticket, general),
        )
        reactive_result, _ = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: _recalculate(db_session, ticket, reactive, reason="reactive_ltss"),
        )

        assert general_result == _result(2, 0, 0)
        assert reactive_result == _result(1, 0, 0)

    async def test_product_without_occurrence_in_the_ticket_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An existing catalog Product absent from this Ticket (it occurs
        only in another Ticket) examines nothing; the other Ticket's stale
        occurrence is untouched."""
        ticket = await cveless(ticket_factory)
        other_ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, await catalog(), eligible=False)
        foreign = await occurrence(other_ticket, product, eligible=False)

        result, _ = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: _recalculate(db_session, ticket, product),
        )

        assert result == _result(0, 0, 0)
        assert await persisted_occurrence(db_session, foreign) == (False, False)
        assert await ticket_events(db_session, other_ticket) == []

    async def test_only_occurrences_of_the_catalog_product_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
    ) -> None:
        """Stale automatic occurrences of other Products, on the same track
        and on another track, keep their stored value (CVE-less 10.0 would
        make each of them `true`)."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        target = await occurrence(ticket, product, eligible=False)
        same_track = await occurrence(
            ticket,
            await catalog(),
            eligible=False,
            track_id=target.ticket_package_track_id,
        )
        other_track = await occurrence(ticket, await catalog(), eligible=False)

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await persisted_occurrence(db_session, target) == (True, False)
        assert await persisted_occurrence(db_session, same_track) == (False, False)
        assert await persisted_occurrence(db_session, other_track) == (False, False)
        assert await ticket_events(db_session, ticket) == [
            await _event(db_session, target, False, True)
        ]


# ---------------------------------------------------------------------------
# Events (ticket-audit-log.md, Event Type Contract and detail contract)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestEvents:
    @pytest.mark.parametrize("reason", sorted(PRODUCT_RECALCULATION_REASONS))
    async def test_one_exact_event_per_changed_occurrence_then_one_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        monkeypatch: pytest.MonkeyPatch,
        reason: ProductRecalculationReason,
    ) -> None:
        """Two occurrences of one Reactive Support catalog Product on
        tracks of two packages are inserted in descending UUID order: the
        events follow ascending `TicketPackageProduct.id`, carry the
        event-time `display_name` (never the short `name`) and CPE, the
        system actor, and no `override_action`. Reconciliation runs exactly
        once, after both events, with the same `evaluation_date`."""
        ticket = await cveless(ticket_factory)
        openssl = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-openssl"
        )
        libssh = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-libssh"
        )
        openssl_track = await ticket_package_track_factory(
            ticket_package_id=openssl.id, reference="Fictional:Codestream:16:Update"
        )
        libssh_track = await ticket_package_track_factory(
            ticket_package_id=libssh.id, reference="Fictional:Codestream:15-SP7:Update"
        )
        server = await catalog(
            lifecycle="reactive",
            name="fes",
            display_name="Fictional Enterprise Server 16 SP1",
            cpe="cpe:/o:example:fes:16:sp1",
        )
        low, high = sorted(uuid.uuid4() for _ in range(2))
        await occurrence(
            ticket, server, eligible=True, track_id=openssl_track.id, occurrence_id=high
        )
        await occurrence(
            ticket, server, eligible=True, track_id=libssh_track.id, occurrence_id=low
        )
        stale = await occurrence(
            ticket, await catalog(), eligible=False, track_id=openssl_track.id
        )
        ticket_id = ticket.id
        original = ticket_mutations.reconcile_ticket_status
        calls: list[tuple[int, dict[str, Any]]] = []

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            calls.append(
                (len(await ticket_events_by_id(db_session, ticket_id)), kwargs)
            )
            await original(*args, **kwargs)

        monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)

        result = await _recalculate(db_session, ticket, server, reason=reason)

        assert result == _result(2, 0, 2)
        assert calls == [(2, {"evaluation_date": EVAL})]
        assert await persisted_occurrence(db_session, stale) == (False, False)
        assert await ticket_events(db_session, ticket) == [
            EventRow(
                "product_eligibility_changed",
                None,
                "true",
                "false",
                None,
                {
                    "track": track,
                    "package": package,
                    "product_name": "Fictional Enterprise Server 16 SP1",
                    "product_cpe": "cpe:/o:example:fes:16:sp1",
                    "reason": reason,
                },
            )
            for track, package in (
                ("Fictional:Codestream:15-SP7:Update", "fictional-libssh"),
                ("Fictional:Codestream:16:Update", "fictional-openssl"),
            )
        ]

    async def test_reinvocation_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Q5: a repeated (delayed or duplicate) invocation reads the
        converged state and has no effect."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)
        await occurrence(ticket, product, eligible=True)
        first = await _recalculate(db_session, ticket, product)
        assert len(await ticket_events(db_session, ticket)) == 1

        second, _ = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: _recalculate(db_session, ticket, product),
        )

        assert (first, second) == (_result(2, 0, 1), _result(2, 0, 0))


# ---------------------------------------------------------------------------
# Guards, locking, and boundary (package-service.md, Q2/Q6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestReasons:
    def test_supported_reasons_are_threshold_and_reactive_ltss(self) -> None:
        """package-service.md, Parameters: `Literal["threshold",
        "reactive_ltss"]`; ticket-audit-log.md, notes on `reason`."""
        assert frozenset({"threshold", "reactive_ltss"}) == (
            PRODUCT_RECALCULATION_REASONS
        )


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestGuards:
    @pytest.mark.parametrize(
        "reason", ["reactivation", "cvss", "va_override", "THRESHOLD", ""]
    )
    async def test_unsupported_reason_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        reason: Any,
    ) -> None:
        """The other `product_eligibility_changed` reasons belong to other
        boundaries; an unsupported value is a caller contract violation."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="reason"),
        ):
            await _recalculate(db_session, ticket, product, reason=reason)

        assert recorder.statements == []
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_events(db_session, ticket) == []

    async def test_missing_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)
        missing = uuid.uuid4()

        _, recorder = await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: recalculate_product_eligibility_for_ticket(
                db_session,
                ticket_id=missing,
                catalog_product_id=product.id,
                reason="threshold",
                evaluation_date=EVAL,
            ),
            error=TicketNotFoundError,
        )

        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])

    @pytest.mark.parametrize("identifier", ["random-uuid", "occurrence-id"])
    async def test_missing_catalog_product_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        identifier: str,
    ) -> None:
        """Q1: `catalog_product_id` is a catalog `Product.id`; neither an
        unknown UUID nor the Ticket's own `TicketPackageProduct.id`
        resolves, and the operable Ticket keeps its stale occurrence."""
        ticket = await cveless(ticket_factory)
        target = await occurrence(ticket, await catalog(), eligible=False)
        product_id = uuid.uuid4() if identifier == "random-uuid" else target.id

        await _assert_no_effects(
            db_session,
            monkeypatch,
            ticket.id,
            lambda: recalculate_product_eligibility_for_ticket(
                db_session,
                ticket_id=ticket.id,
                catalog_product_id=product_id,
                reason="threshold",
                evaluation_date=EVAL,
            ),
            error=ProductNotFoundError,
        )

    async def test_ticket_lock_is_the_first_statement_and_the_only_row_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
    ) -> None:
        """package-service.md, step 1 and Canonical Mutation and No-Event
        Matrix (system `package_service` uses the Ticket root): no User
        lock and no CVE lock, even for a CVE-associated Ticket."""
        ticket = await _cve_ticket(ticket_factory, cve_with, Assessment("9.8"))
        product = await catalog()
        await occurrence(ticket, product, eligible=False)

        with StatementRecorder(db_session) as recorder:
            result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert _is_ticket_lock(recorder.statements[0])
        assert recorder.row_locks() == [recorder.statements[0]]

    @pytest.mark.parametrize(
        "status", [TicketStatus.NEW, TicketStatus.ANALYSIS], ids=str
    )
    async def test_never_assigns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """Acting user convention: a system operation never calls
        `auto_assign_actor()`, so an unassigned Ticket stays unassigned
        and a `New` Ticket is not promoted."""
        ticket = await cveless(ticket_factory, status=status)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)
        assign = Spy(monkeypatch, "auto_assign_actor")

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert assign.calls == []
        assert (await ticket_state(db_session, ticket.id))[:2] == (status, None)
        assert [e.event_type for e in await ticket_events(db_session, ticket)] == [
            "product_eligibility_changed"
        ]

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Transaction ownership: the effective change and its event stay
        in the caller's open transaction, and the caller's rollback then
        discards them."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        await occurrence(ticket, product, eligible=False)
        ticket_id = ticket.id

        async def forbidden(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("the service must not end the transaction")

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(db_session, "commit", forbidden)
            monkeypatch.setattr(db_session, "rollback", forbidden)
            result = await _recalculate(db_session, ticket, product)
            monkeypatch.undo()
            assert result == _result(1, 0, 1)
            assert db_session.in_transaction()
            assert len(await ticket_events_by_id(db_session, ticket_id)) == 1

        assert await eligibility(db_session, ticket_id) == [(False, False)]
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_mutates_no_other_dimension(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
    ) -> None:
        """package-service.md, Architectural Test Requirement: Dimension
        independence. The recalculated occurrence is released and directly
        excluded under an `IN_PROGRESS` `FIXED` track of an excluded
        package: only its `eligible` changes; the override marker,
        affectedness, delivery, release observation, and every exclusion
        marker are untouched."""
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        package = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime.now(UTC)
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            status=PackageStatus.FIXED.value,
            delivery_status=DeliveryStatus.IN_PROGRESS.value,
        )
        product = await catalog()
        target = await occurrence(
            ticket,
            product,
            eligible=False,
            track_id=track.id,
            released=True,
            excluded=True,
        )

        async def other_dimensions() -> tuple[Any, ...]:
            return tuple(
                (
                    await db_session.execute(
                        select(
                            TicketPackage.deleted_at,
                            TicketPackageTrack.status,
                            TicketPackageTrack.delivery_status,
                            TicketPackageTrack.deleted_at,
                            TicketPackageProduct.is_eligible_override,
                            TicketPackageProduct.released_at,
                            TicketPackageProduct.deleted_at,
                        )
                        .join(
                            TicketPackageTrack,
                            TicketPackageTrack.ticket_package_id == TicketPackage.id,
                        )
                        .join(
                            TicketPackageProduct,
                            TicketPackageProduct.ticket_package_track_id
                            == TicketPackageTrack.id,
                        )
                        .where(TicketPackageProduct.id == target.id)
                    )
                ).one()
            )

        seeded = await other_dimensions()
        assert seeded[1:3] == (PackageStatus.FIXED, DeliveryStatus.IN_PROGRESS)
        assert None not in (seeded[0], seeded[5], seeded[6])

        result = await _recalculate(db_session, ticket, product)

        assert result == _result(1, 0, 1)
        assert await other_dimensions() == seeded
        assert await persisted_occurrence(db_session, target) == (True, False)


# ---------------------------------------------------------------------------
# Whole-transaction rollback (ticket-audit-log.md, Testing Requirements 7,
# 20, and 24; package-service.md, Exceptions)
# ---------------------------------------------------------------------------


FAILURES = [
    "settings-missing",
    "invalid-default-version",
    "database",
    "audit",
    "reconcile-before",
    "reconcile-after",
    "final-flush",
]
"""`settings-missing`: no `default_cvss_version` row. `invalid-default-
version`: a persisted `3.0`, rejected by the Eligibility Score Resolution.
`database`: the first statement of the reconciliation fails after both
eligibility updates and events. `audit`: the second event fails after the
first update and event. `reconcile-*`: the reconciliation fails before it
runs or after it changed the status and registered the regression.
`final-flush`: the boundary's own flush after reconciliation fails."""

EXPECTED_ERRORS: dict[str, type[Exception]] = {
    "settings-missing": RequiredSystemSettingMissingError,
    "invalid-default-version": ValueError,
    "database": OperationalError,
}


@pytest.mark.integration
class TestRollback:
    """An assigned CVE-less `High` `Resolved` Ticket with two stale
    occurrences of the recalculated Product on two `AFFECTED` tracks: an
    uninterrupted call would change both, regress the Ticket to
    `Analyzed`, and register one convergence effect. Every failure
    propagates unchanged, and after the caller's rollback the occurrences,
    the Ticket state, its events, and the pending effects equal the
    pre-call state."""

    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_propagates_and_rollback_discards_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        system_setting_factory: SettingFactory,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        if failure != "settings-missing":
            await system_setting_factory(
                key="default_cvss_version",
                value="3.0" if failure == "invalid-default-version" else "3.1",
            )
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=assignee.id
        )
        product = await catalog()
        for _ in range(2):
            await occurrence(
                ticket, product, eligible=False, status=PackageStatus.AFFECTED
            )
        ticket_id = ticket.id

        async def snapshot() -> tuple[Any, ...]:
            return (
                await ticket_state(db_session, ticket_id),
                await ticket_events_by_id(db_session, ticket_id),
                await eligibility(db_session, ticket_id),
                pending_ticket_convergence_effects(db_session),
            )

        before = await snapshot()
        assert before == (
            (TicketStatus.RESOLVED, assignee.id, None, None, "High"),
            [],
            [(False, False), (False, False)],
            (),
        )
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_log = TicketAuditLog.log_event
        original_execute = db_session.execute
        original_flush = db_session.flush
        in_reconcile = reconciled = False
        product_events = 0

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
            nonlocal product_events
            if kwargs["event_type"] is TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED:
                product_events += 1
                if product_events == 2:
                    raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def execute(*args: Any, **kwargs: Any) -> Any:
            if in_reconcile:
                raise OperationalError(
                    "SELECT", None, Exception("injected database failure")
                )
            return await original_execute(*args, **kwargs)

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
            elif failure == "database":
                monkeypatch.setattr(db_session, "execute", execute)
            elif failure == "final-flush":
                monkeypatch.setattr(db_session, "flush", flush)

            with pytest.raises(EXPECTED_ERRORS.get(failure, RuntimeError)):
                await recalculate_product_eligibility_for_ticket(
                    db_session,
                    ticket_id=ticket_id,
                    catalog_product_id=product.id,
                    reason="threshold",
                    evaluation_date=EVAL,
                )

            monkeypatch.undo()
            if reconciled:
                # The regression registered its effect before the failure.
                assert pending_ticket_convergence_effects(db_session) == (
                    TicketConvergenceEffect(ticket_id),
                )

        assert await snapshot() == before


# ---------------------------------------------------------------------------
# Audit-history independence (ticket-audit-log.md, Testing Requirement 25)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestNoAuditHistoryRead:
    """testing-strategy.md, Audit Trail Testing: audit history is never
    queried to determine current state or idempotency. An effective call
    only inserts into `ticket_audit_event`; a no-op never touches it."""

    @pytest.mark.parametrize("seeded", [False, True], ids=["changed", "no-op"])
    async def test_call_never_selects_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_audit_event_factory: Callable[..., Awaitable[Any]],
        catalog: CatalogBuilder,
        occurrence: OccurrenceBuilder,
        seeded: bool,
    ) -> None:
        """A misleading earlier event claiming the occurrence is already
        `true` does not turn the change into a no-op."""
        ticket = await cveless(ticket_factory)
        product = await catalog()
        target = await occurrence(ticket, product, eligible=seeded)
        await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="product_eligibility_changed",
            old_value="false",
            new_value="true",
            detail={**await product_subject(db_session, target), "reason": "cvss"},
        )

        with StatementRecorder(db_session) as recorder:
            result = await _recalculate(db_session, ticket, product)

        changed = not seeded
        assert result == _result(1, 0, int(changed))
        assert await persisted_occurrence(db_session, target) == (True, False)
        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert recorder.selects_from("ticket_audit_event") == []
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []
        assert bool(audit) is changed
