"""Single-session service integration tests for `set_product_eligibility()`
(backend/app/services/package_service.py), part A.

Owning specifications:

- docs/features/packages/package-service.md (Acting user convention;
  Consumer caller context and Ticket accessibility; Auto-Assignment Rule;
  `set_product_eligibility()`; Record Creation Logic; Service Exceptions;
  Architectural Test Requirement: Forward transitions, Auto-assignment,
  Override metadata transitions, Public Product identity, Human-readable
  Product audit subjects, Dimension independence (eligibility part)).
- docs/features/packages/package-model.md (Axis 2: Eligibility, rules
  1-5; Authorized-User Overrides Product Eligibility; Derived
  Actionability; Gate Participation; Override Model; Override Product
  Eligibility, including Reset behavior and the response field table).
- docs/features/packages/product-catalog.md (Lifecycle Evaluator).
- docs/features/tickets/cvss-scoring.md (Eligibility Score Resolution).
- docs/features/tickets/tickets.md (Gate: Analysis -> Analyzed; Gate:
  Analyzed -> Resolved).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`;
  Assignment Eligibility Sanitization).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `product_eligibility_changed`; Rules; Canonical Mutation and No-Event
  Matrix row "Product eligibility or override ownership change";
  Cross-Event Ordering; detail JSONB Schema Contract; Testing Requirements
  1-6, 8, 10, 21).

The caller-boundary validation (a null actor, a non-`TicketCaller`
context, or a caller not identifying the actor raises `ValueError` before
any database operation) and the `override_action` classification are
recorded decisions D3 and D6 of the tracking issue.

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High`, is assigned to the acting VA, and each
factory-built track carries Products in General Support on `EVAL` with a
`NULL` threshold. A CVE-less Ticket resolves the `10.0` fallback score
(cvss-scoring.md, Eligibility Score Resolution), so an automatic
in-support Product with a `NULL` (implicit `0.0`) threshold is eligible.
A track in `ANALYSIS` keeps the Ticket in `Analysis` whatever the Product
eligibility, isolating the eligibility mutation from the gate. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
)
from app.core.exceptions import ServiceError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_service import (
    SYSTEM_INVOCATION,
    MutationOutcome,
    PackageServiceError,
    ProductEligibilityProjection,
    ProductNotFoundError,
    set_product_eligibility,
)
from app.services.ticket_audit_log import list_ticket_events
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import DEFAULT_VERSION, Assessment, CVEBuilder
from tests.support.product_eligibility import (
    assert_no_effects,
    eligibility_event,
    only_occurrence,
    persisted_occurrence,
    product_subject,
    set_default_version,
    set_eligibility,
    track_occurrences,
)
from tests.support.suse_cvss import V31_MEDIUM, assignment_event, upsert
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    REACTIVE_END,
    REACTIVE_GS_END,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    unassigned_event,
)
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

Factory = Callable[..., Awaitable[Any]]

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


async def _cve_ticket(
    ticket_factory: TicketFactory,
    cve_with: CVEBuilder,
    *assessments: Assessment,
    status: TicketStatus = TicketStatus.ANALYSIS,
    severity: Severity | None = Severity.HIGH,
    **overrides: Any,
) -> Ticket:
    """A CVE-associated Ticket whose CVE has the given severity and
    assessments."""
    cve = await cve_with(*assessments, severity=severity)
    return await ticket_factory(status=status.value, cve_id=cve.id, **overrides)


# ---------------------------------------------------------------------------
# Caller boundary (tracking-issue decision D3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCallerValidation:
    """package-service.md, Acting user convention (the boundary requires a
    non-null actor and has no system form) and Consumer caller context: an
    inconsistent pairing is a caller-contract violation rejected before any
    database statement."""

    @pytest.mark.parametrize(
        "case", ["null-actor", "other-user", "anonymous", "system-invocation"]
    )
    async def test_inconsistent_pairing_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        case: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)
        pairings: dict[str, tuple[Any, Any]] = {
            "null-actor": (None, TicketCaller.authenticated(actor.id, Scope.ALL)),
            "other-user": (actor.id, TicketCaller.authenticated(other.id, Scope.ALL)),
            "anonymous": (actor.id, TicketCaller()),
            "system-invocation": (actor.id, SYSTEM_INVOCATION),
        }
        acting_user_id, caller = pairings[case]

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await set_product_eligibility(
                db_session,
                ticket_id=ticket.id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                ticket_package_product_id=occurrence.id,
                eligible=False,
                acting_user_id=acting_user_id,
                caller=caller,
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await persisted_occurrence(db_session, occurrence) == (True, False)
        assert await ticket_events(db_session, ticket) == []
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Override metadata transitions
# ---------------------------------------------------------------------------

TRANSITIONS = [
    # (seed eligible, seed override, request, persisted, action)
    pytest.param(True, False, False, (False, True), "set", id="set-changed-boolean"),
    pytest.param(True, False, True, (True, True), "set", id="set-equal-true"),
    pytest.param(False, False, False, (False, True), "set", id="set-equal-false"),
    pytest.param(True, True, False, (False, True), "changed", id="change-to-false"),
    pytest.param(False, True, True, (True, True), "changed", id="change-to-true"),
    pytest.param(False, True, None, (True, False), "cleared", id="clear-changed"),
    pytest.param(True, True, None, (True, False), "cleared", id="clear-equal"),
]
"""package-service.md, `set_product_eligibility()` override steps 7-9 and
reset steps 7-10; package-model.md, Override Model. A clear recalculates
the CVE-less (10.0) in-support `NULL`-threshold Product to `true`."""


@pytest.mark.integration
class TestOverrideMetadataTransitions:
    """package-service.md, Architectural Test Requirement: Override metadata
    transitions; ticket-audit-log.md, Testing Requirements 10 and 21 (one
    event even when `old_value == new_value`)."""

    @pytest.mark.parametrize(
        ("seed", "override", "request_value", "persisted", "action"), TRANSITIONS
    )
    async def test_effective_transition_creates_one_event_and_reconciles_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        seed: bool,
        override: bool,
        request_value: bool | None,
        persisted: tuple[bool, bool],
        action: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eligible=seed, override=override),),
        )
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_eligibility(db_session, occurrence, request_value, actor)

        assert (result.outcome, result.evaluation_date) == (
            MutationOutcome.CHANGED,
            EVAL,
        )
        assert (result.product.eligible, result.product.is_eligible_override) == (
            persisted
        )
        assert await persisted_occurrence(db_session, occurrence) == persisted
        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": EVAL})
        ]
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, seed, persisted[0], action
            )
        ]
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            actor.id,
        )

    async def test_set_change_clear_sequence_classifies_each_action(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """Each call classifies from the state it reloads: an automatic
        `true` set to `false`, changed back to `true`, then cleared to the
        automatic `true` (equal old/new)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        for request_value in (False, True, None):
            await set_eligibility(db_session, occurrence, request_value, actor)

        assert await persisted_occurrence(db_session, occurrence) == (True, False)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, True, False, "set"),
            await eligibility_event(
                db_session, occurrence, actor, False, True, "changed"
            ),
            await eligibility_event(
                db_session, occurrence, actor, True, True, "cleared"
            ),
        ]

    @pytest.mark.parametrize("cleared", [True, False], ids=["cleared", "override"])
    async def test_later_manual_cvss_upsert_updates_only_a_cleared_occurrence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        cleared: bool,
    ) -> None:
        """package-model.md, Override Model (a cleared occurrence returns to
        automatic management; rule 1 preserves an override). The CVE has no
        assessment, so the clear recalculates with the `10.0` fallback
        against the `7.0` threshold (`true`); the later manual SUSE 3.1
        upsert of score 4.8 at the default version makes an automatic
        occurrence `false` with one system `reason = cvss` event, and leaves
        an override `true` without an event."""
        actor = await va_user()
        ticket = await _cve_ticket(
            ticket_factory, cve_with, severity=None, assignee_id=actor.id
        )
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(
                Prod(eligible=not cleared, override=True, threshold=Decimal("7.0")),
            ),
        )
        occurrence = await only_occurrence(db_session, track)
        assert ticket.cve_id is not None
        if cleared:
            await set_eligibility(db_session, occurrence, None, actor)
            assert await persisted_occurrence(db_session, occurrence) == (True, False)

        await upsert(db_session, ticket.cve_id, V31_MEDIUM.canonical, actor)

        cvss_product_events = [
            e
            for e in await ticket_events(db_session, ticket)
            if e.event_type == "product_eligibility_changed"
            and e.detail["reason"] == "cvss"
        ]
        subject = await product_subject(db_session, occurrence)
        if cleared:
            assert await persisted_occurrence(db_session, occurrence) == (False, False)
            assert cvss_product_events == [
                EventRow(
                    "product_eligibility_changed",
                    None,
                    "true",
                    "false",
                    None,
                    {**subject, "reason": "cvss"},
                )
            ]
        else:
            assert await persisted_occurrence(db_session, occurrence) == (True, True)
            assert cvss_product_events == []


# ---------------------------------------------------------------------------
# True no-ops (package-service.md, Idempotency; audit TR 21)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    """package-service.md, `set_product_eligibility()` step 5, Idempotency,
    and Auto-Assignment Rule: a true no-op returns the current Product
    before assignment, audit, reconciliation, or registration;
    package-model.md, Override Product Eligibility (the same response
    shape for a no-op)."""

    @pytest.mark.parametrize(
        ("seed", "override", "request_value"),
        [
            pytest.param(True, True, True, id="same-override-true"),
            pytest.param(False, True, False, id="same-override-false"),
            pytest.param(True, False, None, id="reset-automatic-true"),
            pytest.param(False, False, None, id="reset-automatic-false"),
        ],
    )
    @pytest.mark.parametrize("new_ticket", [False, True], ids=["stale", "new"])
    async def test_no_op_has_no_effect_and_returns_current_state(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        seed: bool,
        override: bool,
        request_value: bool | None,
        new_ticket: bool,
    ) -> None:
        """An unassigned Ticket and an active VA actor make an assignment
        (and, for `New`, the promotion) visible; the stale `Analyzed` status
        of a Ticket whose only track is in `ANALYSIS` would be corrected by
        any reconciliation. `reset-automatic-false` keeps a persisted
        `false` although a recalculation would give `true`."""
        actor = await va_user()
        status = TicketStatus.NEW if new_ticket else TicketStatus.ANALYZED
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eligible=seed, override=override),),
        )
        occurrence = await only_occurrence(db_session, track)

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(db_session, occurrence, request_value, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
        )

        assert result is not None
        assert (result.outcome, result.evaluation_date) == (
            MutationOutcome.NO_OP,
            EVAL,
        )
        assert (result.product.eligible, result.product.is_eligible_override) == (
            seed,
            override,
        )
        assert await persisted_occurrence(db_session, occurrence) == (seed, override)
        assert await ticket_state(db_session, ticket) == (status, None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Reset recalculation (package-model.md, Axis 2: Eligibility rules 2-5)
# ---------------------------------------------------------------------------

RESET_CASES = [
    # (assessments or None for a CVE-less Ticket, seeded Product, expected)
    pytest.param(
        None,
        Prod(reactive=True, threshold=None),
        False,
        id="reactive-support-forces-false-with-fallback-score",
    ),
    pytest.param(
        (Assessment("0.0"),),
        Prod(threshold=None),
        True,
        id="null-threshold-is-zero",
    ),
    pytest.param(
        (Assessment("5.0"),),
        Prod(lifecycle=False, threshold=Decimal("4.0")),
        True,
        id="null-lifecycle-no-rule-above-threshold",
    ),
    pytest.param(
        (Assessment("5.0"),),
        Prod(lifecycle=False, threshold=Decimal("6.0")),
        False,
        id="null-lifecycle-threshold-still-applies",
    ),
    pytest.param(
        (Assessment("6.9"),),
        Prod(threshold=Decimal("7.0")),
        False,
        id="suse-default-version-below-threshold",
    ),
    pytest.param(
        (Assessment("7.0"),),
        Prod(threshold=Decimal("7.0")),
        True,
        id="suse-default-version-equal-threshold",
    ),
    pytest.param(
        (
            Assessment("2.0", version="4.0"),
            Assessment("2.0", provider="Fictional Provider"),
        ),
        Prod(threshold=Decimal("9.9")),
        True,
        id="non-default-suse-and-external-ignored",
    ),
    pytest.param(
        (),
        Prod(threshold=Decimal("9.9")),
        True,
        id="no-assessment-fallback",
    ),
    pytest.param(
        None,
        Prod(threshold=Decimal("10.0")),
        True,
        id="cveless-fallback-equals-threshold",
    ),
    pytest.param(
        None,
        Prod(eol=True, threshold=None),
        True,
        id="eol-is-not-an-input",
    ),
    pytest.param(
        None,
        Prod(excluded=True, threshold=None),
        True,
        id="product-exclusion-is-not-an-input",
    ),
]
"""Each occurrence is seeded as an override of the opposite value, so the
clear changes the boolean. A second, actionable `ANALYSIS` track anchors
the Ticket in `Analysis`, so an EOL or excluded target cannot change the
gate result."""


def _override_of(spec: Prod, expected: bool) -> Prod:
    """`spec` as a manual override of `not expected`."""
    return Prod(
        eligible=not expected,
        override=True,
        eol=spec.eol,
        lifecycle=spec.lifecycle,
        excluded=spec.excluded,
        threshold=spec.threshold,
        reactive=spec.reactive,
    )


@pytest.mark.integration
class TestResetRecalculation:
    """package-service.md, `set_product_eligibility()` reset steps 7-10;
    package-model.md, Axis 2: Eligibility (rules 2-5; EOL and exclusion are
    not formula inputs) and Reset behavior; cvss-scoring.md, Eligibility
    Score Resolution (SUSE at the default version, otherwise `10.0`,
    including a CVE-less Ticket); product-catalog.md, Lifecycle Evaluator."""

    @pytest.mark.parametrize(("assessments", "spec", "expected"), RESET_CASES)
    async def test_clear_recalculates_from_current_inputs(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        assessments: tuple[Assessment, ...] | None,
        spec: Prod,
        expected: bool,
    ) -> None:
        actor = await va_user()
        if assessments is None:
            ticket = await cveless(ticket_factory, assignee_id=actor.id)
        else:
            ticket = await _cve_ticket(
                ticket_factory, cve_with, *assessments, assignee_id=actor.id
            )
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(_override_of(spec, expected),),
        )
        await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        result = await set_eligibility(db_session, occurrence, None, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            expected,
            False,
        )
        assert await persisted_occurrence(db_session, occurrence) == (expected, False)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, not expected, expected, "cleared"
            )
        ]

    @pytest.mark.parametrize("level", ["track", "package"])
    async def test_ancestor_exclusion_is_not_an_input(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        level: str,
    ) -> None:
        """An occurrence effectively excluded through its track or package
        recalculates exactly as an included one (CVE-less `10.0`, `NULL`
        threshold: `true`)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eligible=False, override=True),),
            track_excluded=level == "track",
            package_excluded=level == "package",
        )
        occurrence = await only_occurrence(db_session, track)

        await set_eligibility(db_session, occurrence, None, actor)

        assert await persisted_occurrence(db_session, occurrence) == (True, False)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, False, True, "cleared"
            )
        ]

    async def test_inconsistent_lifecycle_dates_apply_no_reactive_rule(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """product-catalog.md, Lifecycle Evaluator: a Reactive Support end
        without an Extended Support end makes the date set inconsistent, so
        the phase is `NULL` for every date (never `reactive_support`) and
        the CVE-less `10.0` score keeps the Product eligible."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.ANALYSIS.value
        )
        product = await product_factory(
            general_support_end_date=REACTIVE_GS_END,
            reactive_support_end_date=REACTIVE_END,
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=False,
            is_eligible_override=True,
        )

        result = await set_eligibility(db_session, occurrence, None, actor)

        assert (result.product.eligible, result.product.lifecycle_phase) == (
            True,
            None,
        )
        assert await persisted_occurrence(db_session, occurrence) == (True, False)

    @pytest.mark.parametrize(
        ("version", "expected"), [("3.1", False), ("4.0", True)], ids=["3.1", "4.0"]
    )
    async def test_current_default_version_setting_is_honoured(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        version: str,
        expected: bool,
    ) -> None:
        """package-model.md, Axis 2 (Important): the version is the current
        persisted setting, never hardcoded. SUSE 3.1 scores 5.0 and SUSE
        4.0 scores 9.0 against a 7.0 threshold."""
        actor = await va_user()
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment("5.0", version="3.1"),
            Assessment("9.0", version="4.0"),
            assignee_id=actor.id,
        )
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(
                Prod(eligible=not expected, override=True, threshold=Decimal("7.0")),
            ),
        )
        occurrence = await only_occurrence(db_session, track)
        await set_default_version(db_session, version)

        await set_eligibility(db_session, occurrence, None, actor)

        assert await persisted_occurrence(db_session, occurrence) == (expected, False)

    async def test_clear_changes_only_the_declared_occurrence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """A sibling override of the same track and a stale automatic sibling
        keep their values: the reset recalculates one occurrence only."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(
                Prod(eligible=False, override=True),
                Prod(eligible=False, override=True),
                Prod(eligible=False),
            ),
        )
        occurrences = await track_occurrences(db_session, track)
        target = next(o for o in occurrences if o.is_eligible_override)
        siblings = [o for o in occurrences if o.id != target.id]

        await set_eligibility(db_session, target, None, actor)

        assert await persisted_occurrence(db_session, target) == (True, False)
        assert sorted(
            [await persisted_occurrence(db_session, o) for o in siblings]
        ) == [
            (False, False),
            (False, True),
        ]
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, target, actor, False, True, "cleared")
        ]


# ---------------------------------------------------------------------------
# Forward and backward transitions through reconciliation
# ---------------------------------------------------------------------------

GATE_KINDS = pytest.mark.parametrize("kind", ["fixed-cve", "affected-cveless"])
"""`fixed-cve`: a `FIXED` track of a CVE-associated Ticket (a SUSE 3.1
assessment of 9.8 and CVE severity High satisfy the Analyzed gate), so an
eligible unreleased Product blocks clause (b) of the Resolved gate.
`affected-cveless`: an `AFFECTED` track of a CVE-less Ticket, blocked from
clause (c) while its Product is eligible."""


async def _gate_ticket(
    kind: str,
    status: TicketStatus,
    ticket_factory: TicketFactory,
    cve_with: CVEBuilder,
    actor_id: Any,
) -> tuple[Ticket, PackageStatus]:
    if kind == "fixed-cve":
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment("9.8"),
            status=status,
            assignee_id=actor_id,
        )
        return ticket, PackageStatus.FIXED
    return (
        await cveless(ticket_factory, status=status, assignee_id=actor_id),
        PackageStatus.AFFECTED,
    )


@pytest.mark.integration
class TestGateTransitions:
    """package-service.md, Architectural Test Requirement: Forward
    transitions (a track becoming resolution-complete because all its
    Products become ineligible) and backward transitions; tickets.md,
    Gate: Analyzed -> Resolved clauses (b) and (c); ticket-mutations.md,
    `reconcile_ticket_status()` (a `Resolved` regression registers one
    Ticket convergence effect); ticket-audit-log.md, Cross-Event Ordering
    (the final gate `status_change` is last)."""

    @GATE_KINDS
    async def test_last_eligible_unreleased_product_made_ineligible_resolves(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        actor = await va_user()
        ticket, track_status = await _gate_ticket(
            kind, TicketStatus.ANALYZED, ticket_factory, cve_with, actor.id
        )
        track = await tree(ticket, status=track_status, products=(Prod(),))
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_eligibility(db_session, occurrence, False, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.RESOLVED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, True, False, "set"),
            status_event(TicketStatus.ANALYZED, TicketStatus.RESOLVED),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    @GATE_KINDS
    @pytest.mark.parametrize(
        ("request_value", "action"),
        [(True, "changed"), (None, "cleared")],
        ids=["override-true", "clear"],
    )
    async def test_product_made_eligible_again_regresses_resolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        kind: str,
        request_value: bool | None,
        action: str,
    ) -> None:
        """The clear recalculates `true`: SUSE 9.8 (or the CVE-less `10.0`)
        against the implicit `0.0` threshold."""
        actor = await va_user()
        ticket, track_status = await _gate_ticket(
            kind, TicketStatus.RESOLVED, ticket_factory, cve_with, actor.id
        )
        track = await tree(
            ticket,
            status=track_status,
            products=(Prod(eligible=False, override=True),),
        )
        occurrence = await only_occurrence(db_session, track)

        result = await set_eligibility(db_session, occurrence, request_value, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYZED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, False, True, action),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYZED),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_released_eligible_product_keeps_fixed_track_complete(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """tickets.md, clause (b): an override making a released Product
        eligible leaves every actionable eligible Product released, so the
        `Resolved` Ticket stays `Resolved`."""
        actor = await va_user()
        ticket, _ = await _gate_ticket(
            "fixed-cve", TicketStatus.RESOLVED, ticket_factory, cve_with, actor.id
        )
        track = await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(eligible=False, released=True),),
        )
        occurrence = await only_occurrence(db_session, track)

        await set_eligibility(db_session, occurrence, True, actor)

        assert await ticket_state(db_session, ticket) == (
            TicketStatus.RESOLVED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, False, True, "set")
        ]
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Auto-assignment
# ---------------------------------------------------------------------------

INELIGIBLE_ACTORS = pytest.mark.parametrize(
    ("active", "roles"),
    [
        pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
        pytest.param(True, (Role.ADMIN,), id="admin-only"),
        pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
    ],
)


@pytest.mark.integration
class TestAutoAssignment:
    """package-service.md, Auto-Assignment Rule and `set_product_eligibility()`
    step 6; ticket-audit-log.md, Cross-Event Ordering (assignment and its
    `New -> Analysis` precede the direct event; the gate event is last)."""

    @pytest.mark.parametrize(
        ("override", "request_value", "old", "new", "action", "final"),
        [
            pytest.param(
                False, False, True, False, "set", TicketStatus.RESOLVED, id="set-false"
            ),
            pytest.param(
                False, True, True, True, "set", TicketStatus.ANALYZED, id="set-equal"
            ),
            pytest.param(
                True, None, True, True, "cleared", TicketStatus.ANALYZED, id="clear"
            ),
        ],
    )
    async def test_active_va_on_new_ticket_assigns_and_promotes_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        override: bool,
        request_value: bool | None,
        old: bool,
        new: bool,
        action: str,
        final: TicketStatus,
    ) -> None:
        """A CVE-less High `New` Ticket with one `AFFECTED` track: after the
        promotion, an eligible Product gives `Analyzed` and an ineligible
        one `Resolved` (clause (c))."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, override=override),),
        )
        occurrence = await only_occurrence(db_session, track)

        result = await set_eligibility(db_session, occurrence, request_value, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert await ticket_state(db_session, ticket) == (final, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            await eligibility_event(db_session, occurrence, actor, old, new, action),
            status_event(TicketStatus.ANALYSIS, final),
        ]

    async def test_active_va_on_unassigned_analysis_ticket_assigns_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        await set_eligibility(db_session, occurrence, False, actor)

        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            await eligibility_event(db_session, occurrence, actor, True, False, "set"),
        ]

    @INELIGIBLE_ACTORS
    @pytest.mark.parametrize(
        "status", [TicketStatus.NEW, TicketStatus.ANALYSIS], ids=str
    )
    async def test_ineligible_actor_changes_without_assignment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        status: TicketStatus,
    ) -> None:
        """ticket-mutations.md, `reconcile_ticket_status()` step 1: an
        unassigned `New` Ticket is outside the gate zone and stays `New`."""
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        occurrence = await only_occurrence(db_session, track)

        result = await set_eligibility(db_session, occurrence, False, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert await persisted_occurrence(db_session, occurrence) == (False, True)
        assert await ticket_state(db_session, ticket) == (status, None)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, True, False, "set")
        ]

    async def test_already_assigned_ticket_keeps_its_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        assignee = await va_user()
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eligible=False, override=True),),
        )
        occurrence = await only_occurrence(db_session, track)

        await set_eligibility(db_session, occurrence, None, actor)

        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            assignee.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, False, True, "cleared"
            )
        ]


# ---------------------------------------------------------------------------
# Audit payload and ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditPayload:
    """ticket-audit-log.md, Event Type Contract `product_eligibility_changed`
    (acting user, `true`/`false` values, `comment` `NULL`), detail JSONB
    Schema Contract (Product subject, `reason = va_override`, required
    `override_action`; `product_name` is `Product.display_name`, never
    `Product.name`; no internal UUID), Cross-Event Ordering, and Testing
    Requirements 1-6, 8, 10; package-service.md, Architectural Test
    Requirement: Human-readable Product audit subjects."""

    @staticmethod
    async def _occurrence(
        ticket: Ticket,
        *,
        eligible: bool,
        override: bool,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> tuple[Product, TicketPackageProduct]:
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-libwidget"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Distro:15-SP9:Update",
            status=PackageStatus.ANALYSIS.value,
        )
        product = await product_factory(
            name="exwidget-server",
            display_name="Example Widget Server 15 SP9",
            cpe="cpe:/o:example:widget_server:15:sp9",
            general_support_end_date=AFTER_EVAL,
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=override,
        )
        return product, occurrence

    @pytest.mark.parametrize(
        ("eligible", "override", "request_value", "old", "new", "action"),
        [
            pytest.param(True, False, False, "true", "false", "set", id="set"),
            pytest.param(False, True, True, "false", "true", "changed", id="changed"),
            pytest.param(True, True, None, "true", "true", "cleared", id="cleared"),
        ],
    )
    async def test_event_has_exact_literal_payload(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        eligible: bool,
        override: bool,
        request_value: bool | None,
        old: str,
        new: str,
        action: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        product, occurrence = await self._occurrence(
            ticket,
            eligible=eligible,
            override=override,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )

        await set_eligibility(db_session, occurrence, request_value, actor)

        events = await ticket_events(db_session, ticket)
        assert events == [
            EventRow(
                "product_eligibility_changed",
                actor.id,
                old,
                new,
                None,
                {
                    "track": "Example:Distro:15-SP9:Update",
                    "package": "example-libwidget",
                    "product_name": "Example Widget Server 15 SP9",
                    "product_cpe": "cpe:/o:example:widget_server:15:sp9",
                    "reason": "va_override",
                    "override_action": action,
                },
            )
        ]
        serialized = json.dumps(events[0].detail)
        for internal in (occurrence.id, product.id, ticket.id):
            assert str(internal) not in serialized
        assert "exwidget-server" not in serialized

    @pytest.mark.parametrize(
        "term", ["Widget Server 15 SP9", "cpe:/o:example:widget_server:15:sp9"]
    )
    async def test_event_is_searchable_by_product_name_and_cpe(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        term: str,
    ) -> None:
        """ticket-audit-log.md, Testing Requirement 8 (searchable by both
        event-time values)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        await db_session.refresh(ticket, ["sequence_id"])
        _, occurrence = await self._occurrence(
            ticket,
            eligible=True,
            override=False,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        await set_eligibility(db_session, occurrence, False, actor)

        page = await list_ticket_events(
            db_session,
            ticket_id=format_ticket_id(ticket.sequence_id),
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            search=term,
        )

        assert [
            (e.event_type, (e.detail or {}).get("override_action")) for e in page.items
        ] == [("product_eligibility_changed", "set")]

    @pytest.mark.parametrize(
        ("request_value", "action"),
        [(True, "changed"), (None, "cleared")],
        ids=["override-true", "clear"],
    )
    async def test_sanitation_follows_direct_event_and_precedes_gate_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        request_value: bool | None,
        action: str,
    ) -> None:
        """ticket-mutations.md, Assignment Eligibility Sanitization: the
        inactive assignee of an `Analyzed` result is cleared by a system
        `assignment` event after the direct event and before the final
        `status_change`. The Ticket is assigned when auto-assignment runs,
        so the active VA actor is not assigned."""
        inactive = await va_user(active=False)
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=inactive.id
        )
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, override=True),),
        )
        occurrence = await only_occurrence(db_session, track)

        await set_eligibility(db_session, occurrence, request_value, actor)

        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYZED, None)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(db_session, occurrence, actor, False, True, action),
            unassigned_event(inactive.username, "inactive assignee"),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYZED),
        ]


# ---------------------------------------------------------------------------
# Result projection (package-model.md, Override Product Eligibility response)
# ---------------------------------------------------------------------------


def _response(product: ProductEligibilityProjection) -> dict[str, Any]:
    """The Override Product Eligibility response fields of a projection,
    exactly the package-model.md field table."""
    return {
        "ticket_id": product.ticket_id,
        "package_name": product.package_name,
        "reference": product.reference,
        "id": product.id,
        "product_cpe": product.product_cpe,
        "product_name": product.product_name,
        "eligible": product.eligible,
        "is_eligible_override": product.is_eligible_override,
        "lifecycle_phase": product.lifecycle_phase,
        "actionable": product.actionable,
        "non_actionable_reason": product.non_actionable_reason,
    }


REASONS = [
    # (package, track, product excluded, eol, actionable, reason, phase)
    pytest.param(False, False, False, False, True, None, "gs", id="actionable"),
    pytest.param(
        False, False, False, True, False, NonActionableReason.EOL, "eol", id="eol"
    ),
    pytest.param(
        False,
        False,
        True,
        False,
        False,
        NonActionableReason.PRODUCT_EXCLUDED,
        "gs",
        id="product-excluded",
    ),
    pytest.param(
        False,
        False,
        True,
        True,
        False,
        NonActionableReason.PRODUCT_EXCLUDED,
        "eol",
        id="product-excluded-over-eol",
    ),
    pytest.param(
        False,
        True,
        False,
        False,
        False,
        NonActionableReason.TRACK_EXCLUDED,
        "gs",
        id="track-excluded",
    ),
    pytest.param(
        False,
        True,
        True,
        True,
        False,
        NonActionableReason.TRACK_EXCLUDED,
        "eol",
        id="track-excluded-over-product-and-eol",
    ),
    pytest.param(
        True,
        False,
        False,
        False,
        False,
        NonActionableReason.PACKAGE_EXCLUDED,
        "gs",
        id="package-excluded",
    ),
    pytest.param(
        True,
        True,
        True,
        True,
        False,
        NonActionableReason.PACKAGE_EXCLUDED,
        "eol",
        id="package-excluded-over-all",
    ),
]
"""package-model.md, Derived Actionability: the Product reason is the first
of `package_excluded`, `track_excluded`, `product_excluded`, `eol`."""


@pytest.mark.integration
class TestResultProjection:
    """package-model.md, Override Product Eligibility (response field table;
    the same shape for an effective change and a true no-op) and Derived
    Actionability; package-service.md, Architectural Test Requirement:
    Public Product identity (`id` is the occurrence, never the catalog
    `Product.id`)."""

    @pytest.mark.parametrize(
        ("eligible", "override", "request_value", "outcome", "gs_end", "phase"),
        [
            pytest.param(
                True,
                False,
                False,
                MutationOutcome.CHANGED,
                AFTER_EVAL,
                LifecyclePhase.GENERAL_SUPPORT,
                id="changed",
            ),
            pytest.param(
                False,
                True,
                False,
                MutationOutcome.NO_OP,
                AFTER_EVAL,
                LifecyclePhase.GENERAL_SUPPORT,
                id="no-op",
            ),
            pytest.param(
                True,
                True,
                None,
                MutationOutcome.CHANGED,
                None,
                None,
                id="cleared-without-lifecycle",
            ),
        ],
    )
    async def test_projection_matches_the_response_contract(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        eligible: bool,
        override: bool,
        request_value: bool | None,
        outcome: MutationOutcome,
        gs_end: Any,
        phase: LifecyclePhase | None,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        await db_session.refresh(ticket, ["sequence_id"])
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-libprojection"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Projection:Update",
            status=PackageStatus.ANALYSIS.value,
        )
        product: Product = await product_factory(
            name="exprojection",
            display_name="Example Projection Server 7",
            cpe="cpe:/o:example:projection_server:7",
            general_support_end_date=gs_end,
        )
        occurrence: TicketPackageProduct = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=override,
        )
        persisted = (False, True) if request_value is False else (True, False)

        result = await set_eligibility(db_session, occurrence, request_value, actor)

        assert (result.outcome, result.evaluation_date) == (outcome, EVAL)
        assert result.product.id != product.id
        assert _response(result.product) == {
            "ticket_id": f"SNTL-{ticket.sequence_id}",
            "package_name": "example-libprojection",
            "reference": "Example:Projection:Update",
            "id": occurrence.id,
            "product_cpe": "cpe:/o:example:projection_server:7",
            "product_name": "Example Projection Server 7",
            "eligible": persisted[0],
            "is_eligible_override": persisted[1],
            "lifecycle_phase": phase,
            "actionable": True,
            "non_actionable_reason": None,
        }

    @pytest.mark.parametrize(
        (
            "package_excluded",
            "track_excluded",
            "product_excluded",
            "eol",
            "actionable",
            "reason",
            "phase",
        ),
        REASONS,
    )
    async def test_reason_follows_the_canonical_precedence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        package_excluded: bool,
        track_excluded: bool,
        product_excluded: bool,
        eol: bool,
        actionable: bool,
        reason: NonActionableReason | None,
        phase: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eol=eol, excluded=product_excluded),),
            package_excluded=package_excluded,
            track_excluded=track_excluded,
        )
        occurrence = await only_occurrence(db_session, track)

        result = await set_eligibility(db_session, occurrence, False, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert (
            result.product.id,
            result.product.eligible,
            result.product.is_eligible_override,
            result.product.lifecycle_phase,
            result.product.actionable,
            result.product.non_actionable_reason,
        ) == (
            occurrence.id,
            False,
            True,
            LifecyclePhase.EOL if phase == "eol" else LifecyclePhase.GENERAL_SUPPORT,
            actionable,
            reason,
        )


# ---------------------------------------------------------------------------
# Dimension independence (eligibility part)
# ---------------------------------------------------------------------------


async def _other_dimensions(
    db: AsyncSession, track: TicketPackageTrack
) -> tuple[Any, ...]:
    """Every non-eligibility value of the track's subtree: package marker;
    track status, delivery, and marker; each occurrence's release
    observation and marker (occurrence order)."""
    track_row = (
        await db.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageTrack.id == track.id)
        )
    ).one()
    products = (
        await db.execute(
            select(TicketPackageProduct.released_at, TicketPackageProduct.deleted_at)
            .where(TicketPackageProduct.ticket_package_track_id == track.id)
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    return tuple(track_row), [tuple(p) for p in products]


@pytest.mark.integration
class TestDimensionIndependence:
    """package-service.md, Architectural Test Requirement: Dimension
    independence (eligibility part); package-model.md, Authorized-User
    Overrides Product Eligibility (the track status is not affected) and
    Three Orthogonal Dimensions. The target occurrence is released and
    directly excluded under an `IN_PROGRESS` `FIXED` track of an excluded
    package; a sibling occurrence is an automatic `false`."""

    @pytest.mark.parametrize(
        ("override", "request_value"),
        [(False, False), (True, False), (True, None)],
        ids=["set", "change", "clear"],
    )
    async def test_eligibility_change_mutates_no_other_dimension(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        override: bool,
        request_value: bool | None,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(
                Prod(eligible=True, override=override, released=True, excluded=True),
                Prod(eligible=False),
            ),
            package_excluded=True,
        )
        track.delivery_status = DeliveryStatus.IN_PROGRESS.value
        await db_session.flush()
        occurrences = await track_occurrences(db_session, track)
        target = next(o for o in occurrences if o.released_at is not None)
        (sibling,) = [o for o in occurrences if o.id != target.id]
        seeded = await _other_dimensions(db_session, track)
        assert seeded[0][1:3] == (PackageStatus.FIXED, DeliveryStatus.IN_PROGRESS)
        assert seeded[0][0] is not None
        assert seeded[0][3] is None

        result = await set_eligibility(db_session, target, request_value, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _other_dimensions(db_session, track) == seeded
        assert await persisted_occurrence(db_session, sibling) == (False, False)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProductNotFoundError:
    """package-service.md, Service Exceptions: a module-owned exception with
    a static message that never reveals another path."""

    def test_inherits_package_service_error_with_a_static_message(self) -> None:
        assert issubclass(ProductNotFoundError, PackageServiceError)
        assert issubclass(PackageServiceError, ServiceError)
        assert str(ProductNotFoundError()) == "Product not found."
