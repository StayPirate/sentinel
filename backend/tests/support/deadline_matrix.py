"""Shared input matrix for Ticket deadline and track milestone rules.

`docs/features/tickets/ticket-deadlines.md` (Testing Requirement 10)
requires the pure functions and the service-layer SQL expressions to be
driven from one shared input matrix, so that a new evidence case exercises
both. This module is that matrix. Its consumers are:

- the pure-function tests (`tests/test_services/test_ticket_deadlines.py`);
- the package-tree projection over persisted rows
  (`tests/test_services/test_package_service.py`);
- the SQL/pure parity test over persisted rows
  (`tests/test_services/test_ticket_deadline_expressions.py`).

Each `DeadlineCase` describes one Ticket with one package and one track in
terms of **persisted evidence**: Ticket severity, status, and CVE presence;
the package and track exclusion markers; the track's workflow type,
affectedness, and delivery status; its Product occurrences
(`ProductEvidence`); and the IBS request actions linked to it or to another
track (`RequestEvidence`). `tests/support/deadline_persistence.py` builds
exactly these rows. The already-derived inputs of
`resolve_track_milestones()` (`track_actionable`,
`has_actionable_eligible_product`, `all_actionable_eligible_released`,
`has_active_release_request`) are derived here from the same evidence by an
oracle transcribed from the specifications (package-model.md, Derived
Actionability; ticket-deadlines.md, Completion Evidence), never computed by
the modules under test.

Expected results are transcribed independently from the specification.
`DeadlineCase.expected_due_dates()` gives the expected absolute UTC due
dates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from app.core.enums import (
    CurrentPhase,
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    MilestoneStatus,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)

CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, 123456, tzinfo=UTC)
"""Fixed Ticket start with a non-midnight time of day and microseconds."""

# ticket-deadlines.md (Due Dates) — offsets in days of
# (triage, submission, um, qa, release) per SLA tier.
TIER_30_OFFSETS_DAYS = (3, 18, 21, 30, 30)
TIER_90_OFFSETS_DAYS = (9, 54, 63, 90, 90)
TIER_180_OFFSETS_DAYS = (18, 108, 126, 180, 180)

# Evaluation instants relative to CREATED_AT for the 30-day tier.
BEFORE_ANY_DUE = CREATED_AT + timedelta(days=1)
AT_TRIAGE_DUE = CREATED_AT + timedelta(days=3)
JUST_AFTER_TRIAGE_DUE = AT_TRIAGE_DUE + timedelta(microseconds=1)
AFTER_TRIAGE_DUE = CREATED_AT + timedelta(days=5)
AFTER_SUBMISSION_DUE = CREATED_AT + timedelta(days=19)
AFTER_UM_DUE = CREATED_AT + timedelta(days=22)
AFTER_ALL_DUE = CREATED_AT + timedelta(days=31)

D = MilestoneStatus.DONE
P = MilestoneStatus.PENDING
O = MilestoneStatus.OVERDUE  # noqa: E741 - mirrors the specification value
NA = MilestoneStatus.NOT_APPLICABLE
N = None  # the `null` milestone status

RELEASE = IBSRequestActionType.MAINTENANCE_RELEASE
INCIDENT = IBSRequestActionType.MAINTENANCE_INCIDENT

ACTIVE_RELEASE_REQUEST_STATES: Final = frozenset(
    {IBSRequestState.NEW, IBSRequestState.REVIEW, IBSRequestState.ACCEPTED}
)
"""Transcribed from ticket-deadlines.md (Completion Evidence, `um`)."""

INACTIVE_RELEASE_REQUEST_STATES: Final = frozenset(
    {
        IBSRequestState.DECLINED,
        IBSRequestState.REVOKED,
        IBSRequestState.SUPERSEDED,
        IBSRequestState.DELETED,
    }
)

Statuses = tuple[
    MilestoneStatus | None,
    MilestoneStatus | None,
    MilestoneStatus | None,
    MilestoneStatus | None,
]


@dataclass(frozen=True, slots=True)
class ProductEvidence:
    """One Product occurrence under the case's track.

    `eol`: the catalog Product's lifecycle phase is `eol` on the evaluation
    date (otherwise it is in General Support). `excluded`: the occurrence's
    own `deleted_at` is set. `released`: `released_at` is set.
    """

    eligible: bool = True
    released: bool = False
    excluded: bool = False
    eol: bool = False


@dataclass(frozen=True, slots=True)
class RequestEvidence:
    """One IBS request action linked to the case's track, or to another
    track when `correlated` is false."""

    action_type: IBSRequestActionType = RELEASE
    state: IBSRequestState = IBSRequestState.NEW
    correlated: bool = True


@dataclass(frozen=True, slots=True)
class DeadlineCase:
    """One matrix row: persisted evidence and expected results.

    `expected_offsets_days` is `None` when no due dates exist; otherwise
    the (triage, submission, um, qa, release) offsets from `created_at`.
    `expected_statuses` are the (triage, submission, um, qa) milestone
    statuses.
    """

    id: str
    expected_offsets_days: tuple[int, int, int, int, int] | None
    expected_statuses: Statuses
    expected_current_phase: CurrentPhase | None
    severity: Severity | None = Severity.HIGH
    ticket_status: TicketStatus = TicketStatus.ANALYSIS
    ticket_has_cve: bool = True
    workflow_type: WorkflowType = WorkflowType.IBS
    track_status: PackageStatus = PackageStatus.AFFECTED
    delivery_status: DeliveryStatus = DeliveryStatus.PENDING
    package_excluded: bool = False
    track_excluded: bool = False
    products: tuple[ProductEvidence, ...] = (ProductEvidence(),)
    requests: tuple[RequestEvidence, ...] = ()
    evaluation_instant: datetime = BEFORE_ANY_DUE
    created_at: datetime = field(default=CREATED_AT)

    # --- Oracle: derived inputs of `resolve_track_milestones()` -----------

    def _product_actionable(self, product: ProductEvidence) -> bool:
        # package-model.md (Derived Actionability): all three direct markers
        # clear and the lifecycle phase is not `eol`.
        return not (
            self.package_excluded
            or self.track_excluded
            or product.excluded
            or product.eol
        )

    def _actionable_eligible(self) -> list[ProductEvidence]:
        return [p for p in self.products if self._product_actionable(p) and p.eligible]

    @property
    def track_actionable(self) -> bool:
        """Both direct markers clear and at least one actionable Product."""
        return (
            not self.package_excluded
            and not self.track_excluded
            and any(self._product_actionable(p) for p in self.products)
        )

    @property
    def has_actionable_eligible_product(self) -> bool:
        return bool(self._actionable_eligible())

    @property
    def all_actionable_eligible_released(self) -> bool:
        return all(p.released for p in self._actionable_eligible())

    @property
    def has_active_release_request(self) -> bool:
        return any(
            r.correlated
            and r.action_type is RELEASE
            and r.state in ACTIVE_RELEASE_REQUEST_STATES
            for r in self.requests
        )

    # --- Function arguments -------------------------------------------------

    def due_dates_kwargs(self) -> dict[str, Any]:
        """Keyword arguments of `compute_due_dates()`."""
        return {
            "created_at": self.created_at,
            "severity": self.severity,
            "ticket_status": self.ticket_status,
        }

    def milestone_kwargs(self) -> dict[str, Any]:
        """Keyword arguments of `resolve_track_milestones()` except `due_dates`."""
        return {
            "ticket_has_cve": self.ticket_has_cve,
            "workflow_type": self.workflow_type,
            "track_status": self.track_status,
            "track_actionable": self.track_actionable,
            "has_actionable_eligible_product": self.has_actionable_eligible_product,
            "all_actionable_eligible_released": self.all_actionable_eligible_released,
            "delivery_status": self.delivery_status,
            "has_active_release_request": self.has_active_release_request,
            "evaluation_instant": self.evaluation_instant,
        }

    def expected_due_dates(self) -> tuple[datetime, ...] | None:
        """Expected absolute (triage, submission, um, qa, release) UTC dates."""
        if self.expected_offsets_days is None:
            return None
        return tuple(
            self.created_at + timedelta(days=days)
            for days in self.expected_offsets_days
        )


EXPECTATION_FIELDS: Final = frozenset(
    {"id", "expected_offsets_days", "expected_statuses", "expected_current_phase"}
)
"""`DeadlineCase` fields that are not inputs."""

_T30 = TIER_30_OFFSETS_DAYS
_UNRELEASED = ProductEvidence()
_RELEASED = ProductEvidence(released=True)
_NOT_ELIGIBLE = ProductEvidence(eligible=False)
_EOL = ProductEvidence(eol=True)
_EXCLUDED = ProductEvidence(excluded=True)
_ACTIVE_RR = RequestEvidence()

DEADLINE_CASES: tuple[DeadlineCase, ...] = (
    # --- Rule 1: no SLA ----------------------------------------------------
    DeadlineCase(
        id="no_sla_ignored",
        ticket_status=TicketStatus.IGNORED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="no_sla_duplicated",
        ticket_status=TicketStatus.DUPLICATED,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="no_sla_severity_none_label",
        severity=Severity.NONE,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="no_sla_cve_less_severity_manual_none_label",
        ticket_has_cve=False,
        severity=Severity.NONE,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="no_sla_severity_none_label_non_actionable",
        severity=Severity.NONE,
        track_excluded=True,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="no_sla_manual_zone_precedes_non_actionable",
        ticket_status=TicketStatus.IGNORED,
        track_excluded=True,
        expected_offsets_days=None,
        expected_statuses=(N, N, N, N),
        expected_current_phase=None,
    ),
    # --- SLA tiers -----------------------------------------------------------
    DeadlineCase(
        id="tier_critical_30_days",
        severity=Severity.CRITICAL,
        expected_offsets_days=_T30,
        expected_statuses=(D, P, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="tier_high_30_days",
        severity=Severity.HIGH,
        ticket_status=TicketStatus.ANALYZED,
        expected_offsets_days=_T30,
        expected_statuses=(D, P, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="tier_medium_90_days",
        severity=Severity.MEDIUM,
        evaluation_instant=AFTER_ALL_DUE,  # still before the 90-day submission
        expected_offsets_days=TIER_90_OFFSETS_DAYS,
        expected_statuses=(D, P, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="tier_low_180_days",
        severity=Severity.LOW,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=CREATED_AT + timedelta(days=17),  # before the 18-day triage
        expected_offsets_days=TIER_180_OFFSETS_DAYS,
        expected_statuses=(P, P, P, P),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="tier_unresolved_severity_uses_30_days",
        severity=None,
        ticket_status=TicketStatus.NEW,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, O, O, O),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="dates_exist_for_resolved_ticket",
        ticket_status=TicketStatus.RESOLVED,
        track_status=PackageStatus.FIXED,
        products=(_RELEASED,),
        delivery_status=DeliveryStatus.RELEASED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, D),
        expected_current_phase=CurrentPhase.DONE,
    ),
    # --- Rule 2: non-actionable track ---------------------------------------
    DeadlineCase(
        id="non_actionable_track_excluded",
        track_excluded=True,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(NA, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="non_actionable_package_excluded",
        package_excluded=True,
        requests=(_ACTIVE_RR,),
        expected_offsets_days=_T30,
        expected_statuses=(NA, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="non_actionable_all_products_eol",
        products=(_EOL, ProductEvidence(eol=True, eligible=False)),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(NA, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="non_actionable_all_products_excluded",
        products=(_EXCLUDED,),
        expected_offsets_days=_T30,
        expected_statuses=(NA, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="non_actionable_git_track_cve_less",
        products=(_EOL,),
        ticket_has_cve=False,
        workflow_type=WorkflowType.GIT,
        expected_offsets_days=_T30,
        expected_statuses=(NA, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    # --- Observability: Git tracks and CVE-less Tickets ---------------------
    DeadlineCase(
        id="git_track_untriaged_overdue",
        workflow_type=WorkflowType.GIT,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, N, N, N),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="git_track_triaged_null_reached_first",
        workflow_type=WorkflowType.GIT,
        track_status=PackageStatus.AFFECTED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, N, N, N),
        expected_current_phase=None,
    ),
    DeadlineCase(
        id="git_track_later_evidence_ignored",
        workflow_type=WorkflowType.GIT,
        track_status=PackageStatus.ANALYSIS,
        delivery_status=DeliveryStatus.RELEASED,
        requests=(_ACTIVE_RR,),
        products=(_RELEASED,),
        evaluation_instant=AFTER_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, N, N, N),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="cve_less_untriaged_pending",
        ticket_has_cve=False,
        severity=Severity.MEDIUM,  # severity_manual of a CVE-less Ticket
        track_status=PackageStatus.ANALYSIS,
        expected_offsets_days=TIER_90_OFFSETS_DAYS,
        expected_statuses=(P, N, N, N),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="cve_less_unset_severity_manual_uses_30_days",
        ticket_has_cve=False,
        severity=None,
        track_status=PackageStatus.FIXED,
        delivery_status=DeliveryStatus.RELEASED,
        requests=(_ACTIVE_RR,),
        products=(_RELEASED,),
        expected_offsets_days=_T30,
        expected_statuses=(D, N, N, N),
        expected_current_phase=None,
    ),
    # --- Applicability of later phases ---------------------------------------
    DeadlineCase(
        id="analysis_with_actionable_eligible_product_applicable",
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_SUBMISSION_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, O, P, P),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="analysis_without_actionable_eligible_product",
        track_status=PackageStatus.ANALYSIS,
        products=(_NOT_ELIGIBLE,),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, NA, NA, NA),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="affected_with_actionable_eligible_product_applicable",
        track_status=PackageStatus.AFFECTED,
        evaluation_instant=AFTER_SUBMISSION_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, O, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="affected_without_actionable_eligible_product",
        track_status=PackageStatus.AFFECTED,
        products=(_NOT_ELIGIBLE,),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="fixed_with_actionable_eligible_product_applicable",
        track_status=PackageStatus.FIXED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, O, O, O),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="fixed_without_actionable_eligible_product",
        track_status=PackageStatus.FIXED,
        products=(_NOT_ELIGIBLE,),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="only_eligible_product_is_eol",
        products=(_EOL, _NOT_ELIGIBLE),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="only_eligible_product_is_excluded",
        products=(_EXCLUDED, _NOT_ELIGIBLE),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="not_affected_later_phases_not_applicable",
        track_status=PackageStatus.NOT_AFFECTED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="wont_fix_later_phases_not_applicable",
        track_status=PackageStatus.WONT_FIX,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, NA, NA, NA),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="not_applicable_phase_evidence_does_not_complete_triage",
        track_status=PackageStatus.ANALYSIS,
        products=(_NOT_ELIGIBLE,),
        delivery_status=DeliveryStatus.RELEASED,
        requests=(_ACTIVE_RR,),
        evaluation_instant=AFTER_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, NA, NA, NA),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    # --- Completion evidence ---------------------------------------------------
    DeadlineCase(
        id="no_evidence_all_overdue_after_final_deadline",
        track_status=PackageStatus.AFFECTED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, O, O, O),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        # SR-only evidence: a correlated `maintenance_incident` action is not
        # `um` evidence; submission is completed by the delivery status.
        id="submission_evidence_in_progress_with_sr_only",
        delivery_status=DeliveryStatus.IN_PROGRESS,
        requests=(RequestEvidence(action_type=INCIDENT, state=IBSRequestState.NEW),),
        evaluation_instant=AFTER_UM_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, O, P),
        expected_current_phase=CurrentPhase.UM,
    ),
    DeadlineCase(
        id="submission_evidence_released",
        delivery_status=DeliveryStatus.RELEASED,
        evaluation_instant=AFTER_SUBMISSION_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, P),
        expected_current_phase=CurrentPhase.QA,
    ),
    DeadlineCase(
        id="um_evidence_active_release_request",
        delivery_status=DeliveryStatus.IN_PROGRESS,
        requests=(_ACTIVE_RR,),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, O),
        expected_current_phase=CurrentPhase.QA,
    ),
    DeadlineCase(
        id="um_evidence_delivery_released",
        delivery_status=DeliveryStatus.RELEASED,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, O),
        expected_current_phase=CurrentPhase.QA,
    ),
    # One correlated `maintenance_release` action per request state.
    *(
        DeadlineCase(
            id=f"correlated_rr_{state.value}_is_um_evidence",
            requests=(RequestEvidence(state=state),),
            expected_offsets_days=_T30,
            expected_statuses=(D, D, D, P),
            expected_current_phase=CurrentPhase.QA,
        )
        for state in sorted(ACTIVE_RELEASE_REQUEST_STATES)
    ),
    *(
        DeadlineCase(
            id=f"correlated_rr_{state.value}_is_not_um_evidence",
            requests=(RequestEvidence(state=state),),
            expected_offsets_days=_T30,
            expected_statuses=(D, P, P, P),
            expected_current_phase=CurrentPhase.SUBMISSION,
        )
        for state in sorted(INACTIVE_RELEASE_REQUEST_STATES)
    ),
    DeadlineCase(
        id="uncorrelated_active_rr_is_not_um_evidence",
        requests=(RequestEvidence(correlated=False),),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, O, O, O),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="correlated_accepted_sr_only_is_not_um_evidence",
        requests=(
            RequestEvidence(action_type=INCIDENT, state=IBSRequestState.ACCEPTED),
        ),
        expected_offsets_days=_T30,
        expected_statuses=(D, P, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="inactive_and_active_rr_is_um_evidence",
        requests=(
            RequestEvidence(state=IBSRequestState.DECLINED),
            RequestEvidence(state=IBSRequestState.REVIEW),
        ),
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, P),
        expected_current_phase=CurrentPhase.QA,
    ),
    DeadlineCase(
        id="qa_evidence_all_actionable_eligible_released",
        track_status=PackageStatus.FIXED,
        delivery_status=DeliveryStatus.RELEASED,
        products=(_RELEASED,),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, D),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="qa_one_actionable_eligible_product_unreleased",
        products=(_RELEASED, _UNRELEASED),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, O, O, O),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="qa_unreleased_excluded_and_eol_products_are_ignored",
        products=(_RELEASED, _EXCLUDED, _EOL),
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, D),
        expected_current_phase=CurrentPhase.DONE,
    ),
    # --- Monotonicity --------------------------------------------------------
    DeadlineCase(
        id="monotonic_release_completes_every_earlier_phase",
        track_status=PackageStatus.ANALYSIS,
        delivery_status=DeliveryStatus.PENDING,
        products=(_RELEASED, _NOT_ELIGIBLE),
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, D),
        expected_current_phase=CurrentPhase.DONE,
    ),
    DeadlineCase(
        id="monotonic_rr_completes_submission_and_triage",
        track_status=PackageStatus.ANALYSIS,
        requests=(_ACTIVE_RR,),
        evaluation_instant=AFTER_UM_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, P),
        expected_current_phase=CurrentPhase.QA,
    ),
    DeadlineCase(
        id="monotonic_sr_completes_triage_on_analysis_track",
        track_status=PackageStatus.ANALYSIS,
        delivery_status=DeliveryStatus.IN_PROGRESS,
        evaluation_instant=AFTER_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, P, P),
        expected_current_phase=CurrentPhase.UM,
    ),
    # --- Past-due boundary -----------------------------------------------------
    DeadlineCase(
        id="due_at_equal_to_instant_is_pending",
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AT_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(P, P, P, P),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="due_at_one_microsecond_before_instant_is_overdue",
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=JUST_AFTER_TRIAGE_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, P, P, P),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
    DeadlineCase(
        id="later_due_at_equal_to_instant_is_pending",
        evaluation_instant=CREATED_AT + timedelta(days=18),
        expected_offsets_days=_T30,
        expected_statuses=(D, P, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="later_due_at_one_microsecond_before_instant_is_overdue",
        evaluation_instant=CREATED_AT + timedelta(days=18, microseconds=1),
        expected_offsets_days=_T30,
        expected_statuses=(D, O, P, P),
        expected_current_phase=CurrentPhase.SUBMISSION,
    ),
    DeadlineCase(
        id="um_due_at_equal_to_instant_is_pending",
        delivery_status=DeliveryStatus.IN_PROGRESS,
        evaluation_instant=CREATED_AT + timedelta(days=21),
        expected_offsets_days=_T30,
        expected_statuses=(D, D, P, P),
        expected_current_phase=CurrentPhase.UM,
    ),
    DeadlineCase(
        id="qa_due_at_equal_to_instant_is_pending",
        requests=(_ACTIVE_RR,),
        evaluation_instant=CREATED_AT + timedelta(days=30),
        expected_offsets_days=_T30,
        expected_statuses=(D, D, D, P),
        expected_current_phase=CurrentPhase.QA,
    ),
    # --- Current phase ---------------------------------------------------------
    DeadlineCase(
        id="current_phase_first_pending_after_done",
        delivery_status=DeliveryStatus.IN_PROGRESS,
        evaluation_instant=BEFORE_ANY_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(D, D, P, P),
        expected_current_phase=CurrentPhase.UM,
    ),
    DeadlineCase(
        id="current_phase_overdue_before_null",
        ticket_has_cve=False,
        track_status=PackageStatus.ANALYSIS,
        evaluation_instant=AFTER_ALL_DUE,
        expected_offsets_days=_T30,
        expected_statuses=(O, N, N, N),
        expected_current_phase=CurrentPhase.TRIAGE,
    ),
)
"""Every matrix row. Case ids are unique."""
