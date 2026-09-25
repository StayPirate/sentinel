"""Pure remediation SLA due dates and per-track milestones.

Single database-free formula owner for Ticket deadlines. See
`docs/features/tickets/ticket-deadlines.md` (SLA Tier, Phase Shares, Due
Dates, Evaluation Instant, Track Milestones, Pure Resolution Functions)
for the complete contract.

Every function is Category B: no database access, write, audit, lock, or
external call. Deadlines are informational only and are never persisted.
This module imports no other service module, so `ticket_service` and
`package_service` may both use it without a dependency cycle.

Time handling follows `docs/conventions.md` (Timestamps & Timezones):
naive datetimes are rejected with `ValueError`, and aware inputs are
converted to UTC before arithmetic. The conversion never changes the
instant; it makes every offset an exact elapsed duration (arithmetic on
a zone with daylight-saving transitions would otherwise shift wall-clock
time) and makes every due date a UTC value.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Final

from app.core.enums import (
    CurrentPhase,
    DeliveryStatus,
    MilestonePhase,
    MilestoneStatus,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)

SLA_TIER_DAYS: Final[Mapping[Severity, int]] = MappingProxyType(
    {
        Severity.CRITICAL: 30,
        Severity.HIGH: 30,
        Severity.MEDIUM: 90,
        Severity.LOW: 180,
    }
)
"""SLA tier in days per resolved severity label. `Severity.NONE` has no SLA."""

UNRESOLVED_SLA_DAYS: Final = 30
"""SLA tier for an unresolved (SQL `NULL`) severity: the worst case."""

PHASE_SHARES: Final[Mapping[MilestonePhase, int]] = MappingProxyType(
    {
        MilestonePhase.TRIAGE: 10,
        MilestonePhase.SUBMISSION: 50,
        MilestonePhase.UM: 10,
        MilestonePhase.QA: 30,
    }
)
"""Integer percentage of the SLA window per phase, in phase order.

Invariants: every share is an integer of at least 1 and the shares sum to
exactly 100, so the QA milestone always equals the final release deadline.
"""

_SECONDS_PER_DAY_PERCENT: Final = 864  # 86 400 seconds per day / 100 percent

_MANUAL_ZONE: Final = frozenset({TicketStatus.IGNORED, TicketStatus.DUPLICATED})
_LATER_PHASE_APPLICABLE_STATUSES: Final = frozenset(
    {PackageStatus.ANALYSIS, PackageStatus.AFFECTED, PackageStatus.FIXED}
)
_SUBMITTED_DELIVERY_STATUSES: Final = frozenset(
    {DeliveryStatus.IN_PROGRESS, DeliveryStatus.RELEASED}
)
_PHASES: Final = tuple(MilestonePhase)


def _require_aware(value: datetime, name: str) -> None:
    if value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime.")


@dataclass(frozen=True, slots=True)
class DueDates:
    """Ticket-level due dates (UTC) of one Ticket with an SLA.

    Service-internal typed value, not a Pydantic schema. `qa` always
    equals `release`, the final SLA deadline.
    """

    triage: datetime
    submission: datetime
    um: datetime
    qa: datetime
    release: datetime

    def __post_init__(self) -> None:
        for phase in (*_PHASES, "release"):
            _require_aware(getattr(self, phase), f"DueDates.{phase}")

    def for_phase(self, phase: MilestonePhase) -> datetime:
        """Due date of one milestone phase."""
        due_at: datetime = getattr(self, phase.value)
        return due_at


@dataclass(frozen=True, slots=True)
class TrackMilestones:
    """Milestone statuses and current phase of one track.

    Service-internal typed value. Python `None` represents the `null`
    status (no SLA, or the phase is not observable for the track) and the
    `null` current phase.
    """

    triage: MilestoneStatus | None
    submission: MilestoneStatus | None
    um: MilestoneStatus | None
    qa: MilestoneStatus | None
    current_phase: CurrentPhase | None

    def status_of(self, phase: MilestonePhase) -> MilestoneStatus | None:
        """Status of one milestone phase."""
        status: MilestoneStatus | None = getattr(self, phase.value)
        return status


def resolve_sla_days(severity: Severity | None) -> int | None:
    """Return the SLA tier in days for a resolved severity.

    `severity` is the resolved severity label; `None` means SQL `NULL`
    (unresolved) and selects `UNRESOLVED_SLA_DAYS`. The `Severity.NONE`
    label (resolved score exactly 0.0) has no SLA and returns `None`.
    Infallible.
    """
    if severity is None:
        return UNRESOLVED_SLA_DAYS
    return SLA_TIER_DAYS.get(severity)


def compute_due_dates(
    *,
    created_at: datetime,
    severity: Severity | None,
    ticket_status: TicketStatus,
) -> DueDates | None:
    """Compute the Ticket-level due dates from the immutable start.

    Each milestone is `created_at + d * 864 * c` seconds for SLA tier `d`
    days and cumulative phase share `c` percent; `release` is
    `created_at + d` days. Offsets are exact, so every due date keeps the
    time of day of `created_at`. Returns `None` when the Ticket is
    `Ignored` or `Duplicated`, or its resolved severity is the
    `Severity.NONE` label (SQL `NULL` uses the 30-day tier).

    Raises:
        ValueError: `created_at` is naive (validated for every input).
    """
    _require_aware(created_at, "created_at")
    sla_days = resolve_sla_days(severity)
    if ticket_status in _MANUAL_ZONE or sla_days is None:
        return None

    start = created_at.astimezone(UTC)
    due: dict[MilestonePhase, datetime] = {}
    cumulative = 0
    for phase in _PHASES:
        cumulative += PHASE_SHARES[phase]
        due[phase] = start + timedelta(
            seconds=sla_days * _SECONDS_PER_DAY_PERCENT * cumulative
        )
    return DueDates(
        triage=due[MilestonePhase.TRIAGE],
        submission=due[MilestonePhase.SUBMISSION],
        um=due[MilestonePhase.UM],
        qa=due[MilestonePhase.QA],
        release=start + timedelta(days=sla_days),
    )


def resolve_track_milestones(
    *,
    due_dates: DueDates | None,
    ticket_has_cve: bool,
    workflow_type: WorkflowType,
    track_status: PackageStatus,
    track_actionable: bool,
    has_actionable_eligible_product: bool,
    all_actionable_eligible_released: bool,
    delivery_status: DeliveryStatus,
    has_active_release_request: bool,
    evaluation_instant: datetime,
) -> TrackMilestones:
    """Resolve the milestone statuses and current phase of one track.

    Rules, first match wins: (1) `due_dates is None` (no SLA) → every
    status and `current_phase` is `None`; (2) a non-actionable track →
    every status is `not_applicable` and `current_phase` is `done`;
    (3) otherwise `triage` is always evaluated, while `submission`, `um`,
    and `qa` are `None` when the Ticket has no CVE or the track is a Git
    track, and `not_applicable` unless the track status is `ANALYSIS`,
    `AFFECTED`, or `FIXED` with at least one actionable eligible Product.

    An evaluated phase is completed when it, or any later evaluated
    phase, has completion evidence: `triage` — track status is not
    `ANALYSIS`; `submission` — delivery is `IN_PROGRESS` or `RELEASED`;
    `um` — `has_active_release_request` or delivery is `RELEASED`; `qa` —
    `all_actionable_eligible_released` (meaningful only when
    `has_actionable_eligible_product`). A completed phase is `done`; a
    phase whose due date is strictly before `evaluation_instant` is
    `overdue`; otherwise it is `pending`.

    `current_phase` skips `done` and `not_applicable` phases in order; the
    first `pending` or `overdue` phase is current, a `None` status reached
    first yields `None`, and skipping every phase yields `done`.

    Raises:
        ValueError: `evaluation_instant` is naive (validated for every
            input).
    """
    _require_aware(evaluation_instant, "evaluation_instant")

    if due_dates is None:
        return TrackMilestones(
            triage=None, submission=None, um=None, qa=None, current_phase=None
        )

    if not track_actionable:
        na = MilestoneStatus.NOT_APPLICABLE
        return TrackMilestones(
            triage=na, submission=na, um=na, qa=na, current_phase=CurrentPhase.DONE
        )

    later_observable = ticket_has_cve and workflow_type != WorkflowType.GIT
    later_applicable = (
        track_status in _LATER_PHASE_APPLICABLE_STATUSES
        and has_actionable_eligible_product
    )
    evidence: dict[MilestonePhase, bool] = {
        MilestonePhase.TRIAGE: track_status != PackageStatus.ANALYSIS,
        MilestonePhase.SUBMISSION: delivery_status in _SUBMITTED_DELIVERY_STATUSES,
        MilestonePhase.UM: (
            has_active_release_request or delivery_status == DeliveryStatus.RELEASED
        ),
        MilestonePhase.QA: all_actionable_eligible_released,
    }

    # Phases fixed by observability/applicability; absent phases are evaluated.
    fixed: dict[MilestonePhase, MilestoneStatus | None] = {}
    for phase in _PHASES[1:]:
        if not later_observable:
            fixed[phase] = None
        elif not later_applicable:
            fixed[phase] = MilestoneStatus.NOT_APPLICABLE

    statuses: dict[MilestonePhase, MilestoneStatus | None] = {}
    later_evidence = False
    for phase in reversed(_PHASES):
        if phase in fixed:
            statuses[phase] = fixed[phase]
            continue
        later_evidence = later_evidence or evidence[phase]
        if later_evidence:
            statuses[phase] = MilestoneStatus.DONE
        elif due_dates.for_phase(phase) < evaluation_instant:
            statuses[phase] = MilestoneStatus.OVERDUE
        else:
            statuses[phase] = MilestoneStatus.PENDING

    return TrackMilestones(
        triage=statuses[MilestonePhase.TRIAGE],
        submission=statuses[MilestonePhase.SUBMISSION],
        um=statuses[MilestonePhase.UM],
        qa=statuses[MilestonePhase.QA],
        current_phase=_current_phase(statuses),
    )


def _current_phase(
    statuses: Mapping[MilestonePhase, MilestoneStatus | None],
) -> CurrentPhase | None:
    for phase in _PHASES:
        status = statuses[phase]
        if status is None:
            return None
        if status in (MilestoneStatus.PENDING, MilestoneStatus.OVERDUE):
            return CurrentPhase(phase.value)
    return CurrentPhase.DONE
