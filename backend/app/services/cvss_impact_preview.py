"""Read-only impact preview of a proposed `default_cvss_version`.

See `docs/features/platform/default-cvss-version-operations.md`
(Default-CVSS Impact Preview) for the authoritative contract:
`get_default_cvss_version_impact()`, its fixed-size `DefaultCVSSVersionImpact`
result, and `CVSSPreviewTimeoutError`.

The preview projects the default-version mode of
`ticket_mutations.recalculate_cvss_chain()` without invoking it:

- severity and eligibility come from the pure resolutions of
  `services/cvss.py`, called with the proposed version and each CVE's
  complete assessment set (cvss-scoring.md, Read-Only Impact Projection);
- automatic Product eligibility comes from the shared evaluator of
  `services/product_eligibility.py` (package-model.md, Axis 2: Eligibility,
  Read-only projection);
- the gate comes from the pure projection of
  `services/ticket_gate_projection.py`, evaluated only when execution would
  perform its final reconciliation (Projected Impact).

Observation: every read uses the caller-owned request session. Each keyset
page is one SQL statement returning every input of its CVEs, with
sub-collections aggregated per CVE, so each unit's contribution comes from
one committed observation (Consistency and Staleness). The function never
commits, rolls back, locks, writes, touches Redis, publishes a task, or
registers a post-commit effect.

Deadline: one monotonic budget starts at function entry. Before every
statement that can block, the transaction-local `statement_timeout` is set
to the remaining budget, so PostgreSQL cancels a statement that would
outlive it; the budget is also checked after each statement and before
each projection batch. A cancelled statement leaves the request
transaction for its owner to roll back. On every return that leaves the
transaction usable, the original `statement_timeout` is restored.
"""

from __future__ import annotations

import math
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Final, Literal

from sqlalchemy import (
    JSON,
    ColumnElement,
    Select,
    Text,
    and_,
    case,
    cast,
    func,
    select,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    GATE_ZONE_TICKET_STATUSES,
    OPERABLE_TICKET_STATUSES,
    CVSSVersion,
    LifecyclePhase,
    PackageStatus,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.cvss import (
    SUSE_PROVIDER_NAME,
    EligibilityResolution,
    resolve_eligibility_score,
    resolve_severity_score,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.product_service import lifecycle_phase_expression
from app.services.settings import SettingsServiceError, get_default_cvss_version
from app.services.ticket_gate_projection import (
    GateProductInput,
    GateTrackInput,
    project_gate_status,
)

PREVIEW_DEADLINE_SECONDS: Final = 30.0
"""The contract bound of one invocation (Timeout and Partial Results)."""

_PAGE_SIZE: Final = 1000
"""CVEs per keyset page: an internal choice, not configuration."""

_SUPPORTED_VERSIONS: Final = frozenset({CVSSVersion.V3_1.value, CVSSVersion.V4_0.value})
_ACCEPTED_VERSIONS: Final = frozenset(version.value for version in CVSSVersion)

_REGRESSED: Final = frozenset({TicketStatus.ANALYSIS, TicketStatus.ANALYZED})

_QUERY_CANCELED: Final = "57014"
"""SQLSTATE `query_canceled`, raised when `statement_timeout` expires."""


class CVSSPreviewTimeoutError(SettingsServiceError):
    """The preview deadline expired before a complete result existed.

    Every intermediate count is discarded. API handlers map it to
    `503 CVSS_PREVIEW_TIMEOUT` (default-cvss-version-operations.md,
    Preview Service Exception).
    """

    def __init__(self) -> None:
        super().__init__("The default-CVSS impact preview deadline expired.")


@dataclass(frozen=True, slots=True)
class DefaultCVSSVersionImpact:
    """The fixed-size preview aggregate (Result and Count Units)."""

    observed_default_cvss_version: str
    proposed_default_cvss_version: str
    no_op: bool
    cves_evaluated: int
    cve_severity_changes: int
    product_eligibility_changes: int
    product_eligibility_override_skips: int
    resolved_ticket_regressions: int


# Patch points for controlled clocks in tests.
_monotonic = time.monotonic


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def get_default_cvss_version_impact(
    session: AsyncSession,
    proposed_version: Literal["3.1", "4.0"],
) -> DefaultCVSSVersionImpact:
    """Project the impact of `proposed_version` on persisted derived state.

    Category B read with a database dependency
    (default-cvss-version-operations.md, Preview Service).

    Q1: `session` is the caller-owned request session; `proposed_version`
    is the proposed setting value.

    Q3: reads the observed setting once; returns the no-op result (every
    count `0`, no scan) when the proposal equals it; otherwise captures one
    UTC `evaluation_date` and the `max(CVE.id)` high-water mark, projects
    every CVE up to the mark page by page, and returns one complete
    aggregate. Nothing is written, locked, cached, or published.

    Q6: `RequiredSystemSettingMissingError`, database errors, and
    `ValueError` for a proposal other than `3.1`/`4.0` or an invalid
    persisted assessment set propagate unchanged. `CVSSPreviewTimeoutError`
    is raised when the monotonic deadline expires; no partial result is
    returned.
    """
    deadline = _Deadline(_monotonic() + PREVIEW_DEADLINE_SECONDS)
    if proposed_version not in _SUPPORTED_VERSIONS:
        raise ValueError("proposed_version must be '3.1' or '4.0'.")
    original_timeout: str = (
        await session.execute(
            select(func.current_setting("statement_timeout", type_=Text))
        )
    ).scalar_one()
    try:
        result = await _evaluate(session, proposed_version, deadline)
    except Exception as exc:
        # A statement error aborted the request transaction; its owner rolls
        # back, which also discards the transaction-local timeout.
        if not isinstance(exc, DBAPIError) and not isinstance(
            exc.__cause__, DBAPIError
        ):
            await _set_statement_timeout(session, original_timeout)
        raise
    await _set_statement_timeout(session, original_timeout)
    return result


async def _evaluate(
    session: AsyncSession, proposed_version: str, deadline: _Deadline
) -> DefaultCVSSVersionImpact:
    async with deadline.bounded(session):
        observed = await get_default_cvss_version(session)
    if proposed_version == observed:
        return DefaultCVSSVersionImpact(
            observed_default_cvss_version=observed,
            proposed_default_cvss_version=proposed_version,
            no_op=True,
            cves_evaluated=0,
            cve_severity_changes=0,
            product_eligibility_changes=0,
            product_eligibility_override_skips=0,
            resolved_ticket_regressions=0,
        )

    evaluation_date = _utc_now().date()
    async with deadline.bounded(session):
        # The greatest persisted `CVE.id` (PostgreSQL has no `max(uuid)`).
        mark = (
            await session.execute(select(CVE.id).order_by(CVE.id.desc()).limit(1))
        ).scalar_one_or_none()
    counts = _Counts()
    last_id: uuid.UUID | None = None
    while mark is not None:
        async with deadline.bounded(session):
            rows = (
                await session.execute(_page_statement(evaluation_date, mark, last_id))
            ).all()
        deadline.check()
        for row in rows:
            _project_unit(row, proposed_version, counts)
        if len(rows) < _PAGE_SIZE:
            break
        last_id = rows[-1].id

    return DefaultCVSSVersionImpact(
        observed_default_cvss_version=observed,
        proposed_default_cvss_version=proposed_version,
        no_op=False,
        cves_evaluated=counts.cves_evaluated,
        cve_severity_changes=counts.cve_severity_changes,
        product_eligibility_changes=counts.product_eligibility_changes,
        product_eligibility_override_skips=counts.product_eligibility_override_skips,
        resolved_ticket_regressions=counts.resolved_ticket_regressions,
    )


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------


class _Deadline:
    """One monotonic budget for the complete invocation."""

    def __init__(self, end: float) -> None:
        self._end = end

    def remaining(self) -> float:
        return self._end - _monotonic()

    def check(self) -> None:
        if self.remaining() <= 0:
            raise CVSSPreviewTimeoutError()

    @asynccontextmanager
    async def bounded(self, session: AsyncSession) -> AsyncIterator[None]:
        """Bound the statements issued inside by the remaining budget.

        Rounds up to whole milliseconds (never `0`, which would disable
        the timeout), so PostgreSQL cancels no earlier than the client
        deadline. A cancellation is an expiry only when the budget has
        elapsed; any other `query_canceled` propagates unchanged.
        """
        self.check()
        await _set_statement_timeout(
            session, str(max(1, math.ceil(self.remaining() * 1000)))
        )
        try:
            yield
        except DBAPIError as exc:
            if _sqlstate(exc) == _QUERY_CANCELED and self.remaining() <= 0:
                raise CVSSPreviewTimeoutError() from exc
            raise
        self.check()


async def _set_statement_timeout(session: AsyncSession, value: str) -> None:
    await session.execute(select(func.set_config("statement_timeout", value, True)))


def _sqlstate(exc: DBAPIError) -> str | None:
    orig = exc.orig
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return sqlstate if isinstance(sqlstate, str) else None


# ---------------------------------------------------------------------------
# Page statement
# ---------------------------------------------------------------------------


def _json_rows(*columns: Any) -> ColumnElement[Any]:
    """Aggregate one JSON array per row; `NULL` for an empty set."""
    return func.json_agg(func.json_build_array(*columns), type_=JSON)


def _page_statement(
    evaluation_date: date, mark: uuid.UUID, last_id: uuid.UUID | None
) -> Select[Any]:
    """One keyset page of CVEs with every unit input.

    Each row carries the CVE identity and persisted severity, the complete
    assessment set, the associated Ticket's status, and, for a Ticket whose
    occurrences execution evaluates, its complete track and occurrence sets
    (excluded and EOL records included) with each catalog threshold and
    lifecycle phase on `evaluation_date`. Sub-collections are aggregated
    per CVE as JSON, so rows are never multiplied; numeric values travel
    as text to stay exact.
    """
    assessments = (
        select(
            _json_rows(
                CVECVSSAssessment.provider_name,
                CVECVSSAssessment.cvss_version,
                cast(CVECVSSAssessment.score, Text),
            )
        )
        .where(CVECVSSAssessment.cve_id == CVE.id)
        .correlate(CVE)
        .scalar_subquery()
    )
    tracks = (
        select(
            _json_rows(
                cast(TicketPackageTrack.id, Text),
                TicketPackage.deleted_at.is_not(None),
                TicketPackageTrack.deleted_at.is_not(None),
                TicketPackageTrack.status,
            )
        )
        .select_from(TicketPackageTrack)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == Ticket.id)
        .correlate(Ticket)
        .scalar_subquery()
    )
    occurrences = (
        select(
            _json_rows(
                cast(TicketPackageProduct.ticket_package_track_id, Text),
                TicketPackageProduct.deleted_at.is_not(None),
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at.is_not(None),
                cast(Product.cvss_threshold, Text),
                lifecycle_phase_expression(evaluation_date),
            )
        )
        .select_from(TicketPackageProduct)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Product, Product.id == TicketPackageProduct.product_id)
        .where(TicketPackage.ticket_id == Ticket.id)
        .correlate(Ticket)
        .scalar_subquery()
    )
    evaluated = Ticket.status.in_(OPERABLE_TICKET_STATUSES)

    def _bounds(column: Any) -> list[ColumnElement[bool]]:
        bounds: list[ColumnElement[bool]] = [column <= mark]
        if last_id is not None:
            bounds.append(column > last_id)
        return bounds

    return (
        select(
            CVE.id,
            CVE.severity,
            assessments.label("assessments"),
            Ticket.status.label("ticket_status"),
            case((evaluated, tracks), else_=None).label("tracks"),
            case((evaluated, occurrences), else_=None).label("occurrences"),
        )
        # The page bounds are repeated on the Ticket join, so a merge join
        # starts at the page instead of at the beginning of the
        # `ticket.cve_id` index; the joined rows are unchanged.
        .outerjoin(Ticket, and_(Ticket.cve_id == CVE.id, *_bounds(Ticket.cve_id)))
        .where(and_(*_bounds(CVE.id)))
        .order_by(CVE.id)
        .limit(_PAGE_SIZE)
    )


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Counts:
    cves_evaluated: int = 0
    cve_severity_changes: int = 0
    product_eligibility_changes: int = 0
    product_eligibility_override_skips: int = 0
    resolved_ticket_regressions: int = 0


@dataclass(frozen=True, slots=True)
class _Assessment:
    """A `CVSSAssessmentLike` decoded from one page row."""

    provider_name: str
    cvss_version: str
    score: Decimal


def _decode(value: list[Any] | None) -> list[Any]:
    """A decoded JSON aggregate column: `NULL` for an empty set."""
    return [] if value is None else value


def _project_unit(row: Any, proposed_version: str, counts: _Counts) -> None:
    """Project one CVE unit and add its effects to `counts`.

    Mirrors the default-version state matrix (ticket-mutations.md, CVSS
    Status Matrix): every CVE receives severity; `New` and the gate zone
    receive automatic eligibility; only the gate zone receives a gate
    result, and only when a gate input would change.
    """
    assessments = [
        _Assessment(provider, version, Decimal(score))
        for provider, version, score in _decode(row.assessments)
    ]
    severity = resolve_severity_score(assessments, proposed_version)
    projected_severity = severity.label.value if severity is not None else None
    severity_changed = projected_severity != row.severity
    if severity_changed:
        counts.cve_severity_changes += 1

    status = TicketStatus(row.ticket_status) if row.ticket_status else None
    if status in OPERABLE_TICKET_STATUSES:
        eligibility = resolve_eligibility_score(assessments, proposed_version)
        tracks, eligibility_changes = _project_tree(row, eligibility, counts)
        if status in GATE_ZONE_TICKET_STATUSES and (
            severity_changed or eligibility_changes
        ):
            projected = project_gate_status(
                tracks=tracks,
                has_cve=True,
                severity_resolved=projected_severity is not None,
                has_canonical_suse_assessment=any(
                    assessment.provider_name == SUSE_PROVIDER_NAME
                    and assessment.cvss_version in _ACCEPTED_VERSIONS
                    for assessment in assessments
                ),
            )
            if status is TicketStatus.RESOLVED and projected in _REGRESSED:
                counts.resolved_ticket_regressions += 1
    counts.cves_evaluated += 1


def _project_tree(
    row: Any, eligibility: EligibilityResolution, counts: _Counts
) -> tuple[list[GateTrackInput], int]:
    """Project every occurrence's eligibility; return the gate inputs.

    Every occurrence is evaluated, whatever its exclusion, lifecycle, or
    affectedness. An override is preserved and counted as a skip; the gate
    observes the projected automatic value or the preserved value.
    """
    products: dict[str, list[GateProductInput]] = {}
    changes = 0
    for (
        track_id,
        excluded,
        eligible,
        override,
        released,
        threshold,
        phase,
    ) in _decode(row.occurrences):
        lifecycle_phase = LifecyclePhase(phase) if phase is not None else None
        automatic = evaluate_product_eligibility(
            is_eligible_override=override,
            lifecycle_phase=lifecycle_phase,
            cvss_threshold=Decimal(threshold) if threshold is not None else None,
            eligibility_score=eligibility,
        ).automatic_eligible
        if automatic is None:
            counts.product_eligibility_override_skips += 1
            effective = eligible
        else:
            effective = automatic
            if automatic != eligible:
                changes += 1
        products.setdefault(track_id, []).append(
            GateProductInput(
                excluded=excluded,
                lifecycle_phase=lifecycle_phase,
                eligible=effective,
                released=released,
            )
        )
    counts.product_eligibility_changes += changes
    tracks = [
        GateTrackInput(
            package_excluded=package_excluded,
            track_excluded=track_excluded,
            status=PackageStatus(track_status),
            products=tuple(products.get(track_id, ())),
        )
        for track_id, package_excluded, track_excluded, track_status in _decode(
            row.tracks
        )
    ]
    return tracks, changes
