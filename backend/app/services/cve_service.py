"""CVE service: CVE identifier resolution and accessibility-constrained reads.

See `docs/features/tickets/cve-service.md` (Ownership; CVE Read and
Accessibility Boundary; Caller Validation Responsibility; Service Read
Contracts; Exceptions) for the module contract, and
`docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a CVE)
for the CVSS read implemented here.

CVE accessibility is a projection of the one canonical Ticket visibility
predicate (`docs/features/identity/rbac.md`, Scope and Confidential Ticket
Visibility): a CVE without an associated Ticket is visible, and a CVE with
an associated Ticket is visible exactly when that Ticket is visible to the
caller. The projection composes `ticket_visibility_condition()` and never
defines a second predicate. It constrains the same database selection that
supplies the response, so no preliminary access decision ever authorizes a
later unconstrained query.

Reads are Category B: they create no row or audit event, acquire no lock,
never flush, commit, or roll back, and perform no network I/O. Unexpected
database and programming exceptions propagate unchanged. Results are
semantic service values, not Pydantic schemas.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Final

import structlog
from sqlalchemy import ColumnElement, Row, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSAssessmentSeverity, CVSSVersion
from app.core.exceptions import CVENotFoundError
from app.core.identifiers import is_valid_cve_id
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.ticket import Ticket
from app.services.cvss import (
    CVSSBaseMetrics,
    EligibilityResolution,
    ParsedCVSSVector,
    SeverityResolution,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.settings import (
    RequiredSystemSettingMissingError,
    default_cvss_version_select,
)
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

logger = structlog.get_logger(__name__)

# Canonical list order of the bounded assessment set: version
# 4.0 > 3.1 > 3.0 > 2.0 (cvss-scoring.md, Get CVSS Assessments for a CVE).
_LIST_VERSION_RANK: Final[Mapping[CVSSVersion, int]] = {
    CVSSVersion.V4_0: 0,
    CVSSVersion.V3_1: 1,
    CVSSVersion.V3_0: 2,
    CVSSVersion.V2_0: 3,
}


class CVSSAssessmentIntegrityError(RuntimeError):
    """A persisted `CVECVSSAssessment` row violates its vector-derived unit.

    `docs/data-model.md` (CVECVSSAssessment, Notes) requires `cvss_version`,
    `score`, `severity`, and the canonical `vector_string` to be one
    consistent vector-derived unit written only through the shared parser.
    A row that breaks that invariant is corrupt data, not a caller error:
    it is not a `ServiceError`, is never mapped to a domain error code, and
    therefore surfaces as the global `500 INTERNAL_ERROR`. The message is
    static; the identifying details go to the structured ERROR log emitted
    before raising.
    """

    def __init__(self) -> None:
        super().__init__(
            "A persisted CVSS assessment violates its vector-derived unit."
        )


@dataclass(frozen=True, slots=True)
class CVSSAssessmentProjection:
    """One persisted assessment with its metrics expanded from the vector."""

    id: uuid.UUID
    provider_name: str
    cvss_version: CVSSVersion
    score: Decimal
    severity: CVSSAssessmentSeverity
    vector_string: str
    metrics: CVSSBaseMetrics
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CVECVSSAssessments:
    """The bounded CVSS composite of one accessible CVE.

    `assessments` is the complete set in canonical list order.
    `default_cvss_version` is the setting observed in the same database
    view; `severity` (absent for an empty set) and `eligibility` are the
    pure resolutions of the complete set under that version.
    """

    assessments: tuple[CVSSAssessmentProjection, ...]
    default_cvss_version: CVSSVersion
    severity: SeverityResolution | None
    eligibility: EligibilityResolution


def _cve_accessibility_condition(caller: TicketCaller) -> ColumnElement[bool]:
    """CVE accessibility for a statement that outer-joins the CVE's Ticket.

    The enclosing statement must select from `CVE` outer-joined to `Ticket`
    on `Ticket.cve_id = CVE.id` (unique, so at most one Ticket). No joined
    Ticket means a ticketless, public CVE; otherwise the canonical Ticket
    predicate decides. For an anonymous caller that predicate evaluates no
    grant or maintainer branch.
    """
    return or_(Ticket.id.is_(None), ticket_visibility_condition(caller))


def _mismatched_fields(row: Row[Any], parsed: ParsedCVSSVector | None) -> list[str]:
    """Names of stored columns that disagree with the re-parsed vector."""
    if parsed is None:
        return ["vector_string"]
    mismatched = []
    if parsed.canonical_vector != row.vector_string:
        mismatched.append("vector_string")
    if parsed.version.value != row.cvss_version:
        mismatched.append("cvss_version")
    if parsed.score != row.score:
        mismatched.append("score")
    if parsed.severity.value != row.severity:
        mismatched.append("severity")
    return mismatched


def _project_assessment(cve_id: str, row: Row[Any]) -> CVSSAssessmentProjection:
    """Expand one persisted row, verifying its vector-derived unit.

    The stored vector must parse through the shared parser and already be
    canonical, and the stored version, score, and severity must equal the
    values derived from it. Any disagreement is logged at ERROR with the
    identifiers an operator needs to repair the row (never the vector
    content) and raises `CVSSAssessmentIntegrityError`.
    """
    try:
        parsed: ParsedCVSSVector | None = validate_cvss_vector(row.vector_string)
    except InvalidCVSSVectorError:
        parsed = None
    mismatched = _mismatched_fields(row, parsed)
    if parsed is None or mismatched:
        logger.error(
            "cvss_assessment_integrity_violation",
            cve_id=cve_id,
            assessment_id=str(row.assessment_id),
            fields=mismatched,
        )
        raise CVSSAssessmentIntegrityError()
    return CVSSAssessmentProjection(
        id=row.assessment_id,
        provider_name=row.provider_name,
        cvss_version=parsed.version,
        score=parsed.score,
        severity=parsed.severity,
        vector_string=parsed.canonical_vector,
        metrics=parsed.metrics,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _list_order(assessment: CVSSAssessmentProjection) -> tuple[int, str]:
    """Version rank, then provider by Unicode code point (Python `str` order)."""
    return (_LIST_VERSION_RANK[assessment.cvss_version], assessment.provider_name)


async def get_cvss_assessments(
    db: AsyncSession,
    *,
    cve_id: str,
    caller: TicketCaller,
) -> CVECVSSAssessments:
    """Read the CVSS composite of one accessible CVE.

    See `docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a
    CVE). `cve_id` is the raw `{cve_id}` path value; `caller` is the
    request-resolved caller information.

    1. A value rejected by `core.identifiers.is_valid_cve_id()` raises
       `CVENotFoundError` without any query. Lookup is otherwise by the
       unique `CVE.cve_id`; the internal CVE UUID is never accepted.
    2. One statement selects the CVE, its outer-joined Ticket constrained by
       the CVE accessibility projection, every assessment row, and the
       `default_cvss_version` setting as a scalar subquery, so all of them
       come from one coherent PostgreSQL view. No row means the CVE is
       missing or inaccessible: `CVENotFoundError`.
    3. An accessible CVE whose setting row is absent raises
       `RequiredSystemSettingMissingError`.
    4. Each row is verified and expanded (`_project_assessment()`); the set
       is ordered by version `4.0 > 3.1 > 3.0 > 2.0`, then provider name by
       Unicode code point, independent of database collation.
    5. Severity and eligibility are the pure resolutions of the complete,
       unfiltered set under the observed default version.

    Raises:
        CVENotFoundError: Malformed, missing, or inaccessible CVE.
        RequiredSystemSettingMissingError: The setting row is absent.
        CVSSAssessmentIntegrityError: A persisted row violates its
            vector-derived unit.
        ValueError: The persisted setting is not `3.1` or `4.0`.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()

    statement = (
        select(
            default_cvss_version_select()
            .scalar_subquery()
            .label("default_cvss_version"),
            CVECVSSAssessment.id.label("assessment_id"),
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.score,
            CVECVSSAssessment.severity,
            CVECVSSAssessment.vector_string,
            CVECVSSAssessment.created_at,
            CVECVSSAssessment.updated_at,
        )
        .select_from(CVE)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
        .outerjoin(CVECVSSAssessment, CVECVSSAssessment.cve_id == CVE.id)
        .where(CVE.cve_id == cve_id, _cve_accessibility_condition(caller))
    )
    rows: Sequence[Row[Any]] = (await db.execute(statement)).all()
    if not rows:
        raise CVENotFoundError()

    default_cvss_version: str | None = rows[0].default_cvss_version
    if default_cvss_version is None:
        raise RequiredSystemSettingMissingError()

    assessments = sorted(
        (
            _project_assessment(cve_id, row)
            for row in rows
            if row.assessment_id is not None
        ),
        key=_list_order,
    )
    severity = resolve_severity_score(assessments, default_cvss_version)
    eligibility = resolve_eligibility_score(assessments, default_cvss_version)
    return CVECVSSAssessments(
        assessments=tuple(assessments),
        default_cvss_version=CVSSVersion(default_cvss_version),
        severity=severity,
        eligibility=eligibility,
    )
