"""Shared helpers for the manual SUSE CVSS upsert tests.

Consumers:

- `tests/test_services/test_upsert_cvss_assessment.py` (status matrix,
  classification, authority, assignment, gate, propagation, audit,
  accessibility, lock order);
- `tests/test_services/test_upsert_cvss_assessment_atomicity.py`
  (rollback, evaluation date, independent-session races).

The vectors and their canonical values, scores, and severities are
transcribed from the CVSS specifications (cvss-scoring.md, Accepted Base
Vectors and Severity); nothing here computes an expectation with the
module under test.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Scope
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.user import User
from app.services.ticket_mutations import (
    CVSSAssessmentMutationResult,
    CVSSMutationCaller,
    upsert_cvss_assessment,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.ticket_mutations import EVAL, EventRow


@dataclass(frozen=True, slots=True)
class Vector:
    """One accepted Base vector with its transcribed parsed values."""

    canonical: str
    version: str
    score: str
    assessment_severity: str
    unified: str

    @property
    def audit_value(self) -> str:
        """The canonical `cvss_assessment_changed` value for `SUSE`."""
        return f"SUSE v{self.version} {self.canonical} ({self.score})"

    def columns(self) -> dict[str, Any]:
        """The consistent persisted vector-derived unit."""
        return {
            "cvss_version": self.version,
            "score": Decimal(self.score),
            "severity": self.assessment_severity,
            "vector_string": self.canonical,
        }


V31_CRITICAL = Vector(
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", "9.8", "critical", "Critical"
)
V31_CRITICAL_REORDERED = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
"""`V31_CRITICAL` with its metrics in reverse order (same canonical vector)."""
V31_CRITICAL_10 = Vector(
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "3.1",
    "10.0",
    "critical",
    "Critical",
)
V31_HIGH = Vector(
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "3.1", "8.1", "high", "High"
)
V31_MEDIUM = Vector(
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "3.1", "4.8", "medium", "Medium"
)
V31_NONE = Vector(
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "3.1", "0.0", "none", "None"
)
V30_CRITICAL = Vector(
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.0", "9.8", "critical", "Critical"
)
V20_CRITICAL = Vector("AV:N/AC:L/Au:N/C:C/I:C/A:C", "2.0", "10.0", "high", "Critical")
V40_CRITICAL = Vector(
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "4.0",
    "9.3",
    "critical",
    "Critical",
)


async def upsert(
    db: AsyncSession,
    cve_id: uuid.UUID,
    vector: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    provider: str = "SUSE",
    evaluation_date: date | None = EVAL,
    **kwargs: Any,
) -> CVSSAssessmentMutationResult:
    """Call the service as the POST handler would, with the fixed `EVAL`."""
    return await upsert_cvss_assessment(
        db,
        cve_id=cve_id,
        provider=provider,
        vector_string=vector,
        caller=CVSSMutationCaller.MANUAL_SUSE,
        acting_user_id=actor.id,
        ticket_caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
        **kwargs,
    )


def cvss_event(actor: User, old: Vector | None, new: Vector) -> EventRow:
    """The acting-user `cvss_assessment_changed` event."""
    return EventRow(
        "cvss_assessment_changed",
        actor.id,
        old.audit_value if old is not None else None,
        new.audit_value,
        None,
        None,
    )


def assignment_event(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def persisted_assessments(
    db: AsyncSession, cve_id: uuid.UUID
) -> list[tuple[str, str, Decimal, str, str]]:
    """Every `(provider, version, score, severity, vector)` of a CVE, by
    version then provider."""
    rows = await db.execute(
        select(
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.score,
            CVECVSSAssessment.severity,
            CVECVSSAssessment.vector_string,
        )
        .where(CVECVSSAssessment.cve_id == cve_id)
        .order_by(CVECVSSAssessment.cvss_version, CVECVSSAssessment.provider_name)
    )
    return [tuple(row) for row in rows]


def unit(provider: str, vector: Vector) -> tuple[str, str, Decimal, str, str]:
    """The expected persisted row of `persisted_assessments()`."""
    return (
        provider,
        vector.version,
        Decimal(vector.score),
        vector.assessment_severity,
        vector.canonical,
    )
