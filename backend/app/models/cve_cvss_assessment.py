"""CVECVSSAssessment model — one provider's CVSS assessment of a CVE.

See `docs/data-model.md` (CVECVSSAssessment) and
`docs/features/tickets/cvss-scoring.md` (Version-Specific Assessment
Severity, Assessment Persistence and Ticket Status, Data Model) for the
full specification. This module implements only the persistence root;
vector parsing lives in `app/services/cvss.py` and assessment mutations
belong to the CVE ingestion and CVSS mutation services.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVECVSSAssessment(Base):
    """A CVSS Base assessment of one CVE by one provider and version.

    `cvss_version`, `score`, `severity`, and `vector_string` form one
    vector-derived unit produced by the shared parser. `cvss_version`
    stores a `CVSSVersion` value and `severity` a lowercase
    `CVSSAssessmentSeverity` value; both are Category B columns. The
    database deliberately enforces no range or format CHECK: validation
    belongs to the writing services (`docs/data-model.md`,
    CVECVSSAssessment).
    """

    __tablename__ = "cve_cvss_assessment"
    __table_args__ = (
        UniqueConstraint(
            "cve_id",
            "provider_name",
            "cvss_version",
            name="uq_cve_cvss_assessment_cve_id_provider_name_cvss_version",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False)
    cvss_version: Mapped[str] = mapped_column(String(10), nullable=False)
    score: Mapped[Decimal] = mapped_column(Numeric(3, 1), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    vector_string: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="cvss_assessments")
