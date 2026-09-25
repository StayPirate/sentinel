"""CVE model — root of the CVE domain.

See `docs/data-model.md` (CVE, CveState Enum) and
`docs/features/tickets/cvss-scoring.md` (Unified CVE Severity) for the
full specification. This module implements only the persistence root;
ingestion, rejection handling, and severity recalculation belong to the
CVE service and CVSS mutation workflows.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import CveState
from app.database import Base

if TYPE_CHECKING:
    from app.models.cve_cvss_assessment import CVECVSSAssessment
    from app.models.cve_external_identifier import CVEExternalIdentifier
    from app.models.cve_source import CVESource


class CVE(Base):
    """A Common Vulnerabilities and Exposures record.

    `severity` stores the PascalCase unified `Severity` value denormalized
    from the CVSS Severity Resolution Cascade; `NULL` means unresolved and
    is distinct from the resolved `"None"` label. It is a Category B
    column: the database accepts any string, and values are validated by
    the writing service. `cve_state` is Category A and protected by
    `chk_cve_cve_state_valid`. The `PUBLISHED` ⇒ `date_rejected IS NULL`
    invariant is enforced by the service, not by a database constraint
    (`docs/data-model.md`, CVE).
    """

    __tablename__ = "cve"
    __table_args__ = (
        CheckConstraint(
            f"cve_state IN ({', '.join(repr(e.value) for e in CveState)})",
            name="chk_cve_cve_state_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    published_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cve_state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=CveState.PUBLISHED.value,
        server_default=CveState.PUBLISHED.value,
    )
    date_rejected: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Child rows are owned by the CVE and removed with it by the database
    # (`FK(cve.id) ON DELETE CASCADE`). `passive_deletes=True` leaves
    # unloaded children to that database cascade instead of loading them
    # first; the ORM cascade deletes children already loaded in the
    # session, so it never attempts to null their NOT NULL foreign key.
    sources: Mapped[list[CVESource]] = relationship(
        "CVESource",
        back_populates="cve",
        cascade="all, delete",
        passive_deletes=True,
    )
    cvss_assessments: Mapped[list[CVECVSSAssessment]] = relationship(
        "CVECVSSAssessment",
        back_populates="cve",
        cascade="all, delete",
        passive_deletes=True,
    )
    external_identifiers: Mapped[list[CVEExternalIdentifier]] = relationship(
        "CVEExternalIdentifier",
        back_populates="cve",
        cascade="all, delete",
        passive_deletes=True,
    )
