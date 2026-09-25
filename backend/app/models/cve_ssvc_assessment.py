"""CVESSVCAssessment model — CISA SSVC decision points of a CVE.

See `docs/data-model.md` (CVESSVCAssessment) and
`docs/features/tickets/cve-service.md` (Child Persistence Matrix) for the
full specification. This module implements only the persistence root;
additive ingestion belongs to the CVE service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVESSVCAssessment(Base):
    """The single SSVC assessment of a CVE (`cve_id` is UNIQUE).

    The decision-point columns store the source's descriptive labels
    (e.g. `exploitation` `"none"`/`"poc"`/`"active"`). The database
    enforces no CHECK on them; validation belongs to the writing services.
    """

    __tablename__ = "cve_ssvc_assessment"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    exploitation: Mapped[str] = mapped_column(String(20), nullable=False)
    automatable: Mapped[str] = mapped_column(String(10), nullable=False)
    technical_impact: Mapped[str] = mapped_column(String(20), nullable=False)
    version: Mapped[str] = mapped_column(String(10), nullable=False)
    assessed_at: Mapped[datetime | None] = mapped_column(
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

    cve: Mapped[CVE] = relationship("CVE", back_populates="ssvc_assessment")
