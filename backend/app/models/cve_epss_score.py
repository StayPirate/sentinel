"""CVEEPSSScore model — latest FIRST EPSS snapshot of a CVE.

See `docs/data-model.md` (CVEEPSSScore) and
`docs/features/tickets/cve-service.md` (Child Persistence Matrix) for the
full specification. This module implements only the persistence root;
additive ingestion and the active-Ticket refresh belong to the CVE
service and the EPSS fetcher.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, Float, ForeignKey, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVEEPSSScore(Base):
    """The single point-in-time EPSS snapshot of a CVE (`cve_id` is UNIQUE).

    `score` and `percentile` are `FLOAT` rather than `DECIMAL`: EPSS values
    never gate eligibility or status, and their precision varies
    (`docs/data-model.md`, CVEEPSSScore, FLOAT vs DECIMAL). The database
    enforces no range CHECK; validation belongs to the writing services.
    """

    __tablename__ = "cve_epss_score"

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
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    assessed_at: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="epss_score")
