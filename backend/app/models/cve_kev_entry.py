"""CVEKEVEntry model — CISA Known Exploited Vulnerabilities data of a CVE.

See `docs/data-model.md` (CVEKEVEntry) and
`docs/features/tickets/cve-service.md` (Child Persistence Matrix, KEV
status derivation) for the full specification. This module implements
only the persistence root; additive ingestion and the derived KEV source
status belong to the CVE service.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVEKEVEntry(Base):
    """The single KEV catalog entry of a CVE (`cve_id` is UNIQUE).

    Row presence is the authority for persisted KEV evidence, and
    `updated_at` is the completed `fetched_at` of the derived `kev` source
    status (`docs/data-model.md`, CVEKEVEntry).
    """

    __tablename__ = "cve_kev_entry"

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
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    reference_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="kev_entry")
