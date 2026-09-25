"""CVESource model — latest fetch outcome per CVE data source.

See `docs/data-model.md` (CVESource, CVESourceFetchStatus Enum,
CVESourceType Python Enum) and `docs/features/tickets/cve-service.md`
(CVESource Management) for the full specification. This module
implements only the persistence root; every write goes through
`record_source_status()` in the CVE service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
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


class CVESource(Base):
    """Latest completed fetch-attempt outcome of one source for one CVE.

    One row per `(cve_id, source)`; latest state, not history. `source`
    stores a lowercase `CVESourceType` value and `status` a
    `CVESourceFetchStatus` value. Both are Category B columns without a
    CHECK constraint. `fetched_at` and `first_failed_at` have no default:
    the service writes them from one database wall-clock instant per
    mutation (`docs/features/tickets/cve-service.md`, CVESource
    Management).
    """

    __tablename__ = "cve_source"
    __table_args__ = (
        UniqueConstraint("cve_id", "source", name="uq_cve_source_cve_id_source"),
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
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    first_failed_at: Mapped[datetime | None] = mapped_column(
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

    cve: Mapped[CVE] = relationship("CVE", back_populates="sources")
