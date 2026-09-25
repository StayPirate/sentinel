"""CVECWE model — one provider's CWE classification of a CVE.

See `docs/data-model.md` (CVECWE) and
`docs/features/tickets/cve-service.md` (Child Persistence Matrix) for the
full specification. This module implements only the persistence root;
additive ingestion belongs to the CVE service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVECWE(Base):
    """A CWE identifier assigned to a CVE by one provider.

    Different providers frequently assign different CWEs to the same CVE,
    so provenance is part of the `(cve_id, cwe_id, source)` unique key.
    `source` is a free-form provider label (e.g. `"NVD"`, `"Red Hat"`).
    """

    __tablename__ = "cve_cwe"
    __table_args__ = (
        UniqueConstraint(
            "cve_id",
            "cwe_id",
            "source",
            name="uq_cve_cwe_cve_id_cwe_id_source",
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
    cwe_id: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="cwes")
