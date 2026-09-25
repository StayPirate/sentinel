"""CVEExternalIdentifier model — external advisory IDs mapped to a CVE.

See `docs/data-model.md` (CVEExternalIdentifier,
CVEExternalIdentifierSource Python Enum) for the full specification.
This module implements only the persistence root; external identifiers
are written exclusively by CVE ingestion.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVEExternalIdentifier(Base):
    """An external vulnerability identifier (e.g. a GHSA-ID) for a CVE.

    `source` stores a `CVEExternalIdentifierSource` value (Category B, no
    CHECK constraint). `(source, identifier)` is globally unique, because
    each external ID is unique within its naming system; one CVE may have
    several identifiers, including several from the same source. The
    unique key does not lead with `cve_id`, so the separate non-unique
    `ix_cve_external_identifier_cve_id` index serves per-CVE reads and the
    `ON DELETE CASCADE` lookup.
    """

    __tablename__ = "cve_external_identifier"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "identifier",
            name="uq_cve_external_identifier_source_identifier",
        ),
        Index("ix_cve_external_identifier_cve_id", "cve_id"),
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
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="external_identifiers")
