"""CVEAffectedVersion model — affected product/version entries of a CVE.

See `docs/data-model.md` (CVEAffectedVersion) and
`docs/features/tickets/cve-service.md` (Child Persistence Matrix,
Canonical Payload Duplicate Handling, Affected-Version Snapshot
Operations) for the full specification. This module implements only the
persistence root; scoped snapshot replacement and removal and duplicate
validation belong to the CVE service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CVEAffectedVersion(Base):
    """One affected-version entry of a CVE within a `source_container` scope.

    Rows of one `(cve_id, source_container)` scope are replaced or removed
    only as a complete set and are never updated in place, so the table has
    `created_at` but no `updated_at` (`docs/data-model.md`, Notes). The table
    intentionally has no unique constraint or unique index over its entry
    columns: the entry conflict key in `cve-service.md` (Canonical Payload
    Duplicate Handling) is the sole authority for entry uniqueness. The
    non-unique `(cve_id, source_container)` index serves the scoped reads
    and deletes; it is not an entry-uniqueness mechanism. The upstream
    text columns are `TEXT` with no database length bound; their limits are
    enforced by the ingestion payload schema.
    """

    __tablename__ = "cve_affected_version"
    __table_args__ = (
        Index(
            "ix_cve_affected_version_cve_id_source_container",
            "cve_id",
            "source_container",
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
    source_container: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    product: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    collection_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_end: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_end_inclusive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    program_files: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    default_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    cve: Mapped[CVE] = relationship("CVE", back_populates="affected_versions")
