"""IBSRequestAction model — one normalized relevant action of one IBS request.

See `docs/data-model.md` (IBSRequestAction, IBSRequestActionType Enum, IBS
Request Evidence Retention) and
`docs/features/packages/ibs-submission-tracking.md` (Data Model >
IBSRequestAction, Retention and Deletion) for the full specification. This
module implements only the persistence record; action normalization,
provenance fill, identity-conflict handling, and track correlation belong to
IBS submission tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IBSRequestActionType
from app.database import Base

if TYPE_CHECKING:
    from app.models.ibs_request import IBSRequest
    from app.models.ibs_request_action_track import IBSRequestActionTrack

_INCIDENT = IBSRequestActionType.MAINTENANCE_INCIDENT.value
_RELEASE = IBSRequestActionType.MAINTENANCE_RELEASE.value


class IBSRequestAction(Base):
    """One submission (`maintenance_incident`) or release
    (`maintenance_release`) action belonging to one `IBSRequest`.

    `action_type` is Category B (`IBSRequestActionType`) with no
    single-column enum CHECK: `chk_ibs_request_action_type_coherence` has one
    branch per value, so it both enforces the type-specific required fields
    and `codestream_name` equality and rejects unknown types. The durable
    semantic identity is request-scoped and type-specific, encoded by the two
    unique partial indexes; array position and the RabbitMQ `action_id` are
    never stored. `ix_ibs_request_action_ibs_request_id` serves the
    request-to-all-actions lookup, which neither partial index can serve.
    Actions are retained indefinitely; the parent FK uses
    `ON DELETE RESTRICT`. `track_links` loads the action's
    `IBSRequestActionTrack` correlations.
    """

    __tablename__ = "ibs_request_action"
    __table_args__ = (
        CheckConstraint(
            "incident_number IS NULL OR incident_number > 0",
            name="chk_ibs_request_action_incident_number_positive",
        ),
        CheckConstraint(
            f"(action_type = '{_INCIDENT}'"
            " AND source_project IS NOT NULL"
            " AND source_package IS NOT NULL"
            " AND target_release_project IS NOT NULL"
            " AND codestream_name = target_release_project)"
            f" OR (action_type = '{_RELEASE}'"
            " AND source_project IS NOT NULL"
            " AND source_package IS NOT NULL"
            " AND target_project IS NOT NULL"
            " AND target_package IS NOT NULL"
            " AND incident_number IS NOT NULL"
            " AND codestream_name = target_project)",
            name="chk_ibs_request_action_type_coherence",
        ),
        CheckConstraint(
            "accepted_srcmd5 IS NULL OR accepted_srcmd5 ~ '^[0-9a-f]{32}$'",
            name="chk_ibs_request_action_accepted_srcmd5_hex",
        ),
        CheckConstraint(
            "accepted_xsrcmd5 IS NULL OR accepted_xsrcmd5 ~ '^[0-9a-f]{32}$'",
            name="chk_ibs_request_action_accepted_xsrcmd5_hex",
        ),
        # Type-specific durable semantic identities (docs/data-model.md,
        # IBSRequestAction, Indexes). The predicate fixes the action type, so
        # it is omitted from each key; SR target fields are outside identity.
        Index(
            "uq_ibs_request_action_maintenance_incident_identity",
            "ibs_request_id",
            "source_project",
            "source_package",
            "target_release_project",
            unique=True,
            postgresql_where=text(f"action_type = '{_INCIDENT}'"),
        ),
        Index(
            "uq_ibs_request_action_maintenance_release_identity",
            "ibs_request_id",
            "target_project",
            "target_package",
            unique=True,
            postgresql_where=text(f"action_type = '{_RELEASE}'"),
        ),
        # Non-unique, non-partial: a request-to-all-actions lookup implies
        # neither partial-index predicate (docs/data-model.md,
        # IBSRequestAction, Indexes).
        Index("ix_ibs_request_action_ibs_request_id", "ibs_request_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ibs_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ibs_request.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_package: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_package: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_release_project: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    logical_package: Mapped[str] = mapped_column(String(255), nullable=False)
    codestream_name: Mapped[str] = mapped_column(String(255), nullable=False)
    incident_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_revision: Mapped[str | None] = mapped_column(String(255), nullable=True)
    accepted_revision: Mapped[str | None] = mapped_column(String(255), nullable=True)
    accepted_srcmd5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    accepted_xsrcmd5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    ibs_request: Mapped[IBSRequest] = relationship(
        "IBSRequest", back_populates="actions"
    )
    # passive_deletes="all": correlations are retained indefinitely and never
    # physically deleted. Without it SQLAlchemy would try to null the NOT
    # NULL `ibs_request_action_id` of loaded correlations before deleting the
    # action; the database FK (ON DELETE RESTRICT) must reject the delete
    # instead.
    track_links: Mapped[list[IBSRequestActionTrack]] = relationship(
        "IBSRequestActionTrack",
        back_populates="ibs_request_action",
        passive_deletes="all",
    )
