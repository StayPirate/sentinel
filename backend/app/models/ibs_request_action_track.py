"""IBSRequestActionTrack model — one IBS request action correlated to one track.

See `docs/data-model.md` (IBSRequestActionTrack, IBS Request Evidence
Retention, Notes) and `docs/features/packages/ibs-submission-tracking.md`
(Data Model > IBSRequestActionTrack, Retention and Deletion, RabbitMQ Request
Wake-Ups step 4) for the full specification. This module implements only the
persistence record; the correlation upsert and delivery derivation belong to
IBS submission tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.ibs_request_action import IBSRequestAction


class IBSRequestActionTrack(Base):
    """The correlation between one exact request action (submission or
    release) and one exact `TicketPackageTrack`.

    The pair is unique by `(ticket_package_track_id, ibs_request_action_id)`;
    the track leads because ticket-scoped and reconciliation lookups start
    from the track, and `ix_ibs_request_action_track_ibs_request_action_id`
    serves the action-to-track lookup. One action may correlate to several
    tracks and several actions to one track. Rows are write-once factual
    evidence retained indefinitely: `created_at` only (`docs/data-model.md`,
    Notes) and both FKs use `ON DELETE RESTRICT`.

    Only the documented `IBSRequestAction.track_links` ↔
    `IBSRequestActionTrack.ibs_request_action` pair is mapped; the track side
    is reached through `ticket_package_track_id`.
    """

    __tablename__ = "ibs_request_action_track"
    __table_args__ = (
        # The conventional full-column name exceeds PostgreSQL's 63-character
        # identifier limit, so the columns are abbreviated in key order.
        UniqueConstraint(
            "ticket_package_track_id",
            "ibs_request_action_id",
            name="uq_ibs_request_action_track_track_id_action_id",
        ),
        # Non-unique, non-partial (docs/data-model.md, IBSRequestActionTrack,
        # Indexes): the unique constraint leads with the track.
        Index(
            "ix_ibs_request_action_track_ibs_request_action_id",
            "ibs_request_action_id",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ibs_request_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ibs_request_action.id", ondelete="RESTRICT"),
        nullable=False,
    )
    ticket_package_track_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket_package_track.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    ibs_request_action: Mapped[IBSRequestAction] = relationship(
        "IBSRequestAction", back_populates="track_links"
    )
