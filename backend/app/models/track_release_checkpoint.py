"""TrackReleaseCheckpoint model — the IBS release-detection checkpoint of one track.

See `docs/data-model.md` (TrackReleaseCheckpoint, TicketPackageTrack, Notes)
and `docs/features/packages/ibs-track-release-detection.md` (Track Release
Checkpoint) for the full specification. This module implements only the
persisted state; predecessor validation, conditional advancement, first
observation, and the unavailable-history fallback belong to IBS track release
detection.
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
    from app.models.ticket_package_track import TicketPackageTrack


class TrackReleaseCheckpoint(Base):
    """The expanded IBS source state last successfully examined for one track.

    Operational release-detection state, not Ticket domain history: at most
    one row per `TicketPackageTrack` (UNIQUE `ticket_package_track_id`, which
    also covers the track-keyed lookup). `srcmd5` has no format CHECK (#633
    decision A2). `last_seen_at` replaces the standard timestamps
    (`docs/data-model.md`, Notes) and records when the current `srcmd5` was
    accepted; it has a database default but no `onupdate`, because the
    release detector sets it explicitly when it accepts a new checkpoint and
    an equal observation need not rewrite it. Creating or advancing a
    checkpoint never touches `TicketPackageTrack.updated_at`. The FK uses
    `ON DELETE RESTRICT`: tracks are soft-deleted only, and checkpoint rows
    are never deleted independently.
    """

    __tablename__ = "track_release_checkpoint"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_package_track_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket_package_track.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
    )
    srcmd5: Mapped[str] = mapped_column(String(32), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    ticket_package_track: Mapped[TicketPackageTrack] = relationship(
        "TicketPackageTrack", back_populates="release_checkpoint"
    )
