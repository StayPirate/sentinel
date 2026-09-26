"""IBSRequest model — one normalized IBS request parent relevant to Sentinel.

See `docs/data-model.md` (IBSRequest, IBSRequestState Enum, IBS Request
Evidence Retention) and `docs/features/packages/ibs-submission-tracking.md`
(Request States, Data Model) for the full specification. This module
implements only the persistence record; request discovery, point-fetch,
supersession traversal, upsert conditions, and reconciliation belong to IBS
submission tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Integer, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IBSRequestState
from app.database import Base

if TYPE_CHECKING:
    from app.models.ibs_request_action import IBSRequestAction


class IBSRequest(Base):
    """The exact current IBS state of one public IBS request number.

    `request_number` is the positive, UNIQUE public IBS request number.
    `state` is Category A (`IBSRequestState`), protected by
    `chk_ibs_request_state_valid`, and has no default: it always carries the
    exact state supplied by authoritative request detail.
    `superseded_by_request_number` is present if and only if `state` is
    `superseded`, positive, and different from `request_number`
    (`chk_ibs_request_supersession_coherence`); it is not an FK because the
    successor need not be retained yet. `upstream_created_at` and
    `upstream_updated_at` are IBS chronology and are never substituted by the
    local `created_at` / `updated_at`. No author, actor, comment,
    description, event payload, or raw response is stored. Requests are
    retained indefinitely: an upstream `deleted` state updates the row, and
    actions reference it with `ON DELETE RESTRICT`.
    """

    __tablename__ = "ibs_request"
    __table_args__ = (
        CheckConstraint(
            "request_number > 0",
            name="chk_ibs_request_request_number_positive",
        ),
        CheckConstraint(
            f"state IN ({', '.join(repr(e.value) for e in IBSRequestState)})",
            name="chk_ibs_request_state_valid",
        ),
        CheckConstraint(
            "(state = 'superseded'"
            " AND superseded_by_request_number IS NOT NULL"
            " AND superseded_by_request_number > 0"
            " AND superseded_by_request_number <> request_number)"
            " OR (state <> 'superseded'"
            " AND superseded_by_request_number IS NULL)",
            name="chk_ibs_request_supersession_coherence",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    request_number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    superseded_by_request_number: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    upstream_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    upstream_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
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

    # passive_deletes="all": request evidence is retained indefinitely and
    # never physically deleted. Without it SQLAlchemy would try to null the
    # NOT NULL `ibs_request_id` of loaded actions before deleting the
    # request; the database FK (ON DELETE RESTRICT) must reject the delete
    # instead.
    actions: Mapped[list[IBSRequestAction]] = relationship(
        "IBSRequestAction",
        back_populates="ibs_request",
        passive_deletes="all",
    )
