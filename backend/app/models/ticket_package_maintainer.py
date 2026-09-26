"""TicketPackageMaintainer model — one maintainer of one Ticket package occurrence.

See `docs/data-model.md` (TicketPackageMaintainer) and
`docs/features/packages/package-maintainership.md` (Domain Semantics, Data
Model) for the full specification. This module implements only the
persistence record; SMELT maintainership acquisition, its audit event, the
maintainer branch of confidential Ticket visibility, the Ticket `maintainer`
filter, and maintainer workbench queries belong to the services.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TicketPackageMaintainer(Base):
    """An immutable, additive maintainership association.

    One existing Sentinel user maintains one `TicketPackage` occurrence,
    package-wide (every track below it). The pair is unique by
    `(ticket_package_id, user_id)`, which also covers package-first
    acquisition; `ix_ticket_package_maintainer_user_id` serves the
    caller-first visibility and workbench lookups. Rows are write-once: there
    is no `updated_at` (`docs/data-model.md`, Notes) and no normal workflow
    updates or removes them. Both FKs use `ON DELETE RESTRICT` because users
    are deactivated rather than deleted and package occurrences are
    soft-deleted.

    The class deliberately declares no relationship of its own. The
    documented `TicketPackage.maintainers` ↔ `User.maintained_packages` pair
    is a view-only many-to-many through this table, so associations are
    created only by inserting rows of this class and can never be added or
    removed through an ORM collection.
    """

    __tablename__ = "ticket_package_maintainer"
    __table_args__ = (
        UniqueConstraint(
            "ticket_package_id",
            "user_id",
            name="uq_ticket_package_maintainer_ticket_package_id_user_id",
        ),
        # Non-unique, non-partial (docs/data-model.md,
        # TicketPackageMaintainer, Indexes).
        Index("ix_ticket_package_maintainer_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_package_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket_package.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
