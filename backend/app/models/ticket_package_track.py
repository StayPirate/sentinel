"""TicketPackageTrack model — one package's maintenance track in one Ticket.

See `docs/data-model.md` (TicketPackageTrack, PackageStatus Enum,
DeliveryStatus Enum, WorkflowType Enum) and
`docs/features/packages/package-model.md` (Data Model, Three Orthogonal
Dimensions, Exclusion and Actionability) for the full specification. This
module implements only the persistence record; affectedness and delivery
mutations, exclusion and restoration, and actionability belong to
`package_service`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import DeliveryStatus, PackageStatus
from app.database import Base

if TYPE_CHECKING:
    from app.models.ticket_package import TicketPackage


class TicketPackageTrack(Base):
    """The affectedness and delivery status of a package in one track.

    The track is identified by the `reference` string (IBS codestream project
    name or git branch name), unique per package by `(ticket_package_id,
    reference)`, which also covers the `ticket_package_id` access path.
    `status` (`PackageStatus`) and `delivery_status` (`DeliveryStatus`) are
    Category A, protected by `chk_ticket_package_track_status_valid` and
    `chk_ticket_package_track_delivery_status_valid`; new records start at
    `ANALYSIS` / `PENDING`. `workflow_type` (`WorkflowType`) is Category B and
    validated by the writing service. `deleted_at` is the direct
    manual-exclusion marker; current actionability is derived at read time
    and never persisted. The FK uses the PostgreSQL default `NO ACTION`
    (#633 decision A3).
    """

    __tablename__ = "ticket_package_track"
    __table_args__ = (
        UniqueConstraint(
            "ticket_package_id",
            "reference",
            name="uq_ticket_package_track_ticket_package_id_reference",
        ),
        CheckConstraint(
            f"status IN ({', '.join(repr(e.value) for e in PackageStatus)})",
            name="chk_ticket_package_track_status_valid",
        ),
        CheckConstraint(
            f"delivery_status IN ({', '.join(repr(e.value) for e in DeliveryStatus)})",
            name="chk_ticket_package_track_delivery_status_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_package_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ticket_package.id"), nullable=False
    )
    workflow_type: Mapped[str] = mapped_column(String(20), nullable=False)
    reference: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=PackageStatus.ANALYSIS.value,
        server_default=PackageStatus.ANALYSIS.value,
    )
    delivery_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=DeliveryStatus.PENDING.value,
        server_default=DeliveryStatus.PENDING.value,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
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

    ticket_package: Mapped[TicketPackage] = relationship(
        "TicketPackage", back_populates="tracks"
    )
