"""FetcherRun model — records every execution of a fetcher.

See `docs/data-model.md` (FetcherRun) and
`docs/features/platform/fetcher-infrastructure.md` (Data Model —
FetcherRun) for the full specification, including the status
determination precedence and cursor persistence rules (implemented by
`BaseFetcher.run()`) and stale run detection (implemented by the
atomic run acquisition protocol in `app/services/fetcher_execution.py`
— this model only defines the persistence root).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import FetcherRunStatus
from app.database import Base

if TYPE_CHECKING:
    from app.models.fetcher_config import FetcherConfig
    from app.models.user import User


class FetcherRun(Base):
    """A single execution of a fetcher, tracked from start to finish.

    Primary data source for the fetcher dashboard charts. Records are
    retained indefinitely (no retention policy — see
    `docs/features/platform/fetcher-infrastructure.md`, Data
    Retention). Has no `updated_at`: the `queued -> running` adoption
    transition and finalization are the only in-place updates, and both
    are fully captured by `started_at`/`finished_at` (`docs/data-model.md`,
    Notes).
    """

    __tablename__ = "fetcher_run"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({', '.join(repr(e.value) for e in FetcherRunStatus)})",
            name="chk_fetcher_run_status_valid",
        ),
        Index(
            "ix_fetcher_run_fetcher_name_started_at",
            "fetcher_name",
            "started_at",
        ),
        Index(
            "ix_fetcher_run_fetcher_name_created_at",
            "fetcher_name",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    fetcher_name: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("fetcher_config.fetcher_name", ondelete="RESTRICT"),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    items_succeeded: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    items_created: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    items_updated: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    items_failed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_traceback: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(20), nullable=False)
    # No explicit ON DELETE override: the approved data model
    # (docs/features/platform/fetcher-infrastructure.md, Data Model —
    # FetcherRun) documents this FK as nullable without specifying a
    # delete behavior, unlike the fetcher_name and audit actor FKs,
    # which explicitly require RESTRICT. PostgreSQL's default NO ACTION
    # already protects the row from disappearing on user deletion —
    # Sentinel only ever deactivates users (see `AuditEventMixin`),
    # never hard-deletes them.
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id"), nullable=True
    )
    cursor: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    hard_time_limit_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    config: Mapped[FetcherConfig] = relationship("FetcherConfig", back_populates="runs")
    # Read-only convenience relationship for API consumers. Deliberately
    # unidirectional and NOT back-populated: User gets no reverse
    # collection, mirroring ApiKey.revoking_user. `viewonly=True`
    # because this FK is never intended to be mutated through this
    # relationship — the owning workflow sets `triggered_by_user_id`
    # directly.
    triggered_by_user: Mapped[User | None] = relationship(
        "User", foreign_keys=[triggered_by_user_id], viewonly=True
    )
