"""add Ticket package and track tables

Creates the `ticket_package` and `ticket_package_track` tables documented in
`docs/data-model.md` (TicketPackage, TicketPackageTrack): UNIQUE `(ticket_id,
package_name)`, the non-unique, non-partial `ix_ticket_package_package_name`,
UNIQUE `(ticket_package_id, reference)`, the Category A CHECK constraints
`chk_ticket_package_track_status_valid` (PackageStatus) and
`chk_ticket_package_track_delivery_status_valid` (DeliveryStatus), and both
foreign keys with the PostgreSQL default `NO ACTION` (#633 decision A3). The
CHECK value lists are literal so that this revision does not change when the
enums evolve; adding a value requires a new migration.

Revision ID: 9e4a3d54d5cc
Revises: ebb47af19347
Create Date: 2026-09-26 09:26:39.097382

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9e4a3d54d5cc"
down_revision: str | None = "ebb47af19347"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "ticket_package",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_id", sa.UUID(), nullable=False),
        sa.Column("package_name", sa.String(length=255), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["ticket_id"], ["ticket.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_id",
            "package_name",
            name="uq_ticket_package_ticket_id_package_name",
        ),
    )
    op.create_index(
        "ix_ticket_package_package_name",
        "ticket_package",
        ["package_name"],
        unique=False,
    )
    op.create_table(
        "ticket_package_track",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_package_id", sa.UUID(), nullable=False),
        sa.Column("workflow_type", sa.String(length=20), nullable=False),
        sa.Column("reference", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default="ANALYSIS",
            nullable=False,
        ),
        sa.Column(
            "delivery_status",
            sa.String(length=20),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('ANALYSIS', 'AFFECTED', 'NOT_AFFECTED', 'FIXED', 'WONT_FIX')",
            name="chk_ticket_package_track_status_valid",
        ),
        sa.CheckConstraint(
            "delivery_status IN ('PENDING', 'IN_PROGRESS', 'RELEASED')",
            name="chk_ticket_package_track_delivery_status_valid",
        ),
        sa.ForeignKeyConstraint(["ticket_package_id"], ["ticket_package.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_package_id",
            "reference",
            name="uq_ticket_package_track_ticket_package_id_reference",
        ),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table("ticket_package_track")
    op.drop_index("ix_ticket_package_package_name", table_name="ticket_package")
    op.drop_table("ticket_package")
