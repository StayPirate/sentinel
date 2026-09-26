"""add Ticket package Product and maintainer tables

Creates the `ticket_package_product` and `ticket_package_maintainer` tables
documented in `docs/data-model.md` (TicketPackageProduct,
TicketPackageMaintainer):

- `ticket_package_product`: UNIQUE `(ticket_package_track_id, product_id)`, the
  non-unique, non-partial `ix_ticket_package_product_product_id`, the `eligible`
  (`true`) and `is_eligible_override` (`false`) server defaults, and both foreign
  keys with the PostgreSQL default `NO ACTION` (#633 decision A3);
- `ticket_package_maintainer`: UNIQUE `(ticket_package_id, user_id)`, the
  non-unique, non-partial `ix_ticket_package_maintainer_user_id`, both foreign
  keys with `ON DELETE RESTRICT`, and `created_at` only (no `updated_at`).

Revision ID: 3b04d8069b1d
Revises: 9e4a3d54d5cc
Create Date: 2026-09-26 10:07:21.686448

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3b04d8069b1d"
down_revision: str | None = "9e4a3d54d5cc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "ticket_package_product",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_package_track_id", sa.UUID(), nullable=False),
        sa.Column("product_id", sa.UUID(), nullable=False),
        sa.Column(
            "eligible", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "is_eligible_override",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["ticket_package_track_id"], ["ticket_package_track.id"]
        ),
        sa.ForeignKeyConstraint(["product_id"], ["product.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_package_track_id",
            "product_id",
            name="uq_ticket_package_product_ticket_package_track_id_product_id",
        ),
    )
    op.create_index(
        "ix_ticket_package_product_product_id",
        "ticket_package_product",
        ["product_id"],
        unique=False,
    )
    op.create_table(
        "ticket_package_maintainer",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_package_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["ticket_package_id"], ["ticket_package.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_package_id",
            "user_id",
            name="uq_ticket_package_maintainer_ticket_package_id_user_id",
        ),
    )
    op.create_index(
        "ix_ticket_package_maintainer_user_id",
        "ticket_package_maintainer",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index(
        "ix_ticket_package_maintainer_user_id", table_name="ticket_package_maintainer"
    )
    op.drop_table("ticket_package_maintainer")
    op.drop_index(
        "ix_ticket_package_product_product_id", table_name="ticket_package_product"
    )
    op.drop_table("ticket_package_product")
