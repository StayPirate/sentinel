"""add Product catalog tables

Creates the `product` and `product_repository` tables documented in
`docs/data-model.md` (Product, ProductRepository): UNIQUE `cpe`, UNIQUE
`(product_id, repo_name)`, and the `product_repository.product_id` foreign key
with the PostgreSQL default `NO ACTION` (#633 decision A3). No CHECK constraint
and no standalone index are documented for either table (#633 decision A2).

Revision ID: ebb47af19347
Revises: b3996908657f
Create Date: 2026-09-26 08:44:16.983524

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ebb47af19347"
down_revision: str | None = "b3996908657f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "product",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("cpe", sa.String(length=255), nullable=False),
        sa.Column("cvss_threshold", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("first_customer_ship_date", sa.Date(), nullable=True),
        sa.Column("general_support_end_date", sa.Date(), nullable=True),
        sa.Column("extended_support_end_date", sa.Date(), nullable=True),
        sa.Column("reactive_support_end_date", sa.Date(), nullable=True),
        sa.Column("catalog_last_seen_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cpe"),
    )
    op.create_table(
        "product_repository",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("product_id", sa.UUID(), nullable=False),
        sa.Column("repo_name", sa.String(length=255), nullable=False),
        sa.Column("catalog_last_seen_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.ForeignKeyConstraint(["product_id"], ["product.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "product_id",
            "repo_name",
            name="uq_product_repository_product_id_repo_name",
        ),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table("product_repository")
    op.drop_table("product")
