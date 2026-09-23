"""add items succeeded to fetcher run

Revision ID: ace650c9f7a8
Revises: 2972274112d2
Create Date: 2026-09-23 15:41:57.325974

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ace650c9f7a8"
down_revision: str | None = "2972274112d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    See `docs/features/platform/fetcher-infrastructure.md` (Data Model —
    FetcherRun) and `docs/data-model.md` (FetcherRun) for the full
    contract. Adds the `items_succeeded` counter as
    `INTEGER NOT NULL DEFAULT 0` with no backfill or historical
    inference, and aligns the three pre-existing counters with the same
    documented zero server default. Because a non-null column is added
    to a populated table, the server default is required; PostgreSQL
    applies it as a metadata-only change (no table rewrite).
    """
    op.add_column(
        "fetcher_run",
        sa.Column(
            "items_succeeded",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    for column in ("items_created", "items_updated", "items_failed"):
        op.alter_column(
            "fetcher_run",
            column,
            existing_type=sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        )


def downgrade() -> None:
    """Downgrade database schema.

    Drops `items_succeeded` and restores the pre-migration default-less
    shape of the three existing counters.
    """
    for column in ("items_created", "items_updated", "items_failed"):
        op.alter_column(
            "fetcher_run",
            column,
            existing_type=sa.Integer(),
            nullable=False,
            server_default=None,
        )
    op.drop_column("fetcher_run", "items_succeeded")
