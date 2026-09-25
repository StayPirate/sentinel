"""add ticket assignee index

Creates the non-unique, non-partial `ix_ticket_assignee_id` B-tree index on
`ticket.assignee_id` (docs/data-model.md, Ticket, Indexes; Notes, FK
access-path indexing criterion).

Revision ID: b3996908657f
Revises: e7c553292d65
Create Date: 2026-09-25 17:28:54.797959

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3996908657f"
down_revision: str | None = "e7c553292d65"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_index("ix_ticket_assignee_id", "ticket", ["assignee_id"], unique=False)


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index("ix_ticket_assignee_id", table_name="ticket")
