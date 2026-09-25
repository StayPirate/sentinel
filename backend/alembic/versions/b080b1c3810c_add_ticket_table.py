"""add Ticket core table

Revision ID: b080b1c3810c
Revises: 292b30ba95cb
Create Date: 2026-09-25 14:26:40.041241

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b080b1c3810c"
down_revision: str | None = "292b30ba95cb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "ticket",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column(
            "sequence_id", sa.Integer(), sa.Identity(always=False), nullable=False
        ),
        sa.Column("cve_id", sa.UUID(), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="New", nullable=False),
        sa.Column("severity_manual", sa.String(length=20), nullable=True),
        sa.Column("priority_auto", sa.String(length=10), nullable=True),
        sa.Column("priority_override", sa.String(length=10), nullable=True),
        sa.Column("assignee_id", sa.UUID(), nullable=True),
        sa.Column("duplicate_of_id", sa.UUID(), nullable=True),
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
        sa.Column(
            "is_confidential",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("coordinated_release_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('New', 'Analysis', 'Analyzed', 'Resolved', 'Ignored', "
            "'Duplicated')",
            name="chk_ticket_status_valid",
        ),
        sa.CheckConstraint(
            "(status = 'Duplicated' AND duplicate_of_id IS NOT NULL) "
            "OR (status != 'Duplicated' AND duplicate_of_id IS NULL)",
            name="chk_ticket_duplicate_status_coherence",
        ),
        sa.CheckConstraint(
            "duplicate_of_id <> id", name="chk_ticket_no_self_duplicate"
        ),
        sa.CheckConstraint(
            "severity_manual IS NULL OR cve_id IS NULL",
            name="chk_ticket_severity_manual_cve_exclusive",
        ),
        sa.ForeignKeyConstraint(["assignee_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"]),
        sa.ForeignKeyConstraint(["duplicate_of_id"], ["ticket.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
        sa.UniqueConstraint("sequence_id"),
    )
    op.create_index(
        "ix_ticket_duplicate_of_id",
        "ticket",
        ["duplicate_of_id"],
        unique=False,
        postgresql_where=sa.text("duplicate_of_id IS NOT NULL"),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index("ix_ticket_duplicate_of_id", table_name="ticket")
    op.drop_table("ticket")
