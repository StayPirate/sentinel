"""add Ticket audit event, access grant, and reference tables

Revision ID: 702b657813b7
Revises: b080b1c3810c
Create Date: 2026-09-25 15:33:25.954333

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "702b657813b7"
down_revision: str | None = "b080b1c3810c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "ticket_audit_event",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("ticket_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(["ticket_id"], ["ticket.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ticket_audit_event_created_at", "ticket_audit_event", ["created_at"]
    )
    op.create_index(
        "ix_ticket_audit_event_ticket_id", "ticket_audit_event", ["ticket_id"]
    )
    op.create_index("ix_ticket_audit_event_user_id", "ticket_audit_event", ["user_id"])

    op.create_table(
        "ticket_access_grant",
        sa.Column("ticket_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("granted_by_id", sa.UUID(), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["ticket_id"], ["ticket.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["granted_by_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("ticket_id", "user_id"),
    )

    op.create_table(
        "ticket_reference",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_id", sa.UUID(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=True),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("type", sa.String(length=20), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=False),
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
        sa.ForeignKeyConstraint(["ticket_id"], ["ticket.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_id", "url", name="uq_ticket_reference_ticket_id_url"
        ),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table("ticket_reference")
    op.drop_table("ticket_access_grant")
    op.drop_index("ix_ticket_audit_event_user_id", table_name="ticket_audit_event")
    op.drop_index("ix_ticket_audit_event_ticket_id", table_name="ticket_audit_event")
    op.drop_index("ix_ticket_audit_event_created_at", table_name="ticket_audit_event")
    op.drop_table("ticket_audit_event")
