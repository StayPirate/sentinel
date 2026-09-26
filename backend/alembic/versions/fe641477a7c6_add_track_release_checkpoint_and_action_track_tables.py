"""add IBS track release checkpoint and request action track tables

Creates the `track_release_checkpoint` and `ibs_request_action_track` tables
documented in `docs/data-model.md` (TrackReleaseCheckpoint,
IBSRequestActionTrack):

- `track_release_checkpoint`: the `ticket_package_track_id` foreign key with
  `ON DELETE RESTRICT` and UNIQUE (at most one checkpoint per track);
  `srcmd5` VARCHAR(32) with no format CHECK; `last_seen_at` with a `now()`
  server default instead of the standard timestamps;
- `ibs_request_action_track`: the `ibs_request_action_id` and
  `ticket_package_track_id` foreign keys, both with `ON DELETE RESTRICT`;
  `created_at` only; the track-leading UNIQUE
  `(ticket_package_track_id, ibs_request_action_id)`; and the non-unique,
  non-partial `ix_ibs_request_action_track_ibs_request_action_id`.

Revision ID: fe641477a7c6
Revises: 5d2a9c7e41b8
Create Date: 2026-09-26 12:02:20.620836

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "fe641477a7c6"
down_revision: str | None = "5d2a9c7e41b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "track_release_checkpoint",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ticket_package_track_id", sa.UUID(), nullable=False),
        sa.Column("srcmd5", sa.String(length=32), nullable=False),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["ticket_package_track_id"],
            ["ticket_package_track.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ticket_package_track_id"),
    )
    op.create_table(
        "ibs_request_action_track",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ibs_request_action_id", sa.UUID(), nullable=False),
        sa.Column("ticket_package_track_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["ibs_request_action_id"],
            ["ibs_request_action.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["ticket_package_track_id"],
            ["ticket_package_track.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ticket_package_track_id",
            "ibs_request_action_id",
            name="uq_ibs_request_action_track_track_id_action_id",
        ),
    )
    op.create_index(
        "ix_ibs_request_action_track_ibs_request_action_id",
        "ibs_request_action_track",
        ["ibs_request_action_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index(
        "ix_ibs_request_action_track_ibs_request_action_id",
        table_name="ibs_request_action_track",
    )
    op.drop_table("ibs_request_action_track")
    op.drop_table("track_release_checkpoint")
