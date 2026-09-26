"""add IBS request and request action tables

Creates the `ibs_request` and `ibs_request_action` tables documented in
`docs/data-model.md` (IBSRequest, IBSRequestState Enum, IBSRequestAction,
IBSRequestActionType Enum):

- `ibs_request`: UNIQUE `request_number`, and the
  `chk_ibs_request_request_number_positive`, `chk_ibs_request_state_valid`
  (Category A `IBSRequestState`), and `chk_ibs_request_supersession_coherence`
  CHECKs;
- `ibs_request_action`: the `ibs_request_id` foreign key with
  `ON DELETE RESTRICT`; the `chk_ibs_request_action_incident_number_positive`,
  `chk_ibs_request_action_type_coherence` (one branch per Category B
  `IBSRequestActionType` value), and the two accepted-checksum hex CHECKs; the
  two type-specific unique partial semantic-identity indexes; and the
  non-unique, non-partial `ix_ibs_request_action_ibs_request_id`.

Revision ID: 5d2a9c7e41b8
Revises: 3b04d8069b1d
Create Date: 2026-09-26 14:05:12.318204

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5d2a9c7e41b8"
down_revision: str | None = "3b04d8069b1d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "ibs_request",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("request_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("superseded_by_request_number", sa.Integer(), nullable=True),
        sa.Column("upstream_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("upstream_updated_at", sa.DateTime(timezone=True), nullable=False),
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
            "request_number > 0", name="chk_ibs_request_request_number_positive"
        ),
        sa.CheckConstraint(
            "state IN ('new', 'review', 'accepted', 'declined', 'revoked', "
            "'superseded', 'deleted')",
            name="chk_ibs_request_state_valid",
        ),
        sa.CheckConstraint(
            "(state = 'superseded'"
            " AND superseded_by_request_number IS NOT NULL"
            " AND superseded_by_request_number > 0"
            " AND superseded_by_request_number <> request_number)"
            " OR (state <> 'superseded'"
            " AND superseded_by_request_number IS NULL)",
            name="chk_ibs_request_supersession_coherence",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_number"),
    )
    op.create_table(
        "ibs_request_action",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("ibs_request_id", sa.UUID(), nullable=False),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("source_project", sa.String(length=255), nullable=True),
        sa.Column("source_package", sa.String(length=255), nullable=True),
        sa.Column("target_project", sa.String(length=255), nullable=True),
        sa.Column("target_package", sa.String(length=255), nullable=True),
        sa.Column("target_release_project", sa.String(length=255), nullable=True),
        sa.Column("logical_package", sa.String(length=255), nullable=False),
        sa.Column("codestream_name", sa.String(length=255), nullable=False),
        sa.Column("incident_number", sa.Integer(), nullable=True),
        sa.Column("source_revision", sa.String(length=255), nullable=True),
        sa.Column("accepted_revision", sa.String(length=255), nullable=True),
        sa.Column("accepted_srcmd5", sa.String(length=32), nullable=True),
        sa.Column("accepted_xsrcmd5", sa.String(length=32), nullable=True),
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
            "incident_number IS NULL OR incident_number > 0",
            name="chk_ibs_request_action_incident_number_positive",
        ),
        sa.CheckConstraint(
            "(action_type = 'maintenance_incident'"
            " AND source_project IS NOT NULL"
            " AND source_package IS NOT NULL"
            " AND target_release_project IS NOT NULL"
            " AND codestream_name = target_release_project)"
            " OR (action_type = 'maintenance_release'"
            " AND source_project IS NOT NULL"
            " AND source_package IS NOT NULL"
            " AND target_project IS NOT NULL"
            " AND target_package IS NOT NULL"
            " AND incident_number IS NOT NULL"
            " AND codestream_name = target_project)",
            name="chk_ibs_request_action_type_coherence",
        ),
        sa.CheckConstraint(
            "accepted_srcmd5 IS NULL OR accepted_srcmd5 ~ '^[0-9a-f]{32}$'",
            name="chk_ibs_request_action_accepted_srcmd5_hex",
        ),
        sa.CheckConstraint(
            "accepted_xsrcmd5 IS NULL OR accepted_xsrcmd5 ~ '^[0-9a-f]{32}$'",
            name="chk_ibs_request_action_accepted_xsrcmd5_hex",
        ),
        sa.ForeignKeyConstraint(
            ["ibs_request_id"], ["ibs_request.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_ibs_request_action_maintenance_incident_identity",
        "ibs_request_action",
        [
            "ibs_request_id",
            "source_project",
            "source_package",
            "target_release_project",
        ],
        unique=True,
        postgresql_where=sa.text("action_type = 'maintenance_incident'"),
    )
    op.create_index(
        "uq_ibs_request_action_maintenance_release_identity",
        "ibs_request_action",
        ["ibs_request_id", "target_project", "target_package"],
        unique=True,
        postgresql_where=sa.text("action_type = 'maintenance_release'"),
    )
    op.create_index(
        "ix_ibs_request_action_ibs_request_id",
        "ibs_request_action",
        ["ibs_request_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index(
        "ix_ibs_request_action_ibs_request_id", table_name="ibs_request_action"
    )
    op.drop_index(
        "uq_ibs_request_action_maintenance_release_identity",
        table_name="ibs_request_action",
    )
    op.drop_index(
        "uq_ibs_request_action_maintenance_incident_identity",
        table_name="ibs_request_action",
    )
    op.drop_table("ibs_request_action")
    op.drop_table("ibs_request")
