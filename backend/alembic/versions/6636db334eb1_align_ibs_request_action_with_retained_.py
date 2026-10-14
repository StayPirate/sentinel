"""align IBS request action with the retained-root lookup

Aligns `ibs_request_action` with `docs/data-model.md` (IBSRequestAction):

- drops `chk_ibs_request_action_accepted_xsrcmd5_hex`, then the
  `source_revision` and `accepted_xsrcmd5` columns. Both values are request
  action diff inputs that always come from fresh point detail and have no
  persisted reader (user decision C1 on #942); the table has no writer yet,
  so no data is lost;
- creates the non-unique, non-partial
  `ix_ibs_request_action_logical_package_codestream_name` B-tree index on
  `(logical_package, codestream_name)` for the retained-root lookup of one
  logical package and codestream
  (`docs/features/packages/ibs-submission-tracking.md`, Required Roots).

Downgrade drops the index and restores both nullable columns with their
original types and the CHECK with its original predicate. PostgreSQL
appends restored columns at the end of the table, so their ordinal position
differs from the original creation; no query depends on it.

Revision ID: 6636db334eb1
Revises: fe641477a7c6
Create Date: 2026-10-14 21:40:24.273324

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6636db334eb1"
down_revision: str | None = "fe641477a7c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.drop_constraint(
        "chk_ibs_request_action_accepted_xsrcmd5_hex",
        "ibs_request_action",
        type_="check",
    )
    op.drop_column("ibs_request_action", "accepted_xsrcmd5")
    op.drop_column("ibs_request_action", "source_revision")
    op.create_index(
        "ix_ibs_request_action_logical_package_codestream_name",
        "ibs_request_action",
        ["logical_package", "codestream_name"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index(
        "ix_ibs_request_action_logical_package_codestream_name",
        table_name="ibs_request_action",
    )
    op.add_column(
        "ibs_request_action",
        sa.Column("source_revision", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "ibs_request_action",
        sa.Column("accepted_xsrcmd5", sa.String(length=32), nullable=True),
    )
    op.create_check_constraint(
        "chk_ibs_request_action_accepted_xsrcmd5_hex",
        "ibs_request_action",
        "accepted_xsrcmd5 IS NULL OR accepted_xsrcmd5 ~ '^[0-9a-f]{32}$'",
    )
