"""add CVE enrichment child tables and CVE child access-path indexes

Creates `cve_affected_version`, `cve_cwe`, `cve_ssvc_assessment`,
`cve_kev_entry`, and `cve_epss_score`, the non-unique
`ix_cve_affected_version_cve_id_source_container` scope index, and the
non-unique `ix_cve_external_identifier_cve_id` index on the existing
`cve_external_identifier` table (docs/data-model.md, CVEAffectedVersion,
CVECWE, CVESSVCAssessment, CVEKEVEntry, CVEEPSSScore, CVEExternalIdentifier).

Revision ID: e7c553292d65
Revises: 702b657813b7
Create Date: 2026-09-25 16:52:11.487147

"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7c553292d65"
down_revision: str | None = "702b657813b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _created_at() -> sa.Column[datetime]:
    """`created_at TIMESTAMPTZ NOT NULL DEFAULT now()`."""
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )


def _timestamps() -> list[sa.Column[datetime]]:
    """`created_at` and `updated_at`, both `TIMESTAMPTZ NOT NULL DEFAULT now()`."""
    return [
        _created_at(),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    """Upgrade database schema."""
    # Replaced or removed only as complete (cve_id, source_container) sets
    # and never updated in place: `created_at` only, and no unique
    # constraint or unique index over the entry columns.
    op.create_table(
        "cve_affected_version",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("source_container", sa.String(length=100), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=True),
        sa.Column("product", sa.Text(), nullable=True),
        sa.Column("package_url", sa.Text(), nullable=True),
        sa.Column("collection_url", sa.Text(), nullable=True),
        sa.Column("package_name", sa.Text(), nullable=True),
        sa.Column("repo", sa.Text(), nullable=True),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("version_type", sa.Text(), nullable=True),
        sa.Column("version_end", sa.Text(), nullable=True),
        sa.Column("version_end_inclusive", sa.Boolean(), nullable=True),
        sa.Column(
            "program_files",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column("ecosystem", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("default_status", sa.String(length=20), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_cve_affected_version_cve_id_source_container",
        "cve_affected_version",
        ["cve_id", "source_container"],
        unique=False,
    )
    op.create_table(
        "cve_cwe",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("cwe_id", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "cve_id", "cwe_id", "source", name="uq_cve_cwe_cve_id_cwe_id_source"
        ),
    )
    op.create_table(
        "cve_ssvc_assessment",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("exploitation", sa.String(length=20), nullable=False),
        sa.Column("automatable", sa.String(length=10), nullable=False),
        sa.Column("technical_impact", sa.String(length=20), nullable=False),
        sa.Column("version", sa.String(length=10), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_table(
        "cve_kev_entry",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("reference_url", sa.Text(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_table(
        "cve_epss_score",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("assessed_at", sa.Date(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index(
        "ix_cve_external_identifier_cve_id",
        "cve_external_identifier",
        ["cve_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_index(
        "ix_cve_external_identifier_cve_id", table_name="cve_external_identifier"
    )
    op.drop_table("cve_epss_score")
    op.drop_table("cve_kev_entry")
    op.drop_table("cve_ssvc_assessment")
    op.drop_table("cve_cwe")
    op.drop_index(
        "ix_cve_affected_version_cve_id_source_container",
        table_name="cve_affected_version",
    )
    op.drop_table("cve_affected_version")
