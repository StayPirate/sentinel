"""add CVE root, source, CVSS assessment, and external identifier tables

Revision ID: 292b30ba95cb
Revises: ace650c9f7a8
Create Date: 2026-09-25 13:53:45.137109

"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "292b30ba95cb"
down_revision: str | None = "ace650c9f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> list[sa.Column[datetime]]:
    """`created_at` and `updated_at`, both `TIMESTAMPTZ NOT NULL DEFAULT now()`."""
    return [
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
    ]


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table(
        "cve",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("published_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cve_state",
            sa.String(length=20),
            server_default="PUBLISHED",
            nullable=False,
        ),
        sa.Column("date_rejected", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "cve_state IN ('PUBLISHED', 'REJECTED')",
            name="chk_cve_cve_state_valid",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_table(
        "cve_source",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id", "source", name="uq_cve_source_cve_id_source"),
    )
    op.create_table(
        "cve_cvss_assessment",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("provider_name", sa.String(length=100), nullable=False),
        sa.Column("cvss_version", sa.String(length=10), nullable=False),
        sa.Column("score", sa.Numeric(precision=3, scale=1), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("vector_string", sa.String(length=200), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "cve_id",
            "provider_name",
            "cvss_version",
            name="uq_cve_cvss_assessment_cve_id_provider_name_cvss_version",
        ),
    )
    op.create_table(
        "cve_external_identifier",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("identifier", sa.String(length=100), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source",
            "identifier",
            name="uq_cve_external_identifier_source_identifier",
        ),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table("cve_external_identifier")
    op.drop_table("cve_cvss_assessment")
    op.drop_table("cve_source")
    op.drop_table("cve")
